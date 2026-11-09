//! Verify a strictly rising then strictly falling signed sequence.

use crate::support::script::{script, Script};

mod schedule;

/// Consume a fixed suffix of 3..=998 at-most-four-byte ScriptNums.
/// Require strict ascent to one interior peak and strict descent afterward.
/// Return the canonical zero-based peak index and preserve both caller stacks.
pub fn verify_single_peak(width: u32) -> Script {
    assert!(
        (3..=998).contains(&width),
        "single peak supports 3..=998 values"
    );
    script! {
        { schedule::start() }
        for _ in 0..width - 2 {
            { schedule::strict_ascent() }
            OP_FROMALTSTACK
            // Once the ascent count is nonzero, every new edge must ascend.
            OP_2DUP OP_0NOTEQUAL OP_GREATERTHANOREQUAL OP_VERIFY
            OP_ADD OP_TOALTSTACK
        }
        { schedule::finish() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::test_helpers::{assert_clean_true, run_tapscript, scriptnum},
        support::{script::ScriptCompilation, tapscript::TapscriptProfile},
    };
    use bitcoin::ScriptBuf;
    use bitcoin_scriptexec::ExecError;

    mod baseline {
        use super::*;
        include!("../../../research/strict-signed-single-peak/baseline.rs");
    }

    mod fixture {
        include!("../../../research/strict-signed-single-peak/fixture.rs");
    }

    fn leaf(fragment: Script, expected: Option<usize>) -> ScriptBuf {
        let terminal = match expected {
            Some(peak) => script! { { peak } OP_EQUALVERIFY },
            None => script! { OP_DROP },
        };
        script! { { fragment } { terminal } OP_TRUE }.compile_with_policy()
    }

    fn host_peak(values: &[i64]) -> Option<usize> {
        (1..values.len() - 1).find(|&peak| {
            values[..=peak].windows(2).all(|pair| pair[0] < pair[1])
                && values[peak..].windows(2).all(|pair| pair[0] > pair[1])
        })
    }

    #[test]
    fn exhaustive_small_vectors_match_the_host_peak() {
        for width in 3u32..=6 {
            let leaves: Vec<_> = std::iter::once(None)
                .chain((1..width as usize - 1).map(Some))
                .map(|expected| {
                    [
                        leaf(verify_single_peak(width), expected),
                        leaf(baseline::branch_phase(width), expected),
                    ]
                })
                .collect();
            for mut word in 0..3u32.pow(width) {
                let values: Vec<_> = (0..width)
                    .map(|_| {
                        let value = i64::from(word % 3) - 1;
                        word /= 3;
                        value
                    })
                    .collect();
                let expected = host_peak(&values);
                let witness: Vec<_> = values.into_iter().map(scriptnum).collect();
                for checked in &leaves[expected.unwrap_or(0)] {
                    for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
                        let result = run_tapscript(checked.clone(), witness.clone(), profile);
                        assert_eq!(result.success, expected.is_some(), "{result}");
                        if expected.is_some() {
                            assert_clean_true(&result);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn signed_extremes_and_hostile_encodings_follow_the_contract() {
        let m = i64::from(i32::MAX);
        for fragment in [verify_single_peak(3), baseline::branch_phase(3)] {
            let checked = leaf(fragment, Some(1));
            let extremes = [-m, m, -m].into_iter().map(scriptnum).collect();
            assert_clean_true(&run_tapscript(
                checked.clone(),
                extremes,
                TapscriptProfile::Consensus,
            ));
            let mut alias = vec![vec![0x80], vec![1], vec![]];
            assert_clean_true(&run_tapscript(
                checked.clone(),
                alias.clone(),
                TapscriptProfile::Consensus,
            ));
            assert!(
                !run_tapscript(checked.clone(), alias.clone(), TapscriptProfile::Policy).success
            );
            alias[1] = vec![];
            assert!(!run_tapscript(checked.clone(), alias, TapscriptProfile::Consensus).success);
            let canonical = vec![vec![], vec![1], vec![]];
            for index in 0..3 {
                for bad in [scriptnum(m + 1), scriptnum(-m - 1), vec![0; 520]] {
                    let mut witness = canonical.clone();
                    witness[index] = bad;
                    assert!(
                        !run_tapscript(checked.clone(), witness, TapscriptProfile::Consensus)
                            .success
                    );
                }
            }
            for invalid in [canonical[1..].to_vec(), [vec![vec![]], canonical].concat()] {
                assert!(
                    !run_tapscript(checked.clone(), invalid, TapscriptProfile::Consensus).success
                );
            }
        }
    }

    #[test]
    fn an_ascent_count_alone_accepts_multiple_turns() {
        let unchecked = script! {
            { schedule::start() }
            for _ in 0..3 {
                { schedule::strict_ascent() } OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
            }
            { schedule::finish() }
        };
        let witness: Vec<_> = [0, 2, 1, 3, 0].into_iter().map(scriptnum).collect();
        assert_clean_true(&run_tapscript(
            leaf(unchecked, Some(2)),
            witness.clone(),
            TapscriptProfile::Consensus,
        ));
        assert!(
            !run_tapscript(
                leaf(verify_single_peak(5), None),
                witness,
                TapscriptProfile::Consensus,
            )
            .success
        );
    }

    #[test]
    fn exact_frontier_preserves_both_caller_stacks() {
        for (width, peak) in [(998, 1), (998, 996)] {
            let checked = leaf(verify_single_peak(width), Some(peak));
            let witness = fixture::values(width as usize, peak)
                .into_iter()
                .map(scriptnum)
                .collect();
            let result = run_tapscript(checked, witness, TapscriptProfile::Consensus);
            assert_clean_true(&result);
            assert_eq!(result.stats.max_nb_stack_items, 1000);
        }

        let width = 996;
        let peak = 497usize;
        let caller_leaf = script! {
            OP_TOALTSTACK
            { verify_single_peak(width) } { peak } OP_EQUALVERIFY
            OP_FROMALTSTACK 18 OP_EQUALVERIFY
            17 OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        let mut witness: Vec<_> = std::iter::once(17)
            .chain(fixture::values(width as usize, peak))
            .chain([18])
            .map(scriptnum)
            .collect();
        let result = run_tapscript(
            caller_leaf.clone(),
            witness.clone(),
            TapscriptProfile::Consensus,
        );
        assert_clean_true(&result);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        witness.insert(0, vec![19]);
        let result = run_tapscript(caller_leaf, witness, TapscriptProfile::Consensus);
        assert_eq!(result.error, Some(ExecError::StackSize));
        for width in [0, 2, 999] {
            assert!(std::panic::catch_unwind(|| verify_single_peak(width)).is_err());
        }
    }
}
