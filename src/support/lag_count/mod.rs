//! Count exact byte matches at a fixed non-wrapping offset.

use super::script::{script, Script};

/// Consume a vector of `width` opaque items and return the number of
/// `x[i] == x[i+lag]` comparisons that match. There is no wraparound.
/// Both caller stacks are preserved. Width is 2..=999 and lag is 1..width.
pub fn count_opaque_lag_matches(width: u32, lag: u32) -> Script {
    assert!(
        (2..=999).contains(&width),
        "lag match count supports 2..=999 items"
    );
    assert!((1..width).contains(&lag), "lag must be in 1..width");
    script! {
        // The first comparison leaves the count without a separate zero slot.
        { lag } OP_PICK OP_EQUAL
        for _ in 1..width - lag {
            { lag + 1 } OP_PICK OP_ROT OP_EQUAL OP_ADD
        }
        OP_TOALTSTACK
        for _ in 0..lag { OP_DROP }
        OP_FROMALTSTACK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{
        script::ScriptCompilation,
        tapscript::{execute_tapscript, TapscriptProfile},
    };
    use bitcoin::ScriptBuf;
    use bitcoin_scriptexec::ExecError;

    mod baseline {
        use super::*;
        include!("../../../research/opaque-lag-match-count/baseline.rs");
    }

    mod fixture {
        include!("../../../research/opaque-lag-match-count/fixture.rs");
    }

    fn leaf(fragment: Script, expected: u32) -> ScriptBuf {
        script! { { fragment } { expected } OP_EQUALVERIFY OP_TRUE }.compile_with_policy()
    }

    #[test]
    fn exhaustive_short_binary_vectors_match_the_host_at_every_lag() {
        for width in 2..=8 {
            for lag in 1..width {
                let leaves: Vec<_> = (0..=width - lag)
                    .map(|count| {
                        [
                            count_opaque_lag_matches(width, lag),
                            baseline::eager_destructive(width, lag),
                            baseline::nondestructive(width, lag),
                        ]
                        .map(|fragment| leaf(fragment, count))
                    })
                    .collect();
                for mask in 0u32..1 << width {
                    let witness: Vec<_> = (0..width)
                        .map(|i| {
                            if mask & (1 << i) == 0 {
                                vec![]
                            } else {
                                vec![0]
                            }
                        })
                        .collect();
                    let count = fixture::host_count(&witness, lag);
                    for checked in &leaves[count as usize] {
                        for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
                            assert_eq!(
                                execute_tapscript(checked.clone(), witness.clone(), profile)
                                    .accepted(),
                                Some(true),
                                "width {width}, lag {lag}, mask {mask}, {profile:?}",
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn rejects_wrong_count_and_malformed_suffix() {
        let width = 128;
        let lag = 28;
        let witness = fixture::periodic(width);
        let expected = fixture::host_count(&witness, lag);
        assert_eq!(expected, 100);
        let fragment = count_opaque_lag_matches(width, lag);
        let checked = leaf(fragment.clone(), expected);
        assert_eq!(
            execute_tapscript(
                checked.clone(),
                witness.clone(),
                TapscriptProfile::Consensus
            )
            .accepted(),
            Some(true)
        );
        assert_eq!(
            execute_tapscript(
                leaf(fragment, expected - 1),
                witness.clone(),
                TapscriptProfile::Consensus,
            )
            .accepted(),
            Some(false)
        );
        let mut extra = witness.clone();
        extra.insert(0, vec![0x42]);
        let mut different = witness.clone();
        different[7].push(0);
        for invalid in [extra, different, witness[1..].to_vec(), vec![]] {
            assert_eq!(
                execute_tapscript(checked.clone(), invalid, TapscriptProfile::Consensus).accepted(),
                Some(false)
            );
        }
    }

    #[test]
    fn opaque_items_obey_the_local_element_size_limits() {
        let checked = leaf(count_opaque_lag_matches(4, 2), 1);
        let mut witness = vec![vec![], vec![0xa5; 520], vec![0x80], vec![0xa5; 520]];
        assert_eq!(
            execute_tapscript(
                checked.clone(),
                witness.clone(),
                TapscriptProfile::Consensus
            )
            .accepted(),
            Some(true)
        );
        assert_eq!(
            execute_tapscript(checked.clone(), witness.clone(), TapscriptProfile::Policy)
                .accepted(),
            Some(false)
        );
        witness[1].push(0);
        assert_eq!(
            execute_tapscript(checked, witness, TapscriptProfile::Consensus).accepted(),
            Some(false)
        );
    }

    #[test]
    fn deferred_count_reaches_the_exact_frontier_and_preserves_caller_state() {
        let lag = 27;
        for width in [998, 999] {
            let witness = fixture::periodic(width);
            let count = fixture::host_count(&witness, lag);
            for (fragment, peak) in [
                (count_opaque_lag_matches(width, lag), Some(width + 1)),
                (
                    baseline::eager_destructive(width, lag),
                    (width == 998).then_some(1000),
                ),
                (baseline::nondestructive(width, lag), None),
            ] {
                let result = execute_tapscript(
                    leaf(fragment, count),
                    witness.clone(),
                    TapscriptProfile::Consensus,
                );
                assert_eq!(result.accepted(), Some(peak.is_some()));
                let run = result.execution().unwrap();
                if let Some(peak) = peak {
                    assert_eq!(run.stats.max_nb_stack_items, peak as usize);
                } else {
                    assert_eq!(run.error, Some(ExecError::StackSize));
                }
            }
        }

        let width = 997;
        let mut witness = vec![vec![17]];
        witness.extend(fixture::periodic(width));
        let count = fixture::host_count(&witness[1..], lag);
        witness.push(vec![18]);
        let caller = script! {
            OP_TOALTSTACK
            { count_opaque_lag_matches(width, lag) } { count } OP_EQUALVERIFY
            OP_FROMALTSTACK 18 OP_EQUALVERIFY
            17 OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        let result =
            execute_tapscript(caller.clone(), witness.clone(), TapscriptProfile::Consensus);
        assert_eq!(result.accepted(), Some(true));
        assert_eq!(result.execution().unwrap().stats.max_nb_stack_items, 1000);
        witness.insert(0, vec![19]);
        let result = execute_tapscript(caller, witness, TapscriptProfile::Consensus);
        assert_eq!(
            result.execution().unwrap().error,
            Some(ExecError::StackSize)
        );

        for (width, lag) in [(0, 1), (1, 1), (2, 0), (2, 2), (1000, 1)] {
            assert!(std::panic::catch_unwind(|| count_opaque_lag_matches(width, lag)).is_err());
        }
    }
}
