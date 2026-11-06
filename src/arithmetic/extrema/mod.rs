//! Compute both extrema of canonical signed ScriptNums.

use crate::{
    arithmetic::scriptint::verify_canonical,
    support::script::{script, Script},
};

mod schedule;

/// Consume 1..=997 canonical at-most-four-byte ScriptNums. Return the
/// canonical minimum followed by the maximum. Both caller stacks survive.
pub fn signed_min_max(width: u32) -> Script {
    assert!(
        (1..=997).contains(&width),
        "signed extrema supports 1..=997 values"
    );
    script! {
        if width == 1 {
            { schedule::verify_input() } OP_DUP
        } else {
            { schedule::order_pair() }
            for _ in 0..(width - 2) / 2 {
                OP_2SWAP { schedule::order_pair() }
                // Compare the pair maximum only with max, and its minimum only with min.
                OP_ROT OP_MAX OP_TOALTSTACK OP_MIN OP_FROMALTSTACK
            }
            if width % 2 != 0 {
                { schedule::update_single() }
            }
        }
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
        include!("../../../research/paired-signed-extrema/baseline.rs");
    }

    mod fixture {
        include!("../../../research/paired-signed-extrema/fixture.rs");
    }

    fn variants(width: u32) -> [Script; 2] {
        [signed_min_max(width), baseline::streaming(width)]
    }

    fn checked(fragment: Script, min: i64, max: i64) -> ScriptBuf {
        script! {
            { fragment } { max } OP_EQUALVERIFY { min } OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy()
    }

    #[test]
    fn every_short_ternary_vector_matches_both_host_extrema() {
        for width in 1u32..=6 {
            let leaves = variants(width).map(|fragment| {
                script! {
                    { fragment } OP_ROT OP_EQUALVERIFY OP_EQUALVERIFY OP_TRUE
                }
                .compile_with_policy()
            });
            for mut code in 0..3u32.pow(width) {
                let values: Vec<_> = (0..width)
                    .map(|_| {
                        let value = i64::from(code % 3) - 1;
                        code /= 3;
                        value
                    })
                    .collect();
                let min = *values.iter().min().unwrap();
                let max = *values.iter().max().unwrap();
                let witness: Vec<_> = [min, max]
                    .into_iter()
                    .chain(values)
                    .map(scriptnum)
                    .collect();
                for leaf in &leaves {
                    let result =
                        run_tapscript(leaf.clone(), witness.clone(), TapscriptProfile::Consensus);
                    assert_clean_true(&result);
                }
            }
        }
    }

    #[test]
    fn signed_endpoints_and_numeric_aliases_are_checked() {
        let m = i64::from(i32::MAX);
        for fragment in variants(4) {
            let checked_extremes = checked(fragment.clone(), -m, m);
            for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
                let witness = [-m, m, m, -m].into_iter().map(scriptnum).collect();
                assert_clean_true(&run_tapscript(checked_extremes.clone(), witness, profile));
            }
            let zero = checked(fragment, 0, 0);
            for index in 0..4 {
                for bad in [
                    vec![0],
                    vec![0x80],
                    vec![0, 0],
                    scriptnum(m + 1),
                    scriptnum(-m - 1),
                    vec![0; 520],
                ] {
                    let mut witness = vec![vec![]; 4];
                    witness[index] = bad;
                    assert!(
                        !run_tapscript(zero.clone(), witness, TapscriptProfile::Consensus).success
                    );
                }
            }
            for count in [0, 3, 5] {
                assert!(
                    !run_tapscript(
                        zero.clone(),
                        vec![vec![]; count],
                        TapscriptProfile::Consensus
                    )
                    .success
                );
            }
        }
    }

    #[test]
    fn reconstructing_max_from_the_sum_can_fail_on_valid_inputs() {
        let m = i64::from(i32::MAX);
        let weak = script! {
            OP_2DUP OP_MIN OP_TOALTSTACK
            OP_ADD OP_FROMALTSTACK OP_SUB
            { m } OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        let witness = [m - 1, m].into_iter().map(scriptnum).collect::<Vec<_>>();
        let result = run_tapscript(weak, witness.clone(), TapscriptProfile::Consensus);
        assert!(!result.success);
        assert!(result.error.is_some());
        assert_clean_true(&run_tapscript(
            checked(signed_min_max(2), m - 1, m),
            witness,
            TapscriptProfile::Consensus,
        ));
    }

    #[test]
    fn standalone_and_caller_frontiers_are_observable() {
        let m = i64::from(i32::MAX);
        for fragment in variants(997) {
            let witness = fixture::values(997).into_iter().map(scriptnum).collect();
            let result = run_tapscript(
                checked(fragment, -m, m),
                witness,
                TapscriptProfile::Consensus,
            );
            assert_clean_true(&result);
            assert_eq!(result.stats.max_nb_stack_items, 1000);
        }
        let caller = script! {
            OP_TOALTSTACK
            { signed_min_max(995) } { m } OP_EQUALVERIFY { -m } OP_EQUALVERIFY
            OP_FROMALTSTACK 18 OP_EQUALVERIFY
            17 OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        let mut witness = std::iter::once(17)
            .chain(fixture::values(995))
            .chain([18])
            .map(scriptnum)
            .collect::<Vec<_>>();
        let result = run_tapscript(caller.clone(), witness.clone(), TapscriptProfile::Consensus);
        assert_clean_true(&result);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        witness.insert(0, vec![19]);
        let result = run_tapscript(caller, witness, TapscriptProfile::Consensus);
        assert_eq!(result.error, Some(ExecError::StackSize));
        for width in [0, 998] {
            assert!(std::panic::catch_unwind(|| signed_min_max(width)).is_err());
        }
    }
}
