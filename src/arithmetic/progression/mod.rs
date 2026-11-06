//! Exact signed ScriptNum arithmetic-progression verification.

use crate::support::script::{script, Script};

/// Consume a fixed suffix of 3 through 998 at-most-four-byte ScriptNums.
/// Verify that every adjacent signed difference is the same. Both caller
/// stacks are preserved, and success leaves no result item.
pub fn verify_arithmetic_progression(count: u32) -> Script {
    assert!(
        (3..=998).contains(&count),
        "arithmetic progression supports 3..=998 values"
    );
    script! {
        OP_SIZE 4 OP_LESSTHANOREQUAL OP_VERIFY
        OP_SWAP OP_SIZE 4 OP_LESSTHANOREQUAL OP_VERIFY
        OP_TUCK OP_SWAP OP_SUB
        for _ in 0..count - 2 {
            // Bring the next unvalidated value above the saved raw step.
            OP_ROT OP_SIZE 4 OP_LESSTHANOREQUAL OP_VERIFY
            OP_TUCK 3 OP_ROLL OP_SUB
            OP_OVER OP_EQUALVERIFY
        }
        OP_2DROP
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
        include!("../../../research/signed-arithmetic-progression/baseline.rs");
    }

    const MAX: i64 = i32::MAX as i64;
    const MIN: i64 = -MAX;

    fn leaf(fragment: Script) -> ScriptBuf {
        script! { { fragment } OP_TRUE }.compile_with_policy()
    }

    fn comparable_leaves(count: u32) -> [ScriptBuf; 2] {
        [
            verify_arithmetic_progression(count),
            baseline::cross_sums(count),
        ]
        .map(leaf)
    }

    fn check(leaves: &[ScriptBuf; 2], values: &[i64], expected: bool) {
        for leaf in leaves {
            for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
                let witness = values.iter().copied().map(scriptnum).collect();
                let result = run_tapscript(leaf.clone(), witness, profile);
                assert_eq!(
                    result.success, expected,
                    "{values:?}, {profile:?}: {result}"
                );
                if expected {
                    assert_clean_true(&result);
                }
            }
        }
    }

    #[test]
    fn exhaustive_short_triples_match_the_host_predicate() {
        let leaves = comparable_leaves(3);
        for left in -8..=8 {
            for mid in -8..=8 {
                for right in -8..=8 {
                    check(&leaves, &[left, mid, right], left + right == 2 * mid);
                }
            }
        }
    }

    #[test]
    fn signed_boundaries_and_every_long_position_match_exact_arithmetic() {
        let triples = comparable_leaves(3);
        for (values, expected) in [
            ([MAX, MAX, MAX], true),
            ([MIN, MIN, MIN], true),
            ([MIN, 0, MAX], true),
            ([MAX, 0, MIN], true),
            ([MAX, MIN, MAX], false),
            ([MIN, MAX, MIN], false),
            ([MAX - 2, MAX - 1, MAX], true),
            ([MIN + 2, MIN + 1, MIN], true),
        ] {
            check(&triples, &values, expected);
        }
        let progression: Vec<_> = (0..32).map(|i| MIN + i * 71_390_911).collect();
        let long = comparable_leaves(32);
        check(&long, &progression, true);
        for index in 0..progression.len() {
            let mut hostile = progression.clone();
            hostile[index] += 1;
            check(&long, &hostile, false);
        }
    }

    #[test]
    fn hostile_encoding_and_exact_suffix_boundaries() {
        let ordinary = vec![vec![]; 4];
        for check in [verify_arithmetic_progression(4), baseline::cross_sums(4)] {
            let leaf = leaf(check);
            for index in 0..ordinary.len() {
                for malformed in [
                    scriptnum(MAX + 1),
                    scriptnum(MIN - 1),
                    vec![0, 0, 0, 0, 0x80],
                    vec![0; 520],
                ] {
                    let mut witness = ordinary.clone();
                    witness[index] = malformed;
                    assert!(
                        !run_tapscript(leaf.clone(), witness, TapscriptProfile::Consensus).success
                    );
                }
                for alias in [vec![0], vec![0x80], vec![0, 0, 0, 0x80]] {
                    let mut witness = ordinary.clone();
                    witness[index] = alias;
                    assert_clean_true(&run_tapscript(
                        leaf.clone(),
                        witness.clone(),
                        TapscriptProfile::Consensus,
                    ));
                    assert!(
                        !run_tapscript(leaf.clone(), witness, TapscriptProfile::Policy).success
                    );
                }
            }
            for size in [0, 3, 5] {
                assert!(
                    !run_tapscript(
                        leaf.clone(),
                        vec![vec![]; size],
                        TapscriptProfile::Consensus,
                    )
                    .success
                );
            }
        }
    }

    #[test]
    fn caller_stacks_and_exact_combined_frontier() {
        let caller = script! {
            OP_TOALTSTACK
            { verify_arithmetic_progression(996) }
            OP_FROMALTSTACK 18 OP_EQUALVERIFY
            17 OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        let mut witness = vec![vec![17]];
        witness.extend((0..996).map(|_| vec![]));
        witness.push(vec![18]);
        let result = run_tapscript(caller.clone(), witness.clone(), TapscriptProfile::Consensus);
        assert_clean_true(&result);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        witness.insert(0, vec![19]);
        let result = run_tapscript(caller, witness, TapscriptProfile::Consensus);
        assert_eq!(result.error, Some(ExecError::StackSize));

        let frontier = run_tapscript(
            leaf(verify_arithmetic_progression(998)),
            vec![vec![]; 998],
            TapscriptProfile::Consensus,
        );
        assert_clean_true(&frontier);
        assert_eq!(frontier.stats.max_nb_stack_items, 1000);
        for unsupported in [0, 2, 999] {
            assert!(
                std::panic::catch_unwind(|| verify_arithmetic_progression(unsupported)).is_err()
            );
        }
    }

    #[test]
    fn numeric_comparison_rejects_equal_wide_positive_cross_sums() {
        let numeric = script! {
            OP_ROT OP_ADD
            OP_SWAP OP_DUP OP_ADD
            OP_NUMEQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        let result = run_tapscript(
            numeric,
            vec![scriptnum(MAX); 3],
            TapscriptProfile::Consensus,
        );
        assert!(!result.success);
        assert!(result.error.is_some());
    }
}
