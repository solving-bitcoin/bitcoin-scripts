//! Split an exact signed sum into two ScriptNum operands.

use crate::support::script::{script, Script};

const BOUND: i64 = i32::MAX as i64;

/// Consume two at-most-four-byte signed ScriptNums. Return `residual class`,
/// where `class` is -1, 0, or 1 and the sum is `residual + class*i32::MAX`.
/// Both outputs are canonical numeric operands, and both caller stacks survive.
pub fn split_scriptnum_sum() -> Script {
    script! {
        OP_SIZE 4 OP_LESSTHANOREQUAL OP_VERIFY
        OP_SWAP OP_SIZE 4 OP_LESSTHANOREQUAL OP_VERIFY OP_SWAP
        OP_2DUP OP_ADD
        OP_SIZE 4 OP_LESSTHANOREQUAL OP_IF
            OP_NIP OP_NIP 0
        OP_ELSE
            // A wide sum implies that both operands have the same sign.
            // Drop its raw bytes before reading the sign of an operand.
            OP_DROP OP_DUP 0 OP_LESSTHAN
            OP_IF { -BOUND } -1 OP_ELSE { BOUND } 1 OP_ENDIF
            OP_TOALTSTACK OP_SUB OP_ADD OP_FROMALTSTACK
        OP_ENDIF
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
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    mod baseline {
        use super::*;
        include!("../../../research/exact-signed-sum-spill/baseline.rs");
    }

    mod fixture {
        use super::*;
        include!("../../../research/exact-signed-sum-spill/fixture.rs");
    }

    fn checked(split: Script, a: i64, b: i64) -> ScriptBuf {
        let (residual, class) = fixture::expected(a, b);
        script! {
            { split }
            { class } OP_EQUALVERIFY
            { residual } OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy()
    }

    fn check_pair(a: i64, b: i64, profile: TapscriptProfile) {
        for split in [split_scriptnum_sum(), baseline::precheck_headroom()] {
            let result = run_tapscript(
                checked(split, a, b),
                vec![scriptnum(a), scriptnum(b)],
                profile,
            );
            assert_clean_true(&result);
        }
    }

    #[test]
    fn signed_width_endpoints_and_both_overflow_directions() {
        let edges = [
            -BOUND,
            -BOUND + 1,
            -128,
            -1,
            0,
            1,
            127,
            128,
            BOUND - 1,
            BOUND,
        ];
        for a in edges {
            for b in edges {
                for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
                    check_pair(a, b, profile);
                }
            }
        }
    }

    #[test]
    fn deterministic_pairs_reconstruct_the_exact_host_sum() {
        let mut rng = StdRng::seed_from_u64(0x53_50_49_4c_4c);
        for _ in 0..256 {
            let a = i64::from(rng.next_u32() as i32).max(-BOUND);
            let b = i64::from(rng.next_u32() as i32).max(-BOUND);
            check_pair(a, b, TapscriptProfile::Consensus);
        }
    }

    #[test]
    fn rejects_overlong_operands_and_applies_numeric_alias_policy() {
        for split in [split_scriptnum_sum(), baseline::precheck_headroom()] {
            let leaf = checked(split, 0, 0);
            for malformed in [
                scriptnum(BOUND + 1),
                scriptnum(-BOUND - 1),
                vec![0, 0, 0, 0, 0x80],
                vec![0; 520],
            ] {
                for witness in [vec![malformed.clone(), vec![]], vec![vec![], malformed]] {
                    assert!(
                        !run_tapscript(leaf.clone(), witness, TapscriptProfile::Consensus).success
                    );
                }
            }
            for witness in [vec![vec![0x80], vec![]], vec![vec![], vec![0, 0]]] {
                assert_clean_true(&run_tapscript(
                    leaf.clone(),
                    witness.clone(),
                    TapscriptProfile::Consensus,
                ));
                assert!(!run_tapscript(leaf.clone(), witness, TapscriptProfile::Policy).success);
            }
            for count in [0, 1, 3] {
                assert!(
                    !run_tapscript(
                        leaf.clone(),
                        vec![vec![]; count],
                        TapscriptProfile::Consensus
                    )
                    .success
                );
            }
        }
    }

    #[test]
    fn compares_generated_pairs_as_numbers_after_lexicographic_routing() {
        let sums = [
            (-BOUND, -BOUND),
            (-BOUND, -1),
            (-BOUND, 0),
            (0, 0),
            (BOUND, 0),
            (BOUND, 1),
            (BOUND, 2),
            (BOUND, BOUND),
        ];
        for split in [split_scriptnum_sum(), baseline::precheck_headroom()] {
            let predicate = fixture::compare_sums(split);
            let leaves = [0, 1].map(|expected| {
                script! {
                    { predicate.clone() } { expected } OP_EQUALVERIFY OP_TRUE
                }
                .compile_with_policy()
            });
            for (a, b) in sums {
                for (c, d) in sums {
                    let witness = [a, b, c, d].into_iter().map(scriptnum).collect();
                    let result = run_tapscript(
                        leaves[usize::from(a + b < c + d)].clone(),
                        witness,
                        TapscriptProfile::Consensus,
                    );
                    assert_clean_true(&result);
                }
            }
        }
    }

    #[test]
    fn raw_wide_results_fail_numeric_order_and_clipping_loses_order() {
        let raw_order = script! {
            OP_ADD OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
            OP_LESSTHAN OP_VERIFY OP_TRUE
        }
        .compile_with_policy();
        let result = run_tapscript(
            raw_order,
            [BOUND, 1, BOUND, 2].into_iter().map(scriptnum).collect(),
            TapscriptProfile::Consensus,
        );
        assert!(!result.success);
        assert!(result.error.is_some());
        assert_eq!(
            (BOUND + 1).clamp(-BOUND, BOUND),
            (BOUND + 2).clamp(-BOUND, BOUND)
        );
    }

    #[test]
    fn preserves_both_caller_stacks_at_the_exact_wide_frontier() {
        let leaf = script! {
            OP_TOALTSTACK
            { split_scriptnum_sum() }
            -1 OP_EQUALVERIFY { -BOUND } OP_EQUALVERIFY
            OP_FROMALTSTACK 18 OP_EQUALVERIFY
            for _ in 0..993 { OP_DROP }
            17 OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        let mut witness = vec![scriptnum(17)];
        witness.extend((0..993).map(|_| vec![]));
        witness.extend([-BOUND, -BOUND, 18].into_iter().map(scriptnum));
        let result = run_tapscript(leaf.clone(), witness.clone(), TapscriptProfile::Consensus);
        assert_clean_true(&result);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        witness.insert(0, scriptnum(19));
        let result = run_tapscript(leaf, witness, TapscriptProfile::Consensus);
        assert_eq!(result.error, Some(ExecError::StackSize));
    }
}
