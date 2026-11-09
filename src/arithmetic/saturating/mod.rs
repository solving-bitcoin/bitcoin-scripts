//! Saturating arithmetic over four-byte ScriptNums.

use crate::{arithmetic::scriptint::MAX_SCRIPTNUM, support::script::*};

const MAX: i32 = MAX_SCRIPTNUM as i32;

/// Replace `... lhs rhs` with the canonical sum clamped to `[-MAX, MAX]`.
///
/// Both operands must be at-most-four-byte ScriptNums. Their encoding follows
/// the caller's numeric profile. Both caller stacks are preserved for the exact
/// two-item suffix. The fragment needs zero hints and peaks at four items plus
/// preserved state across both stacks.
pub fn saturating_add() -> Script {
    script! {
        OP_DUP 0 OP_LESSTHAN
        OP_IF
            // For a negative rhs, lhs must be at least -MAX - rhs.
            OP_TUCK {-MAX} OP_SWAP OP_SUB OP_MAX
        OP_ELSE
            OP_TUCK {MAX} OP_SWAP OP_SUB OP_MIN
        OP_ENDIF
        OP_ADD
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::test_helpers::{assert_clean_true, run_tapscript, scriptnum},
        support::tapscript::TapscriptProfile,
    };
    use bitcoin_scriptexec::ExecError;

    mod baseline {
        use crate::support::script::*;
        include!("../../../research/scriptnum-saturation/baseline.rs");
    }

    const BOUND: i64 = MAX as i64;
    const PROFILE: TapscriptProfile = TapscriptProfile::Consensus;

    fn checked(fragment: Script, expected: i64) -> bitcoin::ScriptBuf {
        script! {{fragment} {scriptnum(expected)} OP_EQUALVERIFY OP_TRUE}.compile_with_policy()
    }

    #[test]
    fn compares_both_schedules_against_integer_add_and_clamp() {
        let values = [
            -BOUND,
            1 - BOUND,
            -65536,
            -256,
            -128,
            -127,
            -1,
            0,
            1,
            127,
            128,
            256,
            65536,
            BOUND - 1,
            BOUND,
        ];
        for lhs in values {
            for rhs in values {
                let expected = (lhs + rhs).clamp(-BOUND, BOUND);
                let witness = vec![scriptnum(lhs), scriptnum(rhs)];
                for fragment in [saturating_add(), baseline::saturating_add_by_width()] {
                    assert_clean_true(&run_tapscript(
                        checked(fragment, expected),
                        witness.clone(),
                        PROFILE,
                    ));
                }
            }
        }
    }

    #[test]
    fn rejects_overlong_and_misshapen_witnesses_and_canonicalizes_output() {
        for fragment in [saturating_add(), baseline::saturating_add_by_width()] {
            let script = checked(fragment, 0);
            for position in 0..2 {
                for (bad, error) in [
                    (scriptnum(BOUND + 1), ExecError::ScriptIntNumericOverflow),
                    (scriptnum(-BOUND - 1), ExecError::ScriptIntNumericOverflow),
                    (vec![0; 5], ExecError::ScriptIntNumericOverflow),
                    (vec![0; 521], ExecError::PushSize),
                ] {
                    let mut witness = vec![vec![], vec![]];
                    witness[position] = bad;
                    let result = run_tapscript(script.clone(), witness, PROFILE);
                    assert!(!result.success);
                    assert_eq!(result.error, Some(error));
                }
                for alias in [vec![0], vec![0x80], vec![0, 0x80]] {
                    let mut witness = vec![vec![], vec![]];
                    witness[position] = alias;
                    assert_clean_true(&run_tapscript(script.clone(), witness, PROFILE));
                }
            }
            for length in [0, 1, 3] {
                assert!(!run_tapscript(script.clone(), vec![vec![]; length], PROFILE).success);
            }
        }
    }

    #[test]
    fn preserves_caller_stacks_at_exact_peak() {
        let fragment = saturating_add();
        let script = script! {OP_TOALTSTACK {fragment} OP_FROMALTSTACK}.compile_with_policy();
        let prefix = vec![vec![0x91, 0x36]; 995];
        let alt = vec![0x82, 0x42];
        let mut witness = prefix.clone();
        witness.extend([scriptnum(-BOUND), scriptnum(-1), alt.clone()]);
        let result = run_tapscript(script.clone(), witness.clone(), PROFILE);
        assert_eq!(result.error, None, "{result}");
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        let actual: Vec<_> = (0..result.final_stack.len())
            .map(|i| result.final_stack.get(i))
            .collect();
        assert_eq!(actual, [prefix, vec![scriptnum(-BOUND), alt]].concat());
        witness.insert(0, vec![]);
        assert_eq!(
            run_tapscript(script, witness, PROFILE).error,
            Some(ExecError::StackSize)
        );
    }

    #[test]
    fn post_add_numeric_clamp_fails_and_saturation_is_order_sensitive() {
        let post_add = script! {OP_ADD {MAX} OP_MIN {-MAX} OP_MAX};
        assert_eq!(
            run_tapscript(
                checked(post_add, BOUND),
                vec![scriptnum(BOUND), scriptnum(1)],
                PROFILE
            )
            .error,
            Some(ExecError::ScriptIntNumericOverflow)
        );

        let add = saturating_add();
        let left = script! {OP_ROT OP_ROT {add.clone()} {add.clone()}};
        let right = script! {{add.clone()} {add}};
        let witness = vec![scriptnum(BOUND), scriptnum(1), scriptnum(-1)];
        assert_clean_true(&run_tapscript(
            checked(left, BOUND - 1),
            witness.clone(),
            PROFILE,
        ));
        assert_clean_true(&run_tapscript(checked(right, BOUND), witness, PROFILE));
    }
}
