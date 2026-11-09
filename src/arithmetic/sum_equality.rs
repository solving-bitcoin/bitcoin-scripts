//! Exact equality of two signed ScriptNum sums.

use crate::support::script::*;

/// Consume `... a b c d` and verify `a + b == c + d` over the integers.
///
/// Each input is an at-most-four-byte ScriptNum. The input encoding rules are
/// those of the caller's numeric profile. Both sums use their canonical
/// encodings for byte equality, including when either sum needs five bytes.
/// Preserves both caller stacks for an exact four-item suffix; needs no hints.
pub fn verify_equal_sums() -> Script {
    script! {
        OP_ADD OP_TOALTSTACK
        OP_ADD OP_FROMALTSTACK
        OP_EQUALVERIFY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::{
            scriptint::MAX_SCRIPTNUM,
            test_helpers::{assert_clean_true, run_tapscript, scriptnum},
        },
        support::tapscript::TapscriptProfile,
    };
    use bitcoin_scriptexec::ExecError;

    mod baseline {
        use crate::support::script::*;
        include!("../../research/wide-scriptnum-equality/baseline.rs");
    }

    const MAX: i64 = MAX_SCRIPTNUM as i64;
    const RADIX: i64 = 1 << 30;

    fn witness(operands: [i64; 4]) -> Vec<Vec<u8>> {
        operands.into_iter().map(scriptnum).collect()
    }

    fn complete(fragment: Script) -> bitcoin::ScriptBuf {
        script! {{fragment} OP_TRUE}.compile_with_policy()
    }

    #[test]
    fn matches_exact_integer_oracle_across_sign_and_carry_boundaries() {
        let cases = [
            -MAX,
            -RADIX - 1,
            -RADIX,
            -RADIX + 1,
            -1,
            0,
            1,
            RADIX - 1,
            RADIX,
            RADIX + 1,
            MAX,
        ];
        let scripts = [
            complete(verify_equal_sums()),
            complete(baseline::verify_equal_sums_with_limbs()),
        ];
        for a in cases {
            for b in cases {
                for c in cases {
                    for d in cases {
                        let operands = [a, b, c, d];
                        for script in &scripts {
                            let result = run_tapscript(
                                script.clone(),
                                witness(operands),
                                TapscriptProfile::Consensus,
                            );
                            assert_eq!(result.success, a + b == c + d, "{operands:?}: {result}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn rejects_malformed_witnesses_and_leaves_alias_rules_to_numeric_profile() {
        let scripts = [
            complete(verify_equal_sums()),
            complete(baseline::verify_equal_sums_with_limbs()),
        ];
        for script in scripts {
            for position in 0..4 {
                for (bad, error) in [
                    (scriptnum(MAX + 1), ExecError::ScriptIntNumericOverflow),
                    (scriptnum(-MAX - 1), ExecError::ScriptIntNumericOverflow),
                    (vec![0; 5], ExecError::ScriptIntNumericOverflow),
                    (vec![0; 521], ExecError::PushSize),
                ] {
                    let mut items = witness([0, 0, 0, 0]);
                    items[position] = bad;
                    let result = run_tapscript(script.clone(), items, TapscriptProfile::Consensus);
                    assert!(!result.success);
                    assert_eq!(result.error, Some(error));
                }
                for alias in [vec![0], vec![0x80], vec![0, 0x80]] {
                    let mut items = witness([0, 0, 0, 0]);
                    items[position] = alias;
                    assert_clean_true(&run_tapscript(
                        script.clone(),
                        items.clone(),
                        TapscriptProfile::Consensus,
                    ));
                    assert_eq!(
                        run_tapscript(script.clone(), items, TapscriptProfile::Policy).error,
                        Some(ExecError::MinimalData)
                    );
                }
            }
            for length in [0, 1, 2, 3, 5] {
                let result = run_tapscript(
                    script.clone(),
                    vec![vec![]; length],
                    TapscriptProfile::Consensus,
                );
                assert!(!result.success, "accepted {length} witness items");
            }
        }
    }

    #[test]
    fn raw_equality_handles_wide_sums_and_numeric_equality_rejects_positive_overflow() {
        let raw = complete(verify_equal_sums());
        let numeric = script! {
            OP_ADD OP_TOALTSTACK OP_ADD OP_FROMALTSTACK OP_NUMEQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        for value in [MAX, -MAX] {
            assert_clean_true(&run_tapscript(
                raw.clone(),
                witness([value; 4]),
                TapscriptProfile::Consensus,
            ));
        }
        assert_eq!(
            run_tapscript(numeric, witness([MAX; 4]), TapscriptProfile::Consensus).error,
            Some(ExecError::ScriptIntNumericOverflow)
        );
    }

    #[test]
    fn preserves_both_caller_stacks_at_the_combined_limit() {
        let script = script! {
            OP_TOALTSTACK
            {verify_equal_sums()}
            OP_FROMALTSTACK
        }
        .compile_with_policy();
        let prefix = vec![vec![0x81, 0x73]; 995];
        let alt = vec![0x42, 0x91];
        let mut input = prefix.clone();
        input.extend(witness([MAX, MAX, MAX, MAX]));
        input.push(alt.clone());
        let result = run_tapscript(script.clone(), input.clone(), TapscriptProfile::Consensus);
        assert_eq!(result.error, None, "{result}");
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        let actual: Vec<_> = (0..result.final_stack.len())
            .map(|i| result.final_stack.get(i))
            .collect();
        assert_eq!(actual, [prefix, vec![alt]].concat());
        input.insert(0, vec![]);
        assert_eq!(
            run_tapscript(script, input, TapscriptProfile::Consensus).error,
            Some(ExecError::StackSize)
        );
    }
}
