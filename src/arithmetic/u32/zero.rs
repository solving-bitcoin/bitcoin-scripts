//! Checked zero predicate for a four-byte u32 word.

use crate::support::script::*;

/// Consume the top u32 word and return whether it is zero.
///
/// The input is four byte-valued limbs, most significant byte first. Each
/// limb is checked in `0..=255` before its zero predicate is accumulated. The
/// result is one numeric Boolean ScriptNum.
pub fn u32_iszero() -> Script {
    script! {
        for _ in 0..4 {
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP 256 OP_LESSTHAN OP_VERIFY
            OP_NOT OP_TOALTSTACK
        }
        OP_FROMALTSTACK
        OP_FROMALTSTACK OP_BOOLAND
        OP_FROMALTSTACK OP_BOOLAND
        OP_FROMALTSTACK OP_BOOLAND
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::u32::stack::u32_push,
        support::{
            execution::{execute_script, execute_script_with_inputs_strict},
            script::script,
        },
    };
    use bitcoin_scriptexec::ExecError;

    fn check_checked_zero_contract(predicate: Script) -> Result<(), String> {
        let zero = execute_script_with_inputs_strict(
            script! { { predicate.clone() } OP_1 OP_EQUAL },
            vec![vec![]; 4],
        );
        if !zero.success || zero.final_stack.len() != 1 {
            return Err(format!("zero control failed: {zero}"));
        }

        let cleanup_control = execute_script_with_inputs_strict(
            script! { { predicate.clone() } OP_DROP OP_TRUE },
            vec![vec![]; 4],
        );
        if !cleanup_control.success {
            return Err(format!(
                "valid OP_DROP OP_TRUE control failed: {cleanup_control}"
            ));
        }

        for position in 0..4 {
            let mut nonzero = vec![vec![]; 4];
            nonzero[position] = vec![1];
            let result = execute_script_with_inputs_strict(
                script! { { predicate.clone() } OP_0 OP_EQUAL },
                nonzero,
            );
            if !result.success || result.final_stack.len() != 1 {
                return Err(format!("nonzero limb at {position} failed: {result}"));
            }

            for invalid in [-1, 256] {
                let mut malformed = vec![vec![]; 4];
                malformed[position] = if invalid < 0 {
                    vec![0x81]
                } else {
                    vec![0x00, 0x01]
                };
                let result = execute_script_with_inputs_strict(
                    script! { { predicate.clone() } OP_DROP OP_TRUE },
                    malformed,
                );
                if result.success || result.error != Some(ExecError::Verify) {
                    return Err(format!(
                        "invalid limb {invalid} at position {position}: expected Verify, got {result}"
                    ));
                }
            }
        }

        for position in 0..4 {
            let mut oversized = vec![vec![]; 4];
            oversized[position] = vec![0, 0, 0, 0, 1];
            let result = execute_script_with_inputs_strict(
                script! { { predicate.clone() } OP_DROP OP_TRUE },
                oversized,
            );
            if result.success || result.error != Some(ExecError::ScriptIntNumericOverflow) {
                return Err(format!(
                    "five-byte limb at position {position}: expected ScriptIntNumericOverflow, got {result}"
                ));
            }
        }

        Ok(())
    }

    #[test]
    fn recognizes_zero_and_nonzero_words() {
        for (word, expected) in [
            (0, true),
            (1, false),
            (0x0000_0100, false),
            (0x0001_0000, false),
            (0x0100_0000, false),
            (0x8000_0000, false),
            (u32::MAX, false),
        ] {
            let result = execute_script(script! {
                { u32_push(word) }
                { u32_iszero() }
                { expected as u32 } OP_EQUAL
            });
            assert!(result.success, "word={word:#010x}: {result}");
        }
    }

    #[test]
    fn satisfies_checked_zero_contract_for_runtime_limbs() {
        assert_eq!(check_checked_zero_contract(u32_iszero()), Ok(()));

        // This validation-bypass mutation must fail the same contract check:
        // it omits both byte-range VERIFY operations from each iteration.
        let mutation = script! {
            for _ in 0..4 { OP_NOT OP_TOALTSTACK }
            OP_FROMALTSTACK
            OP_FROMALTSTACK OP_BOOLAND
            OP_FROMALTSTACK OP_BOOLAND
            OP_FROMALTSTACK OP_BOOLAND
        };
        let mutation = check_checked_zero_contract(mutation);
        assert!(
            mutation
                .as_ref()
                .is_err_and(|error| error.contains("invalid limb -1 at position 0")),
            "validation-bypass mutation escaped the malformed-limb assertion: {mutation:?}"
        );
    }

    #[test]
    fn rejects_non_byte_limbs() {
        for position in 0..4 {
            let mut input = vec![0; 4];
            input[position] = if position % 2 == 0 { -1 } else { 256 };
            let result = execute_script(script! {
                for byte in input { { byte } }
                { u32_iszero() }
                OP_DROP OP_TRUE
            });
            assert!(!result.success, "accepted invalid byte at {position}");
        }

        for position in 0..4 {
            let mut witness = vec![vec![]; 4];
            witness[position] = vec![0, 0, 0, 0, 1];
            let result = execute_script_with_inputs_strict(
                script! {
                    { u32_iszero() }
                    OP_DROP OP_TRUE
                },
                witness,
            );
            assert!(!result.success, "accepted oversized byte at {position}");
        }
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let result = execute_script(script! {
            OP_9 OP_TOALTSTACK
            77
            { u32_push(0) }
            { u32_iszero() }
            1 OP_EQUALVERIFY
            77 OP_EQUALVERIFY
            OP_FROMALTSTACK 9 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "preserved state changed: {result}");
    }

    #[test]
    fn respects_combined_stack_frontier() {
        let maximum = execute_script_with_inputs_strict(
            script! {
                { u32_iszero() }
                OP_DROP
                for _ in 0..994 { OP_DROP }
                OP_TRUE
            },
            vec![vec![]; 994 + 4],
        );
        assert!(maximum.success, "maximum preserved state failed: {maximum}");
        assert_eq!(maximum.stats.max_nb_stack_items, 1000);

        let over_budget =
            execute_script_with_inputs_strict(script! { { u32_iszero() } }, vec![vec![]; 995 + 4]);
        assert_eq!(over_budget.error, Some(ExecError::StackSize));
    }
}
