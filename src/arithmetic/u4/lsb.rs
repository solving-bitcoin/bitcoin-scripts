//! Batched least-significant-bit projection for range-checked u4 limbs.

use super::stack::u4_drop;
use crate::support::script::*;

/// Persistent items used by the nibble-LSB lookup table.
pub const U4_LSB_TABLE_ITEMS: u32 = 16;

/// Largest batch that fits the 1,000-item stack limit without unrelated state.
pub const U4_LSB_MAX_BATCH: u32 = 1_000 - U4_LSB_TABLE_ITEMS - 2;

fn push_lsb_table() -> Script {
    script! {
        for value in (0..U4_LSB_TABLE_ITEMS).rev() {
            { value & 1 }
        }
    }
}

/// Consume range-checked nibbles and replace each with its least-significant bit.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
/// on top. After: `preserved | lsb[0] | ... | lsb[n-1]`, with the last output
/// on top. Every input is range-checked before it indexes the table.
pub fn u4_nibbles_to_lsb(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_LSB_MAX_BATCH,
        "nibble-LSB batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        { push_lsb_table() }
        for _ in 0..nibble_count {
            { U4_LSB_TABLE_ITEMS } OP_ROLL
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            OP_PICK OP_TOALTSTACK
        }
        { u4_drop(U4_LSB_TABLE_ITEMS) }
        for _ in 0..nibble_count {
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::u4::stack::{u4_drop, u4_hex_to_nibbles},
        support::{
            execution::{execute_script, execute_script_with_inputs_strict},
            script::script,
        },
    };
    use bitcoin_scriptexec::ExecError;

    fn assert_validation_error(actual: Option<ExecError>, expected: ExecError, case: &str) {
        assert_eq!(actual, Some(expected), "{case}");
    }

    #[test]
    fn projects_all_nibble_least_significant_bits_in_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("0123456789abcdef") }
            { u4_nibbles_to_lsb(16) }
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUAL
        });
        assert!(result.success, "LSB projection failed: {result}");
    }

    #[test]
    fn rejects_out_of_range_nibbles_at_each_position() {
        let valid_cleanup_control = execute_script_with_inputs_strict(
            script! {
                { u4_nibbles_to_lsb(3) }
                OP_2DROP OP_DROP OP_TRUE
            },
            vec![vec![1]; 3],
        );
        assert!(
            valid_cleanup_control.success,
            "valid witness failed the shared cleanup harness: {valid_cleanup_control}"
        );

        for position in 0..3 {
            for (encoded, expected) in [
                (vec![0x81], ExecError::Verify),
                (vec![0x10], ExecError::Verify),
                (vec![0, 0, 0, 0, 1], ExecError::ScriptIntNumericOverflow),
            ] {
                let mut witness = vec![vec![1]; 3];
                witness[position] = encoded;
                let result = execute_script_with_inputs_strict(
                    script! {
                        { u4_nibbles_to_lsb(3) }
                        OP_2DROP OP_DROP OP_TRUE
                    },
                    witness,
                );
                assert_validation_error(
                    result.error,
                    expected,
                    &format!("unexpected error for malformed nibble at position {position}"),
                );
            }
        }

        // The same exact-error assertion must reject a test-only fragment with
        // the production range checks removed. OP_PICK(16) then reads the
        // preserved sentinel below the table and the terminal predicate fails
        // with EqualVerify instead of the expected Verify.
        let lookup_bypass = execute_script_with_inputs_strict(
            script! {
                { push_lsb_table() }
                16 OP_ROLL
                OP_PICK OP_TOALTSTACK
                { u4_drop(U4_LSB_TABLE_ITEMS) }
                OP_FROMALTSTACK
                0 OP_EQUALVERIFY
                7 OP_EQUAL
            },
            vec![vec![7], vec![16]],
        );
        assert_eq!(lookup_bypass.error, Some(ExecError::EqualVerify));
        let bypass_assertion = std::panic::catch_unwind(|| {
            assert_validation_error(
                lookup_bypass.error,
                ExecError::Verify,
                "test-only LSB range-check bypass was not detected",
            )
        });
        assert!(
            bypass_assertion.is_err(),
            "test assertion accepted a bypass"
        );

        assert!(std::panic::catch_unwind(|| u4_nibbles_to_lsb(0)).is_err());
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_lsb(U4_LSB_MAX_BATCH + 1)).is_err());
    }

    #[test]
    fn respects_stack_frontier_and_preserves_state() {
        let maximum = execute_script_with_inputs_strict(
            script! {
                { u4_nibbles_to_lsb(U4_LSB_MAX_BATCH) }
                { u4_drop(U4_LSB_MAX_BATCH) }
                OP_TRUE
            },
            vec![Vec::new(); U4_LSB_MAX_BATCH as usize],
        );
        assert!(maximum.success, "maximum LSB batch failed: {maximum}");
        assert_eq!(maximum.stats.max_nb_stack_items, 1000);

        let mut preserved = vec![vec![7]];
        preserved.extend(vec![Vec::new(); 980]);
        let with_state = execute_script_with_inputs_strict(
            script! {
                OP_9 OP_TOALTSTACK
                { u4_nibbles_to_lsb(980) }
                { u4_drop(980) }
                7 OP_EQUALVERIFY
                OP_FROMALTSTACK 9 OP_EQUALVERIFY
                OP_TRUE
            },
            preserved,
        );
        assert!(with_state.success, "preserved state failed: {with_state}");

        let mut over_budget = vec![vec![7]];
        over_budget.extend(vec![Vec::new(); U4_LSB_MAX_BATCH as usize]);
        let rejected = execute_script_with_inputs_strict(
            script! { OP_9 OP_TOALTSTACK { u4_nibbles_to_lsb(U4_LSB_MAX_BATCH) } },
            over_budget,
        );
        assert_eq!(rejected.error, Some(ExecError::StackSize));
    }
}
