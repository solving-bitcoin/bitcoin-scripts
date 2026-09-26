use super::stack::{u4_drop, u4_pair_to_u8};
use crate::support::script::*;

/// Largest standalone even batch before accounting for unrelated live state.
pub const U4_PACK_MAX_BATCH: u32 = 664;

/// Consume checked high/low nibble pairs and return their packed bytes.
///
/// Stack before: `preserved | nibble[0] ... nibble[n-1]`.
/// Stack after: `preserved | byte[0] ... byte[n/2-1]`.
pub fn u4_nibbles_to_bytes(nibble_count: u32) -> Script {
    assert!(
        nibble_count >= 2 && nibble_count % 2 == 0,
        "nibble batch must have a positive even width"
    );
    assert!(
        nibble_count <= U4_PACK_MAX_BATCH,
        "nibble-pack batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for pair in (0..nibble_count / 2).rev() {
            { nibble_count - 1 - pair * 2 } OP_PICK
            { nibble_count - 1 - pair * 2 } OP_PICK
            { u4_pair_to_u8(true) }
            OP_TOALTSTACK
        }
        { u4_drop(nibble_count) }
        for _ in 0..nibble_count / 2 {
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::u4::stack::u4_hex_to_nibbles,
        support::{
            execution::{execute_script, execute_script_with_inputs_strict},
            script::script,
        },
    };
    use bitcoin_scriptexec::ExecError;

    #[test]
    fn packs_all_pairs_in_input_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("1234abcd") }
            { u4_nibbles_to_bytes(8) }
            0xcd OP_EQUALVERIFY
            0xab OP_EQUALVERIFY
            0x34 OP_EQUALVERIFY
            0x12 OP_EQUAL
        });
        assert!(result.success, "batch packing failed: {result}");
    }

    #[test]
    fn rejects_invalid_nibbles_and_batch_sizes() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid } 1
                { u4_nibbles_to_bytes(2) }
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
        for invalid_size in [0, 1, 3] {
            assert!(std::panic::catch_unwind(|| u4_nibbles_to_bytes(invalid_size)).is_err());
        }
        assert!(
            std::panic::catch_unwind(|| { u4_nibbles_to_bytes(U4_PACK_MAX_BATCH + 2) }).is_err()
        );
    }

    #[test]
    fn packs_scriptnum_boundary_encodings() {
        for (hex, value, byte_len) in [
            ("00", 0, 0),
            ("7f", 0x7f, 1),
            ("80", 0x80, 2),
            ("ff", 0xff, 2),
        ] {
            let result = execute_script(script! {
                { u4_hex_to_nibbles(hex) }
                { u4_nibbles_to_bytes(2) }
                OP_SIZE { byte_len } OP_EQUALVERIFY
                OP_DUP { value } OP_EQUALVERIFY
                OP_DROP OP_TRUE
            });
            assert!(result.success, "wrong encoding for {hex}: {result}");
        }
    }

    fn assert_nibble_range_error(
        result: &crate::support::execution::ExecuteInfo,
        expected: ExecError,
        scenario: &str,
    ) {
        assert!(
            !result.success,
            "accepted malformed nibble ({scenario}): {result}"
        );
        assert_eq!(
            result.error.as_ref(),
            Some(&expected),
            "rejected malformed nibble for the wrong reason ({scenario}): {result}"
        );
    }

    fn unchecked_batch_for_mutation_test(nibble_count: u32) -> Script {
        assert!(nibble_count >= 2 && nibble_count % 2 == 0);
        script! {
            for pair in (0..nibble_count / 2).rev() {
                { nibble_count - 1 - pair * 2 } OP_PICK
                { nibble_count - 1 - pair * 2 } OP_PICK
                { u4_pair_to_u8(false) }
                OP_TOALTSTACK
            }
            { u4_drop(nibble_count) }
            for _ in 0..nibble_count / 2 {
                OP_FROMALTSTACK
            }
        }
    }

    #[test]
    fn rejects_runtime_malformed_nibbles_at_every_position() {
        let valid_control = execute_script_with_inputs_strict(
            script! { { u4_nibbles_to_bytes(4) } OP_2DROP OP_TRUE },
            vec![vec![1], vec![2], vec![3], vec![4]],
        );
        assert!(
            valid_control.success,
            "valid control failed: {valid_control}"
        );

        for position in 0..4 {
            for (label, encoded, expected_error) in [
                ("negative", vec![0x81], ExecError::Verify),
                ("sixteen", vec![0x10], ExecError::Verify),
                (
                    "oversized",
                    vec![0x01, 0x00, 0x00, 0x00, 0x00],
                    ExecError::ScriptIntNumericOverflow,
                ),
            ] {
                let mut witness = vec![vec![1]; 4];
                witness[position] = encoded;
                let scenario = format!("{label} encoding at position {position}");
                let result = execute_script_with_inputs_strict(
                    script! { { u4_nibbles_to_bytes(4) } OP_2DROP OP_TRUE },
                    witness,
                );
                assert_nibble_range_error(&result, expected_error, &scenario);
            }
        }

        let malformed = vec![vec![0x81], vec![1], vec![1], vec![1]];
        let mutant = execute_script_with_inputs_strict(
            script! { { unchecked_batch_for_mutation_test(4) } OP_2DROP OP_TRUE },
            malformed,
        );
        assert!(
            mutant.success,
            "unchecked mutant should expose the missing range check: {mutant}"
        );
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_nibble_range_error(&mutant, ExecError::Verify, "unchecked mutant")
            }))
            .is_err(),
            "shared range-error contract accepted the unchecked mutant"
        );
    }

    #[test]
    fn preserves_surrounding_stack_items() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            77
            { u4_hex_to_nibbles("1122") }
            { u4_nibbles_to_bytes(4) }
            0x22 OP_EQUALVERIFY
            0x11 OP_EQUALVERIFY
            77 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "stack preservation failed: {result}");
    }

    #[test]
    fn maximum_batch_reaches_but_does_not_exceed_stack_limit() {
        let result = execute_script_with_inputs_strict(
            script! {
                { u4_nibbles_to_bytes(U4_PACK_MAX_BATCH) }
                { u4_drop(U4_PACK_MAX_BATCH / 2) }
                OP_TRUE
            },
            vec![Vec::new(); U4_PACK_MAX_BATCH as usize],
        );
        assert!(result.success, "maximum batch failed: {result}");
        assert_eq!(result.stats.max_nb_stack_items, 1000);

        let mut witness = vec![vec![0x42]];
        witness.extend(vec![Vec::new(); U4_PACK_MAX_BATCH as usize]);
        let preserved = execute_script_with_inputs_strict(
            script! {
                { u4_nibbles_to_bytes(U4_PACK_MAX_BATCH) }
            },
            witness,
        );
        assert_eq!(preserved.error, Some(ExecError::StackSize));
        assert_eq!(preserved.stats.max_nb_stack_items, 1001);
    }

    #[test]
    #[should_panic(expected = "nibble-pack batch exceeds Bitcoin Script's stack limit")]
    fn rejects_batch_above_stack_limit() {
        let _ = u4_nibbles_to_bytes(U4_PACK_MAX_BATCH + 2);
    }
}
