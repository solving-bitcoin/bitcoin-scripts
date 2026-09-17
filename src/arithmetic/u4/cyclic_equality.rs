//! Checked cyclic lag-equality masks for contiguous u4 vectors.

use super::stack::u4_drop;
use crate::support::script::*;

/// Largest standalone batch that keeps the source and result schedules below
/// the 1,000-item combined stack limit.
pub const U4_CYCLIC_EQUAL_MAX_BATCH: u32 = 499;

/// Compare each nibble with the nibble `offset` positions ahead, wrapping around.
///
/// Stack before: `preserved | nibble[0] ... nibble[n-1]`.
/// Stack after: `preserved | equal[0] ... equal[n-1]`.
pub fn u4_nibbles_to_cyclic_equality(nibble_count: u32, offset: u32) -> Script {
    assert!(nibble_count > 0, "cyclic equality needs a nonempty vector");
    assert!(
        nibble_count <= U4_CYCLIC_EQUAL_MAX_BATCH,
        "cyclic equality batch exceeds Bitcoin Script's stack limit"
    );

    let offset = offset % nibble_count;
    script! {
        for index in 0..nibble_count {
            { nibble_count - 1 - index } OP_PICK
            OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
            16 OP_LESSTHAN OP_VERIFY
        }
        for output_index in (0..nibble_count).rev() {
            { nibble_count - 1 - output_index } OP_PICK
            { nibble_count - ((output_index + offset) % nibble_count) } OP_PICK
            OP_EQUAL OP_TOALTSTACK
        }
        { u4_drop(nibble_count) }
        for _ in 0..nibble_count {
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::u4::stack::u4_hex_to_nibbles,
        support::{execution::execute_script, script::script},
    };

    #[test]
    fn compares_a_wrapped_periodic_vector_in_input_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("12341234") }
            { u4_nibbles_to_cyclic_equality(8, 4) }
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUAL
        });
        assert!(result.success, "cyclic equality failed: {result}");

        let nonperiodic = execute_script(script! {
            { u4_hex_to_nibbles("1123") }
            { u4_nibbles_to_cyclic_equality(4, 1) }
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUAL
        });
        assert!(
            nonperiodic.success,
            "nonperiodic cyclic equality failed: {nonperiodic}"
        );
    }

    #[test]
    fn supports_zero_offset_and_preserves_surrounding_stack_state() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            { u4_hex_to_nibbles("12") }
            { u4_nibbles_to_cyclic_equality(2, 0) }
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUAL
        });
        assert!(result.success, "stack preservation failed: {result}");
    }

    #[test]
    fn rejects_invalid_nibbles_and_batch_sizes() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid } 1
                { u4_nibbles_to_cyclic_equality(2, 1) }
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_cyclic_equality(0, 1)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_to_cyclic_equality(U4_CYCLIC_EQUAL_MAX_BATCH + 1, 1)
        })
        .is_err());
    }
}
