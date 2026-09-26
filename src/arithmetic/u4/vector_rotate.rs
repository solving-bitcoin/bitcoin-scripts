//! Checked cyclic rotations of contiguous u4 vectors.

use super::stack::u4_drop;
use crate::support::script::*;

/// Largest standalone batch that keeps input and output schedules below the
/// 1,000-item combined stack limit.
pub const U4_VECTOR_ROTATE_MAX_BATCH: u32 = 499;

/// Rotate a checked u4 vector one position to the left.
///
/// Stack before: `preserved | nibble[0] ... nibble[n-1]`.
/// Stack after: `preserved | nibble[1] ... nibble[n-1] nibble[0]`.
pub fn u4_nibbles_rotate_left(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "vector rotation needs a nonempty vector");
    assert!(
        nibble_count <= U4_VECTOR_ROTATE_MAX_BATCH,
        "vector-rotation batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for index in 0..nibble_count {
            { nibble_count - 1 - index } OP_PICK
            OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
            16 OP_LESSTHAN OP_VERIFY
        }
        for output_index in (0..nibble_count).rev() {
            { nibble_count - 1 - ((output_index + 1) % nibble_count) } OP_PICK
            OP_TOALTSTACK
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
    fn rotates_in_input_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("1234") }
            { u4_nibbles_rotate_left(4) }
            1 OP_EQUALVERIFY
            4 OP_EQUALVERIFY
            3 OP_EQUALVERIFY
            2 OP_EQUAL
        });
        assert!(result.success, "vector rotation failed: {result}");
    }

    #[test]
    fn preserves_singletons_and_surrounding_stack_state() {
        let singleton = execute_script(script! {
            7
            { u4_hex_to_nibbles("a") }
            { u4_nibbles_rotate_left(1) }
            10 OP_EQUALVERIFY
            7 OP_EQUAL
        });
        assert!(singleton.success, "singleton rotation failed: {singleton}");

        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            { u4_hex_to_nibbles("123") }
            { u4_nibbles_rotate_left(3) }
            1 OP_EQUALVERIFY
            3 OP_EQUALVERIFY
            2 OP_EQUALVERIFY
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
                { u4_nibbles_rotate_left(2) }
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_rotate_left(0)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_rotate_left(U4_VECTOR_ROTATE_MAX_BATCH + 1)
        })
        .is_err());
    }
}
