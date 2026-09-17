use super::stack::u4_drop;
use crate::support::script::*;

/// Largest standalone batch that keeps the input and result schedules below
/// the 1,000-item stack limit.
pub const U4_ADJACENT_EQUAL_MAX_BATCH: u32 = 499;

/// Consume checked nibbles and return one equality bit for each adjacent pair.
///
/// Stack before: `preserved | nibble[0] ... nibble[n-1]`.
/// Stack after: `preserved | equal[0] ... equal[n-2]`, with `equal[n-2]` on top.
pub fn u4_adjacent_equal_mask(nibble_count: u32) -> Script {
    assert!(
        nibble_count >= 2,
        "adjacent equality needs at least two nibbles"
    );
    assert!(
        nibble_count <= U4_ADJACENT_EQUAL_MAX_BATCH,
        "adjacent equality batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for index in 0..nibble_count {
            { nibble_count - 1 - index } OP_PICK
            OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
            16 OP_LESSTHAN OP_VERIFY
        }
        for index in (0..nibble_count - 1).rev() {
            { nibble_count - 1 - index } OP_PICK
            { nibble_count - 1 - index } OP_PICK
            OP_EQUAL OP_TOALTSTACK
        }
        { u4_drop(nibble_count) }
        for _ in 0..nibble_count - 1 {
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
    fn emits_adjacent_equality_bits_in_input_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("112234") }
            { u4_adjacent_equal_mask(6) }
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUAL
        });
        assert!(result.success, "adjacent equality failed: {result}");
    }

    #[test]
    fn rejects_invalid_nibbles_and_batch_sizes() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid } 1
                { u4_adjacent_equal_mask(2) }
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
        assert!(std::panic::catch_unwind(|| u4_adjacent_equal_mask(1)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_adjacent_equal_mask(U4_ADJACENT_EQUAL_MAX_BATCH + 1)
        })
        .is_err());
    }

    #[test]
    fn preserves_surrounding_stack_items() {
        let result = execute_script(script! {
            77
            { u4_hex_to_nibbles("1122") }
            { u4_adjacent_equal_mask(4) }
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            77 OP_EQUAL
        });
        assert!(result.success, "stack preservation failed: {result}");
    }
}
