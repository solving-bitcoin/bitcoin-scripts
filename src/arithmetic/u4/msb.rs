//! Batched most-significant-bit projection for canonical u4 limbs.

use super::stack::u4_drop;
use crate::support::script::*;

/// Persistent items used by the nibble-MSB lookup table.
pub const U4_MSB_TABLE_ITEMS: u32 = 16;

/// Largest batch that fits the 1,000-item stack limit without unrelated state.
pub const U4_MSB_MAX_BATCH: u32 = 1_000 - U4_MSB_TABLE_ITEMS - 2;

fn push_msb_table() -> Script {
    script! {
        for value in (0..U4_MSB_TABLE_ITEMS).rev() {
            { (value >= 8) as u32 }
        }
    }
}

/// Consume canonical nibbles and replace each with its most-significant bit.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
/// on top. After: `preserved | msb[0] | ... | msb[n-1]`, with the last output
/// on top. Every input is range-checked before it indexes the table.
pub fn u4_nibbles_to_msb(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_MSB_MAX_BATCH,
        "nibble-MSB batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        { push_msb_table() }
        for _ in 0..nibble_count {
            { U4_MSB_TABLE_ITEMS } OP_ROLL
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            OP_PICK OP_TOALTSTACK
        }
        { u4_drop(U4_MSB_TABLE_ITEMS) }
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
    fn projects_all_nibble_most_significant_bits_in_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("0123456789abcdef") }
            { u4_nibbles_to_msb(16) }
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            0 OP_EQUAL
        });
        assert!(result.success, "MSB projection failed: {result}");
    }

    #[test]
    fn rejects_out_of_range_nibbles_and_batch_sizes() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid }
                { u4_nibbles_to_msb(1) }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_msb(0)).is_err());
        assert!(std::panic::catch_unwind(|| { u4_nibbles_to_msb(U4_MSB_MAX_BATCH + 1) }).is_err());
    }
}
