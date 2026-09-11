//! Batched parity projection for canonical u4 limbs.

use super::stack::u4_drop;
use crate::support::script::*;

/// Persistent items used by the nibble-parity lookup table.
pub const U4_PARITY_TABLE_ITEMS: u32 = 16;

/// Largest batch that fits the 1,000-item stack limit without unrelated state.
/// Two temporary stack items are needed by each range check.
pub const U4_PARITY_MAX_BATCH: u32 = 1_000 - U4_PARITY_TABLE_ITEMS - 2;

fn parity(value: u32) -> u32 {
    (value.count_ones() & 1) as u32
}

fn push_parity_table() -> Script {
    script! {
        for value in (0..U4_PARITY_TABLE_ITEMS).rev() {
            { parity(value) }
        }
    }
}

/// Consume `nibble_count` canonical nibbles and replace each with its parity.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`, with `nibble[n-1]`
/// on top. After: `preserved | parity[0] | ... | parity[n-1]`, with the last
/// output on top. Every input is checked to be in `0..=15` before it indexes
/// the table.
pub fn u4_nibbles_to_parity(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_PARITY_MAX_BATCH,
        "nibble-parity batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        { push_parity_table() }
        for _ in 0..nibble_count {
            { U4_PARITY_TABLE_ITEMS } OP_ROLL
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            OP_PICK OP_TOALTSTACK
        }
        { u4_drop(U4_PARITY_TABLE_ITEMS) }
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
    fn projects_all_nibble_parities_in_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("0123456789abcdef") }
            { u4_nibbles_to_parity(16) }
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUAL
        });
        assert!(result.success, "parity projection failed: {result}");
    }

    #[test]
    fn rejects_out_of_range_nibbles() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid }
                { u4_nibbles_to_parity(1) }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
    }

    #[test]
    fn rejects_zero_and_overlarge_batches() {
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_parity(0)).is_err());
        assert!(
            std::panic::catch_unwind(|| { u4_nibbles_to_parity(U4_PARITY_MAX_BATCH + 1) }).is_err()
        );
    }
}
