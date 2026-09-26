//! Batched reflected-Gray-code projection for canonical u4 limbs.

use super::stack::u4_drop;
use crate::support::script::*;

/// Persistent items used by the generated Gray-code lookup table.
pub const U4_GRAY_TABLE_ITEMS: u32 = 16;

/// Largest batch that fits the 1,000-item stack limit without unrelated state.
pub const U4_GRAY_MAX_BATCH: u32 = 1_000 - U4_GRAY_TABLE_ITEMS - 2;

fn gray(value: u32) -> u32 {
    value ^ (value >> 1)
}

fn push_gray_table() -> Script {
    script! {
        for value in (0..U4_GRAY_TABLE_ITEMS).rev() {
            { gray(value) }
        }
    }
}

/// Consume checked nibbles and replace each with its reflected Gray code.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`.
/// After: `preserved | gray[0] | ... | gray[n-1]`.
pub fn u4_nibbles_to_gray(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "Gray-code batch must not be empty");
    assert!(
        nibble_count <= U4_GRAY_MAX_BATCH,
        "Gray-code batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        { push_gray_table() }
        for _ in 0..nibble_count {
            { U4_GRAY_TABLE_ITEMS } OP_ROLL
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            OP_PICK OP_TOALTSTACK
        }
        { u4_drop(U4_GRAY_TABLE_ITEMS) }
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
    fn projects_every_nibble_to_reflected_gray_code() {
        for value in 0..=15u32 {
            let expected = gray(value);
            let result = execute_script(script! {
                { value }
                { u4_nibbles_to_gray(1) }
                { expected } OP_EQUAL
            });
            assert!(
                result.success,
                "Gray projection failed for {value}: {result}"
            );
        }
    }

    #[test]
    fn preserves_batch_order_and_surrounding_state() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            { u4_hex_to_nibbles("0123") }
            { u4_nibbles_to_gray(4) }
            2 OP_EQUALVERIFY
            3 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUAL
        });
        assert!(result.success, "Gray batch failed: {result}");
    }

    #[test]
    fn rejects_malformed_nibbles_and_batch_sizes() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid }
                { u4_nibbles_to_gray(1) }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_gray(0)).is_err());
        assert!(
            std::panic::catch_unwind(|| { u4_nibbles_to_gray(U4_GRAY_MAX_BATCH + 1) }).is_err()
        );
    }
}
