//! Batched inverse reflected-Gray decoding for canonical u4 limbs.

use super::stack::u4_drop;
use crate::support::script::*;

/// Persistent items used by the inverse-Gray lookup table.
pub const U4_GRAY_INVERSE_TABLE_ITEMS: u32 = 16;

/// Largest batch that fits the 1,000-item stack limit without unrelated state.
pub const U4_GRAY_INVERSE_MAX_BATCH: u32 = 1_000 - U4_GRAY_INVERSE_TABLE_ITEMS - 2;

fn inverse_gray(value: u32) -> u32 {
    value ^ (value >> 1) ^ (value >> 2) ^ (value >> 3)
}

fn push_inverse_gray_table() -> Script {
    script! {
        for value in (0..U4_GRAY_INVERSE_TABLE_ITEMS).rev() {
            { inverse_gray(value) }
        }
    }
}

/// Consume canonical reflected-Gray nibbles and replace them with binary nibbles.
///
/// Before: `preserved | gray[0] | ... | gray[n-1]`.
/// After: `preserved | value[0] | ... | value[n-1]`.
pub fn u4_nibbles_from_gray(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "Gray batch must not be empty");
    assert!(
        nibble_count <= U4_GRAY_INVERSE_MAX_BATCH,
        "inverse-Gray batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        { push_inverse_gray_table() }
        for _ in 0..nibble_count {
            { U4_GRAY_INVERSE_TABLE_ITEMS } OP_ROLL
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            OP_PICK OP_TOALTSTACK
        }
        { u4_drop(U4_GRAY_INVERSE_TABLE_ITEMS) }
        for _ in 0..nibble_count {
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{execution::execute_script, script::script};

    fn gray(value: u32) -> u32 {
        value ^ (value >> 1)
    }

    #[test]
    fn decodes_every_four_bit_gray_value() {
        let result = execute_script(script! {
            { u4_nibbles_to_gray_inputs() }
            { u4_nibbles_from_gray(16) }
            for value in (0..16u32).rev() {
                { value } OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(result.success, "inverse-Gray projection failed: {result}");
    }

    #[test]
    fn rejects_out_of_range_nibbles_and_batch_sizes() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid }
                { u4_nibbles_from_gray(1) }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid Gray nibble {invalid}");
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_from_gray(0)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_from_gray(U4_GRAY_INVERSE_MAX_BATCH + 1)
        })
        .is_err());
    }

    fn u4_nibbles_to_gray_inputs() -> Script {
        script! {
            for value in 0..16u32 {
                { gray(value) }
            }
        }
    }
}
