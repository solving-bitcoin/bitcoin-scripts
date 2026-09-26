//! Batched intra-nibble bit-transition-count projection for canonical u4 limbs.

use super::stack::u4_drop;
use crate::support::script::*;

/// Persistent items used by the u4 bit-transition lookup table.
pub const U4_BIT_TRANSITIONS_TABLE_ITEMS: u32 = 16;

/// Largest batch that fits the 1,000-item stack limit without unrelated state.
pub const U4_BIT_TRANSITIONS_MAX_BATCH: u32 = 1_000 - U4_BIT_TRANSITIONS_TABLE_ITEMS - 2;

fn bit_transitions(value: u32) -> u32 {
    ((value ^ (value >> 1)) & 0b111).count_ones()
}

fn push_bit_transitions_table() -> Script {
    script! {
        for value in (0..U4_BIT_TRANSITIONS_TABLE_ITEMS).rev() {
            { bit_transitions(value) }
        }
    }
}

/// Consume canonical nibbles and replace each with its internal bit-transition count.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`.
/// After: `preserved | transitions[0] | ... | transitions[n-1]`.
pub fn u4_nibbles_to_bit_transitions(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_BIT_TRANSITIONS_MAX_BATCH,
        "u4 bit-transition batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        { push_bit_transitions_table() }
        for _ in 0..nibble_count {
            { U4_BIT_TRANSITIONS_TABLE_ITEMS } OP_ROLL
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            OP_PICK OP_TOALTSTACK
        }
        { u4_drop(U4_BIT_TRANSITIONS_TABLE_ITEMS) }
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
    fn projects_all_nibbles_to_internal_bit_transition_counts() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("0123456789abcdef") }
            { u4_nibbles_to_bit_transitions(16) }
            for nibble in (0..16u32).rev() {
                { bit_transitions(nibble) } OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(result.success, "bit-transition projection failed: {result}");
    }

    #[test]
    fn rejects_out_of_range_nibbles_and_batch_sizes() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid }
                { u4_nibbles_to_bit_transitions(1) }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_bit_transitions(0)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_to_bit_transitions(U4_BIT_TRANSITIONS_MAX_BATCH + 1)
        })
        .is_err());
    }
}
