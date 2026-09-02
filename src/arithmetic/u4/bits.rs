//! Batched conversion from canonical nibbles to individual bits.
//!
//! The lookup table is deliberately staggered. Four equal `OP_PICK` indices
//! remain above the table; as each index is consumed, the same numeric depth
//! selects the next bit. Depth zero is unused because nibble zero is answered
//! directly by its four zero-valued indices.

use super::stack::u4_drop;
use crate::support::script::*;

/// Persistent items used by the staggered nibble-to-bits table.
pub const U4_BITS_TABLE_ITEMS: u32 = 61;

/// Largest batch that can execute with no unrelated live stack items.
///
/// A batch peaks at `4 * nibble_count + U4_BITS_TABLE_ITEMS` combined
/// main/alt-stack items. Callers with preserved state must reduce the batch.
pub const U4_BITS_MAX_BATCH: u32 = (1_000 - U4_BITS_TABLE_ITEMS) / 4;

fn table_value_at_depth(depth: u32) -> u32 {
    if depth == 0 {
        return 0;
    }

    let nibble = (depth + 3) / 4;
    let bit_in_be_order = depth - (4 * nibble - 3);
    (nibble >> (3 - bit_in_be_order)) & 1
}

/// Push the 61-item staggered lookup table.
///
/// The item at depth `4*x-3 ..= 4*x` is the big-endian bit sequence of
/// canonical nibble `x` for every `x` in `1..=15`. Depth zero is unused.
pub fn u4_push_to_be_bits_table() -> Script {
    script! {
        for depth in (0..U4_BITS_TABLE_ITEMS).rev() {
            { table_value_at_depth(depth) }
        }
    }
}

/// Drop the complete staggered nibble-to-bits table.
pub fn u4_drop_to_be_bits_table() -> Script {
    u4_drop(U4_BITS_TABLE_ITEMS)
}

/// Convert one nibble immediately below the table and push its bits to altstack.
///
/// Before: `preserved | nibble | table`, where `table` is the 61-item output of
/// [`u4_push_to_be_bits_table`]. After: `preserved | table` on the main stack,
/// with `bit3 | bit2 | bit1 | bit0` newly pushed to the altstack in that order.
/// When `check_input` is true, the numeric nibble is first constrained to
/// `0..=15`. When false, the caller must already have established that range;
/// otherwise `OP_PICK` can address outside the table.
pub fn u4_nibble_below_bits_table_toaltstack(check_input: bool) -> Script {
    script! {
        { U4_BITS_TABLE_ITEMS }
        OP_ROLL

        if check_input {
            OP_DUP
            OP_0
            OP_16
            OP_WITHIN
            OP_VERIFY
        }

        // Four equal indices. As OP_PICK consumes each index, the number of
        // remaining indices above the table falls from three to zero.
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_2DUP

        OP_PICK OP_TOALTSTACK
        OP_PICK OP_TOALTSTACK
        OP_PICK OP_TOALTSTACK
        OP_PICK OP_TOALTSTACK
    }
}

fn validate_batch_size(nibble_count: u32) {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_BITS_MAX_BATCH,
        "nibble-to-bits batch exceeds Bitcoin Script's stack limit"
    );
}

/// Consume a contiguous nibble batch and leave all output bits on altstack.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`, with `nibble[n-1]`
/// on top. After: `preserved` remains on the main stack. Nibbles are processed
/// from the top down; each contributes `bit3`, `bit2`, `bit1`, `bit0` to the
/// altstack. The temporary table is installed above the inputs and completely
/// removed. `check_inputs` has the same meaning as `check_input` in
/// [`u4_nibble_below_bits_table_toaltstack`].
pub fn u4_nibbles_to_be_bits_toaltstack(nibble_count: u32, check_inputs: bool) -> Script {
    validate_batch_size(nibble_count);
    script! {
        { u4_push_to_be_bits_table() }
        for _ in 0..nibble_count {
            { u4_nibble_below_bits_table_toaltstack(check_inputs) }
        }
        { u4_drop_to_be_bits_table() }
    }
}

/// Consume a contiguous nibble batch and replace it with big-endian bits.
///
/// This has the same input contract as [`u4_nibbles_to_be_bits_toaltstack`],
/// then restores its `4*nibble_count` output items to the main stack. The top
/// input nibble's most-significant bit is the top output item, followed by its
/// remaining bits and then each deeper nibble in the same order.
pub fn u4_nibbles_to_be_bits(nibble_count: u32, check_inputs: bool) -> Script {
    script! {
        { u4_nibbles_to_be_bits_toaltstack(nibble_count, check_inputs) }
        for _ in 0..4 * nibble_count {
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::execute_script;

    fn verify_batch(inputs: &[u32], check_inputs: bool) {
        let result = execute_script(script! {
            for input in inputs {
                { *input }
            }
            { u4_nibbles_to_be_bits(inputs.len() as u32, check_inputs) }
            for input in inputs.iter().rev() {
                for bit in (0..4).rev() {
                    { (input >> bit) & 1 }
                    OP_EQUALVERIFY
                }
            }
            OP_TRUE
        });
        assert!(result.success, "batch conversion failed: {result}");
    }

    #[test]
    fn exhaustive_single_nibbles_are_correct() {
        for nibble in 0..16 {
            verify_batch(&[nibble], true);
            verify_batch(&[nibble], false);
        }
    }

    #[test]
    fn checked_batch_preserves_nibble_and_bit_order() {
        verify_batch(&(0..16).collect::<Vec<_>>(), true);
    }

    #[test]
    fn checked_batch_rejects_out_of_range_inputs() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid }
                { u4_nibbles_to_be_bits(1, true) }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
    }

    #[test]
    fn batch_size_guard_matches_the_strict_stack_peak() {
        let result = execute_script(script! {
            for _ in 0..U4_BITS_MAX_BATCH {
                OP_15
            }
            { u4_nibbles_to_be_bits(U4_BITS_MAX_BATCH, true) }
            { u4_drop(4 * U4_BITS_MAX_BATCH - 1) }
        });
        assert!(result.success, "maximum batch failed: {result}");
        assert_eq!(
            result.stats.max_nb_stack_items,
            (4 * U4_BITS_MAX_BATCH + U4_BITS_TABLE_ITEMS) as usize
        );

        assert!(std::panic::catch_unwind(|| u4_nibbles_to_be_bits(0, true)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_to_be_bits(U4_BITS_MAX_BATCH + 1, true)
        })
        .is_err());
    }
}
