//! Batched least-significant-bit projection for canonical u4 limbs.

use super::stack::{u4_drop, verify_canonical_nibble};
use crate::support::script::*;

/// Persistent items used by the nibble-LSB lookup table.
pub const U4_LSB_TABLE_ITEMS: u32 = 16;

/// Largest batch that fits the 1,000-item stack limit without unrelated state.
pub const U4_LSB_MAX_BATCH: u32 = 1_000 - U4_LSB_TABLE_ITEMS - 2;

/// Largest canonical batch that fits after each input's raw-encoding check.
pub const U4_LSB_CANONICAL_MAX_BATCH: u32 = 1_000 - U4_LSB_TABLE_ITEMS - 3;

fn push_lsb_table() -> Script {
    script! {
        for value in (0..U4_LSB_TABLE_ITEMS).rev() {
            { value & 1 }
        }
    }
}

/// Consume canonical nibbles and replace each with its least-significant bit.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
/// on top. After: `preserved | lsb[0] | ... | lsb[n-1]`, with the last output
/// on top. Every input is range-checked before it indexes the table.
pub fn u4_nibbles_to_lsb(nibble_count: u32) -> Script {
    u4_nibbles_to_lsb_impl(nibble_count, false)
}

/// Consume minimally encoded nibbles and replace each with its least-significant bit.
pub fn u4_nibbles_to_lsb_canonical(nibble_count: u32) -> Script {
    u4_nibbles_to_lsb_impl(nibble_count, true)
}

fn u4_nibbles_to_lsb_impl(nibble_count: u32, canonical: bool) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    let max_batch = if canonical {
        U4_LSB_CANONICAL_MAX_BATCH
    } else {
        U4_LSB_MAX_BATCH
    };
    assert!(
        nibble_count <= max_batch,
        "nibble-LSB batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        { push_lsb_table() }
        for _ in 0..nibble_count {
            { U4_LSB_TABLE_ITEMS } OP_ROLL
            if canonical {
                { verify_canonical_nibble() }
            } else {
                OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
                OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            }
            OP_PICK OP_TOALTSTACK
        }
        { u4_drop(U4_LSB_TABLE_ITEMS) }
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
        support::{
            execution::{execute_script, execute_script_with_inputs_strict},
            script::script,
        },
    };

    #[test]
    fn projects_all_nibble_least_significant_bits_in_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("0123456789abcdef") }
            { u4_nibbles_to_lsb(16) }
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUAL
        });
        assert!(result.success, "LSB projection failed: {result}");
    }

    #[test]
    fn rejects_out_of_range_nibbles_and_batch_sizes() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid }
                { u4_nibbles_to_lsb(1) }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_lsb(0)).is_err());
        assert!(std::panic::catch_unwind(|| { u4_nibbles_to_lsb(U4_LSB_MAX_BATCH + 1) }).is_err());
    }

    #[test]
    fn canonical_batch_boundary_is_one_item_smaller() {
        let canonical_witness = vec![vec![15]; U4_LSB_CANONICAL_MAX_BATCH as usize];
        let canonical = execute_script_with_inputs_strict(
            script! {
                { u4_nibbles_to_lsb_canonical(U4_LSB_CANONICAL_MAX_BATCH) }
                for _ in 0..U4_LSB_CANONICAL_MAX_BATCH { OP_DROP }
                OP_TRUE
            },
            canonical_witness,
        );
        assert!(canonical.success, "canonical max batch failed: {canonical}");
        assert_eq!(canonical.stats.max_nb_stack_items, 1_000);

        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_to_lsb_canonical(U4_LSB_CANONICAL_MAX_BATCH + 1)
        })
        .is_err());
        assert!(std::panic::catch_unwind(|| { u4_nibbles_to_lsb_canonical(0) }).is_err());

        // The ordinary wrapper retains the one-item-larger generation bound;
        // its existing metric fixture covers the normal 32-item execution.
        let _ = u4_nibbles_to_lsb(U4_LSB_MAX_BATCH);
    }

    #[test]
    fn canonical_projection_matches_reference_values() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("0123456789abcdef") }
            { u4_nibbles_to_lsb_canonical(16) }
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUAL
        });
        assert!(result.success, "canonical LSB projection failed: {result}");
    }

    #[test]
    fn canonical_projection_rejects_malformed_nibbles() {
        let script = script! {
            { u4_nibbles_to_lsb_canonical(4) }
            for _ in 0..4 { OP_DROP }
            OP_TRUE
        };
        for position in 0..4 {
            for replacement in [vec![1, 0], vec![0, 1], vec![0x80]] {
                let mut witness = vec![vec![1]; 4];
                witness[position] = replacement;
                let result =
                    crate::support::execution::execute_script_with_inputs(script.clone(), witness);
                assert!(
                    !result.success,
                    "accepted malformed nibble at {position}: {result}"
                );
            }
        }
    }

    #[test]
    fn canonical_projection_preserves_surrounding_stacks() {
        let result = crate::support::execution::execute_script_with_inputs_strict(
            script! {
                99 OP_TOALTSTACK
                { u4_nibbles_to_lsb_canonical(2) }
                OP_DROP OP_DROP
                77 OP_EQUALVERIFY
                OP_FROMALTSTACK 99 OP_EQUALVERIFY
                OP_TRUE
            },
            vec![vec![77], vec![1], vec![2]],
        );
        assert!(result.success, "{result}");
    }
}
