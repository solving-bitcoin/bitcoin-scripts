//! Batched modulo-three residue projection for canonical u4 limbs.

use super::stack::u4_drop;
use crate::support::script::*;

/// Persistent items used by the u4 modulo-three lookup table.
pub const U4_MOD3_TABLE_ITEMS: u32 = 16;

/// Largest batch that fits the 1,000-item stack limit without unrelated state.
pub const U4_MOD3_MAX_BATCH: u32 = 1_000 - U4_MOD3_TABLE_ITEMS - 2;

fn mod3(value: u32) -> u32 {
    value % 3
}

fn push_mod3_table() -> Script {
    script! {
        for value in (0..U4_MOD3_TABLE_ITEMS).rev() {
            { mod3(value) }
        }
    }
}

/// Consume canonical nibbles and replace each with its residue modulo three.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`.
/// After: `preserved | residue[0] | ... | residue[n-1]`.
pub fn u4_nibbles_to_mod3(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_MOD3_MAX_BATCH,
        "u4 modulo-three batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        { push_mod3_table() }
        for _ in 0..nibble_count {
            { U4_MOD3_TABLE_ITEMS } OP_ROLL
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            OP_PICK OP_TOALTSTACK
        }
        { u4_drop(U4_MOD3_TABLE_ITEMS) }
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
    fn projects_all_nibbles_to_modulo_three_residues() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("0123456789abcdef") }
            { u4_nibbles_to_mod3(16) }
            for nibble in (0..16u32).rev() {
                { mod3(nibble) } OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(result.success, "modulo-three projection failed: {result}");
    }

    #[test]
    fn rejects_out_of_range_nibbles_and_batch_sizes() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid }
                { u4_nibbles_to_mod3(1) }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_mod3(0)).is_err());
        assert!(
            std::panic::catch_unwind(|| { u4_nibbles_to_mod3(U4_MOD3_MAX_BATCH + 1) }).is_err()
        );
    }
}
