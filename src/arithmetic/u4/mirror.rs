//! Batched complement-reflection projection for canonical u4 limbs.

use super::stack::u4_drop;
use crate::support::script::*;

/// Persistent items used by the reflected-domain lookup table.
pub const U4_MIRROR_TABLE_ITEMS: u32 = 16;

/// Largest batch that fits the 1,000-item stack limit without unrelated state.
pub const U4_MIRROR_MAX_BATCH: u32 = 1_000 - U4_MIRROR_TABLE_ITEMS - 2;

fn mirror(value: u32) -> u32 {
    value.min(15 - value)
}

fn push_mirror_table() -> Script {
    script! {
        for value in (0..U4_MIRROR_TABLE_ITEMS).rev() {
            { mirror(value) }
        }
    }
}

/// Consume canonical nibbles and replace each with its complement-reflection.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`.
/// After: `preserved | mirror[0] | ... | mirror[n-1]`.
pub fn u4_nibbles_to_mirror(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_MIRROR_MAX_BATCH,
        "mirrored u4 batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        { push_mirror_table() }
        for _ in 0..nibble_count {
            { U4_MIRROR_TABLE_ITEMS } OP_ROLL
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            OP_PICK OP_TOALTSTACK
        }
        { u4_drop(U4_MIRROR_TABLE_ITEMS) }
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
    fn projects_all_nibbles_to_their_reflected_domain_in_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("0123456789abcdef") }
            { u4_nibbles_to_mirror(16) }
            for nibble in (0..16u32).rev() {
                { mirror(nibble) } OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(result.success, "mirror projection failed: {result}");
    }

    #[test]
    fn rejects_out_of_range_nibbles_and_batch_sizes() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid }
                { u4_nibbles_to_mirror(1) }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_mirror(0)).is_err());
        assert!(
            std::panic::catch_unwind(|| { u4_nibbles_to_mirror(U4_MIRROR_MAX_BATCH + 1) }).is_err()
        );
    }
}
