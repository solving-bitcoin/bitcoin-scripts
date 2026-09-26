//! Reduction of canonical u4 limbs with the shared full XOR table.

use super::{logic::u4_push_full_xor_table, stack::u4_drop};
use crate::support::script::*;

pub const U4_XOR_TABLE_ITEMS: u32 = 16 * 16;
pub const U4_XOR_MAX_BATCH: u32 = 1_000 - U4_XOR_TABLE_ITEMS - 2;

/// Consume `nibble_count` canonical nibbles and replace them with their XOR.
///
/// The full 16x16 XOR table remains resident while the reduction runs and is
/// removed before the single result is returned. Inputs are restored in their
/// original order after range checking, so the reduction is independent of
/// witness ordering.
pub fn u4_nibbles_to_xor(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_XOR_MAX_BATCH,
        "nibble-xor batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for _ in 0..nibble_count {
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            OP_TOALTSTACK
        }
        { u4_push_full_xor_table() }
        for _ in 0..nibble_count {
            OP_FROMALTSTACK
        }
        for reduction in 1..nibble_count {
            OP_SWAP
            for _ in 0..4 {
                OP_DUP OP_ADD
            }
            OP_SWAP OP_ADD
            { nibble_count - reduction - 1 }
            OP_ADD
            OP_PICK
        }
        OP_TOALTSTACK
        { u4_drop(U4_XOR_TABLE_ITEMS) }
        OP_FROMALTSTACK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::u4::stack::u4_hex_to_nibbles;
    use crate::support::execution::execute_script;

    #[test]
    fn reduces_boundaries_and_patterns() {
        for (digits, expected) in [
            ("0", 0),
            ("f", 15),
            ("0000", 0),
            ("0123456789abcdef", 0),
            ("ffffffff", 0),
            ("1234567", 0),
            ("89abcdef", 0),
        ] {
            let result = execute_script(script! {
                { u4_hex_to_nibbles(digits) }
                { u4_nibbles_to_xor(digits.len() as u32) }
                { expected } OP_EQUAL
            });
            assert!(
                result.success,
                "XOR reduction failed for {digits}: {result}"
            );
        }
    }

    #[test]
    fn rejects_out_of_range_nibbles() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                1 2 { invalid }
                { u4_nibbles_to_xor(3) }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            { u4_hex_to_nibbles("1234") }
            { u4_nibbles_to_xor(4) }
            4 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "XOR reduction changed surrounding state");
    }
}
