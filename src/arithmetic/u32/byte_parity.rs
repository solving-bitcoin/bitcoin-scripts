//! Checked parity projection for the four byte limbs of a u32 word.

use crate::support::script::*;

/// Persistent items used by the byte-parity lookup table.
pub const U8_PARITY_TABLE_ITEMS: u32 = 256;

fn push_parity_table() -> Script {
    script! {
        for value in (0..U8_PARITY_TABLE_ITEMS).rev() {
            { value.count_ones() & 1 }
        }
    }
}

fn drop_parity_table() -> Script {
    script! {
        for _ in 0..U8_PARITY_TABLE_ITEMS / 2 {
            OP_2DROP
        }
    }
}

/// Replace a four-byte u32 word with one parity bit per byte.
///
/// The input is `byte[0] | byte[1] | byte[2] | byte[3]`, with the least
/// significant byte on top. The output is four numeric bits with the most
/// significant byte's parity on the bottom, with the least significant byte's
/// parity on top.
/// Each input byte is range checked before table indexing.
pub fn u32_byte_parity() -> Script {
    script! {
        { push_parity_table() }
        for _ in 0..4 {
            { U8_PARITY_TABLE_ITEMS } OP_ROLL
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP { U8_PARITY_TABLE_ITEMS } OP_LESSTHAN OP_VERIFY
            OP_PICK OP_TOALTSTACK
        }
        { drop_parity_table() }
        for _ in 0..4 {
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::u32::stack::u32_push,
        support::{execution::execute_script, script::script},
    };

    fn parity(value: u32) -> i64 {
        i64::from(value.count_ones() & 1)
    }

    #[test]
    fn projects_boundary_and_representative_words() {
        for word in [0, 1, 0x0102_0304, 0x8000_0000, u32::MAX] {
            let bytes = [
                word & 0xff,
                (word >> 8) & 0xff,
                (word >> 16) & 0xff,
                word >> 24,
            ];
            let result = execute_script(script! {
                { u32_push(word) }
                { u32_byte_parity() }
                for byte in bytes {
                    { parity(byte) } OP_EQUALVERIFY
                }
                OP_TRUE
            });
            assert!(result.success, "word={word:#010x}: {result}");
        }
    }

    #[test]
    fn rejects_non_byte_limbs() {
        for position in 0..4 {
            let mut limbs = [0i64; 4];
            limbs[position] = if position % 2 == 0 { -1 } else { 256 };
            let result = execute_script(script! {
                for limb in limbs {
                    { limb }
                }
                { u32_byte_parity() }
                OP_2DROP OP_2DROP OP_TRUE
            });
            assert!(
                !result.success,
                "accepted invalid byte at {position}: {result}"
            );
        }
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let result = execute_script(script! {
            99 OP_TOALTSTACK
            77
            { u32_push(0x0102_0304) }
            { u32_byte_parity() }
            OP_2DROP OP_2DROP
            77 OP_EQUALVERIFY
            OP_FROMALTSTACK 99 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "stack preservation failed: {result}");
    }
}
