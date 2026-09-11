//! Checked population count for a four-byte u32 word.

use crate::support::script::*;

/// The byte popcount table is kept on the main stack during the four queries.
pub const U8_POPCOUNT_TABLE_ITEMS: u32 = 256;

fn push_popcount_table() -> Script {
    script! {
        for value in (0..U8_POPCOUNT_TABLE_ITEMS).rev() {
            { value.count_ones() }
        }
    }
}

fn drop_popcount_table() -> Script {
    script! {
        for _ in 0..U8_POPCOUNT_TABLE_ITEMS / 2 {
            OP_2DROP
        }
    }
}

/// Count the set bits in the top u32 word and replace it with one integer.
///
/// The input is `byte[0] | byte[1] | byte[2] | byte[3]`, with the least
/// significant byte on top. Each byte is range-checked before it indexes the
/// table. Four byte popcounts are accumulated on the altstack and the final
/// result is in `0..=32`.
pub fn u32_popcount() -> Script {
    script! {
        { push_popcount_table() }
        for _ in 0..4 {
            { U8_POPCOUNT_TABLE_ITEMS } OP_ROLL
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP { U8_POPCOUNT_TABLE_ITEMS } OP_LESSTHAN OP_VERIFY
            OP_PICK OP_TOALTSTACK
        }
        { drop_popcount_table() }
        OP_FROMALTSTACK
        OP_FROMALTSTACK OP_ADD
        OP_FROMALTSTACK OP_ADD
        OP_FROMALTSTACK OP_ADD
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::u32::stack::u32_push,
        support::{execution::execute_script, script::script},
    };

    #[test]
    fn counts_boundary_and_representative_words() {
        for (word, expected) in [
            (0, 0),
            (1, 1),
            (0x8000_0000, 1),
            (0x0123_4567, 12),
            (u32::MAX, 32),
        ] {
            let result = execute_script(script! {
                { u32_push(word) }
                { u32_popcount() }
                { expected } OP_EQUAL
            });
            assert!(result.success, "word={word:#010x}: {result}");
        }
    }

    #[test]
    fn rejects_non_byte_limbs() {
        for invalid in [-1, 256] {
            let result = execute_script(script! {
                0 0 0 { invalid }
                { u32_popcount() }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid byte {invalid}");
        }
    }
}
