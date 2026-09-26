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

/// Count the set bits in each byte of the top u32 word.
///
/// The input is `byte[0] | byte[1] | byte[2] | byte[3]`, with the least
/// significant byte on top. The output has the same byte order and contains
/// four numeric counts in `0..=8`.
pub fn u32_byte_popcounts() -> Script {
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
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::u32::stack::u32_push,
        support::{
            execution::{execute_script, execute_script_with_inputs_strict},
            script::script,
        },
    };
    use bitcoin_scriptexec::ExecError;

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
        for position in 0..4 {
            let mut input = vec![0; 4];
            input[position] = if position % 2 == 0 { -1 } else { 256 };
            let result = execute_script(script! {
                for byte in input { { byte } }
                { u32_popcount() }
                OP_DROP OP_TRUE
            });
            assert!(!result.success, "accepted invalid byte at {position}");
        }

        for position in 0..4 {
            let mut witness = vec![vec![]; 4];
            witness[position] = vec![0, 0, 0, 0, 1];
            let result = execute_script_with_inputs_strict(
                script! {
                    { u32_popcount() }
                    OP_DROP OP_TRUE
                },
                witness,
            );
            assert!(!result.success, "accepted oversized byte at {position}");
        }
    }

    #[test]
    fn counts_boundary_bytes_in_every_limb_position() {
        for position in 0..4 {
            for value in [0u32, 1, 127, 128, 255] {
                let mut input = [0; 4];
                input[position] = value;
                let result = execute_script(script! {
                    for byte in input { { byte } }
                    { u32_popcount() }
                    { value.count_ones() } OP_EQUAL
                });
                assert!(
                    result.success,
                    "position={position} value={value:#04x}: {result}"
                );
            }
        }
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let result = execute_script(script! {
            OP_9 OP_TOALTSTACK
            77
            { u32_push(0) }
            { u32_popcount() }
            OP_0 OP_EQUALVERIFY
            77 OP_EQUALVERIFY
            OP_FROMALTSTACK 9 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "preserved state changed: {result}");
    }

    #[test]
    fn respects_combined_stack_frontier() {
        let maximum_witness = vec![vec![]; 738 + 4];
        let maximum = execute_script_with_inputs_strict(
            script! {
                { u32_popcount() }
                OP_DROP
                for _ in 0..738 { OP_DROP }
                OP_TRUE
            },
            maximum_witness,
        );
        assert!(maximum.success, "maximum preserved state failed: {maximum}");
        assert_eq!(maximum.stats.max_nb_stack_items, 1000);

        let over_budget = execute_script_with_inputs_strict(
            script! { { u32_popcount() } },
            vec![vec![]; 739 + 4],
        );
        assert_eq!(over_budget.error, Some(ExecError::StackSize));
    }

    #[test]
    fn returns_per_byte_counts_in_word_order() {
        let result = execute_script(script! {
            0x80 0x03 0xf0 0xff
            { u32_byte_popcounts() }
            8 OP_EQUALVERIFY
            4 OP_EQUALVERIFY
            2 OP_EQUALVERIFY
            1 OP_EQUAL
        });
        assert!(result.success, "per-byte popcount failed: {result}");
    }

    #[test]
    fn handles_zero_and_full_byte_boundaries() {
        for (value, expected) in [(0, 0), (255, 8)] {
            let result = execute_script(script! {
                { value } { value } { value } { value }
                { u32_byte_popcounts() }
                { expected } OP_EQUALVERIFY
                { expected } OP_EQUALVERIFY
                { expected } OP_EQUALVERIFY
                { expected } OP_EQUAL
            });
            assert!(result.success, "value={value}: {result}");
        }
    }

    #[test]
    fn rejects_non_byte_limbs_for_per_byte_counts() {
        for position in 0..4 {
            let mut input = vec![0; 4];
            input[position] = if position % 2 == 0 { -1 } else { 256 };
            let result = execute_script(script! {
                for byte in input { { byte } }
                { u32_byte_popcounts() }
                OP_2DROP OP_2DROP OP_TRUE
            });
            assert!(!result.success, "accepted invalid byte at {position}");
        }
    }
}
