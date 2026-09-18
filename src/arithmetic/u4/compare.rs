//! Comparisons over fixed-width big-endian u4 vectors.

use crate::support::script::{script, Script};

use super::stack::u4_drop;

const MAX_NIBBLE_COUNT: u32 = 498;

/// Return whether `left <= right` for two fixed-width big-endian u4 vectors.
///
/// Stack before: `left[0] ... left[n-1] right[0] ... right[n-1]`.
/// Stack after: `result`, where both vectors are consumed. Every input is
/// range-checked as a numeric nibble before the first comparison. The input
/// vectors and three transient items must fit the combined 1,000-item stack
/// limit, so `n` is limited to 498.
pub fn lexicographic_le(nibble_count: u32) -> Script {
    assert!(
        (1..=MAX_NIBBLE_COUNT).contains(&nibble_count),
        "comparison width must be in 1..={MAX_NIBBLE_COUNT}"
    );
    let input_count = nibble_count * 2;

    script! {
        for index in 0..input_count {
            { index }
            OP_PICK
            OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
            16 OP_LESSTHAN OP_VERIFY
        }

        // The altstack holds the result; the main stack carries an active flag
        // while the prefixes remain equal.
        1 OP_TOALTSTACK
        1
        for index in 0..nibble_count {
            OP_IF
                // If left < right, the final result is true.
                { 2 * nibble_count - 1 - index } OP_PICK
                { nibble_count - index } OP_PICK
                OP_LESSTHAN
                OP_IF
                    OP_FROMALTSTACK OP_DROP
                    1 OP_TOALTSTACK
                    0
                OP_ELSE
                    // The first comparison was false; test right < left.
                    { nibble_count - 1 - index } OP_PICK
                    { 2 * nibble_count - index } OP_PICK
                    OP_LESSTHAN
                    OP_IF
                        OP_FROMALTSTACK OP_DROP
                        0 OP_TOALTSTACK
                        0
                    OP_ELSE
                        1
                    OP_ENDIF
                OP_ENDIF
            OP_ELSE
                0
            OP_ENDIF
        }

        OP_DROP
        OP_FROMALTSTACK OP_TOALTSTACK
        { u4_drop(input_count) }
        OP_FROMALTSTACK
    }
}

/// Return whether a fixed-width u4 vector is less than or equal to an embedded
/// big-endian constant vector.
pub fn lexicographic_le_constant(constant: &[u8]) -> Script {
    assert!(
        (1..=MAX_NIBBLE_COUNT as usize).contains(&constant.len()),
        "comparison constant width must be in 1..={MAX_NIBBLE_COUNT}"
    );
    assert!(
        constant.iter().all(|&nibble| nibble < 16),
        "comparison constant must contain only u4 nibbles"
    );
    script! {
        for &nibble in constant {
            { nibble }
        }
        { lexicographic_le(constant.len() as u32) }
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
    fn compares_all_two_nibble_values() {
        for left in 0..=0xffu16 {
            for right in 0..=0xffu16 {
                let left_hex = format!("{left:02x}");
                let right_hex = format!("{right:02x}");
                let expected = i64::from(left <= right);
                let result = execute_script(script! {
                    { u4_hex_to_nibbles(&left_hex) }
                    { u4_hex_to_nibbles(&right_hex) }
                    { lexicographic_le(2) }
                    { expected } OP_EQUAL
                });
                assert!(
                    result.success,
                    "left={left:#04x} right={right:#04x}: {result}"
                );
            }
        }
    }

    #[test]
    fn rejects_an_out_of_range_nibble() {
        let result = execute_script(script! {
            0 16
            { lexicographic_le(1) }
        });
        assert!(!result.success);
    }

    #[test]
    #[should_panic(expected = "comparison width must be in 1..=498")]
    fn rejects_zero_width() {
        let _ = lexicographic_le(0);
    }

    #[test]
    #[should_panic(expected = "comparison width must be in 1..=498")]
    fn rejects_width_above_combined_stack_budget() {
        let _ = lexicographic_le(499);
    }

    #[test]
    #[should_panic(expected = "comparison width must be in 1..=498")]
    fn rejects_width_before_u32_multiplication() {
        let _ = lexicographic_le(u32::MAX);
    }

    #[test]
    fn maximum_width_stays_within_combined_stack_budget() {
        let result = crate::support::execution::execute_script_with_inputs_strict(
            lexicographic_le(MAX_NIBBLE_COUNT),
            vec![Vec::new(); (MAX_NIBBLE_COUNT * 2) as usize],
        );
        assert!(result.success, "maximum width failed: {result}");
        assert_eq!(result.stats.max_nb_stack_items, 999);
    }

    #[test]
    fn compares_against_embedded_constant() {
        let constant = [0x0a, 0x0b];
        for value in 0..=0xffu16 {
            let left = [(value >> 4) as u8, (value & 0x0f) as u8];
            let result = execute_script(script! {
                for nibble in left {
                    { nibble }
                }
                { lexicographic_le_constant(&constant) }
                { (left <= constant) as u32 }
                OP_EQUAL
            });
            assert!(
                result.success,
                "embedded comparison failed for {left:02x?} <= {constant:02x?}: {result}"
            );
        }
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let constant = [0x0a, 0x0b];
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            10 10
            { lexicographic_le_constant(&constant) }
            OP_1 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "embedded comparison changed surrounding state: {result}"
        );
    }

    #[test]
    #[should_panic(expected = "comparison constant must contain only u4 nibbles")]
    fn rejects_out_of_range_constant() {
        let _ = lexicographic_le_constant(&[0x10]);
    }

    #[test]
    #[should_panic(expected = "comparison constant width must be in 1..=498")]
    fn rejects_empty_constant() {
        let _ = lexicographic_le_constant(&[]);
    }

    #[test]
    #[should_panic(expected = "comparison constant width must be in 1..=498")]
    fn rejects_constant_above_combined_stack_budget() {
        let _ = lexicographic_le_constant(&[0; 499]);
    }
}
