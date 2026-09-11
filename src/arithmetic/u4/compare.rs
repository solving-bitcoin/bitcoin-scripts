//! Comparisons over fixed-width big-endian u4 vectors.

use crate::support::script::{script, Script};

use super::stack::u4_drop;

/// Return whether `left <= right` for two fixed-width big-endian u4 vectors.
///
/// Stack before: `left[0] ... left[n-1] right[0] ... right[n-1]`.
/// Stack after: `result`, where both vectors are consumed. Every input is
/// range-checked as a numeric nibble before the first comparison.
pub fn lexicographic_le(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "comparison width must be nonzero");
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
    #[should_panic(expected = "comparison width must be nonzero")]
    fn rejects_zero_width() {
        let _ = lexicographic_le(0);
    }
}
