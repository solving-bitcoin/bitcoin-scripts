//! Checked interleaving of two equal-width u4 vectors.

use super::stack::u4_drop;
use crate::support::script::*;

/// Largest standalone width that keeps both input and output vectors below the
/// 1,000-item combined stack limit.
pub const U4_INTERLEAVE_MAX_WIDTH: u32 = 249;

/// Interleave two checked vectors of the same width.
///
/// Stack before: `preserved | left[0] ... left[n-1] | right[0] ... right[n-1]`.
/// Stack after: `preserved | left[0] right[0] ... left[n-1] right[n-1]`.
pub fn u4_nibbles_interleave(width: u32) -> Script {
    assert!(width > 0, "interleave width must be nonzero");
    assert!(
        width <= U4_INTERLEAVE_MAX_WIDTH,
        "interleave width exceeds Bitcoin Script's stack limit"
    );
    let input_count = 2 * width;

    script! {
        for index in 0..input_count {
            { input_count - 1 - index } OP_PICK
            OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
            16 OP_LESSTHAN OP_VERIFY
        }
        for index in (0..width).rev() {
            { width - 1 - index } OP_PICK
            OP_TOALTSTACK
            { input_count - 1 - index } OP_PICK
            OP_TOALTSTACK
        }
        { u4_drop(input_count) }
        for _ in 0..input_count {
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
    fn interleaves_equal_width_vectors_in_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("123") }
            { u4_hex_to_nibbles("abc") }
            { u4_nibbles_interleave(3) }
            12 OP_EQUALVERIFY
            3 OP_EQUALVERIFY
            11 OP_EQUALVERIFY
            2 OP_EQUALVERIFY
            10 OP_EQUALVERIFY
            1 OP_EQUAL
        });
        assert!(result.success, "vector interleave failed: {result}");
    }

    #[test]
    fn preserves_singletons_and_surrounding_stack_state() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            { u4_hex_to_nibbles("4") }
            { u4_hex_to_nibbles("d") }
            { u4_nibbles_interleave(1) }
            13 OP_EQUALVERIFY
            4 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUAL
        });
        assert!(result.success, "stack preservation failed: {result}");
    }

    #[test]
    fn rejects_invalid_nibbles_and_widths() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid } 1
                2 3
                { u4_nibbles_interleave(2) }
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_interleave(0)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_interleave(U4_INTERLEAVE_MAX_WIDTH + 1)
        })
        .is_err());
    }
}
