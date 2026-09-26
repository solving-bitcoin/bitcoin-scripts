//! Checked squaring of a u4 value modulo 16.

use super::stack::u4_drop;
use crate::support::script::*;

/// Number of entries kept by the u4 square table.
pub const U4_SQUARE_TABLE_ITEMS: u32 = 16;

/// Push the lookup table for `value^2 mod 16`, indexed by `value`.
pub fn u4_push_square_table() -> Script {
    script! {
        for value in (0..U4_SQUARE_TABLE_ITEMS).rev() {
            { (value * value) % U4_SQUARE_TABLE_ITEMS }
        }
    }
}

/// Remove a square table pushed by [`u4_push_square_table`].
pub fn u4_drop_square_table() -> Script {
    u4_drop(U4_SQUARE_TABLE_ITEMS)
}

/// Check the top nibble and replace it with its square modulo 16.
///
/// Before: `preserved | table[16] | value`
/// After: `preserved | table[16] | (value^2 mod 16)`
pub fn u4_square_mod16() -> Script {
    script! {
        OP_DUP 0 16 OP_WITHIN OP_VERIFY
        OP_PICK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::execute_script;

    #[test]
    fn squares_every_nibble_and_preserves_surrounding_state() {
        for value in 0..16 {
            let result = execute_script(script! {
                7 OP_TOALTSTACK
                { (value * value) % 16 }
                { value }
                OP_TOALTSTACK
                { u4_push_square_table() }
                OP_FROMALTSTACK
                { u4_square_mod16() }
                OP_TOALTSTACK
                { u4_drop_square_table() }
                OP_FROMALTSTACK
                OP_EQUALVERIFY
                OP_FROMALTSTACK
                7 OP_EQUALVERIFY
                OP_TRUE
            });
            assert!(result.success, "square failed for {value}: {result}");
        }
    }

    #[test]
    fn rejects_out_of_range_values() {
        for value in [-1, 16] {
            let result = execute_script(script! {
                { 0 }
                { value }
                OP_TOALTSTACK
                { u4_push_square_table() }
                OP_FROMALTSTACK
                { u4_square_mod16() }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble {value}");
        }
    }
}
