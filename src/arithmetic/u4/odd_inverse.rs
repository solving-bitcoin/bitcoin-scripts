//! Checked inversion of odd u4 values modulo 16.

use super::stack::u4_drop;
use crate::support::script::*;

/// Number of entries kept by the odd-unit inverse table.
pub const U4_ODD_INVERSE_TABLE_ITEMS: u32 = 16;

fn inverse(value: u32) -> u32 {
    match value {
        1 => 1,
        3 => 11,
        5 => 13,
        7 => 7,
        9 => 9,
        11 => 3,
        13 => 5,
        15 => 15,
        _ => 0,
    }
}

/// Push the lookup table for odd `value^-1 mod 16`, indexed by `value`.
pub fn u4_push_odd_inverse_table() -> Script {
    script! {
        for value in (0..U4_ODD_INVERSE_TABLE_ITEMS).rev() {
            { inverse(value) }
        }
    }
}

/// Remove a table pushed by [`u4_push_odd_inverse_table`].
pub fn u4_drop_odd_inverse_table() -> Script {
    u4_drop(U4_ODD_INVERSE_TABLE_ITEMS)
}

/// Check an odd u4 value and replace it with its multiplicative inverse modulo 16.
///
/// Before: `preserved | table[16] | value`\
/// After: `preserved | table[16] | value^-1 mod 16`
pub fn u4_odd_inverse_mod16() -> Script {
    script! {
        OP_DUP 0 16 OP_WITHIN OP_VERIFY
        OP_PICK
        OP_DUP OP_0NOTEQUAL OP_VERIFY
        OP_SWAP OP_DROP
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::execute_script;

    fn run(value: u32) -> crate::support::execution::ExecuteInfo {
        execute_script(script! {
            7 OP_TOALTSTACK
            { inverse(value) }
            { value }
            OP_TOALTSTACK
            { u4_push_odd_inverse_table() }
            OP_FROMALTSTACK
            { u4_odd_inverse_mod16() }
            OP_TOALTSTACK
            { u4_drop_odd_inverse_table() }
            OP_FROMALTSTACK
            OP_EQUALVERIFY
            OP_FROMALTSTACK
            7 OP_EQUALVERIFY
            OP_TRUE
        })
    }

    #[test]
    fn inverts_every_odd_nibble_and_preserves_surrounding_state() {
        for value in (1..16).step_by(2) {
            let result = run(value);
            assert!(result.success, "inverse failed for {value}: {result}");
        }
    }

    #[test]
    fn rejects_even_and_out_of_range_values() {
        for value in [0, 2, 4, 6, 8, 10, 12, 14, 16, -1] {
            let result = execute_script(script! {
                { 0 }
                { value }
                OP_TOALTSTACK
                { u4_push_odd_inverse_table() }
                OP_FROMALTSTACK
                { u4_odd_inverse_mod16() }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid odd unit {value}");
        }
    }
}
