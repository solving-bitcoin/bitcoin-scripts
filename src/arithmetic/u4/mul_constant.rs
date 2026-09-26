//! Checked multiplication by a public u4 constant modulo 16.

use super::stack::u4_drop;
use crate::support::script::*;

/// Number of entries kept by a constant multiplication table.
pub const U4_MUL_CONSTANT_TABLE_ITEMS: u32 = 16;

/// Push the lookup table for `constant * value mod 16`, indexed by `value`.
pub fn u4_push_mul_constant_table(constant: u32) -> Script {
    assert!(constant < U4_MUL_CONSTANT_TABLE_ITEMS);
    script! {
        for value in (0..U4_MUL_CONSTANT_TABLE_ITEMS).rev() {
            { (constant * value) % U4_MUL_CONSTANT_TABLE_ITEMS }
        }
    }
}

/// Remove a constant multiplication table pushed by
/// [`u4_push_mul_constant_table`].
pub fn u4_drop_mul_constant_table() -> Script {
    u4_drop(U4_MUL_CONSTANT_TABLE_ITEMS)
}

/// Check the top nibble and replace it with the table result.
///
/// Before: `preserved | table[16] | value`
/// After: `preserved | table[16] | (constant * value mod 16)`
///
/// The table is deliberately left resident so callers can reuse it across
/// multiple queries or drop it at their chosen composition boundary.
pub fn u4_mul_constant_mod16() -> Script {
    script! {
        OP_DUP 0 16 OP_WITHIN OP_VERIFY
        OP_PICK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::execute_script;

    fn run(constant: u32, value: i32) -> crate::support::execution::ExecuteInfo {
        execute_script(script! {
            7 OP_TOALTSTACK
            { (constant * value as u32) % 16 }
            { value }
            OP_TOALTSTACK
            { u4_push_mul_constant_table(constant) }
            OP_FROMALTSTACK
            { u4_mul_constant_mod16() }
            OP_TOALTSTACK
            { u4_drop_mul_constant_table() }
            OP_FROMALTSTACK
            OP_EQUALVERIFY
            OP_FROMALTSTACK
            7 OP_EQUALVERIFY
            OP_TRUE
        })
    }

    #[test]
    fn multiplies_every_nibble_and_preserves_surrounding_state() {
        for value in 0..16 {
            let result = run(10, value);
            assert!(
                result.success,
                "constant product failed for {value}: {result}"
            );
        }
    }

    #[test]
    fn rejects_out_of_range_values() {
        for value in [-1, 16] {
            let result = execute_script(script! {
                { 0 }
                { value }
                OP_TOALTSTACK
                { u4_push_mul_constant_table(10) }
                OP_FROMALTSTACK
                { u4_mul_constant_mod16() }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble {value}");
        }
    }

    #[test]
    fn rejects_an_invalid_constant() {
        assert!(std::panic::catch_unwind(|| u4_push_mul_constant_table(16)).is_err());
    }
}
