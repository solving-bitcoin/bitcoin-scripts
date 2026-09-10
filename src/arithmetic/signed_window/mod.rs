//! Checked signed radix-32 digit decoding for scalar-window schedules.
//!
//! A digit is a minimally encoded ScriptNum in `[-31, 31]`. Its native sign
//! is emitted as one bit and its absolute value is expanded to five
//! big-endian magnitude bits. A shared staggered table avoids five conditional
//! branches per digit when a batch is large enough to amortize the table.

use crate::support::script::*;

/// Persistent table items for the five-bit magnitude lookup.
pub const SIGNED_RADIX32_TABLE_ITEMS: u32 = 5 * 31 + 1;

/// Largest no-preserved-state batch under the combined main/alt stack limit.
pub const SIGNED_RADIX32_MAX_BATCH: u32 = (1_000 - SIGNED_RADIX32_TABLE_ITEMS) / 6;

fn table_value_at_depth(depth: u32) -> u32 {
    if depth == 0 {
        return 0;
    }
    let magnitude = (depth + 4) / 5;
    let bit_in_be_order = depth - (5 * magnitude - 4);
    (magnitude >> (4 - bit_in_be_order)) & 1
}

/// Push the staggered magnitude table for values `0..=31`.
pub fn push_table() -> Script {
    script! {
        for depth in (0..SIGNED_RADIX32_TABLE_ITEMS).rev() {
            { table_value_at_depth(depth) }
        }
    }
}

/// Drop the complete magnitude table.
pub fn drop_table() -> Script {
    script! {
        for _ in 0..SIGNED_RADIX32_TABLE_ITEMS / 2 { OP_2DROP }
        if SIGNED_RADIX32_TABLE_ITEMS % 2 == 1 { OP_DROP }
    }
}

/// Decode one signed radix-32 digit to the altstack.
///
/// Before: `preserved | digit | table`
/// After: `preserved | table`, with `sign, mag_bit4, ..., mag_bit0`
/// appended to the altstack. The sign is `0` for nonnegative and `1` for
/// negative. With `check_input = false`, the caller must provide a canonical
/// ScriptNum in `[-31,31]`.
pub fn digit_to_altstack(check_input: bool) -> Script {
    script! {
        { SIGNED_RADIX32_TABLE_ITEMS }
        OP_ROLL

        if check_input {
            // x + 0 must serialize identically to x: reject non-minimal
            // ScriptNum encodings before using the value as a table index.
            OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
        }

        // Preserve the native ScriptNum sign and convert the index to its
        // nonnegative magnitude.
        OP_DUP 0 OP_LESSTHAN
        OP_SWAP OP_ABS
        OP_SWAP
        OP_TOALTSTACK

        if check_input {
            OP_DUP 0 { 32 } OP_WITHIN OP_VERIFY
        }

        // Five equal indices address one staggered row. The table stays below
        // the indices while each result is moved to the altstack.
        OP_DUP OP_DUP OP_2DUP
        OP_ADD OP_ADD OP_ADD OP_ADD
        OP_DUP OP_2DUP OP_DUP
        OP_PICK OP_TOALTSTACK
        OP_PICK OP_TOALTSTACK
        OP_PICK OP_TOALTSTACK
        OP_PICK OP_TOALTSTACK
        OP_PICK OP_TOALTSTACK
    }
}

/// Decode a contiguous batch of signed radix-32 digits to the altstack.
///
/// Inputs are consumed from the top down. Each digit contributes six output
/// items, so unrelated live state must fit below the documented batch bound.
pub fn digits_to_altstack(digit_count: u32, check_inputs: bool) -> Script {
    assert!(digit_count > 0, "signed radix-32 batch must not be empty");
    assert!(
        digit_count <= SIGNED_RADIX32_MAX_BATCH,
        "signed radix-32 batch exceeds Bitcoin Script's stack limit"
    );
    script! {
        { push_table() }
        for _ in 0..digit_count {
            { digit_to_altstack(check_inputs) }
        }
        { drop_table() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};

    fn assert_digit(digit: i64) {
        let magnitude = digit.unsigned_abs() as u32;
        let sign = u32::from(digit < 0);
        let result = execute_script(script! {
            { digit }
            { push_table() }
            { digit_to_altstack(true) }
            { drop_table() }
            for bit in 0..5 {
                OP_FROMALTSTACK
                { (magnitude >> bit) & 1 } OP_EQUALVERIFY
            }
            OP_FROMALTSTACK
            { sign } OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "digit {digit} failed: {result}");
    }

    #[test]
    fn exhaustive_signed_digits_decode() {
        for digit in -31..=31 {
            assert_digit(digit);
        }
    }

    #[test]
    fn batch_preserves_order_and_rejects_out_of_range_values() {
        let digits = [-31i64, -1, 0, 1, 31];
        let mut check = script! {
            for digit in digits { { digit } }
            { digits_to_altstack(digits.len() as u32, true) }
        };
        for digit in digits {
            let magnitude = digit.unsigned_abs() as u32;
            for bit in 0..5 {
                check = script! {
                    { check }
                    OP_FROMALTSTACK
                    { (magnitude >> bit) & 1 } OP_EQUALVERIFY
                };
            }
            check = script! {
                { check }
                OP_FROMALTSTACK
                { u32::from(digit < 0) } OP_EQUALVERIFY
            };
        }
        let result = execute_script(script! { { check } OP_TRUE });
        assert!(result.success, "batch failed: {result}");

        for invalid in [-32i64, 32] {
            let result = execute_script(script! {
                { invalid }
                { push_table() }
                { digit_to_altstack(true) }
            });
            assert!(!result.success, "accepted out-of-range digit {invalid}");
        }
    }

    #[test]
    fn rejects_nonminimal_and_strict_stack_overflow() {
        let nonminimal = script! {
            { vec![1u8, 0] }
            { push_table() }
            { digit_to_altstack(true) }
        }
        .compile_with_policy()
        .to_bytes();
        let result = execute_raw_script_with_inputs_strict(nonminimal, vec![]);
        assert!(result.error.is_some(), "accepted nonminimal digit");

        let result = execute_script(script! {
            for _ in 0..SIGNED_RADIX32_MAX_BATCH { 0 }
            { digits_to_altstack(SIGNED_RADIX32_MAX_BATCH, true) }
            OP_TRUE
        });
        assert!(result.success, "maximum batch failed: {result}");
        assert_eq!(
            result.stats.max_nb_stack_items,
            (SIGNED_RADIX32_TABLE_ITEMS + 6 * SIGNED_RADIX32_MAX_BATCH) as usize
        );
        assert!(std::panic::catch_unwind(|| digits_to_altstack(0, true)).is_err());
        assert!(std::panic::catch_unwind(|| {
            digits_to_altstack(SIGNED_RADIX32_MAX_BATCH + 1, true)
        })
        .is_err());
    }
}
