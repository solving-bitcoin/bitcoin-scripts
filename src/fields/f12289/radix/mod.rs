//! Radix-decomposition multiplication for Falcon's coefficient field.

use crate::support::script::*;

use crate::arithmetic::u31::{u31_add, U31Config, U31_LOOKUP_STACK_LIMIT};
use crate::fields::f12289::u31::F12289;

fn radix_parameters(radix_bits: u32) -> (u32, u32, u32) {
    assert!(
        (1..31).contains(&radix_bits),
        "radix width must be in 1..31"
    );
    let radix = 1u32 << radix_bits;
    let high_max = (F12289::MODULUS - 1) / radix;
    let table_items = radix + high_max + 1;
    assert!(
        u64::from(table_items) + 4 <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "radix multiplication tables and one query do not fit the stack limit"
    );
    (radix, high_max, table_items)
}

/// Return the combined number of high- and low-radix table entries.
pub fn radix_mul_table_items(radix_bits: u32) -> u32 {
    radix_parameters(radix_bits).2
}

/// Push the high- and low-radix tables for one generation-time constant.
///
/// The high table is deepest and the low table nearest the top, with entry
/// zero nearest the top of each region. For `F12289` and `radix_bits = 7`, the
/// tables contain 97 high entries and 128 low entries, or 225 items total.
pub fn push_radix_mul_tables(constant: u32, radix_bits: u32) -> Script {
    let (radix, high_max, _) = radix_parameters(radix_bits);
    let modulus = F12289::MODULUS as u64;
    let constant = constant as u64 % modulus;
    let high_entries = (0..=high_max)
        .rev()
        .map(|high| (constant * radix as u64 * high as u64 % modulus) as u32)
        .collect::<Vec<_>>();
    let low_entries = (0..radix)
        .rev()
        .map(|low| (constant * low as u64 % modulus) as u32)
        .collect::<Vec<_>>();

    script! {
        for entry in high_entries {
            { entry }
        }
        for entry in low_entries {
            { entry }
        }
    }
}

fn split_radix(radix_bits: u32) -> Script {
    let bit_width = 32 - (F12289::MODULUS - 1).leading_zeros();
    script! {
        0 OP_SWAP
        for bit in (radix_bits..bit_width).rev() {
            OP_DUP
            { 1u32 << bit }
            OP_GREATERTHANOREQUAL
            OP_IF
                { 1u32 << bit }
                OP_SUB
                OP_SWAP
                { 1u32 << (bit - radix_bits) }
                OP_ADD
                OP_SWAP
            OP_ENDIF
        }
    }
}

/// Consume one canonical input and multiply it through radix tables.
///
/// Input layout: `tables | preserved_items | x`. Both table regions and the
/// preserved items remain, and one canonical product is returned.
pub fn mul_by_constant_from_radix_tables(radix_bits: u32, preserved_items: u32) -> Script {
    let (radix, _, table_items) = radix_parameters(radix_bits);
    let peak_items = u64::from(table_items) + u64::from(preserved_items) + 4;
    assert!(
        peak_items <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "radix lookup query exceeds Bitcoin Script's stack limit"
    );

    let low_table_depth = preserved_items + 1;
    let high_table_depth = preserved_items + radix;
    script! {
        { split_radix(radix_bits) }
        { low_table_depth } OP_ADD OP_PICK OP_TOALTSTACK
        { high_table_depth } OP_ADD OP_PICK
        OP_FROMALTSTACK
        { u31_add::<F12289>() }
    }
}

/// Drop both radix multiplication tables from the main stack.
pub fn drop_radix_mul_tables(radix_bits: u32) -> Script {
    let table_items = radix_mul_table_items(radix_bits);
    script! {
        for _ in 0..table_items / 2 {
            OP_2DROP
        }
        if table_items % 2 == 1 {
            OP_DROP
        }
    }
}

/// Multiply a contiguous batch through one pair of radix tables.
pub fn mul_by_constant_radix_lookup_batch(constant: u32, radix_bits: u32, count: u32) -> Script {
    if count == 0 {
        return script! {};
    }

    let table_items = radix_mul_table_items(radix_bits);
    let peak_items = u64::from(table_items) + u64::from(count) + 3;
    assert!(
        peak_items <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "radix lookup tables and batch exceed Bitcoin Script's stack limit"
    );

    script! {
        for _ in 0..count {
            OP_TOALTSTACK
        }
        { push_radix_mul_tables(constant, radix_bits) }
        for preserved_items in 0..count {
            OP_FROMALTSTACK
            { mul_by_constant_from_radix_tables(radix_bits, preserved_items) }
        }
        for _ in 0..count {
            OP_TOALTSTACK
        }
        { drop_radix_mul_tables(radix_bits) }
        for _ in 0..count {
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{execution::execute_script, script::script};

    fn mul_mod(value: u32, constant: u32) -> u32 {
        (value as u64 * constant as u64 % F12289::MODULUS as u64) as u32
    }

    fn check(value: u32, constant: u32) {
        let expected = mul_mod(value, constant);
        let result = execute_script(script! {
            { push_radix_mul_tables(constant, 7) }
            { value }
            { mul_by_constant_from_radix_tables(7, 0) }
            { expected } OP_EQUALVERIFY
            { drop_radix_mul_tables(7) }
            OP_TRUE
        });
        assert!(
            result.success,
            "radix lookup failed for value={value}, constant={constant}: {result}"
        );
    }

    #[test]
    fn radix_128_lookup_is_correct() {
        for value in 0..F12289::MODULUS {
            check(value, 10_000);
        }
        for constant in [0, 1, 2, 42, 12_288, u32::MAX] {
            for value in [0, 1, 127, 128, 255, 256, 12_287, 12_288] {
                check(value, constant);
            }
        }
    }

    #[test]
    fn radix_128_batch_preserves_order() {
        let constant = 10_000;
        let values = [0, 1, 127, 128, 255, 256, 12_287, 12_288];
        let expected = values.map(|value| mul_mod(value, constant));
        let result = execute_script(script! {
            for value in values {
                { value }
            }
            { mul_by_constant_radix_lookup_batch(constant, 7, values.len() as u32) }
            for value in expected.iter().rev() {
                { *value } OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(result.success, "radix batch failed: {result}");
    }

    #[test]
    fn radix_tables_fit_beside_a_512_coefficient_state() {
        assert_eq!(radix_mul_table_items(7), 225);
        let result = execute_script(script! {
            { push_radix_mul_tables(10_000, 7) }
            for _ in 0..511 {
                { 12_288u32 }
            }
            { 12_287u32 }
            { mul_by_constant_from_radix_tables(7, 511) }
            { mul_mod(12_287, 10_000) } OP_EQUALVERIFY
            for _ in 0..511 {
                OP_DROP
            }
            { drop_radix_mul_tables(7) }
            OP_TRUE
        });
        assert!(result.success, "stacked radix lookup failed: {result}");
        assert_eq!(result.stats.max_nb_stack_items, 740);
    }

    #[test]
    #[should_panic(expected = "radix lookup tables and batch exceed Bitcoin Script's stack limit")]
    fn radix_batch_rejects_wrapping_count() {
        let _ = mul_by_constant_radix_lookup_batch(1, 7, u32::MAX);
    }

    #[test]
    #[should_panic(expected = "radix lookup query exceeds Bitcoin Script's stack limit")]
    fn radix_query_rejects_wrapping_depth() {
        let _ = mul_by_constant_from_radix_tables(7, u32::MAX);
    }
}
