use crate::support::script::*;

use super::{u31_adjust, U31Config};

/// Bitcoin Script's combined main-stack and altstack item limit.
pub const U31_LOOKUP_STACK_LIMIT: u32 = 1_000;

fn checked_lookup_modulus<C: U31Config>() -> u32 {
    assert!(
        (2..U31_LOOKUP_STACK_LIMIT).contains(&C::MODULUS),
        "a direct lookup table requires a modulus in 2..1000"
    );
    C::MODULUS
}

/// Push a complete table for multiplication by a generation-time constant.
///
/// Entry `x` is `(constant * x) mod p`. Entries are pushed in reverse order,
/// leaving entry zero nearest the top of the stack. The table occupies `p`
/// stack items and is intended to be reused for several multiplications.
pub fn u31_push_mul_by_constant_table<C: U31Config>(constant: u32) -> Script {
    let modulus = checked_lookup_modulus::<C>();
    let constant = (constant as u64 % modulus as u64) as u32;

    script! {
        for value in (0..modulus).rev() {
            { (value as u64 * constant as u64 % modulus as u64) as u32 }
        }
    }
}

/// Consume one canonical input and copy its product from a table below it.
///
/// The input layout is `table | preserved_items | x`, where
/// `preserved_items` is the number passed to this generator. The table and
/// preserved items remain, `x` is consumed, and the product is pushed. Inputs
/// are assumed canonical; this fragment does not range-check `x`.
pub fn u31_mul_by_constant_from_table(preserved_items: u32) -> Script {
    assert!(
        u64::from(preserved_items) + 4 <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "direct lookup query cannot fit Bitcoin Script's stack limit"
    );

    script! {
        if preserved_items > 0 {
            { preserved_items }
            OP_ADD
        }
        OP_PICK
    }
}

/// Drop a direct multiplication table from the top of the main stack.
pub fn u31_drop_mul_by_constant_table<C: U31Config>() -> Script {
    let modulus = checked_lookup_modulus::<C>();
    script! {
        for _ in 0..modulus / 2 {
            OP_2DROP
        }
        if modulus % 2 == 1 {
            OP_DROP
        }
    }
}

/// Multiply a batch of contiguous canonical values by one constant.
///
/// Input and output order are preserved. The direct table is installed once,
/// queried `count` times, and removed. This is normally smaller than repeated
/// addition chains only once the table setup has been amortized across several
/// values. The generated primitive rejects batches that would exceed the
/// 1,000-item combined stack limit by themselves.
pub fn u31_mul_by_constant_lookup_batch<C: U31Config>(constant: u32, count: u32) -> Script {
    if count == 0 {
        return script! {};
    }

    let modulus = checked_lookup_modulus::<C>();
    let peak_items = u64::from(modulus) + u64::from(count) + 1;
    assert!(
        peak_items <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "lookup table and batch exceed Bitcoin Script's stack limit"
    );

    script! {
        // Keep the inputs out of the way while the table is installed. Moving
        // all of them reverses their order on the altstack, so the deepest
        // input is restored and processed first.
        for _ in 0..count {
            OP_TOALTSTACK
        }
        { u31_push_mul_by_constant_table::<C>(constant) }

        for preserved_items in 0..count {
            OP_FROMALTSTACK
            { u31_mul_by_constant_from_table(preserved_items) }
        }

        // Move the products aside, remove the table, and restore the products
        // in their original order.
        for _ in 0..count {
            OP_TOALTSTACK
        }
        { u31_drop_mul_by_constant_table::<C>() }
        for _ in 0..count {
            OP_FROMALTSTACK
        }
    }
}

/// Single-value convenience wrapper around
/// [`u31_mul_by_constant_lookup_batch`].
pub fn u31_mul_by_constant_lookup<C: U31Config>(constant: u32) -> Script {
    u31_mul_by_constant_lookup_batch::<C>(constant, 1)
}

/// Return the number of entries in a symmetry-reduced constant table.
pub fn u31_half_mul_table_items<C: U31Config>() -> u32 {
    let modulus = C::MODULUS;
    assert!(
        (3..(1 << 31)).contains(&modulus) && modulus % 2 == 1,
        "a half table requires an odd modulus in 3..2^31"
    );
    let table_items = modulus / 2 + 1;
    assert!(
        u64::from(table_items) + 3 <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "half lookup table and one query do not fit Bitcoin Script's stack limit"
    );
    table_items
}

/// Push the symmetry-reduced table for multiplication by a constant.
///
/// Only magnitudes `0..=p/2` are stored. Products use centered table entries,
/// while [`u31_mul_by_constant_from_half_table`] converts the selected result
/// back to the canonical representation. This nearly halves the table's stack
/// and script footprint for odd moduli.
pub fn u31_push_half_mul_by_constant_table<C: U31Config>(constant: u32) -> Script {
    let _ = u31_half_mul_table_items::<C>();
    let modulus = C::MODULUS;
    let largest_magnitude = modulus / 2;
    let constant = (constant as u64 % modulus as u64) as u32;
    let entries = (0..=largest_magnitude)
        .rev()
        .map(|magnitude| {
            let product = (magnitude as u64 * constant as u64 % modulus as u64) as u32;
            if product > largest_magnitude {
                product as i64 - modulus as i64
            } else {
                product as i64
            }
        })
        .collect::<Vec<_>>();

    script! {
        for entry in entries {
            { entry }
        }
    }
}

/// Consume one canonical input and multiply through a symmetry-reduced table.
///
/// The layout is `half_table | preserved_items | x`. The result is canonical;
/// the table and preserved items remain in place.
pub fn u31_mul_by_constant_from_half_table<C: U31Config>(preserved_items: u32) -> Script {
    let table_items = u31_half_mul_table_items::<C>();
    let peak_items = u64::from(table_items) + u64::from(preserved_items) + 3;
    assert!(
        peak_items <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "half lookup query exceeds Bitcoin Script's stack limit"
    );
    let modulus = C::MODULUS;
    let largest_magnitude = modulus / 2;

    script! {
        OP_DUP
        { largest_magnitude }
        OP_GREATERTHAN
        OP_IF
            { modulus }
            OP_SWAP OP_SUB
            if preserved_items > 0 {
                { preserved_items }
                OP_ADD
            }
            OP_PICK
            OP_NEGATE
        OP_ELSE
            if preserved_items > 0 {
                { preserved_items }
                OP_ADD
            }
            OP_PICK
        OP_ENDIF
        { u31_adjust::<C>() }
    }
}

/// Drop a symmetry-reduced multiplication table from the main stack.
pub fn u31_drop_half_mul_by_constant_table<C: U31Config>() -> Script {
    let table_items = u31_half_mul_table_items::<C>();
    script! {
        for _ in 0..table_items / 2 {
            OP_2DROP
        }
        if table_items % 2 == 1 {
            OP_DROP
        }
    }
}

/// Multiply a contiguous batch through one symmetry-reduced constant table.
pub fn u31_mul_by_constant_half_lookup_batch<C: U31Config>(constant: u32, count: u32) -> Script {
    if count == 0 {
        return script! {};
    }

    let table_items = u31_half_mul_table_items::<C>();
    let peak_items = u64::from(table_items) + u64::from(count) + 2;
    assert!(
        peak_items <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "half lookup table and batch exceed Bitcoin Script's stack limit"
    );

    script! {
        for _ in 0..count {
            OP_TOALTSTACK
        }
        { u31_push_half_mul_by_constant_table::<C>(constant) }
        for preserved_items in 0..count {
            OP_FROMALTSTACK
            { u31_mul_by_constant_from_half_table::<C>(preserved_items) }
        }
        for _ in 0..count {
            OP_TOALTSTACK
        }
        { u31_drop_half_mul_by_constant_table::<C>() }
        for _ in 0..count {
            OP_FROMALTSTACK
        }
    }
}

/// Single-value convenience wrapper for a symmetry-reduced table.
pub fn u31_mul_by_constant_half_lookup<C: U31Config>(constant: u32) -> Script {
    u31_mul_by_constant_half_lookup_batch::<C>(constant, 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{execution::execute_script, script::script};

    use crate::fields::m31::u31::M31;

    struct TestField257;

    impl U31Config for TestField257 {
        const MODULUS: u32 = 257;
    }

    fn mul_mod_257(value: u32, constant: u32) -> u32 {
        (value as u64 * constant as u64 % TestField257::MODULUS as u64) as u32
    }

    #[test]
    fn direct_lookup_preserves_items_above_the_table() {
        let value = 201;
        let constant = 173;
        let expected = mul_mod_257(value, constant);
        let result = execute_script(script! {
            { u31_push_mul_by_constant_table::<TestField257>(constant) }
            42
            { value }
            { u31_mul_by_constant_from_table(1) }
            { expected }
            OP_EQUALVERIFY
            42
            OP_EQUALVERIFY
            { u31_drop_mul_by_constant_table::<TestField257>() }
            OP_TRUE
        });
        assert!(result.success, "direct table lookup failed: {result}");
    }

    #[test]
    fn lookup_constant_multiplication_is_correct() {
        for constant in [0, 1, 2, 42, 128, 173, 256, u32::MAX] {
            for value in [0, 1, 2, 127, 128, 255, 256] {
                let expected = mul_mod_257(value, constant);
                let result = execute_script(script! {
                    { value }
                    { u31_mul_by_constant_lookup::<TestField257>(constant) }
                    { expected }
                    OP_EQUAL
                });
                assert!(
                    result.success,
                    "lookup multiplication failed for value={value}, constant={constant}: {result}"
                );
            }
        }
    }

    #[test]
    fn lookup_batch_preserves_input_order() {
        let constant = 173;
        let values = [0, 1, 2, 17, 128, 200, 255, 256];
        let expected = values.map(|value| mul_mod_257(value, constant));
        let result = execute_script(script! {
            for value in values {
                { value }
            }
            { u31_mul_by_constant_lookup_batch::<TestField257>(constant, values.len() as u32) }
            for value in expected.iter().rev() {
                { *value }
                OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(result.success, "lookup batch failed: {result}");
        assert_eq!(result.stats.max_nb_stack_items, 266);
    }

    #[test]
    fn half_lookup_constant_multiplication_is_correct() {
        for constant in [0, 1, 2, 42, 128, 173, 256, u32::MAX] {
            for value in 0..TestField257::MODULUS {
                let expected = mul_mod_257(value, constant);
                let result = execute_script(script! {
                    { value }
                    { u31_mul_by_constant_half_lookup::<TestField257>(constant) }
                    { expected }
                    OP_EQUAL
                });
                assert!(
                    result.success,
                    "half lookup failed for value={value}, constant={constant}: {result}"
                );
            }
        }
    }

    #[test]
    fn half_lookup_batch_preserves_input_order() {
        let constant = 173;
        let values = [0, 1, 2, 17, 128, 200, 255, 256];
        let expected = values.map(|value| mul_mod_257(value, constant));
        let result = execute_script(script! {
            for value in values {
                { value }
            }
            { u31_mul_by_constant_half_lookup_batch::<TestField257>(constant, values.len() as u32) }
            for value in expected.iter().rev() {
                { *value }
                OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(result.success, "half lookup batch failed: {result}");
        assert_eq!(result.stats.max_nb_stack_items, 139);
    }

    #[test]
    #[should_panic(expected = "stack limit")]
    fn lookup_batch_rejects_stack_overflow() {
        let _ = u31_mul_by_constant_lookup_batch::<TestField257>(1, 743);
    }

    #[test]
    #[should_panic(expected = "lookup table and batch exceed Bitcoin Script's stack limit")]
    fn lookup_batch_rejects_wrapping_count() {
        let _ = u31_mul_by_constant_lookup_batch::<TestField257>(1, u32::MAX);
    }

    #[test]
    #[should_panic(expected = "direct lookup query cannot fit Bitcoin Script's stack limit")]
    fn direct_lookup_rejects_wrapping_depth() {
        let _ = u31_mul_by_constant_from_table(u32::MAX);
    }

    #[test]
    #[should_panic(
        expected = "half lookup table and one query do not fit Bitcoin Script's stack limit"
    )]
    fn half_lookup_rejects_oversized_modulus() {
        let _ = u31_push_half_mul_by_constant_table::<M31>(1);
    }

    #[test]
    #[should_panic(expected = "half lookup table and batch exceed Bitcoin Script's stack limit")]
    fn half_lookup_batch_rejects_wrapping_count() {
        let _ = u31_mul_by_constant_half_lookup_batch::<TestField257>(1, u32::MAX);
    }

    #[test]
    #[should_panic(expected = "half lookup query exceeds Bitcoin Script's stack limit")]
    fn half_lookup_rejects_wrapping_depth() {
        let _ = u31_mul_by_constant_from_half_table::<TestField257>(u32::MAX);
    }
}
