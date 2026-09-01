//! Lookup multiplication specialized for the centered `F257` representation.
//!
//! The complete multiplication memory consists of a 129-item absolute-value
//! discrete-log table and a 256-item exponent table. It can be shared by
//! variable and constant multiplications and still fits beside a 512-item
//! polynomial state under Bitcoin Script's 1,000-item combined stack limit.

use crate::script::*;

use crate::arithmetic::u31::{U31Config, U31_LOOKUP_STACK_LIMIT};

/// The prime field with modulus `257`.
///
/// This small field is useful for lookup-table experiments and incomplete
/// NTTs whose base cases are degree-four extensions.
pub struct F257;

impl U31Config for F257 {
    const MODULUS: u32 = 257;
}

/// Number of stack items occupied by the shared F257 log/exp memory.
pub const LOG_MUL_TABLE_ITEMS: u32 = 385;

/// Number of stack items occupied by the centered square table.
pub const SQUARE_TABLE_ITEMS: u32 = 129;

const F257_MODULUS: i32 = 257;
const F257_GENERATOR: i32 = 3;

fn f257_center(value: i32) -> i32 {
    let canonical = value.rem_euclid(F257_MODULUS);
    if canonical > 128 {
        canonical - F257_MODULUS
    } else {
        canonical
    }
}

fn f257_pow(mut base: i32, mut exponent: usize) -> i32 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = result * base % F257_MODULUS;
        }
        base = base * base % F257_MODULUS;
        exponent >>= 1;
    }
    result
}

fn f257_logs() -> [u32; 257] {
    let mut result = [u32::MAX; 257];
    for exponent in 0..256 {
        result[f257_pow(F257_GENERATOR, exponent) as usize] = exponent as u32;
    }
    debug_assert!(result[1..].iter().all(|value| *value != u32::MAX));
    result
}

fn drop_items(items: u32) -> Script {
    script! {
        for _ in 0..items {
            OP_DROP
        }
    }
}

/// Convert a canonical F257 element in `0..=256` to `-128..=128`.
pub fn to_centered() -> Script {
    script! {
        OP_DUP 128 OP_GREATERTHAN
        OP_IF
            257 OP_SUB
        OP_ENDIF
    }
}

/// Convert a centered F257 element in `-128..=128` to `0..=256`.
pub fn to_canonical() -> Script {
    script! {
        OP_DUP 0 OP_LESSTHAN
        OP_IF
            257 OP_ADD
        OP_ENDIF
    }
}

/// Push the shared absolute-log and full exponent tables for F257.
///
/// The exponent table is deepest and the absolute-log table is nearest the
/// top. Both use entry zero nearest the top of their respective region.
pub fn push_log_mul_tables() -> Script {
    let logs = f257_logs();
    script! {
        for exponent in (0usize..256).rev() {
            { f257_center(f257_pow(F257_GENERATOR, exponent)) }
        }
        for magnitude in (0usize..=128).rev() {
            { if magnitude == 0 { 0 } else { logs[magnitude] } }
        }
    }
}

/// Drop the shared F257 log/exp memory from the main stack.
pub fn drop_log_mul_tables() -> Script {
    drop_items(LOG_MUL_TABLE_ITEMS)
}

/// Multiply one centered F257 value by a generation-time constant.
///
/// Input layout: `tables | preserved_items | x`. The tables and preserved
/// items remain, and the centered product replaces `x`.
pub fn mul_by_constant_from_log_tables(constant: i32, preserved_items: u32) -> Script {
    let peak_items = u64::from(LOG_MUL_TABLE_ITEMS) + u64::from(preserved_items) + 4;
    assert!(
        peak_items <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "F257 constant lookup query exceeds Bitcoin Script's stack limit"
    );

    let canonical_constant = constant.rem_euclid(F257_MODULUS) as usize;
    if canonical_constant == 0 {
        return script! { OP_DROP 0 };
    }

    let exponent = f257_logs()[canonical_constant];
    let exponent_table_depth = preserved_items + 129;
    script! {
        OP_DUP 0 OP_EQUAL
        OP_IF
            OP_DROP 0
        OP_ELSE
            OP_DUP 0 OP_LESSTHAN
            OP_DUP OP_TOALTSTACK
            OP_IF
                OP_NEGATE
            OP_ENDIF
            if preserved_items > 0 {
                { preserved_items } OP_ADD
            }
            OP_PICK
            { exponent } OP_ADD
            OP_DUP 256 OP_GREATERTHANOREQUAL
            OP_IF
                256 OP_SUB
            OP_ENDIF
            { exponent_table_depth } OP_ADD OP_PICK
            OP_FROMALTSTACK
            OP_IF
                OP_NEGATE
            OP_ENDIF
        OP_ENDIF
    }
}

/// Multiply two centered F257 values through the shared log/exp memory.
///
/// Input layout: `tables | preserved_items | lhs rhs`. Both operands are
/// consumed and one centered product is returned. The altstack is balanced.
pub fn mul_from_log_tables(preserved_items: u32) -> Script {
    let peak_items = u64::from(LOG_MUL_TABLE_ITEMS) + u64::from(preserved_items) + 5;
    assert!(
        peak_items <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "F257 variable lookup query exceeds Bitcoin Script's stack limit"
    );

    let log_table_depth = preserved_items + 1;
    let exponent_table_depth = preserved_items + 129;
    script! {
        OP_2DUP OP_0NOTEQUAL OP_SWAP OP_0NOTEQUAL OP_BOOLAND
        OP_IF
            OP_DUP 0 OP_LESSTHAN
            OP_DUP OP_TOALTSTACK
            OP_IF
                OP_NEGATE
            OP_ENDIF
            { log_table_depth } OP_ADD OP_PICK
            OP_SWAP
            OP_DUP 0 OP_LESSTHAN
            OP_DUP OP_TOALTSTACK
            OP_IF
                OP_NEGATE
            OP_ENDIF
            { log_table_depth } OP_ADD OP_PICK
            OP_ADD
            OP_DUP 256 OP_GREATERTHANOREQUAL
            OP_IF
                256 OP_SUB
            OP_ENDIF
            { exponent_table_depth } OP_ADD OP_PICK
            OP_FROMALTSTACK OP_FROMALTSTACK OP_NUMNOTEQUAL
            OP_IF
                OP_NEGATE
            OP_ENDIF
        OP_ELSE
            OP_2DROP 0
        OP_ENDIF
    }
}

/// Push `x^2` for centered magnitudes `0..=128`.
pub fn push_square_table() -> Script {
    script! {
        for magnitude in (0i32..=128).rev() {
            { magnitude * magnitude }
        }
    }
}

/// Consume a centered F257 value and return its exact integer square.
///
/// Unlike field multiplication, the output lies in `0..=16,384` and is not
/// reduced modulo 257. The layout is `table | preserved_items | x`.
pub fn square_from_table(preserved_items: u32) -> Script {
    let peak_items = u64::from(SQUARE_TABLE_ITEMS) + u64::from(preserved_items) + 3;
    assert!(
        peak_items <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "F257 square lookup query exceeds Bitcoin Script's stack limit"
    );

    script! {
        OP_DUP 0 OP_LESSTHAN
        OP_IF
            OP_NEGATE
        OP_ENDIF
        if preserved_items > 0 {
            { preserved_items } OP_ADD
        }
        OP_PICK
    }
}

/// Drop the exact centered-square table from the main stack.
pub fn drop_square_table() -> Script {
    drop_items(SQUARE_TABLE_ITEMS)
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;
    use crate::execute_script;

    fn center(value: i32) -> i32 {
        f257_center(value)
    }

    #[test]
    fn centered_conversion_round_trips() {
        for canonical in 0..=256 {
            let expected = center(canonical);
            let result = execute_script(script! {
                { canonical }
                { to_centered() }
                { expected } OP_EQUALVERIFY
                { expected }
                { to_canonical() }
                { canonical } OP_EQUAL
            });
            assert!(
                result.success,
                "conversion failed for {canonical}: {result}"
            );
        }
    }

    #[test]
    fn log_table_constant_multiplication_is_correct() {
        for constant in [-128, -42, -1, 0, 1, 2, 42, 128] {
            for value in -128..=128 {
                let expected = center(value * constant);
                let result = execute_script(script! {
                    { push_log_mul_tables() }
                    { value }
                    { mul_by_constant_from_log_tables(constant, 0) }
                    { expected } OP_EQUALVERIFY
                    { drop_log_mul_tables() }
                    OP_TRUE
                });
                assert!(
                    result.success,
                    "log constant multiplication failed for {value}*{constant}: {result}"
                );
            }
        }
    }

    fn check_variable_mul(lhs: i32, rhs: i32) {
        let expected = center(lhs * rhs);
        let result = execute_script(script! {
            { push_log_mul_tables() }
            { lhs } { rhs }
            { mul_from_log_tables(0) }
            { expected } OP_EQUALVERIFY
            { drop_log_mul_tables() }
            OP_TRUE
        });
        assert!(
            result.success,
            "log multiplication failed for {lhs}*{rhs}: {result}"
        );
    }

    #[test]
    fn log_table_variable_multiplication_is_correct() {
        for lhs in [-128, -127, -2, -1, 0, 1, 2, 127, 128] {
            for rhs in [-128, -127, -2, -1, 0, 1, 2, 127, 128] {
                check_variable_mul(lhs, rhs);
            }
        }

        let mut rng = StdRng::seed_from_u64(0x0046_3235_374c_4f47);
        for _ in 0..1_000 {
            check_variable_mul(rng.gen_range(-128..=128), rng.gen_range(-128..=128));
        }
    }

    #[test]
    fn exact_square_lookup_is_correct() {
        for value in -128..=128 {
            let result = execute_script(script! {
                { push_square_table() }
                { value }
                { square_from_table(0) }
                { value * value } OP_EQUALVERIFY
                { drop_square_table() }
                OP_TRUE
            });
            assert!(result.success, "square lookup failed for {value}: {result}");
        }
    }

    #[test]
    fn lookup_tables_fit_beside_a_512_coefficient_state() {
        assert_eq!(
            push_log_mul_tables().compile().instructions().count(),
            LOG_MUL_TABLE_ITEMS as usize
        );
        assert_eq!(
            push_square_table().compile().instructions().count(),
            SQUARE_TABLE_ITEMS as usize
        );

        let multiplication = execute_script(script! {
            { push_log_mul_tables() }
            for _ in 0..510 {
                128
            }
            127 -128
            { mul_from_log_tables(510) }
            { center(127 * -128) } OP_EQUALVERIFY
            for _ in 0..510 {
                OP_DROP
            }
            { drop_log_mul_tables() }
            OP_TRUE
        });
        assert!(
            multiplication.success,
            "stacked log multiplication failed: {multiplication}"
        );
        assert_eq!(multiplication.stats.max_nb_stack_items, 900);

        let square = execute_script(script! {
            { push_square_table() }
            for _ in 0..511 {
                128
            }
            -128
            { square_from_table(511) }
            16384 OP_EQUALVERIFY
            for _ in 0..511 {
                OP_DROP
            }
            { drop_square_table() }
            OP_TRUE
        });
        assert!(square.success, "stacked square failed: {square}");
        assert_eq!(square.stats.max_nb_stack_items, 643);
    }

    #[test]
    #[should_panic(expected = "F257 constant lookup query exceeds Bitcoin Script's stack limit")]
    fn constant_lookup_rejects_wrapping_depth() {
        let _ = mul_by_constant_from_log_tables(1, u32::MAX);
    }

    #[test]
    #[should_panic(expected = "F257 variable lookup query exceeds Bitcoin Script's stack limit")]
    fn variable_lookup_rejects_wrapping_depth() {
        let _ = mul_from_log_tables(u32::MAX);
    }

    #[test]
    #[should_panic(expected = "F257 square lookup query exceeds Bitcoin Script's stack limit")]
    fn square_lookup_rejects_wrapping_depth() {
        let _ = square_from_table(u32::MAX);
    }
}
