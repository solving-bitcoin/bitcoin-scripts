//! Arithmetic over Bitcoin's four-byte Script integer domain.

use crate::treepp::{script, Script};

/// Largest positive integer accepted by four-byte Script-number arithmetic.
pub const MAX_SCRIPTNUM: u32 = 0x7fff_ffff;

/// Multiply the top Script integer by the compile-time constant `multiplier`.
///
/// Stack before: `... value`.
/// Stack after: `... value_times_multiplier`.
///
/// The implementation uses a binary double-and-add chain. The input, result,
/// and every intermediate value must fit Bitcoin's Script-number domain.
pub fn mul_by_constant(multiplier: u32) -> Script {
    let bit_count = u32::BITS - multiplier.leading_zeros();
    let bits = (0..bit_count)
        .map(|index| 1 & (multiplier >> index))
        .collect::<Vec<_>>();

    script! {
        if bit_count == 0 {
            OP_DROP 0
        } else {
            for index in 0..bits.len() - 1 {
                if bits[index] == 1 {
                    OP_DUP
                }
                OP_DUP OP_ADD
            }
            for _ in 1..bits.iter().sum() {
                OP_ADD
            }
        }
    }
}

fn assert_divisor(divisor: u32) {
    assert!(
        (1..=MAX_SCRIPTNUM).contains(&divisor),
        "divisor must be in 1..=2147483647"
    );
}

/// Verify a quotient hint and return both quotient and Euclidean remainder.
///
/// Stack before (top first): `dividend, quotient_hint`.
/// Stack after (top first): `remainder, quotient`.
///
/// The fragment verifies `dividend = quotient_hint * divisor + remainder`
/// and `0 <= remainder < divisor`. `divisor` is a positive compile-time
/// constant. All arithmetic inputs and intermediate results must fit Bitcoin's
/// four-byte Script-number domain.
pub fn hinted_div_rem(divisor: u32) -> Script {
    assert_divisor(divisor);
    script! {
        OP_OVER
        { mul_by_constant(divisor) }
        OP_SUB

        OP_DUP
        0
        { divisor }
        OP_WITHIN
        OP_VERIFY
    }
}

/// Verify a quotient hint and return the quotient, dropping the remainder.
pub fn hinted_div(divisor: u32) -> Script {
    script! {
        { hinted_div_rem(divisor) }
        OP_DROP
    }
}

/// Verify a quotient hint and return the remainder, dropping the quotient.
pub fn hinted_rem(divisor: u32) -> Script {
    script! {
        { hinted_div_rem(divisor) }
        OP_NIP
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{execute_script, treepp::script};

    fn assert_division(dividend: i64, divisor: u32) {
        let divisor_i64 = i64::from(divisor);
        let quotient = dividend.div_euclid(divisor_i64);
        let remainder = dividend.rem_euclid(divisor_i64);

        let div_rem_result = execute_script(script! {
            { quotient }
            { dividend }
            { hinted_div_rem(divisor) }
            { remainder } OP_EQUALVERIFY
            { quotient } OP_EQUAL
        });
        assert!(
            div_rem_result.success,
            "{dividend} / {divisor}: {div_rem_result}"
        );

        let div_result = execute_script(script! {
            { quotient }
            { dividend }
            { hinted_div(divisor) }
            { quotient } OP_EQUAL
        });
        assert!(div_result.success, "{dividend} / {divisor}: {div_result}");

        let rem_result = execute_script(script! {
            { quotient }
            { dividend }
            { hinted_rem(divisor) }
            { remainder } OP_EQUAL
        });
        assert!(rem_result.success, "{dividend} % {divisor}: {rem_result}");
    }

    #[test]
    fn multiplies_by_constants() {
        for multiplier in [0, 1, 2, 3, 5, 13, 255] {
            for value in [-1_000i64, -1, 0, 1, 1_000] {
                let expected = value * i64::from(multiplier);
                let result = execute_script(script! {
                    { value }
                    { mul_by_constant(multiplier) }
                    { expected }
                    OP_EQUAL
                });
                assert!(result.success, "{value} * {multiplier}: {result}");
            }
        }
    }

    #[test]
    fn verifies_division_and_remainder() {
        for divisor in [1, 2, 3, 8, 255, 65_535] {
            for dividend in [
                -1_000_000i64,
                -123_459,
                -1,
                0,
                1,
                119,
                123_459,
                2_147_483_647,
            ] {
                assert_division(dividend, divisor);
            }
        }
        assert_division(-2_147_483_647, 1);
    }

    #[test]
    fn rejects_wrong_quotient_hint() {
        let result = execute_script(script! {
            58 // incorrect: 119 / 2 is 59 remainder 1
            119
            { hinted_div_rem(2) }
            OP_2DROP OP_1
        });
        assert!(!result.success);
    }

    #[test]
    #[should_panic(expected = "divisor must be in 1..=2147483647")]
    fn rejects_zero_divisor() {
        let _ = hinted_div_rem(0);
    }

    #[test]
    #[should_panic(expected = "divisor must be in 1..=2147483647")]
    fn rejects_divisor_outside_scriptnum_domain() {
        let _ = hinted_div_rem(0x8000_0000);
    }
}
