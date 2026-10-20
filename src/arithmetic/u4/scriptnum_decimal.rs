//! Decimal expansion of one non-negative ScriptNum into numeric digits.
//!
//! The decimal sibling of the radix-16 expansion: a hint-free compare-and-
//! subtract ladder and a hint-checked Horner verification, both producing
//! most-significant-first numeric digits `0..=9` that feed decimal checksums.

use crate::{arithmetic::scriptint::mul_by_constant, support::script::*};

/// Widest expansion: ten digits, with the top digit limited to `0..=2`.
pub const SCRIPTNUM_DECIMAL_MAX_WIDTH: u32 = 10;

/// Exclusive upper bound of the accepted input domain for `width` digits.
pub fn scriptnum_decimal_domain(width: u32) -> i64 {
    assert!(
        (1..=SCRIPTNUM_DECIMAL_MAX_WIDTH).contains(&width),
        "width out of range"
    );
    10i64.pow(width).min(1 << 31)
}

/// Hint-free expansion.
///
/// Before: `preserved | x`. After: `preserved | d[0] ... d[width-1]`, `d[0]`
/// the most significant digit, least significant on top. `x` must lie in
/// `0..domain(width)`; anything else aborts.
pub fn u4_scriptnum_to_decimal(width: u32) -> Script {
    let domain = scriptnum_decimal_domain(width);
    script! {
        if domain > i64::from(i32::MAX) {
            OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
        } else {
            OP_DUP 0 { domain } OP_WITHIN OP_VERIFY
        }
        for place in (0..width).rev() {
            0 OP_SWAP
            for bit in (0..4u32).rev() {
                // Skip weights whose place value cannot occur below the domain.
                if (10i64.pow(place) << bit) < domain {
                    OP_DUP { 10i64.pow(place) << bit } OP_GREATERTHANOREQUAL
                    OP_IF
                        { 10i64.pow(place) << bit } OP_SUB
                        OP_SWAP { 1 << bit } OP_ADD OP_SWAP
                    OP_ENDIF
                }
            }
        }
        OP_DROP
    }
}

/// Hint-checked expansion.
///
/// Before: `preserved | d[0] ... d[width-1] | x` (digit hints under the number,
/// `d[0]` most significant). After: `preserved | d[0] ... d[width-1]`. Every
/// hint is range-checked to `0..=9` and the Horner sum must equal `x`.
pub fn u4_scriptnum_to_decimal_hinted(width: u32) -> Script {
    scriptnum_decimal_domain(width);
    script! {
        OP_TOALTSTACK
        for index in 0..width {
            { width - 1 - index } OP_PICK
            0 10 OP_WITHIN OP_VERIFY
        }
        { width - 1 } OP_PICK
        for index in (0..width - 1).rev() {
            { mul_by_constant(10) }
            { index + 1 } OP_PICK
            OP_ADD
        }
        OP_FROMALTSTACK OP_EQUALVERIFY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::u4::damm::u4_decimal_digits_to_damm;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};
    use bitcoin_scriptexec::ExecError;

    fn num(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let len = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..len].to_vec()
    }

    fn digits(value: i64, width: u32) -> Vec<i64> {
        (0..width)
            .rev()
            .map(|place| (value / 10i64.pow(place)) % 10)
            .collect()
    }

    /// Leaf comparing every output digit with the lowest witness items.
    fn zero_hint_leaf(width: u32) -> Vec<u8> {
        script! {
            { u4_scriptnum_to_decimal(width) }
            for index in (0..width).rev() {
                { index + 1 } OP_ROLL OP_EQUALVERIFY
            }
            OP_TRUE
        }
        .compile_with_policy()
        .to_bytes()
    }

    fn run_zero_hint(compiled: &[u8], width: u32, x: i64) -> bool {
        let mut witness: Vec<Vec<u8>> = digits(x, width).into_iter().map(num).collect();
        witness.push(num(x));
        let result = execute_raw_script_with_inputs_strict(compiled.to_vec(), witness);
        assert!(result.error.is_none(), "x={x}: {result}");
        result.success
    }

    #[test]
    fn domain_bounds_match_the_width() {
        assert_eq!(scriptnum_decimal_domain(1), 10);
        assert_eq!(scriptnum_decimal_domain(9), 1_000_000_000);
        assert_eq!(scriptnum_decimal_domain(10), 1 << 31);
        assert!(std::panic::catch_unwind(|| scriptnum_decimal_domain(0)).is_err());
        assert!(std::panic::catch_unwind(|| scriptnum_decimal_domain(11)).is_err());
    }

    #[test]
    fn zero_hint_expansion_is_exhaustive_for_small_widths() {
        for width in 1..=3u32 {
            let compiled = zero_hint_leaf(width);
            for x in 0..scriptnum_decimal_domain(width) {
                assert!(run_zero_hint(&compiled, width, x), "width {width} x {x}");
            }
        }
    }

    #[test]
    fn zero_hint_expansion_matches_the_model_on_boundaries_and_samples() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for width in 4..=10u32 {
            let compiled = zero_hint_leaf(width);
            let domain = scriptnum_decimal_domain(width);
            let mut values = vec![
                0,
                1,
                9,
                10,
                99,
                domain - 1,
                domain / 2,
                domain / 10,
                domain / 10 - 1,
            ];
            for _ in 0..40 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                values.push((state % domain as u64) as i64);
            }
            for x in values {
                assert!(run_zero_hint(&compiled, width, x), "width {width} x {x}");
            }
        }
    }

    #[test]
    fn recorded_sizes_are_current() {
        // (width, hint-free bytes, hint-checked bytes)
        for (width, zero, hinted) in [
            (1, 50, 9),
            (2, 102, 24),
            (4, 223, 59),
            (6, 358, 93),
            (8, 505, 127),
            (9, 582, 144),
            (10, 616, 161),
        ] {
            let measure = |script: Script| script.compile_with_policy().len();
            assert_eq!(
                measure(u4_scriptnum_to_decimal(width)),
                zero,
                "zero {width}"
            );
            assert_eq!(
                measure(u4_scriptnum_to_decimal_hinted(width)),
                hinted,
                "hinted {width}"
            );
        }
    }

    #[test]
    fn zero_hint_expansion_rejects_out_of_domain_inputs() {
        for width in 1..=10u32 {
            let domain = scriptnum_decimal_domain(width);
            for bad in [-1, domain, domain + 1, -i64::from(i32::MAX)] {
                if bad < 0 || bad >= domain {
                    let result = execute_script(script! {
                        { bad }
                        { u4_scriptnum_to_decimal(width) }
                        for _ in 0..width { OP_DROP }
                        OP_TRUE
                    });
                    assert!(
                        matches!(
                            result.error,
                            Some(ExecError::Verify | ExecError::ScriptIntNumericOverflow)
                        ),
                        "width {width} bad {bad}: {result}"
                    );
                }
            }
        }
    }

    fn run_hinted(width: u32, hints: &[i64], x: i64) -> Option<bool> {
        let compiled = script! {
            { u4_scriptnum_to_decimal_hinted(width) }
            for index in (0..width).rev() {
                { index + 1 } OP_ROLL OP_EQUALVERIFY
            }
            OP_TRUE
        }
        .compile_with_policy()
        .to_bytes();
        let mut witness: Vec<Vec<u8>> = digits(x, width).into_iter().map(num).collect();
        witness.extend(hints.iter().map(|&h| num(h)));
        witness.push(num(x));
        let result = execute_raw_script_with_inputs_strict(compiled, witness);
        if result.error.is_some() {
            None
        } else {
            Some(result.success)
        }
    }

    #[test]
    fn hinted_expansion_accepts_exact_digits_and_rejects_every_perturbation() {
        for width in 1..=3u32 {
            for x in (0..scriptnum_decimal_domain(width)).step_by(13) {
                let honest = digits(x, width);
                assert_eq!(run_hinted(width, &honest, x), Some(true), "x {x}");
                for position in 0..width as usize {
                    for delta in [-1i64, 1] {
                        let mut forged = honest.clone();
                        forged[position] += delta;
                        assert_ne!(
                            run_hinted(width, &forged, x),
                            Some(true),
                            "x {x} {forged:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn hinted_expansion_rejects_carry_compensated_aliases() {
        // 10 = [1, 0] = [0, 10]; the second has an out-of-range digit.
        assert_eq!(run_hinted(2, &[1, 0], 10), Some(true));
        assert_ne!(run_hinted(2, &[0, 10], 10), Some(true));
        assert_eq!(run_hinted(2, &[9, 9], 99), Some(true));
        assert_ne!(run_hinted(2, &[10, -1], 99), Some(true));
        assert_ne!(run_hinted(10, &[9; 10], i64::from(i32::MAX)), Some(true));
    }

    // Copy of the Damm primitive's fixed table (CheckDigits.Net
    // 734afa2d3596862ef4c3bb3ec404b512b96b8965); the Damm source is hash-bound
    // by its own tests, so it is duplicated here rather than edited.
    const Q: [[u8; 10]; 10] = [
        [0, 3, 1, 7, 5, 9, 8, 6, 4, 2],
        [7, 0, 9, 2, 1, 5, 4, 8, 6, 3],
        [4, 2, 0, 6, 8, 7, 1, 3, 5, 9],
        [1, 7, 5, 0, 9, 8, 3, 4, 2, 6],
        [6, 1, 2, 3, 0, 4, 5, 9, 7, 8],
        [3, 6, 7, 4, 2, 0, 9, 5, 8, 1],
        [5, 8, 6, 9, 7, 2, 0, 1, 3, 4],
        [8, 9, 4, 5, 3, 6, 2, 0, 1, 7],
        [9, 4, 3, 8, 6, 1, 7, 2, 0, 5],
        [2, 5, 8, 1, 4, 3, 6, 7, 9, 0],
    ];

    fn damm_state(value: i64, width: u32) -> i64 {
        digits(value, width)
            .into_iter()
            .fold(0usize, |state, d| usize::from(Q[state][d as usize])) as i64
    }

    #[test]
    fn composes_with_the_damm_checksum_in_complete_leaves() {
        for x in [0i64, 7, 123_456_789, 999_999_999, 500_000_000] {
            let width = 9;
            let expected = damm_state(x, width);
            // Zero-hint: x -> digits -> Damm -> compare.
            let result = execute_script(script! {
                { x }
                { u4_scriptnum_to_decimal(width) }
                { u4_decimal_digits_to_damm(width) }
                { expected } OP_EQUAL
            });
            assert!(result.success, "zero-hint leaf x={x}: {result}");
            // Hinted: digits and x -> digits -> Damm -> compare.
            let result = execute_script(script! {
                for d in digits(x, width) { { d } }
                { x }
                { u4_scriptnum_to_decimal_hinted(width) }
                { u4_decimal_digits_to_damm(width) }
                { expected } OP_EQUAL
            });
            assert!(result.success, "hinted leaf x={x}: {result}");
            // A forged digit hint cannot reach the Damm fold with a wrong amount.
            let mut forged = digits(x, width);
            forged[8] = (forged[8] + 1) % 10;
            let result = execute_script(script! {
                for d in forged { { d } }
                { x }
                { u4_scriptnum_to_decimal_hinted(width) }
                { u4_decimal_digits_to_damm(width) }
                { expected } OP_EQUAL
            });
            assert!(!result.success, "forged hint accepted for x={x}");
        }
    }
}
