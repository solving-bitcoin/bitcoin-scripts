//! Radix-16 expansion of one non-negative ScriptNum into big-endian u4 nibbles.
//!
//! The inverse direction (`u4_nibbles_to_quad` and friends) packs checked
//! nibbles into a number. Expanding needs division, which Script lacks, so two
//! schedulers are compared: a hint-free compare-and-subtract ladder and a
//! hint-checked form that verifies witness nibbles with a Horner sum.

use crate::support::script::*;

/// Widest expansion: eight nibbles, with the top nibble limited to `0..=7`.
pub const SCRIPTNUM_NIBBLES_MAX_WIDTH: u32 = 8;

/// Exclusive upper bound of the accepted input domain for `width` nibbles.
pub fn scriptnum_nibbles_domain(width: u32) -> i64 {
    assert!(
        (1..=SCRIPTNUM_NIBBLES_MAX_WIDTH).contains(&width),
        "width out of range"
    );
    (1i64 << (4 * width)).min(1 << 31)
}

/// Hint-free expansion.
///
/// Before: `preserved | x`. After: `preserved | d[0] ... d[width-1]` with `d[0]`
/// the most significant nibble and the least significant on top. `x` must lie
/// in `0..domain(width)`; anything else aborts. Each nibble is found by
/// comparing against `8, 4, 2, 1` times its place value and subtracting.
pub fn u4_scriptnum_to_nibbles(width: u32) -> Script {
    let domain = scriptnum_nibbles_domain(width);
    script! {
        if domain > i64::from(i32::MAX) {
            // The full four-byte domain: every non-negative operand is accepted.
            OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
        } else {
            OP_DUP 0 { domain } OP_WITHIN OP_VERIFY
        }
        for place in (0..width).rev() {
            0 OP_SWAP
            for bit in (0..4u32).rev() {
                // The top nibble of a 31-bit domain has no weight-8 place value.
                if (1i64 << (4 * place + bit)) < domain {
                    OP_DUP { 1i64 << (4 * place + bit) } OP_GREATERTHANOREQUAL
                    OP_IF
                        { 1i64 << (4 * place + bit) } OP_SUB
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
/// Before: `preserved | d[0] ... d[width-1] | x` (nibble hints under the number,
/// `d[0]` most significant). After: `preserved | d[0] ... d[width-1]`. Every
/// hint is range-checked and the Horner sum must equal `x`, so a wrong or
/// aliased nibble (for example a carry-compensated pair) aborts.
pub fn u4_scriptnum_to_nibbles_hinted(width: u32) -> Script {
    scriptnum_nibbles_domain(width);
    script! {
        OP_TOALTSTACK
        for index in 0..width {
            { width - 1 - index } OP_PICK
            0 16 OP_WITHIN OP_VERIFY
        }
        // Horner: ((d0 * 16 + d1) * 16 + d2) ...
        { width - 1 } OP_PICK
        for index in (0..width - 1).rev() {
            for _ in 0..4 { OP_DUP OP_ADD }
            { index + 1 } OP_PICK
            OP_ADD
        }
        OP_FROMALTSTACK OP_EQUALVERIFY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};
    use bitcoin_scriptexec::ExecError;

    fn num(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let len = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..len].to_vec()
    }

    fn digits(value: i64, width: u32) -> Vec<i64> {
        (0..width).rev().map(|p| (value >> (4 * p)) & 15).collect()
    }

    /// Compile a leaf that expands `x` and compares every nibble with the model.
    fn compile_zero_hint(width: u32) -> Vec<u8> {
        script! {
            { u4_scriptnum_to_nibbles(width) }
            for index in (0..width).rev() {
                // Expected digits are the lowest witness items, deepest first.
                { index + 1 } OP_ROLL OP_EQUALVERIFY
            }
            OP_TRUE
        }
        .compile_with_policy()
        .to_bytes()
    }

    fn run_zero_hint(compiled: &[u8], width: u32, x: i64) -> bool {
        // Witness: expected digits (most significant first), then x on top.
        let mut witness: Vec<Vec<u8>> = digits(x, width).into_iter().map(num).collect();
        witness.push(num(x));
        let result = execute_raw_script_with_inputs_strict(compiled.to_vec(), witness);
        assert!(result.error.is_none(), "x={x}: {result}");
        result.success
    }

    #[test]
    fn domain_bounds_match_the_width() {
        assert_eq!(scriptnum_nibbles_domain(1), 16);
        assert_eq!(scriptnum_nibbles_domain(4), 65_536);
        assert_eq!(scriptnum_nibbles_domain(7), 1 << 28);
        assert_eq!(scriptnum_nibbles_domain(8), 1 << 31);
        assert!(std::panic::catch_unwind(|| scriptnum_nibbles_domain(0)).is_err());
        assert!(std::panic::catch_unwind(|| scriptnum_nibbles_domain(9)).is_err());
    }

    #[test]
    fn zero_hint_expansion_is_exhaustive_for_small_widths() {
        for width in 1..=3u32 {
            let compiled = compile_zero_hint(width);
            for x in 0..scriptnum_nibbles_domain(width) {
                assert!(run_zero_hint(&compiled, width, x), "width {width} x {x}");
            }
        }
    }

    #[test]
    fn zero_hint_expansion_matches_the_model_on_boundaries_and_samples() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for width in 4..=8u32 {
            let compiled = compile_zero_hint(width);
            let domain = scriptnum_nibbles_domain(width);
            let mut values = vec![
                0,
                1,
                15,
                16,
                domain - 1,
                domain / 2,
                domain / 2 - 1,
                domain / 16,
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
    fn zero_hint_expansion_rejects_values_outside_the_domain() {
        for width in 1..=8u32 {
            let domain = scriptnum_nibbles_domain(width);
            for bad in [
                -1,
                domain,
                domain + 1,
                i64::from(i32::MAX),
                -i64::from(i32::MAX),
            ] {
                if bad >= domain || bad < 0 {
                    let result = execute_script(script! {
                        { bad }
                        { u4_scriptnum_to_nibbles(width) }
                        for _ in 0..width { OP_DROP }
                        OP_TRUE
                    });
                    // Values beyond the four-byte operand domain overflow instead.
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

    #[test]
    fn zero_hint_expansion_preserves_surrounding_state_and_rejects_overlong_numbers() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            4660
            { u4_scriptnum_to_nibbles(4) }
            4 OP_EQUALVERIFY
            3 OP_EQUALVERIFY
            2 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "{result}");
        // A five-byte ScriptNum is outside the four-byte operand domain.
        let result = execute_raw_script_with_inputs_strict(
            script! { { u4_scriptnum_to_nibbles(4) } for _ in 0..4 { OP_DROP } OP_TRUE }
                .compile_with_policy()
                .to_bytes(),
            vec![vec![0, 0, 0, 0, 1]],
        );
        assert!(result.error.is_some() && !result.success, "{result}");
    }

    #[test]
    fn recorded_sizes_are_current() {
        // (width, zero-hint bytes, hinted bytes)
        for (width, zero, hinted) in [
            (1, 50, 9),
            (2, 105, 24),
            (3, 166, 42),
            (4, 230, 59),
            (5, 299, 76),
            (6, 371, 93),
            (7, 448, 110),
            (8, 501, 127),
        ] {
            let measure = |script: Script| script.compile_with_policy().len();
            assert_eq!(
                measure(u4_scriptnum_to_nibbles(width)),
                zero,
                "zero {width}"
            );
            assert_eq!(
                measure(u4_scriptnum_to_nibbles_hinted(width)),
                hinted,
                "hinted {width}"
            );
        }
    }

    fn run_hinted(width: u32, hints: &[i64], x: i64) -> Option<bool> {
        let compiled = script! {
            { u4_scriptnum_to_nibbles_hinted(width) }
            for index in (0..width).rev() {
                { index + 1 } OP_ROLL OP_EQUALVERIFY
            }
            OP_TRUE
        }
        .compile_with_policy()
        .to_bytes();
        // Witness: expected digits, then the hints, then x.
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
    fn hinted_expansion_accepts_exact_nibbles_and_rejects_every_wrong_hint() {
        for width in 1..=3u32 {
            for x in (0..scriptnum_nibbles_domain(width)).step_by(7) {
                let honest = digits(x, width);
                assert_eq!(run_hinted(width, &honest, x), Some(true), "x {x}");
                // Perturb each hint by +1 and -1: either out of range or sum mismatch.
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
        // 16 = [1, 0] = [0, 16]; the second pair has an out-of-range digit.
        assert_eq!(run_hinted(2, &[1, 0], 16), Some(true));
        assert_ne!(run_hinted(2, &[0, 16], 16), Some(true));
        // 255 = [15, 15]; [16, -1] sums to 255 but both digits are out of range.
        assert_eq!(run_hinted(2, &[15, 15], 255), Some(true));
        assert_ne!(run_hinted(2, &[16, -1], 255), Some(true));
        // A hinted width-8 number above 2^31 - 1 cannot even be formed.
        assert_ne!(run_hinted(8, &[15; 8], i64::from(i32::MAX)), Some(true));
    }
}
