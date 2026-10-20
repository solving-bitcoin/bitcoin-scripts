//! Table-free Luhn (mod-10) checksum over numeric decimal digits.
//!
//! Counted from the rightmost digit (position 0), every odd position is
//! doubled, with `9` subtracted from a doubled value above 9. The sum modulo
//! ten is zero exactly for a valid code. Reduction is delayed: the exact sum is
//! reduced once by a ladder of conditional subtractions.

use crate::support::script::*;

/// Largest digit count: the combined peak is `n + 3`.
pub const LUHN_MAX_DIGITS: u32 = 997;

fn check_digit() -> Script {
    script! { OP_DUP 0 10 OP_WITHIN OP_VERIFY }
}

fn double_digit() -> Script {
    script! {
        OP_DUP OP_ADD
        OP_DUP 9 OP_GREATERTHAN
        OP_IF 9 OP_SUB OP_ENDIF
    }
}

/// Consume `digit_count` numeric decimal digits, leftmost first, and return the
/// Luhn sum modulo ten in `0..=9` (zero for a valid code).
///
/// Before: `preserved | d[0] ... d[n-1]`, last digit on top. After:
/// `preserved | r`. Every digit is range-checked as a numeric ScriptNum in
/// `0..=9`; numeric aliases are accepted when the execution profile permits
/// them. No hints or tables. Error detection only: the caller binds length,
/// meaning and the terminal predicate.
pub fn u4_decimal_digits_to_luhn(digit_count: u32) -> Script {
    assert!(
        (1..=LUHN_MAX_DIGITS).contains(&digit_count),
        "Luhn batch supports 1..=997 digits"
    );
    let max_sum = 9 * i64::from(digit_count);
    // Ladder levels k with 10 * 2^k <= max_sum, so that sum < 10 * 2^(top+1).
    let levels = if max_sum >= 10 {
        63 - ((max_sum / 10) as u64).leading_zeros() + 1
    } else {
        0
    };
    script! {
        { check_digit() }
        for position in 1..digit_count {
            OP_SWAP
            { check_digit() }
            if position % 2 == 1 { { double_digit() } }
            OP_ADD
        }
        for level in (0..levels).rev() {
            OP_DUP { 10i64 << level } OP_GREATERTHANOREQUAL
            OP_IF { 10i64 << level } OP_SUB OP_ENDIF
        }
        // A single digit is already below ten, so the ladder has no levels there.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};
    use bitcoin_scriptexec::ExecError;

    // Copy of the Damm primitive's fixed table (CheckDigits.Net 734afa2d3596862ef4c3bb3ec404b512b96b8965),
    // duplicated here so the Damm source file, which is hash-bound by its own tests, stays untouched.
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

    fn luhn_model(digits: &[u8]) -> u8 {
        let mut total = 0u32;
        for (position, &digit) in digits.iter().rev().enumerate() {
            let mut value = u32::from(digit);
            if position % 2 == 1 {
                value *= 2;
                if value > 9 {
                    value -= 9;
                }
            }
            total += value;
        }
        (total % 10) as u8
    }

    fn damm_model(digits: &[u8]) -> u8 {
        digits
            .iter()
            .fold(0u8, |state, &d| Q[state as usize][d as usize])
    }

    fn item(value: u8) -> Vec<u8> {
        if value == 0 {
            Vec::new()
        } else {
            vec![value]
        }
    }

    fn compile(len: usize) -> Vec<u8> {
        // The expected residue is the lowest witness item.
        script! { { u4_decimal_digits_to_luhn(len as u32) } OP_EQUAL }
            .compile_with_policy()
            .to_bytes()
    }

    fn run(compiled: &[u8], digits: &[u8]) -> bool {
        let mut witness = vec![item(luhn_model(digits))];
        witness.extend(digits.iter().map(|&d| item(d)));
        let result = execute_raw_script_with_inputs_strict(compiled.to_vec(), witness);
        assert!(result.error.is_none(), "digits {digits:?}: {result}");
        result.success
    }

    #[test]
    fn exhaustive_for_up_to_four_digits() {
        for len in 1..=4usize {
            let compiled = compile(len);
            for code in 0..10u32.pow(len as u32) {
                let digits: Vec<u8> = (0..len)
                    .map(|i| ((code / 10u32.pow((len - 1 - i) as u32)) % 10) as u8)
                    .collect();
                assert!(run(&compiled, &digits), "digits {digits:?}");
            }
        }
    }

    #[test]
    fn deterministic_longer_codes_and_known_vectors() {
        // 79927398713 is the widely used Luhn example; it is valid (residue 0).
        let example = [7u8, 9, 9, 2, 7, 3, 9, 8, 7, 1, 3];
        assert_eq!(luhn_model(&example), 0);
        assert!(run(&compile(example.len()), &example));
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for len in [5usize, 8, 16, 19, 32, 33, 64, 128] {
            let compiled = compile(len);
            assert!(run(&compiled, &vec![9; len]), "nines {len}");
            assert!(run(&compiled, &vec![0; len]), "zeros {len}");
            for _ in 0..10 {
                let digits: Vec<u8> = (0..len)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        (state % 10) as u8
                    })
                    .collect();
                assert!(run(&compiled, &digits), "digits {digits:?}");
            }
        }
    }

    #[test]
    fn recorded_sizes_are_current() {
        use crate::arithmetic::u4::damm::u4_decimal_digits_to_damm;
        // (digits, Luhn bytes, Damm bytes)
        for (digits, luhn, damm) in [
            (1u32, 5usize, 172usize),
            (2, 28, 191),
            (4, 60, 229),
            (8, 115, 305),
            (16, 216, 457),
            (32, 411, 766),
            (64, 790, 1_406),
            (128, 1_537, 2_686),
        ] {
            let measure = |script: Script| script.compile_with_policy().len();
            assert_eq!(
                measure(u4_decimal_digits_to_luhn(digits)),
                luhn,
                "luhn {digits}"
            );
            assert_eq!(
                measure(u4_decimal_digits_to_damm(digits)),
                damm,
                "damm {digits}"
            );
        }
    }

    #[test]
    fn rejects_non_decimal_digits_at_every_position() {
        for bad in [-1i64, 10, 15, 16, 255] {
            for position in 0..4 {
                let result = execute_script(script! {
                    for index in 0..4 { { if index == position { bad } else { 3 } } }
                    { u4_decimal_digits_to_luhn(4) }
                    OP_DROP OP_TRUE
                });
                assert_eq!(
                    result.error,
                    Some(ExecError::Verify),
                    "bad {bad} at {position}"
                );
            }
        }
    }

    #[test]
    fn preserves_surrounding_state_and_checks_generation_bounds() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            4 5 6 7
            { u4_decimal_digits_to_luhn(4) }
            { luhn_model(&[4, 5, 6, 7]) } OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "{result}");
        assert!(std::panic::catch_unwind(|| u4_decimal_digits_to_luhn(0)).is_err());
        assert!(
            std::panic::catch_unwind(|| u4_decimal_digits_to_luhn(LUHN_MAX_DIGITS + 1)).is_err()
        );
    }

    #[test]
    fn stack_frontier_is_exact() {
        use crate::support::script::MAX_OPTIMIZER_INPUT_BYTES;
        let run_at = |extra: usize| {
            let compiled = script! {
                { u4_decimal_digits_to_luhn(LUHN_MAX_DIGITS) }
                OP_DROP
                for _ in 0..extra { OP_DROP }
                OP_TRUE
                for _ in 0..=MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
            }
            .compile_with_policy()
            .to_bytes();
            let mut witness = vec![vec![9u8]; extra];
            witness.extend(vec![vec![7u8]; LUHN_MAX_DIGITS as usize]);
            execute_raw_script_with_inputs_strict(compiled, witness)
        };
        let base = run_at(0);
        assert!(base.success, "{base}");
        let spare = 1_000 - base.stats.max_nb_stack_items;
        assert!(run_at(spare).success);
        assert_eq!(run_at(spare + 1).error, Some(ExecError::StackSize));
    }

    /// Error-detection comparison with the Damm quasigroup, from Rust models only.
    ///
    /// Codewords are three message digits plus the check digit that makes the
    /// scheme's residue zero. Counts every undetected single-digit substitution
    /// and adjacent transposition over all 1,000 messages.
    #[test]
    fn luhn_misses_the_zero_nine_transposition_that_damm_detects() {
        let mut luhn_counts = (0u32, 0u32);
        let mut damm_counts = (0u32, 0u32);
        for message in 0..1000u32 {
            let m = [
                (message / 100) as u8,
                (message / 10 % 10) as u8,
                (message % 10) as u8,
            ];
            let luhn_check = (0..10u8)
                .find(|&c| luhn_model(&[m[0], m[1], m[2], c]) == 0)
                .unwrap();
            let damm_check = (0..10u8)
                .find(|&c| damm_model(&[m[0], m[1], m[2], c]) == 0)
                .unwrap();
            for (scheme, check, counts) in [
                (0, luhn_check, &mut luhn_counts),
                (1, damm_check, &mut damm_counts),
            ] {
                let word = [m[0], m[1], m[2], check];
                let valid = |w: &[u8]| {
                    if scheme == 0 {
                        luhn_model(w) == 0
                    } else {
                        damm_model(w) == 0
                    }
                };
                assert!(valid(&word));
                for position in 0..4 {
                    for replacement in 0..10u8 {
                        if replacement != word[position] {
                            let mut forged = word;
                            forged[position] = replacement;
                            if valid(&forged) {
                                counts.0 += 1;
                            }
                        }
                    }
                }
                for position in 0..3 {
                    if word[position] != word[position + 1] {
                        let mut forged = word;
                        forged.swap(position, position + 1);
                        if valid(&forged) {
                            counts.1 += 1;
                            // The only blind pair of the Luhn doubling map is {0, 9}.
                            let pair = (
                                word[position].min(word[position + 1]),
                                word[position].max(word[position + 1]),
                            );
                            assert_eq!(pair, (0, 9), "scheme {scheme} word {word:?}");
                        }
                    }
                }
            }
        }
        // Neither scheme misses a single-digit error; only Luhn misses transpositions.
        assert_eq!(luhn_counts.0, 0);
        assert_eq!(damm_counts, (0, 0));
        assert!(
            luhn_counts.1 > 0,
            "Luhn transposition misses: {}",
            luhn_counts.1
        );
        println!("luhn transposition misses: {}", luhn_counts.1);
    }
}
