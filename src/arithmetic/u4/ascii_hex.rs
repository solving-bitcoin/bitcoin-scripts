//! Checked ASCII hexadecimal text to u4 nibbles.
//!
//! Each hostile input item is one ScriptNum that must be the ASCII code of a
//! hexadecimal digit of the selected case. Two schedulers share one contract:
//! a table-free arithmetic fold and a resident 55-entry lookup table.

use super::stack::u4_drop;
use crate::support::script::*;

/// Accepted digit case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HexCase {
    /// `0-9a-f`.
    Lower,
    /// `0-9A-F`.
    Upper,
    /// `0-9a-fA-F`.
    Either,
}

/// Items of the resident table used by [`ascii_hex_to_nibbles_table`].
pub const ASCII_HEX_TABLE_ITEMS: u32 = 55;

/// Largest table-scheduled batch: `n + 55 + 3 <= 1000`.
pub const ASCII_HEX_TABLE_MAX_LEN: u32 = 1_000 - ASCII_HEX_TABLE_ITEMS - 3;

/// Largest fold-scheduled batch: `n + 3 <= 1000`.
pub const ASCII_HEX_FOLD_MAX_LEN: u32 = 1_000 - 3;

/// Value of ASCII code `code` under `case`, or `None` when it is not accepted.
pub fn ascii_hex_value(code: i64, case: HexCase) -> Option<u8> {
    let lower = matches!(case, HexCase::Lower | HexCase::Either);
    let upper = matches!(case, HexCase::Upper | HexCase::Either);
    match code {
        48..=57 => Some((code - 48) as u8),
        97..=102 if lower => Some((code - 87) as u8),
        65..=70 if upper => Some((code - 55) as u8),
        _ => None,
    }
}

/// Table-free decoder.
///
/// Before: `preserved | c[0] ... c[n-1]`, last item on top. After:
/// `preserved | v[0] ... v[n-1]` with each `v[i]` in `0..=15`. Any input that
/// is not an accepted ASCII hex digit aborts the script. No hints.
pub fn ascii_hex_to_nibbles_fold(len: u32, case: HexCase) -> Script {
    assert!(
        (1..=ASCII_HEX_FOLD_MAX_LEN).contains(&len),
        "length out of range"
    );
    script! {
        for _ in 0..len {
            48 OP_SUB
            { decode_offset(case) }
            OP_TOALTSTACK
        }
        for _ in 0..len { OP_FROMALTSTACK }
    }
}

/// Decode `x = code - 48` (an arbitrary ScriptNum) to a nibble or abort.
fn decode_offset(case: HexCase) -> Script {
    // x in 0..=9 is a digit; x in 49..=54 is a-f; x in 17..=22 is A-F.
    match case {
        HexCase::Lower => script! {
            OP_DUP 48 OP_GREATERTHAN
            OP_IF 39 OP_SUB OP_DUP 10 16 OP_WITHIN OP_VERIFY
            OP_ELSE OP_DUP 0 10 OP_WITHIN OP_VERIFY
            OP_ENDIF
        },
        HexCase::Upper => script! {
            OP_DUP 9 OP_GREATERTHAN
            OP_IF 7 OP_SUB OP_DUP 10 16 OP_WITHIN OP_VERIFY
            OP_ELSE OP_DUP 0 10 OP_WITHIN OP_VERIFY
            OP_ENDIF
        },
        HexCase::Either => script! {
            OP_DUP 48 OP_GREATERTHAN
            OP_IF 39 OP_SUB OP_DUP 10 16 OP_WITHIN OP_VERIFY
            OP_ELSE
                OP_DUP 9 OP_GREATERTHAN
                OP_IF 7 OP_SUB OP_DUP 10 16 OP_WITHIN OP_VERIFY
                OP_ELSE OP_DUP 0 10 OP_WITHIN OP_VERIFY
                OP_ENDIF
            OP_ENDIF
        },
    }
}

/// Lookup-table decoder with the same contract as [`ascii_hex_to_nibbles_fold`].
pub fn ascii_hex_to_nibbles_table(len: u32, case: HexCase) -> Script {
    assert!(
        (1..=ASCII_HEX_TABLE_MAX_LEN).contains(&len),
        "length out of range"
    );
    script! {
        for offset in (0..ASCII_HEX_TABLE_ITEMS as i64).rev() {
            { ascii_hex_value(offset + 48, case).map_or(-1, i64::from) }
        }
        for _ in 0..len {
            { ASCII_HEX_TABLE_ITEMS } OP_ROLL
            48 OP_SUB
            OP_DUP 0 { ASCII_HEX_TABLE_ITEMS } OP_WITHIN OP_VERIFY
            OP_PICK
            OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_TOALTSTACK
        }
        { u4_drop(ASCII_HEX_TABLE_ITEMS) }
        for _ in 0..len { OP_FROMALTSTACK }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{
        execute_raw_script_with_inputs_strict, execute_script, execute_script_buf_with_options,
    };
    use bitcoin_scriptexec::{ExecError, Options};

    const CASES: [HexCase; 3] = [HexCase::Lower, HexCase::Upper, HexCase::Either];

    fn schedulers() -> [(&'static str, fn(u32, HexCase) -> Script); 2] {
        [
            ("fold", ascii_hex_to_nibbles_fold),
            ("table", ascii_hex_to_nibbles_table),
        ]
    }

    fn accepted_value(make: fn(u32, HexCase) -> Script, case: HexCase, code: i64, want: i64) {
        let result = execute_script(script! {
            { code }
            { make(1, case) }
            { want } OP_EQUAL
        });
        assert!(result.success, "code {code} want {want}: {result}");
    }

    #[test]
    fn every_nearby_code_matches_the_model_for_both_schedulers() {
        for (name, make) in schedulers() {
            for case in CASES {
                for code in -3i64..=300 {
                    match ascii_hex_value(code, case) {
                        Some(want) => accepted_value(make, case, code, i64::from(want)),
                        None => {
                            let result = execute_script(script! {
                                { code }
                                { make(1, case) }
                                OP_DROP OP_TRUE
                            });
                            assert_eq!(
                                result.error,
                                Some(ExecError::Verify),
                                "{name} {case:?} accepted code {code}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn rejects_extreme_scriptnum_values() {
        for (name, make) in schedulers() {
            for code in [
                i64::from(i32::MAX),
                i64::from(-i32::MAX),
                1 << 20,
                -(1 << 20),
            ] {
                let result = execute_script(script! {
                    { code }
                    { make(1, HexCase::Either) }
                    OP_DROP OP_TRUE
                });
                // Subtracting 48 from -(2^31-1) leaves the four-byte operand domain.
                assert!(
                    matches!(
                        result.error,
                        Some(ExecError::Verify | ExecError::ScriptIntNumericOverflow)
                    ),
                    "{name} {code}: {result}"
                );
            }
        }
    }

    #[test]
    fn decodes_a_batch_in_order_and_preserves_surrounding_state() {
        let text = b"0123456789abcdefABCDEF";
        for (name, make) in schedulers() {
            let result = execute_script(script! {
                77 OP_TOALTSTACK
                99
                for byte in text { { i64::from(*byte) } }
                { make(text.len() as u32, HexCase::Either) }
                for byte in text.iter().rev() {
                    { i64::from(ascii_hex_value(i64::from(*byte), HexCase::Either).unwrap()) }
                    OP_EQUALVERIFY
                }
                99 OP_EQUALVERIFY
                OP_FROMALTSTACK 77 OP_EQUALVERIFY
                OP_TRUE
            });
            assert!(result.success, "{name}: {result}");
        }
    }

    #[test]
    fn one_bad_character_anywhere_in_a_batch_aborts() {
        for (name, make) in schedulers() {
            for position in 0..6 {
                let result = execute_script(script! {
                    for index in 0..6 { { if index == position { i64::from(b'g') } else { i64::from(b'a') } } }
                    { make(6, HexCase::Lower) }
                    for _ in 0..6 { OP_DROP }
                    OP_TRUE
                });
                assert_eq!(
                    result.error,
                    Some(ExecError::Verify),
                    "{name} position {position}"
                );
            }
        }
    }

    #[test]
    fn accepts_nonminimal_numeric_encodings_under_a_permissive_profile() {
        let options = Options {
            require_minimal: false,
            enforce_stack_limit: true,
            ..Default::default()
        };
        for (name, make) in schedulers() {
            let compiled = script! {
                { make(2, HexCase::Lower) }
                6 OP_EQUALVERIFY 10 OP_EQUALVERIFY OP_TRUE
            }
            .compile_with_policy();
            // 'a' = 97 padded with a zero byte; '6' = 54 as a plain byte.
            let result = execute_script_buf_with_options(
                compiled,
                vec![vec![97, 0], vec![54]],
                options.clone(),
            )
            .expect("execution");
            assert!(result.success, "{name}: {result}");
        }
    }

    #[test]
    fn recorded_sizes_are_current() {
        // (case, len, fold bytes, table bytes)
        for (case, len, fold, table) in [
            (HexCase::Lower, 1, 21, 102),
            (HexCase::Lower, 16, 366, 387),
            (HexCase::Lower, 32, 734, 691),
            (HexCase::Lower, 64, 1_470, 1_299),
            (HexCase::Upper, 32, 670, 691),
            (HexCase::Upper, 64, 1_342, 1_299),
            (HexCase::Either, 8, 270, 235),
            (HexCase::Either, 64, 2_174, 1_299),
        ] {
            let measured = |make: fn(u32, HexCase) -> Script| {
                script! { { make(len, case) } }.compile_with_policy().len()
            };
            assert_eq!(
                measured(ascii_hex_to_nibbles_fold),
                fold,
                "{case:?} fold {len}"
            );
            assert_eq!(
                measured(ascii_hex_to_nibbles_table),
                table,
                "{case:?} table {len}"
            );
        }
    }

    #[test]
    fn rejects_generation_bounds() {
        for case in CASES {
            assert!(std::panic::catch_unwind(|| ascii_hex_to_nibbles_fold(0, case)).is_err());
            assert!(std::panic::catch_unwind(|| ascii_hex_to_nibbles_table(0, case)).is_err());
            assert!(std::panic::catch_unwind(|| {
                ascii_hex_to_nibbles_fold(ASCII_HEX_FOLD_MAX_LEN + 1, case)
            })
            .is_err());
            assert!(std::panic::catch_unwind(|| {
                ascii_hex_to_nibbles_table(ASCII_HEX_TABLE_MAX_LEN + 1, case)
            })
            .is_err());
        }
    }

    #[test]
    fn stack_frontier_is_exact_for_both_schedulers() {
        use crate::support::script::MAX_OPTIMIZER_INPUT_BYTES;
        for (name, make, max) in [
            (
                "fold",
                ascii_hex_to_nibbles_fold as fn(u32, HexCase) -> Script,
                ASCII_HEX_FOLD_MAX_LEN,
            ),
            ("table", ascii_hex_to_nibbles_table, ASCII_HEX_TABLE_MAX_LEN),
        ] {
            // Oversize padding keeps the policy on its unoptimized path for speed.
            let run = |len: u32, extra: usize| {
                let compiled = script! {
                    { make(len, HexCase::Lower) }
                    for _ in 0..len { 10 OP_EQUALVERIFY }
                    for _ in 0..extra { OP_DROP }
                    OP_TRUE
                    for _ in 0..=MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
                }
                .compile_with_policy()
                .to_bytes();
                let mut witness = vec![vec![9u8]; extra];
                witness.extend(vec![vec![b'a']; len as usize]);
                execute_raw_script_with_inputs_strict(compiled, witness)
            };
            let accepted = run(max, 0);
            assert!(accepted.success, "{name} len {max}: {accepted}");
            assert_eq!(accepted.stats.max_nb_stack_items, 1_000, "{name}");
            // One more input is one more live item and must overflow the combined stack.
            let rejected = run(max, 1);
            assert_eq!(
                rejected.error,
                Some(ExecError::StackSize),
                "{name}: {rejected}"
            );
        }
    }
}
