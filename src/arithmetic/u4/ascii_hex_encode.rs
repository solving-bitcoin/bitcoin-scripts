//! Checked u4 nibbles to ASCII hexadecimal text.
//!
//! The encoding direction of the text bridge: each hostile nibble becomes the
//! ASCII code of its lower- or upper-case hexadecimal digit. A branching
//! arithmetic scheduler and a resident 16-entry table scheduler share one
//! contract.

use super::stack::u4_drop;
use crate::support::script::*;

/// Output letter case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HexLetterCase {
    /// `a-f`.
    Lower,
    /// `A-F`.
    Upper,
}

/// Resident items of the table scheduler.
pub const ASCII_HEX_ENCODE_TABLE_ITEMS: u32 = 16;

/// Largest arithmetic batch: the combined peak is `n + 3`.
pub const ASCII_HEX_ENCODE_ARITH_MAX_LEN: u32 = 997;

/// Largest table batch: the combined peak is `n + 19`.
pub const ASCII_HEX_ENCODE_TABLE_MAX_LEN: u32 = 981;

/// ASCII code of the hexadecimal digit for `nibble`.
pub fn ascii_hex_code(nibble: u8, case: HexLetterCase) -> u8 {
    match (nibble, case) {
        (0..=9, _) => b'0' + nibble,
        (10..=15, HexLetterCase::Lower) => b'a' + nibble - 10,
        (10..=15, HexLetterCase::Upper) => b'A' + nibble - 10,
        _ => panic!("not a nibble"),
    }
}

/// Branching arithmetic encoder.
///
/// Before: `preserved | v[0] ... v[n-1]`, last nibble on top. After:
/// `preserved | c[0] ... c[n-1]` with `c[i]` the ASCII code of `v[i]`. A nibble
/// outside `0..=15` aborts. No hints.
pub fn u4_nibbles_to_ascii_hex_arith(len: u32, case: HexLetterCase) -> Script {
    assert!(
        (1..=ASCII_HEX_ENCODE_ARITH_MAX_LEN).contains(&len),
        "length out of range"
    );
    let letter_offset = i64::from(ascii_hex_code(10, case)) - 10;
    script! {
        for _ in 0..len {
            OP_DUP 0 16 OP_WITHIN OP_VERIFY
            OP_DUP 9 OP_GREATERTHAN
            OP_IF { letter_offset } OP_ELSE 48 OP_ENDIF
            OP_ADD
            OP_TOALTSTACK
        }
        for _ in 0..len { OP_FROMALTSTACK }
    }
}

/// Resident-table encoder with the contract of [`u4_nibbles_to_ascii_hex_arith`].
pub fn u4_nibbles_to_ascii_hex_table(len: u32, case: HexLetterCase) -> Script {
    assert!(
        (1..=ASCII_HEX_ENCODE_TABLE_MAX_LEN).contains(&len),
        "length out of range"
    );
    script! {
        for nibble in (0..16u8).rev() { { i64::from(ascii_hex_code(nibble, case)) } }
        for _ in 0..len {
            { ASCII_HEX_ENCODE_TABLE_ITEMS } OP_ROLL
            OP_DUP 0 16 OP_WITHIN OP_VERIFY
            OP_PICK OP_TOALTSTACK
        }
        { u4_drop(ASCII_HEX_ENCODE_TABLE_ITEMS) }
        for _ in 0..len { OP_FROMALTSTACK }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};
    use bitcoin_scriptexec::{ExecError, Options};

    const CASES: [HexLetterCase; 2] = [HexLetterCase::Lower, HexLetterCase::Upper];

    fn schedulers() -> [(&'static str, fn(u32, HexLetterCase) -> Script); 2] {
        [
            ("arith", u4_nibbles_to_ascii_hex_arith),
            ("table", u4_nibbles_to_ascii_hex_table),
        ]
    }

    fn item(value: u8) -> Vec<u8> {
        if value == 0 {
            Vec::new()
        } else {
            vec![value]
        }
    }

    #[test]
    fn codes_match_the_standard_formatter() {
        for nibble in 0..16u8 {
            assert_eq!(
                char::from(ascii_hex_code(nibble, HexLetterCase::Lower)).to_string(),
                format!("{nibble:x}")
            );
            assert_eq!(
                char::from(ascii_hex_code(nibble, HexLetterCase::Upper)).to_string(),
                format!("{nibble:X}")
            );
        }
    }

    #[test]
    fn every_nibble_encodes_correctly_for_both_schedulers_and_cases() {
        for (name, make) in schedulers() {
            for case in CASES {
                let compiled = script! { { make(1, case) } OP_EQUAL }
                    .compile_with_policy()
                    .to_bytes();
                for nibble in 0..16u8 {
                    for wrong_offset in [0u8, 1] {
                        let expected = ascii_hex_code(nibble, case) + wrong_offset;
                        let result = execute_raw_script_with_inputs_strict(
                            compiled.clone(),
                            vec![vec![expected], item(nibble)],
                        );
                        assert!(result.error.is_none(), "{name} {case:?} {nibble}: {result}");
                        assert_eq!(
                            result.success,
                            wrong_offset == 0,
                            "{name} {case:?} {nibble}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn batches_keep_order_and_preserve_surrounding_state() {
        let nibbles = [0u8, 15, 9, 10, 1, 14, 5, 11];
        for (name, make) in schedulers() {
            for case in CASES {
                let result = execute_script(script! {
                    77 OP_TOALTSTACK
                    99
                    for n in nibbles { { i64::from(n) } }
                    { make(nibbles.len() as u32, case) }
                    for n in nibbles.iter().rev() {
                        { i64::from(ascii_hex_code(*n, case)) } OP_EQUALVERIFY
                    }
                    99 OP_EQUALVERIFY
                    OP_FROMALTSTACK 77 OP_EQUALVERIFY
                    OP_TRUE
                });
                assert!(result.success, "{name} {case:?}: {result}");
            }
        }
    }

    #[test]
    fn recorded_sizes_are_current() {
        // (n, arithmetic bytes, table bytes); both cases are the same size.
        for (n, arith, table) in [
            (1u32, 16usize, 50usize),
            (4, 70, 80),
            (8, 142, 120),
            (16, 286, 200),
            (32, 574, 360),
            (64, 1_150, 680),
        ] {
            for case in CASES {
                let measure = |script: Script| script.compile_with_policy().len();
                assert_eq!(
                    measure(u4_nibbles_to_ascii_hex_arith(n, case)),
                    arith,
                    "arith {n}"
                );
                assert_eq!(
                    measure(u4_nibbles_to_ascii_hex_table(n, case)),
                    table,
                    "table {n}"
                );
            }
        }
    }

    #[test]
    fn rejects_out_of_range_nibbles_at_every_position() {
        for (name, make) in schedulers() {
            for bad in [-1i64, 16, 255] {
                for position in 0..4 {
                    let result = execute_script(script! {
                        for index in 0..4 { { if index == position { bad } else { 3 } } }
                        { make(4, HexLetterCase::Lower) }
                        for _ in 0..4 { OP_DROP }
                        OP_TRUE
                    });
                    assert_eq!(
                        result.error,
                        Some(ExecError::Verify),
                        "{name} {bad} at {position}"
                    );
                }
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
            let (code_f, code_a) = (i64::from(b'f'), i64::from(b'a'));
            let compiled = script! {
                { make(2, HexLetterCase::Lower) }
                { code_f } OP_EQUALVERIFY { code_a } OP_EQUAL
            }
            .compile_with_policy();
            // 10 padded with a zero byte, and 15.
            let result = crate::support::execution::execute_script_buf_with_options(
                compiled,
                vec![vec![10, 0], vec![15]],
                options.clone(),
            )
            .expect("execution");
            assert!(result.success, "{name}: {result}");
        }
    }

    #[test]
    fn rejects_generation_bounds_and_hits_the_stack_frontier() {
        use crate::support::script::MAX_OPTIMIZER_INPUT_BYTES;
        for (name, make, max) in [
            (
                "arith",
                u4_nibbles_to_ascii_hex_arith as fn(u32, HexLetterCase) -> Script,
                ASCII_HEX_ENCODE_ARITH_MAX_LEN,
            ),
            (
                "table",
                u4_nibbles_to_ascii_hex_table,
                ASCII_HEX_ENCODE_TABLE_MAX_LEN,
            ),
        ] {
            assert!(std::panic::catch_unwind(|| make(0, HexLetterCase::Lower)).is_err());
            assert!(std::panic::catch_unwind(|| make(max + 1, HexLetterCase::Lower)).is_err());
            let run_at = |extra: usize| {
                let compiled = script! {
                    { make(max, HexLetterCase::Lower) }
                    for _ in 0..max { OP_DROP }
                    for _ in 0..extra { OP_DROP }
                    OP_TRUE
                    for _ in 0..=MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
                }
                .compile_with_policy()
                .to_bytes();
                let mut witness = vec![vec![9u8]; extra];
                witness.extend(vec![vec![7u8]; max as usize]);
                execute_raw_script_with_inputs_strict(compiled, witness)
            };
            let base = run_at(0);
            assert!(base.success, "{name}: {base}");
            let spare = 1_000 - base.stats.max_nb_stack_items;
            assert!(run_at(spare).success, "{name}");
            assert_eq!(
                run_at(spare + 1).error,
                Some(ExecError::StackSize),
                "{name}"
            );
        }
    }
}
