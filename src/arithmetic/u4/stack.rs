use crate::support::script::*;
use bitcoin::{opcodes::all::*, Opcode};

/// Moves `n` raw main-stack items to the altstack.
///
/// The moved group is reversed on the altstack. The caller supplies any
/// range and canonical-encoding invariants.
pub fn u4_toaltstack(n: u32) -> Script {
    script! {
        for _ in 0..n {
            OP_TOALTSTACK
        }
    }
}

/// Moves `n` raw altstack items to the main stack.
///
/// The moved group is reversed on the main stack. The caller supplies any
/// range and canonical-encoding invariants.
pub fn u4_fromaltstack(n: u32) -> Script {
    script! {
        for _ in 0..n {
            OP_FROMALTSTACK
        }
    }
}

/// Copies eight contiguous raw stack items starting at `address` items from
/// the top. The caller supplies the range and canonicality invariants.
pub fn u4_copy_u32_from(address: u32) -> Script {
    script! {
        for _ in 0..8 {
            { address + 7 }
            OP_PICK
        }
    }
}

/// Moves eight contiguous raw stack items starting at `address` items from
/// the top. The caller supplies the range and canonicality invariants.
pub fn u4_move_u32_from(address: u32) -> Script {
    script! {
        for _ in 0..8 {
            { address + 7 }
            OP_ROLL
        }
    }
}

pub fn verify_n(n: u32) -> Script {
    script! {
        for i in 0..n {
            { n - i}
            OP_ROLL
            OP_EQUALVERIFY
        }
    }
}

/// Verifies eight staged altstack items against eight main-stack items.
///
/// The staged word must have been transferred with `u4_toaltstack(8)` and is
/// compared by raw byte encoding. This consumes both words on success and
/// performs no nibble-range or canonical-encoding validation.
pub fn u4_u32_verify_from_altstack() -> Script {
    script! {
        for _ in 0..8 {
            OP_FROMALTSTACK
        }

        for i in 0..8 {
            { 8 - i}
            OP_ROLL
            OP_EQUALVERIFY
        }
    }
}

pub fn u4_drop(n: u32) -> Script {
    script! {
        for _ in 0..n / 2 {
            OP_2DROP
        }
        if n & 1 == 1 {
            OP_DROP
        }
    }
}

pub fn u4_number_to_nibble(n: u32) -> Script {
    script! {
       for i in (0..8).rev() {
            { (n >> (i * 4)) & 0xF }
        }
    }
}

pub fn u4_hex_to_nibbles(hex_str: &str) -> Script {
    let nibbles: Result<Vec<u8>, std::num::ParseIntError> = hex_str
        .chars()
        .map(|c| u8::from_str_radix(&c.to_string(), 16))
        .collect();
    let nibbles = nibbles.unwrap();
    script! {
        for nibble in nibbles {
            { nibble }
        }
    }
}

/// Pack `high | low` nibbles into one byte-valued ScriptNum.
///
/// With `check_inputs`, both inputs are constrained to `0..=15`. Without it,
/// the caller must already have established that invariant.
pub fn u4_pair_to_u8(check_inputs: bool) -> Script {
    script! {
        if check_inputs {
            OP_DUP 0 16 OP_WITHIN OP_VERIFY
            1 OP_PICK 0 16 OP_WITHIN OP_VERIFY
        }
        OP_SWAP
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_ADD
    }
}

/// Pack `high | middle | low` nibbles into one 12-bit ScriptNum.
///
/// With `check_inputs`, all three inputs are constrained to `0..=15`. Without
/// it, the caller must already have established that invariant.
pub fn u4_triplet_to_u12(check_inputs: bool) -> Script {
    script! {
        if check_inputs {
            OP_DUP 0 16 OP_WITHIN OP_VERIFY
            1 OP_PICK 0 16 OP_WITHIN OP_VERIFY
            2 OP_PICK 0 16 OP_WITHIN OP_VERIFY
        }
        OP_SWAP
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_ADD
        OP_SWAP
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_ADD
    }
}
/// Pack `high | high_middle | low_middle | low` into one 16-bit ScriptNum.
///
/// With `check_inputs`, all four inputs are constrained to `0..=15`. Without
/// it, the caller must already have established that invariant.
pub fn u4_quad_to_u16(check_inputs: bool) -> Script {
    script! {
        if check_inputs {
            OP_DUP 0 16 OP_WITHIN OP_VERIFY
            1 OP_PICK 0 16 OP_WITHIN OP_VERIFY
            2 OP_PICK 0 16 OP_WITHIN OP_VERIFY
            3 OP_PICK 0 16 OP_WITHIN OP_VERIFY
        }
        OP_SWAP
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_ADD
        OP_SWAP
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_ADD
        OP_SWAP
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_ADD
    }
}
/// Split one byte-valued ScriptNum into `high | low` nibbles.
///
/// With `check_inputs`, the byte is constrained to `0..=255`. Without it,
/// the caller must already have established that invariant.
pub fn u8_to_u4_pair(check_inputs: bool) -> Script {
    script! {
        if check_inputs {
            OP_DUP 0 256 OP_WITHIN OP_VERIFY
        }
        0 OP_TOALTSTACK
        for (threshold, nibble) in [(128, 8), (64, 4), (32, 2), (16, 1)] {
            OP_DUP { threshold } OP_GREATERTHANOREQUAL
            OP_IF
                { threshold } OP_SUB
                OP_FROMALTSTACK { nibble } OP_ADD OP_TOALTSTACK
            OP_ENDIF
        }
        OP_FROMALTSTACK
        OP_SWAP
    }
}
/// Preserve the top value after proving it is a canonical ScriptNum nibble.
pub fn verify_canonical_nibble() -> Script {
    script! {
        OP_DUP 0 16 OP_WITHIN OP_VERIFY
        OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
    }
}

pub fn u4_repeat_number(n: u32, count: u32) -> Script {
    match count {
        0 => script! {},
        1 => script! { { n } },
        2 => script! { { n } OP_DUP },
        _ => {
            let diff = count - 2;
            let count = diff / 2;
            let rem = diff % 2;
            script! {
                {u4_repeat_number(n, 2)}
                for _ in 0..count {
                    OP_2DUP
                }
                if rem == 1 {
                    OP_DUP
                }
            }
        }
    }
}

pub trait CalculateOffset {
    fn modify(&mut self, element: Opcode) -> Script;
}

impl CalculateOffset for i32 {
    fn modify(&mut self, element: Opcode) -> Script {
        match element {
            OP_TOALTSTACK | OP_ADD => *self -= 1,
            OP_PICK => {}
            OP_DUP => *self += 1,
            _ => {
                panic!("unexpected opcode: {:?}", element);
            }
        }

        Script::new("").push_opcode(element)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{u4_hex_to_nibbles, u4_repeat_number};
    use crate::arithmetic::u4::stack::u4_number_to_nibble;
    use crate::support::execution::execute_script_with_inputs_strict;

    #[test]
    fn test_repeat() {
        for n in 0..30 {
            let script = script! {
                { u4_repeat_number(1, n) }
                for _ in 0..n {
                    OP_DROP
                }
                OP_TRUE
            };
            crate::support::execution::run(script);
        }
    }

    #[test]
    fn test_number_to_nibble() {
        let script = script! {
            { u4_number_to_nibble(0xfedc8765) }
            5
            OP_EQUALVERIFY
            6
            OP_EQUALVERIFY
            7
            OP_EQUALVERIFY
            8
            OP_EQUALVERIFY
            12
            OP_EQUALVERIFY
            13
            OP_EQUALVERIFY
            14
            OP_EQUALVERIFY
            15
            OP_EQUALVERIFY
            OP_TRUE
        };
        crate::support::execution::run(script);
    }

    #[test]
    fn altstack_transport_documents_one_way_order_and_roundtrip() {
        let to_alt = execute_script_with_inputs_strict(
            script! {
                42 OP_TOALTSTACK
                1 2 3
                { u4_toaltstack(3) }
                OP_FROMALTSTACK 1 OP_EQUALVERIFY
                OP_FROMALTSTACK 2 OP_EQUALVERIFY
                OP_FROMALTSTACK 3 OP_EQUALVERIFY
                OP_FROMALTSTACK 42 OP_EQUAL
            },
            vec![],
        );
        assert!(to_alt.success, "main-to-alt order changed: {to_alt}");

        let from_alt = execute_script_with_inputs_strict(
            script! {
                42 OP_TOALTSTACK
                3 OP_TOALTSTACK
                2 OP_TOALTSTACK
                1 OP_TOALTSTACK
                { u4_fromaltstack(3) }
                3 OP_EQUALVERIFY
                2 OP_EQUALVERIFY
                1 OP_EQUALVERIFY
                OP_FROMALTSTACK 42 OP_EQUAL
            },
            vec![],
        );
        assert!(from_alt.success, "alt-to-main order changed: {from_alt}");

        let roundtrip = execute_script_with_inputs_strict(
            script! {
                42 OP_TOALTSTACK
                1 2 3
                { u4_toaltstack(3) }
                { u4_fromaltstack(3) }
                3 OP_EQUALVERIFY
                2 OP_EQUALVERIFY
                1 OP_EQUALVERIFY
                OP_FROMALTSTACK 42 OP_EQUAL
            },
            vec![],
        );
        assert!(roundtrip.success, "roundtrip changed order: {roundtrip}");
    }

    #[test]
    fn altstack_transport_zero_is_a_noop() {
        let result = execute_script_with_inputs_strict(
            script! {
                42 OP_TOALTSTACK
                { u4_toaltstack(0) }
                { u4_fromaltstack(0) }
                OP_FROMALTSTACK 42 OP_EQUAL
            },
            vec![],
        );
        assert!(
            result.success,
            "zero-item transport changed state: {result}"
        );
    }

    #[test]
    fn altstack_transport_rejects_missing_items_in_both_directions() {
        let to_alt = execute_script_with_inputs_strict(script! { { u4_toaltstack(1) } }, vec![]);
        assert!(!to_alt.success);
        assert!(matches!(
            to_alt.error,
            Some(bitcoin_scriptexec::ExecError::InvalidStackOperation)
        ));

        let from_alt =
            execute_script_with_inputs_strict(script! { { u4_fromaltstack(1) } }, vec![]);
        assert!(!from_alt.success);
        assert!(matches!(
            from_alt.error,
            Some(bitcoin_scriptexec::ExecError::InvalidStackOperation)
        ));
    }

    #[test]
    fn altstack_word_verifier_accepts_matching_words_and_preserves_sentinels() {
        let result = execute_script_with_inputs_strict(
            script! {
                99 OP_TOALTSTACK
                77
                { u4_number_to_nibble(0x1234_5678) }
                { u4_number_to_nibble(0x1234_5678) }
                { u4_toaltstack(8) }
                { u4_u32_verify_from_altstack() }
                77 OP_EQUALVERIFY
                OP_FROMALTSTACK 99 OP_EQUAL
            },
            vec![],
        );
        assert!(result.success, "matching staged word failed: {result}");
    }

    #[test]
    fn altstack_word_verifier_rejects_a_mismatch_at_each_position() {
        for staged in [
            0x9234_5678,
            0x1934_5678,
            0x12a4_5678,
            0x123b_5678,
            0x1234_c678,
            0x1234_5d78,
            0x1234_56e8,
            0x1234_567f,
        ] {
            let result = execute_script_with_inputs_strict(
                script! {
                    { u4_number_to_nibble(0x1234_5678) }
                    { u4_number_to_nibble(staged) }
                    { u4_toaltstack(8) }
                    { u4_u32_verify_from_altstack() }
                    OP_TRUE
                },
                vec![],
            );
            assert!(!result.success, "accepted mismatching word {staged:#x}");
        }
    }

    #[test]
    fn altstack_word_verifier_compares_raw_encodings() {
        let mut main_word = vec![vec![0x01]; 8];
        let mut staged_word = main_word.clone();
        staged_word[0] = vec![0x01, 0x00];
        let mut witness = main_word.clone();
        witness.extend(staged_word.clone());
        let mismatch = execute_script_with_inputs_strict(
            script! {
                { u4_toaltstack(8) }
                { u4_u32_verify_from_altstack() }
                OP_TRUE
            },
            witness,
        );
        assert!(!mismatch.success, "accepted a noncanonical byte alias");

        staged_word[0] = vec![0x01, 0x00];
        main_word[0] = staged_word[0].clone();
        let mut matching_witness = main_word;
        matching_witness.extend(staged_word);
        let matching = execute_script_with_inputs_strict(
            script! {
                { u4_toaltstack(8) }
                { u4_u32_verify_from_altstack() }
                OP_TRUE
            },
            matching_witness,
        );
        assert!(matching.success, "identical raw encodings did not match");
    }

    #[test]
    fn altstack_word_verifier_rejects_missing_main_or_alt_items() {
        let missing_alt = execute_script_with_inputs_strict(
            script! {
                { u4_number_to_nibble(0x1234_5678) }
                { u4_u32_verify_from_altstack() }
            },
            vec![],
        );
        assert!(!missing_alt.success);
        assert!(matches!(
            missing_alt.error,
            Some(bitcoin_scriptexec::ExecError::InvalidStackOperation)
        ));

        let missing_main = execute_script_with_inputs_strict(
            script! {
                { u4_number_to_nibble(0x1234_5678) }
                { u4_toaltstack(8) }
                { u4_u32_verify_from_altstack() }
            },
            vec![],
        );
        assert!(!missing_main.success);
        assert!(matches!(
            missing_main.error,
            Some(bitcoin_scriptexec::ExecError::InvalidStackOperation)
        ));
    }

    #[test]
    fn copy_and_move_u32_preserve_nibble_order() {
        for (transfer, copied) in [(u4_copy_u32_from(0), true), (u4_move_u32_from(0), false)] {
            crate::support::execution::run(script! {
                { u4_number_to_nibble(0x1234_5678) }
                { transfer }
                8 OP_EQUALVERIFY
                7 OP_EQUALVERIFY
                6 OP_EQUALVERIFY
                5 OP_EQUALVERIFY
                4 OP_EQUALVERIFY
                3 OP_EQUALVERIFY
                2 OP_EQUALVERIFY
                1 OP_EQUALVERIFY
                if copied {
                    8 OP_EQUALVERIFY
                    7 OP_EQUALVERIFY
                    6 OP_EQUALVERIFY
                    5 OP_EQUALVERIFY
                    4 OP_EQUALVERIFY
                    3 OP_EQUALVERIFY
                    2 OP_EQUALVERIFY
                    1 OP_EQUALVERIFY
                }
                OP_TRUE
            });
        }
    }

    #[test]
    fn copy_and_move_u32_at_depth_eight_preserve_every_word() {
        for (transfer, copied) in [(u4_copy_u32_from(8), true), (u4_move_u32_from(8), false)] {
            crate::support::execution::run(script! {
                5 OP_TOALTSTACK
                99
                { u4_number_to_nibble(0x1234_5678) }
                { u4_number_to_nibble(0x9abc_def0) }
                { transfer }
                if copied {
                    8 OP_EQUALVERIFY
                    7 OP_EQUALVERIFY
                    6 OP_EQUALVERIFY
                    5 OP_EQUALVERIFY
                    4 OP_EQUALVERIFY
                    3 OP_EQUALVERIFY
                    2 OP_EQUALVERIFY
                    1 OP_EQUALVERIFY
                    0 OP_EQUALVERIFY
                    15 OP_EQUALVERIFY
                    14 OP_EQUALVERIFY
                    13 OP_EQUALVERIFY
                    12 OP_EQUALVERIFY
                    11 OP_EQUALVERIFY
                    10 OP_EQUALVERIFY
                    9 OP_EQUALVERIFY
                    8 OP_EQUALVERIFY
                    7 OP_EQUALVERIFY
                    6 OP_EQUALVERIFY
                    5 OP_EQUALVERIFY
                    4 OP_EQUALVERIFY
                    3 OP_EQUALVERIFY
                    2 OP_EQUALVERIFY
                    1 OP_EQUALVERIFY
                } else {
                    8 OP_EQUALVERIFY
                    7 OP_EQUALVERIFY
                    6 OP_EQUALVERIFY
                    5 OP_EQUALVERIFY
                    4 OP_EQUALVERIFY
                    3 OP_EQUALVERIFY
                    2 OP_EQUALVERIFY
                    1 OP_EQUALVERIFY
                    0 OP_EQUALVERIFY
                    15 OP_EQUALVERIFY
                    14 OP_EQUALVERIFY
                    13 OP_EQUALVERIFY
                    12 OP_EQUALVERIFY
                    11 OP_EQUALVERIFY
                    10 OP_EQUALVERIFY
                    9 OP_EQUALVERIFY
                }
                99 OP_EQUALVERIFY
                OP_FROMALTSTACK 5 OP_EQUALVERIFY
                OP_TRUE
            });
        }
    }

    #[test]
    fn copy_and_move_u32_reject_out_of_bounds_source_depth() {
        for transfer in [u4_copy_u32_from(9), u4_move_u32_from(9)] {
            let result = crate::support::execution::execute_script_with_inputs_strict(
                script! { { transfer } },
                vec![vec![1]; 16],
            );
            assert_eq!(
                result.error,
                Some(bitcoin_scriptexec::ExecError::InvalidStackOperation),
                "out-of-bounds source depth changed: {result}"
            );
        }
    }

    #[test]
    fn word_transfer_stack_boundaries_are_strict() {
        for (transfer, success_items, success_output_items, failure_items) in [
            (u4_copy_u32_from(0), 992usize, 1000usize, 993usize),
            (u4_move_u32_from(0), 999usize, 999usize, 1000usize),
        ] {
            let success = crate::support::execution::execute_script_with_inputs_strict(
                script! {
                    { transfer.clone() }
                    for _ in 0..success_output_items { OP_DROP }
                    OP_TRUE
                },
                vec![vec![1]; success_items],
            );
            assert!(success.success, "boundary success failed: {success}");

            let failure = crate::support::execution::execute_script_with_inputs_strict(
                script! { { transfer } },
                vec![vec![1]; failure_items],
            );
            assert_eq!(
                failure.error,
                Some(bitcoin_scriptexec::ExecError::StackSize),
                "boundary failure changed: {failure}"
            );
        }
    }

    #[test]
    fn test_hex_to_nibble() {
        let script = script! {
            { u4_hex_to_nibbles("fedc8765")}
            5
            OP_EQUALVERIFY
            6
            OP_EQUALVERIFY
            7
            OP_EQUALVERIFY
            8
            OP_EQUALVERIFY
            12
            OP_EQUALVERIFY
            13
            OP_EQUALVERIFY
            14
            OP_EQUALVERIFY
            15
            OP_EQUALVERIFY
            OP_TRUE
        };
        crate::support::execution::run(script);
    }

    #[test]
    fn packs_all_checked_nibble_pairs() {
        for byte in 0..=u8::MAX {
            let result = crate::support::execution::execute_script(script! {
                { (byte >> 4) as u32 }
                { (byte & 0x0f) as u32 }
                { u4_pair_to_u8(true) }
                { byte as u32 } OP_EQUAL
            });
            assert!(result.success, "failed to pack byte {byte:#x}: {result}");
        }
    }

    #[test]
    fn checked_pair_rejects_malformed_nibbles_and_preserves_state() {
        for (high, low) in [(-1, 0), (0, 16), (16, 0), (0, -1)] {
            let result = crate::support::execution::execute_script(script! {
                { high }
                { low }
                { u4_pair_to_u8(true) }
                OP_TRUE
            });
            assert!(!result.success, "accepted malformed pair {high}, {low}");
        }

        let result = crate::support::execution::execute_script(script! {
            OP_9
            0xa
            0xb
            { u4_pair_to_u8(true) }
            171 OP_EQUALVERIFY
            9 OP_EQUAL
        });
        assert!(
            result.success,
            "pair packing changed preserved state: {result}"
        );
    }

    #[test]
    fn checked_triplet_packs_boundaries_and_preserves_state() {
        for (high, middle, low, expected) in [
            (0, 0, 0, 0),
            (1, 2, 3, 0x123),
            (15, 0, 1, 0xf01),
            (15, 15, 15, 0xfff),
        ] {
            let result = crate::support::execution::execute_script(script! {
                { high }
                { middle }
                { low }
                { u4_triplet_to_u12(true) }
                { expected } OP_EQUAL
            });
            assert!(
                result.success,
                "failed to pack triplet {high:x}{middle:x}{low:x}: {result}"
            );
        }

        for (high, middle, low) in [(-1, 0, 0), (0, 16, 0), (0, 0, 16)] {
            let result = crate::support::execution::execute_script(script! {
                { high }
                { middle }
                { low }
                { u4_triplet_to_u12(true) }
                OP_TRUE
            });
            assert!(
                !result.success,
                "accepted malformed triplet {high}, {middle}, {low}"
            );
        }

        let result = crate::support::execution::execute_script(script! {
            77 OP_TOALTSTACK
            99
            1 2 3
            { u4_triplet_to_u12(true) }
            0x123 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "triplet packing changed preserved state: {result}"
        );
    }

    #[test]
    fn unchecked_triplet_requires_the_caller_invariant() {
        let result = crate::support::execution::execute_script(script! {
            0 -1 2
            { u4_triplet_to_u12(false) }
            -14 OP_EQUAL
        });
        assert!(
            result.success,
            "unchecked triplet did not preserve arithmetic semantics: {result}"
        );
    }
    #[test]
    fn checked_quad_packs_boundaries_and_preserves_state() {
        for (high, high_middle, low_middle, low, expected) in [
            (0, 0, 0, 0, 0),
            (1, 2, 3, 4, 0x1234),
            (15, 0, 1, 2, 0xf012),
            (15, 15, 15, 15, 0xffff),
        ] {
            let result = crate::support::execution::execute_script(script! {
                { high }
                { high_middle }
                { low_middle }
                { low }
                { u4_quad_to_u16(true) }
                { expected } OP_EQUAL
            });
            assert!(
                result.success,
                "failed to pack quad {high:x}{high_middle:x}{low_middle:x}{low:x}: {result}"
            );
        }

        for (high, high_middle, low_middle, low) in
            [(-1, 0, 0, 0), (0, 16, 0, 0), (0, 0, 16, 0), (0, 0, 0, 16)]
        {
            let result = crate::support::execution::execute_script(script! {
                { high }
                { high_middle }
                { low_middle }
                { low }
                { u4_quad_to_u16(true) }
                OP_TRUE
            });
            assert!(
                !result.success,
                "accepted malformed quad {high}, {high_middle}, {low_middle}, {low}"
            );
        }

        let result = crate::support::execution::execute_script(script! {
            77 OP_TOALTSTACK
            99
            1 2 3 4
            { u4_quad_to_u16(true) }
            0x1234 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "quad packing changed preserved state: {result}"
        );
    }

    #[test]
    fn unchecked_pair_requires_the_caller_invariant() {
        let result = crate::support::execution::execute_script(script! {
            0 -1
            { u4_pair_to_u8(false) }
            -1 OP_EQUAL
        });
        assert!(
            result.success,
            "unchecked pair did not preserve hostile item: {result}"
        );
    }
    #[test]
    fn splits_all_checked_bytes() {
        for byte in 0..=u8::MAX {
            let result = crate::support::execution::execute_script(script! {
                { byte as u32 }
                { u8_to_u4_pair(true) }
                { (byte & 0x0f) as u32 } OP_EQUALVERIFY
                { (byte >> 4) as u32 } OP_EQUAL
            });
            assert!(result.success, "failed to split byte {byte:#x}: {result}");
        }
    }

    #[test]
    fn checked_split_rejects_malformed_bytes_and_preserves_altstack() {
        for invalid in [-1, 256] {
            let result = crate::support::execution::execute_script(script! {
                { invalid }
                { u8_to_u4_pair(true) }
                OP_TRUE
            });
            assert!(!result.success, "accepted malformed byte {invalid}");
        }

        let result = crate::support::execution::execute_script(script! {
            OP_7 OP_TOALTSTACK
            171
            { u8_to_u4_pair(true) }
            11 OP_EQUALVERIFY
            10 OP_EQUALVERIFY
            OP_FROMALTSTACK 7 OP_EQUAL
        });
        assert!(
            result.success,
            "split changed unrelated altstack state: {result}"
        );
    }

    #[test]
    fn unchecked_split_requires_the_caller_invariant() {
        let result = crate::support::execution::execute_script(script! {
            -1
            { u8_to_u4_pair(false) }
            -1 OP_EQUALVERIFY
            0 OP_EQUAL
        });
        assert!(
            result.success,
            "unchecked split changed hostile byte: {result}"
        );
    }
    #[test]
    fn canonical_nibble_boundary_rejects_aliases_and_out_of_range_values() {
        for value in 0..=15 {
            let mut bytes = [0u8; 8];
            let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value));
            let encoded = bytes[..length].to_vec();
            let result = crate::support::execution::execute_script_with_inputs(
                script! {
                    5 OP_TOALTSTACK
                    { verify_canonical_nibble() }
                    { value } OP_EQUALVERIFY
                    OP_FROMALTSTACK 5 OP_EQUALVERIFY
                    99 OP_EQUAL
                },
                vec![vec![99], encoded],
            );
            assert!(
                result.success,
                "rejected canonical nibble {value}: {result}"
            );
        }

        for encoded in [
            vec![1, 0],          // redundant positive sign byte
            vec![0x80],          // negative zero
            vec![16],            // canonical but outside the nibble range
            vec![0xff],          // negative value
            vec![0, 0, 0, 0, 0], // oversized zero
        ] {
            let result = crate::support::execution::execute_script_with_inputs(
                script! { { verify_canonical_nibble() } },
                vec![encoded],
            );
            assert!(!result.success, "accepted malformed nibble: {result}");
        }
    }
}
