use crate::arithmetic::u32::sub::u32_sub_drop;
use crate::support::script::*;
use crate::support::script_ops::{push_to_stack, OP_256MUL, OP_4DUP};

pub fn u32_push(value: u32) -> Script {
    script! {
        if ((value >> 24) & 0xff) == ((value >> 16) & 0xff) &&
            ((value >> 24) & 0xff) == ((value >> 8) & 0xff) &&
            ((value >> 24) & 0xff) == (value & 0xff) {
                { push_to_stack(((value >> 24) & 0xff) as usize, 4) }
        }
        else{
                {(value >> 24) & 0xff}
                {(value >> 16) & 0xff}
                {(value >>  8) & 0xff}
                {value & 0xff}
        }
    }
}

/// Preserve the top value after proving it is a canonical ScriptNum byte.
pub fn verify_canonical_byte() -> Script {
    script! {
        OP_DUP 0 256 OP_WITHIN OP_VERIFY
        OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
    }
}

/// Consumes two u32 words and fails unless their four raw byte limbs match.
///
/// It leaves no result on success; callers must provide any terminal predicate.
pub fn u32_equalverify() -> Script {
    script! {
        4
        OP_ROLL
        OP_EQUALVERIFY
        3
        OP_ROLL
        OP_EQUALVERIFY
        OP_ROT
        OP_EQUALVERIFY
        OP_EQUALVERIFY
    }
}

/// Consumes two u32 words and leaves one Boolean result for byte-for-byte equality.
///
/// It does not validate byte range or canonical ScriptNum encoding.
pub fn u32_equal() -> Script {
    script! {
        4
        OP_ROLL
        OP_EQUAL OP_TOALTSTACK
        3
        OP_ROLL
        OP_EQUAL OP_TOALTSTACK
        OP_ROT
        OP_EQUAL OP_TOALTSTACK
        OP_EQUAL
        OP_FROMALTSTACK OP_BOOLAND
        OP_FROMALTSTACK OP_BOOLAND
        OP_FROMALTSTACK OP_BOOLAND
    }
}

pub fn u32_notequal() -> Script {
    script! {
        { u32_equal() }
        OP_NOT
    }
}

/// Replaces the top four-byte word with its bytewise complement.
///
/// The input and output use the module's most-significant-byte-first word
/// layout. Each iteration rolls the next original limb to the top and fails
/// unless it is a minimally encoded numeric byte in `0..=255`, so all four
/// hostile limbs are checked before subtraction. The fragment leaves the four
/// result limbs and no terminal predicate.
pub fn u32_not() -> Script {
    script! {
        for _ in 0..4 {
            3 OP_ROLL
            { verify_canonical_byte() }
            255 OP_SWAP OP_SUB
        }
    }
}

fn certify_compressed_word() -> Script {
    script! {
        OP_DUP
        OP_SIZE
        5
        OP_EQUAL
        OP_IF
            -2147483648
            OP_EQUALVERIFY
        OP_ELSE
            OP_DUP
            0
            OP_ADD
            OP_EQUALVERIFY
        OP_ENDIF
    }
}

/// Compares two canonical compressed u32 ScriptNums for equality.
pub fn u32_compressed_equal() -> Script {
    script! {
        { certify_compressed_word() }
        OP_TOALTSTACK
        { certify_compressed_word() }
        OP_FROMALTSTACK
        OP_EQUAL
    }
}
/// Conditionally negates the top u32 word modulo 2^32.
///
/// Before: `preserved | word | condition`.
/// After: `preserved | (condition == 0 ? word : -word)`.
/// The condition is normalized with `OP_0NOTEQUAL`; the word must already use
/// the module's four-byte representation.
pub fn u32_conditional_negate() -> Script {
    script! {
        OP_0NOTEQUAL
        OP_IF
            { u32_push(0) }
            { u32_sub_drop(0, 1) }
        OP_ENDIF
    }
}
/// Test whether the top u32 word is numerically zero and consume it.
///
/// The four byte limbs must already be canonical values in `0..=255`.
pub fn u32_iszero() -> Script {
    script! {
        OP_0NOTEQUAL
        OP_NOT
        OP_SWAP
        OP_0NOTEQUAL
        OP_NOT
        OP_BOOLAND
        OP_SWAP
        OP_0NOTEQUAL
        OP_NOT
        OP_BOOLAND
        OP_SWAP
        OP_0NOTEQUAL
        OP_NOT
        OP_BOOLAND
    }
}

/// Count the leading zero bytes in the top u32 word.
///
/// The four byte limbs must be canonical values in `0..=255`. The result is
/// in `0..=4`; all four limbs are consumed.
pub fn u32_leading_zero_bytes() -> Script {
    script! {
        { u32_toaltstack() }
        OP_FROMALTSTACK { verify_canonical_byte() } OP_0NOTEQUAL
        OP_IF
            0
            OP_FROMALTSTACK { verify_canonical_byte() } OP_DROP
            OP_FROMALTSTACK { verify_canonical_byte() } OP_DROP
            OP_FROMALTSTACK { verify_canonical_byte() } OP_DROP
        OP_ELSE
            OP_FROMALTSTACK { verify_canonical_byte() } OP_0NOTEQUAL
            OP_IF
                1
                OP_FROMALTSTACK { verify_canonical_byte() } OP_DROP
                OP_FROMALTSTACK { verify_canonical_byte() } OP_DROP
            OP_ELSE
                OP_FROMALTSTACK { verify_canonical_byte() } OP_0NOTEQUAL
                OP_IF
                    2
                    OP_FROMALTSTACK { verify_canonical_byte() } OP_DROP
                OP_ELSE
                    OP_FROMALTSTACK { verify_canonical_byte() } OP_0NOTEQUAL
                    OP_IF
                        3
                    OP_ELSE
                        4
                    OP_ENDIF
                OP_ENDIF
            OP_ENDIF
        OP_ENDIF
    }
}
/// Count the trailing zero bytes in the top u32 word.
///
/// The four byte limbs must be canonical values in `0..=255`. The result is
/// in `0..=4`; all four limbs are consumed.
pub fn u32_trailing_zero_bytes() -> Script {
    script! {
        { verify_canonical_byte() } OP_0NOTEQUAL
        OP_IF
            { verify_canonical_byte() } OP_DROP
            { verify_canonical_byte() } OP_DROP
            { verify_canonical_byte() } OP_DROP
            0
        OP_ELSE
            { verify_canonical_byte() } OP_0NOTEQUAL
            OP_IF
                { verify_canonical_byte() } OP_DROP
                { verify_canonical_byte() } OP_DROP
                1
            OP_ELSE
                { verify_canonical_byte() } OP_0NOTEQUAL
                OP_IF
                    { verify_canonical_byte() } OP_DROP
                    2
                OP_ELSE
                    { verify_canonical_byte() } OP_0NOTEQUAL
                    OP_IF
                        3
                    OP_ELSE
                        4
                    OP_ENDIF
                OP_ENDIF
            OP_ENDIF
        OP_ENDIF
    }
}
/// Extract one checked byte from the top u32 word and consume the other bytes.
///
/// `byte_index` is zero-based from the most significant byte. All four byte
/// limbs must be canonical values in `0..=255`.
pub fn u32_extract_byte(byte_index: usize) -> Script {
    assert!(byte_index < 4);
    let select = match byte_index {
        0 => script! {
            OP_2DROP
            OP_DROP
        },
        1 => script! {
            OP_2DROP
            OP_TOALTSTACK
            OP_DROP
            OP_FROMALTSTACK
        },
        2 => script! {
            OP_DROP
            OP_TOALTSTACK
            OP_2DROP
            OP_FROMALTSTACK
        },
        3 => script! {
            OP_TOALTSTACK
            OP_2DROP
            OP_DROP
            OP_FROMALTSTACK
        },
        _ => unreachable!(),
    };

    script! {
        { u32_toaltstack() }
        OP_FROMALTSTACK { verify_canonical_byte() }
        OP_FROMALTSTACK { verify_canonical_byte() }
        OP_FROMALTSTACK { verify_canonical_byte() }
        OP_FROMALTSTACK { verify_canonical_byte() }
        { select }
    }
}

pub fn u32_toaltstack() -> Script {
    script! {
        OP_TOALTSTACK
        OP_TOALTSTACK
        OP_TOALTSTACK
        OP_TOALTSTACK
    }
}

pub fn u32_fromaltstack() -> Script {
    script! {
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
    }
}

/// Move `num_bytes` raw stack items to the alt stack while preserving order.
///
/// The top item is restored first by `OP_FROMALTSTACK`; callers must enforce
/// byte range and canonical ScriptNum encoding when those invariants matter.
pub fn u8_reverse_toaltstack(num_bytes: usize) -> Script {
    script! {
        for i in 1..=num_bytes {
            {num_bytes - i} OP_ROLL
            OP_TOALTSTACK
        }
    }
}

/// Select one complete u32 word using numeric Script truthiness.
///
/// Stack before (top first): `condition | when_true | when_false`.
/// Stack after: the selected word. The condition is consumed; a canonical
/// boolean is not required: `OP_0NOTEQUAL` accepts an at-most-four-byte
/// ScriptNum before passing a canonical boolean to `OP_IF`. Numeric aliases
/// are accepted when the execution profile permits nonminimal numbers.
/// This routing fragment does not validate either word's limb encoding/range.
pub fn u32_conditional_select() -> Script {
    script! {
        OP_0NOTEQUAL
        OP_IF
            { u32_toaltstack() }
            { u32_drop() }
            { u32_fromaltstack() }
        OP_ELSE
            { u32_drop() }
        OP_ENDIF
    }
}

pub fn u32_dup() -> Script {
    script! { OP_4DUP }
}

pub fn u32_drop() -> Script {
    script! {
        OP_2DROP
        OP_2DROP
    }
}

pub fn u32_roll(n: u32) -> Script {
    let n = (n + 1) * 4 - 1;
    script! {
        {n} OP_ROLL
        {n} OP_ROLL
        {n} OP_ROLL
        {n} OP_ROLL
    }
}

pub fn u32_pick(n: u32) -> Script {
    let n = (n + 1) * 4 - 1;
    script! {
        {n} OP_PICK
        {n} OP_PICK
        {n} OP_PICK
        {n} OP_PICK
    }
}

/// Compresses the top u32 element into a single signed ScriptNum item.
///
/// The four MSB-first byte items are interpreted as a u32 and then mapped to
/// `value as i32`; the result uses minimal signed ScriptNum encoding. The
/// helper does not validate byte range, canonical encoding, or the unsigned
/// domain.
pub fn u32_compress() -> Script {
    script! {
        OP_SWAP OP_2SWAP OP_SWAP
        0x80
        OP_2DUP OP_GREATERTHANOREQUAL
        OP_DUP OP_TOALTSTACK
        OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
        OP_256MUL OP_ADD
        OP_256MUL OP_ADD
        OP_256MUL OP_ADD
        OP_FROMALTSTACK
        OP_IF 0x7FFFFFFF OP_SUB OP_1SUB OP_ENDIF
    }
}

/// Compress a minimally encoded four-byte u32 word into one ScriptNum.
pub fn u32_compress_canonical() -> Script {
    script! {
        for _ in 0..4 {
            { verify_canonical_byte() }
            OP_TOALTSTACK
        }
        for _ in 0..4 {
            OP_FROMALTSTACK
        }
        { u32_compress() }
    }
}

/// Expands a ScriptNum of at most five bytes into four byte items.
///
/// Any five-byte input takes the special `-2^31` branch; callers must enforce
/// the intended signed representation and canonical encoding first.
pub fn u32_uncompress() -> Script {
    script! {
        OP_SIZE OP_5 OP_EQUAL
        OP_TUCK OP_IF
            OP_DROP OP_0
        OP_ELSE
            OP_TUCK OP_GREATERTHAN
            OP_TUCK OP_IF 0x7FFFFFFF OP_ADD OP_1ADD OP_ENDIF
        OP_ENDIF
        { u32_uncompress_body() }
    }
}

fn u32_uncompress_body() -> Script {
    script! {
        OP_SWAP OP_TOALTSTACK
        for i in 1..8 {
            { 1 << (31 - i) } OP_2DUP OP_GREATERTHANOREQUAL
            OP_FROMALTSTACK OP_DUP OP_ADD OP_OVER OP_ADD OP_TOALTSTACK
            OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
        }
        { 1 << 23 } OP_2DUP OP_GREATERTHANOREQUAL OP_DUP OP_TOALTSTACK
        OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
        for i in 1..8 {
            { 1 << (23 - i) } OP_2DUP OP_GREATERTHANOREQUAL
            OP_FROMALTSTACK OP_DUP OP_ADD OP_OVER OP_ADD OP_TOALTSTACK
            OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
        }
        { 1 << 15 } OP_2DUP OP_GREATERTHANOREQUAL OP_DUP OP_TOALTSTACK
        OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
        for i in 1..8 {
            { 1 << (15 - i) } OP_2DUP OP_GREATERTHANOREQUAL
            OP_FROMALTSTACK OP_DUP OP_ADD OP_OVER OP_ADD OP_TOALTSTACK
            OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
        }
        OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
        OP_SWAP OP_2SWAP OP_SWAP
    }
}

/// Decode a canonical non-negative ScriptNum in `0..=0x7fffffff` into four bytes.
/// The input is consumed and must be minimally encoded.
pub fn u32_uncompress_canonical_nonnegative() -> Script {
    script! {
        OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
        OP_DUP { 2_147_483_647i64 } OP_GREATERTHAN OP_NOT OP_VERIFY
        OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
        0
        OP_SWAP
        { u32_uncompress_body() }
    }
}

/// Decode one minimally encoded signed ScriptNum representing a u32.
///
/// The high bit selects the signed two's-complement half of the u32 domain;
/// `0x80000000` is the sole accepted five-byte encoding. The four output
/// bytes retain the module's most-significant-byte-first order.
pub fn u32_uncompress_canonical() -> Script {
    script! {
        OP_SIZE 5 OP_NUMEQUAL
        OP_IF
            OP_DUP { -2_147_483_648i64 } OP_EQUALVERIFY
        OP_ELSE
            OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
        OP_ENDIF
        { u32_uncompress() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{
        execute_raw_script_with_inputs_strict, execute_script, execute_script_buf_with_options,
        execute_script_with_inputs_strict, run,
    };
    use bitcoin_scriptexec::Options;

    fn scriptnum(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let length = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..length].to_vec()
    }

    fn accepts_canonical(value: u32) {
        let script = script! {
            { u32_uncompress_canonical() }
            { u32_push(value) }
            { u32_equalverify() }
            OP_TRUE
        };
        let result = execute_raw_script_with_inputs_strict(
            script.compile_with_policy().to_bytes(),
            vec![scriptnum(i64::from(value as i32))],
        );
        assert!(
            result.success,
            "failed to decode canonical {value:#x}: {result}"
        );
    }

    fn rejects_noncanonical(raw: Vec<u8>) {
        let script = script! {
            { u32_uncompress_canonical() }
            OP_2DROP
            OP_2DROP
            OP_TRUE
        };
        let result = execute_raw_script_with_inputs_strict(
            script.compile_with_policy().to_bytes(),
            vec![raw],
        );
        assert!(!result.success, "accepted noncanonical compressed word");
    }

    fn assert_malformed_limb_error(
        result: &crate::support::execution::ExecuteInfo,
        expected: bitcoin_scriptexec::ExecError,
        scenario: &str,
    ) {
        assert!(
            !result.success,
            "accepted malformed limb ({scenario}): {result}"
        );
        assert_eq!(
            result.error.as_ref(),
            Some(&expected),
            "malformed limb missed its intended validation error ({scenario}): {result}"
        );
    }

    #[test]
    fn test_u32_notequal() {
        for (a, b) in [
            (0, 0),
            (0, 1),
            (0xff, 0x100),
            (u32::MAX, u32::MAX),
            (u32::MAX, 0),
        ] {
            let script = script! {
                { u32_push(a) }
                { u32_push(b) }
                { u32_notequal() }
                { (a != b) as u32 }
                OP_EQUAL
            };
            run(script);
        }
    }

    #[test]
    fn complements_boundary_and_pattern_words() {
        for value in [0, 1, 0x0102_0304, 0x8000_0000, u32::MAX] {
            let script = script! {
                { u32_push(value) }
                { u32_not() }
                { u32_push(!value) }
                { u32_equal() }
                OP_VERIFY
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn checked_complement_rejects_non_byte_limbs() {
        let pushed_limbs = |limbs: [i64; 4]| {
            crate::support::execution::execute_script(script! {
                for limb in limbs {
                    { limb }
                }
                { u32_not() }
                { u32_drop() }
                OP_TRUE
            })
        };
        let control = pushed_limbs([1, 2, 3, 4]);
        assert!(control.success, "rejected valid pushed limbs: {control}");
        for invalid_index in 0..4 {
            let mut limbs = [1i64, 2, 3, 4];
            limbs[invalid_index] = if invalid_index % 2 == 0 { -1 } else { 256 };
            let result = pushed_limbs(limbs);
            assert!(
                !result.success,
                "accepted invalid limb {invalid_index}: {result}"
            );
        }

        let checked_script = script! {
            { u32_not() }
            OP_2DROP OP_2DROP OP_TRUE
        }
        .compile_with_policy()
        .to_bytes();
        let options = Options {
            require_minimal: false,
            enforce_stack_limit: true,
            ..Default::default()
        };
        let valid = execute_script_buf_with_options(
            bitcoin::ScriptBuf::from_bytes(checked_script.clone()),
            vec![vec![1u8]; 4],
            options.clone(),
        )
        .expect("valid checked complement execution");
        assert!(valid.success, "rejected valid byte word: {valid}");

        for invalid in [vec![1, 0], vec![0x80], vec![0xff], vec![0, 1]] {
            for invalid_index in 0..4 {
                let mut witness = vec![vec![1u8]; 4];
                witness[invalid_index] = invalid.clone();
                let result = execute_script_buf_with_options(
                    bitcoin::ScriptBuf::from_bytes(checked_script.clone()),
                    witness,
                    options.clone(),
                )
                .expect("malformed checked complement execution");
                assert!(
                    !result.success,
                    "malformed byte at position {invalid_index} was not rejected: {result}"
                );
            }
        }

        let short = execute_script_buf_with_options(
            bitcoin::ScriptBuf::from_bytes(checked_script),
            vec![vec![1u8]; 3],
            options,
        )
        .expect("short checked complement execution");
        assert_eq!(
            short.error,
            Some(bitcoin_scriptexec::ExecError::InvalidStackOperation)
        );
    }

    #[test]
    fn checked_complement_preserves_surrounding_stacks() {
        let value = 0x1020_3040;
        let result = crate::support::execution::execute_script(script! {
            77 OP_TOALTSTACK
            { u32_push(value) }
            { u32_not() }
            { u32_push(!value) }
            { u32_equalverify() }
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "stack-preserving complement failed: {result}"
        );
    }

    #[test]
    fn checked_complement_rejects_malformed_and_nonminimal_limbs() {
        use crate::support::tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile};
        use bitcoin::ScriptBuf;
        use bitcoin_scriptexec::ExecError;

        fn complete_leaf(fragment: Script) -> ScriptBuf {
            script! {
                { fragment }
                { u32_drop() }
                OP_TRUE
            }
            .compile_with_policy()
        }

        fn executed_success(leaf: &ScriptBuf, witness: Vec<Vec<u8>>) -> bool {
            matches!(
                execute_tapscript(leaf.clone(), witness, TapscriptProfile::Consensus).outcome,
                TapscriptOutcome::Executed(info) if info.success
            )
        }

        fn all_nonminimal_aliases_rejected(leaf: &ScriptBuf) -> bool {
            let canonical = vec![vec![1]; 4];
            let control =
                execute_tapscript(leaf.clone(), canonical.clone(), TapscriptProfile::Consensus);
            let TapscriptOutcome::Executed(info) = &control.outcome else {
                panic!("control leaf had no execution verdict: {control:?}");
            };
            assert!(info.success, "control leaf failed: {control:?}");
            assert!(info.stack_limit_enforced);
            assert_eq!(info.final_stack.len(), 1);
            assert_eq!(info.final_stack.get(0), vec![1]);

            (0..4).all(|index| {
                let mut witness = canonical.clone();
                witness[index] = vec![1, 0];
                matches!(
                    execute_tapscript(leaf.clone(), witness, TapscriptProfile::Consensus).outcome,
                    TapscriptOutcome::Executed(ref info)
                        if !info.success && info.error == Some(ExecError::EqualVerify)
                )
            })
        }

        let leaf = complete_leaf(u32_not());
        let canonical = vec![vec![1]; 4];
        assert!(executed_success(&leaf, canonical.clone()));
        for (raw, expected_error) in [
            (vec![0x81], ExecError::Verify),
            (vec![0xff], ExecError::Verify),
            (vec![0, 1], ExecError::Verify),
            (vec![0x80], ExecError::EqualVerify),
            (vec![1, 0], ExecError::EqualVerify),
            (vec![0, 0, 0, 0, 1], ExecError::ScriptIntNumericOverflow),
        ] {
            for index in 0..4 {
                let mut witness = canonical.clone();
                witness[index] = raw.clone();
                let result = execute_tapscript(leaf.clone(), witness, TapscriptProfile::Consensus);
                assert!(
                    matches!(
                        result.outcome,
                        TapscriptOutcome::Executed(ref info)
                            if !info.success && info.error == Some(expected_error.clone())
                    ),
                    "limb {index} with {raw:02x?} produced unexpected outcome: {result:?}"
                );
            }
        }

        assert!(all_nonminimal_aliases_rejected(&leaf));

        // Top-limb-only validator: all four checks inspect the same original
        // limb, so the all-position predicate above must fail for positions 0–2.
        let top_limb_only_mutant = complete_leaf(script! {
            for _ in 0..4 {
                { verify_canonical_byte() }
            }
            for _ in 0..4 {
                3 OP_ROLL
                255 OP_SWAP OP_SUB
            }
        });
        assert!(executed_success(&top_limb_only_mutant, canonical.clone()));
        assert!(!all_nonminimal_aliases_rejected(&top_limb_only_mutant));
        for index in 0..4 {
            let mut witness = canonical.clone();
            witness[index] = vec![1, 0];
            let result = execute_tapscript(
                top_limb_only_mutant.clone(),
                witness,
                TapscriptProfile::Consensus,
            );
            if index < 3 {
                assert!(
                    matches!(result.outcome, TapscriptOutcome::Executed(ref info) if info.success),
                    "top-limb-only mutant did not accept limb {index}: {result:?}"
                );
            } else {
                assert!(
                    matches!(
                        result.outcome,
                        TapscriptOutcome::Executed(ref info)
                            if !info.success && info.error == Some(ExecError::EqualVerify)
                    ),
                    "top-limb-only mutant changed top-limb behavior: {result:?}"
                );
            }
        }

        for value in [0, 127, 128, 255] {
            for index in 0..4 {
                let mut witness = [0x12, 0x34, 0x56, 0x78].map(scriptnum).to_vec();
                witness[index] = scriptnum(value);
                let result = execute_tapscript(leaf.clone(), witness, TapscriptProfile::Consensus);
                assert!(
                    matches!(result.outcome, TapscriptOutcome::Executed(ref info) if info.success),
                    "rejected canonical limb {value} at {index}: {result:?}"
                );
            }
        }
    }

    #[test]
    fn test_u32_equality_boundaries_and_raw_encoding() {
        for position in 0..4 {
            let mut left = vec![vec![1u8]; 4];
            let mut right = vec![vec![1u8]; 4];
            right[position] = vec![2];
            let witness = left.drain(..).chain(right).collect::<Vec<_>>();
            let result =
                execute_script_with_inputs_strict(script! { { u32_equal() } OP_NOT }, witness);
            assert!(
                result.success,
                "limb mismatch was not detected at {position}: {result}"
            );
        }

        let noncanonical = vec![vec![1, 0]; 8];
        let equal = execute_script_with_inputs_strict(
            script! { { u32_equal() } OP_VERIFY OP_TRUE },
            noncanonical.clone(),
        );
        assert!(
            equal.success,
            "identical raw limbs did not compare equal: {equal}"
        );

        let mut alias_mismatch = vec![vec![1]; 8];
        alias_mismatch[4] = vec![1, 0];
        let unequal =
            execute_script_with_inputs_strict(script! { { u32_equal() } OP_NOT }, alias_mismatch);
        assert!(
            unequal.success,
            "raw aliases compared numerically: {unequal}"
        );

        let equal_result = execute_script_with_inputs_strict(
            script! {
                77 OP_TOALTSTACK
                { u32_equal() }
                OP_VERIFY
                OP_FROMALTSTACK 77 OP_EQUAL
            },
            vec![vec![1u8]; 8],
        );
        assert!(
            equal_result.success,
            "equal stack preservation failed: {equal_result}"
        );

        let equalverify_result = execute_script_with_inputs_strict(
            script! {
                77 OP_TOALTSTACK
                { u32_equalverify() }
                OP_FROMALTSTACK 77 OP_EQUAL
            },
            vec![vec![1u8]; 8],
        );
        assert!(
            equalverify_result.success,
            "equalverify stack preservation failed: {equalverify_result}"
        );
    }

    #[test]
    fn equality_rejects_short_words_with_an_execution_error() {
        for equality in [u32_equal(), u32_equalverify()] {
            let result =
                execute_script_with_inputs_strict(script! { { equality } }, vec![vec![1u8]; 7]);
            assert!(result.error.is_some(), "accepted a short word: {result}");
        }
    }

    #[test]
    fn canonical_uncompress_accepts_signed_boundaries() {
        for value in [0, 127, 128, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            accepts_canonical(value);
        }
    }

    #[test]
    fn compress_emits_signed_scriptnum_encodings() {
        for (value, expected) in [
            (0, vec![]),
            (1, vec![0x01]),
            (0x7f, vec![0x7f]),
            (0x80, vec![0x80, 0x00]),
            (0xff, vec![0xff, 0x00]),
            (0x100, vec![0x00, 0x01]),
            (0x7fff_ffff, vec![0xff, 0xff, 0xff, 0x7f]),
            (0x8000_0000, vec![0x00, 0x00, 0x00, 0x80, 0x80]),
            (u32::MAX, vec![0x81]),
        ] {
            let result = execute_script(script! {
                { u32_push(value) }
                { u32_compress() }
            });
            assert!(
                result.error.is_none(),
                "compression failed for {value:#x}: {result}"
            );
            assert_eq!(
                result.final_stack.get(0),
                expected,
                "wrong encoding for {value:#x}"
            );
        }
    }

    #[test]
    fn uncompress_treats_any_five_byte_input_as_the_signed_boundary() {
        for raw in [
            scriptnum(-2_147_483_648),
            scriptnum(2_147_483_648),
            vec![1, 2, 3, 4, 5],
        ] {
            let result = execute_script_with_inputs_strict(
                script! {
                    { u32_uncompress() }
                    { u32_push(0x8000_0000) }
                    { u32_equalverify() }
                    OP_TRUE
                },
                vec![raw],
            );
            assert!(result.success, "unexpected five-byte behavior: {result}");
        }
    }

    #[test]
    fn uncompress_rejects_scriptnums_wider_than_five_bytes() {
        let result = execute_script_with_inputs_strict(
            script! {
                { u32_uncompress() }
                { u32_drop() }
                OP_TRUE
            },
            vec![vec![0, 0, 0, 0, 0, 0]],
        );
        assert_eq!(
            result.error,
            Some(bitcoin_scriptexec::ExecError::ScriptIntNumericOverflow)
        );
    }

    #[test]
    fn canonical_uncompress_rejects_raw_aliases_and_out_of_domain_words() {
        rejects_noncanonical(vec![0x01, 0x00]);
        rejects_noncanonical(vec![0x80]);
        rejects_noncanonical(vec![0x01, 0x00, 0x00, 0x00, 0x80]);
        rejects_noncanonical(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x80]);
    }

    #[test]
    fn canonical_nonnegative_uncompress_accepts_boundaries_and_rejects_negative() {
        for value in [0, 1, 127, 128, 255, 256, 0xffff, 0x1234_5678, 0x7fff_ffff] {
            let script = script! {
                { u32_uncompress_canonical_nonnegative() }
                { u32_push(value) }
                { u32_equalverify() }
                OP_TRUE
            };
            let result = execute_raw_script_with_inputs_strict(
                script.compile_with_policy().to_bytes(),
                vec![scriptnum(i64::from(value))],
            );
            assert!(result.success, "failed to decode {value:#x}: {result}");
        }

        for raw in [scriptnum(-128), vec![1, 0]] {
            let result = execute_raw_script_with_inputs_strict(
                script! { { u32_uncompress_canonical_nonnegative() } }
                    .compile_with_policy()
                    .to_bytes(),
                vec![raw],
            );
            assert!(!result.success, "accepted malformed nonnegative input");
        }
    }

    #[test]
    fn canonical_byte_boundary_rejects_aliases_and_out_of_range_values() {
        for value in 0..=255 {
            let mut bytes = [0u8; 8];
            let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value));
            let encoded = bytes[..length].to_vec();
            let result = crate::support::execution::execute_script_with_inputs(
                script! {
                    5 OP_TOALTSTACK
                    { verify_canonical_byte() }
                    { value } OP_EQUALVERIFY
                    OP_FROMALTSTACK 5 OP_EQUALVERIFY
                    99 OP_EQUAL
                },
                vec![vec![99], encoded],
            );
            assert!(result.success, "rejected canonical byte {value}: {result}");
        }

        for encoded in [
            vec![1, 0],          // redundant positive sign byte
            vec![0x80],          // negative zero
            vec![0, 1],          // canonical 256, outside the byte range
            vec![0xff],          // negative value
            vec![0, 0, 0, 0, 0], // oversized zero
        ] {
            let result = crate::support::execution::execute_script_with_inputs(
                script! { { verify_canonical_byte() } },
                vec![encoded],
            );
            assert!(!result.success, "accepted malformed byte: {result}");
        }
    }

    #[test]
    fn canonical_compress_accepts_signed_u32_boundaries() {
        for value in [0, 1, 127, 128, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            let result = execute_raw_script_with_inputs_strict(
                script! {
                    { u32_compress_canonical() }
                    { i64::from(value as i32) } OP_EQUAL
                }
                .compile_with_policy()
                .to_bytes(),
                vec![
                    scriptnum(i64::from((value >> 24) as u8)),
                    scriptnum(i64::from((value >> 16) as u8)),
                    scriptnum(i64::from((value >> 8) as u8)),
                    scriptnum(i64::from(value as u8)),
                ],
            );
            assert!(result.success, "failed to compress {value:#x}: {result}");
        }
    }

    #[test]
    fn canonical_compress_rejects_malformed_limbs() {
        let script = script! {
            { u32_compress_canonical() }
            OP_DROP OP_TRUE
        };

        let valid_control = execute_script_with_inputs_strict(script.clone(), vec![vec![1]; 4]);
        assert!(
            valid_control.success,
            "valid cleanup control failed: {valid_control}"
        );
        assert_eq!(
            valid_control.error, None,
            "valid control errored: {valid_control}"
        );

        // A deliberately unchecked compressor accepts this out-of-range
        // ScriptNum limb. The shared exact-error assertion below must reject it.
        let bypass_control = execute_script_with_inputs_strict(
            script! {
                { u32_compress() }
                OP_DROP OP_TRUE
            },
            vec![vec![1], vec![1], vec![1], vec![0, 1]],
        );
        assert!(
            bypass_control.success,
            "unchecked bypass control did not pass: {bypass_control}"
        );
        assert_eq!(
            bypass_control.error, None,
            "unchecked bypass errored: {bypass_control}"
        );
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_malformed_limb_error(
                    &bypass_control,
                    bitcoin_scriptexec::ExecError::Verify,
                    "unchecked mutant",
                )
            }))
            .is_err(),
            "shared malformed-limb assertion accepted the unchecked mutant"
        );

        for position in 0..4 {
            for replacement in [vec![1, 0], vec![0, 1], vec![0x80], vec![0xff]] {
                let mut witness = vec![vec![1]; 4];
                let expected_error = match replacement.as_slice() {
                    [1, 0] | [0x80] => bitcoin_scriptexec::ExecError::MinimalData,
                    [0, 1] | [0xff] => bitcoin_scriptexec::ExecError::Verify,
                    _ => unreachable!("unexpected malformed-limb fixture"),
                };
                witness[position] = replacement;
                let scenario = format!("encoding {position}");
                let result = execute_script_with_inputs_strict(script.clone(), witness);
                assert_malformed_limb_error(&result, expected_error, &scenario);
            }
        }
    }

    #[test]
    fn canonical_compress_preserves_surrounding_stacks() {
        let result = execute_script_with_inputs_strict(
            script! {
                99 OP_TOALTSTACK
                { u32_compress_canonical() }
                OP_DROP
                77 OP_EQUALVERIFY
                OP_FROMALTSTACK 99 OP_EQUALVERIFY
                OP_TRUE
            },
            vec![vec![77], vec![1], vec![2], vec![3], vec![4]],
        );
        assert!(result.success, "{result}");
    }

    #[test]
    fn reverse_byte_batch_preserves_order_state_and_raw_items() {
        let result = execute_script(script! {
            99 OP_TOALTSTACK
            0x44 0x33 0x22 0x11
            { u8_reverse_toaltstack(4) }
            OP_FROMALTSTACK 0x11 OP_EQUALVERIFY
            OP_FROMALTSTACK 0x22 OP_EQUALVERIFY
            OP_FROMALTSTACK 0x33 OP_EQUALVERIFY
            OP_FROMALTSTACK 0x44 OP_EQUALVERIFY
            OP_FROMALTSTACK 99 OP_EQUAL
        });
        assert!(result.success, "{result}");

        let raw_items = execute_script_with_inputs_strict(
            script! {
            { u8_reverse_toaltstack(2) }
            OP_FROMALTSTACK OP_SIZE 2 OP_EQUALVERIFY OP_DROP
            OP_FROMALTSTACK OP_SIZE 1 OP_EQUALVERIFY OP_DROP
            OP_TRUE
            },
            vec![vec![0x80], vec![0x01, 0x00]],
        );
        assert!(raw_items.success, "{raw_items}");

        let empty = execute_script(script! {
            42
            { u8_reverse_toaltstack(0) }
            42 OP_EQUAL
        });
        assert!(empty.success, "{empty}");

        let underflow = execute_script(script! {
            0x11
            { u8_reverse_toaltstack(2) }
        });
        assert_eq!(
            underflow.error,
            Some(bitcoin_scriptexec::ExecError::InvalidStackOperation)
        );
    }
    fn compressed_scriptnum(value: u32) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value as i32));
        bytes[..length].to_vec()
    }

    #[test]
    fn test_u32_compressed_equal_boundaries() {
        for &(a, b) in &[
            (0, 0),
            (0, 1),
            (0x7fff_ffff, 0x7fff_ffff),
            (0x8000_0000, 0x8000_0000),
            (u32::MAX, u32::MAX),
            (u32::MAX, 0),
        ] {
            let result = execute_script_with_inputs_strict(
                script! {
                    { u32_compressed_equal() }
                    { (a == b) as u32 }
                    OP_EQUAL
                },
                vec![compressed_scriptnum(b), compressed_scriptnum(a)],
            );
            assert!(
                result.success,
                "compressed equality failed for {a:08x} == {b:08x}: {result}"
            );
        }
    }

    #[test]
    fn test_u32_compressed_equal_rejects_noncanonical_inputs() {
        for inputs in [
            vec![vec![1, 0], compressed_scriptnum(1)],
            vec![vec![0, 0, 0, 0x80], compressed_scriptnum(0)],
            vec![vec![1, 0, 0, 0, 0], compressed_scriptnum(0)],
        ] {
            let result =
                execute_script_with_inputs_strict(script! { { u32_compressed_equal() } }, inputs);
            assert!(
                result.error.is_some(),
                "accepted malformed compressed input: {result}"
            );
        }
    }
    #[test]
    fn test_u32_conditional_select() {
        for (condition, expected) in [
            (0, 0x1122_3344),
            (1, 0xaabb_ccdd),
            (2, 0xaabb_ccdd),
            (-1, 0xaabb_ccdd),
        ] {
            let script = script! {
                { u32_push(0x1122_3344) }
                { u32_push(0xaabb_ccdd) }
                { condition }
                { u32_conditional_select() }
                { u32_push(expected) }
                { u32_equal() }
            };
            run(script);
        }
    }
    #[test]
    fn test_u32_conditional_negate() {
        let words = [0, 1, 0xff, 0x100, 0x7fff_ffff, 0x8000_0000, u32::MAX];
        for word in words {
            for condition in [0i64, 1, 2, -1] {
                let expected = if condition == 0 {
                    word
                } else {
                    word.wrapping_neg()
                };
                let script = script! {
                    { u32_push(word) }
                    { condition }
                    { u32_conditional_negate() }
                    { u32_push(expected) }
                    { u32_equal() }
                };
                run(script);
            }
        }
    }
    #[test]
    fn test_u32_iszero() {
        let boundaries = [0, 1, 0xff, 0x100, 0x8000_0000, u32::MAX];
        for &value in &boundaries {
            check_u32_iszero(value);
        }

        for index in 0..256u32 {
            let value = index.wrapping_mul(0x9e37_79b9).wrapping_add(0x243f_6a88);
            check_u32_iszero(value);
        }
    }

    #[test]
    fn test_u32_leading_zero_bytes() {
        for (value, expected) in [
            (0, 4),
            (1, 3),
            (0x0000_0100, 2),
            (0x0001_0000, 1),
            (0x0100_0000, 0),
            (u32::MAX, 0),
        ] {
            let script = script! {
                { u32_push(value) }
                { u32_leading_zero_bytes() }
                { expected } OP_EQUAL
            };
            let result = execute_script(script.clone());
            assert!(
                result.success,
                "value {value:#x}: {result:?}\n{}",
                script.compile_with_policy().to_asm_string()
            );
        }
    }

    #[test]
    fn test_u32_leading_zero_bytes_rejects_non_byte_limbs() {
        for limbs in [
            [-1, 0, 0, 0],
            [0, 256, 0, 0],
            [0, 0, -1, 0],
            [0, 0, 0, 256],
            [1, 0, 0, 256],
        ] {
            let result = execute_script(script! {
                { limbs[0] }
                { limbs[1] }
                { limbs[2] }
                { limbs[3] }
                { u32_leading_zero_bytes() }
                OP_TRUE
            });
            assert!(
                !result.success,
                "accepted invalid limbs {limbs:?}: {result}"
            );
        }
    }

    #[test]
    fn test_u32_leading_zero_bytes_rejects_noncanonical_witness_limbs() {
        for index in 0..4 {
            let mut witness = vec![vec![0]; 4];
            witness[index] = vec![1, 0];
            let result = execute_script_with_inputs_strict(
                script! {
                    { u32_leading_zero_bytes() }
                    OP_DROP
                    OP_TRUE
                },
                witness,
            );
            assert!(
                !result.success,
                "accepted noncanonical limb {index}: {result}"
            );
        }
    }
    #[test]
    fn test_u32_trailing_zero_bytes() {
        for (value, expected) in [
            (0, 4),
            (0x0100_0000, 3),
            (0x0001_0000, 2),
            (0x0000_0100, 1),
            (1, 0),
            (u32::MAX, 0),
        ] {
            let script = script! {
                { u32_push(value) }
                { u32_trailing_zero_bytes() }
                { expected } OP_EQUAL
            };
            let result = execute_script(script.clone());
            assert!(
                result.success,
                "value {value:#x}: {result:?}\n{}",
                script.compile_with_policy().to_asm_string()
            );
        }
    }

    #[test]
    fn test_u32_trailing_zero_bytes_rejects_invalid_limbs() {
        for limbs in [
            [-1, 0, 0, 0],
            [0, 256, 0, 0],
            [0, 0, -1, 0],
            [0, 0, 0, 256],
            [256, 0, 0, 1],
        ] {
            let result = execute_script(script! {
                { limbs[0] }
                { limbs[1] }
                { limbs[2] }
                { limbs[3] }
                { u32_trailing_zero_bytes() }
                OP_TRUE
            });
            assert!(
                !result.success,
                "accepted invalid limbs {limbs:?}: {result}"
            );
        }
    }

    #[test]
    fn test_u32_trailing_zero_bytes_rejects_noncanonical_witness_limbs() {
        for index in 0..4 {
            let mut witness = vec![vec![0]; 4];
            witness[index] = vec![1, 0];
            let result = execute_raw_script_with_inputs_strict(
                script! {
                    { u32_trailing_zero_bytes() }
                    OP_DROP
                    OP_TRUE
                }
                .compile_with_policy()
                .to_bytes(),
                witness,
            );
            assert!(
                !result.success,
                "accepted noncanonical limb {index}: {result}"
            );
        }
    }
    #[test]
    fn test_u32_extract_byte() {
        let value = 0x1122_3344;
        for (byte_index, expected) in [0x11, 0x22, 0x33, 0x44].into_iter().enumerate() {
            run(script! {
                { u32_push(value) }
                { u32_extract_byte(byte_index) }
                { expected } OP_EQUAL
            });
        }
    }

    #[test]
    fn test_u32_extract_byte_rejects_invalid_limbs() {
        for limbs in [[-1, 0, 0, 0], [0, 256, 0, 0], [0, 0, -1, 0], [0, 0, 0, 256]] {
            let result = execute_raw_script_with_inputs_strict(
                script! {
                    { u32_extract_byte(0) }
                    OP_DROP
                    OP_TRUE
                }
                .compile_with_policy()
                .to_bytes(),
                limbs
                    .into_iter()
                    .map(|limb| {
                        let mut bytes = [0u8; 8];
                        let length = bitcoin::script::write_scriptint(&mut bytes, limb);
                        bytes[..length].to_vec()
                    })
                    .collect(),
            );
            assert!(
                !result.success,
                "accepted invalid limbs {limbs:?}: {result}"
            );
        }
    }

    #[test]
    fn test_u32_iszero_does_not_treat_invalid_nonzero_limbs_as_zero() {
        for invalid_limb in [-1, 256, 65_536] {
            let script = script! {
                0
                0
                0
                { invalid_limb }
                { u32_iszero() }
                OP_0
                OP_EQUAL
            };
            run(script);
        }
    }

    fn check_u32_iszero(value: u32) {
        let script = script! {
            { u32_push(value) }
            { u32_iszero() }
            { (value == 0) as u32 }
            OP_EQUAL
        };
        run(script);
    }
    #[test]
    fn test_u32_pick_preserves_words() {
        let words = [0x0102_0304, 0xa0b0_c0d0, 0x1122_3344];
        let script = script! {
            { u32_push(words[0]) }
            { u32_push(words[1]) }
            { u32_push(words[2]) }
            { u32_pick(2) }
            { u32_push(words[0]) } { u32_equal() } OP_VERIFY
            { u32_push(words[2]) } { u32_equal() } OP_VERIFY
            { u32_push(words[1]) } { u32_equal() } OP_VERIFY
            { u32_push(words[0]) } { u32_equal() } OP_VERIFY
            OP_1
        };
        run(script);
    }
}
