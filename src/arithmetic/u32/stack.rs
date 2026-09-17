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
/// layout. Inputs must already be numeric bytes in `0..=255`.
pub fn u32_not() -> Script {
    script! {
        for _ in 0..4 {
            { verify_canonical_byte() }
            { u32_not_step() }
        }
    }
}

pub(crate) fn u32_not_unchecked() -> Script {
    script! {
        for _ in 0..4 {
            { u32_not_step() }
        }
    }
}

fn u32_not_step() -> Script {
    script! {
        0xff
        4 OP_ROLL OP_SUB
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

/// Select one complete u32 word using Script truthiness.
///
/// Stack before (top first): `condition | when_true | when_false`.
/// Stack after: the selected word. The condition is consumed; a canonical
/// boolean is not required because selection follows `OP_IF` semantics.
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

/// Compresses the top u32 element into a single element
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

pub fn u32_uncompress() -> Script {
    script! {
        OP_SIZE OP_5 OP_EQUAL
        OP_TUCK OP_IF
            OP_DROP OP_0
        OP_ELSE
            OP_TUCK OP_GREATERTHAN
            OP_TUCK OP_IF 0x7FFFFFFF OP_ADD OP_1ADD OP_ENDIF
        OP_ENDIF
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
    use crate::support::execution::{execute_raw_script_with_inputs_strict, run};

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
        for invalid_index in 0..4 {
            let mut limbs = [1i64, 2, 3, 4];
            limbs[invalid_index] = if invalid_index % 2 == 0 { -1 } else { 256 };
            let result = crate::support::execution::execute_script(script! {
                for limb in limbs {
                    { limb }
                }
                { u32_not() }
            });
            assert!(
                !result.success,
                "accepted invalid limb {invalid_index}: {result}"
            );
        }

        for alias_index in 0..4 {
            let mut witness = vec![vec![1u8]; 4];
            witness[alias_index] = vec![1, 0];
            let result = execute_raw_script_with_inputs_strict(
                u32_not().compile_with_policy().to_bytes(),
                witness,
            );
            assert!(
                !result.success,
                "accepted non-minimal byte alias {alias_index}: {result}"
            );
        }
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
    fn canonical_uncompress_accepts_signed_boundaries() {
        for value in [0, 127, 128, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            accepts_canonical(value);
        }
    }

    #[test]
    fn canonical_uncompress_rejects_raw_aliases_and_out_of_domain_words() {
        rejects_noncanonical(vec![0x01, 0x00]);
        rejects_noncanonical(vec![0x80]);
        rejects_noncanonical(vec![0x01, 0x00, 0x00, 0x00, 0x80]);
        rejects_noncanonical(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x80]);
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
    use crate::support::execution::execute_script_with_inputs_strict;

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
}
