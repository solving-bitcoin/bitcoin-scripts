//! Total-domain logical right shifts for the compressed one-item u32 wire.

use crate::{
    arithmetic::u32::{and::u32_and, rotate::u32_rrot, stack::*},
    support::script::*,
};

fn certify_compressed_word() -> Script {
    script! {
        OP_SIZE 5 OP_NUMEQUAL
        OP_IF
            OP_DUP { -2_147_483_648i64 } OP_EQUALVERIFY
        OP_ELSE
            OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
        OP_ENDIF
    }
}

/// Logically shift four byte-valued u32 limbs right by `shift` bits.
///
/// Before and after: `byte[3] | byte[2] | byte[1] | byte[0]`, with the
/// least-significant byte on top. The shared byte-logic table is installed
/// internally and the result preserves no input copy.
pub fn u32_bytes_rshift(shift: usize) -> Script {
    assert!((1..=31).contains(&shift));
    let mask = u32::MAX >> shift;
    script! {
        { u32_rrot(shift) }
        { u32_toaltstack() }
        { crate::arithmetic::u32::xor::u8_push_xor_table() }
        { u32_fromaltstack() }
        { u32_push(mask) }
        { u32_and(0, 1, 3) }
        { u32_toaltstack() }
        { u32_drop() }
        { crate::arithmetic::u32::xor::u8_drop_xor_table() }
        { u32_fromaltstack() }
    }
}

/// Logically shift a compressed u32 word right by `shift` bits.
///
/// The input and output are the one-item compressed representation produced by
/// [`u32_compress`]. The `0x8000_0000` word is handled through the canonical
/// five-byte negative ScriptNum representation rather than numeric sign
/// semantics. The shared byte-logic table is installed internally.
pub fn u32_compressed_rshift(shift: usize) -> Script {
    assert!((1..=31).contains(&shift));
    script! {
        { certify_compressed_word() }
        { u32_uncompress() }
        { u32_bytes_rshift(shift) }
        { u32_compress() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};

    #[test]
    fn compressed_shift_covers_semantic_boundaries() {
        let values = [0, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff];
        for value in values {
            for shift in 1..=31 {
                let result = execute_script(script! {
                    { u32_push(value) }
                    { u32_compress() }
                    { u32_compressed_rshift(shift) }
                    { u32_push(value >> shift) }
                    { u32_compress() }
                    OP_EQUAL
                });
                assert!(result.success, "value={value:#x}, shift={shift}: {result}");
            }
        }
        for value in [0x0102_0304, 0xa5c3_19e7] {
            for shift in [3, 11, 19, 27] {
                let result = execute_script(script! {
                    { u32_push(value) }
                    { u32_compress() }
                    { u32_compressed_rshift(shift) }
                    { u32_push(value >> shift) }
                    { u32_compress() }
                    OP_EQUAL
                });
                assert!(result.success, "value={value:#x}, shift={shift}: {result}");
            }
        }
    }

    #[test]
    fn rejects_noncanonical_and_wrong_width_inputs() {
        let script = script! {
            { u32_compressed_rshift(1) }
            OP_TRUE
        }
        .compile_with_policy()
        .to_bytes();
        for raw in [
            vec![1, 0],
            vec![0, 0, 0, 0x80],
            vec![1, 0, 0, 0, 0],
            vec![1, 0, 0, 0, 0, 0],
        ] {
            let result = execute_raw_script_with_inputs_strict(script.clone(), vec![raw]);
            assert!(
                !result.success,
                "accepted malformed compressed word: {result}"
            );
        }
    }
}
