//! Checked addition of a byte-oriented u32 word and an embedded constant.

use super::{
    add::u32_add_drop,
    stack::{u32_push, verify_canonical_byte},
};
use crate::support::script::{script, Script};

/// Adds an embedded constant to the top canonical u32 word modulo `2^32`.
///
/// The input is four most-significant-byte-first numeric limbs. Each limb is
/// checked for both the byte range and minimal ScriptNum encoding. The
/// constant is public script data, so it contributes no witness items.
pub fn u32_add_constant(value: u32) -> Script {
    script! {
        for _ in 0..4 {
            { verify_canonical_byte() }
        }
        { u32_push(value) }
        { u32_add_drop(0, 1) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::u32::stack::{u32_equal, u32_equalverify};
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};
    use crate::support::script::ScriptCompilation;

    fn scriptnum(value: u32) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value as i32));
        bytes[..length].to_vec()
    }

    fn byte_word(value: u32) -> [Vec<u8>; 4] {
        [
            scriptnum(value >> 24),
            scriptnum((value >> 16) & 0xff),
            scriptnum((value >> 8) & 0xff),
            scriptnum(value & 0xff),
        ]
    }

    #[test]
    fn adds_boundaries_and_wraps() {
        for (word, constant) in [
            (0, 0),
            (0, u32::MAX),
            (1, u32::MAX),
            (0x7fff_ffff, 1),
            (0x8000_0000, 0x8000_0000),
            (u32::MAX, 1),
            (0x0123_4567, 0x89ab_cdef),
        ] {
            let result = execute_script(script! {
                { u32_push(word) }
                { u32_add_constant(constant) }
                { u32_push(word.wrapping_add(constant)) }
                { u32_equal() }
                OP_VERIFY
                OP_TRUE
            });
            assert!(
                result.success,
                "constant add failed: {word:08x}+{constant:08x}: {result}"
            );
        }
    }

    #[test]
    fn rejects_malformed_and_nonminimal_limbs() {
        for (index, raw) in [
            (0, vec![0x80]),
            (1, vec![0, 1]),
            (2, vec![1, 0]),
            (3, vec![0xff, 0]),
        ] {
            let mut witness = byte_word(0x1234_5678).to_vec();
            witness[index] = raw;
            let result = execute_raw_script_with_inputs_strict(
                u32_add_constant(0x89ab_cdef)
                    .compile_with_policy()
                    .to_bytes(),
                witness,
            );
            assert!(!result.success, "accepted malformed limb {index}: {result}");
        }
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let word = 0x1020_3040;
        let constant = 0x5566_7788;
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            { u32_push(word) }
            { u32_add_constant(constant) }
            { u32_push(word.wrapping_add(constant)) }
            { u32_equalverify() }
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "constant add did not preserve stack state: {result}"
        );
    }
}
