//! Checked bitwise XNOR of a byte-oriented u32 word and an embedded mask.

use super::{
    stack::{u32_drop, u32_fromaltstack, u32_push, u32_toaltstack, verify_canonical_byte},
    xor::{u32_xor, u8_drop_xor_table, u8_push_xor_table},
};
use crate::support::script::{script, Script};

/// XNORs the top canonical u32 word with an embedded public mask.
///
/// The input is four most-significant-byte-first numeric limbs. Each limb is
/// checked for both the byte range and minimal ScriptNum encoding. The shared
/// Boolean table is generated and removed within the fragment.
pub fn u32_xnor_constant(value: u32) -> Script {
    script! {
        { u32_toaltstack() }
        { u8_push_xor_table() }
        { u32_fromaltstack() }
        { u32_push(value) }
        { u32_toaltstack() }
        for _ in 0..4 {
            { verify_canonical_byte() }
        }
        { u32_fromaltstack() }
        { u32_xor(0, 1, 3) }
        { u32_toaltstack() }
        { u32_drop() }
        { u8_drop_xor_table() }
        { u32_fromaltstack() }
        for _ in 0..3 {
            255 OP_SWAP OP_SUB
            OP_TOALTSTACK
        }
        255 OP_SWAP OP_SUB
        OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::u32::stack::{u32_equal, u32_equalverify, u32_push};
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
    fn masks_boundaries_and_patterns() {
        for (word, mask) in [
            (0, 0),
            (0, u32::MAX),
            (u32::MAX, 0),
            (u32::MAX, u32::MAX),
            (0x0123_4567, 0x89ab_cdef),
            (0x8000_0000, 0x7fff_ffff),
        ] {
            let result = execute_script(script! {
                { u32_push(word) }
                { u32_xnor_constant(mask) }
                { u32_push(!(word ^ mask)) }
                { u32_equal() }
                OP_VERIFY
                OP_TRUE
            });
            assert!(
                result.success,
                "constant XNOR failed: {word:08x}~^{mask:08x}: {result}"
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
                u32_xnor_constant(0x89ab_cdef)
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
        let mask = 0x5566_7788;
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            { u32_push(word) }
            { u32_xnor_constant(mask) }
            { u32_push(!(word ^ mask)) }
            { u32_equalverify() }
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "constant XNOR did not preserve stack state: {result}"
        );
    }
}
