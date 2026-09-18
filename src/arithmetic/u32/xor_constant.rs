//! Checked XOR of a byte-oriented u32 word with a generation-time constant.

use super::{
    stack::{u32_drop, u32_fromaltstack, u32_push, u32_toaltstack, verify_canonical_byte},
    xor::{u32_xor, u8_drop_xor_table, u8_push_xor_table},
};
use crate::support::script::{script, Script};

/// XOR the top canonical u32 word with an embedded constant.
///
/// The word uses the normal most-significant-byte-first layout, with the
/// least-significant byte on top. The constant is embedded in the script, so
/// only the four input limbs are supplied by the witness.
pub fn u32_xor_constant(value: u32) -> Script {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};
    use crate::support::script::{script, ScriptCompilation};

    #[test]
    fn projects_boundary_and_pattern_words() {
        for (word, constant) in [
            (0, 0),
            (0, u32::MAX),
            (1, 0xff00_00ff),
            (0x0123_4567, 0x89ab_cdef),
            (u32::MAX, 0x8000_0000),
        ] {
            let result = execute_script(script! {
                { u32_push(word) }
                { u32_xor_constant(constant) }
                { u32_push(word ^ constant) }
                { super::super::stack::u32_equal() }
                OP_VERIFY
                OP_TRUE
            });
            assert!(result.success, "constant XOR failed: {result}");
        }
    }

    #[test]
    fn rejects_malformed_and_nonminimal_limbs() {
        for (index, raw) in [
            (0, vec![0x80]),
            (1, vec![0, 1]),
            (2, vec![1, 0]),
            (3, vec![0xff]),
        ] {
            let mut witness = vec![vec![1u8]; 4];
            witness[index] = raw;
            let result = execute_raw_script_with_inputs_strict(
                u32_xor_constant(0x1234_5678)
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
            { u32_xor_constant(constant) }
            { u32_push(word ^ constant) }
            { super::super::stack::u32_equalverify() }
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "stack-preserving constant XOR failed: {result}"
        );
    }
}
