//! Checked projection from a u32's byte limbs to a zero-byte mask.

use super::stack::verify_canonical_byte;
use crate::support::script::*;

/// Number of byte limbs in a u32 word.
pub const U32_ZERO_BYTE_MASK_LIMBS: u32 = 4;

/// Consume a canonical four-byte u32 and return its zero-byte mask.
///
/// Before: `preserved | byte[0] | byte[1] | byte[2] | byte[3]`, with the
/// least-significant byte on top. After: `preserved | mask`, where bit `i` is
/// set iff `byte[i] == 0`. The result is a numeric ScriptNum in `0..=15`.
pub fn u32_to_zero_byte_mask() -> Script {
    script! {
        OP_0
        for _ in 0..U32_ZERO_BYTE_MASK_LIMBS {
            OP_DUP OP_ADD
            OP_SWAP
            { verify_canonical_byte() }
            OP_0 OP_NUMEQUAL
            OP_ADD
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};

    #[test]
    fn projects_zero_bytes_in_word_order_and_preserves_stacks() {
        let result = execute_script(script! {
            7 OP_TOALTSTACK
            11
            0 1 255 0
            { u32_to_zero_byte_mask() }
            9 OP_EQUALVERIFY
            11 OP_EQUALVERIFY
            OP_FROMALTSTACK 7 OP_EQUAL
        });
        assert!(result.success, "zero-byte mask failed: {result}");
    }

    #[test]
    fn covers_byte_boundary_vectors() {
        for (bytes, expected) in [
            ([0, 0, 0, 0], 15),
            ([255, 255, 255, 255], 0),
            ([128, 255, 0, 1], 4),
            ([0, 1, 255, 0], 9),
        ] {
            let result = execute_script(script! {
                { bytes[0] }
                { bytes[1] }
                { bytes[2] }
                { bytes[3] }
                { u32_to_zero_byte_mask() }
                { expected } OP_EQUAL
            });
            assert!(result.success, "wrong mask for {bytes:?}: {result}");
        }
    }

    #[test]
    fn rejects_invalid_numeric_and_raw_byte_inputs() {
        for invalid in [-1, 256, 65_536] {
            let result = execute_script(script! {
                0 0 0
                { invalid }
                { u32_to_zero_byte_mask() }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid byte {invalid}");
        }

        let script = u32_to_zero_byte_mask().compile_with_policy().to_bytes();
        for invalid in [vec![0x80], vec![0x01, 0x00], vec![0x00, 0x01]] {
            let mut inputs = vec![Vec::new(); 3];
            inputs.push(invalid.clone());
            let result = execute_raw_script_with_inputs_strict(script.clone(), inputs);
            assert!(
                !result.success,
                "accepted malformed byte witness {invalid:?}"
            );
        }
    }
}
