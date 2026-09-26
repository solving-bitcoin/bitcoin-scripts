use super::stack::verify_canonical_byte;
use crate::support::script::*;

/// Logical left shift of a four-byte u32 word by eight bits.
///
/// The top byte is the least-significant byte in the module's stack layout.
/// The most-significant byte is dropped, zero is inserted at the least-
/// significant end, and unrelated main- and alt-stack items are preserved.
pub fn u32_lshift8() -> Script {
    script! {
        for _ in 0..4 {
            OP_TOALTSTACK
        }
        OP_FROMALTSTACK OP_DROP
        for _ in 0..3 {
            OP_FROMALTSTACK
        }
        OP_0
    }
}

/// Checked logical left shift of a four-byte u32 word by eight bits.
pub fn u32_lshift8_checked() -> Script {
    script! {
        for _ in 0..4 {
            { verify_canonical_byte() }
            OP_TOALTSTACK
        }
        for _ in 0..4 {
            OP_FROMALTSTACK
        }
        { u32_lshift8() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::test_helpers::{run_with_witness, word_witness};
    use crate::support::execution::{
        execute_script_with_inputs, execute_script_with_inputs_strict,
    };

    #[test]
    fn checked_shift_accepts_boundaries() {
        let script = script! {
            { u32_lshift8_checked() }
            { crate::arithmetic::u32::stack::u32_equal() }
        }
        .compile_with_policy()
        .to_bytes();
        for value in [0, 1, 0x0102_0304, 0x8000_0000, u32::MAX] {
            run_with_witness(&script, word_witness(value << 8).chain(word_witness(value)));
        }
    }

    #[test]
    fn checked_shift_rejects_malformed_bytes() {
        let script = script! {
            { u32_lshift8_checked() }
            OP_2DROP OP_2DROP
            OP_TRUE
        };
        for position in 0..4 {
            for replacement in [vec![1, 0], vec![0, 1], vec![0x80]] {
                let mut witness = vec![vec![1]; 4];
                witness[position] = replacement;
                let result = execute_script_with_inputs(script.clone(), witness);
                assert!(
                    !result.success,
                    "accepted malformed byte at {position}: {result}"
                );
            }
        }
    }

    #[test]
    fn checked_shift_preserves_surrounding_stacks() {
        let result = execute_script_with_inputs_strict(
            script! {
                99 OP_TOALTSTACK
                { u32_lshift8_checked() }
                OP_2DROP OP_2DROP
                77 OP_EQUALVERIFY
                OP_FROMALTSTACK 99 OP_EQUALVERIFY
                OP_TRUE
            },
            vec![vec![77], vec![1], vec![2], vec![3], vec![4]],
        );
        assert!(result.success, "stack preservation failed: {result}");
    }
}
