//! Checked zero predicate for a four-byte u32 word.

use crate::support::script::*;

/// Consume the top u32 word and return whether it is zero.
///
/// The input is four byte-valued limbs, most significant byte first. Each
/// limb is checked in `0..=255` before its zero predicate is accumulated. The
/// result is one numeric Boolean ScriptNum.
pub fn u32_iszero() -> Script {
    script! {
        for _ in 0..4 {
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP 256 OP_LESSTHAN OP_VERIFY
            OP_NOT OP_TOALTSTACK
        }
        OP_FROMALTSTACK
        OP_FROMALTSTACK OP_BOOLAND
        OP_FROMALTSTACK OP_BOOLAND
        OP_FROMALTSTACK OP_BOOLAND
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::u32::stack::u32_push,
        support::{execution::execute_script, script::script},
    };

    #[test]
    fn recognizes_zero_and_nonzero_words() {
        for (word, expected) in [
            (0, true),
            (1, false),
            (0x8000_0000, false),
            (u32::MAX, false),
        ] {
            let result = execute_script(script! {
                { u32_push(word) }
                { u32_iszero() }
                { expected as u32 } OP_EQUAL
            });
            assert!(result.success, "word={word:#010x}: {result}");
        }
    }

    #[test]
    fn rejects_non_byte_limbs() {
        for invalid in [-1, 256] {
            let result = execute_script(script! {
                0 0 0 { invalid }
                { u32_iszero() }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid byte {invalid}");
        }
    }
}
