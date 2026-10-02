//! Comparison-only general bitwise remainder circuit; not a public API.
use bitcoin_lab::arithmetic::u32::bits::u32_to_le_bits_canonical;
use bitcoin_lab::support::script::{script, Script};

pub fn bitwise_horner() -> Script {
    script! {
        { u32_to_le_bits_canonical() }
        for _ in 0..32 { OP_TOALTSTACK }
        0
        for _ in 0..32 {
            OP_DUP OP_ADD OP_FROMALTSTACK OP_ADD
            OP_DUP 65537 OP_GREATERTHANOREQUAL
            OP_IF 65537 OP_SUB OP_ENDIF
        }
    }
}
