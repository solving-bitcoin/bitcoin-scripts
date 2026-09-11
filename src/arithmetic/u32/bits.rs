//! Conversion from a byte-oriented u32 word to a little-endian bit stack.

use super::rotate::u8_extract_1bit;
use crate::support::script::{script, Script};

/// Converts one byte-oriented u32 word to 32 little-endian bit items.
///
/// The input is four numeric byte items with the least-significant byte on
/// top. The output has bit zero of that byte on top, followed by its higher
/// bits and then the next byte's bits. Each input byte is checked to be in
/// `0..=255`; callers that require byte-unique witness encodings must add a
/// canonical ScriptNum check separately.
pub fn u32_to_le_bits() -> Script {
    script! {
        // Park the four input bytes so the most-significant byte is processed
        // first while each later byte's bits are left above it.
        for _ in 0..4 {
            OP_TOALTSTACK
        }

        for _ in 0..4 {
            OP_FROMALTSTACK
            OP_DUP
            OP_0
            256
            OP_WITHIN
            OP_VERIFY

            // The extracted bit remains below the shifting byte. This leaves
            // bits in MSB-to-LSB stack order, so the final LSB is on top.
            for _ in 0..8 {
                { u8_extract_1bit() }
                OP_SWAP
            }
            OP_DROP
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::execute_script;

    fn verify_word(bytes: [u8; 4]) {
        let result = execute_script(script! {
            for byte in bytes {
                { byte }
            }
            { u32_to_le_bits() }
            for byte in bytes.iter().rev() {
                for bit in 0..8 {
                    { (byte >> bit) & 1 }
                    OP_EQUALVERIFY
                }
            }
            OP_TRUE
        });
        assert!(result.success, "bit conversion failed: {result}");
    }

    #[test]
    fn converts_boundary_and_pattern_words() {
        verify_word([0, 0, 0, 0]);
        verify_word([0xff, 0xff, 0xff, 0xff]);
        verify_word([0x80, 0x01, 0xaa, 0x55]);
        for value in 0..=255 {
            verify_word([value, !value, 0x3c, 0xc3]);
        }
    }

    #[test]
    fn rejects_non_byte_values() {
        for invalid in [-1, 256] {
            let result = execute_script(script! {
                { invalid }
                0
                0
                0
                { u32_to_le_bits() }
            });
            assert!(!result.success, "accepted invalid byte {invalid}");
        }
    }
}
