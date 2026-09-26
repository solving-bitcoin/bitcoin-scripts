//! Conversion from a byte-oriented u32 word to a little-endian bit stack.

use super::rotate::u8_extract_1bit;
use super::stack::verify_canonical_byte;
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

/// Transposes one checked byte-oriented u32 word into eight 4-bit planes.
///
/// Plane zero contains the most-significant bit of each input byte, with the
/// most-significant input byte as the plane's high bit. Plane seven is on top.
/// All four byte limbs must use canonical ScriptNum encodings.
pub fn u32_to_bit_planes() -> Script {
    script! {
        for _ in 0..4 {
            OP_TOALTSTACK
        }

        for _ in 0..4 {
            OP_FROMALTSTACK
            { verify_canonical_byte() }
        }

        { u32_to_le_bits() }

        for bit in 0..8 {
            // The source bit stack is unchanged while copies are parked on
            // the altstack. Depths select one bit from each byte lane.
            { bit } OP_PICK OP_TOALTSTACK
            { bit + 8 } OP_PICK OP_TOALTSTACK
            { bit + 16 } OP_PICK OP_TOALTSTACK
            { bit + 24 } OP_PICK OP_TOALTSTACK

            0
            OP_FROMALTSTACK
            OP_SWAP OP_DUP OP_ADD OP_SWAP OP_ADD
            OP_FROMALTSTACK
            OP_SWAP OP_DUP OP_ADD OP_SWAP OP_ADD
            OP_FROMALTSTACK
            OP_SWAP OP_DUP OP_ADD OP_SWAP OP_ADD
            OP_FROMALTSTACK
            OP_SWAP OP_DUP OP_ADD OP_SWAP OP_ADD
            OP_TOALTSTACK
        }

        // Remove the 32 source bits, then expose plane zero on top.
        for _ in 0..32 {
            OP_DROP
        }
        for _ in 0..8 {
            OP_FROMALTSTACK
        }
    }
}
/// Converts a canonical byte-oriented u32 word to 32 little-endian bit items.
pub fn u32_to_le_bits_canonical() -> Script {
    script! {
        for _ in 0..4 {
            { verify_canonical_byte() }
            OP_TOALTSTACK
        }
        for _ in 0..4 {
            OP_FROMALTSTACK
        }
        { u32_to_le_bits() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{execute_script, execute_script_with_inputs_strict};

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

    fn verify_planes(bytes: [u8; 4]) {
        let result = execute_script(script! {
            for byte in bytes {
                { byte }
            }
            { u32_to_bit_planes() }
            for bit in (0..8).rev() {
                { bytes.iter().fold(0u32, |plane, byte| (plane << 1) | u32::from((byte >> (7 - bit)) & 1)) }
                OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(
            result.success,
            "bit-plane conversion failed for {bytes:02x?}: {result}"
        );
    }

    #[test]
    fn converts_bit_planes() {
        verify_planes([0, 0, 0, 0]);
        verify_planes([0xff, 0xff, 0xff, 0xff]);
        verify_planes([0x80, 0x01, 0xaa, 0x55]);
        verify_planes([0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn rejects_out_of_range_bytes() {
        for invalid in [-1, 256] {
            for index in 0..4 {
                let mut limbs = [0; 4];
                limbs[index] = invalid;
                let result = execute_script(script! {
                    { limbs[0] }
                    { limbs[1] }
                    { limbs[2] }
                    { limbs[3] }
                    { u32_to_bit_planes() }
                });
                assert!(
                    !result.success,
                    "accepted invalid byte {invalid} at index {index}: {result}"
                );
            }
        }
    }

    #[test]
    fn rejects_noncanonical_witness_bytes() {
        for index in 0..4 {
            let mut witness = vec![vec![0]; 4];
            witness[index] = vec![1, 0];
            let result = execute_script_with_inputs_strict(
                script! {
                    { u32_to_bit_planes() }
                    OP_2DROP
                    OP_2DROP
                    OP_2DROP
                    OP_2DROP
                    OP_TRUE
                },
                witness,
            );
            assert!(
                !result.success,
                "accepted noncanonical byte {index}: {result}"
            );
        }
    }
    #[test]
    fn canonical_bits_match_reference_vectors() {
        for bytes in [
            [0, 0, 0, 0],
            [0xff, 0xff, 0xff, 0xff],
            [0x80, 0x01, 0xaa, 0x55],
        ] {
            let result = execute_script(script! {
                for byte in bytes {
                    { byte }
                }
                { u32_to_le_bits_canonical() }
                for byte in bytes.iter().rev() {
                    for bit in 0..8 {
                        { (byte >> bit) & 1 }
                        OP_EQUALVERIFY
                    }
                }
                OP_TRUE
            });
            assert!(result.success, "canonical bit conversion failed: {result}");
        }
    }

    #[test]
    fn canonical_bits_reject_malformed_witness_limbs() {
        let script = script! {
            { u32_to_le_bits_canonical() }
        };
        for position in 0..4 {
            for replacement in [vec![1, 0], vec![0, 1], vec![0x80], vec![0xff]] {
                let mut witness = vec![vec![1]; 4];
                witness[position] = replacement;
                let result =
                    crate::support::execution::execute_script_with_inputs(script.clone(), witness);
                assert!(
                    !result.success,
                    "accepted malformed limb at {position}: {result}"
                );
            }
        }
    }

    #[test]
    fn canonical_bits_preserve_surrounding_stacks() {
        let result = crate::support::execution::execute_script_with_inputs_strict(
            script! {
                99 OP_TOALTSTACK
                { u32_to_le_bits_canonical() }
                for _ in 0..32 { OP_DROP }
                77 OP_EQUALVERIFY
                OP_FROMALTSTACK 99 OP_EQUALVERIFY
                OP_TRUE
            },
            vec![vec![77], vec![1], vec![2], vec![3], vec![4]],
        );
        assert!(result.success, "{result}");
    }
}
