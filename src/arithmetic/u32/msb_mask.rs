use super::rotate::u8_extract_1bit;
use super::stack::{u32_toaltstack, verify_canonical_byte};
use crate::support::script::*;

/// Consume a byte-oriented u32 and return one bit per byte's most-significant bit.
///
/// The result is a numeric mask: bit 3 corresponds to the most-significant
/// byte and bit 0 to the least-significant byte.
pub fn u32_msb_mask() -> Script {
    script! {
        { u32_toaltstack() }
        0
        for _ in 0..4 {
            OP_FROMALTSTACK
            { verify_canonical_byte() }
            { u8_extract_1bit() }
            OP_SWAP
            OP_DROP
            OP_SWAP
            OP_DUP
            OP_ADD
            OP_ADD
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{execute_script, execute_script_with_inputs_strict};
    use crate::support::script::script;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    fn expected(value: u32) -> i64 {
        i64::from(
            (value >> 28 & 0x8) | (value >> 21 & 0x4) | (value >> 14 & 0x2) | (value >> 7 & 0x1),
        )
    }

    fn word_witness(value: u32) -> Vec<Vec<u8>> {
        value
            .to_be_bytes()
            .into_iter()
            .map(|byte| {
                let mut encoded = [0u8; 8];
                let length = bitcoin::script::write_scriptint(&mut encoded, i64::from(byte));
                encoded[..length].to_vec()
            })
            .collect()
    }

    #[test]
    fn returns_packed_most_significant_byte_bits() {
        let boundaries = [0, 1, 0x7f, 0x80, 0xff, 0x8000_0000, 0xffff_ffff];
        let mut rng = StdRng::seed_from_u64(0x7533_3232_6d73_6269);

        for value in boundaries.into_iter().chain((0..256).map(|_| rng.gen())) {
            let result = execute_script_with_inputs_strict(
                script! {
                    { u32_msb_mask() }
                    { expected(value) }
                    OP_EQUAL
                },
                word_witness(value),
            );
            assert!(result.success, "mask failed for {value:08x}: {result}");
        }
    }

    #[test]
    fn preserves_unrelated_main_and_alt_stack_items() {
        let result = execute_script(script! {
            11 OP_TOALTSTACK
            22
            0x80 0 0xff 1
            { u32_msb_mask() }
            0xa
            OP_EQUALVERIFY
            22 OP_EQUALVERIFY
            OP_FROMALTSTACK
            11 OP_EQUAL
        });
        assert!(result.success, "stack preservation failed: {result}");
    }

    #[test]
    fn rejects_invalid_numeric_bytes_in_every_position() {
        for position in 0..4 {
            let mut values = [0i64; 4];
            values[position] = if position % 2 == 0 { -1 } else { 256 };
            let result = execute_script(script! {
                { values[0] }
                { values[1] }
                { values[2] }
                { values[3] }
                { u32_msb_mask() }
            });
            assert!(
                !result.success,
                "accepted invalid byte at position {position}"
            );
        }
    }

    #[test]
    fn rejects_noncanonical_zero_in_every_position() {
        for position in 0..4 {
            let mut witness = vec![vec![0u8]; 4];
            witness[position] = vec![0, 0];
            let result = execute_script_with_inputs_strict(u32_msb_mask(), witness);
            assert!(
                !result.success,
                "accepted noncanonical byte at position {position}"
            );
        }
    }
}
