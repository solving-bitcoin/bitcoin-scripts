//! Checked per-byte less-than mask for two u32 byte words.

use super::stack::verify_canonical_byte;
use super::zip::u32_zip;
use crate::support::script::{script, Script};

fn compare_byte_pair() -> Script {
    script! {
        OP_SWAP
        { verify_canonical_byte() }
        OP_SWAP
        { verify_canonical_byte() }
        OP_GREATERTHAN
    }
}

/// Compare corresponding MSB-first bytes and return a four-bit less-than mask.
///
/// The lower word is compared with the upper word in each lane. Bit 3 of the
/// result describes byte 0 (the most-significant byte), and bit 0 describes
/// byte 3. Every input byte is checked for range and canonical Script-number
/// encoding before comparison.
pub fn u32_byte_lessthan_mask() -> Script {
    script! {
        { u32_zip(0, 1) }
        for _ in 0..4 {
            { compare_byte_pair() }
            OP_TOALTSTACK
        }

        for _ in 0..4 {
            OP_FROMALTSTACK
        }

        // The comparison results are e0 | e1 | e2 | e3, with e3 on top.
        // Move them aside so a small Horner-style pack can read e0 first.
        OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK
        0
        OP_FROMALTSTACK
        OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
        OP_ADD
        OP_FROMALTSTACK
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_ADD
        OP_FROMALTSTACK
        OP_DUP OP_ADD
        OP_ADD
        OP_FROMALTSTACK
        OP_ADD
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::test_helpers::{run_with_witness, word_witness};
    use crate::support::{
        execution::execute_raw_script_with_inputs_strict, script::ScriptCompilation,
    };
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn expected_mask(a: u32, b: u32) -> u32 {
        a.to_be_bytes()
            .into_iter()
            .zip(b.to_be_bytes())
            .enumerate()
            .map(|(index, (left, right))| u32::from(left < right) << (3 - index))
            .sum()
    }

    fn check(a: u32, b: u32) {
        let script = script! {
            { u32_byte_lessthan_mask() }
            { expected_mask(a, b) }
            OP_EQUAL
        }
        .compile_with_policy()
        .to_bytes();
        run_with_witness(&script, word_witness(a).chain(word_witness(b)));
    }

    #[test]
    fn matches_boundary_and_random_words() {
        for (a, b) in [
            (0x0000_0000, 0x0000_0000),
            (0xffff_ffff, 0xffff_ffff),
            (0x0000_0000, 0xffff_ffff),
            (0x00ff_1234, 0x00aa_1235),
            (0x1122_3344, 0x1122_aa44),
        ] {
            check(a, b);
        }

        let mut rng = ChaCha20Rng::seed_from_u64(0x7533_3265_6c74_6d73);
        for _ in 0..256 {
            check(rng.gen(), rng.gen());
        }
    }

    #[test]
    fn preserves_unrelated_main_and_altstack_items() {
        let result = crate::support::execution::execute_script(script! {
            7 OP_TOALTSTACK
            11
            { crate::arithmetic::u32::stack::u32_push(0x1122_3344) }
            { crate::arithmetic::u32::stack::u32_push(0x1122_aa44) }
            { u32_byte_lessthan_mask() }
            2 OP_EQUALVERIFY
            11 OP_EQUALVERIFY
            OP_FROMALTSTACK
            7 OP_EQUAL
        });
        assert!(result.success, "stack preservation failed: {result}");
    }

    #[test]
    fn rejects_numeric_out_of_range_bytes_in_every_position() {
        let script = script! {
            { u32_byte_lessthan_mask() }
            OP_DROP
            OP_TRUE
        }
        .compile_with_policy()
        .to_bytes();

        for word in 0..2 {
            for limb in 0..4 {
                let mut witness = word_witness(0).chain(word_witness(0)).collect::<Vec<_>>();
                witness[word * 4 + limb] = 256;
                let result = execute_raw_script_with_inputs_strict(
                    script.clone(),
                    witness
                        .into_iter()
                        .map(|value| {
                            let mut bytes = [0u8; 8];
                            let len = bitcoin::script::write_scriptint(&mut bytes, value);
                            bytes[..len].to_vec()
                        })
                        .collect(),
                );
                assert!(!result.success, "accepted invalid byte at {word}:{limb}");
            }
        }
    }

    #[test]
    fn rejects_noncanonical_zero_witness_bytes_in_every_position() {
        let script = script! {
            { u32_byte_lessthan_mask() }
            OP_DROP
            OP_TRUE
        }
        .compile_with_policy()
        .to_bytes();
        let zero = vec![0];

        for index in 0..8 {
            let mut witness = vec![Vec::new(); 8];
            witness[index] = zero.clone();
            let result = execute_raw_script_with_inputs_strict(script.clone(), witness);
            assert!(!result.success, "accepted noncanonical byte at {index}");
        }
    }
}
