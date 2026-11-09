//! Hint-checked expansion of a compressed u32 ScriptNum into four byte items.
//!
//! The decoders in [`super::stack`] recover the bytes with a 31-step bit ladder.
//! Compression is a cheap bijection between u32 words and signed ScriptNums, so a
//! prover can supply the four bytes and the script can re-compress them and
//! compare the result with the compressed value.

use super::stack::{u32_compress, u32_dup, verify_canonical_byte};
use crate::support::script::*;

/// Expand one compressed u32 into its four bytes, checking witness-supplied bytes.
///
/// Before (witness, bottom to top): `b0 b1 b2 b3 x`, bytes most significant first,
/// `x` the compressed ScriptNum (`value as i32`, including the five-byte
/// `-2^31`). After: `b0 b1 b2 b3`. The script aborts unless every byte is a
/// canonical ScriptNum in `0..=255` and the minimal encoding of the bytes' compression
/// equals `x` byte for byte, which also makes `x` canonical. Compression is
/// injective on four-byte words, so the bytes are determined by `x`.
pub fn u32_uncompress_hinted_canonical() -> Script {
    script! {
        OP_TOALTSTACK
        for _ in 0..4 {
            { verify_canonical_byte() }
            OP_TOALTSTACK
        }
        for _ in 0..4 { OP_FROMALTSTACK }
        { u32_dup() }
        { u32_compress() }
        OP_FROMALTSTACK
        OP_EQUALVERIFY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::u32::stack::{u32_equalverify, u32_push, u32_uncompress_canonical};
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};
    use bitcoin_scriptexec::{ExecError, Options};

    fn num(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let len = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..len].to_vec()
    }

    fn compressed(word: u32) -> Vec<u8> {
        num(i64::from(word as i32))
    }

    fn hints(word: u32) -> Vec<Vec<u8>> {
        word.to_be_bytes()
            .iter()
            .map(|&b| num(i64::from(b)))
            .collect()
    }

    /// Complete leaf: expand, then compare the four returned bytes with `word`.
    fn leaf(word: u32) -> Vec<u8> {
        script! {
            { u32_uncompress_hinted_canonical() }
            { u32_push(word) }
            { u32_equalverify() }
            OP_TRUE
        }
        .compile_with_policy()
        .to_bytes()
    }

    fn accepts(word: u32) -> bool {
        let mut witness = hints(word);
        witness.push(compressed(word));
        let result = execute_raw_script_with_inputs_strict(leaf(word), witness);
        assert!(result.error.is_none(), "{word:#010x}: {result}");
        result.success
    }

    #[test]
    fn expands_boundary_and_deterministic_words() {
        let mut words = vec![
            0u32,
            1,
            0x7f,
            0x80,
            0xff,
            0x100,
            0xffff,
            0x1_0000,
            0x00ff_ffff,
            0x0100_0000,
            0x7fff_fffe,
            0x7fff_ffff,
            0x8000_0000,
            0x8000_0001,
            0xffff_ff80,
            0xffff_fffe,
            0xffff_ffff,
        ];
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..300 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            words.push((state >> 16) as u32);
        }
        for word in words {
            assert!(accepts(word), "{word:#010x}");
        }
    }

    #[test]
    fn agrees_with_the_existing_bit_ladder_decoder() {
        for word in [
            0u32,
            5,
            0x1234_5678,
            0x7fff_ffff,
            0x8000_0000,
            0xdead_beef,
            0xffff_ffff,
        ] {
            let result = execute_script(script! {
                { compressed_script(word) }
                { u32_uncompress_canonical() }
                { u32_push(word) }
                { u32_equalverify() }
                OP_TRUE
            });
            assert!(result.success, "existing decoder {word:#010x}: {result}");
            assert!(accepts(word), "hinted {word:#010x}");
        }
    }

    fn compressed_script(word: u32) -> Script {
        script! { { i64::from(word as i32) } }
    }

    #[test]
    fn rejects_every_forged_hint_byte() {
        let word = 0x89ab_cdefu32;
        for position in 0..4 {
            for delta in [1i64, -1, 128, -128, 255] {
                let mut witness = hints(word);
                let forged = i64::from(word.to_be_bytes()[position]) + delta;
                witness[position] = num(forged);
                witness.push(compressed(word));
                let result = execute_raw_script_with_inputs_strict(leaf(word), witness);
                assert!(
                    result.error.is_some() || !result.success,
                    "position {position} delta {delta}: {result}"
                );
            }
        }
    }

    #[test]
    fn rejects_noncanonical_and_out_of_range_bytes_and_values() {
        let word = 0x0000_0102u32;
        // Out-of-range byte hints, including carry-compensated pairs that still re-compress to x.
        for (position, bad) in [(3usize, 258i64), (3, -254), (2, 256), (2, -1), (0, 256)] {
            let mut witness = hints(word);
            witness[position] = num(bad);
            witness.push(compressed(word));
            let result = execute_raw_script_with_inputs_strict(leaf(word), witness);
            assert!(result.error.is_some(), "byte {bad} at {position}: {result}");
        }
        // Non-minimal encodings of a byte hint or of the compressed value.
        let mut witness = hints(word);
        witness[3] = vec![2, 0];
        witness.push(compressed(word));
        assert!(execute_raw_script_with_inputs_strict(leaf(word), witness)
            .error
            .is_some());
        let mut witness = hints(word);
        witness.push(vec![0x02, 0x01, 0x00]);
        assert!(execute_raw_script_with_inputs_strict(leaf(word), witness)
            .error
            .is_some());
        let mut witness = hints(0);
        witness.push(vec![0x80]); // negative zero for compressed 0
        assert!(execute_raw_script_with_inputs_strict(leaf(0), witness)
            .error
            .is_some());
        // A compressed value that does not match the bytes.
        let mut witness = hints(word);
        witness.push(compressed(word + 1));
        let result = execute_raw_script_with_inputs_strict(leaf(word), witness);
        assert_eq!(result.error, Some(ExecError::EqualVerify));
        // Permissive profile: numeric aliases still fail the bytewise comparison.
        let options = Options {
            require_minimal: false,
            enforce_stack_limit: true,
            ..Default::default()
        };
        let mut witness = hints(word);
        witness.push(vec![0x02, 0x01, 0x00]);
        let result = crate::support::execution::execute_script_buf_with_options(
            bitcoin::ScriptBuf::from_bytes(leaf(word)),
            witness,
            options,
        )
        .expect("execution");
        assert!(result.error.is_some() || !result.success, "{result}");
    }

    #[test]
    fn preserves_surrounding_state() {
        let word = 0xcafe_babeu32;
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            for hint in hints(word) { { hint } }
            { i64::from(word as i32) }
            { u32_uncompress_hinted_canonical() }
            { u32_push(word) }
            { u32_equalverify() }
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "{result}");
    }
}
