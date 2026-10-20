//! Checked reductions of a byte-oriented u32 word modulo 2^8 - 1 and 2^16 - 1.
//!
//! Since 256 = 1 modulo 255 and 65,536 = 1 modulo 65,535, the residue is the
//! sum of the byte (respectively 16-bit lane) limbs reduced by a ladder of
//! conditional subtractions. Contrast `residue::u32_mod65537`, where
//! 65,536 = -1 and a difference replaces the sum.

use super::stack::verify_canonical_byte;
use crate::support::{script::*, script_ops::OP_256MUL};

fn ladder(modulus: i64, top: u32) -> Script {
    script! {
        for level in (0..=top).rev() {
            OP_DUP { modulus << level } OP_GREATERTHANOREQUAL
            OP_IF { modulus << level } OP_SUB OP_ENDIF
        }
    }
}

/// Consume four canonical ScriptNum bytes, most significant first, and return
/// the integer modulo 255 in `0..=254`. Byte sum is at most `4 * 255`, so a
/// three-step ladder (`1020`, `510`, `255`) finishes the reduction.
pub fn u32_mod255() -> Script {
    script! {
        { verify_canonical_byte() }
        for _ in 0..3 {
            OP_SWAP { verify_canonical_byte() } OP_ADD
        }
        { ladder(255, 2) }
    }
}

fn join_two_bytes() -> Script {
    script! {
        { verify_canonical_byte() } OP_TOALTSTACK
        { verify_canonical_byte() } { OP_256MUL() }
        OP_FROMALTSTACK OP_ADD
    }
}

/// Consume four canonical ScriptNum bytes, most significant first, and return
/// the integer modulo 65,535 in `0..=65534`. The two 16-bit lanes sum to at
/// most `2 * 65535`, so a two-step ladder (`131070`, `65535`) finishes.
pub fn u32_mod65535() -> Script {
    script! {
        { join_two_bytes() } OP_TOALTSTACK
        { join_two_bytes() }
        OP_FROMALTSTACK OP_ADD
        { ladder(65535, 1) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};

    fn num(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let len = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..len].to_vec()
    }

    fn compile(fragment: Script) -> Vec<u8> {
        script! { { fragment } OP_EQUAL }
            .compile_with_policy()
            .to_bytes()
    }

    fn run(compiled: &[u8], word: u32, residue: u32) -> bool {
        let mut witness = vec![num(i64::from(residue))];
        witness.extend(word.to_be_bytes().iter().map(|&b| num(i64::from(b))));
        let result = execute_raw_script_with_inputs_strict(compiled.to_vec(), witness);
        assert!(result.error.is_none(), "word {word:08x}: {result}");
        result.success
    }

    #[test]
    fn mod255_matches_unsigned_remainder_on_boundary_byte_combinations() {
        let compiled = compile(u32_mod255());
        let edges = [0u32, 1, 2, 127, 128, 253, 254, 255];
        for &a in &edges {
            for &b in &edges {
                for &c in &edges {
                    for &d in &edges {
                        let word = (a << 24) | (b << 16) | (c << 8) | d;
                        assert!(run(&compiled, word, word % 255), "word {word:08x}");
                        assert!(!run(&compiled, word, (word % 255 + 1) % 255), "{word:08x}");
                    }
                }
            }
        }
    }

    #[test]
    fn mod65535_matches_unsigned_remainder_on_lane_boundaries() {
        let compiled = compile(u32_mod65535());
        let edges = [0u32, 1, 255, 256, 32_767, 32_768, 65_534, 65_535];
        for &hi in &edges {
            for &lo in &edges {
                let word = (hi << 16) | lo;
                assert!(run(&compiled, word, word % 65_535), "word {word:08x}");
                assert!(
                    !run(&compiled, word, (word % 65_535 + 1) % 65_535),
                    "{word:08x}"
                );
            }
        }
        // The largest word has both lanes saturated and reduces to zero.
        assert!(run(&compiled, u32::MAX, 0));
    }

    #[test]
    fn deterministic_words_match_unsigned_remainder() {
        let (c255, c65535) = (compile(u32_mod255()), compile(u32_mod65535()));
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..300 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let word = (state >> 16) as u32;
            assert!(run(&c255, word, word % 255), "mod255 {word:08x}");
            assert!(run(&c65535, word, word % 65_535), "mod65535 {word:08x}");
        }
    }

    #[test]
    fn rejects_noncanonical_and_out_of_range_bytes_at_every_position() {
        for (name, fragment) in [("mod255", u32_mod255()), ("mod65535", u32_mod65535())] {
            let compiled = script! { { fragment } OP_DROP OP_TRUE }
                .compile_with_policy()
                .to_bytes();
            for bad in [num(256), num(-1), vec![1u8, 0], vec![0x80], num(1 << 20)] {
                for position in 0..4 {
                    let mut witness: Vec<Vec<u8>> = vec![vec![9u8]; 4];
                    witness[position] = bad.clone();
                    let result = execute_raw_script_with_inputs_strict(compiled.clone(), witness);
                    assert!(
                        result.error.is_some(),
                        "{name} accepted bad byte {bad:?} at {position}"
                    );
                }
            }
        }
    }

    #[test]
    fn preserves_surrounding_state() {
        for (name, fragment, modulus) in [
            ("mod255", u32_mod255(), 255u32),
            ("mod65535", u32_mod65535(), 65_535),
        ] {
            let word = 0x1234_5678u32;
            let result = execute_script(script! {
                77 OP_TOALTSTACK
                99
                0x12 0x34 0x56 0x78
                { fragment }
                { i64::from(word % modulus) } OP_EQUALVERIFY
                99 OP_EQUALVERIFY
                OP_FROMALTSTACK 77 OP_EQUALVERIFY
                OP_TRUE
            });
            assert!(result.success, "{name}: {result}");
        }
    }
}
