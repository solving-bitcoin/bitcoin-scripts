//! Ternary hash-path commitments using fixed-length SHA-256/RIPEMD-160 codewords.
//!
//! The three codewords are `0 -> SS`, `1 -> SR`, and `2 -> RS`. The unused
//! `RR` codeword keeps every trit at exactly two hashes while leaving a
//! canonical three-valued selector.

use bitcoin::hashes::{ripemd160, sha256, Hash};

use crate::support::script::{script, Script};

use super::hash_path::MAX_INTEGER_BITS;

/// Compute a ternary hash-path commitment for least-significant-first trits.
pub fn ternary_hash_path_commitment(preimage: &[u8], trits: &[u8]) -> [u8; 20] {
    let mut state = preimage.to_vec();
    for &trit in trits {
        assert!(trit < 3, "ternary hash-path trits must be in 0..=2");
        state = match trit {
            0 => sha256::Hash::hash(&sha256::Hash::hash(&state).to_byte_array())
                .to_byte_array()
                .to_vec(),
            1 => ripemd160::Hash::hash(&sha256::Hash::hash(&state).to_byte_array())
                .to_byte_array()
                .to_vec(),
            2 => sha256::Hash::hash(&ripemd160::Hash::hash(&state).to_byte_array())
                .to_byte_array()
                .to_vec(),
            _ => unreachable!(),
        };
    }
    ripemd160::Hash::hash(&state).to_byte_array()
}

/// Compute a ternary commitment to a `bit_width`-bit integer.
pub fn ternary_hash_path_integer_commitment(
    preimage: &[u8],
    value: u32,
    bit_width: usize,
) -> [u8; 20] {
    let trits = integer_trits(value, bit_width);
    ternary_hash_path_commitment(preimage, &trits)
}

/// Build the canonical witness for [`verify_ternary_hash_path_to_integer`].
///
/// The witness order is most-significant trit first, then `preimage`; the
/// verifier's first `OP_SWAP` activates the least-significant trit.
pub fn ternary_hash_path_integer_witness(
    preimage: &[u8],
    value: u32,
    bit_width: usize,
) -> Vec<Vec<u8>> {
    let trits = integer_trits(value, bit_width);
    ternary_hash_path_witness(preimage, &trits)
}

/// Build a canonical witness for a generic ternary path.
pub fn ternary_hash_path_witness(preimage: &[u8], trits: &[u8]) -> Vec<Vec<u8>> {
    let mut witness = trits
        .iter()
        .rev()
        .map(|&trit| {
            assert!(trit < 3, "ternary hash-path trits must be in 0..=2");
            match trit {
                0 => vec![],
                1 | 2 => vec![trit],
                _ => unreachable!(),
            }
        })
        .collect::<Vec<_>>();
    witness.push(preimage.to_vec());
    witness
}

fn integer_trits(value: u32, bit_width: usize) -> Vec<u8> {
    assert_integer_width(bit_width);
    assert!(
        value < (1u32 << bit_width),
        "value does not fit in bit_width"
    );
    let mut value = u64::from(value);
    let mut trits = Vec::with_capacity(integer_trit_count(bit_width));
    for _ in 0..integer_trit_count(bit_width) {
        trits.push((value % 3) as u8);
        value /= 3;
    }
    assert_eq!(value, 0);
    trits
}

fn integer_trit_count(bit_width: usize) -> usize {
    let limit = 1u64 << bit_width;
    let mut capacity = 1u64;
    let mut count = 0;
    while capacity < limit {
        capacity *= 3;
        count += 1;
    }
    count
}

fn assert_integer_width(bit_width: usize) {
    assert!(
        (1..=MAX_INTEGER_BITS).contains(&bit_width),
        "bit_width must be in 1..={MAX_INTEGER_BITS}"
    );
}

fn certify_trit() -> Script {
    script! {
        OP_DUP
        OP_0
        OP_EQUAL
        OP_IF
            OP_SIZE
            OP_0
            OP_EQUALVERIFY
        OP_ELSE
            OP_DUP
            1
            OP_EQUAL
            OP_IF
            OP_ELSE
                OP_DUP
                2
                OP_EQUALVERIFY
            OP_ENDIF
        OP_ENDIF
    }
}

fn ternary_hash_path_script_inner(trit_count: usize, save_trits: bool) -> Script {
    assert!(trit_count > 0, "trit_count must be non-zero");
    script! {
        for _ in 0..trit_count {
            OP_SWAP
            { certify_trit() }

            if save_trits {
                OP_DUP
                OP_TOALTSTACK
            }

            OP_DUP
            2
            OP_LESSTHAN
            OP_IF
                OP_SWAP
                OP_SHA256
                OP_SWAP
                OP_IF
                    OP_RIPEMD160
                OP_ELSE
                    OP_SHA256
                OP_ENDIF
            OP_ELSE
                2
                OP_EQUALVERIFY
                OP_RIPEMD160
                OP_SHA256
            OP_ENDIF
        }
        OP_RIPEMD160
    }
}

/// Compute a ternary hash path from a preimage and least-significant-first trits.
pub fn ternary_hash_path_script(trit_count: usize) -> Script {
    ternary_hash_path_script_inner(trit_count, false)
}

/// Verify a generic ternary hash path and leave true.
pub fn verify_ternary_hash_path(trit_count: usize, commitment: [u8; 20]) -> Script {
    script! {
        { ternary_hash_path_script(trit_count) }
        { commitment.to_vec() }
        OP_EQUALVERIFY
        OP_1
    }
}

/// Verify a ternary path and reconstruct its committed integer.
pub fn verify_ternary_hash_path_to_integer(bit_width: usize, commitment: [u8; 20]) -> Script {
    assert_integer_width(bit_width);
    let trit_count = integer_trit_count(bit_width);
    script! {
        { ternary_hash_path_script_inner(trit_count, true) }
        { commitment.to_vec() }
        OP_EQUALVERIFY

        0
        for _ in 0..trit_count {
            OP_FROMALTSTACK
            OP_SWAP
            OP_DUP
            OP_DUP
            OP_ADD
            OP_ADD
            OP_ADD
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::execute_script_with_inputs_strict;

    #[test]
    fn verifies_all_ternary_codewords() {
        let preimage = b"ternary nonce";
        for trit in 0..3 {
            let trits = [trit];
            let commitment = ternary_hash_path_commitment(preimage, &trits);
            let result = execute_script_with_inputs_strict(
                verify_ternary_hash_path(1, commitment),
                ternary_hash_path_witness(preimage, &trits),
            );
            assert!(result.success, "trit={trit}: {result}");
        }
    }

    #[test]
    fn verifies_integer_boundaries_and_values() {
        for (value, width) in [
            (0, 1),
            (1, 1),
            (2, 2),
            (4, 3),
            (0x55, 7),
            (0x1234_5678, 31),
            (u32::MAX >> 1, 31),
        ] {
            let preimage = [0x42; 32];
            let commitment = ternary_hash_path_integer_commitment(&preimage, value, width);
            let result = execute_script_with_inputs_strict(
                script! {
                    { verify_ternary_hash_path_to_integer(width, commitment) }
                    { value }
                    OP_EQUAL
                },
                ternary_hash_path_integer_witness(&preimage, value, width),
            );
            assert!(result.success, "value={value}, width={width}: {result}");
        }
    }

    #[test]
    fn rejects_wrong_openings_and_noncanonical_trits() {
        let preimage = [0x11; 32];
        let commitment = ternary_hash_path_integer_commitment(&preimage, 17, 6);
        let wrong_value = ternary_hash_path_integer_witness(&preimage, 18, 6);
        let result = execute_script_with_inputs_strict(
            script! { { verify_ternary_hash_path_to_integer(6, commitment) } OP_DROP OP_1 },
            wrong_value,
        );
        assert!(!result.success);

        let mut noncanonical = ternary_hash_path_integer_witness(&preimage, 17, 6);
        noncanonical[0] = vec![2, 0];
        let result = execute_script_with_inputs_strict(
            script! { { verify_ternary_hash_path_to_integer(6, commitment) } OP_DROP OP_1 },
            noncanonical,
        );
        assert!(!result.success);
    }

    #[test]
    fn rejects_out_of_range_generic_trits() {
        let preimage = b"bad trit";
        let commitment = ternary_hash_path_commitment(preimage, &[0, 1, 2]);
        let witness = vec![vec![3], vec![], vec![], preimage.to_vec()];
        let result = execute_script_with_inputs_strict(
            script! { { verify_ternary_hash_path(3, commitment) } OP_DROP OP_1 },
            witness,
        );
        assert!(!result.success);
    }
}
