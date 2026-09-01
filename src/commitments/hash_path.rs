//! Hash-path commitments to bit strings and 1–31-bit Script integers.

use bitcoin::hashes::{ripemd160, sha256, Hash};

use crate::script::{script, Script};

/// Largest bit width that can be reconstructed as a positive four-byte
/// Script integer.
pub const MAX_INTEGER_BITS: usize = 31;

/// Compute the hash-path commitment for `bits`, starting from `preimage`.
///
/// Bits are processed least-significant first. A false bit applies SHA-256 and
/// a true bit applies RIPEMD-160. A final RIPEMD-160 maps both branch output
/// sizes to the 20-byte commitment.
pub fn hash_path_commitment(preimage: &[u8], bits: &[bool]) -> [u8; 20] {
    let mut state = preimage.to_vec();
    for bit in bits {
        state = if *bit {
            ripemd160::Hash::hash(&state).to_byte_array().to_vec()
        } else {
            sha256::Hash::hash(&state).to_byte_array().to_vec()
        };
    }
    ripemd160::Hash::hash(&state).to_byte_array()
}

/// Compute a commitment to the low `bit_width` bits of `value`.
///
/// Panics unless `bit_width` is in `1..=31` and `value < 2^bit_width`.
pub fn hash_path_integer_commitment(preimage: &[u8], value: u32, bit_width: usize) -> [u8; 20] {
    let bits = integer_bits(value, bit_width);
    hash_path_commitment(preimage, &bits)
}

/// Build the canonical witness for [`verify_hash_path_to_integer`].
///
/// The returned vector is in witness serialization order: the most
/// significant bit is deepest, bit zero is immediately below `preimage`, and
/// `preimage` is the top item.
pub fn hash_path_integer_witness(preimage: &[u8], value: u32, bit_width: usize) -> Vec<Vec<u8>> {
    let bits = integer_bits(value, bit_width);
    let mut witness = bits
        .iter()
        .rev()
        .map(|bit| if *bit { vec![1] } else { vec![] })
        .collect::<Vec<_>>();
    witness.push(preimage.to_vec());
    witness
}

fn integer_bits(value: u32, bit_width: usize) -> Vec<bool> {
    assert_integer_width(bit_width);
    assert!(
        value < (1u32 << bit_width),
        "value does not fit in bit_width"
    );
    (0..bit_width)
        .map(|index| value & (1u32 << index) != 0)
        .collect()
}

fn assert_integer_width(bit_width: usize) {
    assert!(
        (1..=MAX_INTEGER_BITS).contains(&bit_width),
        "bit_width must be in 1..={MAX_INTEGER_BITS}"
    );
}

/// Compute a `bit_width`-step hash path from a preimage on top of the stack.
///
/// Stack before (top first): `preimage, bit0, ..., bitN-1`.
/// Stack after: `commitment`.
///
/// Each bit is required to use the unique Script encodings `[]` or `[1]`.
pub fn hash_path_script(bit_width: usize) -> Script {
    assert!(bit_width > 0, "bit_width must be non-zero");
    hash_path_script_inner(bit_width, false)
}

fn hash_path_script_inner(bit_width: usize, save_bits: bool) -> Script {
    script! {
        for _ in 0..bit_width {
            OP_SWAP

            // Enforce exactly [] or [1], including under legacy rules where
            // OP_IF itself accepts other truthy/falsy encodings.
            OP_DUP OP_SIZE OP_EQUALVERIFY

            if save_bits {
                OP_DUP OP_TOALTSTACK
            }

            OP_IF
                OP_RIPEMD160
            OP_ELSE
                OP_SHA256
            OP_ENDIF
        }
        OP_RIPEMD160
    }
}

/// Verify a generic hash path and consume the preimage and all input bits.
///
/// Leaves true on success. `bit_width` has no Script-integer restriction, but
/// the enclosing script's stack, opcode, and execution limits still apply.
pub fn verify_hash_path(bit_width: usize, commitment: [u8; 20]) -> Script {
    script! {
        { hash_path_script(bit_width) }
        { commitment.to_vec() }
        OP_EQUALVERIFY
        OP_1
    }
}

/// Verify a generic hash path and save its bits on the altstack.
///
/// Leaves true on the main stack. After verification, bit `N-1` is on top of
/// the altstack and bit zero is deepest.
pub fn verify_hash_path_to_altstack(bit_width: usize, commitment: [u8; 20]) -> Script {
    assert!(bit_width > 0, "bit_width must be non-zero");
    script! {
        { hash_path_script_inner(bit_width, true) }
        { commitment.to_vec() }
        OP_EQUALVERIFY
        OP_1
    }
}

/// Verify a hash-path commitment and return its committed integer.
///
/// Stack before (top first): `preimage, bit0, ..., bitN-1`.
/// Stack after: the non-negative Script integer represented by those bits.
/// `bit_width` must be in `1..=31`.
pub fn verify_hash_path_to_integer(bit_width: usize, commitment: [u8; 20]) -> Script {
    assert_integer_width(bit_width);
    script! {
        { hash_path_script_inner(bit_width, true) }
        { commitment.to_vec() }
        OP_EQUALVERIFY

        0
        for _ in 0..bit_width {
            // Bits leave the altstack from most to least significant.
            OP_FROMALTSTACK
            OP_SWAP OP_DUP OP_ADD OP_ADD
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{execute_script_with_inputs, script::script};

    #[test]
    fn verifies_and_returns_integers() {
        for (value, width) in [(0, 1), (1, 1), (0x55, 7), (0x1234_5678, 31)] {
            let preimage = [0x42; 32];
            let commitment = hash_path_integer_commitment(&preimage, value, width);
            let witness = hash_path_integer_witness(&preimage, value, width);
            let result = execute_script_with_inputs(
                script! {
                    { verify_hash_path_to_integer(width, commitment) }
                    { value }
                    OP_EQUAL
                },
                witness,
            );
            assert!(result.success, "value={value}, width={width}: {result}");
        }
    }

    #[test]
    fn wrong_opening_fails() {
        let width = 8;
        let preimage = [0x11; 32];
        let commitment = hash_path_integer_commitment(&preimage, 42, width);
        let witness = hash_path_integer_witness(&preimage, 43, width);
        let result = execute_script_with_inputs(
            script! { { verify_hash_path_to_integer(width, commitment) } OP_DROP OP_1 },
            witness,
        );
        assert!(!result.success);
    }

    #[test]
    fn wrong_preimage_fails() {
        let width = 8;
        let commitment = hash_path_integer_commitment(&[0x11; 32], 42, width);
        let witness = hash_path_integer_witness(&[0x12; 32], 42, width);
        let result = execute_script_with_inputs(
            script! { { verify_hash_path_to_integer(width, commitment) } OP_DROP OP_1 },
            witness,
        );
        assert!(!result.success);
    }

    #[test]
    fn non_canonical_bit_fails() {
        let width = 1;
        let preimage = [0x23; 32];
        let commitment = hash_path_integer_commitment(&preimage, 1, width);
        let witness = vec![vec![2], preimage.to_vec()];
        let result = execute_script_with_inputs(
            script! { { verify_hash_path_to_integer(width, commitment) } OP_DROP OP_1 },
            witness,
        );
        assert!(!result.success);
    }

    #[test]
    fn generic_verifier_consumes_bits() {
        let bits = [true, false, true, true];
        let preimage = b"nonce";
        let commitment = hash_path_commitment(preimage, &bits);
        let mut witness = bits
            .iter()
            .rev()
            .map(|bit| if *bit { vec![1] } else { vec![] })
            .collect::<Vec<_>>();
        witness.push(preimage.to_vec());

        let result = execute_script_with_inputs(verify_hash_path(bits.len(), commitment), witness);
        assert!(result.success, "{result}");
        assert_eq!(result.final_stack.len(), 1);
    }

    #[test]
    #[should_panic(expected = "bit_width must be in 1..=31")]
    fn integer_width_above_scriptnum_limit_panics() {
        let _ = hash_path_integer_commitment(b"nonce", 0, 32);
    }
}
