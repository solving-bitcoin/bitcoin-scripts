//! Four-way hash-path commitments to base-4 digits and 1–31-bit integers.
//!
//! Each digit selects one fixed-length, two-stage hash codeword over SHA-256
//! (`S`) and RIPEMD-160 (`R`): `0 -> SS`, `1 -> SR`, `2 -> RS`, and
//! `3 -> RR`. Keeping every codeword the same length avoids the deterministic
//! path aliases introduced by directly mixing `OP_SHA256`, `OP_HASH256`,
//! `OP_RIPEMD160`, and `OP_HASH160`.

use bitcoin::hashes::{ripemd160, sha256, Hash};

use crate::support::script::{script, Script};

use super::hash_path::MAX_INTEGER_BITS;

/// Compute the four-way hash-path commitment for `digits`, starting from
/// `preimage`.
///
/// Digits are processed least-significant first and must be in `0..=3`. For
/// each digit, its high bit selects the first hash (`0 -> SHA-256`,
/// `1 -> RIPEMD-160`) and its low bit selects the second hash using the same
/// mapping. A final RIPEMD-160 produces the 20-byte commitment.
pub fn four_way_hash_path_commitment(preimage: &[u8], digits: &[u8]) -> [u8; 20] {
    let mut state = preimage.to_vec();
    for &digit in digits {
        assert!(digit < 4, "four-way hash-path digits must be in 0..=3");
        state = if digit < 2 {
            sha256::Hash::hash(&state).to_byte_array().to_vec()
        } else {
            ripemd160::Hash::hash(&state).to_byte_array().to_vec()
        };
        state = if digit & 1 == 0 {
            sha256::Hash::hash(&state).to_byte_array().to_vec()
        } else {
            ripemd160::Hash::hash(&state).to_byte_array().to_vec()
        };
    }
    ripemd160::Hash::hash(&state).to_byte_array()
}

/// Build the canonical witness for a generic four-way hash path.
///
/// The returned vector is in witness serialization order: the most
/// significant digit is deepest, digit zero is immediately below `preimage`,
/// and `preimage` is the top item. Digits use canonical Script-number
/// encodings: zero is empty and `1..=3` are one-byte items.
pub fn four_way_hash_path_witness(preimage: &[u8], digits: &[u8]) -> Vec<Vec<u8>> {
    let mut witness = digits
        .iter()
        .rev()
        .map(|&digit| {
            assert!(digit < 4, "four-way hash-path digits must be in 0..=3");
            if digit == 0 {
                vec![]
            } else {
                vec![digit]
            }
        })
        .collect::<Vec<_>>();
    witness.push(preimage.to_vec());
    witness
}

/// Compute a four-way commitment to the low `bit_width` bits of `value`.
///
/// Panics unless `bit_width` is in `1..=31` and `value < 2^bit_width`.
pub fn four_way_hash_path_integer_commitment(
    preimage: &[u8],
    value: u32,
    bit_width: usize,
) -> [u8; 20] {
    let digits = integer_digits(value, bit_width);
    four_way_hash_path_commitment(preimage, &digits)
}

/// Build the canonical witness for
/// [`verify_four_way_hash_path_to_integer`].
pub fn four_way_hash_path_integer_witness(
    preimage: &[u8],
    value: u32,
    bit_width: usize,
) -> Vec<Vec<u8>> {
    let digits = integer_digits(value, bit_width);
    four_way_hash_path_witness(preimage, &digits)
}

fn integer_digits(value: u32, bit_width: usize) -> Vec<u8> {
    assert_integer_width(bit_width);
    assert!(
        value < (1u32 << bit_width),
        "value does not fit in bit_width"
    );
    (0..bit_width.div_ceil(2))
        .map(|index| ((value >> (2 * index)) & 3) as u8)
        .collect()
}

fn assert_integer_width(bit_width: usize) {
    assert!(
        (1..=MAX_INTEGER_BITS).contains(&bit_width),
        "bit_width must be in 1..={MAX_INTEGER_BITS}"
    );
}

/// Compute a `digit_count`-step four-way hash path from a preimage on top of
/// the stack.
///
/// Stack before (top first): `preimage, digit0, ..., digitN-1`.
/// Stack after: `commitment`.
///
/// Each digit is required to use the canonical Script-number encoding of a
/// value in `0..=3`.
pub fn four_way_hash_path_script(digit_count: usize) -> Script {
    assert!(digit_count > 0, "digit_count must be non-zero");
    four_way_hash_path_script_inner(digit_count, false)
}

fn four_way_hash_path_script_inner(digit_count: usize, save_digits: bool) -> Script {
    assert!(digit_count > 0, "digit_count must be non-zero");
    script! {
        for _ in 0..digit_count {
            OP_SWAP

            // Enforce canonical Script-number encoding. For 0..=3, the
            // encoded length is exactly the truth value of the digit: zero is
            // empty and every non-zero digit is one byte.
            OP_DUP OP_SIZE OP_SWAP OP_0NOTEQUAL OP_EQUALVERIFY
            OP_DUP 0 4 OP_WITHIN OP_VERIFY

            if save_digits {
                OP_DUP OP_TOALTSTACK
            }

            // The high bit selects the first hash and the low bit the second:
            // 0 -> SS, 1 -> SR, 2 -> RS, 3 -> RR.
            OP_DUP 2 OP_LESSTHAN
            OP_IF
                OP_SWAP OP_SHA256 OP_SWAP
            OP_ELSE
                2 OP_SUB
                OP_SWAP OP_RIPEMD160 OP_SWAP
            OP_ENDIF
            OP_IF
                OP_RIPEMD160
            OP_ELSE
                OP_SHA256
            OP_ENDIF
        }
        OP_RIPEMD160
    }
}

/// Verify a generic four-way hash path and consume the preimage and all input
/// digits.
///
/// Leaves true on success. The enclosing script's stack, opcode, and execution
/// limits still apply.
pub fn verify_four_way_hash_path(digit_count: usize, commitment: [u8; 20]) -> Script {
    script! {
        { four_way_hash_path_script(digit_count) }
        { commitment.to_vec() }
        OP_EQUALVERIFY
        OP_1
    }
}

/// Verify a generic four-way hash path and save its digits on the altstack.
///
/// Leaves true on the main stack. After verification, digit `N-1` is on top
/// of the altstack and digit zero is deepest.
pub fn verify_four_way_hash_path_to_altstack(digit_count: usize, commitment: [u8; 20]) -> Script {
    script! {
        { four_way_hash_path_script_inner(digit_count, true) }
        { commitment.to_vec() }
        OP_EQUALVERIFY
        OP_1
    }
}

/// Verify a four-way hash-path commitment and return its committed integer.
///
/// Stack before (top first): `preimage, digit0, ..., digitN-1`.
/// Stack after: the non-negative Script integer represented by those base-4
/// digits. `bit_width` must be in `1..=31`; an odd width restricts the most
/// significant digit to `0..=1`.
pub fn verify_four_way_hash_path_to_integer(bit_width: usize, commitment: [u8; 20]) -> Script {
    assert_integer_width(bit_width);
    let digit_count = bit_width.div_ceil(2);
    let restrict_top_digit = bit_width % 2 == 1;

    script! {
        { four_way_hash_path_script_inner(digit_count, true) }
        { commitment.to_vec() }
        OP_EQUALVERIFY

        0
        for index in 0..digit_count {
            // Digits leave the altstack from most to least significant.
            OP_FROMALTSTACK
            if restrict_top_digit && index == 0 {
                OP_DUP 0 2 OP_WITHIN OP_VERIFY
            }
            // accumulator = accumulator * 4 + digit
            OP_SWAP OP_DUP OP_ADD OP_DUP OP_ADD OP_ADD
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{
        execution::{execute_script, execute_script_with_inputs},
        script::script,
    };

    #[test]
    fn verifies_all_four_hash_codewords() {
        let preimage = b"four-way nonce";
        for digit in 0..4 {
            let digits = [digit];
            let commitment = four_way_hash_path_commitment(preimage, &digits);
            let witness = four_way_hash_path_witness(preimage, &digits);
            let result =
                execute_script_with_inputs(verify_four_way_hash_path(1, commitment), witness);
            assert!(result.success, "digit={digit}: {result}");
        }
    }

    #[test]
    fn verifies_and_returns_integers() {
        for (value, width) in [
            (0, 1),
            (1, 1),
            (3, 2),
            (5, 3),
            (0x1555_5555, 30),
            (0x1234_5678, 31),
        ] {
            let preimage = [0x42; 32];
            let commitment = four_way_hash_path_integer_commitment(&preimage, value, width);
            let witness = four_way_hash_path_integer_witness(&preimage, value, width);
            let result = execute_script_with_inputs(
                script! {
                    { verify_four_way_hash_path_to_integer(width, commitment) }
                    { value }
                    OP_EQUAL
                },
                witness,
            );
            assert!(result.success, "value={value}, width={width}: {result}");
        }
    }

    #[test]
    fn representative_integer_passes_with_stack_limit_enabled() {
        let value = 0x1234_5678;
        let width = 31;
        let preimage = [0x42; 32];
        let commitment = four_way_hash_path_integer_commitment(&preimage, value, width);
        let witness = four_way_hash_path_integer_witness(&preimage, value, width);
        let result = execute_script(script! {
            for item in witness {
                { item }
            }
            { verify_four_way_hash_path_to_integer(width, commitment) }
            { value }
            OP_EQUAL
        });
        assert!(result.success, "{result}");
    }

    #[test]
    fn wrong_opening_fails() {
        let width = 8;
        let preimage = [0x11; 32];
        let commitment = four_way_hash_path_integer_commitment(&preimage, 42, width);
        let witness = four_way_hash_path_integer_witness(&preimage, 43, width);
        let result = execute_script_with_inputs(
            script! {
                { verify_four_way_hash_path_to_integer(width, commitment) }
                OP_DROP OP_1
            },
            witness,
        );
        assert!(!result.success);
    }

    #[test]
    fn wrong_preimage_fails() {
        let width = 8;
        let commitment = four_way_hash_path_integer_commitment(&[0x11; 32], 42, width);
        let witness = four_way_hash_path_integer_witness(&[0x12; 32], 42, width);
        let result = execute_script_with_inputs(
            script! {
                { verify_four_way_hash_path_to_integer(width, commitment) }
                OP_DROP OP_1
            },
            witness,
        );
        assert!(!result.success);
    }

    #[test]
    fn non_canonical_digit_fails() {
        let preimage = [0x23; 32];
        let commitment = four_way_hash_path_integer_commitment(&preimage, 1, 2);
        let witness = vec![vec![1, 0], preimage.to_vec()];
        let result = execute_script_with_inputs(
            script! {
                { verify_four_way_hash_path_to_integer(2, commitment) }
                OP_DROP OP_1
            },
            witness,
        );
        assert!(!result.success);
    }

    #[test]
    fn out_of_range_digit_fails() {
        let preimage = [0x24; 32];
        let commitment = four_way_hash_path_integer_commitment(&preimage, 0, 2);
        for encoded_digit in [vec![4], vec![0x81]] {
            let witness = vec![encoded_digit, preimage.to_vec()];
            let result = execute_script_with_inputs(
                script! {
                    { verify_four_way_hash_path_to_integer(2, commitment) }
                    OP_DROP OP_1
                },
                witness,
            );
            assert!(!result.success);
        }
    }

    #[test]
    fn odd_width_rejects_oversized_top_digit() {
        let preimage = [0x25; 32];
        let digits = [0, 2];
        let commitment = four_way_hash_path_commitment(&preimage, &digits);
        let witness = four_way_hash_path_witness(&preimage, &digits);
        let result = execute_script_with_inputs(
            script! {
                { verify_four_way_hash_path_to_integer(3, commitment) }
                OP_DROP OP_1
            },
            witness,
        );
        assert!(!result.success);
    }

    #[test]
    fn generic_verifier_consumes_digits() {
        let digits = [0, 1, 2, 3];
        let preimage = b"nonce";
        let commitment = four_way_hash_path_commitment(preimage, &digits);
        let witness = four_way_hash_path_witness(preimage, &digits);
        let result = execute_script_with_inputs(
            verify_four_way_hash_path(digits.len(), commitment),
            witness,
        );
        assert!(result.success, "{result}");
        assert_eq!(result.final_stack.len(), 1);
    }

    #[test]
    #[should_panic(expected = "four-way hash-path digits must be in 0..=3")]
    fn host_commitment_rejects_out_of_range_digit() {
        let _ = four_way_hash_path_commitment(b"nonce", &[4]);
    }

    #[test]
    #[should_panic(expected = "bit_width must be in 1..=31")]
    fn integer_width_above_scriptnum_limit_panics() {
        let _ = four_way_hash_path_integer_commitment(b"nonce", 0, 32);
    }
}
