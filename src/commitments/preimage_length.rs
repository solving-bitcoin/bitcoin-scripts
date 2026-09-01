//! Integer commitments encoded as authenticated preimage lengths.

use bitcoin::hashes::{sha256, Hash};

use crate::script::{script, Script};

/// Offset used by [`verify_preimage_length`].
pub const DEFAULT_PREIMAGE_LENGTH_OFFSET: usize = 16;

/// Consensus maximum size of a Bitcoin Script stack element.
pub const MAX_PREIMAGE_LENGTH: usize = 520;

/// Compute the public SHA-256 commitment to a preimage.
pub fn preimage_length_commitment(preimage: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(preimage).to_byte_array()
}

/// Verify a preimage and return `preimage.len() - 16` as a Script integer.
pub fn verify_preimage_length(commitment: [u8; 32]) -> Script {
    verify_preimage_length_with_offset(commitment, DEFAULT_PREIMAGE_LENGTH_OFFSET)
}

/// Verify a preimage and return `preimage.len() - offset` as a Script integer.
///
/// The preimage must be on top of the stack and its length must be at least
/// `offset`. Panics if `offset` exceeds Bitcoin's 520-byte stack-element limit.
pub fn verify_preimage_length_with_offset(commitment: [u8; 32], offset: usize) -> Script {
    assert!(
        offset <= MAX_PREIMAGE_LENGTH,
        "offset exceeds the 520-byte stack-element limit"
    );
    script! {
        OP_DUP
        OP_SHA256
        { commitment.to_vec() }
        OP_EQUALVERIFY

        OP_SIZE
        { offset }
        OP_SUB
        OP_NIP

        // Define the committed integer over the non-negative domain.
        OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{execute_script_with_inputs, script::script};

    #[test]
    fn verifies_default_offset() {
        let preimage = vec![0x42; 37];
        let commitment = preimage_length_commitment(&preimage);
        let result = execute_script_with_inputs(
            script! {
                { verify_preimage_length(commitment) }
                21 OP_EQUAL
            },
            vec![preimage],
        );
        assert!(result.success, "{result}");
    }

    #[test]
    fn verifies_custom_offset_and_zero_value() {
        let preimage = vec![0x24; 32];
        let commitment = preimage_length_commitment(&preimage);
        let result = execute_script_with_inputs(
            script! {
                { verify_preimage_length_with_offset(commitment, 32) }
                0 OP_EQUAL
            },
            vec![preimage],
        );
        assert!(result.success, "{result}");
    }

    #[test]
    fn wrong_preimage_fails() {
        let commitment = preimage_length_commitment(&[0x11; 32]);
        let result = execute_script_with_inputs(
            script! { { verify_preimage_length(commitment) } OP_DROP OP_1 },
            vec![vec![0x12; 32]],
        );
        assert!(!result.success);
    }

    #[test]
    fn preimage_shorter_than_offset_fails() {
        let preimage = vec![0x11; 15];
        let commitment = preimage_length_commitment(&preimage);
        let result = execute_script_with_inputs(
            script! { { verify_preimage_length(commitment) } OP_DROP OP_1 },
            vec![preimage],
        );
        assert!(!result.success);
    }

    #[test]
    #[should_panic(expected = "offset exceeds the 520-byte stack-element limit")]
    fn offset_above_stack_element_limit_panics() {
        let _ = verify_preimage_length_with_offset([0; 32], 521);
    }
}
