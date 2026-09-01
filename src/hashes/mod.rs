//! Hash primitives and their representation-specific implementations.

pub mod blake3;
pub mod sha256;

/// Compatibility wrappers for the former `hashes::bithash` API.
///
/// BitHash is a hash-path commitment rather than a general-purpose hash. New
/// code should use [`crate::commitments::integer::hash_path`] directly.
pub mod bithash {
    use crate::{
        commitments::integer::hash_path::{
            hash_path_commitment, hash_path_script, verify_hash_path, verify_hash_path_to_altstack,
        },
        treepp::{script, Script},
    };

    fn legacy_bits(bits: &[u8; 128]) -> Vec<bool> {
        bits.iter().map(|bit| *bit != 0).collect()
    }

    /// Deprecated fixed-width reference implementation using an empty initial
    /// preimage.
    #[deprecated(note = "use commitments::integer::hash_path_commitment")]
    pub fn bithash_compute(bits: &[u8; 128]) -> [u8; 20] {
        hash_path_commitment(&[], &legacy_bits(bits))
    }

    /// Deprecated fixed-width verifier using an empty initial preimage.
    #[deprecated(note = "use commitments::integer::verify_hash_path")]
    pub fn bithash_verify(expected_hash: [u8; 20]) -> Script {
        script! {
            OP_0
            { verify_hash_path(128, expected_hash) }
        }
    }

    /// Deprecated fixed-width verifier that saves the input bits to the
    /// altstack.
    #[deprecated(note = "use commitments::integer::verify_hash_path_to_altstack")]
    pub fn bithash_verify_save_to_altstack(expected_hash: [u8; 20]) -> Script {
        script! {
            OP_0
            { verify_hash_path_to_altstack(128, expected_hash) }
        }
    }

    /// Deprecated fixed-width hash-path computation script.
    #[deprecated(note = "use commitments::integer::hash_path_script")]
    pub fn bithash_compute_script() -> Script {
        script! {
            OP_0
            { hash_path_script(128) }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::execute_script_with_inputs;

        #[test]
        #[allow(deprecated)]
        fn fixed_width_compatibility_wrapper_verifies() {
            let mut bits = [0u8; 128];
            for index in (0..128).step_by(3) {
                bits[index] = 1;
            }
            let commitment = bithash_compute(&bits);
            let witness = bits
                .iter()
                .rev()
                .map(|bit| if *bit == 0 { vec![] } else { vec![1] })
                .collect();

            let result = execute_script_with_inputs(bithash_verify(commitment), witness);
            assert!(result.success, "{result}");
        }
    }
}

// Compatibility aliases for the original flat hash module.
pub use blake3::utils as blake3_utils;
pub use sha256::sha2_u4 as sha256_u4;
pub use sha256::sha2_u4_stack as sha256_u4_stack;
