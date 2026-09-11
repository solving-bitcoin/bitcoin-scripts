//! HASH160 composition: RIPEMD-160(SHA-256(message)).

use crate::{
    hashes::{ripemd160, sha256::sha2_u32},
    support::script::{script, Script},
};

/// Hashes a fixed-length byte message with Bitcoin's HASH160 construction.
///
/// The message bytes are consumed from the main stack and the 20 digest bytes
/// remain on the main stack with the first digest byte on top.
pub fn hash160(num_bytes: usize) -> Script {
    script! {
        { sha2_u32::sha256(num_bytes) }
        { ripemd160::ripemd160(32) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::{ripemd160 as reference_ripemd160, sha256 as reference_sha256, Hash};

    fn push_message(message: &[u8]) -> Script {
        script! {
            for byte in message.iter().rev() {
                { *byte }
            }
        }
    }

    fn verify_hash160(message: &[u8]) {
        let sha256 = reference_sha256::Hash::hash(message);
        let expected = reference_ripemd160::Hash::hash(sha256.as_ref()).to_byte_array();
        let result = crate::support::execution::execute_script_with_inputs_strict(
            script! {
                { push_message(message) }
                { hash160(message.len()) }
                for byte in expected {
                    { byte }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            },
            vec![],
        );
        assert!(result.success, "{result}");
    }

    #[test]
    fn matches_reference_vectors() {
        verify_hash160(b"");
        verify_hash160(b"abc");
        verify_hash160(&[0x42; 55]);
        verify_hash160(&[0x24; 56]);
    }

    #[test]
    fn rejects_unsupported_message_length() {
        assert!(std::panic::catch_unwind(|| hash160(512)).is_err());
    }
}
