//! HASH160 composition: RIPEMD-160(SHA-256(message)).

use crate::{
    arithmetic::u32::stack::{u32_fromaltstack, u32_toaltstack, u8_reverse_toaltstack},
    arithmetic::u32::xor::{u8_drop_xor_table, u8_push_xor_table},
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

/// HASH160 variant that keeps the shared byte-logic table resident between
/// the SHA-256 and RIPEMD-160 stages.
pub fn hash160_shared_table(num_bytes: usize) -> Script {
    script! {
        { u8_reverse_toaltstack(num_bytes) }
        { u8_push_xor_table() }
        { sha2_u32::sha256_without_table_after_input(num_bytes) }
        { ripemd160::ripemd160_without_table(32) }
        for _ in 0..5 { { u32_toaltstack() } }
        { u8_drop_xor_table() }
        for _ in 0..5 { { u32_fromaltstack() } }
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

    fn verify_hash160(message: &[u8], shared_table: bool) {
        let sha256 = reference_sha256::Hash::hash(message);
        let expected = reference_ripemd160::Hash::hash(sha256.as_ref()).to_byte_array();
        let fragment = if shared_table {
            hash160_shared_table(message.len())
        } else {
            hash160(message.len())
        };
        let result = crate::support::execution::execute_script_with_inputs_strict(
            script! {
                { push_message(message) }
                { fragment }
                for byte in expected {
                    { byte }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            },
            vec![],
        );
        assert!(
            result.success,
            "shared_table={shared_table}, message_len={}: {result}",
            message.len()
        );
    }

    #[test]
    fn matches_reference_vectors() {
        for message in [b"".as_slice(), b"abc", &[0x42; 55], &[0x24; 56]] {
            verify_hash160(message, false);
            verify_hash160(message, true);
        }
    }

    #[test]
    fn shared_table_rejects_non_byte_inputs() {
        for invalid in [vec![0x81], vec![0x00, 0x01]] {
            let result = crate::support::execution::execute_script_with_inputs_strict(
                hash160_shared_table(1),
                vec![invalid],
            );
            assert!(!result.success, "accepted invalid input: {result}");
        }
    }

    #[test]
    fn rejects_unsupported_message_length() {
        assert!(std::panic::catch_unwind(|| hash160(512)).is_err());
    }
}
