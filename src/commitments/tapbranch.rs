//! Taproot `TapBranch` hashing over two already-ordered 32-byte nodes.

use bitcoin::hashes::{sha256, Hash};

use crate::{
    arithmetic::u4::stack::{u4_fromaltstack, u4_number_to_nibble, u4_toaltstack},
    hashes::sha256::sha2_u4,
    support::script::{script, Script},
};

/// Compute the Taproot `TapBranch` tagged-hash fragment over two sorted nodes.
///
/// The witness supplies 64 bytes as 128 canonical u4 stack items, ordered as
/// `left || right`. The caller must enforce `left <= right` lexicographically,
/// as required by BIP341. The fragment returns the 32-byte digest as 64 u4
/// stack items, most-significant nibble first.
pub fn tapbranch_hash_u4() -> Script {
    let tag_hash = sha256::Hash::hash(b"TapBranch").to_byte_array();

    script! {
        // The generic SHA-256 circuit assumes canonical numeric nibbles;
        // validate every hostile witness item before routing it.
        for index in 0..128 {
            { index }
            OP_PICK
            OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
            16 OP_LESSTHAN OP_VERIFY
        }
        // Move the dynamic nodes aside, insert SHA256(tag) || SHA256(tag),
        // then restore the nodes beneath the fixed prefix.
        { u4_toaltstack(128) }
        for _ in 0..2 {
            for chunk in tag_hash.chunks_exact(4) {
                { u4_number_to_nibble(u32::from_be_bytes(chunk.try_into().unwrap())) }
            }
        }
        { u4_fromaltstack(128) }
        { sha2_u4::sha256(128) }
    }
}

/// Encode two 32-byte nodes into the canonical u4 witness consumed by
/// [`tapbranch_hash_u4`].
pub fn tapbranch_hash_u4_witness(left: [u8; 32], right: [u8; 32]) -> Vec<Vec<u8>> {
    left.into_iter()
        .chain(right)
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .map(|nibble| {
            if nibble == 0 {
                Vec::new()
            } else {
                vec![nibble]
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{execution::execute_script_with_inputs, script::script};
    use bitcoin::hex::DisplayHex;

    fn expected(left: [u8; 32], right: [u8; 32]) -> String {
        let tag_hash = sha256::Hash::hash(b"TapBranch");
        let mut preimage = Vec::with_capacity(128);
        preimage.extend_from_slice(tag_hash.as_ref());
        preimage.extend_from_slice(tag_hash.as_ref());
        preimage.extend_from_slice(&left);
        preimage.extend_from_slice(&right);
        sha256::Hash::hash(&preimage)
            .to_byte_array()
            .to_lower_hex_string()
    }

    fn assert_digest(left: [u8; 32], right: [u8; 32]) {
        let digest = expected(left, right);
        let result = execute_script_with_inputs(
            script! {
                { tapbranch_hash_u4() }
                { crate::arithmetic::u4::stack::u4_hex_to_nibbles(&digest) }
                for _ in 0..64 { OP_TOALTSTACK }
                for i in 1..64 { { i } OP_ROLL }
                for _ in 0..64 { OP_FROMALTSTACK OP_EQUALVERIFY }
                OP_TRUE
            },
            tapbranch_hash_u4_witness(left, right),
        );
        assert!(result.success, "{result}");
    }

    #[test]
    fn matches_bip341_tagged_hash_for_ordered_nodes() {
        assert_digest([0; 32], [1; 32]);
        assert_digest([0x12; 32], [0x34; 32]);
    }

    #[test]
    fn rejects_an_out_of_range_witness_nibble() {
        let mut witness = tapbranch_hash_u4_witness([0; 32], [1; 32]);
        witness[0] = vec![16];
        let result = execute_script_with_inputs(
            script! {
                { tapbranch_hash_u4() }
                for _ in 0..64 { OP_DROP }
                OP_1
            },
            witness,
        );
        assert!(!result.success);
    }

    #[test]
    fn wrong_node_order_changes_the_digest() {
        let left = [0; 32];
        let right = [1; 32];
        let expected_ordered = expected(left, right);
        let result = execute_script_with_inputs(
            script! {
                { tapbranch_hash_u4() }
                { crate::arithmetic::u4::stack::u4_hex_to_nibbles(&expected_ordered) }
                for _ in 0..64 { OP_TOALTSTACK }
                for i in 1..64 { { i } OP_ROLL }
                for _ in 0..64 { OP_FROMALTSTACK OP_EQUALVERIFY }
                OP_TRUE
            },
            tapbranch_hash_u4_witness(right, left),
        );
        assert!(!result.success);
    }
}
