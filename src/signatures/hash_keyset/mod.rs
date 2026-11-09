//! Verify a native Schnorr signer against public HASH160 identifiers.

use crate::support::script::{script, Script};

mod schedule;

/// Consume `signature public_key` in tapscript. Verify that the exact
/// 32-byte key hashes to one of 1..=512 identifiers and checks the signature.
/// Success preserves both caller stacks and produces no result item.
pub fn verify_hash160_keyset(identifiers: &[[u8; 20]]) -> Script {
    assert!(
        (1..=512).contains(&identifiers.len()),
        "HASH160 key set supports 1..=512 identifiers"
    );
    script! {
        OP_SIZE 32 OP_EQUALVERIFY
        OP_DUP OP_HASH160
        { schedule::verify_any_match(identifiers) }
        OP_DROP OP_CHECKSIGVERIFY
    }
}
