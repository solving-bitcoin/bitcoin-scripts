//! Experimental two-check point lock, using legacy ECDSA and one scriptCode.
//!
//! The honest SINGLE-bug spend reveals the target scalar. Unlike `three_check`,
//! extraction from a valid ordinary-digest transcript is NOT established.
//! Its exclusion requires an additional native-transaction transcript
//! assumption; see README.md. Do not substitute this for `three_check` while
//! retaining that construction's stronger extraction claim.

use bitcoin::{
    hashes::Hash,
    secp256k1::{ecdsa, Message, PublicKey, Secp256k1, SecretKey},
    sighash::SighashCache,
    EcdsaSighashType, Transaction,
};
use bitcoin_script::Script;

use super::{extract_from_g_half, sighash_single_bug_message, three_check};
use crate::support::script::{script, ScriptCompilation};

pub use super::three_check::{companion_key, AMBIGUOUS_R_MAX_SIGNATURE_SIZE};

/// Errors distinguish malformed/invalid signatures from the unresolved
/// extraction case of a VALID two-check signature on an ordinary digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TwoCheckError {
    ExceptionalTarget,
    InvalidInputIndex,
    InvalidSignature,
    SignatureVerificationFailed,
    /// Both signature checks succeeded, but the digest is not the SINGLE
    /// constant. No public extraction algorithm is established for this case.
    NonConstantDigest,
    TargetPointMismatch,
}

/// Construct the complete experimental 76-byte revelation predicate.
///
/// Initial stack: `... signature`. Success leaves `... true`.
/// The key derivation and size guard are shared with `three_check`.
pub fn point_lock(target: PublicKey) -> Result<Script, TwoCheckError> {
    let companion = companion_key(target).map_err(setup_error)?;
    let target = bitcoin::PublicKey::new(target);
    let companion = bitcoin::PublicKey::new(companion);
    Ok(script! {
        OP_SIZE
        { AMBIGUOUS_R_MAX_SIGNATURE_SIZE }
        OP_GREATERTHAN
        OP_VERIFY
        OP_DUP
        { target }
        OP_CHECKSIGVERIFY
        { companion }
        OP_CHECKSIG
    })
}

/// Create an honest G/2-nonce signature, with the legacy high-S fallback if
/// the low-S encoding is too short for the size guard.
pub fn sign(target_secret: SecretKey) -> Result<bitcoin::ecdsa::Signature, TwoCheckError> {
    let target = PublicKey::from_secret_key(&Secp256k1::new(), &target_secret);
    companion_key(target).map_err(setup_error)?;
    three_check::sign(target_secret).map_err(setup_error)
}

/// Compute the exact policy-produced legacy scriptCode digest. Raw sighash
/// bytes are retained, including values that consensus permits but policy
/// rejects. No accepted signature push occurs at an instruction boundary in
/// this script, so legacy FindAndDelete cannot modify its scriptCode.
pub fn legacy_digest(
    transaction: &Transaction,
    input_index: usize,
    target: PublicKey,
    raw_sighash_byte: u8,
) -> Result<[u8; 32], TwoCheckError> {
    let script = point_lock(target)?.compile_with_policy();
    SighashCache::new(transaction)
        .legacy_signature_hash(input_index, &script, u32::from(raw_sighash_byte))
        .map(|digest| digest.to_byte_array())
        .map_err(|_| TwoCheckError::InvalidInputIndex)
}

/// Verify both equations and extract on the constant-digest branch. This
/// function accepts an explicitly supplied digest, not evidence that a real
/// transaction hashes to it. Prefer `extract_from_transaction` for spends.
pub fn extract(
    target: PublicKey,
    signature: &bitcoin::ecdsa::Signature,
    digest: [u8; 32],
) -> Result<SecretKey, TwoCheckError> {
    if signature.to_vec().len() <= AMBIGUOUS_R_MAX_SIGNATURE_SIZE {
        return Err(TwoCheckError::InvalidSignature);
    }
    let companion = companion_key(target).map_err(setup_error)?;
    // Normalization admits legacy-consensus high-S signatures even though
    // libsecp256k1's verification interface accepts only low-S.
    let mut normalized = signature.signature;
    normalized.normalize_s();
    let secp = Secp256k1::verification_only();
    for key in [target, companion] {
        secp.verify_ecdsa(&Message::from_digest(digest), &normalized, &key)
            .map_err(|_| TwoCheckError::SignatureVerificationFailed)?;
    }
    if digest != sighash_single_bug_message() {
        return Err(TwoCheckError::NonConstantDigest);
    }
    extract_from_g_half(digest, signature, target).map_err(|_| TwoCheckError::TargetPointMismatch)
}

/// Parse strict DER while retaining the raw consensus sighash byte, calculate
/// the real transaction digest, and run the explicitly partial extractor.
pub fn extract_from_transaction(
    target: PublicKey,
    signature_item: &[u8],
    transaction: &Transaction,
    input_index: usize,
) -> Result<SecretKey, TwoCheckError> {
    if signature_item.len() <= AMBIGUOUS_R_MAX_SIGNATURE_SIZE {
        return Err(TwoCheckError::InvalidSignature);
    }
    let (&flag, der) = signature_item
        .split_last()
        .ok_or(TwoCheckError::InvalidSignature)?;
    let inner = ecdsa::Signature::from_der(der).map_err(|_| TwoCheckError::InvalidSignature)?;
    let signature = bitcoin::ecdsa::Signature {
        signature: inner,
        // Only a DER container; the actual byte is passed separately below.
        sighash_type: EcdsaSighashType::All,
    };
    let digest = legacy_digest(transaction, input_index, target, flag)?;
    extract(target, &signature, digest)
}

fn setup_error(error: three_check::ThreeCheckError) -> TwoCheckError {
    match error {
        three_check::ThreeCheckError::ExceptionalTarget => TwoCheckError::ExceptionalTarget,
        _ => TwoCheckError::InvalidSignature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::pointlocks::{
        g_half_nonce, group_order, inverse, scalar_bytes, secret_from_biguint, sign_with_nonce,
        G_HALF_R,
    };
    use bitcoin::{
        absolute, script::PushBytesBuf, transaction, Amount, OutPoint, ScriptBuf, Sequence, TxIn,
        TxOut, Witness,
    };
    use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};
    use num_bigint::BigUint;

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn bug_transaction() -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: (0..2)
                .map(|vout| TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::Txid::all_zeros(),
                        vout,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn execute(script: ScriptBuf, signature: Vec<u8>) -> (bool, usize) {
        let mut exec = Exec::new(
            ExecCtx::Legacy,
            Options::default(),
            TxTemplate {
                tx: bug_transaction(),
                prevouts: vec![],
                input_idx: 1,
                taproot_annex_scriptleaf: None,
            },
            script,
            vec![signature],
        )
        .unwrap();
        while exec.exec_next().is_ok() {}
        (
            exec.result().unwrap().success,
            exec.stats().max_nb_stack_items,
        )
    }

    #[test]
    fn exact_76_byte_script_executes_without_padding_and_reveals_target() {
        let secret = key(7);
        let target = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        let script = point_lock(target).unwrap().compile_with_policy();
        let signature = sign(secret).unwrap();
        assert_eq!(script.len(), 76);
        assert_eq!(signature.to_vec().len(), 60);
        let script_sig = bitcoin::script::Builder::new()
            .push_slice(PushBytesBuf::try_from(signature.to_vec()).unwrap())
            .into_script();
        assert_eq!(script_sig.len(), 61);
        assert_eq!(execute(script.clone(), signature.to_vec()), (true, 3));
        assert_eq!(
            extract_from_transaction(target, &signature.to_vec(), &bug_transaction(), 1),
            Ok(secret)
        );
        let ops: Vec<_> = script
            .instructions()
            .filter_map(|entry| match entry.unwrap() {
                bitcoin::script::Instruction::Op(op) => Some(op),
                _ => None,
            })
            .collect();
        assert_eq!(ops.len(), 6);
        assert!(!ops.contains(&bitcoin::opcodes::all::OP_CODESEPARATOR));
    }

    #[test]
    fn valid_synthetic_ordinary_transcript_is_explicitly_not_extractable() {
        // This constructs digest bytes, NOT a transaction preimage. It proves
        // why the two-check claim needs a stronger assumption than three_check.
        let n = group_order();
        let secret = key(13);
        let target = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        let nonce = key(17);
        let point = PublicKey::from_secret_key(&Secp256k1::new(), &nonce);
        let r = BigUint::from_bytes_be(&point.serialize_uncompressed()[1..33]) % &n;
        let c = BigUint::from_bytes_be(&sighash_single_bug_message());
        let r0 = BigUint::from_bytes_be(&G_HALF_R);
        let z = c * r * inverse(&r0, &n) % &n;
        let digest = scalar_bytes(&z).unwrap();
        assert_ne!(digest, sighash_single_bug_message());
        let signature = sign_with_nonce(digest, secret, nonce, EcdsaSighashType::All).unwrap();
        // extract() verifies BOTH keys before returning this specific error.
        assert_eq!(
            extract(target, &signature, digest),
            Err(TwoCheckError::NonConstantDigest)
        );
    }

    #[test]
    fn short_low_s_has_extractable_high_s_fallback() {
        let n = group_order();
        let r0 = BigUint::from_bytes_be(&G_HALF_R);
        let c = BigUint::from_bytes_be(&sighash_single_bug_message());
        let k0 = BigUint::from_bytes_be(&g_half_nonce().unwrap().secret_bytes());
        let secret = secret_from_biguint(&((&n + k0 - c) * inverse(&r0, &n) % &n)).unwrap();
        let target = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        let signature = sign(secret).unwrap();
        assert_eq!(signature.to_vec().len(), 61);
        assert_eq!(
            extract_from_transaction(target, &signature.to_vec(), &bug_transaction(), 1),
            Ok(secret)
        );
        let mut short = signature;
        short.signature.normalize_s();
        assert_eq!(short.to_vec().len(), 29);
        assert!(
            !execute(
                point_lock(target).unwrap().compile_with_policy(),
                short.to_vec()
            )
            .0
        );
        assert_eq!(
            extract(target, &short, sighash_single_bug_message()),
            Err(TwoCheckError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_both_exceptional_targets() {
        let n = group_order();
        let c = BigUint::from_bytes_be(&sighash_single_bug_message());
        let r0 = BigUint::from_bytes_be(&G_HALF_R);
        let offset = &n - (BigUint::from(2u8) * c * inverse(&r0, &n) % &n);
        for scalar in [
            &offset,
            &(offset.clone() * inverse(&BigUint::from(2u8), &n) % &n),
        ] {
            let secret = secret_from_biguint(scalar).unwrap();
            let target = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
            assert!(matches!(
                point_lock(target),
                Err(TwoCheckError::ExceptionalTarget)
            ));
            assert_eq!(sign(secret), Err(TwoCheckError::ExceptionalTarget));
        }
    }

    #[test]
    fn malformed_guard_boundary_wrong_target_and_wrong_context_fail() {
        let target = PublicKey::from_secret_key(&Secp256k1::new(), &key(7));
        let script = point_lock(target).unwrap().compile_with_policy();
        for length in [0, 57, 58, 73] {
            let malformed = vec![0; length];
            assert!(!execute(script.clone(), malformed.clone()).0);
            assert_eq!(
                extract_from_transaction(target, &malformed, &bug_transaction(), 1),
                Err(TwoCheckError::InvalidSignature)
            );
        }
        let signature = sign(key(9)).unwrap();
        assert!(!execute(script, signature.to_vec()).0);
        assert_eq!(
            extract(target, &signature, sighash_single_bug_message()),
            Err(TwoCheckError::SignatureVerificationFailed)
        );
        let signature = sign(key(7)).unwrap();
        assert_eq!(
            extract_from_transaction(target, &signature.to_vec(), &bug_transaction(), 0),
            Err(TwoCheckError::SignatureVerificationFailed)
        );
        assert_eq!(
            extract_from_transaction(target, &signature.to_vec(), &bug_transaction(), 2),
            Err(TwoCheckError::InvalidInputIndex)
        );
    }

    #[test]
    fn raw_undefined_single_flag_preserves_consensus_digest() {
        let secret = key(7);
        let target = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        let mut signature = sign(secret).unwrap().to_vec();
        for flag in [0x03, 0x23, 0x83, 0xa3] {
            *signature.last_mut().unwrap() = flag;
            assert_eq!(
                extract_from_transaction(target, &signature, &bug_transaction(), 1),
                Ok(secret)
            );
        }
        for flag in [0x01, 0x02, 0x04] {
            *signature.last_mut().unwrap() = flag;
            assert_eq!(
                extract_from_transaction(target, &signature, &bug_transaction(), 1),
                Err(TwoCheckError::SignatureVerificationFailed)
            );
        }
    }

    #[test]
    fn accepted_signature_push_cannot_trigger_find_and_delete() {
        let target = PublicKey::from_secret_key(&Secp256k1::new(), &key(7));
        let script = point_lock(target).unwrap().compile_with_policy();
        for entry in script.instruction_indices() {
            let (index, _) = entry.unwrap();
            assert!(!(58..=73).contains(&(script.as_bytes()[index] as usize)));
        }
    }
}
