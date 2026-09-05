//! ECDSA point locks built from signature-size and signature-hash constraints.
//!
//! These scripts use legacy ECDSA `OP_CHECKSIG` semantics. They are not safe
//! as tapscripts, where `OP_CHECKSIG` verifies BIP340 signatures and treats a
//! 33-byte key as an unknown public-key type.

use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{ecdsa, Message, PublicKey, Secp256k1, SecretKey},
    EcdsaSighashType,
};
use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::support::script::*;

pub mod three_check;

/// The largest accepted serialized Bitcoin signature for the `G/2` lock.
///
/// A low-S signature with the 21-byte x-coordinate of `G/2` is at most
/// `7 + 21 + 32 = 60` bytes, including its sighash byte.
pub const G_HALF_MAX_SIGNATURE_SIZE: usize = 60;

/// `x(G/2)`, minimally encoded as the ECDSA `r` integer (21 bytes).
pub const G_HALF_R: [u8; 21] = [
    0x3b, 0x78, 0xce, 0x56, 0x3f, 0x89, 0xa0, 0xed, 0x94, 0x14, 0xf5, 0xaa, 0x28, 0xad, 0x0d, 0x96,
    0xd6, 0x79, 0x5f, 0x9c, 0x63,
];

/// Errors returned by the research-only point-lock setup and extraction helpers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PointLockError {
    InvalidScalar,
    InvalidSignature,
    WrongSighashType,
    PublicKeyMismatch,
    TargetPointMismatch,
}

/// A legacy/P2SH/P2WSH ECDSA point lock using the known nonce `G/2`.
///
/// The witness is one low-S Bitcoin ECDSA signature made with nonce scalar
/// `1/2 mod n`. The size check accepts every such signature. Publishing it
/// reveals the signing key through the ECDSA equation. The script alone only
/// enforces a small signature, so its soundness is bounded by the cost of
/// finding another sufficiently small valid signature.
pub fn g_half_point_lock(public_key: PublicKey) -> Script {
    let public_key = bitcoin::PublicKey::new(public_key);
    script! {
        OP_SIZE
        { G_HALF_MAX_SIGNATURE_SIZE }
        OP_LESSTHANOREQUAL
        OP_VERIFY
        { public_key }
        OP_CHECKSIG
    }
}

/// A legacy/P2SH ECDSA point lock committed to one complete signature item.
///
/// `signature_commitment` is `SHA256(DER(r,s) || 0x03)`. The committed
/// signature must be checked in a legacy transaction input for which
/// `input_index >= output_count`, activating the historical SIGHASH_SINGLE
/// digest. SegWit v0 deliberately does not reproduce that bug.
pub fn committed_point_lock(public_key: PublicKey, signature_commitment: sha256::Hash) -> Script {
    let public_key = bitcoin::PublicKey::new(public_key);
    script! {
        OP_DUP
        OP_SHA256
        { signature_commitment.to_byte_array().to_vec() }
        OP_EQUALVERIFY
        { public_key }
        OP_CHECKSIG
    }
}

/// Commit to the complete Bitcoin signature item consumed by `OP_CHECKSIG`.
pub fn signature_commitment(signature: &bitcoin::ecdsa::Signature) -> sha256::Hash {
    sha256::Hash::hash(&signature.serialize())
}

/// Sign a 32-byte ECDSA message with a caller-selected nonce.
///
/// This helper is for deterministic research vectors. Its bigint arithmetic
/// is not constant-time and must not be used as a production signing API.
pub fn sign_with_nonce(
    message: [u8; 32],
    signing_key: SecretKey,
    nonce: SecretKey,
    sighash_type: EcdsaSighashType,
) -> Result<bitcoin::ecdsa::Signature, PointLockError> {
    let n = group_order();
    let secp = Secp256k1::new();
    let nonce_point = PublicKey::from_secret_key(&secp, &nonce).serialize_uncompressed();
    let r = BigUint::from_bytes_be(&nonce_point[1..33]) % &n;
    if r.is_zero() {
        return Err(PointLockError::InvalidScalar);
    }

    let z = BigUint::from_bytes_be(&message) % &n;
    let d = BigUint::from_bytes_be(&signing_key.secret_bytes());
    let k = BigUint::from_bytes_be(&nonce.secret_bytes());
    let s = ((z + (&r * d)) * inverse(&k, &n)) % &n;
    if s.is_zero() {
        return Err(PointLockError::InvalidScalar);
    }

    let mut compact = [0u8; 64];
    compact[..32].copy_from_slice(&scalar_bytes(&r)?);
    compact[32..].copy_from_slice(&scalar_bytes(&s)?);
    let mut signature =
        ecdsa::Signature::from_compact(&compact).map_err(|_| PointLockError::InvalidSignature)?;
    signature.normalize_s();

    let public_key = PublicKey::from_secret_key(&secp, &signing_key);
    secp.verify_ecdsa(&Message::from_digest(message), &signature, &public_key)
        .map_err(|_| PointLockError::InvalidSignature)?;

    Ok(bitcoin::ecdsa::Signature {
        signature,
        sighash_type,
    })
}

/// Produce the small-R point-lock signature using nonce scalar `1/2 mod n`.
pub fn sign_with_g_half(
    message: [u8; 32],
    signing_key: SecretKey,
    sighash_type: EcdsaSighashType,
) -> Result<bitcoin::ecdsa::Signature, PointLockError> {
    sign_with_nonce(message, signing_key, g_half_nonce()?, sighash_type)
}

/// Produce a committed point-lock signature for the legacy SIGHASH_SINGLE bug.
///
/// The `point_secret` is the discrete logarithm that the spend will reveal.
pub fn sign_committed(
    public_signing_secret: SecretKey,
    point_secret: SecretKey,
) -> Result<bitcoin::ecdsa::Signature, PointLockError> {
    sign_with_nonce(
        sighash_single_bug_message(),
        public_signing_secret,
        point_secret,
        EcdsaSighashType::Single,
    )
}

/// Extract the signing secret revealed by a valid `G/2` signature.
pub fn extract_from_g_half(
    message: [u8; 32],
    signature: &bitcoin::ecdsa::Signature,
    expected_public_key: PublicKey,
) -> Result<SecretKey, PointLockError> {
    let (r, s) = signature_scalars(signature);
    let n = group_order();
    let z = BigUint::from_bytes_be(&message) % &n;
    let half = (BigUint::one() + &n) >> 1;
    let negative_half = &n - &half;

    for k in [&half, &negative_half] {
        let d = sub_mod(&((&s * k) % &n), &z, &n) * inverse(&r, &n) % &n;
        if let Ok(candidate) = secret_from_biguint(&d) {
            if PublicKey::from_secret_key(&Secp256k1::new(), &candidate) == expected_public_key {
                return Ok(candidate);
            }
        }
    }
    Err(PointLockError::PublicKeyMismatch)
}

/// Extract the discrete logarithm of `target_point` from a committed signature.
///
/// `public_signing_secret` is intentionally public protocol data. Low-S
/// normalization may negate the effective nonce; this function corrects that
/// sign against the full target point.
pub fn extract_from_committed(
    signature: &bitcoin::ecdsa::Signature,
    public_signing_secret: SecretKey,
    target_point: PublicKey,
) -> Result<SecretKey, PointLockError> {
    if signature.sighash_type != EcdsaSighashType::Single {
        return Err(PointLockError::WrongSighashType);
    }
    let (r, s) = signature_scalars(signature);
    let n = group_order();
    let z = BigUint::from_bytes_be(&sighash_single_bug_message()) % &n;
    let d = BigUint::from_bytes_be(&public_signing_secret.secret_bytes());
    let k = ((z + r * d) % &n) * inverse(&s, &n) % &n;
    let candidate = secret_from_biguint(&k)?;
    let secp = Secp256k1::new();
    let candidate_point = PublicKey::from_secret_key(&secp, &candidate);
    if candidate_point == target_point {
        return Ok(candidate);
    }
    if candidate_point == target_point.negate(&secp) {
        return secret_from_biguint(&(&n - k));
    }
    Err(PointLockError::TargetPointMismatch)
}

/// The digest bytes passed to libsecp256k1 for the legacy SIGHASH_SINGLE bug.
///
/// Bitcoin's `uint256(1)` is exposed to the signature checker in this internal
/// byte order. Interpreted as ECDSA's big-endian message integer, it is
/// `2^248`, even though Bitcoin conventionally displays the digest as `...0001`.
pub fn sighash_single_bug_message() -> [u8; 32] {
    let mut message = [0u8; 32];
    message[0] = 1;
    message
}

pub(super) fn g_half_nonce() -> Result<SecretKey, PointLockError> {
    let half = (group_order() + BigUint::one()) >> 1;
    secret_from_biguint(&half)
}

pub(super) fn signature_scalars(signature: &bitcoin::ecdsa::Signature) -> (BigUint, BigUint) {
    let compact = signature.signature.serialize_compact();
    (
        BigUint::from_bytes_be(&compact[..32]),
        BigUint::from_bytes_be(&compact[32..]),
    )
}

pub(super) fn group_order() -> BigUint {
    BigUint::parse_bytes(
        b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .expect("secp256k1 order parses")
}

pub(super) fn inverse(value: &BigUint, modulus: &BigUint) -> BigUint {
    value.modpow(&(modulus - BigUint::from(2u8)), modulus)
}

fn sub_mod(lhs: &BigUint, rhs: &BigUint, modulus: &BigUint) -> BigUint {
    if lhs >= rhs {
        lhs - rhs
    } else {
        modulus - (rhs - lhs)
    }
}

pub(super) fn scalar_bytes(value: &BigUint) -> Result<[u8; 32], PointLockError> {
    let bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        return Err(PointLockError::InvalidScalar);
    }
    let mut scalar = [0u8; 32];
    scalar[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(scalar)
}

pub(super) fn secret_from_biguint(value: &BigUint) -> Result<SecretKey, PointLockError> {
    SecretKey::from_slice(&scalar_bytes(value)?).map_err(|_| PointLockError::InvalidScalar)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute, consensus::encode::serialize, sighash::SighashCache, transaction, Amount,
        OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };
    use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};

    use crate::support::script::ScriptCompilation;

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn execute_legacy(script: Script, signature: Vec<u8>) -> bool {
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                },
            ],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let mut script = script.compile_with_policy().into_bytes();
        // Work around an unsigned underflow in the pinned scriptexec legacy
        // FindAndDelete loop when scriptCode is shorter than the signature.
        // The bug digest is independent of scriptCode, so executed NOP suffix
        // bytes preserve this test's signature and predicate semantics.
        script.resize(
            script.len().max(signature.len()),
            bitcoin::opcodes::all::OP_NOP.to_u8(),
        );
        let mut exec = Exec::new(
            ExecCtx::Legacy,
            Options::default(),
            TxTemplate {
                tx,
                prevouts: vec![],
                input_idx: 1,
                taproot_annex_scriptleaf: None,
            },
            ScriptBuf::from_bytes(script),
            vec![signature],
        )
        .unwrap();
        while exec.exec_next().is_ok() {}
        exec.result().unwrap().success
    }

    #[test]
    fn g_half_is_the_21_byte_r_value() {
        let nonce = g_half_nonce().unwrap();
        let point = PublicKey::from_secret_key(&Secp256k1::new(), &nonce);
        assert_eq!(&point.serialize_uncompressed()[12..33], &G_HALF_R);
    }

    #[test]
    fn small_r_lock_accepts_and_reveals_the_signing_key() {
        let signing_key = key(3);
        let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &signing_key);
        let signature = sign_with_g_half(
            sighash_single_bug_message(),
            signing_key,
            EcdsaSighashType::Single,
        )
        .unwrap();
        let signature_bytes = signature.to_vec();
        assert!(signature_bytes.len() <= G_HALF_MAX_SIGNATURE_SIZE);
        assert!(execute_legacy(
            g_half_point_lock(public_key),
            signature_bytes
        ));
        assert_eq!(
            extract_from_g_half(sighash_single_bug_message(), &signature, public_key).unwrap(),
            signing_key
        );
    }

    #[test]
    fn small_r_lock_rejects_an_ordinary_signature() {
        let signing_key = key(3);
        let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &signing_key);
        let signature = Secp256k1::new().sign_ecdsa(
            &Message::from_digest(sighash_single_bug_message()),
            &signing_key,
        );
        let signature = bitcoin::ecdsa::Signature {
            signature,
            sighash_type: EcdsaSighashType::Single,
        };
        assert!(signature.to_vec().len() > G_HALF_MAX_SIGNATURE_SIZE);
        assert!(!execute_legacy(
            g_half_point_lock(public_key),
            signature.to_vec()
        ));
    }

    #[test]
    fn small_r_lock_works_with_the_actual_p2wsh_digest() {
        let signing_key = key(3);
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &signing_key);
        let script = g_half_point_lock(public_key).compile_with_policy();
        let amount = Amount::from_sat(50_000);
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let sighash = SighashCache::new(&tx)
            .p2wsh_signature_hash(0, &script, amount, EcdsaSighashType::All)
            .unwrap();
        let message = sighash.to_byte_array();
        let signature = sign_with_g_half(message, signing_key, EcdsaSighashType::All).unwrap();
        let mut exec = Exec::new(
            ExecCtx::SegwitV0,
            Options::default(),
            TxTemplate {
                tx,
                prevouts: vec![TxOut {
                    value: amount,
                    script_pubkey: script.to_p2wsh(),
                }],
                input_idx: 0,
                taproot_annex_scriptleaf: None,
            },
            script,
            vec![signature.to_vec()],
        )
        .unwrap();
        while exec.exec_next().is_ok() {}
        assert!(exec.result().unwrap().success);
        assert_eq!(
            extract_from_g_half(message, &signature, public_key).unwrap(),
            signing_key
        );
    }

    #[test]
    fn committed_lock_accepts_only_the_committed_signature_and_extracts_point() {
        let public_secret = key(7);
        let point_secret = key(11);
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &public_secret);
        let target_point = PublicKey::from_secret_key(&secp, &point_secret);
        let signature = sign_committed(public_secret, point_secret).unwrap();
        let commitment = signature_commitment(&signature);
        let lock = committed_point_lock(public_key, commitment);

        assert!(execute_legacy(lock.clone(), signature.to_vec()));
        assert_eq!(
            extract_from_committed(&signature, public_secret, target_point).unwrap(),
            point_secret
        );

        let other = sign_committed(public_secret, key(12)).unwrap();
        assert!(!execute_legacy(lock, other.to_vec()));
    }

    #[test]
    fn committed_extraction_rejects_wrong_target_and_sighash() {
        let public_secret = key(7);
        let point_secret = key(11);
        let secp = Secp256k1::new();
        let mut signature = sign_committed(public_secret, point_secret).unwrap();
        let wrong_target = PublicKey::from_secret_key(&secp, &key(12));
        assert_eq!(
            extract_from_committed(&signature, public_secret, wrong_target),
            Err(PointLockError::TargetPointMismatch)
        );
        signature.sighash_type = EcdsaSighashType::All;
        assert_eq!(
            extract_from_committed(
                &signature,
                public_secret,
                PublicKey::from_secret_key(&secp, &point_secret)
            ),
            Err(PointLockError::WrongSighashType)
        );
    }

    #[test]
    fn point_lock_metrics_are_stable() {
        let public_secret = key(7);
        let point_secret = key(11);
        let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &public_secret);
        let small = sign_with_g_half(
            sighash_single_bug_message(),
            public_secret,
            EcdsaSighashType::Single,
        )
        .unwrap();
        let committed = sign_committed(public_secret, point_secret).unwrap();

        assert_eq!(
            g_half_point_lock(public_key).compile_with_policy().len(),
            40
        );
        assert_eq!(serialize(&Witness::from_slice(&[small.to_vec()])).len(), 62);
        assert_eq!(
            committed_point_lock(public_key, signature_commitment(&committed))
                .compile_with_policy()
                .len(),
            71
        );
        assert_eq!(
            serialize(&Witness::from_slice(&[committed.to_vec()])).len(),
            73
        );
    }
}
