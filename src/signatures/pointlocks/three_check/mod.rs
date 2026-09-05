//! A point-only ECDSA lock using one signature under two related keys.
//!
//! The construction is meaningful only with legacy signature hashing. It uses
//! an executed `OP_CODESEPARATOR` to give two checks under the target key
//! different `scriptCode` views, then checks the same signature under a
//! deterministically related companion key.

use bitcoin::{
    hashes::Hash,
    opcodes::all::OP_CODESEPARATOR,
    script::Instruction,
    secp256k1::{ecdsa, Message, PublicKey, Secp256k1, SecretKey},
    sighash::SighashCache,
    EcdsaSighashType, ScriptBuf, Transaction,
};
use bitcoin_script::Script;
use num_bigint::BigUint;
use num_traits::Zero;

use crate::support::script::{script, ScriptCompilation};

use super::{
    g_half_nonce, group_order, inverse, scalar_bytes, secret_from_biguint,
    sighash_single_bug_message, sign_with_g_half, signature_scalars, G_HALF_R,
};

/// Accepted signatures must be strictly longer than this many bytes.
///
/// If ECDSA's alternative field coordinate `r + n` exists, then `r < p-n`
/// and strict DER encodes `r` in at most 17 bytes. Even a 33-byte `s` then
/// makes the complete Bitcoin signature item at most `7 + 17 + 33 = 57`
/// bytes. Rejecting those items makes the nonce point unique up to sign.
pub const AMBIGUOUS_R_MAX_SIGNATURE_SIZE: usize = 57;

/// Errors from construction, signing, digest calculation, and extraction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ThreeCheckError {
    /// `Q` is infinity or equals `T`; both cases are publicly detectable.
    ExceptionalTarget,
    /// The policy-produced script did not contain the expected single separator.
    InvalidScriptShape,
    /// The requested transaction input does not exist.
    InvalidInputIndex,
    /// Scalar or DER signature construction failed.
    InvalidSignature,
    /// The two ordinary legacy digests are equal modulo the group order.
    ReducedSighashCollision,
    /// The supplied signature does not satisfy all three ECDSA equations.
    SignatureVerificationFailed,
    /// Extraction produced no scalar whose public point is the target.
    TargetPointMismatch,
}

/// The two Core legacy `scriptCode` views used by the target-key checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptCodeViews {
    /// The complete locking script with `OP_CODESEPARATOR` removed.
    pub full: ScriptBuf,
    /// The suffix beginning immediately after the executed separator.
    pub suffix: ScriptBuf,
}

/// The reduced legacy digests for the full and suffix `scriptCode` views.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyDigestPair {
    pub full: [u8; 32],
    pub suffix: [u8; 32],
}

/// Derive `Q = -(2*z0/r0)G - T` from the public target alone.
pub fn companion_key(target: PublicKey) -> Result<PublicKey, ThreeCheckError> {
    let secp = Secp256k1::new();
    let offset = secret_from_biguint(&companion_offset_scalar())
        .map_err(|_| ThreeCheckError::InvalidSignature)?;
    let offset_point = PublicKey::from_secret_key(&secp, &offset);
    let companion = offset_point
        .combine(&target.negate(&secp))
        .map_err(|_| ThreeCheckError::ExceptionalTarget)?;
    if companion == target {
        return Err(ThreeCheckError::ExceptionalTarget);
    }
    Ok(companion)
}

/// Construct the complete 79-byte revelation predicate.
///
/// Initial stack: `... signature`. Successful execution leaves `... true`.
pub fn point_lock(target: PublicKey) -> Result<Script, ThreeCheckError> {
    let companion = companion_key(target)?;
    let target = bitcoin::PublicKey::new(target);
    let companion = bitcoin::PublicKey::new(companion);
    Ok(script! {
        OP_SIZE
        { AMBIGUOUS_R_MAX_SIGNATURE_SIZE }
        OP_GREATERTHAN
        OP_VERIFY
        OP_DUP
        { target }
        OP_2DUP
        OP_CHECKSIGVERIFY
        OP_CODESEPARATOR
        OP_CHECKSIGVERIFY
        { companion }
        OP_CHECKSIG
    })
}

/// Return the exact Core legacy `scriptCode` views of the policy-produced lock.
pub fn script_code_views(target: PublicKey) -> Result<ScriptCodeViews, ThreeCheckError> {
    let script = point_lock(target)?.compile_with_policy();
    let mut separators = script
        .instruction_indices()
        .filter_map(|entry| match entry {
            Ok((index, Instruction::Op(op))) if op == OP_CODESEPARATOR => Some(Ok(index)),
            Ok(_) => None,
            Err(_) => Some(Err(ThreeCheckError::InvalidScriptShape)),
        });
    let separator = separators
        .next()
        .ok_or(ThreeCheckError::InvalidScriptShape)??;
    if separators.next().is_some() {
        return Err(ThreeCheckError::InvalidScriptShape);
    }

    let bytes = script.as_bytes();
    let mut full = Vec::with_capacity(bytes.len() - 1);
    full.extend_from_slice(&bytes[..separator]);
    full.extend_from_slice(&bytes[separator + 1..]);
    Ok(ScriptCodeViews {
        full: ScriptBuf::from_bytes(full),
        suffix: ScriptBuf::from_bytes(bytes[separator + 1..].to_vec()),
    })
}

/// Compute both legacy sighashes with rust-bitcoin.
///
/// The raw byte is accepted without applying standardness parsing, matching
/// legacy consensus behavior for undefined sighash flag values.
pub fn legacy_digest_pair(
    transaction: &Transaction,
    input_index: usize,
    target: PublicKey,
    raw_sighash_byte: u8,
) -> Result<LegacyDigestPair, ThreeCheckError> {
    let views = script_code_views(target)?;
    let cache = SighashCache::new(transaction);
    let full = cache
        .legacy_signature_hash(input_index, &views.full, u32::from(raw_sighash_byte))
        .map_err(|_| ThreeCheckError::InvalidInputIndex)?;
    let suffix = cache
        .legacy_signature_hash(input_index, &views.suffix, u32::from(raw_sighash_byte))
        .map_err(|_| ThreeCheckError::InvalidInputIndex)?;
    Ok(LegacyDigestPair {
        full: full.to_byte_array(),
        suffix: suffix.to_byte_array(),
    })
}

/// Parse an arbitrary-consensus-sighash signature item, calculate its two
/// rust-bitcoin legacy digests, and extract the target scalar.
///
/// Unlike `bitcoin::ecdsa::Signature::from_slice`, this deliberately does not
/// reject undefined sighash bytes under standardness rules.
pub fn extract_from_transaction(
    target: PublicKey,
    signature_item: &[u8],
    transaction: &Transaction,
    input_index: usize,
) -> Result<SecretKey, ThreeCheckError> {
    if signature_item.len() <= AMBIGUOUS_R_MAX_SIGNATURE_SIZE {
        return Err(ThreeCheckError::InvalidSignature);
    }
    let (&sighash_byte, der) = signature_item
        .split_last()
        .ok_or(ThreeCheckError::InvalidSignature)?;
    let inner = ecdsa::Signature::from_der(der).map_err(|_| ThreeCheckError::InvalidSignature)?;
    let signature = bitcoin::ecdsa::Signature {
        signature: inner,
        // Extraction and verification below use the separately retained raw
        // byte. This enum value is only a DER serialization container.
        sighash_type: EcdsaSighashType::All,
    };
    let digests = legacy_digest_pair(transaction, input_index, target, sighash_byte)?;
    extract(target, &signature, &digests)
}

/// Create the honest SIGHASH_SINGLE-bug signature with nonce `G/2`.
///
/// Low-S is used when its signature item is longer than 57 bytes. If an
/// unusually short low-S encoding fails the guard, the consensus-equivalent
/// high-S form is returned; it is non-standard under current relay policy.
pub fn sign(target_secret: SecretKey) -> Result<bitcoin::ecdsa::Signature, ThreeCheckError> {
    let signature = sign_with_g_half(
        sighash_single_bug_message(),
        target_secret,
        EcdsaSighashType::Single,
    )
    .map_err(|_| ThreeCheckError::InvalidSignature)?;
    if signature.to_vec().len() > AMBIGUOUS_R_MAX_SIGNATURE_SIZE {
        return Ok(signature);
    }
    high_s_equivalent(&signature)
}

/// Extract the target scalar after verifying all three signature equations.
pub fn extract(
    target: PublicKey,
    signature: &bitcoin::ecdsa::Signature,
    digests: &LegacyDigestPair,
) -> Result<SecretKey, ThreeCheckError> {
    if signature.to_vec().len() <= AMBIGUOUS_R_MAX_SIGNATURE_SIZE {
        return Err(ThreeCheckError::InvalidSignature);
    }
    let companion = companion_key(target)?;
    verify(signature, digests.full, target)?;
    verify(signature, digests.suffix, target)?;
    verify(signature, digests.suffix, companion)?;

    let n = group_order();
    let z_a = BigUint::from_bytes_be(&digests.full) % &n;
    let z_b = BigUint::from_bytes_be(&digests.suffix) % &n;
    let z_0 = BigUint::from_bytes_be(&sighash_single_bug_message()) % &n;

    if z_a == z_0 && z_b == z_0 {
        return extract_known_nonce(target, signature);
    }
    if z_a == z_b {
        return Err(ThreeCheckError::ReducedSighashCollision);
    }

    let (r, _) = signature_scalars(signature);
    let denominator = (BigUint::from(2u8) * r) % &n;
    let numerator = (&n - ((z_a + z_b) % &n)) % &n;
    let candidate = numerator * inverse(&denominator, &n) % &n;
    checked_target_scalar(target, candidate)
}

fn extract_known_nonce(
    target: PublicKey,
    signature: &bitcoin::ecdsa::Signature,
) -> Result<SecretKey, ThreeCheckError> {
    let n = group_order();
    let (r, s) = signature_scalars(signature);
    let r_0 = BigUint::from_bytes_be(&G_HALF_R);
    if r != r_0 {
        return Err(ThreeCheckError::SignatureVerificationFailed);
    }
    let z_0 = BigUint::from_bytes_be(&sighash_single_bug_message()) % &n;
    let k_0 = BigUint::from_bytes_be(
        &g_half_nonce()
            .map_err(|_| ThreeCheckError::InvalidSignature)?
            .secret_bytes(),
    );
    for signed_k in [&k_0, &(&n - &k_0)] {
        let sk = (&s * signed_k) % &n;
        let numerator = if sk >= z_0 {
            &sk - &z_0
        } else {
            &n - (&z_0 - &sk)
        };
        let candidate = numerator * inverse(&r_0, &n) % &n;
        if let Ok(secret) = checked_target_scalar(target, candidate) {
            return Ok(secret);
        }
    }
    Err(ThreeCheckError::TargetPointMismatch)
}

fn verify(
    signature: &bitcoin::ecdsa::Signature,
    digest: [u8; 32],
    public_key: PublicKey,
) -> Result<(), ThreeCheckError> {
    // libsecp256k1's verification API requires low-S. Normalizing here is
    // equivalent for ECDSA verification and lets extraction accept the legacy
    // consensus-valid high-S fallback.
    let mut normalized = signature.signature;
    normalized.normalize_s();
    Secp256k1::verification_only()
        .verify_ecdsa(&Message::from_digest(digest), &normalized, &public_key)
        .map_err(|_| ThreeCheckError::SignatureVerificationFailed)
}

fn checked_target_scalar(target: PublicKey, scalar: BigUint) -> Result<SecretKey, ThreeCheckError> {
    let secret = secret_from_biguint(&scalar).map_err(|_| ThreeCheckError::TargetPointMismatch)?;
    if PublicKey::from_secret_key(&Secp256k1::new(), &secret) == target {
        Ok(secret)
    } else {
        Err(ThreeCheckError::TargetPointMismatch)
    }
}

fn high_s_equivalent(
    signature: &bitcoin::ecdsa::Signature,
) -> Result<bitcoin::ecdsa::Signature, ThreeCheckError> {
    let sighash_type = signature.sighash_type;
    let n = group_order();
    let (r, s) = signature_scalars(signature);
    let high_s = &n - s;
    let mut compact = [0u8; 64];
    compact[..32]
        .copy_from_slice(&scalar_bytes(&r).map_err(|_| ThreeCheckError::InvalidSignature)?);
    compact[32..]
        .copy_from_slice(&scalar_bytes(&high_s).map_err(|_| ThreeCheckError::InvalidSignature)?);
    let signature =
        ecdsa::Signature::from_compact(&compact).map_err(|_| ThreeCheckError::InvalidSignature)?;
    Ok(bitcoin::ecdsa::Signature {
        signature,
        sighash_type,
    })
}

fn companion_offset_scalar() -> BigUint {
    let n = group_order();
    let z_0 = BigUint::from_bytes_be(&sighash_single_bug_message()) % &n;
    let r_0 = BigUint::from_bytes_be(&G_HALF_R);
    let magnitude = (BigUint::from(2u8) * z_0 * inverse(&r_0, &n)) % &n;
    if magnitude.is_zero() {
        BigUint::zero()
    } else {
        &n - magnitude
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute, script::PushBytesBuf, transaction, Amount, OutPoint, Sequence, TxIn, TxOut,
        Witness,
    };
    use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};
    use num_traits::One;

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    fn bug_transaction() -> Transaction {
        Transaction {
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
        }
    }

    fn execute_bug_lock(script: ScriptBuf, signature: Vec<u8>) -> (bool, usize) {
        // The pinned interpreter's legacy FindAndDelete loop underflows when
        // the post-CODESEPARATOR suffix is shorter than the signature. Core
        // does not have that bug. Padding after the terminal check is semantic
        // NOP on the constant-digest path; the unpadded 79-byte lock is what
        // the constructor and metrics report.
        let mut padded = script.into_bytes();
        padded.extend(std::iter::repeat_n(
            bitcoin::opcodes::all::OP_NOP.to_u8(),
            signature.len(),
        ));
        let mut exec = Exec::new(
            ExecCtx::Legacy,
            Options::default(),
            TxTemplate {
                tx: bug_transaction(),
                prevouts: vec![],
                input_idx: 1,
                taproot_annex_scriptleaf: None,
            },
            ScriptBuf::from_bytes(padded),
            vec![signature],
        )
        .unwrap();
        while exec.exec_next().is_ok() {}
        let peak = exec.stats().max_nb_stack_items;
        let success = exec.result().unwrap().success;
        (success, peak)
    }

    #[test]
    fn lock_is_79_bytes_and_has_two_core_scriptcode_views() {
        let target = PublicKey::from_secret_key(&Secp256k1::new(), &key(7));
        let script = point_lock(target).unwrap().compile_with_policy();
        assert_eq!(script.len(), 79);
        let views = script_code_views(target).unwrap();
        assert_eq!(views.full.len(), 78);
        assert_eq!(views.suffix.len(), 36);
        assert_ne!(views.full, views.suffix);
    }

    #[test]
    fn single_bug_signature_executes_and_reveals_target() {
        let secret = key(7);
        let target = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        let signature = sign(secret).unwrap();
        assert_eq!(signature.to_vec().len(), 60);
        let script_sig = bitcoin::script::Builder::new()
            .push_slice(PushBytesBuf::try_from(signature.to_vec()).unwrap())
            .into_script();
        assert_eq!(script_sig.len(), 61);

        let script = point_lock(target).unwrap().compile_with_policy();
        let (success, peak) = execute_bug_lock(script, signature.to_vec());
        assert!(success);
        assert_eq!(peak, 5);

        let digests = legacy_digest_pair(
            &bug_transaction(),
            1,
            target,
            EcdsaSighashType::Single as u8,
        )
        .unwrap();
        assert_eq!(digests.full, sighash_single_bug_message());
        assert_eq!(digests.suffix, sighash_single_bug_message());
        assert_eq!(extract(target, &signature, &digests).unwrap(), secret);
        assert_eq!(
            extract_from_transaction(target, &signature.to_vec(), &bug_transaction(), 1).unwrap(),
            secret
        );
    }

    #[test]
    fn companion_key_accepts_the_same_bug_signature() {
        let secret = key(9);
        let target = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        let companion = companion_key(target).unwrap();
        let signature = sign(secret).unwrap();
        verify(&signature, sighash_single_bug_message(), target).unwrap();
        verify(&signature, sighash_single_bug_message(), companion).unwrap();
    }

    #[test]
    fn rejects_both_publicly_detectable_exceptional_targets() {
        let n = group_order();
        let offset = companion_offset_scalar();
        let infinity_target = secret_from_biguint(&offset).unwrap();
        let inverse_two = (&n + BigUint::one()) >> 1;
        let equal_target = secret_from_biguint(&(offset * inverse_two % &n)).unwrap();
        let secp = Secp256k1::new();
        assert_eq!(
            companion_key(PublicKey::from_secret_key(&secp, &infinity_target)),
            Err(ThreeCheckError::ExceptionalTarget)
        );
        assert_eq!(
            companion_key(PublicKey::from_secret_key(&secp, &equal_target)),
            Err(ThreeCheckError::ExceptionalTarget)
        );
    }

    #[test]
    fn ordinary_opposite_nonce_branch_extracts_without_known_nonce() {
        let n = group_order();
        let secret = key(13);
        let target = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        let t = BigUint::from_bytes_be(&secret.secret_bytes());
        let nonce = key(17);
        let nonce_point = PublicKey::from_secret_key(&Secp256k1::new(), &nonce);
        let r = BigUint::from_bytes_be(&nonce_point.serialize_uncompressed()[1..33]) % &n;
        let c = companion_offset_scalar();
        let inverse_two = (&n + BigUint::one()) >> 1;
        let four_t = BigUint::from(4u8) * &t % &n;
        let c_minus_four_t = if c >= four_t {
            &c - &four_t
        } else {
            &n - (&four_t - &c)
        };
        let z_a = &r * c_minus_four_t % &n * &inverse_two % &n;
        let z_b = (&n - (&r * &c % &n)) % &n * &inverse_two % &n;
        let k = BigUint::from_bytes_be(&nonce.secret_bytes());
        let s = ((&z_a + &r * &t) % &n) * inverse(&k, &n) % &n;

        let mut compact = [0u8; 64];
        compact[..32].copy_from_slice(&scalar_bytes(&r).unwrap());
        compact[32..].copy_from_slice(&scalar_bytes(&s).unwrap());
        let mut inner = ecdsa::Signature::from_compact(&compact).unwrap();
        inner.normalize_s();
        let signature = bitcoin::ecdsa::Signature {
            signature: inner,
            sighash_type: EcdsaSighashType::All,
        };
        assert!(signature.to_vec().len() > AMBIGUOUS_R_MAX_SIGNATURE_SIZE);
        let digests = LegacyDigestPair {
            full: scalar_bytes(&z_a).unwrap(),
            suffix: scalar_bytes(&z_b).unwrap(),
        };
        assert_eq!(extract(target, &signature, &digests).unwrap(), secret);
    }

    #[test]
    fn length_guard_excludes_every_r_plus_n_case() {
        let p = BigUint::parse_bytes(
            b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            16,
        )
        .unwrap();
        let maximum_ambiguous_r = p - group_order() - BigUint::one();
        assert!(maximum_ambiguous_r.bits() <= 129);
        let r_der_bytes = maximum_ambiguous_r.to_bytes_be().len();
        assert_eq!(r_der_bytes, 17);
        assert_eq!(7 + r_der_bytes + 33, AMBIGUOUS_R_MAX_SIGNATURE_SIZE);
    }

    #[test]
    fn accepted_signature_push_cannot_start_at_an_opcode_boundary() {
        let target = PublicKey::from_secret_key(&Secp256k1::new(), &key(7));
        let script = point_lock(target).unwrap().compile_with_policy();
        for entry in script.instruction_indices() {
            let (index, _) = entry.unwrap();
            assert!(
                !(58..=73).contains(&(script.as_bytes()[index] as usize)),
                "an accepted serialized signature push could trigger FindAndDelete"
            );
        }
    }

    #[test]
    fn short_low_s_uses_consensus_valid_high_s_fallback() {
        let n = group_order();
        let r_0 = BigUint::from_bytes_be(&G_HALF_R);
        let z_0 = BigUint::from_bytes_be(&sighash_single_bug_message());
        let k_0 = BigUint::from_bytes_be(&g_half_nonce().unwrap().secret_bytes());
        let numerator = if k_0 >= z_0 {
            &k_0 - &z_0
        } else {
            &n - (&z_0 - &k_0)
        };
        let t = numerator * inverse(&r_0, &n) % &n;
        let secret = secret_from_biguint(&t).unwrap();
        let target = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        let signature = sign(secret).unwrap();
        assert_eq!(signature.to_vec().len(), 61);
        let mut normalized = signature.signature;
        normalized.normalize_s();
        assert!(normalized.serialize_der().len() < AMBIGUOUS_R_MAX_SIGNATURE_SIZE);
        verify(&signature, sighash_single_bug_message(), target).unwrap();
        verify(
            &signature,
            sighash_single_bug_message(),
            companion_key(target).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn ordinary_transaction_produces_distinct_views() {
        let secret = key(7);
        let target = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        let mut transaction = bug_transaction();
        transaction.output.push(TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::new(),
        });
        let digests =
            legacy_digest_pair(&transaction, 1, target, EcdsaSighashType::Single as u8).unwrap();
        assert_ne!(digests.full, digests.suffix);
        assert_ne!(digests.full, sighash_single_bug_message());
    }

    #[test]
    fn size_boundary_and_undefined_sighash_do_not_bypass_the_lock() {
        let secret = key(7);
        let target = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        let script = point_lock(target).unwrap().compile_with_policy();
        assert!(!execute_bug_lock(script, vec![0u8; 57]).0);

        let mut undefined = sign(secret).unwrap().to_vec();
        *undefined.last_mut().unwrap() = 0x04;
        assert_eq!(
            extract_from_transaction(target, &undefined, &bug_transaction(), 1),
            Err(ThreeCheckError::SignatureVerificationFailed)
        );
    }

    #[test]
    fn segwit_v0_has_no_out_of_range_single_digest() {
        let secret = key(7);
        let target = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        let script = point_lock(target).unwrap().compile_with_policy();
        let transaction = bug_transaction();
        let digest = SighashCache::new(&transaction)
            .p2wsh_signature_hash(
                1,
                &script,
                Amount::from_sat(50_000),
                EcdsaSighashType::Single,
            )
            .unwrap();
        assert_ne!(digest.to_byte_array(), sighash_single_bug_message());
        assert_eq!(script.len(), 79);
        assert!(script.to_p2sh().is_p2sh());
    }
}
