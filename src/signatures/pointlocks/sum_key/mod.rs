//! ECDSA point locks for the sum of two verification keys.
//!
//! For distinct keys P,Q, one signature accepted by both at the same digest z
//! reveals log_G(P+Q) = -2z/r. The length guard excludes r+n recovery cases.
//! The common-generator setup makes Q=G and generates independent targets from
//! caller-selected nonces. No signature hash commitment or ZKP is needed.

use super::{
    group_order, inverse, secret_from_biguint, sighash_single_bug_message, sign_with_nonce,
    signature_scalars,
};
use crate::support::script::{script, Script, ScriptCompilation};
use bitcoin::{
    hashes::Hash,
    secp256k1::{ecdsa, Message, PublicKey, Secp256k1, SecretKey},
    sighash::SighashCache,
    EcdsaSighashType, Transaction,
};
use num_bigint::BigUint;

/// Strict DER plus the sighash byte is at most 57 bytes whenever r+n < p.
pub const AMBIGUOUS_R_MAX_SIGNATURE_SIZE: usize = 57;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    EqualVerificationKeys,
    InfiniteTarget,
    InvalidSignature,
    InvalidInputIndex,
    SignatureVerificationFailed,
    TargetPointMismatch,
    /// A caller-supplied nonce produced a degenerate or too-short signature.
    UnusableNonce,
}

/// Public points together with the unrevealed opening and target scalar.
/// No Debug implementation: logging the signature also reveals the scalar.
pub struct CommonGeneratorSetup {
    pub target: PublicKey,
    pub verification_key: PublicKey,
    signature: bitcoin::ecdsa::Signature,
    target_secret: SecretKey,
}

impl CommonGeneratorSetup {
    /// The opening itself is secret until publication.
    pub fn signature(&self) -> &bitcoin::ecdsa::Signature {
        &self.signature
    }

    /// Explicit access to the generated target's secret scalar.
    pub fn target_secret(&self) -> SecretKey {
        self.target_secret
    }
}

/// The common public verification key, with intentionally public scalar one.
pub fn generator_key() -> PublicKey {
    PublicKey::from_secret_key(
        &Secp256k1::new(),
        &secret_from_biguint(&BigUint::from(1u8)).expect("one is a valid scalar"),
    )
}

/// Validate both verification keys and return the point whose scalar is locked.
/// Valid secp256k1 encodings are enforced by the PublicKey argument type.
pub fn target_point(first: PublicKey, second: PublicKey) -> Result<PublicKey, Error> {
    if first == second {
        return Err(Error::EqualVerificationKeys);
    }
    first.combine(&second).map_err(|_| Error::InfiniteTarget)
}

/// Complete predicate: `... sigma -> ... true`, with no auxiliary hints.
/// The caller checks that first+second equals its intended target point.
pub fn point_lock(first: PublicKey, second: PublicKey) -> Result<Script, Error> {
    target_point(first, second)?;
    Ok(script! {
        OP_SIZE { AMBIGUOUS_R_MAX_SIGNATURE_SIZE } OP_GREATERTHAN OP_VERIFY
        OP_DUP { first.serialize().to_vec() } OP_CHECKSIGVERIFY
        { second.serialize().to_vec() } OP_CHECKSIG
    })
}

/// Common-G predicate locking log_G(verification_key+G).
/// Rejects verification_key=G and verification_key=-G.
pub fn common_generator_lock(verification_key: PublicKey) -> Result<Script, Error> {
    point_lock(verification_key, generator_key())
}

/// Generate a common-G target from a caller-selected independent nonce.
///
/// r=x(kG) mod n, t=-2C/r, T=tG, P=T-G, and the opening is the low-S ECDSA
/// signature on C with public signing scalar one and nonce k. This generates
/// T; it does not provide an opening for an arbitrary previously selected T.
/// No randomness is supplied by this API. Never reuse/publicize a nonce.
/// The inherited bigint signing helpers are research-only and not constant-time.
pub fn setup_from_nonce(nonce: SecretKey) -> Result<CommonGeneratorSetup, Error> {
    setup_for_digest(nonce, sighash_single_bug_message())
}

fn setup_for_digest(nonce: SecretKey, digest: [u8; 32]) -> Result<CommonGeneratorSetup, Error> {
    let one = secret_from_biguint(&BigUint::from(1u8)).expect("one is a valid scalar");
    let signature = sign_with_nonce(digest, one, nonce, EcdsaSighashType::Single)
        .map_err(|_| Error::UnusableNonce)?;
    if signature.to_vec().len() <= AMBIGUOUS_R_MAX_SIGNATURE_SIZE {
        return Err(Error::UnusableNonce);
    }
    let n = group_order();
    let (r, _) = signature_scalars(&signature);
    let z = BigUint::from_bytes_be(&digest) % &n;
    let scalar = (&n - BigUint::from(2u8) * z * inverse(&r, &n) % &n) % &n;
    let target_secret = secret_from_biguint(&scalar).map_err(|_| Error::UnusableNonce)?;
    let secp = Secp256k1::new();
    let target = PublicKey::from_secret_key(&secp, &target_secret);
    let verification_key = target
        .combine(&generator_key().negate(&secp))
        .map_err(|_| Error::UnusableNonce)?;
    if target_point(verification_key, generator_key()).map_err(|_| Error::UnusableNonce)? != target
    {
        return Err(Error::UnusableNonce);
    }
    let extracted = extract_from_digest(
        verification_key,
        generator_key(),
        &signature.to_vec(),
        digest,
    )?;
    if extracted != target_secret {
        return Err(Error::TargetPointMismatch);
    }
    Ok(CommonGeneratorSetup {
        target,
        verification_key,
        signature,
        target_secret,
    })
}

fn parse(signature_item: &[u8]) -> Result<(ecdsa::Signature, u8), Error> {
    if signature_item.len() <= AMBIGUOUS_R_MAX_SIGNATURE_SIZE || signature_item.len() > 73 {
        return Err(Error::InvalidSignature);
    }
    let (&flag, der) = signature_item.split_last().ok_or(Error::InvalidSignature)?;
    let signature = ecdsa::Signature::from_der(der).map_err(|_| Error::InvalidSignature)?;
    if signature.serialize_der().as_ref() != der {
        return Err(Error::InvalidSignature);
    }
    Ok((signature, flag))
}

/// Verify both ECDSA equations at a caller-supplied actual digest, then extract.
/// Handles low-S and consensus-valid high-S encodings. This helper verifies
/// algebra, not the origin of the supplied digest or a funded prevout.
pub fn extract_from_digest(
    first: PublicKey,
    second: PublicKey,
    signature_item: &[u8],
    digest: [u8; 32],
) -> Result<SecretKey, Error> {
    let target = target_point(first, second)?;
    let (mut signature, _) = parse(signature_item)?;
    let r = BigUint::from_bytes_be(&signature.serialize_compact()[..32]);
    signature.normalize_s();
    let message = Message::from_digest(digest);
    let secp = Secp256k1::new();
    for key in [first, second] {
        secp.verify_ecdsa(&message, &signature, &key)
            .map_err(|_| Error::SignatureVerificationFailed)?;
    }
    let n = group_order();
    let z = BigUint::from_bytes_be(&digest) % &n;
    let scalar = (&n - BigUint::from(2u8) * z * inverse(&r, &n) % &n) % &n;
    let extracted = secret_from_biguint(&scalar).map_err(|_| Error::TargetPointMismatch)?;
    if PublicKey::from_secret_key(&secp, &extracted) != target {
        return Err(Error::TargetPointMismatch);
    }
    Ok(extracted)
}

/// Compute the actual legacy digest for the exact policy-compiled single lock,
/// verify both checks, and extract the locked sum scalar for any accepted flag.
/// This is a transcript helper, not a prevout/full-transaction validator.
/// A batched script requires its complete scriptCode and extract_from_digest.
pub fn extract_from_transaction(
    first: PublicKey,
    second: PublicKey,
    signature_item: &[u8],
    transaction: &Transaction,
    input_index: usize,
) -> Result<SecretKey, Error> {
    if input_index >= transaction.input.len() {
        return Err(Error::InvalidInputIndex);
    }
    let (_, flag) = parse(signature_item)?;
    let script = point_lock(first, second)?.compile_with_policy();
    // The script has no CODESEPARATOR and pushes only 33-byte keys. An accepted
    // signature item is >57 bytes, so its pushed encoding cannot occur at an
    // opcode boundary: native legacy FindAndDelete leaves scriptCode unchanged.
    let digest = SighashCache::new(transaction)
        .legacy_signature_hash(input_index, &script, u32::from(flag))
        .map_err(|_| Error::InvalidInputIndex)?
        .to_byte_array();
    extract_from_digest(first, second, signature_item, digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness,
    };
    use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};

    fn tx() -> Transaction {
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
    fn setup() -> CommonGeneratorSetup {
        setup_from_nonce(SecretKey::from_slice(&[7; 32]).unwrap()).unwrap()
    }
    fn execute(script: ScriptBuf, item: Vec<u8>) -> (bool, usize) {
        let mut exec = Exec::new(
            ExecCtx::Legacy,
            Options::default(),
            TxTemplate {
                tx: tx(),
                prevouts: vec![],
                input_idx: 1,
                taproot_annex_scriptleaf: None,
            },
            script,
            vec![item],
        )
        .unwrap();
        while exec.exec_next().is_ok() {}
        (
            exec.result().unwrap().success && exec.stack().len() == 1,
            exec.stats().max_nb_stack_items,
        )
    }
    #[test]
    fn constant_digest_execution_and_extraction() {
        let s = setup();
        let p = s.verification_key;
        let g = generator_key();
        assert_eq!(target_point(p, g), Ok(s.target));
        let script = common_generator_lock(p).unwrap().compile_with_policy();
        assert_eq!(script.len(), 76);
        assert_eq!(execute(script, s.signature().to_vec()), (true, 3));
        assert_eq!(
            extract_from_transaction(p, g, &s.signature().to_vec(), &tx(), 1),
            Ok(s.target_secret())
        );
        assert_eq!(
            extract_from_transaction(p, g, &s.signature().to_vec(), &tx(), 2),
            Err(Error::InvalidInputIndex)
        );
        assert!(extract_from_transaction(p, g, &s.signature().to_vec(), &tx(), 0).is_err());
    }
    #[test]
    fn reject_equal_keys_and_infinite_sum() {
        let g = generator_key();
        assert_eq!(target_point(g, g), Err(Error::EqualVerificationKeys));
        assert!(common_generator_lock(g).is_err());
        assert_eq!(
            target_point(g, g.negate(&Secp256k1::new())),
            Err(Error::InfiniteTarget)
        );
        assert!(common_generator_lock(g.negate(&Secp256k1::new())).is_err());
    }
    #[test]
    fn reject_malformed_short_wrong_flag_and_wrong_key() {
        let s = setup();
        let p = s.verification_key;
        let g = generator_key();
        let script = common_generator_lock(p).unwrap().compile_with_policy();
        for len in [0, 57, 58, 73, 74] {
            let item = vec![0; len];
            assert!(!execute(script.clone(), item.clone()).0);
            assert_eq!(
                extract_from_transaction(p, g, &item, &tx(), 1),
                Err(Error::InvalidSignature)
            );
        }
        let mut wrong_flag = s.signature().to_vec();
        *wrong_flag.last_mut().unwrap() = 1;
        assert!(!execute(script, wrong_flag.clone()).0);
        assert!(extract_from_transaction(p, g, &wrong_flag, &tx(), 1).is_err());
        let wrong_key = setup_from_nonce(SecretKey::from_slice(&[8; 32]).unwrap())
            .unwrap()
            .verification_key;
        assert_eq!(
            extract_from_digest(
                wrong_key,
                g,
                &s.signature().to_vec(),
                sighash_single_bug_message()
            ),
            Err(Error::SignatureVerificationFailed)
        );
    }
    #[test]
    fn synthetic_ordinary_digest_still_extracts_sum() {
        let digest = [0x23; 32];
        let s = setup_for_digest(SecretKey::from_slice(&[9; 32]).unwrap(), digest).unwrap();
        assert_eq!(
            extract_from_digest(
                s.verification_key,
                generator_key(),
                &s.signature().to_vec(),
                digest
            ),
            Ok(s.target_secret())
        );
        // Synthetic digest algebra does not establish a native ordinary spend.
        assert!(extract_from_transaction(
            s.verification_key,
            generator_key(),
            &s.signature().to_vec(),
            &tx(),
            1
        )
        .is_err());
    }
    #[test]
    fn zero_digest_cannot_pass_for_nonzero_sum() {
        let s = setup();
        assert_eq!(
            extract_from_digest(
                s.verification_key,
                generator_key(),
                &s.signature().to_vec(),
                [0; 32]
            ),
            Err(Error::SignatureVerificationFailed)
        );
    }
    #[test]
    fn distinct_nonces_generate_distinct_candidate_rows() {
        let first = setup();
        let second = setup_from_nonce(SecretKey::from_slice(&[8; 32]).unwrap()).unwrap();
        assert_ne!(first.target, second.target);
        assert!(extract_from_digest(
            second.verification_key,
            generator_key(),
            &first.signature().to_vec(),
            sighash_single_bug_message()
        )
        .is_err());
        // Negated nonce has the same x-coordinate and therefore same target;
        // pool setup must explicitly reject duplicate rows, not merely nonces.
        let opposite = setup_from_nonce(SecretKey::from_slice(&[7; 32]).unwrap().negate()).unwrap();
        assert_eq!(first.target, opposite.target);
    }
    #[test]
    fn high_s_and_undefined_legacy_flag_extract_same_scalar() {
        let s = setup();
        let sig = s.signature();
        let (r, low_s) = signature_scalars(sig);
        let mut compact = [0; 64];
        compact[..32].copy_from_slice(&super::super::scalar_bytes(&r).unwrap());
        compact[32..]
            .copy_from_slice(&super::super::scalar_bytes(&(group_order() - low_s)).unwrap());
        let high = ecdsa::Signature::from_compact(&compact).unwrap();
        let mut item = high.serialize_der().to_vec();
        item.push(0x23);
        assert_eq!(
            extract_from_transaction(s.verification_key, generator_key(), &item, &tx(), 1),
            Ok(s.target_secret())
        );
        // High-S / undefined hash flags are consensus-transcript cases, not
        // current relay-policy claims or local interpreter success claims.
    }
}
