//! HASH160-committed two-check legacy ECDSA point lock.
//!
//! Constant-digest spends reveal the target scalar. Excluding non-extractable
//! ordinary transaction digests remains an open assumption; see README.md.
use super::two_check;
use crate::support::script::{script, Script, ScriptCompilation};
use bitcoin::{
    hashes::{hash160, Hash},
    secp256k1::{ecdsa, PublicKey, SecretKey},
    sighash::SighashCache,
    EcdsaSighashType, Transaction,
};

pub use super::two_check::{companion_key, sign};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    CommitmentMismatch,
    TwoCheck(two_check::TwoCheckError),
}

impl From<two_check::TwoCheckError> for Error {
    fn from(error: two_check::TwoCheckError) -> Self {
        Self::TwoCheck(error)
    }
}

/// Hash the exact DER signature and its sighash byte, without normalization.
pub fn signature_commitment(signature: &bitcoin::ecdsa::Signature) -> hash160::Hash {
    hash160::Hash::hash(&signature.to_vec())
}

/// Complete predicate: `... signature -> ... true`, with no hint items.
/// Derives and validates the companion key instead of accepting a supplied key.
pub fn point_lock(target: PublicKey, commitment: hash160::Hash) -> Result<Script, Error> {
    let checks = two_check::point_lock(target)?;
    Ok(script! {
        OP_DUP OP_HASH160 { commitment.to_byte_array().to_vec() } OP_EQUALVERIFY
        { checks }
    })
}

/// Verify the byte-exact commitment and both ECDSA equations using this
/// construction's full scriptCode. Returns NonConstantDigest for a valid
/// ordinary-digest signature whose scalar extraction is not established.
/// This is a transcript helper, not a full transaction/prevout validator.
pub fn extract_from_transaction(
    target: PublicKey,
    commitment: hash160::Hash,
    signature_item: &[u8],
    transaction: &Transaction,
    input_index: usize,
) -> Result<SecretKey, Error> {
    if hash160::Hash::hash(signature_item) != commitment {
        return Err(Error::CommitmentMismatch);
    }
    let (&flag, der) = signature_item
        .split_last()
        .ok_or(two_check::TwoCheckError::InvalidSignature)?;
    let inner =
        ecdsa::Signature::from_der(der).map_err(|_| two_check::TwoCheckError::InvalidSignature)?;
    let signature = bitcoin::ecdsa::Signature {
        signature: inner,
        // Container only: retain the actual raw flag for the digest below.
        sighash_type: EcdsaSighashType::All,
    };
    let script = point_lock(target, commitment)?.compile_with_policy();
    let digest = SighashCache::new(transaction)
        .legacy_signature_hash(input_index, &script, u32::from(flag))
        .map_err(|_| two_check::TwoCheckError::InvalidInputIndex)?
        .to_byte_array();
    Ok(two_check::extract(target, &signature, digest)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{
        absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness,
    };
    use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};

    fn transaction() -> Transaction {
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

    fn execute(script: ScriptBuf, items: Vec<Vec<u8>>) -> (bool, usize) {
        let mut exec = Exec::new(
            ExecCtx::Legacy,
            Options::default(),
            TxTemplate {
                tx: transaction(),
                prevouts: vec![],
                input_idx: 1,
                taproot_annex_scriptleaf: None,
            },
            script,
            items,
        )
        .unwrap();
        while exec.exec_next().is_ok() {}
        (
            exec.result().unwrap().success,
            exec.stats().max_nb_stack_items,
        )
    }

    #[test]
    fn commitment_execution_and_extraction() {
        let secret = SecretKey::from_slice(&[7; 32]).unwrap();
        let target = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        let signature = sign(secret).unwrap();
        let h = signature_commitment(&signature);
        let script = point_lock(target, h).unwrap().compile_with_policy();
        assert_eq!(script.len(), 100);
        assert_eq!(execute(script.clone(), vec![signature.to_vec()]), (true, 3));
        assert_eq!(
            extract_from_transaction(target, h, &signature.to_vec(), &transaction(), 1),
            Ok(secret)
        );
        assert!(
            extract_from_transaction(target, h, &signature.to_vec(), &transaction(), 0).is_err()
        );
        assert!(
            extract_from_transaction(target, h, &signature.to_vec(), &transaction(), 2).is_err()
        );
        let mut changed = signature.to_vec();
        *changed.last_mut().unwrap() = 0x83;
        assert!(!execute(script, vec![changed.clone()]).0);
        assert_eq!(
            extract_from_transaction(target, h, &changed, &transaction(), 1),
            Err(Error::CommitmentMismatch)
        );
        // Even a matching commitment must not bypass DER and size validation.
        for len in [0, 57, 58, 73] {
            let malformed = vec![0; len];
            let h = hash160::Hash::hash(&malformed);
            assert!(
                !execute(
                    point_lock(target, h).unwrap().compile_with_policy(),
                    vec![malformed.clone()]
                )
                .0
            );
            assert!(extract_from_transaction(target, h, &malformed, &transaction(), 1).is_err());
        }
    }

    #[test]
    fn five_distinct_locks_compose_with_seven_stack_items() {
        let mut locks = Vec::new();
        let mut items = Vec::new();
        for byte in 7..12 {
            let secret = SecretKey::from_slice(&[byte; 32]).unwrap();
            let target = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
            let signature = sign(secret).unwrap();
            locks.push(point_lock(target, signature_commitment(&signature)).unwrap());
            items.push(signature.to_vec());
        }
        let script = script! {
            for i in 0..5 {
                { locks[i].clone() }
                if i < 4 { OP_VERIFY }
            }
        }
        .compile_with_policy();
        assert_eq!(script.len(), 500);
        items.reverse();
        assert_eq!(execute(script.clone(), items.clone()), (true, 7));
        items.swap(0, 1);
        assert!(!execute(script, items).0);
    }
}
