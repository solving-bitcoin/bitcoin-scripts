//! Deterministic Binohash-style legacy sighash mutation.
//!
//! This is a host-side legacy transaction primitive, not a tapscript fragment.
//! It models the opcode-boundary FindAndDelete step used by legacy
//! `OP_CHECKMULTISIG` before calculating a legacy signature hash.

use bitcoin::{hashes::Hash, sighash::SighashCache, Script, ScriptBuf, Transaction};

/// Errors returned by the deterministic Binohash digest helper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BinohashError {
    /// A selected dummy-signature index is outside the supplied candidate set.
    InvalidSelection,
    /// The requested transaction input does not exist.
    InvalidInputIndex,
}

/// Encode one byte vector as a Bitcoin Script push.
pub fn push_data(data: &[u8]) -> Vec<u8> {
    match data.len() {
        0..=75 => std::iter::once(data.len() as u8)
            .chain(data.iter().copied())
            .collect(),
        76..=255 => std::iter::once(0x4c)
            .chain(std::iter::once(data.len() as u8))
            .chain(data.iter().copied())
            .collect(),
        256..=0xffff => std::iter::once(0x4d)
            .chain((data.len() as u16).to_le_bytes())
            .chain(data.iter().copied())
            .collect(),
        _ => std::iter::once(0x4e)
            .chain((data.len() as u32).to_le_bytes())
            .chain(data.iter().copied())
            .collect(),
    }
}

fn next_sop(script: &[u8], index: usize) -> usize {
    if index >= script.len() {
        return script.len();
    }
    let opcode = script[index];
    let mut next = index + 1;
    match opcode {
        0x01..=0x4b => next += opcode as usize,
        0x4c if next < script.len() => next += 1 + script[next] as usize,
        0x4d if next + 1 < script.len() => {
            next += 2 + u16::from_le_bytes([script[next], script[next + 1]]) as usize
        }
        0x4e if next + 3 < script.len() => {
            next += 4 + u32::from_le_bytes([
                script[next],
                script[next + 1],
                script[next + 2],
                script[next + 3],
            ]) as usize
        }
        _ => {}
    }
    next.min(script.len())
}

fn find_and_delete_one(script: &[u8], pushed_signature: &[u8]) -> Vec<u8> {
    if pushed_signature.is_empty() {
        return script.to_vec();
    }
    let mut output = Vec::with_capacity(script.len());
    let mut last_sop = 0;
    let mut sop = 0;
    let mut skip = true;

    while sop < script.len() {
        if !skip {
            output.extend_from_slice(&script[last_sop..sop]);
        }
        last_sop = sop;
        skip = script[sop..].starts_with(pushed_signature);
        sop = next_sop(script, sop);
    }
    if !skip {
        output.extend_from_slice(&script[last_sop..]);
    }
    output
}

/// Remove each selected signature push at Script opcode boundaries.
pub fn find_and_delete(script_code: &Script, signatures: &[Vec<u8>]) -> ScriptBuf {
    signatures.iter().fold(
        ScriptBuf::from_bytes(script_code.as_bytes().to_vec()),
        |script, signature| {
            ScriptBuf::from_bytes(find_and_delete_one(
                script.as_bytes(),
                &push_data(signature),
            ))
        },
    )
}

/// Calculate a Binohash-style digest for a chosen subset of dummy signatures.
pub fn binohash_digest(
    transaction: &Transaction,
    input_index: usize,
    script_code: &Script,
    dummy_signatures: &[Vec<u8>],
    selected_indices: &[usize],
    hash_type: u32,
) -> Result<[u8; 32], BinohashError> {
    let mut selected = Vec::with_capacity(selected_indices.len());
    for &index in selected_indices {
        selected.push(
            dummy_signatures
                .get(index)
                .ok_or(BinohashError::InvalidSelection)?
                .clone(),
        );
    }
    let modified = find_and_delete(script_code, &selected);
    SighashCache::new(transaction)
        .legacy_signature_hash(input_index, &modified, hash_type)
        .map(|digest| digest.to_byte_array())
        .map_err(|_| BinohashError::InvalidInputIndex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{absolute, transaction, Amount, OutPoint, Sequence, TxIn, TxOut, Witness};

    fn transaction_with_two_outputs() -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
                TxOut {
                    value: Amount::from_sat(2_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
            ],
        }
    }

    #[test]
    fn deletes_only_opcode_aligned_signature_pushes() {
        let signature = b"sig".to_vec();
        let script = ScriptBuf::from_bytes(
            [
                push_data(&signature),
                push_data(b"sig inside data"),
                vec![0x51],
                push_data(&signature),
            ]
            .concat(),
        );
        let deleted = find_and_delete(&script, &[signature]);
        assert_eq!(
            deleted.as_bytes(),
            &[
                0x0f, b's', b'i', b'g', b' ', b'i', b'n', b's', b'i', b'd', b'e', b' ', b'd', b'a',
                b't', b'a', 0x51
            ]
        );
    }

    #[test]
    fn subset_selection_changes_legacy_digest() {
        let transaction = transaction_with_two_outputs();
        let signatures = vec![b"sig0".to_vec(), b"sig1".to_vec(), b"sig2".to_vec()];
        let script = ScriptBuf::from_bytes(
            signatures
                .iter()
                .flat_map(|signature| push_data(signature))
                .chain([0x51])
                .collect(),
        );
        let empty = binohash_digest(&transaction, 0, &script, &signatures, &[], 1).unwrap();
        let one = binohash_digest(&transaction, 0, &script, &signatures, &[1], 1).unwrap();
        assert_ne!(empty, one);
    }

    #[test]
    fn reproduces_legacy_single_bug_digest() {
        let mut transaction = transaction_with_two_outputs();
        let script = ScriptBuf::new();
        let digest = binohash_digest(&transaction, 0, &script, &[], &[], 3).unwrap();
        let bug_digest = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        assert_ne!(digest, bug_digest);

        transaction.input.push(transaction.input[0].clone());
        transaction.output.pop();
        let digest = binohash_digest(&transaction, 1, &script, &[], &[], 3).unwrap();
        assert_eq!(digest, bug_digest);
    }

    #[test]
    fn rejects_invalid_selection_and_input() {
        let transaction = transaction_with_two_outputs();
        let script = ScriptBuf::new();
        assert_eq!(
            binohash_digest(&transaction, 0, &script, &[], &[0], 1),
            Err(BinohashError::InvalidSelection)
        );
        assert_eq!(
            binohash_digest(&transaction, 2, &script, &[], &[], 1),
            Err(BinohashError::InvalidInputIndex)
        );
    }
}
