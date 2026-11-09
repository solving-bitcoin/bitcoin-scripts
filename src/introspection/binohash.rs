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
        0x4d => {
            if next + 1 >= script.len() {
                return script.len();
            }
            next += 2 + u16::from_le_bytes([script[next], script[next + 1]]) as usize
        }
        0x4e => {
            if next + 3 >= script.len() {
                return script.len();
            }
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
    fn deletes_canonical_pushes_across_pushdata_boundaries() {
        for length in [3, 76, 256] {
            let signature = vec![0x31; length];
            let canonical = push_data(&signature);
            let mut embedded = vec![0xaa];
            embedded.extend_from_slice(&canonical);
            embedded.push(0xbb);
            let embedded_push = push_data(&embedded);
            let script = ScriptBuf::from_bytes(
                [
                    canonical.clone(),
                    embedded_push.clone(),
                    vec![0x51],
                    canonical,
                ]
                .concat(),
            );

            let deleted = find_and_delete(&script, &[signature]);
            assert_eq!(deleted.as_bytes(), [embedded_push, vec![0x51]].concat());
        }
    }

    #[test]
    fn leaves_nonminimal_signature_pushes_untouched() {
        let cases = [
            (vec![0x31; 3], vec![0x4c, 3]),
            (vec![0x31; 76], vec![0x4d, 76, 0]),
            (vec![0x31; 256], vec![0x4e, 0, 1, 0, 0]),
        ];
        for (signature, mut nonminimal) in cases {
            nonminimal.extend_from_slice(&signature);
            let canonical = push_data(&signature);
            let script = ScriptBuf::from_bytes([nonminimal.clone(), canonical].concat());

            let deleted = find_and_delete(&script, &[signature]);
            assert_eq!(deleted.as_bytes(), nonminimal);
        }
    }

    #[test]
    fn malformed_trailing_push_stops_boundary_scanning() {
        let signature = b"sig".to_vec();
        let canonical = push_data(&signature);
        // OP_PUSHDATA1 declares six payload bytes but only five follow. The
        // canonical signature bytes inside that truncated payload are not a
        // subsequent opcode boundary. This is parser-parity coverage only: a
        // script containing this malformed push is not consensus-valid.
        let malformed_tail = [vec![0x4c, 6, 0xaa], canonical.clone()].concat();
        let script = ScriptBuf::from_bytes([canonical, malformed_tail.clone()].concat());

        let deleted = find_and_delete(&script, &[signature]);
        assert_eq!(deleted.as_bytes(), malformed_tail);
    }

    #[test]
    fn incomplete_pushdata_length_headers_stop_boundary_scanning() {
        // A zero byte inside a truncated length header is not an opcode
        // boundary. Core's GetOp stops at the malformed push, including when
        // a matching push was already deleted before it. These scripts are
        // parser-parity fixtures, not consensus-valid locking scripts.
        for malformed in [
            vec![0x4d, 0x00],
            vec![0x4e, 0x00],
            vec![0x4e, 0x00, 0x00],
            vec![0x4e, 0x00, 0x00, 0x00],
        ] {
            let script = ScriptBuf::from_bytes(malformed.clone());
            assert_eq!(find_and_delete(&script, &[vec![]]), script);

            let prefixed = ScriptBuf::from_bytes([vec![0x00], malformed.clone()].concat());
            assert_eq!(find_and_delete(&prefixed, &[vec![]]).as_bytes(), malformed);
        }
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
