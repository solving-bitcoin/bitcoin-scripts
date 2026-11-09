//! Fixed-template host probe of the paper's 10-choose-5 nonce-pool example.
//! These are legacy digest calculations, not valid signatures or Core spends.

use bitcoin::{
    absolute, hashes::Hash, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness,
};
use bitcoin_lab::introspection::binohash::{binohash_digest, push_data, BinohashError};
use itertools::Itertools;
use std::collections::HashSet;

const POOL: usize = 10;
const SELECTED: usize = 5;

fn fixture() -> (Transaction, ScriptBuf, Vec<Vec<u8>>) {
    // Distinct 9-byte DER-shaped values with SIGHASH_SINGLE byte 03. They
    // represent candidate deletion targets, not validated ECDSA signatures.
    let signatures: Vec<Vec<u8>> = (1..=POOL)
        .map(|r| vec![0x30, 0x06, 0x02, 0x01, r as u8, 0x02, 0x01, 0x01, 0x03])
        .collect();
    let script_code = ScriptBuf::from_bytes(
        signatures
            .iter()
            .flat_map(|signature| push_data(signature))
            .chain([0x51])
            .collect(),
    );
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([7; 32]),
                vout: 1,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    (tx, script_code, signatures)
}

#[test]
fn all_252_canonical_subsets_have_distinct_local_digests() {
    let (tx, script, signatures) = fixture();
    assert_eq!(script.len(), 101);
    let mut digests = HashSet::new();
    let mut subsets = 0;
    for subset in (0..POOL).combinations(SELECTED) {
        assert!(subset.windows(2).all(|pair| pair[0] < pair[1]));
        let digest = binohash_digest(&tx, 0, &script, &signatures, &subset, 0x01).unwrap();
        assert!(
            digests.insert(digest),
            "fixed-template digest collision: {subset:?}"
        );
        subsets += 1;
    }
    assert_eq!(subsets, 252);
    assert_eq!(digests.len(), 252);
}

#[test]
fn order_and_duplicate_aliases_require_script_side_canonicalization() {
    let (tx, script, signatures) = fixture();
    let canonical = [0, 2, 4, 6, 8];
    let reversed = [8, 6, 4, 2, 0];
    assert_eq!(
        binohash_digest(&tx, 0, &script, &signatures, &canonical, 0x01),
        binohash_digest(&tx, 0, &script, &signatures, &reversed, 0x01)
    );
    assert_eq!(
        binohash_digest(&tx, 0, &script, &signatures, &[0, 0, 2, 4, 6], 0x01),
        binohash_digest(&tx, 0, &script, &signatures, &[0, 2, 4, 6], 0x01)
    );
    assert_eq!(
        binohash_digest(&tx, 0, &script, &signatures, &[0, 2, 4, 6, 10], 0x01),
        Err(BinohashError::InvalidSelection)
    );
}
