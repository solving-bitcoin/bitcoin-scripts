//! Deterministic legacy P2SH spends for the 256 raw ECDSA sighash bytes.
//!
//! The byte is consensus data but only six encodings pass default STRICTENC
//! policy. Public test keys and one-input spends do not reproduce Binohash.

use bitcoin::{
    absolute,
    consensus::serialize,
    hashes::{hash160, Hash},
    hex::{DisplayHex, FromHex},
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey},
    transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin_lab::introspection::binohash::{binohash_digest, push_data};
use serde_json::{json, Value};
use std::str::FromStr;

const INPUT_VALUE: u64 = 100_000;
const FEE: u64 = 10_000;
const CANONICAL: [u8; 6] = [0x01, 0x02, 0x03, 0x81, 0x82, 0x83];

fn p2sh(script: &[u8]) -> ScriptBuf {
    let digest = hash160::Hash::hash(script);
    ScriptBuf::from_bytes(
        [
            vec![0xa9, 0x14],
            digest.to_byte_array().to_vec(),
            vec![0x87],
        ]
        .concat(),
    )
}

fn transaction_record(tx: &Transaction) -> Value {
    json!({
        "hex": serialize(tx).to_lower_hex_string(),
        "txid": tx.compute_txid().to_string(),
        "weight": tx.weight().to_wu(),
        "vsize": tx.vsize(),
        "base_bytes": tx.base_size(),
        "total_bytes": tx.total_size(),
        "script_sig_bytes": tx.input[0].script_sig.len(),
    })
}

fn generate(funding_txid: Txid, destination: ScriptBuf) -> Value {
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&[7; 32]).unwrap();
    let pubkey = PublicKey::from_secret_key(&secp, &key).serialize();
    let redeem = ScriptBuf::from_bytes([push_data(&pubkey), vec![0xac]].concat());
    let lock = p2sh(redeem.as_bytes());
    let mut wrong_flag_transaction = None;
    let rows: Vec<Value> = (0..=255_u8)
        .map(|flag| {
            let mut tx = Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: funding_txid,
                        vout: flag as u32,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(INPUT_VALUE - FEE),
                    script_pubkey: destination.clone(),
                }],
            };
            let digest = binohash_digest(&tx, 0, &redeem, &[], &[], flag as u32).unwrap();
            let mut signature = secp
                .sign_ecdsa(&Message::from_digest(digest), &key)
                .serialize_der()
                .to_vec();
            signature.push(flag);
            if flag == 0x01 {
                let mut wrong = tx.clone();
                let mut wrong_signature = signature.clone();
                *wrong_signature.last_mut().unwrap() = 0x21;
                wrong.input[0].script_sig = ScriptBuf::from_bytes(
                    [push_data(&wrong_signature), push_data(redeem.as_bytes())].concat(),
                );
                wrong_flag_transaction = Some(transaction_record(&wrong));
            }
            tx.input[0].script_sig = ScriptBuf::from_bytes(
                [push_data(&signature), push_data(redeem.as_bytes())].concat(),
            );
            json!({
                "flag": flag,
                "canonical": CANONICAL.contains(&flag),
                "local_digest_hex": digest.to_lower_hex_string(),
                "signature_bytes": signature.len(),
                "transaction": transaction_record(&tx),
            })
        })
        .collect();
    let fixed_template = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: funding_txid,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(INPUT_VALUE - FEE),
            script_pubkey: destination.clone(),
        }],
    };
    let fixed_template_digests: Vec<String> = (0..=255_u8)
        .map(|flag| {
            binohash_digest(&fixed_template, 0, &redeem, &[], &[], flag as u32)
                .unwrap()
                .to_lower_hex_string()
        })
        .collect();
    json!({
        "experiment": "binohash-raw-sighash-byte-census",
        "funding_txid": funding_txid.to_string(),
        "input_value_sat": INPUT_VALUE,
        "fee_sat": FEE,
        "redeem_script_hex": redeem.as_bytes().to_lower_hex_string(),
        "redeem_script_bytes": redeem.len(),
        "p2sh_script_pubkey_hex": lock.as_bytes().to_lower_hex_string(),
        "destination_script_pubkey_hex": destination.as_bytes().to_lower_hex_string(),
        "fixed_template_digests_hex": fixed_template_digests,
        "wrong_flag_transaction": wrong_flag_transaction.unwrap(),
        "results": rows,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: binohash_sighash_flag_fixtures FUNDING_TXID DESTINATION_SCRIPT_HEX"
    );
    let funding_txid = Txid::from_str(&args[1]).expect("funding txid");
    let destination = ScriptBuf::from_bytes(Vec::from_hex(&args[2]).expect("destination hex"));
    println!("{}", generate(funding_txid, destination));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_256_flags_have_distinct_local_digests_and_six_canonical_encodings() {
        let fixture = generate(
            Txid::from_byte_array([0; 32]),
            ScriptBuf::from_bytes(vec![0x51]),
        );
        let rows = fixture["results"].as_array().unwrap();
        assert_eq!(rows.len(), 256);
        assert_eq!(
            rows.iter().filter(|row| row["canonical"] == true).count(),
            6
        );
        let digests: std::collections::HashSet<_> = rows
            .iter()
            .map(|row| row["local_digest_hex"].as_str().unwrap())
            .collect();
        assert_eq!(digests.len(), 256);
        let fixed_digests = fixture["fixed_template_digests_hex"].as_array().unwrap();
        assert_eq!(fixed_digests.len(), 256);
        assert_eq!(
            fixed_digests
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            256
        );
        assert_eq!(fixture["redeem_script_bytes"], 35);
    }
}
