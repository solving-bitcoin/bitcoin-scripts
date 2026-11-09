//! Signed legacy P2SH field-mutation fixtures for the six canonical sighash modes.
//!
//! This isolates transaction-field commitments. The signature is in scriptSig,
//! not embedded in scriptCode, so it does not reproduce Binohash grinding.

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

const MODES: [(u8, &str); 6] = [
    (0x01, "ALL"),
    (0x02, "NONE"),
    (0x03, "SINGLE"),
    (0x81, "ALL|ANYONECANPAY"),
    (0x82, "NONE|ANYONECANPAY"),
    (0x83, "SINGLE|ANYONECANPAY"),
];
const INPUT_VALUE: u64 = 100_000;
const EXPECTED: [[bool; 6]; 8] = [
    [true; 6],
    [true; 6],
    [true; 6],
    [true; 6],
    [true, true, true, false, false, false],
    [true, false, false, false, false, false],
    [true, false, true, true, false, true],
    [true, false, false, true, false, false],
];
const MUTATIONS: [&str; 8] = [
    "version",
    "locktime",
    "selected prevout",
    "selected sequence",
    "other prevout",
    "other sequence",
    "selected output",
    "other output",
];

fn p2sh(script: &[u8]) -> ScriptBuf {
    ScriptBuf::from_bytes(
        [
            vec![0xa9, 0x14],
            hash160::Hash::hash(script).to_byte_array().to_vec(),
            vec![0x87],
        ]
        .concat(),
    )
}

fn record(tx: &Transaction) -> Value {
    json!({
        "hex": serialize(tx).to_lower_hex_string(),
        "txid": tx.compute_txid().to_string(),
        "weight": tx.weight().to_wu(),
        "base_bytes": tx.base_size(),
        "total_bytes": tx.total_size(),
        "script_sig_bytes": tx.input.iter().map(|input| input.script_sig.len()).collect::<Vec<_>>(),
    })
}

fn digest(tx: &Transaction, redeem: &ScriptBuf, mode: u8) -> [u8; 32] {
    binohash_digest(tx, 1, redeem, &[], &[], u32::from(mode)).unwrap()
}

fn mutate(tx: &mut Transaction, case: usize, mode_index: usize) {
    match case {
        0 => tx.version = transaction::Version::ONE,
        // Height 1 is already mature on the funded regtest chain.
        1 => tx.lock_time = absolute::LockTime::from_consensus(1),
        2 => tx.input[1].previous_output.vout = (4 * mode_index + 3) as u32,
        // Keep BIP68 disabled and preserve finality for every sequence case.
        3 => tx.input[1].sequence = Sequence(0xffff_fffa),
        4 => tx.input[0].previous_output.vout = (4 * mode_index + 2) as u32,
        5 => tx.input[0].sequence = Sequence(0xffff_fff9),
        6 => tx.output[1].value = Amount::from_sat(90_001),
        7 => tx.output[0].value = Amount::from_sat(90_001),
        _ => unreachable!(),
    }
}

fn generate(funding_txid: Txid, destination: ScriptBuf) -> Value {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[7; 32]).unwrap();
    let public = PublicKey::from_secret_key(&secp, &secret).serialize();
    let redeem = ScriptBuf::from_bytes([push_data(&public), vec![0xac]].concat());
    let easy_redeem = ScriptBuf::from_bytes(vec![0x51]);
    let selected_lock = p2sh(redeem.as_bytes());
    let other_lock = p2sh(easy_redeem.as_bytes());
    let mut rows = Vec::new();
    for (mode_index, (mode, name)) in MODES.iter().enumerate() {
        let input = |vout: u32, script_sig: ScriptBuf, sequence: u32| TxIn {
            previous_output: OutPoint {
                txid: funding_txid,
                vout,
            },
            script_sig,
            sequence: Sequence(sequence),
            witness: Witness::new(),
        };
        let mut base = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![
                input(
                    (4 * mode_index) as u32,
                    ScriptBuf::from_bytes(push_data(easy_redeem.as_bytes())),
                    0xffff_fffe,
                ),
                input((4 * mode_index + 1) as u32, ScriptBuf::new(), 0xffff_fffd),
            ],
            output: vec![
                TxOut {
                    value: Amount::from_sat(90_000),
                    script_pubkey: destination.clone(),
                },
                TxOut {
                    value: Amount::from_sat(90_000),
                    script_pubkey: destination.clone(),
                },
            ],
        };
        let baseline_digest = digest(&base, &redeem, *mode);
        let mut signature = secp
            .sign_ecdsa(&Message::from_digest(baseline_digest), &secret)
            .serialize_der()
            .to_vec();
        signature.push(*mode);
        base.input[1].script_sig =
            ScriptBuf::from_bytes([push_data(&signature), push_data(redeem.as_bytes())].concat());
        let variants: Vec<Value> = MUTATIONS
            .iter()
            .enumerate()
            .map(|(case, label)| {
                let mut changed = base.clone();
                mutate(&mut changed, case, mode_index);
                let changed_digest = digest(&changed, &redeem, *mode);
                let digest_changed = changed_digest != baseline_digest;
                assert_eq!(
                    digest_changed, EXPECTED[case][mode_index],
                    "{name}: {label}"
                );
                json!({
                    "mutation": label,
                    "expected_digest_change": EXPECTED[case][mode_index],
                    "digest_changed": digest_changed,
                    "local_digest_hex": changed_digest.to_lower_hex_string(),
                    "transaction": record(&changed),
                })
            })
            .collect();
        rows.push(json!({
            "flag": mode,
            "mode": name,
            "local_digest_hex": baseline_digest.to_lower_hex_string(),
            "signature_bytes": signature.len(),
            "baseline": record(&base),
            "variants": variants,
        }));
    }
    json!({
        "experiment": "binohash-signed-six-mode-field-matrix",
        "funding_txid": funding_txid.to_string(),
        "input_value_sat": INPUT_VALUE,
        "redeem_script_hex": redeem.as_bytes().to_lower_hex_string(),
        "redeem_script_bytes": redeem.len(),
        "selected_script_pubkey_hex": selected_lock.as_bytes().to_lower_hex_string(),
        "other_redeem_script_hex": easy_redeem.as_bytes().to_lower_hex_string(),
        "other_script_pubkey_hex": other_lock.as_bytes().to_lower_hex_string(),
        "destination_script_pubkey_hex": destination.as_bytes().to_lower_hex_string(),
        "rows": rows,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: binohash_signed_sighash_matrix FUNDING_TXID DESTINATION_SCRIPT_HEX"
    );
    let funding_txid = Txid::from_str(&args[1]).expect("funding txid");
    let destination = ScriptBuf::from_bytes(Vec::from_hex(&args[2]).expect("destination script"));
    println!("{}", generate(funding_txid, destination));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_has_six_modes_and_eight_mutations_each() {
        let fixture = generate(
            Txid::from_byte_array([0; 32]),
            ScriptBuf::from_bytes(vec![0x51]),
        );
        assert_eq!(fixture["redeem_script_bytes"], 35);
        let rows = fixture["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 6);
        for (index, row) in rows.iter().enumerate() {
            assert_eq!(row["flag"], MODES[index].0);
            assert_eq!(row["variants"].as_array().unwrap().len(), 8);
            assert_ne!(
                row["baseline"]["txid"],
                row["variants"][0]["transaction"]["txid"]
            );
        }
    }
}
