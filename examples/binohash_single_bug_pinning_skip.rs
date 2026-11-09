//! Adversarial field mutations that retain an embedded legacy SIGHASH_SINGLE bug signature.
//! Raw redeemScript bytes are intentional: FindAndDelete of the signature is under test.

use bitcoin::{
    absolute,
    consensus::serialize,
    hashes::{hash160, Hash},
    hex::{DisplayHex, FromHex},
    secp256k1::{
        ecdsa::{RecoverableSignature, RecoveryId, Signature},
        Message, Secp256k1,
    },
    transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin_lab::introspection::binohash::{binohash_digest, push_data};
use serde_json::{json, Value};
use std::str::FromStr;

const INPUT_VALUE: u64 = 1_000_000;
const FEE: u64 = 20_000;
const ANCHOR: [u8; 9] = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x03];
const MUTATIONS: [&str; 9] = [
    "version",
    "locktime",
    "selected prevout",
    "selected sequence",
    "other prevout",
    "other sequence",
    "output value",
    "output script",
    "all eight fields",
];

fn p2sh(redeem: &[u8]) -> ScriptBuf {
    ScriptBuf::from_bytes(
        [
            vec![0xa9, 0x14],
            hash160::Hash::hash(redeem).to_byte_array().to_vec(),
            vec![0x87],
        ]
        .concat(),
    )
}

fn input(txid: Txid, vout: u32, redeem: &[u8], sequence: u32) -> TxIn {
    TxIn {
        previous_output: OutPoint { txid, vout },
        script_sig: ScriptBuf::from_bytes(push_data(redeem)),
        sequence: Sequence(sequence),
        witness: Witness::new(),
    }
}

fn record(tx: &Transaction) -> Value {
    json!({
        "hex": serialize(tx).to_lower_hex_string(),
        "txid": tx.compute_txid().to_string(),
        "weight": tx.weight().to_wu(),
        "base_bytes": tx.base_size(),
        "total_bytes": tx.total_size(),
        "script_sig_bytes": tx.input.iter().map(|i| i.script_sig.len()).collect::<Vec<_>>(),
        "input_vouts": tx.input.iter().map(|i| i.previous_output.vout).collect::<Vec<_>>(),
        "output_count": tx.output.len(),
    })
}

fn mutate(tx: &mut Transaction, case: usize, pair: usize, alternate_script: &ScriptBuf) {
    if case == 0 || case == 8 {
        tx.version = transaction::Version::ONE;
    }
    if case == 1 || case == 8 {
        tx.lock_time = absolute::LockTime::from_consensus(1);
    }
    if case == 2 || case == 8 {
        tx.input[1].previous_output.vout = (4 * pair + 3) as u32;
    }
    if case == 3 || case == 8 {
        tx.input[1].sequence = Sequence(0xffff_fffa);
    }
    if case == 4 || case == 8 {
        tx.input[0].previous_output.vout = (4 * pair + 2) as u32;
    }
    if case == 5 || case == 8 {
        tx.input[0].sequence = Sequence(0xffff_fff9);
    }
    if case == 6 || case == 8 {
        tx.output[0].value = Amount::from_sat(2 * INPUT_VALUE - FEE - 1);
    }
    if case == 7 || case == 8 {
        tx.output[0].script_pubkey = alternate_script.clone();
    }
}

fn generate(funding_txid: Txid, destination: ScriptBuf) -> Value {
    let secp = Secp256k1::new();
    let mut compact = [0_u8; 64];
    compact[31] = 1;
    compact[63] = 1;
    let mut constant_digest = [0_u8; 32];
    constant_digest[0] = 1;
    let message = Message::from_digest(constant_digest);
    let recovered = secp
        .recover_ecdsa(
            &message,
            &RecoverableSignature::from_compact(&compact, RecoveryId::from_i32(0).unwrap())
                .unwrap(),
        )
        .unwrap();
    secp.verify_ecdsa(
        &message,
        &Signature::from_der(&ANCHOR[..8]).unwrap(),
        &recovered,
    )
    .unwrap();
    let anchor_redeem = ScriptBuf::from_bytes(
        [
            push_data(&ANCHOR),
            push_data(&recovered.serialize()),
            vec![0xac],
        ]
        .concat(),
    );
    let easy_redeem = ScriptBuf::from_bytes(vec![0x51]);
    let easy_lock = p2sh(easy_redeem.as_bytes());
    let anchor_lock = p2sh(anchor_redeem.as_bytes());
    let output = |script_pubkey: ScriptBuf| TxOut {
        value: Amount::from_sat(2 * INPUT_VALUE - FEE),
        script_pubkey,
    };
    let baseline = |pair: usize| Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            input(
                funding_txid,
                (4 * pair) as u32,
                easy_redeem.as_bytes(),
                0xffff_fffe,
            ),
            input(
                funding_txid,
                (4 * pair + 1) as u32,
                anchor_redeem.as_bytes(),
                0xffff_fffd,
            ),
        ],
        output: vec![output(destination.clone())],
    };
    let digest = |tx: &Transaction, input_index| {
        binohash_digest(tx, input_index, &anchor_redeem, &[ANCHOR.to_vec()], &[0], 3).unwrap()
    };
    let rows: Vec<Value> = MUTATIONS
        .iter()
        .enumerate()
        .map(|(case, name)| {
            let mut tx = baseline(case);
            mutate(&mut tx, case, case, &easy_lock);
            let local_digest = digest(&tx, 1);
            assert_eq!(local_digest, constant_digest, "{name}");
            json!({"mutation": name, "local_digest_hex": local_digest.to_lower_hex_string(),
               "transaction": record(&tx)})
        })
        .collect();
    let mut added_output = baseline(9);
    added_output.output[0].value = Amount::from_sat(2 * INPUT_VALUE - FEE - 1_000);
    added_output.output.push(TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: destination.clone(),
    });
    let mut moved_input = baseline(10);
    moved_input.input.swap(0, 1);
    let control_added_digest = digest(&added_output, 1);
    let control_moved_digest = digest(&moved_input, 0);
    assert_ne!(control_added_digest, constant_digest);
    assert_ne!(control_moved_digest, constant_digest);
    json!({
        "experiment": "binohash-single-bug-pinning-skip",
        "funding_txid": funding_txid.to_string(),
        "input_value_sat": INPUT_VALUE,
        "fee_sat": FEE,
        "anchor_signature_hex": ANCHOR.to_lower_hex_string(),
        "anchor_signature_bytes": ANCHOR.len(),
        "anchor_pubkey_hex": recovered.serialize().to_lower_hex_string(),
        "anchor_redeem_script_hex": anchor_redeem.as_bytes().to_lower_hex_string(),
        "anchor_redeem_script_bytes": anchor_redeem.len(),
        "anchor_script_pubkey_hex": anchor_lock.as_bytes().to_lower_hex_string(),
        "easy_script_pubkey_hex": easy_lock.as_bytes().to_lower_hex_string(),
        "destination_script_pubkey_hex": destination.as_bytes().to_lower_hex_string(),
        "bug_digest_hex": constant_digest.to_lower_hex_string(),
        "rows": rows,
        "controls": {
            "added_output": {"local_digest_hex": control_added_digest.to_lower_hex_string(),
                             "transaction": record(&added_output), "anchor_input_index": 1},
            "moved_input": {"local_digest_hex": control_moved_digest.to_lower_hex_string(),
                            "transaction": record(&moved_input), "anchor_input_index": 0},
        },
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: binohash_single_bug_pinning_skip FUNDING_TXID DESTINATION_SCRIPT_HEX"
    );
    let funding_txid = Txid::from_str(&args[1]).expect("funding txid");
    let destination = ScriptBuf::from_bytes(Vec::from_hex(&args[2]).expect("destination script"));
    println!("{}", generate(funding_txid, destination));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutations_keep_bug_digest_and_controls_cross_boundary() {
        let fixture = generate(
            Txid::from_byte_array([0; 32]),
            ScriptBuf::from_bytes(vec![0x51]),
        );
        assert_eq!(fixture["anchor_signature_bytes"], 9);
        assert_eq!(fixture["rows"].as_array().unwrap().len(), 9);
        for row in fixture["rows"].as_array().unwrap() {
            assert_eq!(row["local_digest_hex"], fixture["bug_digest_hex"]);
            assert_eq!(row["transaction"]["output_count"], 1);
        }
        for control in ["added_output", "moved_input"] {
            assert_ne!(
                fixture["controls"][control]["local_digest_hex"],
                fixture["bug_digest_hex"]
            );
        }
    }
}
