//! Nine-byte embedded ECDSA signature anchored to legacy SIGHASH_SINGLE's z=1 bug.
//! Raw bytecode is intentional: FindAndDelete of the embedded signature is under test.

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

fn input(txid: Txid, vout: u32, redeem: &[u8]) -> TxIn {
    TxIn {
        previous_output: OutPoint { txid, vout },
        script_sig: ScriptBuf::from_bytes(push_data(redeem)),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }
}

fn transaction_record(tx: &Transaction) -> Value {
    json!({
        "hex": serialize(tx).to_lower_hex_string(),
        "txid": tx.compute_txid().to_string(),
        "weight": tx.weight().to_wu(),
        "vsize": tx.vsize(),
        "base_bytes": tx.base_size(),
        "total_bytes": tx.total_size(),
        "input_script_sig_bytes": tx.input.iter().map(|input| input.script_sig.len()).collect::<Vec<_>>(),
        "input_vouts": tx.input.iter().map(|input| input.previous_output.vout).collect::<Vec<_>>(),
        "output_count": tx.output.len(),
    })
}

fn generate(funding_txid: Txid, destination: ScriptBuf) -> Value {
    let secp = Secp256k1::new();
    let mut compact = [0_u8; 64];
    compact[31] = 1; // r=1
    compact[63] = 1; // s=1
    let mut constant_digest = [0_u8; 32];
    constant_digest[0] = 1;
    let message = Message::from_digest(constant_digest);
    let recoverable =
        RecoverableSignature::from_compact(&compact, RecoveryId::from_i32(0).unwrap()).unwrap();
    let recovered = secp.recover_ecdsa(&message, &recoverable).unwrap();
    let signature = Signature::from_der(&ANCHOR[..8]).unwrap();
    secp.verify_ecdsa(&message, &signature, &recovered).unwrap();
    let anchor_pubkey = recovered.serialize();
    let anchor_redeem =
        ScriptBuf::from_bytes([push_data(&ANCHOR), push_data(&anchor_pubkey), vec![0xac]].concat());
    let easy_redeem = ScriptBuf::from_bytes(vec![0x51]);
    let output = |value| TxOut {
        value: Amount::from_sat(value),
        script_pubkey: destination.clone(),
    };
    let valid = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            input(funding_txid, 0, easy_redeem.as_bytes()),
            input(funding_txid, 1, anchor_redeem.as_bytes()),
        ],
        output: vec![output(2 * INPUT_VALUE - FEE)],
    };
    let mut added_output = valid.clone();
    added_output.output[0].value = Amount::from_sat(2 * INPUT_VALUE - FEE - 1_000);
    added_output.output.push(output(1_000));
    let mut moved_to_input_zero = valid.clone();
    moved_to_input_zero.input.swap(0, 1);

    let digest = |tx: &Transaction, index| {
        binohash_digest(tx, index, &anchor_redeem, &[ANCHOR.to_vec()], &[0], 3).unwrap()
    };
    let bug_digest = digest(&valid, 1);
    assert_eq!(bug_digest, constant_digest);
    let added_output_digest = digest(&added_output, 1);
    let moved_input_digest = digest(&moved_to_input_zero, 0);
    assert_ne!(bug_digest, added_output_digest);
    assert_ne!(bug_digest, moved_input_digest);
    json!({
        "experiment": "binohash-nine-byte-single-anchor",
        "funding_txid": funding_txid.to_string(),
        "input_value_sat": INPUT_VALUE,
        "fee_sat": FEE,
        "anchor_signature_hex": ANCHOR.to_lower_hex_string(),
        "anchor_signature_bytes": ANCHOR.len(),
        "anchor_pubkey_hex": anchor_pubkey.to_lower_hex_string(),
        "anchor_redeem_script_hex": anchor_redeem.as_bytes().to_lower_hex_string(),
        "anchor_redeem_script_bytes": anchor_redeem.len(),
        "anchor_script_pubkey_hex": p2sh(anchor_redeem.as_bytes()).as_bytes().to_lower_hex_string(),
        "easy_script_pubkey_hex": p2sh(easy_redeem.as_bytes()).as_bytes().to_lower_hex_string(),
        "destination_script_pubkey_hex": destination.as_bytes().to_lower_hex_string(),
        "local_digests": {
            "valid_hex": bug_digest.to_lower_hex_string(),
            "added_output_hex": added_output_digest.to_lower_hex_string(),
            "moved_input_hex": moved_input_digest.to_lower_hex_string(),
        },
        "transactions": {
            "valid": transaction_record(&valid),
            "added_output": transaction_record(&added_output),
            "moved_input": transaction_record(&moved_to_input_zero),
        },
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: binohash_single_bug_anchor FUNDING_TXID DESTINATION_SCRIPT_HEX"
    );
    let funding_txid = Txid::from_str(&args[1]).expect("funding txid");
    let destination = ScriptBuf::from_bytes(Vec::from_hex(&args[2]).expect("destination hex"));
    println!("{}", generate(funding_txid, destination));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nine_byte_anchor_and_boundary_digests() {
        let fixture = generate(
            Txid::from_byte_array([0_u8; 32]),
            ScriptBuf::from_bytes(vec![0x51]),
        );
        assert_eq!(fixture["anchor_signature_bytes"], 9);
        assert_eq!(fixture["transactions"]["valid"]["output_count"], 1);
        assert_eq!(fixture["transactions"]["added_output"]["output_count"], 2);
        assert_eq!(fixture["transactions"]["moved_input"]["input_vouts"][0], 1);
    }

    #[test]
    fn malformed_minimal_der_length_is_rejected() {
        assert_eq!(ANCHOR[1] as usize, ANCHOR.len() - 3);
        let mut wrong_length = ANCHOR;
        wrong_length[1] = 7;
        assert!(Signature::from_der(&wrong_length[..8]).is_err());
    }
}
