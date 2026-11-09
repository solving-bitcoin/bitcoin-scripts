//! Funded legacy P2SH fixture for the committed ECDSA point lock.
//! The generated predicate uses the repository's centralized compile policy.

use bitcoin::{
    absolute,
    consensus::serialize,
    hashes::{hash160, Hash},
    hex::{DisplayHex, FromHex},
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin_lab::{
    introspection::binohash::push_data,
    signatures::pointlocks::{
        committed_point_lock, extract_from_committed, sighash_single_bug_message, sign_committed,
        signature_commitment,
    },
    support::script::ScriptCompilation,
};
use serde_json::{json, Value};
use std::str::FromStr;

const INPUT_VALUE: u64 = 1_000_000;
const FEE: u64 = 20_000;

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

fn input(txid: Txid, vout: u32, script_sig: ScriptBuf) -> TxIn {
    TxIn {
        previous_output: OutPoint { txid, vout },
        script_sig,
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }
}

fn point_script_sig(signature: &[u8], redeem: &[u8]) -> ScriptBuf {
    ScriptBuf::from_bytes([push_data(signature), push_data(redeem)].concat())
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
    let public_signing_secret = SecretKey::from_slice(&[2_u8; 32]).unwrap();
    let point_secret = SecretKey::from_slice(&[3_u8; 32]).unwrap();
    let other_point_secret = SecretKey::from_slice(&[4_u8; 32]).unwrap();
    let signing_pubkey = PublicKey::from_secret_key(&secp, &public_signing_secret);
    let target_point = PublicKey::from_secret_key(&secp, &point_secret);
    let signature = sign_committed(public_signing_secret, point_secret).unwrap();
    let substitute = sign_committed(public_signing_secret, other_point_secret).unwrap();
    let signature_bytes = signature.serialize();
    let substitute_bytes = substitute.serialize();
    assert_ne!(signature_bytes, substitute_bytes);
    let commitment = signature_commitment(&signature);
    let redeem = committed_point_lock(signing_pubkey, commitment).compile_with_policy();
    assert!(redeem.len() <= 520);
    let extracted =
        extract_from_committed(&signature, public_signing_secret, target_point).unwrap();
    assert_eq!(PublicKey::from_secret_key(&secp, &extracted), target_point);
    let easy_redeem = ScriptBuf::from_bytes(vec![0x51]);
    let output = |value| TxOut {
        value: Amount::from_sat(value),
        script_pubkey: destination.clone(),
    };
    let valid = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            input(
                funding_txid,
                0,
                ScriptBuf::from_bytes(push_data(easy_redeem.as_bytes())),
            ),
            input(
                funding_txid,
                1,
                point_script_sig(&signature_bytes, redeem.as_bytes()),
            ),
        ],
        output: vec![output(2 * INPUT_VALUE - FEE)],
    };
    let mut wrong_signature = valid.clone();
    wrong_signature.input[1].script_sig = point_script_sig(&substitute_bytes, redeem.as_bytes());
    let mut added_output = valid.clone();
    added_output.output[0].value = Amount::from_sat(2 * INPUT_VALUE - FEE - 1_000);
    added_output.output.push(output(1_000));

    json!({
        "experiment": "binohash-committed-point-core",
        "funding_txid": funding_txid.to_string(),
        "input_value_sat": INPUT_VALUE,
        "fee_sat": FEE,
        "signing_pubkey_hex": signing_pubkey.serialize().to_lower_hex_string(),
        "public_signing_scalar_hex": public_signing_secret.secret_bytes().to_lower_hex_string(),
        "target_point_hex": target_point.serialize().to_lower_hex_string(),
        "expected_point_secret_hex": point_secret.secret_bytes().to_lower_hex_string(),
        "extracted_point_secret_hex": extracted.secret_bytes().to_lower_hex_string(),
        "signature_hex": signature_bytes.to_lower_hex_string(),
        "signature_bytes": signature_bytes.len(),
        "substitute_signature_hex": substitute_bytes.to_lower_hex_string(),
        "signature_commitment_hex": commitment.to_byte_array().to_lower_hex_string(),
        "bug_digest_hex": sighash_single_bug_message().to_lower_hex_string(),
        "redeem_script_hex": redeem.as_bytes().to_lower_hex_string(),
        "redeem_script_bytes": redeem.len(),
        "point_script_pubkey_hex": p2sh(redeem.as_bytes()).as_bytes().to_lower_hex_string(),
        "point_script_pubkey_bytes": p2sh(redeem.as_bytes()).len(),
        "easy_script_pubkey_hex": p2sh(easy_redeem.as_bytes()).as_bytes().to_lower_hex_string(),
        "hint_items": 0,
        "witness_items": 0,
        "destination_script_pubkey_hex": destination.as_bytes().to_lower_hex_string(),
        "transactions": {
            "valid": transaction_record(&valid),
            "wrong_signature": transaction_record(&wrong_signature),
            "added_output": transaction_record(&added_output),
        },
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: binohash_committed_point_core FUNDING_TXID DESTINATION_SCRIPT_HEX"
    );
    let funding_txid = Txid::from_str(&args[1]).expect("funding txid");
    let destination = ScriptBuf::from_bytes(Vec::from_hex(&args[2]).expect("destination hex"));
    println!("{}", generate(funding_txid, destination));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_signature_extracts_target_and_uses_complete_script() {
        let fixture = generate(
            Txid::from_byte_array([0_u8; 32]),
            ScriptBuf::from_bytes(vec![0x51]),
        );
        assert_eq!(
            fixture["expected_point_secret_hex"],
            fixture["extracted_point_secret_hex"]
        );
        assert!(fixture["redeem_script_bytes"].as_u64().unwrap() <= 520);
        assert_eq!(fixture["transactions"]["valid"]["output_count"], 1);
        assert_eq!(fixture["transactions"]["added_output"]["output_count"], 2);
        assert_ne!(
            fixture["signature_hex"],
            fixture["substitute_signature_hex"]
        );
        assert_eq!(fixture["signature_bytes"], 71);
        assert_eq!(fixture["point_script_pubkey_bytes"], 23);
        // This unit vector uses a one-byte OP_TRUE destination; the funded
        // Core fixture uses its longer deterministic mining destination.
        assert_eq!(fixture["transactions"]["valid"]["weight"], 992);
        assert_eq!(
            fixture["transactions"]["valid"]["input_script_sig_bytes"],
            json!([2, 144])
        );
    }
}
