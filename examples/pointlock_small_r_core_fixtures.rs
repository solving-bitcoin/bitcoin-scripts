//! Deterministic, funded legacy P2SH G/2 point-lock fixture for pinned Core.
//! The test scalar is public; these helpers are not production signing code.

use bitcoin::{
    absolute,
    consensus::serialize,
    hashes::{hash160, Hash},
    hex::{DisplayHex, FromHex},
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey},
    sighash::SighashCache,
    transaction, Amount, EcdsaSighashType, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};
use bitcoin_lab::{
    introspection::binohash::push_data,
    signatures::pointlocks::{
        extract_from_g_half, g_half_point_lock, sign_with_g_half, G_HALF_MAX_SIGNATURE_SIZE,
    },
    support::script::ScriptCompilation,
};
use serde_json::{json, Value};
use std::str::FromStr;

const INPUT_VALUE: u64 = 1_000_000;
const FEE: u64 = 20_000;

fn p2sh(redeem: &ScriptBuf) -> ScriptBuf {
    let hash = hash160::Hash::hash(redeem.as_bytes());
    ScriptBuf::from_bytes([vec![0xa9, 0x14], hash.to_byte_array().to_vec(), vec![0x87]].concat())
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

fn with_signature(tx: &Transaction, signature: &[u8], redeem: &ScriptBuf) -> Transaction {
    let mut spend = tx.clone();
    spend.input[0].script_sig =
        ScriptBuf::from_bytes([push_data(signature), push_data(redeem.as_bytes())].concat());
    spend
}

fn generate(funding_txid: Txid, destination: ScriptBuf) -> Value {
    let secp = Secp256k1::new();
    let point_secret = SecretKey::from_slice(&[7; 32]).unwrap();
    let point = PublicKey::from_secret_key(&secp, &point_secret);
    let redeem = g_half_point_lock(point).compile_with_policy();
    assert_eq!(redeem.len(), 40);
    let base = Transaction {
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
    let message = SighashCache::new(&base)
        .legacy_signature_hash(0, &redeem, EcdsaSighashType::All as u32)
        .unwrap()
        .to_byte_array();
    let honest_signature = sign_with_g_half(message, point_secret, EcdsaSighashType::All).unwrap();
    let extracted = extract_from_g_half(message, &honest_signature, point).unwrap();
    assert_eq!(extracted, point_secret);
    let honest_bytes = honest_signature.to_vec();
    assert!(honest_bytes.len() <= G_HALF_MAX_SIGNATURE_SIZE);
    let ordinary_signature = bitcoin::ecdsa::Signature {
        signature: secp.sign_ecdsa(&Message::from_digest(message), &point_secret),
        sighash_type: EcdsaSighashType::All,
    };
    let ordinary_bytes = ordinary_signature.to_vec();
    assert!(ordinary_bytes.len() > G_HALF_MAX_SIGNATURE_SIZE);
    let honest = with_signature(&base, &honest_bytes, &redeem);
    let length_control = with_signature(&base, &ordinary_bytes, &redeem);
    assert_ne!(honest.compute_txid(), length_control.compute_txid());
    json!({
        "experiment": "pointlock-g-half-funded-p2sh-core",
        "funding_txid": funding_txid.to_string(),
        "input_value_sat": INPUT_VALUE,
        "fee_sat": FEE,
        "point_secret_hex": point_secret.secret_bytes().to_lower_hex_string(),
        "point_compressed_hex": point.serialize().to_lower_hex_string(),
        "legacy_sighash_all_hex": message.to_lower_hex_string(),
        "redeem_script_hex": redeem.as_bytes().to_lower_hex_string(),
        "redeem_script_bytes": redeem.len(),
        "p2sh_script_pubkey_hex": p2sh(&redeem).as_bytes().to_lower_hex_string(),
        "destination_script_pubkey_hex": destination.as_bytes().to_lower_hex_string(),
        "honest_signature_hex": honest_bytes.to_lower_hex_string(),
        "honest_signature_bytes": honest_bytes.len(),
        "ordinary_signature_hex": ordinary_bytes.to_lower_hex_string(),
        "ordinary_signature_bytes": ordinary_bytes.len(),
        "extracted_secret_matches": extracted == point_secret,
        "honest": transaction_record(&honest),
        "length_control": transaction_record(&length_control),
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: pointlock_small_r_core_fixtures FUNDING_TXID DESTINATION_SCRIPT_HEX"
    );
    let funding_txid = Txid::from_str(&args[1]).expect("funding txid");
    let destination = ScriptBuf::from_bytes(Vec::from_hex(&args[2]).expect("destination hex"));
    println!("{}", generate(funding_txid, destination));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honest_and_length_control_share_message_but_differ_in_size() {
        let fixture = generate(
            Txid::from_str(&"00".repeat(32)).unwrap(),
            ScriptBuf::from_bytes(vec![0x51]),
        );
        assert!(fixture["extracted_secret_matches"].as_bool().unwrap());
        assert!(fixture["honest_signature_bytes"].as_u64().unwrap() <= 60);
        assert!(fixture["ordinary_signature_bytes"].as_u64().unwrap() > 60);
        assert_ne!(fixture["honest"]["txid"], fixture["length_control"]["txid"]);
        assert_eq!(
            fixture["honest"]["weight"],
            fixture["honest"]["base_bytes"].as_u64().unwrap() * 4
        );
    }
}
