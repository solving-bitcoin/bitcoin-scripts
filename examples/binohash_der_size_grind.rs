//! Deterministic low-difficulty ECDSA nonce grind for an exact DER size.

use bitcoin::{
    absolute,
    consensus::serialize,
    hashes::{hash160, sha256, Hash},
    hex::{DisplayHex, FromHex},
    script::Instruction,
    secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey},
    sighash::SighashCache,
    transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin_lab::introspection::binohash::push_data;
use bitcoin_lab::support::script::{script, ScriptCompilation};
use serde_json::{json, Value};
use std::str::FromStr;

const INPUT_VALUE: u64 = 1_000_000;
const FEE: u64 = 10_000;
const TARGET_BYTES: usize = 70;
const MAX_ATTEMPTS: u32 = 10_000;
const FLAG: u8 = 0x01;
const SEED: [u8; 32] = [0x5a; 32];

fn p2sh(redeem: &[u8]) -> ScriptBuf {
    let hash = hash160::Hash::hash(redeem);
    ScriptBuf::from_bytes([vec![0xa9, 0x14], hash.to_byte_array().to_vec(), vec![0x87]].concat())
}

fn record(tx: &Transaction) -> Value {
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

fn nonce_data(counter: u32) -> [u8; 32] {
    let mut preimage = SEED.to_vec();
    preimage.extend_from_slice(&counter.to_le_bytes());
    sha256::Hash::hash(&preimage).to_byte_array()
}

fn signed_tx(base: &Transaction, signature: &[u8], redeem: &ScriptBuf) -> Transaction {
    let mut tx = base.clone();
    tx.input[0].script_sig =
        ScriptBuf::from_bytes([push_data(signature), push_data(redeem.as_bytes())].concat());
    tx
}

fn generate(funding: Txid, destination: ScriptBuf) -> Value {
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&[42; 32]).unwrap();
    let pubkey = PublicKey::from_secret_key(&secp, &key).serialize().to_vec();
    let redeem = script! {
        OP_SIZE { TARGET_BYTES as i64 } OP_EQUALVERIFY { pubkey.clone() } OP_CHECKSIG
    }
    .compile_with_policy();
    let static_non_push_opcodes = redeem
        .instructions()
        .map(|item| item.expect("valid policy-produced script"))
        .filter(|item| matches!(item, Instruction::Op(_)))
        .count();
    assert_eq!(static_non_push_opcodes, 3);
    let locking = p2sh(redeem.as_bytes());
    let base = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: funding,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(INPUT_VALUE - FEE),
            script_pubkey: destination,
        }],
    };
    let digest = SighashCache::new(&base)
        .legacy_signature_hash(0, &redeem, u32::from(FLAG))
        .unwrap()
        .to_byte_array();
    let message = Message::from_digest(digest);
    let mut first_other = None;
    let mut selected = None;
    for counter in 0..MAX_ATTEMPTS {
        let der = secp
            .sign_ecdsa_with_noncedata(&message, &key, &nonce_data(counter))
            .serialize_der();
        let mut signature = der.to_vec();
        signature.push(FLAG);
        if signature.len() == TARGET_BYTES {
            selected = Some((counter, signature));
            break;
        }
        if first_other.is_none() {
            first_other = Some((counter, signature));
        }
    }
    let (counter, good) = selected.expect("deterministic nonce search exceeded bound");
    let (other_counter, wrong_size) = first_other.expect("missing non-target size control");
    let good_der = Signature::from_der(&good[..good.len() - 1]).unwrap();
    let wrong_size_der = Signature::from_der(&wrong_size[..wrong_size.len() - 1]).unwrap();
    secp.verify_ecdsa(
        &message,
        &good_der,
        &PublicKey::from_slice(&pubkey).unwrap(),
    )
    .unwrap();
    secp.verify_ecdsa(
        &message,
        &wrong_size_der,
        &PublicKey::from_slice(&pubkey).unwrap(),
    )
    .unwrap();
    let mut wrong_ecdsa = good.clone();
    let last_der_byte = wrong_ecdsa.len() - 2;
    wrong_ecdsa[last_der_byte] ^= 1;
    let corrupted = Signature::from_der(&wrong_ecdsa[..wrong_ecdsa.len() - 1]).unwrap();
    assert!(secp
        .verify_ecdsa(
            &message,
            &corrupted,
            &PublicKey::from_slice(&pubkey).unwrap()
        )
        .is_err());
    let valid = signed_tx(&base, &good, &redeem);
    let invalid_size = signed_tx(&base, &wrong_size, &redeem);
    let invalid_ecdsa = signed_tx(&base, &wrong_ecdsa, &redeem);
    json!({
        "experiment": "binohash-der-size-grind",
        "funding_txid": funding.to_string(),
        "input_value_sat": INPUT_VALUE,
        "fee_sat": FEE,
        "sighash_flag_hex": format!("{FLAG:02x}"),
        "seed_hex": SEED.to_lower_hex_string(),
        "nonce_derivation": "SHA256(seed || counter_le32), supplied to secp256k1 RFC6979 noncedata",
        "max_attempts": MAX_ATTEMPTS,
        "target_signature_bytes": TARGET_BYTES,
        "attempts": counter + 1,
        "selected_counter": counter,
        "other_counter": other_counter,
        "other_signature_bytes": wrong_size.len(),
        "digest_hex": digest.to_lower_hex_string(),
        "public_key_hex": pubkey.to_lower_hex_string(),
        "redeem_script_hex": redeem.to_bytes().to_lower_hex_string(),
        "redeem_script_bytes": redeem.len(),
        "redeem_static_non_push_opcodes": static_non_push_opcodes,
        "locking_script_hex": locking.to_bytes().to_lower_hex_string(),
        "locking_script_bytes": locking.len(),
        "good_signature_hex": good.to_lower_hex_string(),
        "wrong_size_signature_hex": wrong_size.to_lower_hex_string(),
        "wrong_ecdsa_signature_hex": wrong_ecdsa.to_lower_hex_string(),
        "hint_items": 0,
        "witness_items": 0,
        "transactions": {
            "valid": record(&valid),
            "invalid_size": record(&invalid_size),
            "invalid_ecdsa": record(&invalid_ecdsa),
        },
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: binohash_der_size_grind FUNDING_TXID DESTINATION_SCRIPT_HEX"
    );
    let funding = Txid::from_str(&args[1]).unwrap();
    let destination = ScriptBuf::from_bytes(Vec::<u8>::from_hex(&args[2]).unwrap());
    println!("{}", generate(funding, destination));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finds_exact_size_with_fixed_digest() {
        let row = generate(Txid::all_zeros(), ScriptBuf::from_bytes(vec![0x51]));
        assert_eq!(row["target_signature_bytes"], 70);
        assert_ne!(row["other_signature_bytes"], 70);
        assert_ne!(
            row["transactions"]["valid"]["txid"],
            row["transactions"]["invalid_size"]["txid"]
        );
    }
}
