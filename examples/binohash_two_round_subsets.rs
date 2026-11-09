//! Two reduced FindAndDelete subset rounds in one funded legacy P2SH spend.
//!
//! The small pools and 71-byte size targets are execution probes, not the
//! paper's work parameter or a collision-security claim.

use bitcoin::{
    absolute,
    consensus::serialize,
    hashes::{hash160, Hash},
    hex::{DisplayHex, FromHex},
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey},
    transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin_lab::introspection::binohash::{binohash_digest, push_data};
use bitcoin_lab::support::script::{script, ScriptCompilation};
use serde_json::{json, Value};
use std::str::FromStr;

const INPUT_VALUE: u64 = 1_000_000;
const FEE: u64 = 20_000;
const TARGET: usize = 71;
const MAX_VARIANTS: u8 = 64;

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

fn input(txid: Txid, vout: u32) -> TxIn {
    TxIn {
        previous_output: OutPoint { txid, vout },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }
}

fn record(tx: &Transaction) -> Value {
    json!({
        "hex": serialize(tx).to_lower_hex_string(),
        "txid": tx.compute_txid().to_string(),
        "weight": tx.weight().to_wu(),
        "vsize": tx.vsize(),
        "base_bytes": tx.base_size(),
        "total_bytes": tx.total_size(),
        "input_script_sig_bytes": tx.input.iter().map(|i| i.script_sig.len()).collect::<Vec<_>>(),
    })
}

fn redeem(
    pool: &[[Vec<u8>; 2]; 2],
    puzzle_pub: &[Vec<u8>; 2],
    pool_pub: &[Vec<u8>; 2],
) -> ScriptBuf {
    // Stack after P2SH's redeem push is removed:
    // dummy2, puzzle2, dummy1, puzzle1, selector1, selector2.
    // The selectors are Script booleans; each chooses one embedded pool sig.
    script! {
        OP_TOALTSTACK
        OP_IF { pool[0][0].clone() } OP_ELSE { pool[0][1].clone() } OP_ENDIF
        OP_OVER OP_SIZE { TARGET as i64 } OP_EQUALVERIFY OP_DROP
        OP_2 { puzzle_pub[0].clone() } { pool_pub[0].clone() } OP_2 OP_CHECKMULTISIGVERIFY
        OP_FROMALTSTACK
        OP_IF { pool[1][0].clone() } OP_ELSE { pool[1][1].clone() } OP_ENDIF
        OP_OVER OP_SIZE { TARGET as i64 } OP_EQUALVERIFY OP_DROP
        OP_2 { puzzle_pub[1].clone() } { pool_pub[1].clone() } OP_2 OP_CHECKMULTISIGVERIFY
        OP_TRUE
    }
    .compile_with_policy()
}

fn signature_script_sig(
    puzzles: &[Vec<u8>; 2],
    choices: [usize; 2],
    redeem: &ScriptBuf,
) -> ScriptBuf {
    let selector = |choice| if choice == 0 { 0x51 } else { 0x00 };
    ScriptBuf::from_bytes(
        [
            vec![0x00],
            push_data(&puzzles[1]),
            vec![0x00],
            push_data(&puzzles[0]),
            vec![selector(choices[0]), selector(choices[1])],
            push_data(redeem.as_bytes()),
        ]
        .concat(),
    )
}

fn generate(funding: Txid, destination: ScriptBuf) -> Value {
    let secp = Secp256k1::new();
    let pool_keys: [SecretKey; 2] = [
        SecretKey::from_slice(&[11; 32]).unwrap(),
        SecretKey::from_slice(&[12; 32]).unwrap(),
    ];
    let puzzle_keys: [SecretKey; 2] = [
        SecretKey::from_slice(&[21; 32]).unwrap(),
        SecretKey::from_slice(&[22; 32]).unwrap(),
    ];
    let pool_pub: [Vec<u8>; 2] = std::array::from_fn(|i| {
        PublicKey::from_secret_key(&secp, &pool_keys[i])
            .serialize()
            .to_vec()
    });
    let puzzle_pub: [Vec<u8>; 2] = std::array::from_fn(|i| {
        PublicKey::from_secret_key(&secp, &puzzle_keys[i])
            .serialize()
            .to_vec()
    });
    let mut bug_digest = [0_u8; 32];
    bug_digest[0] = 1;
    let easy_redeem = vec![0x51];
    let mut base = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input(funding, 0), input(funding, 1)],
        output: vec![TxOut {
            value: Amount::from_sat(2 * INPUT_VALUE - FEE),
            script_pubkey: destination,
        }],
    };
    base.input[0].script_sig = ScriptBuf::from_bytes(push_data(&easy_redeem));
    for variant in 0..MAX_VARIANTS {
        let pool: [[Vec<u8>; 2]; 2] = std::array::from_fn(|round| {
            std::array::from_fn(|choice| {
                let mut noncedata = [0_u8; 32];
                noncedata[0] = variant;
                noncedata[1] = round as u8;
                noncedata[2] = choice as u8;
                let mut signature = secp
                    .sign_ecdsa_with_noncedata(
                        &Message::from_digest(bug_digest),
                        &pool_keys[round],
                        &noncedata,
                    )
                    .serialize_der()
                    .to_vec();
                signature.push(0x03); // out-of-range SIGHASH_SINGLE, input 1 > output index 0
                signature
            })
        });
        let redeem = redeem(&pool, &puzzle_pub, &pool_pub);
        assert!(
            redeem.len() <= 520,
            "reduced P2SH redeemScript grew past 520 bytes"
        );
        let flattened = [
            pool[0][0].clone(),
            pool[0][1].clone(),
            pool[1][0].clone(),
            pool[1][1].clone(),
        ];
        assert_eq!(
            flattened
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            4
        );
        let mut candidates: [Vec<Value>; 2] = std::array::from_fn(|_| Vec::new());
        let mut chosen: [Option<(usize, Vec<u8>, [u8; 32])>; 2] = [None, None];
        for round in 0..2 {
            for choice in 0..2 {
                let digest =
                    binohash_digest(&base, 1, &redeem, &flattened, &[2 * round + choice], 0x01)
                        .unwrap();
                let mut signature = secp
                    .sign_ecdsa(&Message::from_digest(digest), &puzzle_keys[round])
                    .serialize_der()
                    .to_vec();
                signature.push(0x01);
                candidates[round].push(json!({
                    "choice": choice, "digest_hex": digest.to_lower_hex_string(),
                    "signature_bytes": signature.len(), "passes_size": signature.len() == TARGET,
                }));
                if chosen[round].is_none() && signature.len() == TARGET {
                    chosen[round] = Some((choice, signature, digest));
                    break;
                }
            }
        }
        let (Some(first), Some(second)) = (chosen[0].clone(), chosen[1].clone()) else {
            continue;
        };
        if first.0 == second.0 {
            continue;
        }
        let choices = [first.0, second.0];
        let puzzles = [first.1.clone(), second.1.clone()];
        let mut valid = base.clone();
        valid.input[1].script_sig = signature_script_sig(&puzzles, choices, &redeem);
        let mut flip_first = valid.clone();
        flip_first.input[1].script_sig =
            signature_script_sig(&puzzles, [1 - choices[0], choices[1]], &redeem);
        let mut flip_second = valid.clone();
        flip_second.input[1].script_sig =
            signature_script_sig(&puzzles, [choices[0], 1 - choices[1]], &redeem);
        let mut wrong_size = None;
        for counter in 1..=255_u8 {
            let mut noncedata = [0_u8; 32];
            noncedata[0] = counter;
            let mut signature = secp
                .sign_ecdsa_with_noncedata(
                    &Message::from_digest(first.2),
                    &puzzle_keys[0],
                    &noncedata,
                )
                .serialize_der()
                .to_vec();
            signature.push(0x01);
            if signature.len() != TARGET {
                wrong_size = Some((counter, signature));
                break;
            }
        }
        let (wrong_size_counter, wrong_size_signature) = wrong_size.unwrap();
        let mut wrong_size_puzzles = puzzles.clone();
        wrong_size_puzzles[0] = wrong_size_signature.clone();
        let mut wrong_size_tx = valid.clone();
        wrong_size_tx.input[1].script_sig =
            signature_script_sig(&wrong_size_puzzles, choices, &redeem);
        return json!({
            "experiment": "binohash-two-round-subsets",
            "funding_txid": funding.to_string(),
            "input_value_sat": INPUT_VALUE,
            "fee_sat": FEE,
            "pool_variant_attempts": variant + 1,
            "selected_pool_variant": variant,
            "target_puzzle_signature_bytes": TARGET,
            "round_candidate_counts": [candidates[0].len(), candidates[1].len()],
            "round_candidates": candidates,
            "selected_indices": choices,
            "selected_digests_hex": [first.2.to_lower_hex_string(), second.2.to_lower_hex_string()],
            "selected_puzzle_signatures_hex": puzzles.iter().map(|s| s.to_lower_hex_string()).collect::<Vec<_>>(),
            "pool_signatures_hex": flattened.iter().map(|s| s.to_lower_hex_string()).collect::<Vec<_>>(),
            "redeem_script_hex": redeem.to_bytes().to_lower_hex_string(),
            "redeem_script_bytes": redeem.len(),
            "locking_script_hex": p2sh(redeem.as_bytes()).to_bytes().to_lower_hex_string(),
            "locking_script_bytes": 23,
            "easy_script_pubkey_hex": p2sh(&easy_redeem).to_bytes().to_lower_hex_string(),
            "wrong_size_counter": wrong_size_counter,
            "wrong_size_signature_bytes": wrong_size_signature.len(),
            "hint_items": 0,
            "witness_items": 0,
            "transactions": {"valid": record(&valid), "flip_first": record(&flip_first),
                             "flip_second": record(&flip_second), "wrong_size": record(&wrong_size_tx)},
        });
    }
    panic!("no distinct two-round selection within deterministic variant bound");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: binohash_two_round_subsets FUNDING_TXID DESTINATION_SCRIPT_HEX"
    );
    let funding = Txid::from_str(&args[1]).unwrap();
    let destination = ScriptBuf::from_bytes(Vec::<u8>::from_hex(&args[2]).unwrap());
    println!("{}", generate(funding, destination));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn two_distinct_selected_rounds() {
        let fixture = generate(Txid::all_zeros(), ScriptBuf::from_bytes(vec![0x51]));
        assert_ne!(
            fixture["selected_indices"][0],
            fixture["selected_indices"][1]
        );
        assert_eq!(
            fixture["round_candidate_counts"].as_array().unwrap().len(),
            2
        );
        assert_eq!(fixture["transactions"].as_object().unwrap().len(), 4);
    }
}
