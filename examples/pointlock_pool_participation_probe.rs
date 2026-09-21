//! Retained-creator participation probe using the exact 95-pool public fixture.
//! No new scripts or setup are introduced. All signing secrets are public tests.

use bitcoin::{
    consensus::{deserialize, serialize},
    hashes::Hash,
    opcodes::all::{OP_CHECKSIGVERIFY, OP_CODESEPARATOR},
    script::Instruction,
    secp256k1::{ecdsa::Signature, Keypair, Message, PublicKey, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache},
    Amount, EcdsaSighashType, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn,
    TxOut, Witness,
};
use bitcoin_lab::signatures::pointlocks;
use num_bigint::BigUint;
use serde_json::{json, Value};
use std::{fs, str::FromStr};

const AMOUNT: u64 = 100_000_000;
const POOLS: usize = 95;
const T: usize = 5;
const ROUNDS: usize = 6;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    assert!(s.is_ascii() && s.len() % 2 == 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn scalar(value: &BigUint) -> SecretKey {
    let mut bytes = [0; 32];
    let encoded = value.to_bytes_be();
    bytes[32 - encoded.len()..].copy_from_slice(&encoded);
    SecretKey::from_slice(&bytes).unwrap()
}
fn one() -> SecretKey {
    scalar(&BigUint::from(1u8))
}
fn info(tx: &Transaction) -> Value {
    json!({"hex":hex(&serialize(tx)), "txid":tx.compute_txid().to_string(),
        "wtxid":tx.compute_wtxid().to_string(), "weight":tx.weight().to_wu(), "vbytes":tx.vsize()})
}
fn contexts(code: &ScriptBuf) -> Vec<ScriptBuf> {
    let mut start = 0;
    let mut result = vec![];
    for item in code.instruction_indices() {
        match item.unwrap() {
            (offset, Instruction::Op(op)) if op == OP_CODESEPARATOR => start = offset + 1,
            (_, Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {
                result.push(ScriptBuf::from_bytes(code.as_bytes()[start..].to_vec()));
            }
            _ => {}
        }
    }
    assert_eq!(result.len(), 1 + T * (ROUNDS + 1));
    result
}
fn digest(tx: &Transaction, index: usize, script: &ScriptBuf, flag: EcdsaSighashType) -> [u8; 32] {
    SighashCache::new(tx)
        .p2wsh_signature_hash(index, script, Amount::from_sat(100_000), flag)
        .unwrap()
        .to_byte_array()
}
fn sign_taproot(tx: &mut Transaction, previous: &[TxOut]) {
    let hash = SighashCache::new(&*tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(previous), TapSighashType::Default)
        .unwrap();
    let secp = Secp256k1::new();
    let sig = secp.sign_schnorr_no_aux_rand(
        &Message::from_digest(hash.to_byte_array()),
        &Keypair::from_secret_key(&secp, &one()),
    );
    tx.input[0].witness = Witness::from_slice(&[sig.as_ref()]);
}

fn open(
    funding: &Transaction,
    manifest: &Value,
    selected_pools: &[usize],
    helper: bool,
) -> (Transaction, Value) {
    let mut vouts = vec![];
    if helper {
        vouts.push(0usize);
    }
    vouts.extend(selected_pools.iter().map(|p| p + 1));
    let previous: Vec<_> = vouts.iter().map(|&v| funding.output[v].clone()).collect();
    let value = previous.iter().map(|o| o.value.to_sat()).sum::<u64>();
    let fee = if selected_pools.len() == POOLS {
        100_000
    } else {
        10_000
    };
    let mut tx = Transaction {
        version: funding.version,
        lock_time: funding.lock_time,
        input: vouts
            .iter()
            .map(|&v| TxIn {
                previous_output: OutPoint {
                    txid: funding.compute_txid(),
                    vout: v as u32,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(value - fee),
            script_pubkey: funding.output[0].script_pubkey.clone(),
        }],
    };
    let secp = Secp256k1::new();
    let order = BigUint::parse_bytes(
        b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .unwrap();
    let half = scalar(&((&order + 1u8) / 2u8));
    let flags = [
        EcdsaSighashType::All,
        EcdsaSighashType::None,
        EcdsaSighashType::Single,
        EcdsaSighashType::AllPlusAnyoneCanPay,
        EcdsaSighashType::NonePlusAnyoneCanPay,
        EcdsaSighashType::SinglePlusAnyoneCanPay,
    ];
    let mut attempts = 0u32;
    let records = 'attempt: loop {
        // Re-sign all contexts after any sequence retry, including authorization.
        assert!(attempts < 0x8000_0000);
        tx.input[0].sequence = Sequence::from_consensus(u32::MAX - attempts);
        attempts += 1;
        let mut records = vec![];
        for (position, &pool_id) in selected_pools.iter().enumerate() {
            let index = position + usize::from(helper);
            let pool = &manifest["pools"][pool_id];
            let script = ScriptBuf::from_bytes(unhex(pool["script_hex"].as_str().unwrap()));
            assert_eq!(script.to_p2wsh(), funding.output[pool_id + 1].script_pubkey);
            let checks = contexts(&script);
            let selected: Vec<_> = pool["selected"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as usize)
                .collect();
            let mut remaining: Vec<_> = (0..54).collect();
            let mut stream = vec![];
            for &label in &selected {
                let pos = remaining.iter().position(|&v| v == label).unwrap();
                let depth = remaining.len() - pos;
                remaining.remove(pos);
                stream.push(unhex(pool["tau_table"][label].as_str().unwrap()));
                stream.push(vec![depth as u8]);
            }
            let mut keys = vec![];
            let mut shorts = vec![];
            for (slot, &label) in selected.iter().rev().enumerate() {
                let frame = pool["frames"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|v| v["selected"] == label)
                    .unwrap();
                let t = BigUint::parse_bytes(
                    frame["target_scalar_fixture"].as_str().unwrap().as_bytes(),
                    16,
                )
                .unwrap();
                let target = PublicKey::from_secret_key(&secp, &scalar(&t)).serialize();
                assert_eq!(
                    target.to_vec(),
                    unhex(pool["targets"][label].as_str().unwrap())
                );
                let rt = BigUint::from_bytes_be(&target[1..]);
                let msg = digest(&tx, index, &checks[1 + slot], EcdsaSighashType::All);
                let z = BigUint::from_bytes_be(&msg) % &order;
                let secret = (&t + &order - z) * rt.modpow(&(&order - 2u8), &order) % &order;
                if secret == BigUint::from(0u8) {
                    continue 'attempt;
                }
                let secret = scalar(&secret);
                let key = PublicKey::from_secret_key(&secp, &secret);
                let tau = unhex(pool["tau_table"][label].as_str().unwrap());
                secp.verify_ecdsa(
                    &Message::from_digest(msg),
                    &Signature::from_der(&tau[..tau.len() - 1]).unwrap(),
                    &key,
                )
                .unwrap();
                keys.push(key.serialize().to_vec());
                let mut row = vec![];
                for round in 0..ROUNDS {
                    let code = &checks[1 + T + round * T + slot];
                    let signature = flags.iter().find_map(|&flag| {
                        let msg = digest(&tx, index, code, flag);
                        let sig = pointlocks::sign_with_nonce(msg, secret, half, flag)
                            .ok()?
                            .to_vec();
                        if sig.len() != 60 {
                            return None;
                        }
                        secp.verify_ecdsa(
                            &Message::from_digest(msg),
                            &Signature::from_der(&sig[..59]).unwrap(),
                            &key,
                        )
                        .unwrap();
                        Some(sig)
                    });
                    let Some(signature) = signature else {
                        continue 'attempt;
                    };
                    row.push(signature);
                }
                shorts.push(row);
            }
            for round in 0..ROUNDS {
                for row in &shorts {
                    stream.push(row[round].clone());
                }
            }
            stream.extend(keys);
            stream.reverse();
            let msg = digest(&tx, index, &script, EcdsaSighashType::All);
            let mut auth = secp
                .sign_ecdsa(&Message::from_digest(msg), &one())
                .serialize_der()
                .to_vec();
            auth.push(1);
            stream.push(auth);
            stream.push(script.into_bytes());
            assert_eq!(stream.len(), 47);
            tx.input[index].witness = Witness::from_slice(&stream);
            records.push(
                json!({"pool":pool_id,"input_index":index,"funding_vout":pool_id+1,
                "selected":selected,"hint_items":5,"entry_items":46,"complete_witness_items":47,
                "serialized_witness_bytes":serialize(&tx.input[index].witness).len()}),
            );
        }
        break records;
    };
    if helper {
        sign_taproot(&mut tx, &previous);
    }
    (
        tx,
        json!({"pools":records,"includes_helper":helper,"omitted_pools":POOLS-selected_pools.len(),
        "opening_transaction_attempts":attempts,"total_hint_items":5*selected_pools.len(),
        "total_pool_entry_items":46*selected_pools.len(),"total_pool_witness_items":47*selected_pools.len()}),
    )
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: pointlock_pool_participation_probe MANIFEST GRANT_TXID"
    );
    let manifest: Value = serde_json::from_slice(&fs::read(&args[1]).unwrap()).unwrap();
    assert_eq!(manifest["pool_count"], POOLS);
    let mut funding: Transaction =
        deserialize(&unhex(manifest["funding"]["hex"].as_str().unwrap())).unwrap();
    assert_eq!(funding.output.len(), POOLS + 1);
    assert_eq!(
        funding.output.iter().map(|o| o.value.to_sat()).sum::<u64>(),
        AMOUNT - 50_000
    );
    funding.input[0].previous_output = OutPoint {
        txid: bitcoin::Txid::from_str(&args[2]).unwrap(),
        vout: 0,
    };
    let initial = TxOut {
        value: Amount::from_sat(AMOUNT),
        script_pubkey: funding.output[0].script_pubkey.clone(),
    };
    sign_taproot(&mut funding, &[initial]);
    let (full, full_metrics) = open(&funding, &manifest, &(0..POOLS).collect::<Vec<_>>(), true);
    let mut cases = vec![
        json!({"name":"full-95-pool-control","expected":true,"transaction":info(&full),"metrics":full_metrics}),
    ];
    let mut first_partial = None;
    for (name, pool_id, helper) in [
        ("first-pool-alone", 0, false),
        ("middle-pool-alone", 47, false),
        ("last-pool-alone", 94, false),
        ("helper-and-middle-pool", 47, true),
    ] {
        let (tx, metrics) = open(&funding, &manifest, &[pool_id], helper);
        if pool_id == 0 {
            first_partial = Some(tx.clone());
        }
        cases.push(json!({"name":name,"expected":true,"transaction":info(&tx),"metrics":metrics}));
    }
    let partial = first_partial.unwrap();
    let fresh: Vec<Vec<u8>> = partial.input[0]
        .witness
        .iter()
        .map(|v| v.to_vec())
        .collect();
    let stale: Vec<Vec<u8>> = full.input[1].witness.iter().map(|v| v.to_vec()).collect();
    for (name, witness) in [
        ("trimmed-full-witness", stale.clone()),
        ("fresh-opening-stale-authorization", {
            let mut w = fresh.clone();
            w[45] = stale[45].clone();
            w
        }),
        ("stale-opening-fresh-authorization", {
            let mut w = stale.clone();
            w[45] = fresh[45].clone();
            w
        }),
    ] {
        let mut tx = partial.clone();
        tx.input[0].witness = Witness::from_slice(&witness);
        cases.push(json!({"name":name,"expected":false,"transaction":info(&tx)}));
    }
    println!("{}",serde_json::to_string_pretty(&json!({
        "scope":"Exact existing 95-pool instance, retained deterministic creator secrets, newly chosen input sets. No extraction or garbling theorem claimed.",
        "evidence":"locally-reproduced","deployment":"unclassified",
        "funding":info(&funding),"cases":cases})).unwrap());
}
