//! Reduced, funded bare-legacy four-mode pinning fixture.
//!
//! The deterministic exact-size search is deliberately cheap. It demonstrates
//! field dependencies and executable composition, not a security parameter.

use bitcoin::{
    absolute,
    consensus::serialize,
    hashes::Hash,
    hex::{DisplayHex, FromHex},
    opcodes::all::OP_CODESEPARATOR,
    script::Instruction,
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey},
    sighash::SighashCache,
    transaction, Amount, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use bitcoin_lab::introspection::binohash::push_data;
use bitcoin_lab::support::script::{script, ScriptCompilation};
use serde_json::{json, Value};
use std::str::FromStr;

const INPUT_VALUE: u64 = 1_000_000;
const FEE: u64 = 20_000;
const TARGET_SIZE: usize = 71;
const FLAGS: [u8; 4] = [0x82, 0x02, 0x81, 0x01];

fn strip_separators(script: &Script) -> ScriptBuf {
    let mut out = Vec::new();
    let mut copied = 0;
    for item in script.instruction_indices() {
        let (index, instruction) = item.expect("valid fixture script");
        if instruction == Instruction::Op(OP_CODESEPARATOR) {
            out.extend_from_slice(&script.as_bytes()[copied..index]);
            copied = index + 1;
        }
    }
    out.extend_from_slice(&script.as_bytes()[copied..]);
    ScriptBuf::from_bytes(out)
}

fn script_codes(locking: &Script) -> [ScriptBuf; 4] {
    let mut starts = vec![0];
    for item in locking.instruction_indices() {
        let (index, instruction) = item.expect("valid fixture script");
        if instruction == Instruction::Op(OP_CODESEPARATOR) {
            starts.push(index + 1);
        }
    }
    assert_eq!(starts.len(), 4);
    std::array::from_fn(|i| strip_separators(Script::from_bytes(&locking.as_bytes()[starts[i]..])))
}

fn digest(tx: &Transaction, script_code: &Script, phase: usize) -> [u8; 32] {
    SighashCache::new(tx)
        .legacy_signature_hash(1, script_code, u32::from(FLAGS[phase]))
        .unwrap()
        .to_byte_array()
}

fn signed(tx: &Transaction, code: &Script, phase: usize, key: &SecretKey) -> Vec<u8> {
    let secp = Secp256k1::new();
    let mut signature = secp
        .sign_ecdsa(&Message::from_digest(digest(tx, code, phase)), key)
        .serialize_der()
        .to_vec();
    signature.push(FLAGS[phase]);
    signature
}

fn input(txid: Txid, vout: u32) -> TxIn {
    TxIn {
        previous_output: OutPoint { txid, vout },
        script_sig: ScriptBuf::new(),
        sequence: Sequence(0xffff_fffe),
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

fn signature_script_sig(signatures: &[Vec<u8>; 4]) -> ScriptBuf {
    ScriptBuf::from_bytes(signatures.iter().rev().flat_map(|s| push_data(s)).collect())
}

fn generate(funding: Txid, destination: ScriptBuf) -> Value {
    let secp = Secp256k1::new();
    let keys: [SecretKey; 4] =
        std::array::from_fn(|i| SecretKey::from_slice(&[i as u8 + 1; 32]).unwrap());
    let pubkeys: [PublicKey; 4] =
        std::array::from_fn(|i| PublicKey::from_secret_key(&secp, &keys[i]));
    let p: [Vec<u8>; 4] = pubkeys.map(|key| key.serialize().to_vec());
    let locking = script! {
        OP_SIZE { TARGET_SIZE as i64 } OP_EQUALVERIFY { p[0].clone() } OP_CHECKSIGVERIFY
        OP_CODESEPARATOR
        OP_SIZE { TARGET_SIZE as i64 } OP_EQUALVERIFY { p[1].clone() } OP_CHECKSIGVERIFY
        OP_CODESEPARATOR
        OP_SIZE { TARGET_SIZE as i64 } OP_EQUALVERIFY { p[2].clone() } OP_CHECKSIGVERIFY
        OP_CODESEPARATOR
        OP_SIZE { TARGET_SIZE as i64 } OP_EQUALVERIFY { p[3].clone() } OP_CHECKSIG
    }
    .compile_with_policy();
    let static_non_push_opcodes = locking
        .instructions()
        .map(|item| item.expect("valid policy-produced script"))
        .filter(|item| matches!(item, Instruction::Op(_)))
        .count();
    assert_eq!(static_non_push_opcodes, 15);
    let codes = script_codes(&locking);
    let easy_redeem = vec![0x51]; // OP_TRUE
    let easy_script = {
        let h = bitcoin::hashes::hash160::Hash::hash(&easy_redeem);
        ScriptBuf::from_bytes([vec![0xa9, 0x14], h.to_byte_array().to_vec(), vec![0x87]].concat())
    };
    let mut tx = Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![input(funding, 0), input(funding, 64)],
        output: vec![
            TxOut {
                value: Amount::from_sat(2 * INPUT_VALUE - FEE),
                script_pubkey: destination,
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x01, 0]),
            },
        ],
    };
    tx.input[0].script_sig = ScriptBuf::from_bytes(push_data(&easy_redeem));
    let mut signatures: [Vec<u8>; 4] = std::array::from_fn(|_| Vec::new());
    let mut attempts = [0_usize; 4];
    for phase in 0..4 {
        let limit = if phase == 0 { 4096 } else { 64 };
        for candidate in 0..limit {
            match phase {
                0 => tx.input[1].sequence = Sequence(0xffff_fffe - candidate as u32),
                1 => tx.input[0].previous_output.vout = candidate as u32,
                2 => {
                    tx.output[1].script_pubkey =
                        ScriptBuf::from_bytes(vec![0x6a, 0x01, candidate as u8])
                }
                _ => tx.input[0].sequence = Sequence(0x8000_0000 + candidate as u32),
            }
            attempts[phase] += 1;
            let sig = signed(&tx, &codes[phase], phase, &keys[phase]);
            if sig.len() == TARGET_SIZE {
                signatures[phase] = sig;
                break;
            }
        }
        assert_eq!(
            signatures[phase].len(),
            TARGET_SIZE,
            "phase {phase} exhausted low-work candidates"
        );
        for earlier in 0..=phase {
            let unchanged = signed(&tx, &codes[earlier], earlier, &keys[earlier]);
            assert_eq!(
                unchanged, signatures[earlier],
                "later phase invalidated earlier signature"
            );
        }
    }
    let digests: Vec<String> = (0..4)
        .map(|i| digest(&tx, &codes[i], i).to_lower_hex_string())
        .collect();
    tx.input[1].script_sig = signature_script_sig(&signatures);
    let valid = record(&tx);
    let wrong_sizes: Vec<Value> = (0..4)
        .map(|phase| {
            let mut shortened = signatures.clone();
            shortened[phase].remove(TARGET_SIZE - 2); // keep the sighash byte
            let mut wrong = tx.clone();
            wrong.input[1].script_sig = signature_script_sig(&shortened);
            json!({"phase": phase, "transaction": record(&wrong)})
        })
        .collect();
    let mut mutations = Vec::new();
    for name in [
        "version",
        "selected_sequence",
        "locktime",
        "other_prevout",
        "output_data",
        "other_sequence",
    ] {
        let mut changed = tx.clone();
        match name {
            "version" => changed.version = transaction::Version(tx.version.0 + 1),
            "selected_sequence" => changed.input[1].sequence = Sequence(tx.input[1].sequence.0 - 1),
            "locktime" => changed.lock_time = absolute::LockTime::from_consensus(1),
            "other_prevout" => {
                changed.input[0].previous_output.vout = (tx.input[0].previous_output.vout + 1) % 64
            }
            "output_data" => {
                changed.output[1].script_pubkey = ScriptBuf::from_bytes(vec![
                    0x6a,
                    0x01,
                    tx.output[1].script_pubkey.as_bytes()[2].wrapping_add(1),
                ])
            }
            "other_sequence" => changed.input[0].sequence = Sequence(tx.input[0].sequence.0 + 1),
            _ => unreachable!(),
        }
        let changed_digests: Vec<String> = (0..4)
            .map(|i| digest(&changed, &codes[i], i).to_lower_hex_string())
            .collect();
        let changed_modes: Vec<bool> = (0..4).map(|i| changed_digests[i] != digests[i]).collect();
        let expected = match name {
            "other_prevout" => [false, true, false, true],
            "output_data" => [false, false, true, true],
            "other_sequence" => [false, false, false, true],
            _ => [true; 4],
        };
        assert_eq!(
            changed_modes, expected,
            "unexpected field commitment for {name}"
        );
        mutations.push(json!({"name": name, "changed_modes": changed_modes, "digests_hex": changed_digests, "transaction": record(&changed)}));
    }
    json!({
        "experiment": "binohash-four-mode-pinning",
        "funding_txid": funding.to_string(),
        "input_value_sat": INPUT_VALUE,
        "fee_sat": FEE,
        "easy_script_pubkey_hex": easy_script.to_bytes().to_lower_hex_string(),
        "locking_script_hex": locking.to_bytes().to_lower_hex_string(),
        "locking_script_bytes": locking.len(),
        "static_non_push_opcodes": static_non_push_opcodes,
        "script_codes_hex": codes.iter().map(|s| s.to_bytes().to_lower_hex_string()).collect::<Vec<_>>(),
        "flags_hex": FLAGS.iter().map(|f| format!("{f:02x}")).collect::<Vec<_>>(),
        "target_signature_bytes": TARGET_SIZE,
        "hint_items": 0,
        "witness_items": 0,
        "attempts": attempts,
        "signatures_hex": signatures.iter().map(|s| s.to_lower_hex_string()).collect::<Vec<_>>(),
        "digests_hex": digests,
        "valid": valid,
        "wrong_sizes": wrong_sizes,
        "mutations": mutations,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: binohash_four_mode_pinning FUNDING_TXID DESTINATION_SCRIPT_HEX"
    );
    let funding = Txid::from_str(&args[1]).unwrap();
    let destination = ScriptBuf::from_bytes(Vec::<u8>::from_hex(&args[2]).unwrap());
    println!("{}", generate(funding, destination));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_ordered_modes_and_mutation_contract() {
        let fixture = generate(Txid::all_zeros(), ScriptBuf::from_bytes(vec![0x51]));
        assert_eq!(fixture["flags_hex"], json!(["82", "02", "81", "01"]));
        assert_eq!(fixture["mutations"].as_array().unwrap().len(), 6);
        assert_eq!(fixture["wrong_sizes"].as_array().unwrap().len(), 4);
        assert_eq!(fixture["valid"]["weight"].as_u64().unwrap() % 4, 0);
    }
}
