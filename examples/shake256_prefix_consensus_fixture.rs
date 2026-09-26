//! Deterministic complete Taproot spend for the SHAKE256 32-byte prefix.
//!
//! The companion Python harness submits this exact spend to the pinned Core
//! regtest node. The script is intentionally large; Tapscript consensus does
//! not impose the legacy 10,000-byte script-size ceiling, while relay policy
//! is evaluated separately and is not claimed here.

use bitcoin::{
    consensus::encode::serialize,
    hashes::Hash,
    hex::DisplayHex,
    secp256k1::{Keypair, Secp256k1, SecretKey},
    taproot::{LeafVersion, TaprootBuilder},
    Address, Network, ScriptBuf, TapLeafHash, Witness,
};
use bitcoin_lab::{
    hashes::shake256::shake256_prefix,
    support::script::{script, ScriptCompilation},
};
use serde_json::{json, Value};

const MESSAGE_BYTES: usize = 32;
const OUTPUT_BYTES: usize = 32;

fn fixture() -> Value {
    let script = script! {
        { shake256_prefix(MESSAGE_BYTES, OUTPUT_BYTES) }
        for _ in 0..(OUTPUT_BYTES / 2) { OP_2DROP }
        OP_TRUE
    }
    .compile_with_policy();
    let data_witness = vec![vec![0x42; 1]; MESSAGE_BYTES];

    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[0x01; 32]).expect("fixed test key");
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let (internal_key, _) = keypair.x_only_public_key();
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .expect("single leaf")
        .finalize(&secp, internal_key)
        .expect("complete single-leaf tree");
    let control = spend_info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .expect("leaf control block")
        .serialize();
    let script_pubkey = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
    let mut complete_witness = data_witness.clone();
    complete_witness.push(script.to_bytes());
    complete_witness.push(control.clone());

    json!({
        "name": "shake256-prefix-32-consensus",
        "description": "32-byte SHAKE256 output prefix with deterministic 32-byte message and clean terminal predicate.",
        "message_bytes": MESSAGE_BYTES,
        "output_bytes": OUTPUT_BYTES,
        "script_hex": script.as_bytes().to_lower_hex_string(),
        "script_sha256": sha256(script.as_bytes()),
        "data_witness_hex": data_witness.iter().map(|item| item.to_lower_hex_string()).collect::<Vec<_>>(),
        "control_block_hex": control.to_lower_hex_string(),
        "script_pubkey_hex": script_pubkey.as_bytes().to_lower_hex_string(),
        "mining_address": Address::p2wsh(&ScriptBuf::from_bytes(vec![0x51]), Network::Regtest).to_string(),
        "tapleaf_hash": TapLeafHash::from_script(&script, LeafVersion::TapScript).to_string(),
        "expected_consensus": true,
        "metrics": {
            "locking_script_bytes": script.len(),
            "data_witness_bytes": serialize(&Witness::from_slice(&data_witness)).len(),
            "taproot_witness_bytes": serialize(&Witness::from_slice(&complete_witness)).len(),
            "data_items": data_witness.len(),
            "hint_items": 0,
            "witness_items_coexist_at_entry": true,
        },
        "oracle": {
            "name": "Bitcoin Core",
            "version": "30.3",
            "commit": "49faec4f87f5cd19c88db01a82e5c68b087c8227",
            "mode": "complete Taproot spend included by generateblock",
            "policy_checked": false,
        },
    })
}

fn sha256(bytes: &[u8]) -> String {
    let digest = bitcoin::hashes::sha256::Hash::hash(bytes);
    digest.to_string()
}

fn main() {
    serde_json::to_writer_pretty(std::io::stdout().lock(), &fixture()).expect("write fixture JSON");
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_is_deterministic_and_exceeds_legacy_script_size_only() {
        let first = fixture();
        assert_eq!(first, fixture());
        assert_eq!(first["expected_consensus"], true);
        assert_eq!(first["metrics"]["data_items"], MESSAGE_BYTES);
        assert_eq!(first["metrics"]["hint_items"], 0);
        assert_eq!(first["metrics"]["data_witness_bytes"], 65);
        assert_eq!(first["metrics"]["taproot_witness_bytes"], 2_000_248);
        assert_eq!(first["metrics"]["locking_script_bytes"], 2_000_144);
        assert_eq!(
            first["script_sha256"],
            "e1072cc7b403840fc7fa9b2794afe3e73f70c498f4699f14e7514432434e9bde"
        );
        assert_eq!(
            first["tapleaf_hash"],
            "b4962e553d23074c9de05d85a5f94c0bad5e455c1fbeba77713b20e0c9c66525"
        );
        assert_eq!(first["metrics"]["witness_items_coexist_at_entry"], true);
        assert_eq!(first["oracle"]["policy_checked"], false);
    }
}
