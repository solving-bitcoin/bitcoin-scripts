//! Deterministic checked PRINCEv2 Taproot leaves for the pinned Core experiment.
//!
//! Run `cargo run --locked --example prince_validation_fixtures` for JSON.
//! Each complete leaf is compiled through repository policy once, then its exact
//! bytes supply execution, metrics, the Tapleaf hash, and the output commitment.
//! Ciphertexts come from the checked-in independent upstream C vectors.
//! Public test keys and plaintexts provide no secrecy or spending authorization.

use bitcoin::{
    consensus::serialize,
    hashes::{sha256, Hash},
    hex::DisplayHex,
    script::Instruction,
    secp256k1::{Keypair, Secp256k1, SecretKey},
    taproot::{LeafVersion, TaprootBuilder},
    Address, Network, ScriptBuf, TapLeafHash, Witness,
};
use bitcoin_lab::{
    ciphers::prince::{prince_verify, u64_to_nibbles_msb},
    support::{
        provenance,
        script::{script, ScriptCompilation},
        tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
    },
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    panic::{self, AssertUnwindSafe},
    sync::Mutex,
};

const CORE_VERSION: &str = "30.3";
const CORE_COMMIT: &str = "49faec4f87f5cd19c88db01a82e5c68b087c8227";
const C_COMMIT: &str = "0c6172dcd85f1fe6a269519093a79c7350fe6e55";
const C_VECTORS: &str = include_str!("../tests/data/princev2_upstream_vectors.json");
static PANIC_HOOK_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy)]
struct Vector {
    index: usize,
    key: u128,
    plaintext: u64,
    ciphertext: u64,
}

fn vectors() -> [Vector; 3] {
    let source: Value = serde_json::from_str(C_VECTORS).expect("independent C vectors");
    assert_eq!(source["commit"], C_COMMIT);
    assert_eq!(source["vectors"].as_array().unwrap().len(), 37);
    [0, 3, 4].map(|index| {
        let row = &source["vectors"][index];
        Vector {
            index,
            key: u128::from_str_radix(row["key"].as_str().unwrap(), 16).unwrap(),
            plaintext: u64::from_str_radix(row["plaintext"].as_str().unwrap(), 16).unwrap(),
            ciphertext: u64::from_str_radix(row["ciphertext"].as_str().unwrap(), 16).unwrap(),
        }
    })
}

fn plaintext_witness(plaintext: u64) -> Vec<Vec<u8>> {
    u64_to_nibbles_msb(plaintext)
        .into_iter()
        .rev()
        .map(|value| if value == 0 { vec![] } else { vec![value] })
        .collect()
}

fn local_profile(script: &ScriptBuf, witness: &[Vec<u8>], profile: TapscriptProfile) -> Value {
    // Panics and unsupported outcomes must remain distinct from rejection.
    // Serialize global hook changes and keep stdout a single JSON document.
    let _lock = PANIC_HOOK_LOCK.lock().expect("panic-hook lock");
    let previous_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        execute_tapscript(script.clone(), witness.to_vec(), profile)
    }));
    panic::set_hook(previous_hook);
    match outcome {
        Ok(result) => {
            let (outcome, error) = match &result.outcome {
                TapscriptOutcome::Executed(execution) => (
                    "executed",
                    execution.error.as_ref().map(|error| format!("{error:?}")),
                ),
                TapscriptOutcome::OpSuccess(opcode) => ("op-success", Some(opcode.to_string())),
                TapscriptOutcome::PolicyRejected(error) => {
                    ("policy-rejected", Some(format!("{error:?}")))
                }
                TapscriptOutcome::InvalidScript(error) => {
                    ("invalid-script", Some(format!("{error:?}")))
                }
                TapscriptOutcome::UnsupportedOpcode(opcode) => {
                    ("unsupported-opcode", Some(opcode.to_string()))
                }
                TapscriptOutcome::InitializationError(error) => {
                    ("initialization-error", Some(format!("{error:?}")))
                }
            };
            json!({
                "outcome": outcome,
                "accepted": result.accepted(),
                "error": error,
                "execution": result.execution().map(|execution| json!({
                    "stack_limit_enforced": execution.stack_limit_enforced,
                    "max_stack_items": execution.stats.max_nb_stack_items,
                    "final_main_stack_items": execution.final_stack.len(),
                    "final_main_stack_hex": (0..execution.final_stack.len())
                        .map(|index| execution.final_stack.get(index).to_lower_hex_string())
                        .collect::<Vec<_>>(),
                })),
                "deployment": "unclassified",
            })
        }
        Err(payload) => json!({
            "outcome": "panic", "accepted": null, "execution": null,
            "error": payload.downcast_ref::<String>().cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|message| (*message).to_owned()))
                .unwrap_or_else(|| "non-string panic payload".to_owned()),
            "deployment": "unclassified",
        }),
    }
}

fn fixture(
    name: &str,
    vector: Vector,
    expected_ciphertext: u64,
    witness: Vec<Vec<u8>>,
    mutation: Value,
    rejections: [Option<&str>; 2],
    compiled: &mut BTreeMap<(u128, u64), ScriptBuf>,
) -> Value {
    let script = compiled
        .entry((vector.key, expected_ciphertext))
        .or_insert_with(|| prince_verify(vector.key, expected_ciphertext).compile_with_policy());
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(
        &secp,
        &SecretKey::from_slice(&[0x01; 32]).expect("fixed public test key"),
    );
    let (internal_key, _) = keypair.x_only_public_key();
    let spend = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .expect("single leaf")
        .finalize(&secp, internal_key)
        .expect("complete single-leaf tree");
    let control = spend
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .expect("control block")
        .serialize();
    let static_non_push_opcodes = script
        .instructions()
        .map(|instruction| instruction.expect("policy-produced PRINCE leaf parses"))
        .filter(|instruction| {
            matches!(instruction, Instruction::Op(opcode)
                if !matches!(opcode.to_u8(), 0x4f | 0x51..=0x60))
        })
        .count();
    let mut complete_witness = witness.clone();
    complete_witness.push(script.to_bytes());
    complete_witness.push(control.clone());
    let consensus = local_profile(script, &witness, TapscriptProfile::Consensus);
    let policy = local_profile(script, &witness, TapscriptProfile::Policy);
    json!({
        "name": name,
        "reference_vector_index": vector.index,
        "key_hex": format!("{:032x}", vector.key),
        "reference_plaintext_hex": format!("{:016x}", vector.plaintext),
        "reference_ciphertext_hex": format!("{:016x}", vector.ciphertext),
        "expected_ciphertext_hex": format!("{expected_ciphertext:016x}"),
        "mutation": mutation,
        "script_hex": script.as_bytes().to_lower_hex_string(),
        "script_sha256": sha256::Hash::hash(script.as_bytes()).to_string(),
        "data_witness_hex": witness.iter().map(|item| item.to_lower_hex_string()).collect::<Vec<_>>(),
        "control_block_hex": control.to_lower_hex_string(),
        "script_pubkey_hex": ScriptBuf::new_p2tr_tweaked(spend.output_key()).as_bytes().to_lower_hex_string(),
        "tapleaf_hash": TapLeafHash::from_script(script, LeafVersion::TapScript).to_string(),
        "compilation": "repository-policy; complete leaf compiled as one script",
        "expected": {
            "consensus": rejections[0].is_none(), "policy": rejections[1].is_none(),
            "consensus_rejection": rejections[0], "policy_rejection": rejections[1],
        },
        "local_profiles": {"consensus": consensus, "policy": policy},
        "metrics": {
            "includes": "complete-leaf: input-count, canonical-encoding and range validation, PRINCEv2 table setup, encryption, cleanup, all ciphertext comparisons and one true result; excludes input pushes; serialized Taproot witness includes data, script, control block and all CompactSize overhead; transaction metrics recorded by runner",
            "locking_script_bytes": script.len(),
            "data_items": witness.len(), "hint_items": 0, "hint_bytes": 0,
            "taproot_witness_items": complete_witness.len(),
            "data_witness_bytes": serialize(&Witness::from_slice(&witness)).len(),
            "taproot_witness_bytes": serialize(&Witness::from_slice(&complete_witness)).len(),
            "witness_items_coexist_at_entry": true,
            "stack_peak": consensus["execution"]["max_stack_items"],
            "static_non_push_opcodes": static_non_push_opcodes,
            "executed_non_push_opcodes": null,
            "executed_opcode_scope": "not measured; canonical zero and nonzero nibbles take different validation branches; the interpreter parsed-instruction counter is not an executed non-push count",
            "signature_validation_weight_consumed": 0,
            "validation_weight_scope": "no signature opcodes; no claim about the interpreter's full-witness initial budget",
        },
    })
}

fn fixtures() -> Value {
    let selected = vectors();
    let mut compiled = BTreeMap::new();
    let mut rows = Vec::new();
    for (name, vector) in [
        ("zero-key-zero-block", selected[0]),
        ("zero-key-max-block", selected[1]),
        ("published-key-varied-block", selected[2]),
    ] {
        rows.push(fixture(
            name,
            vector,
            vector.ciphertext,
            plaintext_witness(vector.plaintext),
            Value::Null,
            [None, None],
            &mut compiled,
        ));
    }
    for (name, vector) in [
        ("wrong-ciphertext-zero-key", selected[0]),
        ("wrong-ciphertext-published-key", selected[2]),
    ] {
        rows.push(fixture(
            name,
            vector,
            vector.ciphertext ^ 1,
            plaintext_witness(vector.plaintext),
            json!({"kind": "ciphertext", "xor_mask_hex": "0000000000000001"}),
            [Some("equalverify"); 2],
            &mut compiled,
        ));
    }
    for (name, count) in [
        ("missing-plaintext-item", 15usize),
        ("extra-plaintext-item", 17),
        ("empty-plaintext-vector", 0),
    ] {
        let vector = selected[0];
        rows.push(fixture(
            name,
            vector,
            vector.ciphertext,
            vec![vec![]; count],
            json!({"kind": "data-item-count", "count": count}),
            [Some("numequalverify"); 2],
            &mut compiled,
        ));
    }
    // Position 0 is the MSB/top input; raw witness vectors are bottom-first.
    for (name, source, position, bytes, consensus, policy) in [
        ("negative-one-msb", 0, 0, vec![0x81], "verify", "verify"),
        (
            "nibble-sixteen-interior",
            0,
            7,
            vec![0x10],
            "verify",
            "verify",
        ),
        (
            "negative-zero-lsb",
            0,
            15,
            vec![0x80],
            "verify",
            "minimaldata",
        ),
        (
            "explicit-zero-byte-msb",
            0,
            0,
            vec![0x00],
            "verify",
            "minimaldata",
        ),
        (
            "padded-one-published",
            2,
            1,
            vec![0x01, 0x00],
            "equalverify",
            "equalverify",
        ),
        (
            "padded-fifteen-published",
            2,
            15,
            vec![0x0f, 0x00],
            "equalverify",
            "equalverify",
        ),
        (
            "two-byte-128-interior",
            0,
            7,
            vec![0x80, 0x00],
            "equalverify",
            "equalverify",
        ),
        (
            "five-byte-number-lsb",
            0,
            15,
            vec![1, 0, 0, 0, 0],
            "equalverify",
            "equalverify",
        ),
        (
            "two-byte-zero-interior",
            0,
            7,
            vec![0, 0],
            "equalverify",
            "equalverify",
        ),
        (
            "four-byte-zero-lsb",
            0,
            15,
            vec![0; 4],
            "equalverify",
            "equalverify",
        ),
        (
            "nibble-127-published-msb",
            2,
            0,
            vec![0x7f],
            "verify",
            "verify",
        ),
        (
            "negative-127-published-interior",
            2,
            8,
            vec![0xff],
            "verify",
            "verify",
        ),
    ] {
        let vector = selected[source];
        let mut witness = plaintext_witness(vector.plaintext);
        witness[15 - position] = bytes.clone();
        rows.push(fixture(name, vector, vector.ciphertext, witness,
            json!({"kind": "raw-nibble", "nibble_index_msb_first": position, "replacement_hex": bytes.to_lower_hex_string()}),
            [Some(consensus), Some(policy)], &mut compiled));
    }
    let interpreter = provenance::interpreter().expect("embedded interpreter provenance");
    let compiler = provenance::compiler().expect("embedded compiler provenance");
    let source: Value = serde_json::from_str(C_VECTORS).unwrap();
    json!({
        "schema_version": 1,
        "experiment": "checked-princev2-complete-taproot-leaves",
        "expected_bitcoin_core_version": CORE_VERSION,
        "expected_bitcoin_core_commit": CORE_COMMIT,
        "local_interpreter": {"name": interpreter.name, "version": interpreter.version, "source": interpreter.source, "commit": interpreter.commit},
        "compiler": {"name": compiler.name, "version": compiler.version, "source": compiler.source, "commit": compiler.commit},
        "cipher_reference": {
            "source": source["source"], "commit": C_COMMIT,
            "fixture_path": "tests/data/princev2_upstream_vectors.json",
            "fixture_sha256": sha256::Hash::hash(C_VECTORS.as_bytes()).to_string(),
            "generator": source["generator"], "generator_seed_hex": source["seed_hex"],
            "vector_indices": [0, 3, 4], "total_available_vectors": 37,
        },
        "mining_address": Address::p2wsh(&script! { OP_TRUE }.compile_with_policy(), Network::Regtest).to_string(),
        "internal_key_seed_hex": ([0x01u8; 32]).to_lower_hex_string(),
        "security_scope": "Public fixed test internal key and public embedded cipher keys. This experiment checks an encryption relation; it provides no transaction authorization or plaintext secrecy.",
        "local_scope": "Supported context-free consensus/policy profiles execute exact complete-leaf scripts with the stack limit enabled; Core independently checks full funded Taproot commitments and transactions. No signature, annex, general key-independent resource or complete local transaction-validation claim.",
        "fixture_count": rows.len(),
        "unique_complete_leaves": compiled.len(),
        "fixtures": rows,
    })
}

fn main() {
    serde_json::to_writer_pretty(std::io::stdout().lock(), &fixtures()).expect("fixture JSON");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_are_deterministic_complete_and_locally_supported() {
        let first = fixtures();
        assert_eq!(first, fixtures());
        assert_eq!(first["fixture_count"], 20);
        assert_eq!(first["unique_complete_leaves"], 5);
        for row in first["fixtures"].as_array().unwrap() {
            let count = row["data_witness_hex"].as_array().unwrap().len();
            assert_eq!(row["metrics"]["data_items"], count);
            assert_eq!(row["metrics"]["taproot_witness_items"], count + 2);
            assert_eq!(row["metrics"]["hint_items"], 0);
            assert_eq!(row["metrics"]["hint_bytes"], 0);
            for profile in ["consensus", "policy"] {
                let local = &row["local_profiles"][profile];
                assert_eq!(local["outcome"], "executed", "{}: {local}", row["name"]);
                assert_eq!(
                    local["accepted"], row["expected"][profile],
                    "{} {profile}: {local}",
                    row["name"]
                );
                assert_eq!(local["execution"]["stack_limit_enforced"], true);
                if local["accepted"] == true {
                    assert_eq!(count, 16);
                    assert_eq!(local["execution"]["final_main_stack_hex"], json!(["01"]));
                    assert!(local["execution"]["max_stack_items"].as_u64().unwrap() <= 1_000);
                }
            }
        }
    }
}
