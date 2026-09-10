//! Deterministic complete Taproot leaves for the pinned Bitcoin Core harness.
//!
//! Run with `cargo run --locked --example core_validation_fixtures`.
//! Stdout is a single JSON document. Raw boundary bytecode deliberately avoids
//! optimization: deleting a transient push would erase the case being tested.
//! Generated Winternitz bytecode uses the repository compilation policy once,
//! and that same ScriptBuf supplies execution, metrics, and the Taproot leaf.
//!
//! This example performs local tapscript execution with the stack limit enabled.
//! It does not itself establish consensus validity or relay-policy acceptance.
//! Both test key seeds are public and unsuitable for holding real funds.

use bitcoin::{
    consensus::encode::serialize,
    hex::DisplayHex,
    script::Instruction,
    secp256k1::{Keypair, Secp256k1, SecretKey},
    taproot::{LeafVersion, TaprootBuilder},
    Address, Network, ScriptBuf, TapLeafHash, Witness,
};
use bitcoin_lab::{
    signatures::winternitz::{ConstantCompositionWinternitz20, Hash160, Preimage16},
    support::{
        execution::execute_raw_script_with_inputs_strict,
        provenance,
        script::{script, ScriptCompilation},
        tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
    },
};
use serde_json::{json, Value};
use std::{
    any::Any,
    panic::{self, AssertUnwindSafe},
    sync::Mutex,
};

const CORE_VERSION: &str = "30.3";
const CORE_COMMIT: &str = "49faec4f87f5cd19c88db01a82e5c68b087c8227";
const RAW_BOUNDARY: &str = "raw-boundary-bytecode";
const POLICY: &str = "repository-policy";
type Wots = ConstantCompositionWinternitz20<Hash160, Preimage16>;

/// Serializes hook changes when example tests invoke independent fixture runs.
static PANIC_HOOK_LOCK: Mutex<()> = Mutex::new(());

fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else {
        "non-string panic payload".to_owned()
    }
}

fn catch_local<T>(run: impl FnOnce() -> T) -> Result<T, String> {
    // The legacy research helper still panics on malformed script syntax.
    // Keep all panic outcomes distinct without polluting the JSON stream.
    let _lock = PANIC_HOOK_LOCK.lock().expect("panic-hook lock");
    let previous_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let result = panic::catch_unwind(AssertUnwindSafe(run));
    panic::set_hook(previous_hook);
    result.map_err(|payload| panic_message(payload.as_ref()))
}

fn local_execution(script: &ScriptBuf, witness: &[Vec<u8>]) -> Value {
    let result =
        catch_local(|| execute_raw_script_with_inputs_strict(script.to_bytes(), witness.to_vec()));

    match result {
        Ok(result) => json!({
            "outcome": if result.success { "success" } else { "reject" },
            "error": result.error.map(|error| format!("{error:?}")),
            "stack_limit_enforced": result.stack_limit_enforced,
            "context": "tapscript",
            "deployment": "unclassified",
            "max_stack_items": result.stats.max_nb_stack_items,
            "final_main_stack_items": result.final_stack.len(),
        }),
        Err(error) => json!({
            "outcome": "panic",
            "error": error,
            "stack_limit_enforced": true,
            "context": "tapscript",
            "deployment": "unclassified",
            "max_stack_items": null,
            "final_main_stack_items": null,
        }),
    }
}

fn local_profile(script: &ScriptBuf, witness: &[Vec<u8>], profile: TapscriptProfile) -> Value {
    let name = match profile {
        TapscriptProfile::Consensus => "consensus",
        TapscriptProfile::Policy => "policy",
    };
    match catch_local(|| execute_tapscript(script.clone(), witness.to_vec(), profile)) {
        Ok(result) => {
            let (outcome, error, opcode) = match &result.outcome {
                TapscriptOutcome::Executed(_) => ("executed", None, None),
                TapscriptOutcome::OpSuccess(opcode) => ("op-success", None, Some(opcode.to_u8())),
                TapscriptOutcome::PolicyRejected(error) => {
                    ("policy-rejected", Some(format!("{error:?}")), None)
                }
                TapscriptOutcome::InvalidScript(error) => {
                    ("invalid-script", Some(format!("{error:?}")), None)
                }
                TapscriptOutcome::UnsupportedOpcode(opcode) => {
                    ("unsupported-opcode", None, Some(opcode.to_u8()))
                }
                TapscriptOutcome::InitializationError(error) => {
                    ("initialization-error", Some(format!("{error:?}")), None)
                }
            };
            json!({
                "profile": name,
                "outcome": outcome,
                "accepted": result.accepted(),
                "error": error,
                "opcode": opcode,
                "execution": result.execution().map(|execution| json!({
                    "success": execution.success,
                    "error": execution.error.as_ref().map(|error| format!("{error:?}")),
                    "stack_limit_enforced": execution.stack_limit_enforced,
                    "max_stack_items": execution.stats.max_nb_stack_items,
                    "final_main_stack_items": execution.final_stack.len(),
                })),
                "deployment": "unclassified",
            })
        }
        Err(error) => json!({
            "profile": name,
            "outcome": "panic",
            "accepted": null,
            "error": error,
            "opcode": null,
            "execution": null,
            "deployment": "unclassified",
        }),
    }
}

fn expectations(consensus_rejection: Option<&str>, policy_rejection: Option<&str>) -> Value {
    json!({
        "consensus": consensus_rejection.is_none(),
        "policy": consensus_rejection.is_none() && policy_rejection.is_none(),
        "consensus_rejection": consensus_rejection,
        "policy_rejection": policy_rejection.or(consensus_rejection),
    })
}

fn fixture(
    name: &str,
    description: &str,
    script: ScriptBuf,
    witness: Vec<Vec<u8>>,
    compilation: &str,
    expected: Value,
) -> Value {
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
        .expect("leaf control block");
    let control_bytes = control.serialize();
    let output_script = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());
    let static_non_push_opcodes = script
        .instructions()
        .collect::<Result<Vec<_>, _>>()
        .ok()
        .map(|instructions| {
            instructions
                .into_iter()
                .filter(|instruction| {
                    // PushBytes includes OP_0; the other numeric pushes are
                    // OP_1NEGATE and OP_1..OP_16. OP_SUCCESS80 is not a push.
                    matches!(instruction, Instruction::Op(opcode)
                        if !matches!(opcode.to_u8(), 0x4f | 0x51..=0x60))
                })
                .count()
        });
    let mut complete_witness = witness.clone();
    complete_witness.push(script.to_bytes());
    complete_witness.push(control_bytes.clone());
    json!({
        "name": name,
        "description": description,
        "script_hex": script.as_bytes().to_lower_hex_string(),
        "data_witness_hex": witness.iter().map(|item| item.to_lower_hex_string()).collect::<Vec<_>>(),
        "control_block_hex": control_bytes.to_lower_hex_string(),
        "script_pubkey_hex": output_script.as_bytes().to_lower_hex_string(),
        "tapleaf_hash": TapLeafHash::from_script(&script, LeafVersion::TapScript).to_string(),
        "compilation": compilation,
        "expected": expected,
        "local": local_execution(&script, &witness),
        "local_profiles": {
            "consensus": local_profile(&script, &witness, TapscriptProfile::Consensus),
            "policy": local_profile(&script, &witness, TapscriptProfile::Policy),
        },
        "local_profile_comparison": {
            "scope": "script execution and data-witness policy; complete Taproot commitment separately validated by Core",
            "compare_to_core": true,
            "expected": {"consensus": expected["consensus"], "policy": expected["policy"]},
        },
        "metrics": {
            "includes": "complete-leaf bytecode and witness data; complete Taproot witness includes item count, data items, script and control block; transaction overhead excluded. OP_SUCCESS fixtures intentionally bypass script execution and clean-stack checks; malformed-script static opcode counts are unavailable.",
            "locking_script_bytes": script.len(),
            "data_witness_bytes": serialize(&Witness::from_slice(&witness)).len(),
            "taproot_witness_bytes": serialize(&Witness::from_slice(&complete_witness)).len(),
            "data_items": witness.len(),
            "hint_items": 0,
            "hint_bytes": 0,
            "witness_items_coexist_at_entry": true,
            "static_non_push_opcodes": static_non_push_opcodes,
            // The local interpreter's opcode_count and initial validation
            // weight are not valid complete-Taproot measurements.
            "executed_non_push_opcodes": null,
            "validation_weight_consumed": null,
        },
    })
}

fn drop_items(count: usize) -> Vec<u8> {
    let mut bytes = vec![0x6d; count / 2]; // OP_2DROP
    if count % 2 != 0 {
        bytes.push(0x75); // OP_DROP
    }
    bytes.push(0x51); // OP_TRUE
    bytes
}

fn fixtures() -> Value {
    let interpreter = provenance::interpreter().expect("embedded interpreter provenance");
    let mut fixtures = Vec::new();
    for count in [1000, 1001] {
        fixtures.push(fixture(
            &format!("entry-stack-{count}"),
            "Initial data stack is checked before its cleanup executes.",
            ScriptBuf::from_bytes(drop_items(count)),
            vec![vec![]; count],
            RAW_BOUNDARY,
            expectations((count > 1000).then_some("stack-size"), None),
        ));
    }
    for size in [80, 81, 520, 521] {
        fixtures.push(fixture(
            &format!("witness-element-{size}"),
            "Initial data-item size is checked before OP_DROP; tapscript policy limits items to 80 bytes.",
            ScriptBuf::from_bytes(drop_items(1)),
            vec![vec![0x42; size]],
            RAW_BOUNDARY,
            expectations(
                (size > 520).then_some("push-size"),
                (size > 80).then_some("witness-stack-item-size"),
            ),
        ));
    }
    for count in [999, 1000] {
        let mut script = vec![0x01, 0x11, 0x75]; // minimally push 17, OP_DROP
        script.extend(drop_items(count));
        fixtures.push(fixture(
            &format!("transient-data-push-{count}"),
            "A temporary data push counts even when the following instruction drops it.",
            ScriptBuf::from_bytes(script),
            vec![vec![]; count],
            RAW_BOUNDARY,
            expectations((count == 1000).then_some("stack-size"), None),
        ));
    }
    for count in [998, 999] {
        // Stage one item on altstack; two data pushes raise combined depth by
        // two, while the main stack alone remains at or below 1,000 items.
        let mut script = vec![0x6b, 0x01, 0x11, 0x01, 0x12, 0x6d, 0x6c];
        script.extend(drop_items(count));
        fixtures.push(fixture(
            &format!("transient-combined-stack-{count}"),
            "Main and altstack items share the same 1,000-item limit during data pushes.",
            ScriptBuf::from_bytes(script),
            vec![vec![]; count],
            RAW_BOUNDARY,
            expectations((count == 999).then_some("stack-size"), None),
        ));
    }
    for (name, opcode, remaining_items) in [("pick", 0x79, 2), ("roll", 0x7a, 1)] {
        for selector in [0, 1] {
            let mut script = vec![opcode];
            script.extend(drop_items(remaining_items));
            fixtures.push(fixture(
                &format!("{name}-{}", if selector == 0 { "valid" } else { "exact-boundary" }),
                "Selector is compared with pool length after popping the selector; equality is invalid.",
                ScriptBuf::from_bytes(script),
                vec![vec![0x42], if selector == 0 { vec![] } else { vec![1] }],
                RAW_BOUNDARY,
                expectations((selector == 1).then_some("invalid-stack-operation"), None),
            ));
        }
    }

    for (name, bytes, rejection) in [
        (
            "nonminimal-push-executed",
            vec![1, 1, 0x75, 0x51],
            Some("minimal-push"),
        ),
        (
            "nonminimal-push-skipped",
            vec![0, 0x63, 1, 1, 0x68, 0x51],
            None,
        ),
    ] {
        fixtures.push(fixture(
            name,
            "A nonminimal data push is consensus-valid; MINIMALDATA policy rejects it only when executed.",
            ScriptBuf::from_bytes(bytes),
            vec![],
            RAW_BOUNDARY,
            expectations(None, rejection),
        ));
    }
    for (name, condition, invalid) in [
        ("minimal-if-false", vec![], false),
        ("minimal-if-true", vec![1], false),
        ("minimal-if-nonminimal-false", vec![0], true),
        ("minimal-if-nonminimal-true", vec![2], true),
    ] {
        fixtures.push(fixture(
            name,
            "Tapscript IF requires exactly an empty vector or 01 under both consensus and policy, independently of numeric minimality options.",
            ScriptBuf::from_bytes(vec![0x63, 0x51, 0x67, 0x51, 0x68]),
            vec![condition],
            RAW_BOUNDARY,
            expectations(invalid.then_some("tapscript-minimal-if"), None),
        ));
    }
    for size in [520u16, 521] {
        let mut bytes = vec![0x4d]; // PUSHDATA2
        bytes.extend(size.to_le_bytes());
        bytes.extend(vec![0x42; size as usize]);
        bytes.extend([0x75, 0x51]);
        fixtures.push(fixture(
            &format!("script-push-{size}"),
            "The 520-byte element limit applies to executed script pushes; the 80-byte relay-policy limit applies only to initial witness data items.",
            ScriptBuf::from_bytes(bytes),
            vec![],
            RAW_BOUNDARY,
            expectations((size > 520).then_some("push-size"), None),
        ));
    }
    for (name, opcode) in [
        ("op-success-80", 80),
        ("op-success-126-cat", 126),
        ("op-success-254", 254),
    ] {
        fixtures.push(fixture(
            name,
            "A decoded OP_SUCCESS opcode unconditionally accepts the leaf under Core v30.3 consensus and is discouraged by policy; opcode 126 does not perform concatenation.",
            ScriptBuf::from_bytes(vec![opcode]),
            vec![],
            RAW_BOUNDARY,
            expectations(None, Some("discourage-op-success")),
        ));
    }
    for (name, witness, policy_rejection) in [
        (
            "op-success-initial-stack-1001",
            vec![vec![]; 1001],
            "discourage-op-success",
        ),
        (
            "op-success-witness-element-521",
            vec![vec![0x42; 521]],
            "witness-stack-item-size",
        ),
    ] {
        fixtures.push(fixture(
            name,
            "Consensus OP_SUCCESS pre-scan precedes initial resource checks; policy checks the 80-byte witness-data limit before script flags.",
            ScriptBuf::from_bytes(vec![0x7e]),
            witness,
            RAW_BOUNDARY,
            expectations(None, Some(policy_rejection)),
        ));
    }
    let mut oversized_before_success = vec![0x4d, 9, 2];
    oversized_before_success.extend(vec![0x42; 521]);
    oversized_before_success.push(0x7e);
    for (name, bytes) in [
        ("op-success-skipped-branch", vec![0, 0x63, 0x7e, 0x68, 0]),
        ("op-success-after-op-return", vec![0x6a, 0x7e]),
        ("op-success-malformed-after", vec![0x7e, 0x4c]),
        ("op-success-after-nonminimal-push", vec![1, 1, 0x7e]),
        ("op-success-after-oversized-push", oversized_before_success),
    ] {
        fixtures.push(fixture(
            name,
            "A decoded OP_SUCCESS precedes execution, branch selection, push-size/minimality checks, and any malformed suffix; policy discourages it during the same pre-scan.",
            ScriptBuf::from_bytes(bytes),
            vec![],
            RAW_BOUNDARY,
            expectations(None, Some("discourage-op-success")),
        ));
    }
    for (name, bytes, rejection) in [
        (
            "op-success-byte-in-payload",
            vec![1, 0x7e, 0x75, 0],
            "eval-false",
        ),
        (
            "op-success-malformed-before",
            vec![0x4c, 2, 0x7e],
            "bad-opcode",
        ),
    ] {
        fixtures.push(fixture(
            name,
            "Only decoded opcodes trigger OP_SUCCESS; a payload byte does not, and a malformed push before that byte rejects the script.",
            ScriptBuf::from_bytes(bytes),
            vec![],
            RAW_BOUNDARY,
            expectations(Some(rejection), None),
        ));
    }

    let signing_key = Wots::signing_key_from_seed([0x42; 32]);
    let public_key = Wots::public_key(&signing_key);
    let message = core::array::from_fn(|i| (37 * i) as u8);
    let witness = Wots::sign(signing_key, &message).to_witness().to_vec();
    let verifier = Wots::checksig_verify_isolated_and_clear(&public_key);
    let script = script! { { verifier } OP_TRUE }.compile_with_policy();
    let valid = fixture(
        "winternitz-valid",
        "Isolated HASH160/Preimage16 constant-composition verification plus OP_TRUE, with 70 signature data items and zero auxiliary hints.",
        script.clone(),
        witness.clone(),
        POLICY,
        expectations(None, None),
    );
    fixtures.push(valid.clone());

    let mut invalid_control = valid;
    // Toggle only the output-key parity bit. The script, data witness, and
    // scriptPubKey stay identical, so fragment execution still succeeds.
    let original_control = invalid_control["control_block_hex"].as_str().unwrap();
    let parity_byte = u8::from_str_radix(&original_control[..2], 16).unwrap() ^ 1;
    invalid_control["control_block_hex"] =
        json!(format!("{parity_byte:02x}{}", &original_control[2..]));
    invalid_control["name"] = json!("winternitz-invalid-control-block");
    invalid_control["description"] = json!("The control-block output-key parity bit is flipped; local fragment success cannot validate the Taproot commitment.");
    invalid_control["expected"] = expectations(Some("taproot-commitment"), None);
    invalid_control["local_profile_comparison"] = json!({
        "scope": "Taproot commitment validation is outside the local fragment API; both profiles accept the unchanged leaf while Core rejects the invalid control block",
        "compare_to_core": false,
        "expected": {"consensus": true, "policy": true},
    });
    fixtures.push(invalid_control);

    for (name, selector, rejection) in [
        ("negative-selector", vec![0x81], "invalid-stack-operation"),
        (
            "exact-pool-boundary",
            vec![Wots::CHAINS as u8],
            "invalid-stack-operation",
        ),
        (
            "beyond-pool",
            vec![Wots::CHAINS as u8 + 1],
            "invalid-stack-operation",
        ),
        (
            "oversized-selector-number",
            vec![1, 0, 0, 0, 1],
            "scriptnum-overflow",
        ),
    ] {
        let mut malformed = witness.clone();
        malformed[0] = selector;
        fixtures.push(fixture(
            &format!("winternitz-{name}"),
            "The first opening selector is malformed; all other signature items are unchanged.",
            script.clone(),
            malformed,
            POLICY,
            expectations(Some(rejection), None),
        ));
    }

    let mut nonminimal = witness.clone();
    nonminimal[0].push(0); // Same nonnegative selector value, redundant high zero.
    fixtures.push(fixture(
        "winternitz-nonminimal-selector",
        "Redundant numeric zero byte preserves the selected key under consensus but violates MINIMALDATA policy; explicit local profiles reproduce this difference while the legacy research helper requires minimal numbers.",
        script.clone(),
        nonminimal,
        POLICY,
        expectations(None, Some("minimaldata")),
    ));

    let mut corrupted = witness.clone();
    corrupted[1][0] ^= 1;
    fixtures.push(fixture(
        "winternitz-mutated-node",
        "A single bit in the first chain opening is flipped, breaking its commitment check.",
        script.clone(),
        corrupted,
        POLICY,
        expectations(Some("equalverify"), None),
    ));
    for extra in [false, true] {
        let mut malformed = witness.clone();
        if extra {
            malformed.insert(0, vec![1]);
        } else {
            malformed.pop();
        }
        fixtures.push(fixture(
            if extra {
                "winternitz-extra-item"
            } else {
                "winternitz-missing-item"
            },
            "The isolated verifier requires exactly 70 initial main-stack data items.",
            script.clone(),
            malformed,
            POLICY,
            expectations(Some("equalverify"), None),
        ));
    }

    json!({
        "schema_version": 2,
        "expected_bitcoin_core_version": CORE_VERSION,
        "expected_bitcoin_core_commit": CORE_COMMIT,
        "local_interpreter": {
            "name": interpreter.name,
            "commit": interpreter.commit,
            "context": "tapscript",
            "helper": "execute_raw_script_with_inputs_strict",
            "stack_limit_enforced": true,
            "full_consensus_validation": false,
            "limitations": "The legacy research helper retains default minimal-number policy and experimental OP_CAT. Explicit profiles use current OP_SUCCESS semantics, no experimental opcodes, consensus numeric encoding or policy MINIMALDATA, and policy's 80-byte witness-data limit. All are fragment-only: no transaction, Taproot commitment, annex or full policy validation; signature/timelock-dependent opcodes are unsupported. Execution opcode and complete-witness budget counters remain unavailable. Panics and unsupported outcomes are distinct, never converted to rejection.",
            "profiles": {
                "consensus": "support::tapscript::execute_tapscript with TapscriptProfile::Consensus",
                "policy": "support::tapscript::execute_tapscript with TapscriptProfile::Policy; bounded script/witness policy subset",
            },
        },
        "mining_address": Address::p2wsh(&ScriptBuf::from_bytes(vec![0x51]), Network::Regtest).to_string(),
        "internal_key_derivation": "secp256k1 x-only public key of secret [0x01;32]; public test key, never use with real funds",
        "winternitz": {
            "profile": "ConstantCompositionWinternitz20<Hash160,Preimage16>",
            "seed_hex": ([0x42u8; 32].to_lower_hex_string()),
            "message_hex": message.to_lower_hex_string(),
            "chains": Wots::CHAINS,
            "openings": Wots::OPENINGS,
            "signature_data_items": Wots::WITNESS_DATA_ITEMS,
            "hint_items_per_invocation": 0,
            "stack_composition": "All 70 signature data items coexist at entry; the isolated verifier stages them on altstack and loads 49 trusted public keys, reaching 119 combined items. Extra main-stack items are rejected. No repeated configuration is measured; all surrounding main and altstack state shares the 1,000-item limit.",
        },
        "fixture_count": fixtures.len(),
        "fixtures": fixtures,
    })
}

fn main() {
    serde_json::to_writer_pretty(std::io::stdout().lock(), &fixtures())
        .expect("write fixture JSON");
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_are_deterministic_and_complete() {
        let first = fixtures();
        assert_eq!(first, fixtures());
        let rows = first["fixtures"].as_array().unwrap();
        assert_eq!(first["fixture_count"], rows.len());
        assert_eq!(rows.len(), 44);
        let interpreter = provenance::interpreter().unwrap();
        assert_eq!(first["local_interpreter"]["name"], interpreter.name);
        assert_eq!(first["local_interpreter"]["commit"], interpreter.commit);
        let valid = rows
            .iter()
            .find(|row| row["name"] == "winternitz-valid")
            .unwrap();
        assert_eq!(valid["local"]["outcome"], "success");
        assert_eq!(valid["local"]["max_stack_items"], 119);
        assert_eq!(valid["local"]["final_main_stack_items"], 1);
        assert_eq!(valid["metrics"]["locking_script_bytes"], 1599);
        assert_eq!(valid["metrics"]["data_witness_bytes"], 796);
        assert_eq!(valid["metrics"]["taproot_witness_bytes"], 2432);
        assert_eq!(valid["metrics"]["data_items"], 70);
        assert_eq!(valid["metrics"]["hint_items"], 0);
        assert_eq!(valid["metrics"]["static_non_push_opcodes"], 567);
        let success80 = rows
            .iter()
            .find(|row| row["name"] == "op-success-80")
            .unwrap();
        assert_eq!(success80["metrics"]["static_non_push_opcodes"], 1);
        assert_eq!(valid["control_block_hex"].as_str().unwrap().len(), 66);
        assert_eq!(valid["script_pubkey_hex"].as_str().unwrap().len(), 68);
        let names: std::collections::HashSet<_> = rows.iter().map(|row| &row["name"]).collect();
        assert_eq!(names.len(), rows.len());
        for row in rows {
            assert_eq!(row["local"]["stack_limit_enforced"], true);
            assert_eq!(
                row["metrics"]["data_items"],
                row["data_witness_hex"].as_array().unwrap().len()
            );
            for profile in ["consensus", "policy"] {
                assert!(
                    row["local_profiles"][profile]["accepted"].is_boolean(),
                    "{} {profile}: panic/unsupported/init failure is not a rejection",
                    row["name"]
                );
                assert_eq!(
                    row["local_profiles"][profile]["accepted"],
                    row["local_profile_comparison"]["expected"][profile],
                    "{} {profile}: profile verdict",
                    row["name"]
                );
                if row["local_profile_comparison"]["compare_to_core"] == true {
                    assert_eq!(
                        row["local_profiles"][profile]["accepted"], row["expected"][profile],
                        "{} {profile}: declared Core expectation",
                        row["name"]
                    );
                } else {
                    assert_eq!(row["name"], "winternitz-invalid-control-block");
                }
                if row["local_profiles"][profile]["outcome"] == "op-success" {
                    assert!(row["local_profiles"][profile]["execution"].is_null());
                }
            }
        }
    }
}
