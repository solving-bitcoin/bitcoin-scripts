//! Deterministic, funded Taproot signature fixtures for the independent Core runner.
//!
//! No arguments emit funding commitments. `--funding-txid HEX` additionally
//! constructs and signs each spending transaction against its real prevout.
//! All generated scripts use the repository compilation policy exactly once.
//! Local execution uses full TxTemplate context, consensus numeric settings and
//! no experimental opcodes. Its initial signature budget counts data witness
//! only, so this experiment deliberately keeps every case far from that limit.

use bitcoin::{
    absolute,
    consensus::serialize,
    hashes::Hash,
    hex::DisplayHex,
    script::Instruction,
    secp256k1::{Keypair, Message, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TaprootBuilder},
    transaction, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TapLeafHash, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use bitcoin_lab::support::{
    provenance,
    script::{script, ScriptCompilation},
};
use bitcoin_scriptexec::{Exec, ExecCtx, Experimental, Options, TxTemplate};
use serde_json::{json, Value};
use std::{
    panic::{self, AssertUnwindSafe},
    str::FromStr,
    sync::Mutex,
};

const FUNDING_VALUE: u64 = 1_000_000;
const FEE: u64 = 10_000;
const SIGNING_SEED: [u8; 32] = [0x23; 32];
const INTERNAL_SEED: [u8; 32] = [0x01; 32];
static PANIC_HOOK_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone)]
enum Input {
    Data(Vec<Vec<u8>>),
    Signed {
        extra: Vec<Vec<u8>>,
        codesep_position: u32,
        hash_type: TapSighashType,
        append_type: Option<u8>,
    },
}

struct Fixture {
    name: String,
    script: ScriptBuf,
    input: Input,
    codesep: Option<(u32, u32)>,
    consensus_error: Option<&'static str>,
    policy_error: Option<&'static str>,
}

fn keypair(seed: &[u8; 32]) -> Keypair {
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(seed).unwrap())
}

fn signed(extra: Vec<Vec<u8>>, position: u32) -> Input {
    Input::Signed {
        extra,
        codesep_position: position,
        hash_type: TapSighashType::Default,
        append_type: None,
    }
}

fn last_codesep(script: &ScriptBuf) -> (u32, u32) {
    let mut offset = 0;
    let mut last = None;
    let mut instructions = script.instructions();
    let mut position = 0;
    while let Some(instruction) = instructions.next() {
        if matches!(instruction.unwrap(), Instruction::Op(opcode) if opcode.to_u8() == 0xab) {
            last = Some((position, offset));
        }
        position += 1;
        offset = (script.len() - instructions.as_script().len()) as u32;
    }
    last.expect("CODESEPARATOR fixture retains its separator")
}

fn fixtures() -> Vec<Fixture> {
    let public = keypair(&SIGNING_SEED)
        .x_only_public_key()
        .0
        .serialize()
        .to_vec();
    let mut result = Vec::new();
    let simple = script! { OP_2DROP { public.clone() } OP_CHECKSIG }.compile_with_policy();
    result.push(Fixture {
        name: "valid-signature-no-separator".into(),
        script: simple,
        input: signed(vec![], u32::MAX),
        codesep: None,
        consensus_error: None,
        policy_error: None,
    });
    for skipped_prefix in [false, true] {
        let prefix = if skipped_prefix {
            script! { OP_IF OP_CODESEPARATOR OP_ENDIF }
        } else {
            script! {}
        };
        let script = script! {
            OP_2DROP { prefix } { vec![0x11u8, 0x12] } OP_EQUALVERIFY
            OP_CODESEPARATOR { public.clone() } OP_CHECKSIG
        }
        .compile_with_policy();
        let (position, offset) = last_codesep(&script);
        assert_ne!(
            position, offset,
            "a multibyte push must precede the separator"
        );
        if skipped_prefix {
            assert_eq!(script.instructions().filter(|instruction|
                matches!(instruction, Ok(Instruction::Op(opcode)) if opcode.to_u8() == 0xab)).count(), 2);
        }
        for wrong_offset in [false, true] {
            let mut extra = vec![vec![0x11, 0x12]];
            if skipped_prefix {
                extra.push(vec![]);
            }
            let error = wrong_offset.then_some("schnorr-signature");
            result.push(Fixture {
                name: format!(
                    "codesep-{}{}",
                    if skipped_prefix {
                        "skipped-prefix-"
                    } else {
                        ""
                    },
                    if wrong_offset {
                        "wrong-byte-offset"
                    } else {
                        "opcode-position"
                    }
                ),
                script: script.clone(),
                input: signed(extra, if wrong_offset { offset } else { position }),
                codesep: Some((position, offset)),
                consensus_error: error,
                policy_error: error,
            });
        }
    }
    for operation in ["checksig", "checksigverify", "checksigadd"] {
        for empty in [true, false] {
            let public = vec![2u8]; // a nonempty, non-32-byte upgradeable key
            let script = match operation {
                "checksig" if empty => script! { OP_2DROP { public } OP_CHECKSIG OP_NOT },
                "checksig" => script! { OP_2DROP { public } OP_CHECKSIG },
                "checksigverify" => script! { OP_2DROP { public } OP_CHECKSIGVERIFY OP_TRUE },
                "checksigadd" => script! { OP_2DROP OP_2 { public } OP_CHECKSIGADD { if empty { 2 } else { 3 } } OP_NUMEQUAL },
                _ => unreachable!(),
            }.compile_with_policy();
            result.push(Fixture {
                name: format!(
                    "unknown-key-{}-{operation}",
                    if empty { "empty" } else { "nonempty" }
                ),
                script,
                input: Input::Data(vec![if empty { vec![] } else { vec![0x42] }]),
                codesep: None,
                consensus_error: (empty && operation == "checksigverify")
                    .then_some("checksigverify"),
                policy_error: Some("discourage-upgradeable-pubkey"),
            });
        }
    }
    let invalid_public = vec![0xffu8; 32];
    assert!(bitcoin::secp256k1::XOnlyPublicKey::from_slice(&invalid_public).is_err());
    for (name, hash_type, append_type, error) in [
        (
            "64-default",
            TapSighashType::Default,
            None,
            "schnorr-signature",
        ),
        ("65-all", TapSighashType::All, Some(1), "schnorr-signature"),
        (
            "65-explicit-default",
            TapSighashType::Default,
            Some(0),
            "schnorr-hashtype",
        ),
        (
            "65-invalid-hashtype",
            TapSighashType::Default,
            Some(4),
            "schnorr-hashtype",
        ),
    ] {
        result.push(Fixture {
            name: format!("invalid-xonly-key-{name}"),
            script: script! { OP_2DROP { invalid_public.clone() } OP_CHECKSIG }
                .compile_with_policy(),
            input: Input::Signed {
                extra: vec![],
                codesep_position: u32::MAX,
                hash_type,
                append_type,
            },
            codesep: None,
            consensus_error: Some(error),
            policy_error: Some(error),
        });
    }
    result.push(Fixture {
        name: "invalid-xonly-key-empty-signature".into(),
        script: script! { OP_2DROP { invalid_public } OP_CHECKSIG OP_NOT }.compile_with_policy(),
        input: Input::Data(vec![vec![]]),
        codesep: None,
        consensus_error: None,
        policy_error: None,
    });
    for verify in [false, true] {
        for skipped in [false, true] {
            let operation = if verify {
                script! { OP_CHECKMULTISIGVERIFY }
            } else {
                script! { OP_CHECKMULTISIG }
            };
            let script = if skipped {
                script! { OP_2DROP OP_IF { operation } OP_ENDIF OP_TRUE }
            } else {
                script! { OP_2DROP { operation } OP_TRUE }
            }
            .compile_with_policy();
            let error = (!skipped).then_some("tapscript-checkmultisig");
            result.push(Fixture {
                name: format!(
                    "{}-{}",
                    if verify {
                        "checkmultisigverify"
                    } else {
                        "checkmultisig"
                    },
                    if skipped { "skipped" } else { "executed" }
                ),
                script,
                input: Input::Data(if skipped { vec![vec![]] } else { vec![] }),
                codesep: None,
                consensus_error: error,
                policy_error: error,
            });
        }
    }
    assert_eq!(result.len(), 20);
    result
}

fn interpreter_pin() -> Value {
    let interpreter = provenance::interpreter().expect("embedded interpreter provenance");
    json!({"name": interpreter.name, "source": interpreter.source, "commit": interpreter.commit,
        "context": "tapscript", "require_minimal": false, "experimental_op_cat": false,
        "stack_limit_enforced": true, "comparison": "consensus only; policy independently measured by Core",
        "limitations": "Full real transaction/prevouts/leaf context supplied, but local initial signature budget counts serialized data witness only rather than complete Taproot witness. Each fixture has at most one nonempty signature opcode, with a conservative lower bound of at least 67 budget units after one charge; empty signatures incur no charge. Two ordinary 32-byte witness padding items are removed by initial OP_2DROP; these are not signature hints and are included in data/witness/stack metrics. Remaining budget is unavailable on instruction errors because upstream statistics may precede the failed instruction's charge. Upstream opcode_count is not an executed non-push count; that measurement is unavailable. No annex or budget-boundary claim."})
}

fn local_execution(
    script: &ScriptBuf,
    tx: &Transaction,
    prevout: TxOut,
    data: &[Vec<u8>],
) -> Value {
    let _lock = PANIC_HOOK_LOCK.lock().unwrap();
    let hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        let mut exec = match Exec::new(
            ExecCtx::Tapscript,
            Options {
                require_minimal: false,
                verify_minimal_if: true,
                verify_cltv: true,
                verify_csv: true,
                enforce_stack_limit: true,
                experimental: Experimental { op_cat: false },
            },
            TxTemplate {
                tx: tx.clone(),
                prevouts: vec![prevout],
                input_idx: 0,
                taproot_annex_scriptleaf: Some((
                    TapLeafHash::from_script(script, LeafVersion::TapScript),
                    None,
                )),
            },
            script.clone(),
            data.to_vec(),
        ) {
            Ok(exec) => exec,
            Err(error) => {
                return json!({"outcome": "initialization-error", "accepted": null, "error": format!("{error:?}"), "stats": null})
            }
        };
        while exec.exec_next().is_ok() {}
        let result = exec.result().unwrap();
        let stats = exec.stats();
        json!({"outcome": "executed", "accepted": result.success,
            "error": result.error.as_ref().map(|error| format!("{error:?}")),
            "final_stack_hex": exec.stack().iter_str().map(|item| item.to_lower_hex_string()).collect::<Vec<_>>(),
            "stats": {"combined_stack_peak": stats.max_nb_stack_items,
                "initial_data_only_validation_weight": stats.start_validation_weight,
                "remaining_data_only_validation_weight": result.error.is_none().then_some(stats.validation_weight)}})
    }));
    panic::set_hook(hook);
    match outcome {
        Ok(outcome) => outcome,
        Err(payload) => json!({"outcome": "panic", "accepted": null,
            "error": payload.downcast_ref::<String>().map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied()).unwrap_or("non-string panic payload"), "stats": null}),
    }
}

fn document(funding: Option<Txid>) -> Value {
    let secp = Secp256k1::new();
    let internal = keypair(&INTERNAL_SEED).x_only_public_key().0;
    let destination = ScriptBuf::new_p2wsh(&ScriptBuf::from_bytes(vec![0x51]).wscript_hash());
    let mut rows = Vec::new();
    for (index, fixture) in fixtures().into_iter().enumerate() {
        let spend = TaprootBuilder::new()
            .add_leaf(0, fixture.script.clone())
            .unwrap()
            .finalize(&secp, internal)
            .unwrap();
        let control = spend
            .control_block(&(fixture.script.clone(), LeafVersion::TapScript))
            .unwrap()
            .serialize();
        let prevout = TxOut {
            value: Amount::from_sat(FUNDING_VALUE),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(spend.output_key()),
        };
        let leaf = TapLeafHash::from_script(&fixture.script, LeafVersion::TapScript);
        let mut row = json!({"name": fixture.name, "funding_vout": index,
            "script_hex": fixture.script.as_bytes().to_lower_hex_string(),
            "control_block_hex": control.to_lower_hex_string(),
            "script_pubkey_hex": prevout.script_pubkey.as_bytes().to_lower_hex_string(),
            "tapleaf_hash": leaf.to_string(), "compilation": "repository-policy",
            "codesep": fixture.codesep.map(|(position,offset)| json!({"last_executed_opcode_position": position, "last_executed_byte_offset": offset})),
            "expected": {"consensus": fixture.consensus_error.is_none(), "policy": fixture.policy_error.is_none(),
                "consensus_rejection": fixture.consensus_error, "policy_rejection": fixture.policy_error},
            "hint_items": 0, "budget_padding_items": 2, "budget_padding_bytes": 64, "witness_items_coexist_at_entry": true});
        if let Some(txid) = funding {
            let mut tx = Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid,
                        vout: index as u32,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(FUNDING_VALUE - FEE),
                    script_pubkey: destination.clone(),
                }],
            };
            let mut data = match fixture.input {
                Input::Data(data) => data,
                Input::Signed {
                    extra,
                    codesep_position,
                    hash_type,
                    append_type,
                } => {
                    let digest = SighashCache::new(&tx)
                        .taproot_signature_hash(
                            0,
                            &Prevouts::All(&[prevout.clone()]),
                            None,
                            Some((leaf, codesep_position)),
                            hash_type,
                        )
                        .unwrap();
                    let signature = secp.sign_schnorr_no_aux_rand(
                        &Message::from_digest(digest.to_byte_array()),
                        &keypair(&SIGNING_SEED),
                    );
                    let mut bytes = signature.as_ref().to_vec();
                    if let Some(hash_type) = append_type {
                        bytes.push(hash_type);
                    }
                    row["signing"] = json!({"sighash_hex": digest.to_string(), "codesep_position": codesep_position,
                        "sighash_type": hash_type as u8, "appended_hashtype": append_type});
                    let mut data = vec![bytes];
                    data.extend(extra);
                    data
                }
            };
            data.extend([vec![0x55; 32], vec![0x66; 32]]);
            let mut complete = data.clone();
            complete.push(fixture.script.to_bytes());
            complete.push(control);
            tx.input[0].witness = Witness::from_slice(&complete);
            row["data_witness_hex"] = json!(data
                .iter()
                .map(|item| item.to_lower_hex_string())
                .collect::<Vec<_>>());
            row["local"] = local_execution(&fixture.script, &tx, prevout, &data);
            let data_witness_bytes = serialize(&Witness::from_slice(&data)).len();
            let static_non_push_opcodes = fixture
                .script
                .instructions()
                .filter(|instruction| {
                    matches!(instruction, Ok(Instruction::Op(opcode))
                    if !matches!(opcode.to_u8(), 0x4f | 0x51..=0x60))
                })
                .count();
            row["metrics"] = json!({"locking_script_bytes": fixture.script.len(), "data_items": data.len(),
                "hint_items": 0, "hint_bytes": 0, "data_witness_bytes": data_witness_bytes,
                "taproot_witness_items": tx.input[0].witness.len(),
                "taproot_witness_bytes": serialize(&tx.input[0].witness).len(),
                "stack_peak": row["local"]["stats"]["combined_stack_peak"],
                "static_non_push_opcodes": static_non_push_opcodes,
                "executed_non_push_opcodes": null,
                "nonempty_signature_checks_upper_bound": 1,
                // Local budget starts at 50 + serialized data witness bytes;
                // each fixture can incur at most one 50-unit signature charge.
                "data_only_validation_weight_lower_bound_after_one_check": data_witness_bytes,
                "local_deployment": "unclassified", "local_execution_context": "tapscript", "stack_limit_enforced": true});
            row["transaction"] = json!({"hex": serialize(&tx).to_lower_hex_string(), "txid": tx.compute_txid().to_string(),
                "wtxid": tx.compute_wtxid().to_string(), "weight": tx.weight().to_wu(), "vsize": tx.vsize()});
        }
        rows.push(row);
    }
    let core: Value =
        serde_json::from_str(include_str!("../tools/bitcoin_core_release.json")).unwrap();
    json!({"schema_version": 1, "experiment": "funded-tapscript-signature-semantics", "fixture_count": rows.len(),
        "funding_txid": funding.map(|txid| txid.to_string()), "funding_value_sat": FUNDING_VALUE, "fee_sat": FEE,
        "mining_address": Address::p2wsh(&ScriptBuf::from_bytes(vec![0x51]), Network::Regtest).to_string(),
        "destination_script_pubkey_hex": destination.as_bytes().to_lower_hex_string(),
        "expected_bitcoin_core_version": core["version"], "expected_bitcoin_core_commit": core["commit"],
        "signing_seed_hex": SIGNING_SEED.to_lower_hex_string(), "internal_seed_hex": INTERNAL_SEED.to_lower_hex_string(),
        "test_key_warning": "Public deterministic test keys; never use for real funds", "local_interpreter": interpreter_pin(),
        "fixtures": rows})
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let funding = match args.as_slice() {
        [] => None,
        [flag, txid] if flag == "--funding-txid" => {
            Some(Txid::from_str(txid).expect("funding txid"))
        }
        _ => panic!("usage: tapscript_signature_fixtures [--funding-txid HEX]"),
    };
    serde_json::to_writer_pretty(std::io::stdout().lock(), &document(funding)).unwrap();
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn funding_and_signed_modes_are_deterministic_and_bind_identical_leaves() {
        let manifest = document(None);
        assert_eq!(manifest, document(None));
        let funded = document(Some(Txid::from_byte_array([0x42; 32])));
        assert_eq!(funded, document(Some(Txid::from_byte_array([0x42; 32]))));
        for (commitment, spend) in manifest["fixtures"]
            .as_array()
            .unwrap()
            .iter()
            .zip(funded["fixtures"].as_array().unwrap())
        {
            for key in [
                "name",
                "script_hex",
                "script_pubkey_hex",
                "control_block_hex",
                "tapleaf_hash",
            ] {
                assert_eq!(commitment[key], spend[key]);
            }
            assert_eq!(spend["metrics"]["hint_items"], 0);
            assert!(spend["metrics"]["data_items"].as_u64().unwrap() <= 5);
            assert_eq!(
                spend["metrics"]["taproot_witness_items"].as_u64().unwrap(),
                spend["metrics"]["data_items"].as_u64().unwrap() + 2
            );
            let budget_floor = spend["metrics"]
                ["data_only_validation_weight_lower_bound_after_one_check"]
                .as_i64()
                .unwrap();
            assert!(budget_floor >= 67);
            if let Some(stats) = spend["local"]["stats"].as_object() {
                if let Some(remaining) = stats["remaining_data_only_validation_weight"].as_i64() {
                    assert!(remaining >= budget_floor);
                }
            }
        }
    }
}
