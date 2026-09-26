//! Complete, funded Taproot witnesses at signature-budget boundaries.
//!
//! The legacy fragment constructor is deliberately retained as a labeled
//! counterexample. The complete-witness constructor is compared independently
//! with Bitcoin Core by tools/tapscript_budget_regtest.py.

use bitcoin::{
    absolute,
    consensus::serialize,
    hashes::Hash,
    hex::DisplayHex,
    script::Instruction,
    secp256k1::{Keypair, Message, Secp256k1, SecretKey},
    sighash::{Annex, Prevouts, SighashCache, TapSighashType},
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
    sync::{LazyLock, Mutex},
};

const FUNDING_VALUE: u64 = 1_000_000;
const FEE: u64 = 10_000;
const SIGNING_SEED: [u8; 32] = [0x23; 32];
const INTERNAL_SEED: [u8; 32] = [0x01; 32];
static PANIC_HOOK_LOCK: Mutex<()> = Mutex::new(());
static PUBLIC_KEY: LazyLock<Vec<u8>> = LazyLock::new(|| {
    keypair(&SIGNING_SEED)
        .x_only_public_key()
        .0
        .serialize()
        .to_vec()
});

#[derive(Clone, Copy, Debug)]
enum Operation {
    Checksig,
    Checksigverify,
    Checksigadd,
}
impl Operation {
    fn name(self) -> &'static str {
        match self {
            Self::Checksig => "checksig",
            Self::Checksigverify => "checksigverify",
            Self::Checksigadd => "checksigadd",
        }
    }
    fn opcode(self) -> u8 {
        match self {
            Self::Checksig => 0xac,
            Self::Checksigverify => 0xad,
            Self::Checksigadd => 0xba,
        }
    }
}

#[derive(Clone)]
struct Fixture {
    name: String,
    operation: Operation,
    checks: usize,
    empty_last: bool,
    padding_bytes: usize,
    extra_items: usize,
    element_bytes: Option<usize>,
    control_depth: u8,
    annex_bytes: usize,
    script: ScriptBuf,
    consensus_error: Option<&'static str>,
    policy_error: Option<&'static str>,
}

fn keypair(seed: &[u8; 32]) -> Keypair {
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(seed).unwrap())
}

fn make_script(
    operation: Operation,
    checks: usize,
    empty_last: bool,
    discarded: usize,
) -> ScriptBuf {
    let script = script! {
        for _ in 0..discarded { OP_DROP }
        for index in 0..checks {
            // Keep the original signature/key pair live for every iteration.
            OP_2DUP
            if empty_last && index + 1 == checks { OP_SWAP OP_DROP OP_0 OP_SWAP }
            { match operation {
                Operation::Checksig => script! { OP_CHECKSIG OP_TOALTSTACK },
                Operation::Checksigverify => script! { OP_CHECKSIGVERIFY },
                Operation::Checksigadd => script! { OP_0 OP_SWAP OP_CHECKSIGADD OP_TOALTSTACK },
            } }
        }
        OP_2DROP
        for index in 0..checks {
            { match operation {
                Operation::Checksig => if empty_last && index == 0 { script! { OP_FROMALTSTACK OP_NOT OP_VERIFY } } else { script! { OP_FROMALTSTACK OP_VERIFY } },
                Operation::Checksigverify => script! {},
                Operation::Checksigadd => script! { OP_FROMALTSTACK { if empty_last && index == 0 { 0 } else { 1 } } OP_NUMEQUALVERIFY },
            } }
        }
        OP_TRUE
    }.compile_with_policy();
    assert_eq!(
        script
            .instructions()
            .filter(|op| matches!(op, Ok(Instruction::Op(op)) if op.to_u8() == operation.opcode()))
            .count(),
        checks,
        "compilation must retain every intended signature opcode"
    );
    script
}

fn control(fixture: &Fixture) -> (Vec<u8>, ScriptBuf) {
    let secp = Secp256k1::new();
    let internal = keypair(&INTERNAL_SEED).x_only_public_key().0;
    let mut builder = TaprootBuilder::new()
        .add_leaf(fixture.control_depth, fixture.script.clone())
        .unwrap();
    // A deterministic unbalanced tree gives the selected leaf exactly depth
    // siblings without constructing 2^depth leaves.
    for depth in (1..=fixture.control_depth).rev() {
        let sibling = script! { { i64::from(depth) } OP_DROP OP_TRUE }.compile_with_policy();
        builder = builder.add_leaf(depth, sibling).unwrap();
    }
    let spend = builder.finalize(&secp, internal).unwrap();
    let control = spend
        .control_block(&(fixture.script.clone(), LeafVersion::TapScript))
        .unwrap()
        .serialize();
    assert_eq!(control.len(), 33 + 32 * usize::from(fixture.control_depth));
    (control, ScriptBuf::new_p2tr_tweaked(spend.output_key()))
}

fn data(fixture: &Fixture, signature: Vec<u8>) -> Vec<Vec<u8>> {
    let mut data = vec![signature, PUBLIC_KEY.clone()];
    data.push(vec![0x55; fixture.padding_bytes]);
    data.extend((0..fixture.extra_items).map(|_| vec![]));
    if let Some(bytes) = fixture.element_bytes {
        data.push(vec![0x66; bytes]);
    }
    data
}

fn annex(fixture: &Fixture) -> Option<Vec<u8>> {
    (fixture.annex_bytes > 0).then(|| {
        let mut bytes = vec![0x77; fixture.annex_bytes];
        bytes[0] = 0x50;
        bytes
    })
}

fn witness(fixture: &Fixture, data: &[Vec<u8>], control: &[u8]) -> Witness {
    let mut items = data.to_vec();
    items.extend([fixture.script.to_bytes(), control.to_vec()]);
    if let Some(annex) = annex(fixture) {
        items.push(annex);
    }
    Witness::from_slice(&items)
}

fn full_budget(fixture: &Fixture) -> i64 {
    // Only serialization length matters while tuning; the real commitment is
    // constructed and independently checked after the final leaf is chosen.
    let control = vec![0; 33 + 32 * usize::from(fixture.control_depth)];
    50 + serialize(&witness(fixture, &data(fixture, vec![0; 64]), &control)).len() as i64
}

fn template(
    name: &str,
    operation: Operation,
    depth: u8,
    annex_bytes: usize,
    extras: usize,
    element: Option<usize>,
) -> Fixture {
    Fixture {
        name: name.into(),
        operation,
        checks: 0,
        empty_last: false,
        padding_bytes: 0,
        extra_items: extras,
        element_bytes: element,
        control_depth: depth,
        annex_bytes,
        script: ScriptBuf::new(),
        consensus_error: None,
        policy_error: (annex_bytes > 0 || element.is_some_and(|n| n > 80))
            .then_some("witness-nonstandard"),
    }
}

fn tune(mut fixture: Fixture, target_remaining: i64) -> Fixture {
    for checks in 1..100 {
        fixture.checks = checks;
        fixture.script = make_script(
            fixture.operation,
            checks,
            fixture.empty_last,
            1 + fixture.extra_items + usize::from(fixture.element_bytes.is_some()),
        );
        for padding in 0..=80 {
            fixture.padding_bytes = padding;
            let charges = checks - usize::from(fixture.empty_last);
            if full_budget(&fixture) - 50 * charges as i64 == target_remaining {
                fixture.consensus_error = if target_remaining < 0 {
                    Some("validation-weight")
                } else if fixture.empty_last
                    && matches!(fixture.operation, Operation::Checksigverify)
                {
                    Some("checksigverify")
                } else {
                    None
                };
                if fixture.policy_error.is_none() {
                    fixture.policy_error = fixture.consensus_error;
                }
                return fixture;
            }
        }
    }
    panic!(
        "cannot tune {} to remaining {target_remaining}",
        fixture.name
    )
}

fn fixtures() -> Vec<Fixture> {
    let mut fixtures = Vec::new();
    for operation in [
        Operation::Checksig,
        Operation::Checksigverify,
        Operation::Checksigadd,
    ] {
        let base = template(operation.name(), operation, 0, 0, 0, None);
        for (suffix, remaining) in [
            ("exact-zero", 0),
            ("one-unit-short", -1),
            ("next-charge-short", -50),
        ] {
            let mut fixture = base.clone();
            fixture.name = format!("{}-{suffix}", operation.name());
            fixtures.push(tune(fixture, remaining));
        }
        let mut empty = base;
        empty.name = format!("{}-empty-at-zero", operation.name());
        empty.empty_last = true;
        fixtures.push(tune(empty, 0));
    }
    for (name, depth, annex_bytes, extras, element) in [
        ("control-depth-1", 1, 0, 0, None),
        ("control-depth-6", 6, 0, 0, None),
        ("control-depth-7", 7, 0, 0, None),
        ("annex-1", 0, 1, 0, None),
        ("annex-252", 0, 252, 0, None),
        ("annex-253", 0, 253, 0, None),
        ("witness-count-252", 0, 0, 247, None),
        ("witness-count-253", 0, 0, 248, None),
        ("data-element-252", 0, 0, 0, Some(252)),
        ("data-element-253", 0, 0, 0, Some(253)),
    ] {
        let base = template(
            name,
            Operation::Checksigverify,
            depth,
            annex_bytes,
            extras,
            element,
        );
        for (suffix, remaining) in [("exact-zero", 0), ("one-unit-short", -1)] {
            let mut fixture = base.clone();
            fixture.name = format!("{name}-{suffix}");
            fixtures.push(tune(fixture, remaining));
        }
    }
    assert_eq!(fixtures.len(), 32);
    fixtures
}

fn local_execution(
    fixture: &Fixture,
    tx: &Transaction,
    prevout: &TxOut,
    data: &[Vec<u8>],
    full: bool,
) -> Value {
    let _lock = PANIC_HOOK_LOCK.lock().unwrap();
    let hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let options = Options {
            require_minimal: false,
            verify_minimal_if: true,
            verify_cltv: true,
            verify_csv: true,
            enforce_stack_limit: true,
            experimental: Experimental { op_cat: false },
        };
        let context = TxTemplate {
            tx: tx.clone(),
            prevouts: vec![prevout.clone()],
            input_idx: 0,
            taproot_annex_scriptleaf: Some((
                TapLeafHash::from_script(&fixture.script, LeafVersion::TapScript),
                annex(fixture),
            )),
        };
        let initialized = if full {
            Exec::new_tapscript(options, context)
        } else {
            Exec::new(
                ExecCtx::Tapscript,
                options,
                context,
                fixture.script.clone(),
                data.to_vec(),
            )
        };
        let mut exec = match initialized {
            Ok(exec) => exec,
            Err(error) => {
                return json!({"outcome":"initialization-error", "accepted":null, "error":format!("{error:?}"), "stats":null})
            }
        };
        while exec.exec_next().is_ok() {}
        let result = exec.result().unwrap();
        let stats = exec.stats();
        json!({"outcome":"executed", "accepted":result.success,
            "error":result.error.as_ref().map(|error|format!("{error:?}")),
            "final_stack_hex":exec.stack().iter_str().map(|item|item.to_lower_hex_string()).collect::<Vec<_>>(),
            "stats":{"combined_stack_peak":stats.max_nb_stack_items, "initial_validation_weight":stats.start_validation_weight,
                "remaining_validation_weight":stats.validation_weight}})
    }));
    panic::set_hook(hook);
    result.unwrap_or_else(
        |_| json!({"outcome":"panic", "accepted":null, "error":"interpreter panic", "stats":null}),
    )
}

fn document(funding: Option<Txid>) -> Value {
    let secp = Secp256k1::new();
    let destination = ScriptBuf::new_p2wsh(&ScriptBuf::from_bytes(vec![0x51]).wscript_hash());
    let mut rows = Vec::new();
    for (index, fixture) in fixtures().into_iter().enumerate() {
        let (control, script_pubkey) = control(&fixture);
        let prevout = TxOut {
            value: Amount::from_sat(FUNDING_VALUE),
            script_pubkey,
        };
        let leaf = TapLeafHash::from_script(&fixture.script, LeafVersion::TapScript);
        let mut row = json!({"name":fixture.name, "funding_vout":index, "script_hex":fixture.script.as_bytes().to_lower_hex_string(),
            "control_block_hex":control.to_lower_hex_string(), "script_pubkey_hex":prevout.script_pubkey.as_bytes().to_lower_hex_string(),
            "tapleaf_hash":leaf.to_string(), "compilation":"repository-policy", "operation":fixture.operation.name(),
            "signature_opcodes":fixture.checks, "nonempty_signature_checks":fixture.checks-usize::from(fixture.empty_last),
            "empty_signature_checks":usize::from(fixture.empty_last), "control_depth":fixture.control_depth,
            "annex_hex":annex(&fixture).map(|bytes|bytes.to_lower_hex_string()), "padding_bytes":fixture.padding_bytes,
            "expected":{"consensus":fixture.consensus_error.is_none(), "policy":fixture.policy_error.is_none(),
                "consensus_rejection":fixture.consensus_error, "policy_rejection":fixture.policy_error},
            "hint_items":0, "witness_data_items_coexist_at_entry":true});
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
            let annex_bytes = annex(&fixture);
            let digest = SighashCache::new(&tx)
                .taproot_signature_hash(
                    0,
                    &Prevouts::All(&[prevout.clone()]),
                    annex_bytes
                        .as_deref()
                        .map(|bytes| Annex::new(bytes).unwrap()),
                    Some((leaf, u32::MAX)),
                    TapSighashType::Default,
                )
                .unwrap();
            let signature = secp.sign_schnorr_no_aux_rand(
                &Message::from_digest(digest.to_byte_array()),
                &keypair(&SIGNING_SEED),
            );
            let data = data(&fixture, signature.as_ref().to_vec());
            tx.input[0].witness = witness(&fixture, &data, &control);
            row["data_witness_hex"] = json!(data
                .iter()
                .map(|bytes| bytes.to_lower_hex_string())
                .collect::<Vec<_>>());
            row["signing"] = json!({"sighash_hex":digest.to_string(), "sighash_type":0, "codesep_position":u32::MAX});
            row["local_legacy_fragment"] = local_execution(&fixture, &tx, &prevout, &data, false);
            row["local_full_witness"] = local_execution(&fixture, &tx, &prevout, &data, true);
            let full_bytes = serialize(&tx.input[0].witness).len();
            let data_bytes = serialize(&Witness::from_slice(&data)).len();
            let charges = fixture.checks - usize::from(fixture.empty_last);
            row["metrics"] = json!({"locking_script_bytes":fixture.script.len(), "control_block_bytes":control.len(),
                "annex_bytes":fixture.annex_bytes, "data_items":data.len(), "hint_items":0, "hint_bytes":0,
                "data_witness_bytes":data_bytes, "taproot_witness_items":tx.input[0].witness.len(), "taproot_witness_bytes":full_bytes,
                "initial_full_witness_validation_weight":50+full_bytes, "initial_data_only_validation_weight":50+data_bytes,
                "requested_validation_weight":50*charges, "expected_remaining_if_all_checks_charged":50+full_bytes as i64-50*charges as i64,
                "stack_peak":row["local_full_witness"]["stats"]["combined_stack_peak"],
                "static_non_push_opcodes":fixture.script.instructions().filter(|instruction| matches!(instruction, Ok(Instruction::Op(opcode)) if !matches!(opcode.to_u8(), 0x4f | 0x51..=0x60))).count(),
                "executed_non_push_opcodes":null, "local_deployment":"unclassified", "local_execution_context":"tapscript", "stack_limit_enforced":true});
            row["transaction"] = json!({"hex":serialize(&tx).to_lower_hex_string(), "txid":tx.compute_txid().to_string(),
                "wtxid":tx.compute_wtxid().to_string(), "weight":tx.weight().to_wu(), "vsize":tx.vsize()});
        }
        rows.push(row);
    }
    let core: Value =
        serde_json::from_str(include_str!("../tools/bitcoin_core_release.json")).unwrap();
    let interpreter = provenance::interpreter().unwrap();
    let compiler = provenance::compiler().unwrap();
    json!({"schema_version":1, "experiment":"funded-tapscript-signature-budget", "fixture_count":rows.len(), "funding_txid":funding.map(|txid|txid.to_string()),
        "funding_value_sat":FUNDING_VALUE, "fee_sat":FEE, "mining_address":Address::p2wsh(&ScriptBuf::from_bytes(vec![0x51]),Network::Regtest).to_string(),
        "destination_script_pubkey_hex":destination.as_bytes().to_lower_hex_string(), "expected_bitcoin_core_version":core["version"], "expected_bitcoin_core_commit":core["commit"],
        "signing_seed_hex":SIGNING_SEED.to_lower_hex_string(), "internal_seed_hex":INTERNAL_SEED.to_lower_hex_string(),
        "test_key_warning":"Public deterministic test keys; never use for real funds",
        "local_interpreter":{"name":interpreter.name,"source":interpreter.source,"commit":interpreter.commit,
            "context":"tapscript","require_minimal":false,"stack_limit_enforced":true,"experimental_op_cat":false,
            "legacy_constructor":"Exec::new: serialized initial data stack only; retained counterexample, not historical source revision",
            "full_witness_constructor":"Exec::new_tapscript: complete current-input witness including script, control block and annex",
            "limitations":"Constructor does not establish Taproot output commitment or full consensus/policy validity. Core checks the complete funded spend independently. Remaining budget on instruction failure is recorded from the repaired interpreter only. Executed non-push count is unavailable."},
        "compiler":{"name":compiler.name,"source":compiler.source,"commit":compiler.commit,"policy":"repository-policy"}, "fixtures":rows})
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let funding = match args.as_slice() {
        [] => None,
        [flag, txid] if flag == "--funding-txid" => {
            Some(Txid::from_str(txid).expect("funding txid"))
        }
        _ => panic!("usage: tapscript_budget_fixtures [--funding-txid HEX]"),
    };
    serde_json::to_writer_pretty(std::io::stdout().lock(), &document(funding)).unwrap();
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tuned_boundaries_keep_all_signature_operations_and_expected_serialization() {
        for fixture in fixtures() {
            let remaining = full_budget(&fixture)
                - 50 * (fixture.checks - usize::from(fixture.empty_last)) as i64;
            assert_eq!(
                remaining,
                if fixture.name.ends_with("one-unit-short") {
                    -1
                } else if fixture.name.ends_with("next-charge-short") {
                    -50
                } else {
                    0
                },
                "{}",
                fixture.name
            );
            if fixture.name.starts_with("witness-count-") {
                let count = fixture
                    .name
                    .split('-')
                    .nth(2)
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                assert_eq!(data(&fixture, vec![0; 64]).len() + 2, count);
            }
        }
    }
    #[test]
    fn funded_mode_is_deterministic_and_matches_the_funding_commitments() {
        let manifest = document(None);
        let funded = document(Some(Txid::from_byte_array([0x42; 32])));
        assert_eq!(funded, document(Some(Txid::from_byte_array([0x42; 32]))));
        for (commitment, fixture) in manifest["fixtures"]
            .as_array()
            .unwrap()
            .iter()
            .zip(funded["fixtures"].as_array().unwrap())
        {
            for (key, value) in commitment.as_object().unwrap() {
                assert_eq!(value, &fixture[key]);
            }
            assert_eq!(fixture["local_full_witness"]["outcome"], "executed");
            assert_eq!(
                fixture["local_full_witness"]["accepted"], fixture["expected"]["consensus"],
                "{}",
                fixture["name"]
            );
            assert_eq!(
                fixture["local_full_witness"]["stats"]["initial_validation_weight"],
                fixture["metrics"]["initial_full_witness_validation_weight"]
            );
            assert_eq!(
                fixture["local_full_witness"]["stats"]["remaining_validation_weight"],
                fixture["metrics"]["expected_remaining_if_all_checks_charged"]
            );
        }
    }
}
