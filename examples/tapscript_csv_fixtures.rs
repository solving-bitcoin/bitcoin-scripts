//! Funded Tapscript CHECKSEQUENCEVERIFY boundary fixtures for pinned Core.
//!
//! This generator reports local execution, not complete transaction validity.
//! The isolated Core runner supplies the latter. Test keys are public.

use bitcoin::{
    absolute,
    consensus::serialize,
    hashes::Hash,
    hex::DisplayHex,
    script::Instruction,
    secp256k1::{Keypair, Secp256k1, SecretKey},
    taproot::{LeafVersion, TaprootBuilder},
    transaction, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};
use bitcoin_lab::support::{
    provenance,
    script::{script, ScriptCompilation},
};
use bitcoin_scriptexec::{Exec, Experimental, Options, TxTemplate};
use serde_json::{json, Value};
use std::{
    panic::{self, AssertUnwindSafe},
    str::FromStr,
    sync::Mutex,
};

const FUNDING_VALUE: u64 = 1_000_000;
const FEE: u64 = 10_000;
const TIME: u32 = 1 << 22;
const DISABLE: u32 = 1 << 31;
static PANIC_HOOK_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone)]
struct Case {
    name: &'static str,
    operand: Vec<u8>,
    version: i32,
    sequence: u32,
    script: ScriptBuf,
    consensus_error: Option<&'static str>,
    policy_error: Option<&'static str>,
}

fn number(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![];
    }
    let mut magnitude = value.unsigned_abs();
    let mut bytes = Vec::new();
    while magnitude != 0 {
        bytes.push(magnitude as u8);
        magnitude >>= 8;
    }
    if bytes.last().unwrap() & 0x80 != 0 {
        bytes.push(if value < 0 { 0x80 } else { 0 });
    } else if value < 0 {
        *bytes.last_mut().unwrap() |= 0x80;
    }
    bytes
}

fn cases() -> Vec<Case> {
    let csv = script! { OP_CSV OP_DROP OP_TRUE }.compile_with_policy();
    let cltv = script! { OP_CLTV OP_DROP OP_TRUE }.compile_with_policy();
    assert!(csv
        .instructions()
        .any(|instruction| matches!(instruction, Ok(Instruction::Op(op)) if op.to_u8() == 0xb2)));
    let mut cases = Vec::new();
    let mut add = |name,
                   operand: Vec<u8>,
                   version,
                   sequence,
                   consensus_error,
                   policy_error,
                   script: &ScriptBuf| {
        cases.push(Case {
            name,
            operand,
            version,
            sequence,
            script: script.clone(),
            consensus_error,
            policy_error,
        });
    };
    let high = 1_i64 << 32;
    add("csv-zero-control", number(0), 2, 0, None, None, &csv);
    add("csv-high-zero", number(high), 2, 0, None, None, &csv);
    add("csv-high-bit-38", number(1 << 38), 2, 0, None, None, &csv);
    add(
        "csv-high-height-exact",
        number(high | 5),
        2,
        5,
        None,
        None,
        &csv,
    );
    add(
        "csv-high-height-short",
        number(high | 6),
        2,
        5,
        Some("unsatisfied-locktime"),
        Some("unsatisfied-locktime"),
        &csv,
    );
    add(
        "csv-high-time-exact",
        number(high | i64::from(TIME) | 5),
        2,
        TIME | 5,
        None,
        None,
        &csv,
    );
    add(
        "csv-high-time-short",
        number(high | i64::from(TIME) | 6),
        2,
        TIME | 5,
        Some("unsatisfied-locktime"),
        Some("unsatisfied-locktime"),
        &csv,
    );
    add(
        "csv-height-to-time",
        number(high | 1),
        2,
        TIME | 1,
        Some("unsatisfied-locktime"),
        Some("unsatisfied-locktime"),
        &csv,
    );
    add(
        "csv-time-to-height",
        number(high | i64::from(TIME) | 1),
        2,
        1,
        Some("unsatisfied-locktime"),
        Some("unsatisfied-locktime"),
        &csv,
    );
    add(
        "csv-reserved-middle-bits",
        number(high | (1 << 30) | 5),
        2,
        5,
        None,
        None,
        &csv,
    );
    add(
        "csv-version-one",
        number(high),
        1,
        0,
        Some("unsatisfied-locktime"),
        Some("unsatisfied-locktime"),
        &csv,
    );
    add(
        "csv-input-disabled",
        number(high),
        2,
        DISABLE,
        Some("unsatisfied-locktime"),
        Some("unsatisfied-locktime"),
        &csv,
    );
    add(
        "csv-operand-disabled",
        number(high | i64::from(DISABLE)),
        1,
        u32::MAX,
        None,
        None,
        &csv,
    );
    add(
        "csv-max-five-byte-disabled",
        number((1_i64 << 39) - 1),
        1,
        u32::MAX,
        None,
        None,
        &csv,
    );
    add(
        "csv-negative",
        number(-1),
        2,
        0,
        Some("negative-locktime"),
        Some("negative-locktime"),
        &csv,
    );
    add(
        "csv-six-byte",
        number(1_i64 << 39),
        2,
        0,
        Some("numeric-overflow"),
        Some("numeric-overflow"),
        &csv,
    );
    add(
        "csv-nonminimal-zero",
        vec![0],
        2,
        0,
        None,
        Some("minimaldata"),
        &csv,
    );
    add(
        "csv-nonminimal-one",
        vec![1, 0],
        2,
        1,
        None,
        Some("minimaldata"),
        &csv,
    );
    add(
        "cltv-five-byte-overflow-control",
        number(high),
        2,
        0,
        Some("unsatisfied-locktime"),
        Some("unsatisfied-locktime"),
        &cltv,
    );
    assert_eq!(cases.len(), 19);
    cases
}

fn local(tx: &Transaction, prevout: &TxOut, require_minimal: bool) -> Value {
    let _guard = PANIC_HOOK_LOCK.lock().unwrap();
    let old_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let answer = panic::catch_unwind(AssertUnwindSafe(|| {
        let options = Options {
            require_minimal,
            verify_cltv: true,
            verify_csv: true,
            verify_minimal_if: true,
            enforce_stack_limit: true,
            experimental: Experimental { op_cat: false },
        };
        let mut exec = match Exec::new_tapscript(
            options,
            TxTemplate {
                tx: tx.clone(),
                prevouts: vec![prevout.clone()],
                input_idx: 0,
                taproot_annex_scriptleaf: None,
            },
        ) {
            Ok(exec) => exec,
            Err(error) => {
                return json!({"outcome":"initialization-error","accepted":null,
                "error":format!("{error:?}"),"stats":null})
            }
        };
        while exec.exec_next().is_ok() {}
        let result = exec.result().unwrap();
        let stats = exec.stats();
        json!({"outcome":"executed","accepted":result.success,
            "error":result.error.as_ref().map(|error|format!("{error:?}")),
            "stats":{"combined_stack_peak":stats.max_nb_stack_items,
                "initial_validation_weight":stats.start_validation_weight,
                "remaining_validation_weight":stats.validation_weight}})
    }));
    panic::set_hook(old_hook);
    answer.unwrap_or_else(
        |_| json!({"outcome":"panic","accepted":null,"error":"interpreter panic","stats":null}),
    )
}

fn document(funding: Option<Txid>) -> Value {
    let secp = Secp256k1::new();
    let internal = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[1; 32]).unwrap())
        .x_only_public_key()
        .0;
    let destination = ScriptBuf::new_p2wsh(&ScriptBuf::from_bytes(vec![0x51]).wscript_hash());
    let mut rows = Vec::new();
    for (index, case) in cases().into_iter().enumerate() {
        let spend = TaprootBuilder::new()
            .add_leaf(0, case.script.clone())
            .unwrap()
            .finalize(&secp, internal)
            .unwrap();
        let control = spend
            .control_block(&(case.script.clone(), LeafVersion::TapScript))
            .unwrap()
            .serialize();
        let prevout = TxOut {
            value: Amount::from_sat(FUNDING_VALUE),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(spend.output_key()),
        };
        let mut row = json!({"name":case.name,"funding_vout":index,"script_hex":case.script.as_bytes().to_lower_hex_string(),
            "control_block_hex":control.to_lower_hex_string(),"script_pubkey_hex":prevout.script_pubkey.as_bytes().to_lower_hex_string(),
            "data_witness_hex":[case.operand.to_lower_hex_string()],"operand_hex":case.operand.to_lower_hex_string(),
            "transaction_version":case.version,"input_sequence":case.sequence,"hint_items":0,
            "witness_data_items_coexist_at_entry":true,"compilation":"repository-policy",
            "expected":{"consensus":case.consensus_error.is_none(),"policy":case.policy_error.is_none(),
                "consensus_rejection":case.consensus_error,"policy_rejection":case.policy_error}});
        if let Some(txid) = funding {
            let mut tx = Transaction {
                version: transaction::Version(case.version),
                lock_time: absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid,
                        vout: index as u32,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::from_consensus(case.sequence),
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(FUNDING_VALUE - FEE),
                    script_pubkey: destination.clone(),
                }],
            };
            tx.input[0].witness = Witness::from_slice(&[
                case.operand.clone(),
                case.script.to_bytes(),
                control.clone(),
            ]);
            row["local_consensus"] = local(&tx, &prevout, false);
            row["local_policy"] = local(&tx, &prevout, true);
            let full_bytes = serialize(&tx.input[0].witness).len();
            let data_bytes = serialize(&Witness::from_slice(&[case.operand.clone()])).len();
            row["metrics"] = json!({"locking_script_bytes":case.script.len(),"data_items":1,"taproot_witness_items":3,
                "data_witness_bytes":data_bytes,"taproot_witness_bytes":full_bytes,"control_block_bytes":control.len(),
                "hint_items":0,"hint_bytes":0,"stack_peak":row["local_consensus"]["stats"]["combined_stack_peak"],
                "initial_validation_weight":50+full_bytes,"remaining_validation_weight":row["local_consensus"]["stats"]["remaining_validation_weight"],
                "static_non_push_opcodes":case.script.instructions().filter(|instruction| matches!(instruction, Ok(Instruction::Op(opcode)) if !matches!(opcode.to_u8(),0x4f|0x51..=0x60))).count(),
                "executed_non_push_opcodes":null,"local_execution_context":"tapscript","local_deployment":"unclassified",
                "stack_limit_enforced":true});
            row["transaction"] = json!({"hex":serialize(&tx).to_lower_hex_string(),"txid":tx.compute_txid().to_string(),
                "wtxid":tx.compute_wtxid().to_string(),"weight":tx.weight().to_wu(),"vsize":tx.vsize()});
        }
        rows.push(row);
    }
    let internal_seed = [1u8; 32];
    let release: Value =
        serde_json::from_str(include_str!("../tools/bitcoin_core_release.json")).unwrap();
    let interpreter = provenance::interpreter().unwrap();
    let compiler = provenance::compiler().unwrap();
    json!({"schema_version":1,"experiment":"funded-tapscript-csv-five-byte","fixture_count":rows.len(),
        "funding_txid":funding.map(|txid|txid.to_string()),"funding_value_sat":FUNDING_VALUE,"fee_sat":FEE,
        "mining_address":Address::p2wsh(&ScriptBuf::from_bytes(vec![0x51]),Network::Regtest).to_string(),
        "destination_script_pubkey_hex":destination.as_bytes().to_lower_hex_string(),
        "expected_bitcoin_core_version":release["version"],"expected_bitcoin_core_commit":release["commit"],
        "internal_seed_hex":internal_seed.to_lower_hex_string(),"test_key_warning":"Public deterministic test key; never use for real funds",
        "local_interpreter":{"name":interpreter.name,"source":interpreter.source,"commit":interpreter.commit,
            "constructor":"Exec::new_tapscript","context":"tapscript","stack_limit_enforced":true,
            "experimental_op_cat":false,"limitations":"Local leaf execution does not verify Taproot commitment, full transaction or relay policy. Numeric-policy options do not implement all Core standardness. Dynamic executed-opcode count unavailable."},
        "compiler":{"name":compiler.name,"source":compiler.source,"commit":compiler.commit,"policy":"repository-policy"},
        "fixtures":rows})
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let funding = match args.as_slice() {
        [] => None,
        [flag, txid] if flag == "--funding-txid" => {
            Some(Txid::from_str(txid).expect("funding txid"))
        }
        _ => panic!("usage: tapscript_csv_fixtures [--funding-txid HEX]"),
    };
    serde_json::to_writer_pretty(std::io::stdout().lock(), &document(funding)).unwrap();
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compiled_leaves_and_funded_outputs_are_deterministic() {
        let manifest = document(None);
        let funded = document(Some(Txid::from_byte_array([0x42; 32])));
        assert_eq!(funded, document(Some(Txid::from_byte_array([0x42; 32]))));
        for (commitment, row) in manifest["fixtures"]
            .as_array()
            .unwrap()
            .iter()
            .zip(funded["fixtures"].as_array().unwrap())
        {
            for (key, value) in commitment.as_object().unwrap() {
                assert_eq!(value, &row[key]);
            }
            assert_eq!(
                row["local_consensus"]["outcome"], "executed",
                "{}",
                row["name"]
            );
            assert_eq!(
                row["local_consensus"]["accepted"], row["expected"]["consensus"],
                "{}",
                row["name"]
            );
            assert_eq!(
                row["local_policy"]["accepted"], row["expected"]["policy"],
                "{}",
                row["name"]
            );
            assert_eq!(
                row["local_consensus"]["stats"]["initial_validation_weight"],
                row["metrics"]["initial_validation_weight"]
            );
        }
    }
}
