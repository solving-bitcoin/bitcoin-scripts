//! Deterministic whole-artifact report using the centralized compiler policy.
use bitcoin::{
    consensus::encode::serialize,
    hashes::{sha256, Hash},
    script::Instruction,
    ScriptBuf, Witness,
};
use bitcoin_lab::{
    arithmetic::{
        scriptint::mul_by_constant,
        u4::{damm::u4_decimal_digits_to_damm, stack::u4_drop},
    },
    support::{
        execution::ExecuteInfo,
        provenance,
        script::*,
        tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
    },
};
use serde_json::{json, Value};
#[path = "baseline.rs"]
pub mod baseline;
pub fn num(x: i64) -> Vec<u8> {
    let mut b = [0; 8];
    let n = bitcoin::script::write_scriptint(&mut b, x);
    b[..n].to_vec()
}
pub fn expected(d: &[u8]) -> u8 {
    d.iter()
        .fold(0, |s, &x| baseline::Q[s as usize][x as usize])
}
pub fn run(s: ScriptBuf, w: Vec<Vec<u8>>) -> ExecuteInfo {
    match execute_tapscript(s, w, TapscriptProfile::Consensus).outcome {
        TapscriptOutcome::Executed(r) => r,
        o => panic!("unexpected outcome: {o:?}"),
    }
}
pub fn leaf(f: Script, out: u8) -> Script {
    script! {{f}{out}OP_EQUALVERIFY OP_TRUE}
}
fn sha(b: &[u8]) -> String {
    sha256::Hash::hash(b).to_string()
}
pub fn encoded(w: &[Vec<u8>]) -> Vec<u8> {
    serialize(&Witness::from_slice(w))
}
fn artifact(g: Script, w: &[Vec<u8>]) -> Value {
    let raw = g.len();
    let s = g.compile_with_policy();
    let r = run(s.clone(), w.to_vec());
    let out: Vec<_> = (0..r.final_stack.len())
        .map(|i| r.final_stack.get(i))
        .collect();
    let policy = match execute_tapscript(s.clone(), w.to_vec(), TapscriptProfile::Policy).outcome {
        TapscriptOutcome::Executed(r) => {
            json!({"error":r.error.as_ref().map(|e|format!("{e:?}")),"clean_success":r.success})
        }
        o => panic!("unexpected policy outcome: {o:?}"),
    };
    json!({"raw_bytes":raw,"compile_options":if raw<=MAX_OPTIMIZER_INPUT_BYTES{"ALL"}else{"NONE"},"script_bytes":s.len(),"sha256":sha(s.as_bytes()),"static_non_push_opcodes":s.instructions().filter(|i|matches!(i,Ok(Instruction::Op(op))if op.to_u8()>0x60)).count(),"max_stack_items":r.stats.max_nb_stack_items,"error":r.error.as_ref().map(|e|format!("{e:?}")),"clean_success":r.success,"output_items":out.len(),"output_sha256":if r.error.is_none(){Some(sha(&encoded(&out)))}else{None},"executed_opcodes":null,"validation_weight_charged":r.stats.start_validation_weight-r.stats.validation_weight,"local_policy":policy})
}
fn row(name: &str, g: fn(u32) -> Script, n: u32, pattern: &str, wide: bool) -> Value {
    let d: Vec<_> = (0..n)
        .map(|i| match pattern {
            "zeros" => 0,
            "nines" => 9,
            "mixed" => ((7 * i + 3) % 10) as u8,
            _ => panic!("pattern"),
        })
        .collect();
    let w: Vec<_> = d
        .iter()
        .map(|&d| {
            if wide {
                vec![d, 0, 0, 0]
            } else {
                num(d.into())
            }
        })
        .collect();
    let out = expected(&d);
    let f = g(n);
    json!({"algorithm":name,"n":n,"digit_pattern":pattern,"encoding":if wide{"four-byte-alias"}else{"canonical"},"data_items":n,"hint_items":0,"hint_bytes":0,"witness_bytes":encoded(&w).len(),"witness_sha256":sha(&encoded(&w)),"expected_digit":out,"expected_output_sha256":sha(&encoded(&[num(out.into())])),"fragment":artifact(f.clone(),&w),"leaf":artifact(leaf(f,out),&w)})
}
/// Independently compile lifecycle components, then attribute the whole-policy delta.
fn resident_breakdown(n: u32) -> Value {
    let (table, initial_state, queries, cleanup) = if n == 0 {
        (script! {}, script! {0}, script! {}, script! {})
    } else {
        (
            script! {for a in (0..10).rev(){for b in (0..10).rev(){{baseline::Q[a][b]}}}},
            script! {0},
            script! {for i in 0..n {
                {100+n-i} OP_ROLL
                {baseline::guard()} OP_SWAP {mul_by_constant(10)} OP_ADD OP_PICK
            }},
            script! {OP_TOALTSTACK {u4_drop(100)} OP_FROMALTSTACK},
        )
    };
    let parts = [table, initial_state, queries, cleanup].map(|s| s.compile_with_policy().len());
    let sum: usize = parts.iter().sum();
    let total = u4_decimal_digits_to_damm(n).compile_with_policy().len();
    json!({"digit_count":n,"table_setup_bytes":parts[0],"initial_state_bytes":parts[1],"validated_query_and_routing_bytes":parts[2],"table_cleanup_and_state_restore_bytes":parts[3],"component_bytes_sum":sum,"whole_script_bytes":total,"whole_optimizer_delta":total as i64-sum as i64,"boundary":"Independently policy-compiled table pushes, zero initial state, all n validated/routed queries, and table cleanup preserving final state. Whole optimizer delta reconciles their sum with the final public fragment. No reusable-table API or per-digit constant byte cost is implied."})
}
/// Preloaded independent 32-digit messages, with distinct known states.
pub fn independent_groups(repeats: u32) -> (Script, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let targets: Vec<u8> = (0..repeats).map(|i| [4, 7, 9][i as usize % 3]).collect();
    let mut w = Vec::new();
    for &target in &targets {
        w.extend(vec![num(0); 31]);
        let last = baseline::Q[0].iter().position(|&v| v == target).unwrap();
        w.push(num(last as i64));
    }
    let e: Vec<_> = targets.iter().map(|&x| num(x.into())).collect();
    let f = script! {
        for _ in 0..repeats {{u4_decimal_digits_to_damm(32)} OP_TOALTSTACK}
        for _ in 0..repeats {OP_FROMALTSTACK}
    };
    (f, w, e)
}
fn composition(repeats: u32) -> Value {
    let (f, w, e) = independent_groups(repeats);
    let fragment = artifact(f.clone(), &w);
    let leaf = script! {{f}for x in e.iter().rev(){{x.clone()}OP_EQUALVERIFY}OP_TRUE};
    let components =
        repeats as usize * (u4_decimal_digits_to_damm(32).compile_with_policy().len() + 2);
    json!({"id":format!("independent{repeats}x32"),"digit_count":32,"repeat_count":repeats,"digit_pattern":"Each message: 31 zero digits, then unique row-zero column yielding cycling targets 4,7,9","encoding":"canonical","expected_digits":(0..repeats).map(|i|[4,7,9][i as usize%3]).collect::<Vec<_>>(),"data_items":32*repeats,"hint_items":0,"hint_bytes":0,"witness_bytes":encoded(&w).len(),"witness_sha256":sha(&encoded(&w)),"expected_output_sha256":sha(&encoded(&e)),"component_bytes_sum":components,"composition_optimizer_delta":fragment["script_bytes"].as_i64().unwrap()-components as i64,"fragment":fragment,"leaf":artifact(leaf,&w),"boundary":"All 32*repeat_count ordinary items coexist at entry. Each public fold consumes the top remaining message with a fresh zero state and parks its output above caller altstack; outputs are restored in original message order. Fragment includes all table lifecycles and park/restore operations; leaf binds every final state then TRUE. Zero hints. Future messages and accumulated results are included in combined peak."})
}
pub fn report(revision: &str) -> Value {
    let mut rows = Vec::new();
    for n in [0, 1, 2, 8, 32, 128, 896] {
        for pattern in ["mixed", "zeros", "nines"] {
            rows.push(row(
                "resident",
                u4_decimal_digits_to_damm,
                n,
                pattern,
                false,
            ));
        }
        rows.push(row("resident", u4_decimal_digits_to_damm, n, "mixed", true));
    }
    rows.push(row(
        "resident-unbounded",
        baseline::resident_unbounded,
        897,
        "mixed",
        false,
    ));
    for (name, g, cap) in [
        ("dispatch", baseline::dispatch as fn(u32) -> Script, 997),
        ("warmup", baseline::warmup as fn(u32) -> Script, 897),
        ("row-table", baseline::row_table as fn(u32) -> Script, 990),
    ] {
        for n in [0, 1, 2, 8, 32, 128, 896, cap, cap + 1] {
            rows.push(row(name, g, n, "mixed", false));
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let paths = [
        "src/arithmetic/u4/damm/mod.rs",
        "src/arithmetic/scriptint/mod.rs",
        "src/arithmetic/u4/stack.rs",
        "src/arithmetic/u4/sum.rs",
        "src/support/script.rs",
        "src/support/execution.rs",
        "src/support/tapscript.rs",
        "src/support/provenance.rs",
        "Cargo.lock",
        "research/damm-finite-state/baseline.rs",
        "research/damm-finite-state/measure.rs",
        "research/damm-finite-state/verify_metrics.py",
        "examples/damm_metrics.rs",
        "tests/damm_contract.rs",
        "research/damm-finite-state/reference/DammAlgorithm.cs",
        "research/damm-finite-state/reference/DammQuasigroupTable.cs",
        "research/damm-finite-state/reference/LICENSE.txt",
    ];
    let bindings: serde_json::Map<_, _> = paths
        .into_iter()
        .map(|p| {
            (
                p.to_owned(),
                json!(sha(&std::fs::read(root.join(p)).unwrap())),
            )
        })
        .collect();
    json!({"schema_version":1,"source_revision":revision,"source_sha256":bindings,"compiler_source":provenance::compiler().unwrap().source,"interpreter_source":provenance::interpreter().unwrap().source,"evidence":"locally-reproduced","execution":"unclassified","profile":{"context":"Tapscript","require_minimal":false,"verify_minimal_if":true,"verify_cltv":true,"verify_csv":true,"enforce_stack_limit":true,"experimental_op_cat":false,"transaction":"synthetic empty transaction, data-only witness budget, no signatures"},"boundary":"Fragment includes all table setup/cleanup, hostile numeric digit validation, forward routing, state initially zero and final canonical state. Excludes witness pushes and terminal predicates. Leaf checks exact final digit then TRUE. Witness includes all n ordinary data items and serialization prefixes; excludes script/control block/annex/transaction. Zero hints; all data present at entry; no caller state in report.","counter_note":"Static non-push counts are separate. Dynamic executed counts unavailable: the interpreter position counter includes pushes and inactive instructions. Zero signature weight charged is not a complete transaction budget. Local Policy outcomes are partial fragment checks, not relay classification.","reference_revision":"734afa2d3596862ef4c3bb3ec404b512b96b8965","resident_breakdowns":([0,1,2,8,32,128,896].map(resident_breakdown)),"rows":rows,"compositions":[composition(2),composition(3),composition(28),composition(29)]})
}
