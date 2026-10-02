//! Shared deterministic report builder; no bytecode compiled outside policy.
use bitcoin::{
    consensus::encode::serialize,
    hashes::{sha256, Hash},
    script::Instruction,
    ScriptBuf, Witness,
};
use bitcoin_lab::support::{
    execution::ExecuteInfo,
    provenance,
    script::*,
    selection::compact_selected_items,
    tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
};
use serde_json::{json, Value};
#[path = "baseline.rs"]
pub mod baseline;
pub fn num(x: i64) -> Vec<u8> {
    let mut b = [0; 8];
    let n = bitcoin::script::write_scriptint(&mut b, x);
    b[..n].to_vec()
}
pub fn run(s: ScriptBuf, w: Vec<Vec<u8>>) -> ExecuteInfo {
    match execute_tapscript(s, w, TapscriptProfile::Consensus).outcome {
        TapscriptOutcome::Executed(r) => r,
        o => panic!("expected execution: {o:?}"),
    }
}
pub fn input(payloads: &[Vec<u8>], flags: &[bool]) -> Vec<Vec<u8>> {
    assert_eq!(payloads.len(), flags.len());
    payloads
        .iter()
        .zip(flags)
        .flat_map(|(x, &b)| [x.clone(), num(b.into())])
        .collect()
}
pub fn expected(payloads: &[Vec<u8>], flags: &[bool]) -> Vec<Vec<u8>> {
    let mut e: Vec<_> = payloads
        .iter()
        .zip(flags)
        .filter(|(_, b)| **b)
        .map(|(x, _)| x.clone())
        .collect();
    e.push(num(e.len() as i64));
    e
}
pub fn leaf(fragment: Script, e: &[Vec<u8>]) -> Script {
    script! {{fragment}for x in e.iter().rev(){{x.clone()}OP_EQUALVERIFY}OP_TRUE}
}
pub fn static_ops(s: &ScriptBuf) -> usize {
    s.instructions()
        .filter(|i| matches!(i,Ok(Instruction::Op(op))if op.to_u8()>0x60))
        .count()
}
fn sha(b: &[u8]) -> String {
    sha256::Hash::hash(b).to_string()
}
fn encoded(items: &[Vec<u8>]) -> Vec<u8> {
    serialize(&Witness::from_slice(items))
}
fn artifact(g: Script, w: &[Vec<u8>]) -> Value {
    let raw = g.len();
    let s = g.compile_with_policy();
    let r = run(s.clone(), w.to_vec());
    let output: Vec<_> = (0..r.final_stack.len())
        .map(|i| r.final_stack.get(i))
        .collect();
    json!({"raw_bytes":raw,"compile_options":if raw<=MAX_OPTIMIZER_INPUT_BYTES{"ALL"}else{"NONE"},"script_bytes":s.len(),"sha256":sha(s.as_bytes()),"static_non_push_opcodes":static_ops(&s),"max_stack_items":r.stats.max_nb_stack_items,"error":r.error.as_ref().map(|e|format!("{e:?}")),"clean_success":r.success,"output_items":output.len(),"output_sha256":if r.error.is_none(){Some(sha(&encoded(&output)))}else{None},"executed_opcodes":null,"validation_weight_charged":r.stats.start_validation_weight-r.stats.validation_weight})
}
pub fn report(revision: &str) -> Value {
    let mut rows = Vec::new();
    for (name, g, ns) in [
        (
            "reverse-native",
            compact_selected_items as fn(u32) -> Script,
            vec![0, 1, 2, 32, 128, 498, 499],
        ),
        (
            "forward-native",
            baseline::forward_native as fn(u32) -> Script,
            vec![0, 1, 2, 32, 128, 498, 499, 500],
        ),
        (
            "reverse-explicit",
            baseline::backward_explicit as fn(u32) -> Script,
            vec![0, 1, 2, 32, 128, 498, 499],
        ),
        (
            "forward-explicit",
            baseline::forward_explicit as fn(u32) -> Script,
            vec![0, 1, 2, 32, 128, 498, 499],
        ),
    ] {
        for n in ns {
            let sizes = if name == "reverse-native" || n == 32 || n == 499 {
                vec![1, 80, 520]
            } else {
                vec![1]
            };
            for size in sizes {
                for keep in [false, true] {
                    let payloads = vec![vec![0x42; size]; n as usize];
                    let flags = vec![keep; n as usize];
                    let w = input(&payloads, &flags);
                    let e = expected(&payloads, &flags);
                    let f = g(n);
                    rows.push(json!({"algorithm":name,"n":n,"payload_bytes":size,"payload_pattern":"0x42 repeated","flags":if keep{"all-keep"}else{"all-drop"},"data_items":2*n,"hint_items":0,"witness_bytes":encoded(&w).len(),"witness_sha256":sha(&encoded(&w)),"expected_output_items":e.len(),"expected_output_sha256":sha(&encoded(&e)),"fragment":artifact(f.clone(),&w),"leaf":artifact(leaf(f,&e),&w)}));
                }
            }
        }
    }
    let paths = [
        "src/support/selection/mod.rs",
        "src/support/script.rs",
        "src/support/execution.rs",
        "src/support/tapscript.rs",
        "src/support/provenance.rs",
        "src/arithmetic/scriptint/mod.rs",
        "src/arithmetic/u32/stack.rs",
        "Cargo.lock",
        "research/stable-stack-compaction/baseline.rs",
        "research/stable-stack-compaction/measure.rs",
        "examples/stable_stack_compaction_probe.rs",
        "tests/selection_contract.rs",
    ];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let bindings: serde_json::Map<_, _> = paths
        .into_iter()
        .map(|p| {
            (
                p.to_owned(),
                json!(sha(&std::fs::read(root.join(p)).unwrap())),
            )
        })
        .collect();
    json!({"schema_version":1,"source_revision":revision,"source_sha256":bindings,"compiler_source":provenance::compiler().unwrap().source,"interpreter_source":provenance::interpreter().unwrap().source,"evidence":"locally-reproduced","execution":"unclassified","profile":{"context":"Tapscript","require_minimal":false,"verify_minimal_if":true,"verify_cltv":true,"verify_csv":true,"enforce_stack_limit":true,"experimental_op_cat":false,"transaction":"synthetic empty transaction, data-only budget, no signatures"},"boundary":"Fragment includes selector validation under native MINIMALIF (or explicit numeric guards), routing, count and stable output restoration. Excludes input pushes and terminal predicates. Complete leaf checks count then every retained raw payload and leaves TRUE. Witness includes all 2n ordinary items/count/length prefixes, including discarded payloads; excludes script/control block/annex/transaction. Zero hints; all inputs coexist at entry; no caller items in report.","counter_note":"Executed non-push opcode counts unavailable: interpreter Tapscript counter includes pushes and inactive branch instructions. Static counts are separate. Zero signature weight charged is not a complete transaction budget measurement.","rows":rows})
}
