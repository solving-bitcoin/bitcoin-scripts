//! Deterministic artifacts shared by the report producer and binding test.
use bitcoin::{
    consensus::encode::serialize,
    hashes::{sha256, Hash},
    script::Instruction,
    ScriptBuf, Witness,
};
use bitcoin_lab::{
    arithmetic::checksums::adler32::adler32_state,
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
    let mut b = [0u8; 8];
    let n = bitcoin::script::write_scriptint(&mut b, x);
    b[..n].to_vec()
}
/// Closed-form weighted sum, distinct from the Script's recurrence.
pub fn states(v: &[u8]) -> [u32; 2] {
    let a = 1 + v.iter().map(|&x| u64::from(x)).sum::<u64>();
    let b = v.len() as u64
        + v.iter()
            .enumerate()
            .map(|(i, &x)| (v.len() - i) as u64 * u64::from(x))
            .sum::<u64>();
    [(a % 65521) as u32, (b % 65521) as u32]
}
pub fn run(script: ScriptBuf, witness: Vec<Vec<u8>>) -> ExecuteInfo {
    match execute_tapscript(script, witness, TapscriptProfile::Consensus).outcome {
        TapscriptOutcome::Executed(r) => r,
        o => panic!("expected executed local fragment: {o:?}"),
    }
}
pub fn leaf(fragment: Script, e: [u32; 2]) -> Script {
    script! {{fragment}{e[1]}OP_EQUALVERIFY{e[0]}OP_EQUALVERIFY OP_TRUE}
}
fn sha(bytes: &[u8]) -> String {
    sha256::Hash::hash(bytes).to_string()
}
fn policy(raw: usize) -> &'static str {
    if raw <= MAX_OPTIMIZER_INPUT_BYTES {
        "ALL"
    } else {
        "NONE"
    }
}
pub fn static_ops(s: &ScriptBuf) -> usize {
    s.instructions()
        .filter(|i| matches!(i, Ok(Instruction::Op(op)) if op.to_u8()>0x60))
        .count()
}
fn artifact(generated: Script, witness: &[Vec<u8>]) -> Value {
    let raw = generated.len();
    let compiled = generated.compile_with_policy();
    let r = run(compiled.clone(), witness.to_vec());
    let final_stack = r.error.is_none().then(|| {
        (0..r.final_stack.len())
            .map(|i| r.final_stack.get(i))
            .collect::<Vec<_>>()
    });
    json!({"raw_bytes":raw,"compile_options":policy(raw),"script_bytes":compiled.len(),
        "sha256":sha(compiled.as_bytes()),"static_non_push_opcodes":static_ops(&compiled),
        "max_stack_items":r.stats.max_nb_stack_items,"error":r.error.map(|e|format!("{e:?}")),
        "clean_success":r.success,"executed_opcodes":null,
        "validation_weight_charged":r.stats.start_validation_weight-r.stats.validation_weight,
        "final_stack":final_stack})
}
pub fn report(source_revision: &str) -> Value {
    let mut rows = Vec::new();
    for (name, g, sizes) in [
        (
            "delayed",
            adler32_state as fn(u32) -> Script,
            vec![0, 1, 2, 32, 128, 512, 728, 808, 809, 995, 997],
        ),
        (
            "bounded-streaming",
            baseline::bounded_streaming as fn(u32) -> Script,
            vec![0, 1, 2, 32, 128, 512, 728, 808, 809, 995, 997, 998],
        ),
        (
            "naive-streaming",
            baseline::naive_streaming as fn(u32) -> Script,
            vec![32, 728, 729, 997],
        ),
        (
            "interleaved",
            baseline::interleaved as fn(u32) -> Script,
            vec![32, 995, 996, 997],
        ),
    ] {
        for n in sizes {
            let v = vec![255u8; n as usize];
            let e = states(&v);
            let w = vec![num(255); n as usize];
            let serialized = serialize(&Witness::from_slice(&w));
            let f = g(n);
            rows.push(
                json!({"algorithm":name,"n":n,"input":"all-255 canonical ScriptNums",
                "state":e,"data_items":n,"hint_items":0,"witness_bytes":serialized.len(),
                "witness_sha256":sha(&serialized),"fragment":artifact(f.clone(), &w),
                "leaf":artifact(leaf(f,e),&w)}),
            );
        }
    }
    let paths = [
        "src/arithmetic/checksums/adler32.rs",
        "src/arithmetic/checksums/mod.rs",
        "src/arithmetic/mod.rs",
        "src/arithmetic/u32/stack.rs",
        "src/support/script.rs",
        "src/support/execution.rs",
        "src/support/tapscript.rs",
        "src/support/provenance.rs",
        "Cargo.lock",
        "research/adler32-delayed-reduction/baseline.rs",
        "research/adler32-delayed-reduction/measure.rs",
        "research/adler32-delayed-reduction/oracle.json",
        "research/adler32-delayed-reduction/oracle.py",
        "research/adler32-delayed-reduction/oracle-provenance.json",
        "examples/adler32_delayed_probe.rs",
        "tests/adler32_contract.rs",
        "tests/primitive_metrics.rs",
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
    json!({"schema_version":1,"source_revision":source_revision,
        "compiler_source":provenance::compiler().unwrap().source,
        "interpreter_source":provenance::interpreter().unwrap().source,"source_sha256":bindings,
        "evidence":"locally-reproduced","execution":"unclassified",
        "profile":{"context":"Tapscript","require_minimal":false,"verify_cltv":true,"verify_csv":true,
            "verify_minimal_if":true,"enforce_stack_limit":true,"experimental_op_cat":false,
            "transaction":"synthetic empty transaction, data-only witness budget; no signatures"},
        "boundary":"Canonical input validation, staging, computation and both normalized outputs included. Fragment excludes input pushes and terminal checks; leaf checks B then A and leaves TRUE. Data-witness serialization excludes script/control block/annex. All n data items coexist at entry; zero hints.",
        "counter_note":"Pinned interpreter's Tapscript opcode_count is an instruction-position counter including pushes and inactive branch instructions, not an executed non-push opcode counter; executed_opcodes remains null. Static non-push counts are separate. No signature checks means zero validation weight charged, not a full transaction budget measurement.","rows":rows})
}
