//! Policy-produced whole artifacts; scalar and all-inputs-preloaded boundaries.
use bitcoin::{
    consensus::encode::serialize,
    hashes::{sha256, Hash},
    script::Instruction,
    ScriptBuf, Witness,
};
use bitcoin_lab::{
    arithmetic::{integer_root::scriptnum_isqrt, scriptint::verify_canonical},
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
pub fn restoring_canonical(bits: u32) -> Script {
    script! {{verify_canonical()}{scriptnum_isqrt(bits)}}
}
pub fn thresholds_canonical(bits: u32) -> Script {
    script! {{verify_canonical()}{baseline::thresholds(bits)}}
}
pub fn num(x: i64) -> Vec<u8> {
    let mut b = [0; 8];
    let n = bitcoin::script::write_scriptint(&mut b, x);
    b[..n].to_vec()
}
pub fn sha(b: &[u8]) -> String {
    sha256::Hash::hash(b).to_string()
}
pub fn encoded(w: &[Vec<u8>]) -> Vec<u8> {
    serialize(&Witness::from_slice(w))
}
pub fn run(s: ScriptBuf, w: Vec<Vec<u8>>) -> ExecuteInfo {
    match execute_tapscript(s, w, TapscriptProfile::Consensus).outcome {
        TapscriptOutcome::Executed(r) => r,
        o => panic!("unexpected {o:?}"),
    }
}
fn artifact(g: Script, w: &[Vec<u8>]) -> Value {
    let raw = g.len();
    let s = g.compile_with_policy();
    let r = run(s.clone(), w.to_vec());
    let out: Vec<_> = (0..r.final_stack.len())
        .map(|i| r.final_stack.get(i))
        .collect();
    let p = match execute_tapscript(s.clone(), w.to_vec(), TapscriptProfile::Policy).outcome {
        TapscriptOutcome::Executed(r) => {
            json!({"error":r.error.as_ref().map(|e|format!("{e:?}")),"clean_success":r.success})
        }
        o => panic!("unexpected {o:?}"),
    };
    json!({"raw_bytes":raw,"compile_options":if raw<=32768{"ALL"}else{"NONE"},"script_bytes":s.len(),"sha256":sha(s.as_bytes()),"static_non_push_opcodes":s.instructions().filter(|i|matches!(i,Ok(Instruction::Op(op))if op.to_u8()>0x60)).count(),"max_stack_items":r.stats.max_nb_stack_items,"error":r.error.as_ref().map(|e|format!("{e:?}")),"clean_success":r.success,"output_items":out.len(),"output_sha256":if r.error.is_none(){Some(sha(&encoded(&out)))}else{None},"executed_opcodes":null,"validation_weight_charged":r.stats.start_validation_weight-r.stats.validation_weight,"local_policy":p})
}
fn row(name: &str, g: fn(u32) -> Script, bits: u32, pattern: &str, wide: bool) -> Value {
    let x = match pattern {
        "zero" => 0,
        "one" => 1,
        "max" => baseline::max(bits),
        "middle" => baseline::max(bits) / 2,
        _ => panic!("pattern"),
    };
    let q = baseline::host_root(x);
    let mut b = num(x.into());
    if wide {
        b.resize(4, 0)
    }
    let w = vec![b];
    let f = g(bits);
    json!({"algorithm":name,"bit_count":bits,"input_pattern":pattern,"input":x,"encoding":if wide{"four-byte-alias"}else{"canonical"},"expected_root":q,"expected_output_sha256":sha(&encoded(&[num(q.into())])),"data_items":1,"hint_items":0,"hint_bytes":0,"witness_bytes":encoded(&w).len(),"witness_sha256":sha(&encoded(&w)),"fragment":artifact(f.clone(),&w),"leaf":artifact(script!{{f}{q}OP_EQUALVERIFY OP_TRUE},&w)})
}
pub fn independent_roots(bits: u32, repeats: u32) -> (Script, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let d: Vec<_> = (0..repeats)
        .map(|i| {
            [0, 1, 2, 3, 16, 65535, 0x13579b, baseline::max(bits)][i as usize % 8]
                .min(baseline::max(bits))
        })
        .collect();
    let w = d.iter().map(|&x| num(x.into())).collect();
    let e = d
        .iter()
        .map(|&x| num(baseline::host_root(x).into()))
        .collect();
    (
        script! {for _ in 0..repeats{{scriptnum_isqrt(bits)}OP_TOALTSTACK}for _ in 0..repeats{OP_FROMALTSTACK}},
        w,
        e,
    )
}
pub fn bound_outputs(f: Script, e: &[Vec<u8>]) -> Script {
    script! {{f}for x in e.iter().rev(){{x.clone()}OP_EQUALVERIFY}OP_TRUE}
}
fn composition(bits: u32, repeats: u32) -> Value {
    let (f, w, e) = independent_roots(bits, repeats);
    let a = artifact(f.clone(), &w);
    let g = scriptnum_isqrt(bits);
    let component_bytes_sum = repeats as usize * (g.clone().compile_with_policy().len() + 2);
    let component_raw_bytes_sum = repeats as usize * (g.len() + 2);
    json!({"id":format!("independent{repeats}x{bits}"),"bit_count":bits,"repeat_count":repeats,"input_pattern":"cycle 0,1,2,3,16,65535,0x13579b,max clipped to bit width","encoding":"canonical","data_items":repeats,"hint_items":0,"hint_bytes":0,"expected_roots":(0..repeats).map(|i|baseline::host_root([0,1,2,3,16,65535,0x13579b,baseline::max(bits)][i as usize%8].min(baseline::max(bits)))).collect::<Vec<_>>(),"expected_output_sha256":sha(&encoded(&e)),"witness_bytes":encoded(&w).len(),"witness_sha256":sha(&encoded(&w)),"component_bytes_sum":component_bytes_sum,"component_raw_bytes_sum":component_raw_bytes_sum,"whole_policy_delta":a["script_bytes"].as_i64().unwrap()-component_bytes_sum as i64,"fragment":a,"leaf":artifact(bound_outputs(f,&e),&w),"boundary":"All repeat_count ordinary inputs coexist at entry; zero hints. Top remaining input is consumed, its root parked above caller altstack; roots restored in original order. Includes all root computations, parking/restoration and future inputs/produced roots in combined peak; leaf binds every exact root then TRUE. Excludes witness pushes and transaction framing. Fragment component sum uses individually ALL-compiled scalar folds plus park/restore; fragment whole-policy delta includes policy changes when the whole raw script exceeds 32 KiB (NONE, explicitly unoptimized)."})
}
fn family_contract(name: &str, g: fn(u32) -> Script, canonical: bool) -> Value {
    let f = g(16);
    let w = vec![num(65535)];
    let alias = vec![vec![1, 0]];
    json!({"algorithm":name,"bit_count":16,"canonical_input":canonical,"data_items":1,"hint_items":0,"hint_bytes":0,"maximum_control_input":65535,"maximum_control_root":255,"maximum_control_witness_sha256":sha(&encoded(&w)),"fragment":artifact(f.clone(),&w),"leaf":artifact(script!{{f}255 OP_EQUALVERIFY OP_TRUE},&w),"alias_control_input":1,"alias_control_encoding_hex":"0100","alias_control_artifact":artifact(g(16),&alias),"boundary":"One runtime scalar input; numeric and canonical compositions keep their distinct contracts. The shared test suite exhausts all 65536 16-bit inputs for each of these exact fragments, and binds this artifact serialization to the same family generator."})
}
pub fn report(rev: &str) -> Value {
    let mut rows = Vec::new();
    for bits in [1, 2, 3, 4, 5, 6, 7, 8, 16, 24, 31] {
        for p in ["zero", "max", "middle"] {
            rows.push(row("restoring", scriptnum_isqrt, bits, p, false))
        }
        rows.push(row("restoring", scriptnum_isqrt, bits, "one", true));
        for p in ["zero", "max"] {
            rows.push(row("thresholds", baseline::thresholds, bits, p, false))
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut bindings = serde_json::Map::new();
    for p in [
        "src/arithmetic/integer_root/mod.rs",
        "src/arithmetic/scriptint/mod.rs",
        "src/support/script.rs",
        "src/support/execution.rs",
        "src/support/tapscript.rs",
        "src/support/provenance.rs",
        "Cargo.lock",
        "research/integer-root-bounds/baseline.rs",
        "research/integer-root-bounds/measure.rs",
        "research/integer-root-bounds/verify_metrics.py",
        "examples/integer_root_metrics.rs",
        "tests/integer_root_contract.rs",
    ] {
        bindings.insert(p.into(), json!(sha(&std::fs::read(root.join(p)).unwrap())));
    }
    json!({"schema_version":1,"source_revision":rev,"source_sha256":bindings,"compiler_source":provenance::compiler().unwrap().source,"interpreter_source":provenance::interpreter().unwrap().source,"evidence":"locally-reproduced","execution":"unclassified","profile":{"context":"Tapscript","require_minimal":false,"verify_minimal_if":true,"verify_cltv":true,"verify_csv":true,"enforce_stack_limit":true,"experimental_op_cat":false,"transaction":"synthetic empty transaction, data-only witness budget, no signatures"},"boundary":"Fragment includes numeric guards, residual/root computation and residual cleanup, one ordinary input and zero hints; excludes witness pushes and terminal predicate. Leaf binds exact canonical root then TRUE. Witness includes count/length prefixes; excludes script/control block/annex/transaction. No caller state in scalar rows.","counter_note":"Static non-push counts separate. Executed counts unavailable; instruction position includes pushes/inactive branches. Zero signature weight charged is not complete transaction-budget validation. Local Policy probes are partial fragment checks, not relay evidence.","family_contracts":[family_contract("restoring",scriptnum_isqrt,false),family_contract("thresholds",baseline::thresholds,false),family_contract("restoring-canonical",restoring_canonical,true),family_contract("thresholds-canonical",thresholds_canonical,true)],"rows":rows,"compositions":[composition(16,2),composition(31,2),composition(31,3),composition(31,32),composition(31,53),composition(31,54),composition(31,996),composition(31,997)]})
}
