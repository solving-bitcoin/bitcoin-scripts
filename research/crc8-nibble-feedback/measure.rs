//! Exact generators shared by metrics and the family contract suite.
#[path = "baseline.rs"]
pub mod baseline;
use bitcoin::{
    consensus::encode::serialize,
    hashes::{sha256, Hash},
    script::Instruction,
    ScriptBuf, TapLeafHash, Witness,
};
use bitcoin_lab::{
    arithmetic::checksums::crc8::crc8_smbus_nibbles,
    arithmetic::u4::stack::verify_canonical_nibble,
    support::{
        execution::ExecuteInfo,
        provenance,
        script::*,
        tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
    },
};
use serde_json::{json, Value};

#[derive(Clone, Copy)]
pub struct Family {
    pub name: &'static str,
    pub generate: fn(u32) -> Script,
    pub canonical: bool,
}
pub fn serial_bytes(bytes: u32) -> Script {
    assert!(bytes <= 493);
    baseline::serial(2 * bytes, 0)
}
pub fn canonical(gen: fn(u32) -> Script, bytes: u32) -> Script {
    let g = gen(bytes);
    script! {
        for _ in 0..2*bytes { {verify_canonical_nibble()} OP_TOALTSTACK }
        for _ in 0..2*bytes { OP_FROMALTSTACK }
        {g}
    }
}
pub fn canonical_feedback(bytes: u32) -> Script {
    canonical(crc8_smbus_nibbles, bytes)
}
pub fn canonical_serial(bytes: u32) -> Script {
    canonical(serial_bytes, bytes)
}
pub const FAMILIES: [Family; 4] = [
    Family {
        name: "feedback-numeric",
        generate: crc8_smbus_nibbles,
        canonical: false,
    },
    Family {
        name: "serial-numeric",
        generate: serial_bytes,
        canonical: false,
    },
    Family {
        name: "feedback-canonical",
        generate: canonical_feedback,
        canonical: true,
    },
    Family {
        name: "serial-canonical",
        generate: canonical_serial,
        canonical: true,
    },
];
pub fn num(x: i64) -> Vec<u8> {
    let mut b = [0; 8];
    let n = bitcoin::script::write_scriptint(&mut b, x);
    b[..n].to_vec()
}
pub fn witness(d: &[u8]) -> Vec<Vec<u8>> {
    d.iter().rev().map(|&x| num(x.into())).collect()
}
pub fn encoded(w: &[Vec<u8>]) -> Vec<u8> {
    serialize(&Witness::from_slice(w))
}
pub fn sha(b: &[u8]) -> String {
    sha256::Hash::hash(b).to_string()
}
pub fn run(s: ScriptBuf, w: Vec<Vec<u8>>) -> ExecuteInfo {
    match execute_tapscript(s, w, TapscriptProfile::Consensus).outcome {
        TapscriptOutcome::Executed(r) => r,
        o => panic!("unexpected {o:?}"),
    }
}
pub fn leaf(g: Script, q: u8) -> Script {
    script! {{g}{q} OP_EQUALVERIFY OP_TRUE}
}
pub fn message(bytes: u32, group: u32) -> Vec<u8> {
    (0..2 * bytes)
        .map(|i| ((i * 7 + 3 * group + 3) % 16) as u8)
        .collect()
}
pub fn scalar_data(bytes: u32, pattern: &str) -> Vec<u8> {
    if pattern == "zero" {
        vec![0; 2 * bytes as usize]
    } else if bytes == 9 {
        b"123456789"
            .iter()
            .flat_map(|&b| [b >> 4, b & 15])
            .collect()
    } else {
        message(bytes, 0)
    }
}
pub fn repeated(family: Family, bytes: u32, repeats: u32) -> (Script, Vec<Vec<u8>>, Vec<u8>) {
    assert!((1..=55).contains(&repeats));
    let g = (family.generate)(bytes);
    let digits: Vec<u8> = (0..repeats)
        .flat_map(|group| message(bytes, group))
        .collect();
    let expected: Vec<u8> = (0..repeats)
        .map(|group| baseline::oracle(&message(bytes, group), 0))
        .collect();
    (
        script! {for _ in 0..repeats {{g.clone()} OP_TOALTSTACK} for _ in 0..repeats {OP_FROMALTSTACK}},
        witness(&digits),
        expected,
    )
}
pub fn bind_outputs(g: Script, expected_top_first: &[u8]) -> Script {
    script! {{g} for q in expected_top_first {{*q} OP_EQUALVERIFY} OP_TRUE}
}
fn policy(s: ScriptBuf, w: Vec<Vec<u8>>) -> Value {
    match execute_tapscript(s, w, TapscriptProfile::Policy).outcome {
        TapscriptOutcome::Executed(r) => {
            json!({"error":r.error.map(|e|format!("{e:?}")),"clean_success":r.success && r.final_stack.len()==1})
        }
        TapscriptOutcome::PolicyRejected(e) => json!({"precheck_rejection":format!("{e:?}")}),
        o => panic!("unexpected Policy {o:?}"),
    }
}
pub fn artifact(g: Script, w: &[Vec<u8>]) -> Value {
    let raw = g.len();
    let s = g.compile_with_policy();
    let r = run(s.clone(), w.to_vec());
    let out: Vec<Vec<u8>> = (0..r.final_stack.len())
        .map(|i| r.final_stack.get(i))
        .collect();
    json!({"raw_script_bytes":raw,"compilation_options":if raw<=32768 {"ALL"} else {"NONE"},"script_bytes":s.len(),"script_sha256":sha(s.as_bytes()),"tapleaf_hash":TapLeafHash::from_script(&s,bitcoin::taproot::LeafVersion::TapScript).to_string(),"static_non_push_opcodes":s.instructions().filter(|i|matches!(i,Ok(Instruction::Op(op))if op.to_u8()>0x60)).count(),"executed_opcodes":null,"complete_validation_budget":null,"charged_sig_budget":r.stats.start_validation_weight-r.stats.validation_weight,"stack_limit_enforced":r.stack_limit_enforced,"error":r.error.map(|e|format!("{e:?}")),"clean_success":r.success && r.final_stack.len()==1,"max_combined_stack_items":r.stats.max_nb_stack_items,"output_items":out.len(),"output_sha256":sha(&encoded(&out)),"local_policy":policy(s,w.to_vec())})
}
fn sources() -> Value {
    let mut obj = serde_json::Map::new();
    for p in [
        "src/arithmetic/checksums/crc8/mod.rs",
        "research/crc8-nibble-feedback/baseline.rs",
        "research/crc8-nibble-feedback/measure.rs",
        "research/crc8-nibble-feedback/verify_metrics.py",
        "research/crc8-nibble-feedback/verify_probe.py",
        "tests/crc8_contract.rs",
        "examples/crc8_metrics.rs",
        "src/arithmetic/u4/logic.rs",
        "src/arithmetic/u4/stack.rs",
        "src/arithmetic/scriptint/mod.rs",
        "src/support/script.rs",
        "src/support/execution.rs",
        "src/support/tapscript.rs",
        "src/support/provenance.rs",
        "Cargo.lock",
    ] {
        obj.insert(p.into(), json!(sha(&std::fs::read(p).unwrap())));
    }
    Value::Object(obj)
}
pub fn report(revision: &str) -> Value {
    let mut rows = Vec::new();
    let mut alias_contracts = Vec::new();
    let mut compositions = Vec::new();
    for f in FAMILIES {
        for bytes in [
            0, 1, 2, 3, 9, 16, 64, 114, 115, 124, 125, 128, 249, 250, 306, 307, 406,
        ] {
            for pattern in ["zero", "varied"] {
                let d = scalar_data(bytes, pattern);
                let q = baseline::oracle(&d, 0);
                let w = witness(&d);
                let g = (f.generate)(bytes);
                rows.push(json!({"family":f.name,"byte_count":bytes,"pattern":pattern,"input_nibbles_hex":d.iter().map(|x|format!("{x:x}")).collect::<String>(),"initial_crc":0,"expected_crc":q,"canonical_input_required":f.canonical,"data_items":d.len(),"hint_items":0,"hint_bytes":0,"all_data_at_entry":true,"witness_bytes":encoded(&w).len(),"witness_domain_upper_bound":(if f.canonical {2} else {5})*d.len()+if d.len()>=253 {3} else {1},"witness_bytes_max":if f.canonical {None} else {Some(5*d.len()+if d.len()>=253 {3} else {1})},"witness_sha256":sha(&encoded(&w)),"fragment":artifact(g.clone(),&w),"checked_leaf":artifact(leaf(g,q),&w)}));
            }
        }
        let d = vec![1; 18];
        let w = vec![vec![1, 0]; 18];
        let g = (f.generate)(9);
        alias_contracts.push(json!({"family":f.name,"canonical_input_required":f.canonical,"byte_count":9,"data_items":18,"hint_items":0,"encoding":"two-byte positive-one alias at every position","witness_bytes":encoded(&w).len(),"witness_sha256":sha(&encoded(&w)),"expected_crc":baseline::oracle(&d,0),"checked_leaf":artifact(leaf(g,baseline::oracle(&d,0)),&w)}));
        for repeats in [2, 8, 25, 26, 45, 46] {
            let (g, w, e) = repeated(f, 9, repeats);
            let component = (f.generate)(9);
            let raw_sum = repeats as usize * (component.len() + 2);
            let compiled_sum = repeats as usize * (component.compile_with_policy().len() + 2);
            let final_bytes = g.clone().compile_with_policy().len();
            compositions.push(json!({"family":f.name,"bytes_per_invocation":9,"repeats":repeats,"input_pattern":"nibble i of logical message g = (7*i+3*g+3) mod 16; messages and nibbles consumed top first","expected_top_first_crc":e,"data_items":w.len(),"incremental_hint_items":0,"total_hint_items":0,"hint_bytes":0,"all_data_at_entry":true,"caller_main_items":0,"caller_alt_items":0,"witness_bytes":encoded(&w).len(),"witness_domain_upper_bound":(if f.canonical {2} else {5})*w.len()+if w.len()>=253 {3} else {1},"witness_bytes_max":if f.canonical {None} else {Some(5*w.len()+if w.len()>=253 {3} else {1})},"witness_sha256":sha(&encoded(&w)),"fragment_component_raw_sum":raw_sum,"fragment_component_policy_sum":compiled_sum,"fragment_whole_policy_delta":final_bytes as i64-compiled_sum as i64,"fragment":artifact(g.clone(),&w),"checked_leaf":artifact(bind_outputs(g,&e),&w)}));
        }
    }
    json!({"source_revision":revision,"source_sha256":sources(),"compiler_source":provenance::compiler().unwrap().source,"interpreter_source":provenance::interpreter().unwrap().source,"profile":{"context":"tapscript","minimal_numbers":false,"minimal_if":true,"stack_limit":true,"op_cat":false,"cltv":true,"csv":true,"synthetic_empty_transaction":true,"data_only_budget":true,"signatures":0},"local_policy_subset":"add numeric/push minimality and an 80-byte entry-item cap; not complete relay policy","evidence":"locally-reproduced","execution":"unclassified","boundary":"Fragment includes range checks, tables or bit state, all calculation and cleanup; consumes high-first nibbles top first and returns canonical numeric CRC. Witness is complete serialized data-only vector, excluding leaf/control block/annex/transaction. Checked leaf binds every output then TRUE. Compositions include every future input and parked output.","polynomial":"0x107","initial_crc":0,"reflected_input":false,"reflected_output":false,"xorout":0,"rows":rows,"alias_contracts":alias_contracts,"compositions":compositions})
}
