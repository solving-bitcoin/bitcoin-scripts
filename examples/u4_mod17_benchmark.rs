//! Exact-artifact, strict-local comparison; dynamic opcode counts unavailable.
use bitcoin::{
    consensus::encode::serialize,
    hashes::{sha256, Hash},
    script::Instruction,
    Witness,
};
use bitcoin_lab::{
    arithmetic::u4::mod17::u4_nibbles_to_mod17,
    support::{
        execution::execute_raw_script_with_inputs_strict,
        provenance,
        script::{script, Script, ScriptCompilation},
    },
};
use serde_json::json;
#[path = "../research/u4-mod17/baseline.rs"]
mod baseline;

fn measure(name: &str, n: u32, fragment: Script) -> serde_json::Value {
    let values: Vec<u8> = (0..n).map(|i| ((i * 7 + i / 3) % 16) as u8).collect();
    let expected = values
        .iter()
        .fold(0u32, |r, &x| (16 * r + u32::from(x)) % 17);
    let witness: Vec<_> = values
        .iter()
        .map(|&x| if x == 0 { vec![] } else { vec![x] })
        .collect();
    let compiled = fragment.clone().compile_with_policy();
    let leaf = script! { { fragment } { expected } OP_EQUAL }.compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(leaf.to_bytes(), witness.clone());
    assert!(execution.success, "{name} n={n}: {execution}");
    assert_eq!(execution.final_stack.len(), 1);
    let static_ops = compiled
        .instructions()
        .filter(|i| matches!(i, Ok(Instruction::Op(op)) if op.to_u8() > 0x60))
        .count();
    json!({"name":name,"nibble_count":n,"input_generator":"x[i]=(7*i+floor(i/3)) mod16", "witness_sha256":sha256::Hash::hash(&serialize(&Witness::from_slice(&witness))).to_string(),"expected":expected,
        "fragment_bytes":compiled.len(),"fragment_sha256":sha256::Hash::hash(compiled.as_bytes()).to_string(),
        "leaf_bytes":leaf.len(),"leaf_sha256":sha256::Hash::hash(leaf.as_bytes()).to_string(),
        "witness_bytes":serialize(&Witness::from_slice(&witness)).len(),"data_items":n,"hint_items":0,
        "combined_peak":execution.stats.max_nb_stack_items,"static_non_push_opcodes":static_ops,
        "executed_opcodes":null,"validation_weight":null})
}
fn main() {
    let compiler = provenance::compiler().unwrap();
    let interpreter = provenance::interpreter().unwrap();
    let records: Vec<_> = [1, 2, 32, 128, 997]
        .into_iter()
        .flat_map(|n| {
            [
                measure("reverse-fold", n, u4_nibbles_to_mod17(n)),
                measure("forward-horner", n, baseline::forward_horner(n)),
            ]
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&json!({
        "compiler_source":compiler.source,"interpreter_source":interpreter.source,
        "execution":"unclassified","evidence":"locally-reproduced",
        "options":"ExecCtx::Tapscript; Options::default with enforce_stack_limit=true; empty synthetic transaction; data-only budget; no signatures",
        "boundary":"fragment-only: all canonical checks and reduction; no inputs or terminal predicate; witness is full data-only vector; peak measured with runtime witness and expected-residue OP_EQUAL",
        "compilation":"compile_with_policy: ALL <=32KiB, NONE above; every measured fragment below cutoff",
        "records":records
    })).unwrap());
}
