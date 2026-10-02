//! Initial same-boundary comparison; no public primitive or deployment claim.
use bitcoin::{
    consensus::encode::serialize,
    hashes::{sha256, Hash},
    script::Instruction,
    Witness,
};
use bitcoin_lab::support::{
    execution::execute_raw_script_with_inputs_strict,
    provenance,
    script::{script, Script, ScriptCompilation},
};

#[path = "../research/u32-fermat-residue/baseline.rs"]
mod baseline;
use baseline::bitwise_horner as bits;
use bitcoin_lab::arithmetic::u32::residue::u32_mod65537 as lanes;

fn scriptnum(x: u32) -> Vec<u8> {
    let mut data = [0; 8];
    let len = bitcoin::script::write_scriptint(&mut data, i64::from(x));
    data[..len].to_vec()
}
fn check(fragment: Script, x: u32) {
    let leaf = script! { { fragment } { x % 65537 } OP_EQUAL }.compile_with_policy();
    let witness = x.to_be_bytes().map(|v| scriptnum(u32::from(v))).to_vec();
    let result = execute_raw_script_with_inputs_strict(leaf.to_bytes(), witness);
    assert!(result.success, "x={x:08x}: {result}");
    assert_eq!(result.final_stack.len(), 1);
}
fn main() {
    for x in [
        0,
        1,
        65535,
        65536,
        65537,
        0x7fffffff,
        0x80000000,
        u32::MAX,
        0x12345678,
        0xfedcba98,
    ] {
        check(lanes(), x);
        check(bits(), x);
    }
    for i in 0u32..128 {
        let x = i.wrapping_mul(0x9e3779b9).rotate_left(i % 32);
        check(lanes(), x);
        check(bits(), x);
    }
    let compiler = provenance::compiler().unwrap();
    let interpreter = provenance::interpreter().unwrap();
    let records: Vec<_> = [("paired-lanes", lanes()), ("bitwise-horner", bits())].into_iter().map(|(name,fragment)| {
        let x: u32 = 0x89abcdef;
        let compiled = fragment.clone().compile_with_policy();
        let leaf = script! { { fragment } { x % 65537 } OP_EQUAL }.compile_with_policy();
        let witness = x.to_be_bytes().map(|v| scriptnum(u32::from(v))).to_vec();
        let serialized = serialize(&Witness::from_slice(&witness));
        let execution = execute_raw_script_with_inputs_strict(leaf.to_bytes(), witness.clone());
        assert!(execution.success);
        assert_eq!(execution.final_stack.len(), 1);
        serde_json::json!({
            "name":name, "word_hex":"89abcdef", "input_bytes_msb_first":x.to_be_bytes(),
            "expected_residue":x%65537, "fragment_bytes":compiled.len(), "leaf_bytes":leaf.len(),
            "witness_bytes":serialized.len(), "data_items":4, "hint_items":0,
            "combined_peak":execution.stats.max_nb_stack_items,
            "static_non_push_opcodes":compiled.instructions().filter(|i|matches!(i,Ok(Instruction::Op(op)) if op.to_u8()>0x60)).count(),
            "fragment_sha256":sha256::Hash::hash(compiled.as_bytes()).to_string(),
            "leaf_sha256":sha256::Hash::hash(leaf.as_bytes()).to_string(),
            "witness_sha256":sha256::Hash::hash(&serialized).to_string(),
            "executed_opcodes":null, "validation_weight":null
        })
    }).collect();
    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
        "compiler_source":compiler.source, "interpreter_source":interpreter.source,
        "execution":"unclassified", "evidence":"locally-reproduced",
        "options":"ExecCtx::Tapscript; Options::default with enforce_stack_limit=true; synthetic empty transaction; data-only budget; no signatures",
        "boundary":"fragment-only: canonical checks, packing and reduction; input pushes and terminal expected-residue OP_EQUAL excluded; witness is complete data-only vector; combined peak measured using recorded complete leaf and runtime witness",
        "compilation":"compile_with_policy: all reported scripts below 32KiB cutoff and receive CompileOptions::ALL",
        "correctness_vectors":"ten boundary words plus i*0x9e3779b9 wrapping, rotated left by i mod32, i=0..127; both scripts checked against unsigned host remainder",
        "records":records
    })).unwrap());
}
