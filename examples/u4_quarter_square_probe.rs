//! Reproducible exact and modulo product lifecycle comparison.
use bitcoin::{
    consensus::encode::serialize,
    hashes::{sha256, Hash},
    script::Instruction,
    Witness,
};
use bitcoin_lab::support::{
    execution::execute_raw_script_with_inputs_strict, provenance, script::*,
};
#[path = "../research/u4-quarter-square/baseline.rs"]
mod baseline;
fn batch(n: u32, quarter: bool, exact: bool) -> Script {
    if quarter && exact {
        bitcoin_lab::arithmetic::u4::quarter_square::u4_pairwise_mul_exact(n)
    } else {
        baseline::batch(n, quarter, exact)
    }
}
fn num(x: u32) -> Vec<u8> {
    let mut b = [0u8; 8];
    let n = bitcoin::script::write_scriptint(&mut b, i64::from(x));
    b[..n].to_vec()
}
fn main() {
    for exact in [false, true] {
        for quarter in [false, true] {
            let comparison = script! {{batch(1,quarter,exact)}OP_EQUAL}.compile_with_policy();
            for a in 0u32..16 {
                for b in 0u32..16 {
                    let expected = if exact { a * b } else { a * b % 16 };
                    let r = execute_raw_script_with_inputs_strict(
                        comparison.to_bytes(),
                        vec![num(expected), num(a), num(b)],
                    );
                    assert!(
                        r.success,
                        "a={a} b={b} quarter={quarter} exact={exact}: {r}"
                    );
                }
            }
        }
    }
    let mut records = vec![];
    for n in [1, 2, 8, 32, 128, 370, 483] {
        for exact in [false, true] {
            for quarter in [false, true] {
                if !quarter && n > 370 {
                    continue;
                }
                let name = match (quarter, exact) {
                    (true, true) => "quarter-exact",
                    (false, true) => "full-exact",
                    (true, false) => "quarter-mod",
                    (false, false) => "full-mod-canonical",
                };
                let fragment = batch(n, quarter, exact);
                let compiled = fragment.clone().compile_with_policy();
                let expected = if exact { 49 } else { 1 };
                let leaf = script! {{fragment}for _ in 0..n{{expected}OP_EQUALVERIFY}OP_TRUE}
                    .compile_with_policy();
                let data = vec![num(7); (2 * n) as usize];
                let serialized = serialize(&Witness::from_slice(&data));
                let r = execute_raw_script_with_inputs_strict(leaf.to_bytes(), data);
                assert!(r.success);
                assert_eq!(r.final_stack.len(), 1);
                records.push(serde_json::json!({
            "name":name,"pair_count":n,"exact":exact,"table_items":if quarter{31}else{256},
            "fragment_bytes":compiled.len(),"leaf_bytes":leaf.len(),"data_items":2*n,"hint_items":0,
            "witness_bytes":serialized.len(),"combined_peak":r.stats.max_nb_stack_items,
            "static_non_push_opcodes":compiled.instructions().filter(|i|matches!(i,Ok(Instruction::Op(op))if op.to_u8()>0x60)).count(),
            "fragment_sha256":sha256::Hash::hash(compiled.as_bytes()).to_string(),
            "leaf_sha256":sha256::Hash::hash(leaf.as_bytes()).to_string(),
            "witness_sha256":sha256::Hash::hash(&serialized).to_string(),
            "executed_opcodes":null,"validation_weight":null
        }));
            }
        }
    }
    println!("{}",serde_json::to_string_pretty(&serde_json::json!({
        "compiler_source":provenance::compiler().unwrap().source,
        "interpreter_source":provenance::interpreter().unwrap().source,
        "evidence":"locally-reproduced","execution":"unclassified",
        "options":"ExecCtx::Tapscript; Options::default with enforce_stack_limit=true; synthetic empty transaction; data-only budget; no signatures",
        "compilation":"compile_with_policy: every measured fragment and leaf below 32KiB raw cutoff, CompileOptions::ALL",
        "boundary":"fragment-with-memory: table setup, canonical/range checks, pair routing from below memory, all ordered products, table cleanup and restoration; excludes input pushes and output comparisons; complete data-only witness; combined peak measured on recorded complete leaf",
        "witness_generator":"2*n canonical sevens, all operands present at entry, zero hints",
        "terminal_predicate":"compare n outputs in reverse using OP_EQUALVERIFY against49 for exact,1 for modulo, then OP_TRUE",
        "correctness_vectors":"all256 operand pairs; host expected-product oracle item below two operands for comparison leaf only, excluded from metrics",
        "records":records
    })).unwrap());
}
