//! Reproducible same-boundary canonical prefix-vector comparison.
use bitcoin::{
    consensus::encode::serialize,
    hashes::{sha256, Hash},
    script::Instruction,
    Witness,
};
use bitcoin_lab::{
    arithmetic::u4::prefix_sum::u4_nibbles_to_prefix_sum as direct,
    support::{
        execution::execute_raw_script_with_inputs_strict,
        provenance,
        script::{script, Script, ScriptCompilation},
    },
};

#[path = "../research/u4-prefix-reconstruction/baseline.rs"]
mod baseline;
use baseline::table;

fn check(fragment: Script, values: &[u8]) {
    let mut acc = 0u32;
    let expected: Vec<_> = values
        .iter()
        .map(|&x| {
            acc = (acc + u32::from(x)) % 16;
            acc
        })
        .collect();
    let leaf = script! {
        {fragment}
        for &value in expected.iter().rev() {{value} OP_EQUALVERIFY}
        OP_TRUE
    }
    .compile_with_policy();
    let data = values
        .iter()
        .map(|&x| if x == 0 { vec![] } else { vec![x] })
        .collect();
    let result = execute_raw_script_with_inputs_strict(leaf.to_bytes(), data);
    assert!(result.success, "values={values:?}: {result}");
    assert_eq!(result.final_stack.len(), 1);
}
fn main() {
    for n in [1, 2, 3, 4, 16, 32, 128, 966] {
        let values: Vec<_> = (0..n).map(|i| ((7 * i + i / 3) % 16) as u8).collect();
        check(direct(n), &values);
        check(table(n), &values);
    }
    check(direct(997), &vec![7; 997]);
    let mut records = vec![];
    for n in [1, 2, 32, 128, 966, 997] {
        for (name, fragment) in std::iter::once(("conditional", direct(n)))
            .chain((n <= 966).then(|| ("table", table(n))))
        {
            let compiled = fragment.clone().compile_with_policy();
            let leaf=script!{{fragment} for index in (1..=n).rev(){{(7*index)%16}OP_EQUALVERIFY} OP_TRUE}.compile_with_policy();
            let data = vec![vec![7]; n as usize];
            let serialized = serialize(&Witness::from_slice(&data));
            let result = execute_raw_script_with_inputs_strict(leaf.to_bytes(), data);
            assert!(result.success);
            assert_eq!(result.final_stack.len(), 1);
            records.push(serde_json::json!({
                "name":name,"nibble_count":n,"fragment_bytes":compiled.len(),"leaf_bytes":leaf.len(),
                "data_items":n,"hint_items":0,"witness_bytes":serialized.len(),
                "combined_peak":result.stats.max_nb_stack_items,
                "static_non_push_opcodes":compiled.instructions().filter(|i|matches!(i,Ok(Instruction::Op(op))if op.to_u8()>0x60)).count(),
                "fragment_sha256":sha256::Hash::hash(compiled.as_bytes()).to_string(),
                "leaf_sha256":sha256::Hash::hash(leaf.as_bytes()).to_string(),
                "witness_sha256":sha256::Hash::hash(&serialized).to_string(),
                "executed_opcodes":null,"validation_weight":null
            }));
        }
    }
    let n = 32;
    let values: Vec<_> = (0..n).map(|i| ((7 * i + i / 3) % 16) as u8).collect();
    let fragment = baseline::roundtrip(n);
    let compiled = fragment.clone().compile_with_policy();
    let leaf = script! {{fragment}for &x in values.iter().rev(){{x}OP_EQUALVERIFY}OP_TRUE}
        .compile_with_policy();
    let data: Vec<_> = values
        .iter()
        .map(|&x| if x == 0 { vec![] } else { vec![x] })
        .collect();
    let serialized = serialize(&Witness::from_slice(&data));
    let result = execute_raw_script_with_inputs_strict(leaf.to_bytes(), data);
    assert!(result.success);
    let composition = serde_json::json!({
        "name":"canonical-delta-roundtrip","nibble_count":n,
        "input_generator":"x[i]=(7*i+floor(i/3))%16",
        "fragment_bytes":compiled.len(),"leaf_bytes":leaf.len(),"data_items":n,"hint_items":0,
        "witness_bytes":serialized.len(),"combined_peak":result.stats.max_nb_stack_items,
        "fragment_sha256":sha256::Hash::hash(compiled.as_bytes()).to_string(),
        "leaf_sha256":sha256::Hash::hash(leaf.as_bytes()).to_string(),
        "witness_sha256":sha256::Hash::hash(&serialized).to_string(),
        "static_non_push_opcodes":compiled.instructions().filter(|i|matches!(i,Ok(Instruction::Op(op))if op.to_u8()>0x60)).count(),
        "executed_opcodes":null,"validation_weight":null,
        "boundary":"fragment-with-memory: canonical checks on original vector, retained initial item, existing encoder, ordered routing and prefix scan; excludes input pushes and equality checks against all original values through clean OP_TRUE",
        "terminal_predicate":"compare reconstructed outputs with all original values in reverse using OP_EQUALVERIFY, then OP_TRUE"
    });
    println!("{}",serde_json::to_string_pretty(&serde_json::json!({
        "compiler_source":provenance::compiler().unwrap().source,
        "interpreter_source":provenance::interpreter().unwrap().source,
        "execution":"unclassified","evidence":"locally-reproduced",
        "options":"ExecCtx::Tapscript; Options::default with enforce_stack_limit=true; synthetic empty transaction; data-only budget; no signatures",
        "compilation":"compile_with_policy: all fragments and leaves below 32KiB raw cutoff, CompileOptions::ALL",
        "boundary":"fragment-with-memory: canonical input checks, staging, every ordered prefix output; table setup/cleanup/restoration included for baseline; input pushes and terminal comparisons excluded; complete data-only witness; combined peak measured using recorded complete leaf",
        "witness_generator":"n canonical sevens, all data items present at entry, zero hints",
        "terminal_predicate":"reverse i=n..1 compare output with (7*i)%16 using OP_EQUALVERIFY, then OP_TRUE",
        "correctness_vectors":"x[i]=(7*i+floor(i/3))%16 for n=1,2,3,4,16,32,128,966; n997 all7; host cumulative sum mod16",
        "records":records, "composition":composition
    })).unwrap());
}
