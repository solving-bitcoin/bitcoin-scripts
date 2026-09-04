//! One-shot benchmark for the Ed25519 factor-8 field multiplication gate.
//!
//! Run with `cargo run --release --example ed25519_field_benchmark`.

use std::time::Instant;

use bitcoin::{consensus::encode::serialize, script::Instruction, Witness};
use bitcoin_lab::{
    fields::ed25519::bigint9 as ed25519,
    support::{execution::execute_raw_script_with_inputs_strict, script::ScriptCompilation},
};
use num_bigint::BigUint;
use num_traits::One;

fn scriptnum(value: i32) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value));
    bytes[..length].to_vec()
}

fn main() {
    let modulus = ed25519::modulus();
    let logical = &modulus - BigUint::one();
    let lhs = ed25519::encode(&logical);
    let rhs = lhs.clone();
    let hints = ed25519::hinted_mul(&lhs, &rhs);

    let mut witness = Vec::with_capacity(ed25519::MUL_WITNESS_ITEM_COUNT);
    for value in [&lhs, &rhs] {
        witness.extend(
            ed25519::field_digits(value)
                .iter()
                .rev()
                .map(|digit| scriptnum(*digit)),
        );
    }
    witness.extend(hints.witness_items());

    let start = Instant::now();
    let compiled = ed25519::mul_mod_hinted(0).compile_with_policy();
    let compile_millis = start.elapsed().as_millis();
    let static_non_push_opcodes = compiled
        .instructions()
        .map(|instruction| instruction.expect("generated script must parse"))
        .filter(
            |instruction| matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() > 0x60),
        )
        .count();
    let hint_witness = hints.witness_items();
    let complete_data_witness_bytes = serialize(&Witness::from_slice(&witness)).len();

    let cost = ed25519::one_shot_cost_breakdown();
    assert_eq!(cost.total(), compiled.len());
    let standalone = ed25519::mul_mod_hinted_from_raw_witness(0).compile_with_policy();

    const EXECUTION_SAMPLES: usize = 100;
    let mut execution_nanos = Vec::with_capacity(EXECUTION_SAMPLES);
    let mut max_stack_items = 0usize;
    for _ in 0..EXECUTION_SAMPLES {
        let start = Instant::now();
        let execution =
            execute_raw_script_with_inputs_strict(compiled.clone().to_bytes(), witness.clone());
        execution_nanos.push(start.elapsed().as_nanos());
        assert!(
            execution.error.is_none(),
            "benchmark execution failed: {execution}"
        );
        max_stack_items = max_stack_items.max(execution.stats.max_nb_stack_items);
    }
    execution_nanos.sort_unstable();
    let execution_min_nanos = execution_nanos[0];
    let execution_median_nanos = execution_nanos[EXECUTION_SAMPLES / 2];
    let execution_p95_nanos = execution_nanos[EXECUTION_SAMPLES * 95 / 100];
    let execution_max_nanos = execution_nanos[EXECUTION_SAMPLES - 1];

    println!("locking_script_bytes={}", compiled.len());
    println!("raw_operand_locking_script_bytes={}", standalone.len());
    println!("table_setup_bytes={}", cost.table_setup);
    println!("table_drop_bytes={}", cost.table_drop);
    println!("product_generation_bytes={}", cost.product_generation);
    println!("folded_relation_bytes={}", cost.folded_relation);
    println!("cleanup_bytes={}", cost.cleanup);
    println!("non_table_computation_bytes={}", cost.computation());
    println!("incremental_hint_items={}", hint_witness.len());
    println!(
        "incremental_hint_witness_bytes={}",
        serialize(&Witness::from_slice(&hint_witness)).len()
    );
    println!("complete_data_items={}", ed25519::MUL_WITNESS_ITEM_COUNT);
    println!("complete_data_witness_bytes={complete_data_witness_bytes}");
    println!("static_non_push_opcodes={static_non_push_opcodes}");
    println!("max_stack_items={max_stack_items}");
    println!("compile_millis={compile_millis}");
    println!("execution_samples={EXECUTION_SAMPLES}");
    println!("execution_min_nanos={execution_min_nanos}");
    println!("execution_median_nanos={execution_median_nanos}");
    println!("execution_p95_nanos={execution_p95_nanos}");
    println!("execution_max_nanos={execution_max_nanos}");
    println!(
        "build_profile={}",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
    println!("execution_class=unclassified");
    println!("context=tapscript,strict_1000_item_stack,bitcoin-scriptexec");
}
