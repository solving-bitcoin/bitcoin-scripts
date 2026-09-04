//! One-shot benchmark for centered radix-32 Ed25519 field multiplication.
//!
//! Run with `cargo run --locked --release --example ed25519_u5_balanced_field_benchmark`.

use std::time::Instant;

use bitcoin::{consensus::encode::serialize, script::Instruction, Witness};
use bitcoin_lab::{
    fields::ed25519::u5_balanced_table as ed25519,
    support::{execution::execute_raw_script_with_inputs_strict, script::ScriptCompilation},
};

fn scriptnum(value: i32) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value));
    bytes[..length].to_vec()
}

fn assert_result(
    execution: &bitcoin_lab::support::execution::ExecuteInfo,
    expected_result: &[Vec<u8>],
) {
    assert!(
        execution.error.is_none(),
        "benchmark execution failed: {execution}"
    );
    assert_eq!(execution.final_stack.len(), expected_result.len());
    for (index, expected_digit) in expected_result.iter().enumerate() {
        assert_eq!(execution.final_stack.get(index), expected_digit.clone());
    }
}

fn main() {
    // Exercise opposite ends of the centered interval. These are canonical,
    // asymmetric, table-stressing encodings with a nonzero reduction quotient.
    let lhs_stored = [0; ed25519::FIELD_DIGIT_COUNT];
    let mut rhs_stored = [31; ed25519::FIELD_DIGIT_COUNT];
    rhs_stored[0] = 12;
    let lhs = ed25519::value_from_field_digits(&lhs_stored);
    let rhs = ed25519::value_from_field_digits(&rhs_stored);
    assert_eq!(ed25519::field_digits(&lhs), lhs_stored);
    assert_eq!(ed25519::field_digits(&rhs), rhs_stored);

    let hints = ed25519::hinted_mul(&lhs, &rhs);
    assert_ne!(
        hints.quotient, 0,
        "benchmark must exercise the quotient path"
    );
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
    let expected_result = ed25519::field_digits(&hints.remainder)
        .iter()
        .rev()
        .map(|digit| scriptnum(*digit))
        .collect::<Vec<_>>();

    let start = Instant::now();
    let compiled = ed25519::mul_mod_hinted(0).compile_with_policy();
    let compile_millis = start.elapsed().as_millis();
    let raw = ed25519::mul_mod_hinted_from_raw_witness(0).compile_with_policy();
    let cost = ed25519::one_shot_cost_breakdown();
    assert_eq!(cost.total(), compiled.len());
    let static_non_push_opcodes = compiled
        .instructions()
        .map(|instruction| instruction.expect("generated script must parse"))
        .filter(
            |instruction| matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() > 0x60),
        )
        .count();
    let hint_witness = hints.witness_items();
    eprintln!("candidate_locking_script_bytes={}", compiled.len());

    // The raw certification wrapper is part of the reported artifact and is
    // executed once even though timings cover the compact certified-input gate.
    let raw_execution = execute_raw_script_with_inputs_strict(raw.to_bytes(), witness.clone());
    assert_result(&raw_execution, &expected_result);

    const EXECUTION_SAMPLES: usize = 100;
    let mut execution_nanos = Vec::with_capacity(EXECUTION_SAMPLES);
    let mut max_stack_items = raw_execution.stats.max_nb_stack_items;
    for _ in 0..EXECUTION_SAMPLES {
        let start = Instant::now();
        let execution =
            execute_raw_script_with_inputs_strict(compiled.clone().to_bytes(), witness.clone());
        execution_nanos.push(start.elapsed().as_nanos());
        assert_result(&execution, &expected_result);
        max_stack_items = max_stack_items.max(execution.stats.max_nb_stack_items);
    }
    execution_nanos.sort_unstable();

    println!("locking_script_bytes={}", compiled.len());
    println!("raw_operand_locking_script_bytes={}", raw.len());
    println!("table_setup_bytes={}", cost.table_setup);
    println!("folded_relation_bytes={}", cost.folded_relation);
    println!("cleanup_bytes={}", cost.cleanup);
    println!("quotient={}", hints.quotient);
    println!("incremental_hint_items={}", hint_witness.len());
    println!(
        "incremental_hint_witness_bytes={}",
        serialize(&Witness::from_slice(&hint_witness)).len()
    );
    println!("complete_data_items={}", ed25519::MUL_WITNESS_ITEM_COUNT);
    println!(
        "complete_data_witness_bytes={}",
        serialize(&Witness::from_slice(&witness)).len()
    );
    println!("static_non_push_opcodes={static_non_push_opcodes}");
    println!("max_stack_items={max_stack_items}");
    println!("compile_millis={compile_millis}");
    println!("execution_samples={EXECUTION_SAMPLES}");
    println!("execution_min_nanos={}", execution_nanos[0]);
    println!(
        "execution_median_nanos={}",
        execution_nanos[EXECUTION_SAMPLES / 2]
    );
    println!(
        "execution_p95_nanos={}",
        execution_nanos[EXECUTION_SAMPLES * 95 / 100]
    );
    println!(
        "execution_max_nanos={}",
        execution_nanos[EXECUTION_SAMPLES - 1]
    );
    println!("execution_class=unclassified");
    println!("context=tapscript,strict_1000_item_stack,bitcoin-scriptexec");
}
