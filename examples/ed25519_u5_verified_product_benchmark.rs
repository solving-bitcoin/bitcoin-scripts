//! Lightweight one-shot metric for the quotient-only Ed25519 product verifier.
//!
//! Run with
//! `cargo run --locked --release --example ed25519_u5_verified_product_benchmark`.

use std::time::Instant;

use bitcoin::{consensus::encode::serialize, script::Instruction, Witness};
use bitcoin_lab::{
    fields::ed25519::u5_balanced_table as ed25519,
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
    },
};

fn scriptnum(value: i32) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value));
    bytes[..length].to_vec()
}

/// Recover a fragment's raw serialization through the repository policy.
/// Four copies exceed the 32-KiB cutoff, so no optimizer pass is applied.
fn raw_fragment_len(fragment: Script) -> usize {
    const COPIES: usize = 4;
    let repeated = script! {
        for _ in 0..COPIES { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % COPIES, 0);
    repeated.len() / COPIES
}

fn main() {
    // Canonical, asymmetric endpoint encodings exercise signed table entries
    // and a nonzero quotient without a sampling loop.
    let lhs_stored = [0; ed25519::FIELD_DIGIT_COUNT];
    let mut rhs_stored = [31; ed25519::FIELD_DIGIT_COUNT];
    rhs_stored[0] = 12;
    let lhs = ed25519::value_from_field_digits(&lhs_stored);
    let rhs = ed25519::value_from_field_digits(&rhs_stored);
    let hints = ed25519::hinted_mul(&lhs, &rhs);
    assert_ne!(hints.quotient, 0);

    let mut witness = Vec::with_capacity(ed25519::VERIFIED_PRODUCT_WITNESS_ITEM_COUNT);
    for value in [&lhs, &rhs, &hints.remainder] {
        witness.extend(
            ed25519::field_digits(value)
                .iter()
                .rev()
                .map(|digit| scriptnum(*digit)),
        );
    }
    let quotient_item = scriptnum(hints.quotient);
    witness.push(quotient_item.clone());

    let start = Instant::now();
    let candidate = ed25519::verify_product_hinted(0);
    let unoptimized_len = raw_fragment_len(candidate.clone());
    if std::env::args().any(|argument| argument == "--raw-only") {
        println!("unoptimized_locking_script_bytes={unoptimized_len}");
        return;
    }
    let compiled = candidate.compile_with_policy();
    let compile_millis = start.elapsed().as_millis();
    let raw = ed25519::verify_product_hinted_from_raw_witness(0).compile_with_policy();
    let cost = ed25519::verified_product_cost_breakdown();
    assert_eq!(cost.total(), compiled.len());
    let static_non_push_opcodes = compiled
        .instructions()
        .map(|instruction| instruction.expect("generated script must parse"))
        .filter(
            |instruction| matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() > 0x60),
        )
        .count();

    let execution = execute_raw_script_with_inputs_strict(compiled.to_bytes(), witness.clone());
    assert!(
        execution.error.is_none(),
        "benchmark execution failed: {execution}"
    );
    assert_eq!(
        execution.stats.max_nb_stack_items,
        ed25519::VERIFIED_PRODUCT_STACK_ITEMS as usize,
        "documented stack peak drifted"
    );
    assert_eq!(execution.final_stack.len(), ed25519::FIELD_DIGIT_COUNT);
    for (index, digit) in ed25519::field_digits(&hints.remainder)
        .iter()
        .rev()
        .enumerate()
    {
        assert_eq!(execution.final_stack.get(index), scriptnum(*digit));
    }

    let wrong_product = (&hints.remainder + 1u32) % ed25519::modulus();
    let wrong_digits = ed25519::field_digits(&wrong_product);
    let mut wrong_witness = witness.clone();
    let product_start = 2 * ed25519::FIELD_DIGIT_COUNT;
    for (slot, digit) in wrong_witness[product_start..product_start + ed25519::FIELD_DIGIT_COUNT]
        .iter_mut()
        .zip(wrong_digits.iter().rev())
    {
        *slot = scriptnum(*digit);
    }
    let rejected = execute_raw_script_with_inputs_strict(compiled.to_bytes(), wrong_witness);
    assert!(
        rejected.error.is_some(),
        "wrong certified product was accepted: {rejected}"
    );

    println!("locking_script_bytes={}", compiled.len());
    println!("unoptimized_locking_script_bytes={unoptimized_len}");
    println!("raw_input_locking_script_bytes={}", raw.len());
    println!("table_setup_bytes={}", cost.table_setup);
    println!("folded_relation_bytes={}", cost.folded_relation);
    println!("cleanup_bytes={}", cost.cleanup);
    println!("quotient={}", hints.quotient);
    println!(
        "incremental_hint_items={}",
        ed25519::VERIFIED_PRODUCT_HINT_ITEM_COUNT
    );
    println!(
        "incremental_hint_witness_bytes={}",
        serialize(&Witness::from_slice(&[quotient_item])).len()
    );
    println!("claimed_product_items={}", ed25519::FIELD_DIGIT_COUNT);
    println!(
        "complete_data_items={}",
        ed25519::VERIFIED_PRODUCT_WITNESS_ITEM_COUNT
    );
    println!(
        "complete_data_witness_bytes={}",
        serialize(&Witness::from_slice(&witness)).len()
    );
    println!("static_non_push_opcodes={static_non_push_opcodes}");
    println!("max_stack_items={}", execution.stats.max_nb_stack_items);
    println!("compile_millis={compile_millis}");
    println!("execution_samples=1");
    println!("execution_class=unclassified");
    println!("context=tapscript,strict_1000_item_stack,bitcoin-scriptexec");
}
