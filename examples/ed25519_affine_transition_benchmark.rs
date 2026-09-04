//! Lightweight metric for one quotient-only fixed-Q Ed25519 affine transition.
//!
//! Run with
//! `cargo run --locked --release --example ed25519_affine_transition_benchmark`.

use bitcoin::{consensus::encode::serialize, script::Instruction, Witness};
use bitcoin_lab::{
    curves::ed25519::{
        affine_add, basepoint_constants, conservative_packed_schedule_kernel_cost_breakdown,
        conservative_runtime_transition_cost_breakdown, packed_schedule_kernel_cost_breakdown,
        runtime_transition_cost_breakdown, runtime_transition_witness_items,
        streamed_kernel_cost_breakdown, transition_hints, transition_witness_items,
        verify_affine_transition, verify_affine_transition_runtime_constants,
        FIXED_CLAIMED_FIELD_ITEM_COUNT, FIXED_COMPLETE_INPUT_ITEM_COUNT, HINT_ITEM_COUNT,
        RUNTIME_CLAIMED_FIELD_ITEM_COUNT, RUNTIME_COMPLETE_INPUT_ITEM_COUNT,
    },
    support::{execution::execute_raw_script_with_inputs_strict, script::ScriptCompilation},
};

fn main() {
    let fixed = basepoint_constants();
    let (x_next, y_next, tau) = affine_add(&fixed.a, &fixed.b, &fixed);
    let hints = transition_hints(&fixed.a, &fixed.b, &tau, &x_next, &y_next, &fixed);
    let fixed_witness =
        transition_witness_items(&fixed.a, &fixed.b, &tau, &x_next, &y_next, &hints);
    let fixed_script = verify_affine_transition(&fixed).compile_with_policy();
    let fixed_execution =
        execute_raw_script_with_inputs_strict(fixed_script.to_bytes(), fixed_witness.clone());
    assert!(
        fixed_execution.error.is_none(),
        "fixed-constant benchmark execution failed: {fixed_execution}"
    );

    let witness = runtime_transition_witness_items(
        &fixed.a, &fixed.b, &tau, &x_next, &y_next, &fixed, &hints,
    );
    let compiled = verify_affine_transition_runtime_constants().compile_with_policy();
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
        "runtime-constant benchmark execution failed: {execution}"
    );
    let cost = runtime_transition_cost_breakdown();
    assert_eq!(cost.total(), compiled.len());
    let streamed = streamed_kernel_cost_breakdown();
    let packed_schedule = packed_schedule_kernel_cost_breakdown();
    let conservative_cost = conservative_runtime_transition_cost_breakdown();
    let conservative_packed = conservative_packed_schedule_kernel_cost_breakdown();

    println!("runtime_locking_script_bytes={}", compiled.len());
    println!(
        "conservative_runtime_locking_script_bytes={}",
        conservative_cost.total()
    );
    println!("fixed_locking_script_bytes={}", fixed_script.len());
    println!("locking_script_optimized=false");
    println!("incremental_hint_items={HINT_ITEM_COUNT}");
    println!("quotients={:?}", hints.quotients);
    println!(
        "incremental_hint_witness_bytes={}",
        serialize(&Witness::from_slice(&hints.witness_items())).len()
    );
    println!("runtime_claimed_field_items={RUNTIME_CLAIMED_FIELD_ITEM_COUNT}");
    println!("runtime_complete_data_items={RUNTIME_COMPLETE_INPUT_ITEM_COUNT}");
    println!(
        "complete_data_witness_bytes={}",
        serialize(&Witness::from_slice(&witness)).len()
    );
    println!("static_non_push_opcodes={static_non_push_opcodes}");
    println!("runtime_r0_bytes={}", cost.r0);
    println!("runtime_r_plus_bytes={}", cost.r_plus);
    println!("runtime_r_minus_bytes={}", cost.r_minus);
    println!("runtime_cleanup_bytes={}", cost.cleanup);
    println!(
        "streamed_accumulator_initialization_bytes={}",
        streamed.accumulator_initialization
    );
    println!("streamed_r0_product_bytes={}", streamed.r0_products);
    println!("streamed_r_plus_product_bytes={}", streamed.r_plus_products);
    println!(
        "streamed_r_minus_product_bytes={}",
        streamed.r_minus_products
    );
    println!("streamed_relation_close_bytes={}", streamed.relation_closes);
    println!("streamed_kernel_total_bytes={}", streamed.total());
    println!(
        "packed_schedule_xy_product_bytes={}",
        packed_schedule.xy_product
    );
    println!(
        "packed_schedule_k_tau_product_bytes={}",
        packed_schedule.k_tau_product
    );
    println!(
        "packed_schedule_a_cp_product_bytes={}",
        packed_schedule.a_cp_product
    );
    println!(
        "packed_schedule_b_next_tau_product_bytes={}",
        packed_schedule.b_next_tau_product
    );
    println!(
        "packed_schedule_b_cm_product_bytes={}",
        packed_schedule.b_cm_product
    );
    println!(
        "packed_schedule_a_next_tau_product_bytes={}",
        packed_schedule.a_next_tau_product
    );
    println!(
        "packed_schedule_accumulator_setup_bytes={}",
        packed_schedule.accumulator_setup
    );
    println!(
        "packed_schedule_linear_add_bytes={}",
        packed_schedule.linear_add
    );
    println!(
        "packed_schedule_relation_close_bytes={}",
        packed_schedule.relation_closes
    );
    println!(
        "packed_schedule_kernel_total_bytes={}",
        packed_schedule.total()
    );
    println!(
        "conservative_packed_schedule_kernel_total_bytes={}",
        conservative_packed.total()
    );
    println!(
        "runtime_max_stack_items={}",
        execution.stats.max_nb_stack_items
    );
    println!("fixed_claimed_field_items={FIXED_CLAIMED_FIELD_ITEM_COUNT}");
    println!("fixed_complete_data_items={FIXED_COMPLETE_INPUT_ITEM_COUNT}");
    println!(
        "fixed_complete_data_witness_bytes={}",
        serialize(&Witness::from_slice(&fixed_witness)).len()
    );
    println!(
        "fixed_max_stack_items={}",
        fixed_execution.stats.max_nb_stack_items
    );
    println!("execution_samples=1");
    println!("execution_class=unclassified");
    println!("context=tapscript,strict_1000_item_stack,bitcoin-scriptexec");
}
