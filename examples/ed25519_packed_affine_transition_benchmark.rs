use bitcoin_lab::{
    curves::ed25519::{
        affine_add, asymmetric_r0_transition_hints, basepoint_constants,
        chained_direct_constants_witness_items, chained_direct_k_witness_items,
        packed_positive_transition_cost_breakdown,
        packed_positive_transition_direct_k_witness_items,
        packed_positive_transition_witness_items, shared_tau_mixed_transition_hints,
        shared_tau_transition_hints, verify_packed_positive_transition,
        verify_packed_positive_transition_chained,
        verify_packed_positive_transition_chained_direct_constants_sequential,
        verify_packed_positive_transition_chained_direct_constants_shared_tau,
        verify_packed_positive_transition_chained_direct_constants_shared_tau_mixed,
        verify_packed_positive_transition_chained_direct_k,
        verify_packed_positive_transition_chained_direct_k_sequential,
        verify_packed_positive_transition_chained_direct_k_sequential_mixed,
        verify_packed_positive_transition_chained_direct_k_shared_tau,
        verify_packed_positive_transition_chained_direct_k_shared_tau_mixed,
        verify_packed_positive_transition_direct_k,
        verify_packed_positive_transition_direct_k_shared_tau,
        verify_packed_positive_transition_expanded,
        verify_packed_positive_transition_expanded_direct_k_sequential,
        verify_packed_positive_transition_expanded_direct_k_sequential_mixed,
        verify_packed_positive_transition_expanded_direct_k_shared_tau,
        verify_packed_positive_transition_expanded_direct_k_shared_tau_mixed,
        EXPANDED_CURRENT_DIRECT_CONSTANTS_INPUT_ITEM_COUNT,
        EXPANDED_CURRENT_DIRECT_K_INPUT_ITEM_COUNT, FIRST_SEQUENTIAL_MIXED_MAX_PRESERVED_ITEMS,
        HINT_ITEM_COUNT, PACKED_POSITIVE_COMPLETE_INPUT_ITEM_COUNT,
        PACKED_POSITIVE_DIRECT_K_INPUT_ITEM_COUNT, PACKED_POSITIVE_MAX_PRESERVED_ITEMS,
        PACKED_POSITIVE_OUTPUT_ITEM_COUNT,
    },
    support::{execution::execute_raw_script_with_inputs_strict, script::ScriptCompilation},
};

fn main() {
    // Full first-entry model: 736 items for the packed trace, paired quotient
    // hints, and scalar, plus 40 current/selected-constant packed items not
    // already in that trace, plus the direct scalar splitter's one live
    // remainder. The wrapper owns 67 of those items.
    const FIRST_ENTRY_ITEMS: usize = 777;
    let preserved_items = FIRST_ENTRY_ITEMS - PACKED_POSITIVE_COMPLETE_INPUT_ITEM_COUNT;
    assert!(preserved_items <= PACKED_POSITIVE_MAX_PRESERVED_ITEMS as usize);

    let fixed = basepoint_constants();
    let (x_next, y_next, tau) = affine_add(&fixed.a, &fixed.b, &fixed);
    let hints = asymmetric_r0_transition_hints(&fixed.a, &fixed.b, &tau, &x_next, &y_next, &fixed);
    let local_witness = packed_positive_transition_witness_items(
        &fixed.a, &fixed.b, &tau, &x_next, &y_next, &fixed, &hints,
    );
    let mut witness = vec![Vec::new(); preserved_items];
    witness.extend(local_witness);

    let compiled = verify_packed_positive_transition(preserved_items as u32).compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(compiled.to_bytes(), witness);
    assert!(
        execution.error.is_none(),
        "packed positive transition failed: {execution}"
    );
    assert_eq!(
        execution.final_stack.len(),
        preserved_items + PACKED_POSITIVE_OUTPUT_ITEM_COUNT
    );
    let cost = packed_positive_transition_cost_breakdown();
    assert_eq!(cost.total(), compiled.len());
    let expanded_output_bytes = verify_packed_positive_transition_expanded(0)
        .compile_with_policy()
        .len();
    let chained_bytes = verify_packed_positive_transition_chained(0)
        .compile_with_policy()
        .len();

    const DIRECT_K_FIRST_ENTRY_ITEMS: usize = FIRST_ENTRY_ITEMS + 5;
    let direct_k_preserved = DIRECT_K_FIRST_ENTRY_ITEMS - PACKED_POSITIVE_DIRECT_K_INPUT_ITEM_COUNT;
    let direct_k_local = packed_positive_transition_direct_k_witness_items(
        &fixed.a, &fixed.b, &tau, &x_next, &y_next, &fixed, &hints,
    );
    let mut direct_k_witness = vec![Vec::new(); direct_k_preserved];
    direct_k_witness.extend(direct_k_local);
    let direct_k_script =
        verify_packed_positive_transition_direct_k(direct_k_preserved as u32).compile_with_policy();
    let direct_k_execution =
        execute_raw_script_with_inputs_strict(direct_k_script.to_bytes(), direct_k_witness);
    assert!(
        direct_k_execution.error.is_none(),
        "direct-K packed transition failed: {direct_k_execution}"
    );
    let chained_direct_k_bytes = verify_packed_positive_transition_chained_direct_k(0)
        .compile_with_policy()
        .len();

    let shared_hints =
        shared_tau_transition_hints(&fixed.a, &fixed.b, &tau, &x_next, &y_next, &fixed);
    let shared_local = packed_positive_transition_direct_k_witness_items(
        &fixed.a,
        &fixed.b,
        &tau,
        &x_next,
        &y_next,
        &fixed,
        &shared_hints,
    );
    let mut shared_witness = vec![Vec::new(); direct_k_preserved];
    shared_witness.extend(shared_local);
    let shared_script =
        verify_packed_positive_transition_direct_k_shared_tau(direct_k_preserved as u32)
            .compile_with_policy();
    let shared_execution =
        execute_raw_script_with_inputs_strict(shared_script.to_bytes(), shared_witness);
    assert!(
        shared_execution.error.is_none(),
        "shared-tau direct-K packed transition failed: {shared_execution}"
    );
    let chained_direct_k_shared_tau_bytes =
        verify_packed_positive_transition_chained_direct_k_shared_tau(0)
            .compile_with_policy()
            .len();

    let first_sequential =
        verify_packed_positive_transition_expanded_direct_k_sequential(0).compile_with_policy();
    let first_sequential_execution = execute_raw_script_with_inputs_strict(
        first_sequential.to_bytes(),
        packed_positive_transition_direct_k_witness_items(
            &fixed.a,
            &fixed.b,
            &tau,
            &x_next,
            &y_next,
            &fixed,
            &shared_hints,
        ),
    );
    assert!(
        first_sequential_execution.error.is_none(),
        "first sequential transition failed: {first_sequential_execution}"
    );
    let first_shared =
        verify_packed_positive_transition_expanded_direct_k_shared_tau(0).compile_with_policy();
    let first_shared_execution = execute_raw_script_with_inputs_strict(
        first_shared.to_bytes(),
        packed_positive_transition_direct_k_witness_items(
            &fixed.a,
            &fixed.b,
            &tau,
            &x_next,
            &y_next,
            &fixed,
            &shared_hints,
        ),
    );
    assert!(
        first_shared_execution.error.is_none(),
        "first shared transition failed: {first_shared_execution}"
    );

    let chained_sequential =
        verify_packed_positive_transition_chained_direct_k_sequential(0).compile_with_policy();
    let chained_sequential_execution = execute_raw_script_with_inputs_strict(
        chained_sequential.to_bytes(),
        chained_direct_k_witness_items(
            &fixed.a,
            &fixed.b,
            &tau,
            &x_next,
            &y_next,
            &fixed,
            &shared_hints,
        ),
    );
    assert!(
        chained_sequential_execution.error.is_none(),
        "chained sequential transition failed: {chained_sequential_execution}"
    );
    let chained_shared =
        verify_packed_positive_transition_chained_direct_k_shared_tau(0).compile_with_policy();
    let chained_shared_execution = execute_raw_script_with_inputs_strict(
        chained_shared.to_bytes(),
        chained_direct_k_witness_items(
            &fixed.a,
            &fixed.b,
            &tau,
            &x_next,
            &y_next,
            &fixed,
            &shared_hints,
        ),
    );
    assert!(
        chained_shared_execution.error.is_none(),
        "chained shared transition failed: {chained_shared_execution}"
    );

    let direct_constants_sequential =
        verify_packed_positive_transition_chained_direct_constants_sequential(0)
            .compile_with_policy();
    let direct_constants_sequential_execution = execute_raw_script_with_inputs_strict(
        direct_constants_sequential.to_bytes(),
        chained_direct_constants_witness_items(
            &fixed.a,
            &fixed.b,
            &tau,
            &x_next,
            &y_next,
            &fixed,
            &shared_hints,
        ),
    );
    assert!(
        direct_constants_sequential_execution.error.is_none(),
        "direct-constants sequential transition failed: {direct_constants_sequential_execution}"
    );
    let direct_constants_shared =
        verify_packed_positive_transition_chained_direct_constants_shared_tau(0)
            .compile_with_policy();
    let direct_constants_shared_execution = execute_raw_script_with_inputs_strict(
        direct_constants_shared.to_bytes(),
        chained_direct_constants_witness_items(
            &fixed.a,
            &fixed.b,
            &tau,
            &x_next,
            &y_next,
            &fixed,
            &shared_hints,
        ),
    );
    assert!(
        direct_constants_shared_execution.error.is_none(),
        "direct-constants shared transition failed: {direct_constants_shared_execution}"
    );

    let mixed_hints =
        shared_tau_mixed_transition_hints(&fixed.a, &fixed.b, &tau, &x_next, &y_next, &fixed);
    let first_sequential_mixed =
        verify_packed_positive_transition_expanded_direct_k_sequential_mixed(0)
            .compile_with_policy();
    let first_sequential_mixed_execution = execute_raw_script_with_inputs_strict(
        first_sequential_mixed.to_bytes(),
        packed_positive_transition_direct_k_witness_items(
            &fixed.a,
            &fixed.b,
            &tau,
            &x_next,
            &y_next,
            &fixed,
            &mixed_hints,
        ),
    );
    assert!(
        first_sequential_mixed_execution.error.is_none(),
        "first compact mixed transition failed: {first_sequential_mixed_execution}"
    );
    let mixed_t0_preserved = FIRST_SEQUENTIAL_MIXED_MAX_PRESERVED_ITEMS as usize;
    let mut mixed_t0_witness = vec![Vec::new(); mixed_t0_preserved];
    mixed_t0_witness.extend(packed_positive_transition_direct_k_witness_items(
        &fixed.a,
        &fixed.b,
        &tau,
        &x_next,
        &y_next,
        &fixed,
        &mixed_hints,
    ));
    let integrated_first_sequential_mixed =
        verify_packed_positive_transition_expanded_direct_k_sequential_mixed(
            FIRST_SEQUENTIAL_MIXED_MAX_PRESERVED_ITEMS,
        )
        .compile_with_policy();
    let integrated_first_sequential_mixed_execution = execute_raw_script_with_inputs_strict(
        integrated_first_sequential_mixed.to_bytes(),
        mixed_t0_witness,
    );
    assert!(
        integrated_first_sequential_mixed_execution.error.is_none(),
        "integrated-limit mixed transition failed: {integrated_first_sequential_mixed_execution}"
    );
    assert_eq!(
        integrated_first_sequential_mixed_execution
            .stats
            .max_nb_stack_items,
        1_000
    );
    let first_shared_mixed =
        verify_packed_positive_transition_expanded_direct_k_shared_tau_mixed(0)
            .compile_with_policy();
    let first_shared_mixed_execution = execute_raw_script_with_inputs_strict(
        first_shared_mixed.to_bytes(),
        packed_positive_transition_direct_k_witness_items(
            &fixed.a,
            &fixed.b,
            &tau,
            &x_next,
            &y_next,
            &fixed,
            &mixed_hints,
        ),
    );
    assert!(first_shared_mixed_execution.error.is_none());
    let chained_sequential_mixed =
        verify_packed_positive_transition_chained_direct_k_sequential_mixed(0)
            .compile_with_policy();
    let chained_sequential_mixed_execution = execute_raw_script_with_inputs_strict(
        chained_sequential_mixed.to_bytes(),
        chained_direct_k_witness_items(
            &fixed.a,
            &fixed.b,
            &tau,
            &x_next,
            &y_next,
            &fixed,
            &mixed_hints,
        ),
    );
    assert!(chained_sequential_mixed_execution.error.is_none());
    let packed_constants_mixed =
        verify_packed_positive_transition_chained_direct_k_shared_tau_mixed(0)
            .compile_with_policy();
    let packed_constants_mixed_execution = execute_raw_script_with_inputs_strict(
        packed_constants_mixed.to_bytes(),
        chained_direct_k_witness_items(
            &fixed.a,
            &fixed.b,
            &tau,
            &x_next,
            &y_next,
            &fixed,
            &mixed_hints,
        ),
    );
    assert!(
        packed_constants_mixed_execution.error.is_none(),
        "packed-constants mixed transition failed: {packed_constants_mixed_execution}"
    );
    let direct_constants_mixed =
        verify_packed_positive_transition_chained_direct_constants_shared_tau_mixed(0)
            .compile_with_policy();
    let direct_constants_mixed_execution = execute_raw_script_with_inputs_strict(
        direct_constants_mixed.to_bytes(),
        chained_direct_constants_witness_items(
            &fixed.a,
            &fixed.b,
            &tau,
            &x_next,
            &y_next,
            &fixed,
            &mixed_hints,
        ),
    );
    assert!(
        direct_constants_mixed_execution.error.is_none(),
        "direct-constants mixed transition failed: {direct_constants_mixed_execution}"
    );

    println!("execution_class=research-unlimited");
    println!("final_script_bytes={}", compiled.len());
    println!("expanded_output_script_bytes={expanded_output_bytes}");
    println!("chained_script_bytes={chained_bytes}");
    println!("direct_k_script_bytes={}", direct_k_script.len());
    println!("chained_direct_k_script_bytes={chained_direct_k_bytes}");
    println!("shared_tau_direct_k_script_bytes={}", shared_script.len());
    println!("shared_tau_chained_direct_k_script_bytes={chained_direct_k_shared_tau_bytes}");
    println!("first_sequential_expanded_bytes={}", first_sequential.len());
    println!(
        "first_sequential_local_peak={}",
        first_sequential_execution.stats.max_nb_stack_items
    );
    println!(
        "first_sequential_transient_growth={}",
        first_sequential_execution.stats.max_nb_stack_items
            - PACKED_POSITIVE_DIRECT_K_INPUT_ITEM_COUNT
    );
    println!("first_shared_expanded_bytes={}", first_shared.len());
    println!(
        "first_shared_local_peak={}",
        first_shared_execution.stats.max_nb_stack_items
    );
    println!(
        "first_shared_transient_growth={}",
        first_shared_execution.stats.max_nb_stack_items - PACKED_POSITIVE_DIRECT_K_INPUT_ITEM_COUNT
    );
    println!("chained_sequential_bytes={}", chained_sequential.len());
    println!(
        "chained_sequential_local_peak={}",
        chained_sequential_execution.stats.max_nb_stack_items
    );
    println!(
        "chained_sequential_transient_growth={}",
        chained_sequential_execution.stats.max_nb_stack_items
            - EXPANDED_CURRENT_DIRECT_K_INPUT_ITEM_COUNT
    );
    println!("chained_shared_bytes={}", chained_shared.len());
    println!(
        "chained_shared_local_peak={}",
        chained_shared_execution.stats.max_nb_stack_items
    );
    println!(
        "chained_shared_transient_growth={}",
        chained_shared_execution.stats.max_nb_stack_items
            - EXPANDED_CURRENT_DIRECT_K_INPUT_ITEM_COUNT
    );
    println!(
        "direct_constants_sequential_bytes={}",
        direct_constants_sequential.len()
    );
    println!(
        "direct_constants_sequential_local_peak={}",
        direct_constants_sequential_execution
            .stats
            .max_nb_stack_items
    );
    println!(
        "direct_constants_sequential_transient_growth={}",
        direct_constants_sequential_execution
            .stats
            .max_nb_stack_items
            - EXPANDED_CURRENT_DIRECT_CONSTANTS_INPUT_ITEM_COUNT
    );
    println!(
        "direct_constants_shared_bytes={}",
        direct_constants_shared.len()
    );
    println!(
        "direct_constants_shared_local_peak={}",
        direct_constants_shared_execution.stats.max_nb_stack_items
    );
    println!(
        "direct_constants_shared_transient_growth={}",
        direct_constants_shared_execution.stats.max_nb_stack_items
            - EXPANDED_CURRENT_DIRECT_CONSTANTS_INPUT_ITEM_COUNT
    );
    println!(
        "packed_constants_mixed_shared_bytes={}",
        packed_constants_mixed.len()
    );
    println!(
        "packed_constants_mixed_shared_local_peak={}",
        packed_constants_mixed_execution.stats.max_nb_stack_items
    );
    println!(
        "first_sequential_mixed_bytes={}",
        first_sequential_mixed.len()
    );
    println!(
        "first_sequential_mixed_local_peak={}",
        first_sequential_mixed_execution.stats.max_nb_stack_items
    );
    println!("first_sequential_mixed_max_preserved={FIRST_SEQUENTIAL_MIXED_MAX_PRESERVED_ITEMS}");
    println!(
        "first_sequential_mixed_limit_entry_items={}",
        mixed_t0_preserved + PACKED_POSITIVE_DIRECT_K_INPUT_ITEM_COUNT
    );
    println!(
        "first_sequential_mixed_limit_script_bytes={}",
        integrated_first_sequential_mixed.len()
    );
    println!(
        "first_sequential_mixed_limit_peak={}",
        integrated_first_sequential_mixed_execution
            .stats
            .max_nb_stack_items
    );
    println!("first_shared_mixed_bytes={}", first_shared_mixed.len());
    println!(
        "first_shared_mixed_local_peak={}",
        first_shared_mixed_execution.stats.max_nb_stack_items
    );
    println!(
        "chained_sequential_mixed_bytes={}",
        chained_sequential_mixed.len()
    );
    println!(
        "chained_sequential_mixed_local_peak={}",
        chained_sequential_mixed_execution.stats.max_nb_stack_items
    );
    println!(
        "direct_constants_mixed_shared_bytes={}",
        direct_constants_mixed.len()
    );
    println!(
        "direct_constants_mixed_shared_local_peak={}",
        direct_constants_mixed_execution.stats.max_nb_stack_items
    );
    println!("direct_k_entry_items={DIRECT_K_FIRST_ENTRY_ITEMS}");
    println!(
        "direct_k_combined_main_alt_stack_peak={}",
        direct_k_execution.stats.max_nb_stack_items
    );
    println!(
        "direct_k_local_combined_stack_peak={}",
        direct_k_execution.stats.max_nb_stack_items as usize - direct_k_preserved
    );
    println!(
        "shared_tau_direct_k_combined_main_alt_stack_peak={}",
        shared_execution.stats.max_nb_stack_items
    );
    println!(
        "shared_tau_direct_k_local_combined_stack_peak={}",
        shared_execution.stats.max_nb_stack_items as usize - direct_k_preserved
    );
    println!("decode_bytes={}", cost.decoding);
    println!("encode_bytes={}", cost.encoding);
    println!("six_product_bytes={}", cost.six_products);
    println!("relation_close_bytes={}", cost.relation_closes);
    println!("accumulator_setup_bytes={}", cost.accumulator_setup);
    println!("coordinate_derivation_bytes={}", cost.coordinate_derivation);
    println!("routing_cleanup_bytes={}", cost.routing_and_cleanup);
    println!("script_compilation=unoptimized_over_32KiB");
    println!("claimed_field_items=64");
    println!("hint_items={HINT_ITEM_COUNT}");
    println!("complete_local_input_items={PACKED_POSITIVE_COMPLETE_INPUT_ITEM_COUNT}");
    println!("preserved_items={preserved_items}");
    println!("complete_entry_items={FIRST_ENTRY_ITEMS}");
    println!("local_output_items={PACKED_POSITIVE_OUTPUT_ITEM_COUNT}");
    println!(
        "local_net_items={}",
        PACKED_POSITIVE_OUTPUT_ITEM_COUNT as isize
            - PACKED_POSITIVE_COMPLETE_INPUT_ITEM_COUNT as isize
    );
    println!(
        "combined_main_alt_stack_peak={}",
        execution.stats.max_nb_stack_items
    );
    println!(
        "local_combined_stack_peak={}",
        execution.stats.max_nb_stack_items as usize - preserved_items
    );
    println!("maximum_preserved_allowance={PACKED_POSITIVE_MAX_PRESERVED_ITEMS}");
}
