//! Focused strict probe for the continuity-first 92-item slope-chain state.
//!
//! This executes only one chained transition (plus one malformed rerun). It
//! does not build a table schedule, hash, scalar multiplication, or whole leaf.

use bitcoin::script::Instruction;
use bitcoin_lab::{
    curves::ed25519::montgomery_slope::{
        chained_transition_derived_hybrid_u5_witness_items,
        chained_transition_derived_hybrid_witness_items, first_transition_derived_witness_items,
        hybrid_output_state_items, verify_chained_transition_derived,
        verify_chained_transition_derived_hybrid_state,
        verify_chained_transition_derived_hybrid_state_certified_u_next_u5,
        verify_chained_transition_derived_hybrid_state_certified_u_next_u5_terminal,
        verify_first_transition_derived, verify_first_transition_derived_hybrid_state,
        HYBRID_CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT,
        HYBRID_CHAINED_U5_DERIVED_COMPLETE_INPUT_ITEM_COUNT, HYBRID_STATE_ITEM_COUNT,
    },
    fields::ed25519::{
        u5_balanced_table::{field_digits, modulus},
        u5_packed,
    },
    support::{
        execution::{execute_raw_script_with_inputs_strict, ExecuteInfo},
        script::ScriptCompilation,
    },
};
use num_bigint::BigUint;

const PRESERVED_PROBE_ITEMS: usize = 712;
// Frozen square-specialized, pre-shared-pool checkpoints. The pooled kernels
// live behind separate explicit APIs and do not change these baselines.
const EXPECTED_HYBRID_FIRST_BYTES: usize = 37_296;
const EXPECTED_HYBRID_CHAINED_BYTES: usize = 50_306;
const EXPECTED_HYBRID_U5_RETURNING_BYTES: usize = 45_834;
const EXPECTED_HYBRID_U5_TERMINAL_BYTES: usize = 45_605;

fn add_mod(lhs: &BigUint, rhs: &BigUint, p: &BigUint) -> BigUint {
    (lhs + rhs) % p
}

fn sub_mod(lhs: &BigUint, rhs: &BigUint, p: &BigUint) -> BigUint {
    (lhs + p - rhs) % p
}

fn mul_mod(lhs: &BigUint, rhs: &BigUint, p: &BigUint) -> BigUint {
    (lhs * rhs) % p
}

fn hex(value: &[u8]) -> BigUint {
    BigUint::parse_bytes(value, 16).expect("fixed hexadecimal fixture is valid")
}

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn assert_output(execution: &ExecuteInfo, expected: &[Vec<u8>]) {
    assert!(
        execution.error.is_none(),
        "hybrid derived transition failed: {execution}"
    );
    assert_eq!(execution.final_stack.len(), expected.len());
    for (index, item) in expected.iter().enumerate() {
        assert_eq!(execution.final_stack.get(index), *item);
    }
}

fn static_non_push_opcodes(script: &bitcoin::Script) -> usize {
    script
        .instructions()
        .map(|instruction| instruction.expect("generated script parses"))
        .filter(
            |instruction| matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() > 0x60),
        )
        .count()
}

fn main() {
    assert_eq!(HYBRID_STATE_ITEM_COUNT, 92);
    assert_eq!(HYBRID_CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT, 133);
    assert_eq!(HYBRID_CHAINED_U5_DERIVED_COMPLETE_INPUT_ITEM_COUNT, 176);

    let p = modulus();
    let montgomery_a = BigUint::from(486_662u32);
    let u_prev = hex(b"123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let a_prev = hex(b"23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0");
    let b_prev = hex(b"3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01");
    let lambda_prev = hex(b"456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012");
    let u_initial = sub_mod(
        &sub_mod(
            &sub_mod(&mul_mod(&lambda_prev, &lambda_prev, &p), &u_prev, &p),
            &a_prev,
            &p,
        ),
        &montgomery_a,
        &p,
    );
    let v_initial = sub_mod(
        &b_prev,
        &mul_mod(&lambda_prev, &sub_mod(&a_prev, &u_initial, &p), &p),
        &p,
    );
    let a_next = hex(b"56789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123");
    let lambda_next = hex(b"6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234");
    let u_next = sub_mod(
        &sub_mod(
            &sub_mod(&mul_mod(&lambda_next, &lambda_next, &p), &u_prev, &p),
            &a_next,
            &p,
        ),
        &montgomery_a,
        &p,
    );
    let next_term = mul_mod(&lambda_next, &sub_mod(&a_next, &u_prev, &p), &p);
    let previous_term = mul_mod(&lambda_prev, &sub_mod(&a_prev, &u_prev, &p), &p);
    let b_next = sub_mod(&add_mod(&next_term, &previous_term, &p), &b_prev, &p);

    let witness = chained_transition_derived_hybrid_witness_items(
        &u_prev,
        &lambda_prev,
        &a_prev,
        &b_prev,
        &u_next,
        &lambda_next,
        &a_next,
        &b_next,
    );
    assert_eq!(
        witness.len(),
        HYBRID_CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT
    );
    let u5_final_witness = chained_transition_derived_hybrid_u5_witness_items(
        &u_prev,
        &lambda_prev,
        &a_prev,
        &b_prev,
        &u_next,
        &lambda_next,
        &a_next,
        &b_next,
    );
    assert_eq!(
        u5_final_witness.len(),
        HYBRID_CHAINED_U5_DERIVED_COMPLETE_INPUT_ITEM_COUNT
    );
    let expected = hybrid_output_state_items(&u_next, &lambda_next, &a_next, &b_next);
    assert_eq!(expected.len(), HYBRID_STATE_ITEM_COUNT);

    let first_witness = first_transition_derived_witness_items(
        &u_initial,
        &v_initial,
        &u_prev,
        &lambda_prev,
        &a_prev,
        &b_prev,
    );
    let first_expected = hybrid_output_state_items(&u_prev, &lambda_prev, &a_prev, &b_prev);

    let baseline_first = verify_first_transition_derived(0).compile_with_policy();
    let baseline = verify_chained_transition_derived(0).compile_with_policy();
    let hybrid_first = verify_first_transition_derived_hybrid_state(0).compile_with_policy();
    let hybrid = verify_chained_transition_derived_hybrid_state(0).compile_with_policy();
    let hybrid_u5_final =
        verify_chained_transition_derived_hybrid_state_certified_u_next_u5(0).compile_with_policy();
    let hybrid_u5_terminal =
        verify_chained_transition_derived_hybrid_state_certified_u_next_u5_terminal(0)
            .compile_with_policy();
    assert_eq!(hybrid_first.len(), EXPECTED_HYBRID_FIRST_BYTES);
    assert_eq!(hybrid.len(), EXPECTED_HYBRID_CHAINED_BYTES);
    assert_eq!(hybrid_u5_final.len(), EXPECTED_HYBRID_U5_RETURNING_BYTES);
    assert_eq!(hybrid_u5_terminal.len(), EXPECTED_HYBRID_U5_TERMINAL_BYTES);
    if std::env::args().nth(1).as_deref() == Some("--terminal-only") {
        let terminal_execution = execute_raw_script_with_inputs_strict(
            hybrid_u5_terminal.to_bytes(),
            u5_final_witness.clone(),
        );
        assert_output(&terminal_execution, &[scriptnum_item(1)]);
        println!("model=ed25519_montgomery_slope_hybrid_state_terminal_probe");
        println!("evidence=locally-reproduced");
        println!("execution_class=unclassified");
        println!("entry_data_items={HYBRID_CHAINED_U5_DERIVED_COMPLETE_INPUT_ITEM_COUNT}");
        println!("entry_hint_items=0");
        println!("returning_u5_kernel_policy_bytes={}", hybrid_u5_final.len());
        println!(
            "separate_returning_terminal_policy_bytes={}",
            hybrid_u5_final.len() + 47
        );
        println!(
            "terminal_u5_kernel_policy_bytes={}",
            hybrid_u5_terminal.len()
        );
        println!(
            "terminal_fusion_byte_saving={}",
            hybrid_u5_final.len() + 47 - hybrid_u5_terminal.len()
        );
        println!(
            "terminal_u5_strict_combined_peak={}",
            terminal_execution.stats.max_nb_stack_items
        );
        println!("terminal_output_items=1");
        println!("terminal_output_clean_truth=true");
        println!("whole_scalar_leaf_built=false");
        println!("whole_scalar_leaf_executed=false");
        return;
    }
    let first_execution =
        execute_raw_script_with_inputs_strict(hybrid_first.to_bytes(), first_witness);
    assert_output(&first_execution, &first_expected);
    let local_execution = execute_raw_script_with_inputs_strict(hybrid.to_bytes(), witness.clone());
    assert_output(&local_execution, &expected);
    let u5_final_execution =
        execute_raw_script_with_inputs_strict(hybrid_u5_final.to_bytes(), u5_final_witness.clone());
    assert_output(&u5_final_execution, &expected);
    let u5_terminal_execution = execute_raw_script_with_inputs_strict(
        hybrid_u5_terminal.to_bytes(),
        u5_final_witness.clone(),
    );
    assert_output(&u5_terminal_execution, &[scriptnum_item(1)]);

    let hybrid_preserving =
        verify_chained_transition_derived_hybrid_state(PRESERVED_PROBE_ITEMS as u32)
            .compile_with_policy();
    let prefix = (0..PRESERVED_PROBE_ITEMS)
        .map(|index| scriptnum_item(1 + (index % 97) as i64))
        .collect::<Vec<_>>();
    let mut preserving_witness = prefix.clone();
    preserving_witness.extend(witness.clone());
    let mut preserving_expected = prefix;
    preserving_expected.extend(expected);
    let preserving_execution =
        execute_raw_script_with_inputs_strict(hybrid_preserving.to_bytes(), preserving_witness);
    assert_output(&preserving_execution, &preserving_expected);

    // All malformed data remains canonical, but u_next no longer satisfies
    // the curve relation. Derived quotient reconstruction must reject it.
    let malformed_u = (&u_next + BigUint::from(1u8)) % &p;
    let mut malformed = witness;
    malformed[..u5_packed::PACKED_WORD_COUNT]
        .clone_from_slice(&u5_packed::packed_value_witness_items(&malformed_u));
    let malformed_execution = execute_raw_script_with_inputs_strict(hybrid.to_bytes(), malformed);
    assert!(
        malformed_execution.error.is_some(),
        "hybrid transition accepted malformed canonical u_next"
    );
    let mut malformed_u5 = u5_final_witness;
    let malformed_u5_items = field_digits(&malformed_u)
        .iter()
        .rev()
        .map(|digit| scriptnum_item(i64::from(*digit)))
        .collect::<Vec<_>>();
    malformed_u5[..51].clone_from_slice(&malformed_u5_items);
    let malformed_u5_execution =
        execute_raw_script_with_inputs_strict(hybrid_u5_final.to_bytes(), malformed_u5.clone());
    assert!(
        malformed_u5_execution.error.is_some(),
        "certified-u5 hybrid transition accepted incorrect canonical u_next"
    );
    let malformed_u5_terminal_execution =
        execute_raw_script_with_inputs_strict(hybrid_u5_terminal.to_bytes(), malformed_u5);
    assert!(
        malformed_u5_terminal_execution.error.is_some(),
        "terminal certified-u5 hybrid transition accepted incorrect canonical u_next"
    );

    println!("model=ed25519_montgomery_slope_hybrid_state_probe");
    println!("evidence=locally-reproduced");
    println!("execution_class=unclassified");
    println!("entry_data_items={HYBRID_CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT}");
    println!("entry_hint_items=0");
    println!("all_entry_items_coexist=true");
    println!("output_state_items={HYBRID_STATE_ITEM_COUNT}");
    println!("output_state_order=b9|a16|lambda_biased51|u16");
    println!(
        "baseline_packed_state_first_policy_bytes={}",
        baseline_first.len()
    );
    println!(
        "baseline_packed_state_chained_policy_bytes={}",
        baseline.len()
    );
    println!("hybrid_first_policy_bytes={}", hybrid_first.len());
    println!("hybrid_chained_policy_bytes={}", hybrid.len());
    println!(
        "hybrid_certified_u5_final_policy_bytes={}",
        hybrid_u5_final.len()
    );
    println!(
        "hybrid_certified_u5_terminal_policy_bytes={}",
        hybrid_u5_terminal.len()
    );
    println!(
        "hybrid_first_byte_saving={}",
        baseline_first.len() - hybrid_first.len()
    );
    println!(
        "hybrid_chained_byte_saving={}",
        baseline.len() - hybrid.len()
    );
    println!(
        "hybrid_certified_u5_final_byte_saving_vs_packed_hybrid={}",
        hybrid.len() - hybrid_u5_final.len()
    );
    println!(
        "hybrid_chained_static_non_push_opcodes={}",
        static_non_push_opcodes(&hybrid)
    );
    println!(
        "hybrid_first_local_strict_combined_peak={}",
        first_execution.stats.max_nb_stack_items
    );
    println!(
        "hybrid_local_strict_combined_peak={}",
        local_execution.stats.max_nb_stack_items
    );
    println!(
        "hybrid_certified_u5_final_local_strict_combined_peak={}",
        u5_final_execution.stats.max_nb_stack_items
    );
    println!(
        "hybrid_certified_u5_terminal_local_strict_combined_peak={}",
        u5_terminal_execution.stats.max_nb_stack_items
    );
    println!("preserved_probe_items={PRESERVED_PROBE_ITEMS}");
    println!("hybrid_preserving_policy_bytes={}", hybrid_preserving.len());
    println!(
        "hybrid_preserving_strict_combined_peak={}",
        preserving_execution.stats.max_nb_stack_items
    );
    println!("lambda_next_packed_decode_count=1");
    println!("u_next_packed_decode_count=1");
    println!("previous_expanded_field_decode_count=0");
    println!("malformed_canonical_u_next_rejected=true");
    println!("malformed_certified_u5_u_next_rejected=true");
    println!("malformed_terminal_certified_u5_u_next_rejected=true");
    println!(
        "certified_u5_final_input_items={HYBRID_CHAINED_U5_DERIVED_COMPLETE_INPUT_ITEM_COUNT}"
    );
    println!("certified_u5_final_input_certification=external_final_r_path");
    println!("auxiliary_hint_items_per_invocation=0");
    println!("whole_scalar_leaf_built=false");
    println!("whole_scalar_leaf_executed=false");
}
