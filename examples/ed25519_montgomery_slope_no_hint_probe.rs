//! Focused strict probe for the quotient-free Montgomery slope kernels.
//!
//! This executes one deterministic first transition, one chained transition,
//! and one malformed canonical-trace rejection. It does not build or execute
//! a scalar multiplication, table schedule, transcript hash, or full leaf.

use bitcoin_lab::{
    curves::ed25519::montgomery_slope::{
        chained_transition_derived_witness_items, first_transition_derived_witness_items,
        output_state_items, verify_chained_transition, verify_chained_transition_derived,
        verify_chained_transition_derived_legacy_naf, verify_first_transition,
        verify_first_transition_derived, verify_first_transition_derived_legacy_naf,
        CHAINED_COMPLETE_INPUT_ITEM_COUNT, CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT,
        FIRST_COMPLETE_INPUT_ITEM_COUNT, FIRST_DERIVED_COMPLETE_INPUT_ITEM_COUNT,
        OUTPUT_ITEM_COUNT,
    },
    fields::ed25519::{u5_balanced_table::modulus, u5_packed},
    support::{
        execution::{execute_raw_script_with_inputs_strict, ExecuteInfo},
        script::ScriptCompilation,
    },
};
use num_bigint::BigUint;

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

fn assert_output(execution: &ExecuteInfo, expected: &[Vec<u8>]) {
    assert!(
        execution.error.is_none(),
        "derived transition failed: {execution}"
    );
    assert_eq!(execution.final_stack.len(), OUTPUT_ITEM_COUNT);
    for (index, item) in expected.iter().enumerate() {
        assert_eq!(execution.final_stack.get(index), *item);
    }
}

fn main() {
    assert_eq!(FIRST_COMPLETE_INPUT_ITEM_COUNT, 68);
    assert_eq!(FIRST_DERIVED_COMPLETE_INPUT_ITEM_COUNT, 66);
    assert_eq!(CHAINED_COMPLETE_INPUT_ITEM_COUNT, 84);
    assert_eq!(CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT, 82);

    let p = modulus();
    let montgomery_a = BigUint::from(486_662u32);
    let u0 = hex(b"123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let a1 = hex(b"23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0");
    let b1 = hex(b"3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01");
    let lambda1 = hex(b"456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012");
    let u1 = sub_mod(
        &sub_mod(&sub_mod(&mul_mod(&lambda1, &lambda1, &p), &u0, &p), &a1, &p),
        &montgomery_a,
        &p,
    );
    let v0 = sub_mod(&b1, &mul_mod(&lambda1, &sub_mod(&a1, &u0, &p), &p), &p);
    let first_witness = first_transition_derived_witness_items(&u0, &v0, &u1, &lambda1, &a1, &b1);
    assert_eq!(first_witness.len(), FIRST_DERIVED_COMPLETE_INPUT_ITEM_COUNT);

    let a2 = hex(b"56789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123");
    let lambda2 = hex(b"6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234");
    let u2 = sub_mod(
        &sub_mod(&sub_mod(&mul_mod(&lambda2, &lambda2, &p), &u1, &p), &a2, &p),
        &montgomery_a,
        &p,
    );
    let term2a = mul_mod(&lambda2, &sub_mod(&a2, &u1, &p), &p);
    let term2b = mul_mod(&lambda1, &sub_mod(&a1, &u1, &p), &p);
    let b2 = sub_mod(&add_mod(&term2a, &term2b, &p), &b1, &p);
    let chained_witness =
        chained_transition_derived_witness_items(&u1, &lambda1, &a1, &b1, &u2, &lambda2, &a2, &b2);
    assert_eq!(
        chained_witness.len(),
        CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT
    );

    let first = verify_first_transition_derived(0).compile_with_policy();
    let chained = verify_chained_transition_derived(0).compile_with_policy();
    let legacy_naf_first = verify_first_transition_derived_legacy_naf(0).compile_with_policy();
    let legacy_naf_chained = verify_chained_transition_derived_legacy_naf(0).compile_with_policy();
    let hinted_first = verify_first_transition(0).compile_with_policy();
    let hinted_chained = verify_chained_transition(0).compile_with_policy();

    let first_execution =
        execute_raw_script_with_inputs_strict(first.to_bytes(), first_witness.clone());
    assert_output(
        &first_execution,
        &output_state_items(&u1, &lambda1, &a1, &b1),
    );
    let chained_execution =
        execute_raw_script_with_inputs_strict(chained.to_bytes(), chained_witness);
    assert_output(
        &chained_execution,
        &output_state_items(&u2, &lambda2, &a2, &b2),
    );
    let legacy_naf_first_execution =
        execute_raw_script_with_inputs_strict(legacy_naf_first.to_bytes(), first_witness.clone());
    assert_output(
        &legacy_naf_first_execution,
        &output_state_items(&u1, &lambda1, &a1, &b1),
    );
    let legacy_naf_chained_execution = execute_raw_script_with_inputs_strict(
        legacy_naf_chained.to_bytes(),
        chained_transition_derived_witness_items(&u1, &lambda1, &a1, &b1, &u2, &lambda2, &a2, &b2),
    );
    assert_output(
        &legacy_naf_chained_execution,
        &output_state_items(&u2, &lambda2, &a2, &b2),
    );

    // Keep every supplied item canonical but change u_next by one. The
    // derived quotient still exists as a residue; the full carry recurrence
    // must reject the nonzero curve relation.
    let mut malformed = first_witness;
    let malformed_u = (&u1 + BigUint::from(1u8)) % &p;
    malformed[..u5_packed::PACKED_WORD_COUNT]
        .clone_from_slice(&u5_packed::packed_value_witness_items(&malformed_u));
    let malformed_execution = execute_raw_script_with_inputs_strict(first.to_bytes(), malformed);
    assert!(
        malformed_execution.error.is_some(),
        "derived kernel accepted malformed canonical u_next"
    );

    println!("model=ed25519_montgomery_slope_no_hint_probe");
    println!("first_hint_items=0");
    println!("chained_hint_items=0");
    println!("first_complete_input_items={FIRST_DERIVED_COMPLETE_INPUT_ITEM_COUNT}");
    println!("chained_complete_input_items={CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT}");
    println!("first_policy_bytes={}", first.len());
    println!("chained_policy_bytes={}", chained.len());
    println!("legacy_naf_first_policy_bytes={}", legacy_naf_first.len());
    println!(
        "legacy_naf_chained_policy_bytes={}",
        legacy_naf_chained.len()
    );
    println!("hinted_first_policy_bytes={}", hinted_first.len());
    println!("hinted_chained_policy_bytes={}", hinted_chained.len());
    println!(
        "optimized_first_saving_vs_legacy_naf={}",
        legacy_naf_first.len() - first.len()
    );
    println!(
        "optimized_chained_saving_vs_legacy_naf={}",
        legacy_naf_chained.len() - chained.len()
    );
    println!(
        "optimized_44_transition_saving_vs_legacy_naf={}",
        (legacy_naf_first.len() - first.len()) + 43 * (legacy_naf_chained.len() - chained.len())
    );
    println!(
        "first_policy_delta_bytes={}",
        first.len() - hinted_first.len()
    );
    println!(
        "chained_policy_delta_bytes={}",
        chained.len() - hinted_chained.len()
    );
    println!(
        "full_44_transition_kernel_delta_bytes={}",
        (first.len() - hinted_first.len()) + 43 * (chained.len() - hinted_chained.len())
    );
    println!(
        "first_strict_local_peak={}",
        first_execution.stats.max_nb_stack_items
    );
    println!(
        "chained_strict_local_peak={}",
        chained_execution.stats.max_nb_stack_items
    );
    println!(
        "legacy_naf_first_strict_local_peak={}",
        legacy_naf_first_execution.stats.max_nb_stack_items
    );
    println!(
        "legacy_naf_chained_strict_local_peak={}",
        legacy_naf_chained_execution.stats.max_nb_stack_items
    );
    println!("malformed_canonical_trace_rejected=true");
    println!("whole_scalar_hash_or_leaf_executed=false");
}
