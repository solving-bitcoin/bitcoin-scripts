//! One-shot benchmark for the Montgomery slope-chain transition kernels.
//!
//! This executes positive and literal-negative-selected fixtures for one
//! top/first transition and one chained transition. It deliberately does not
//! construct or execute the 44-transition scalar multiplication. Pass
//! `--sizes-only` to skip all four transition executions.
//!
//! Run with:
//! `cargo run --locked --release --example ed25519_montgomery_slope_transition_benchmark`.

use bitcoin::{consensus::encode::serialize, script::Instruction, Witness};
use bitcoin_lab::{
    curves::ed25519::montgomery_slope::{
        chained_transition_hints, chained_transition_hints_from_direct_limbs,
        chained_transition_witness_items, chained_transition_witness_items_from_direct_limbs,
        first_transition_hints, first_transition_hints_from_direct_limbs,
        first_transition_witness_items, first_transition_witness_items_from_direct_limbs,
        output_state_items, output_state_items_from_direct_limbs, verify_chained_transition,
        verify_first_transition, DirectCoordinateLimbs, CHAINED_CLAIMED_DATA_ITEM_COUNT,
        CHAINED_COMPLETE_INPUT_ITEM_COUNT, FIRST_CLAIMED_DATA_ITEM_COUNT,
        FIRST_COMPLETE_INPUT_ITEM_COUNT, HINT_ITEM_COUNT, LINEAR_LIMB_COUNT, OUTPUT_ITEM_COUNT,
        PRODUCT_LIMB_COUNT,
    },
    fields::ed25519::u5_balanced_table::modulus,
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
    },
};
use num_bigint::BigUint;

// The 29 response groups plus sixteen byte-aligned challenge groups require
// 44 transitions. Each future transition contributes 18 packet items. The
// carrier predecoder materializes eight scalar words and leaves one live
// transcript chunk below the first kernel, then two below kernel #2.
const FIRST_PRESERVED_ITEMS: usize = 43 * 18 + 8 + 1;
const CHAINED_PRESERVED_ITEMS: usize = 42 * 18 + 8 + 2;
const FULL_CHAIN_TRANSITIONS: usize = 44;
// Older 14-group challenge profile, retained only for a directly comparable
// projection from the measured data-independent local peaks.
const G43_FIRST_PRESERVED_ITEMS: usize = 746;
const G43_CHAINED_PRESERVED_ITEMS: usize = 728;
const EXPECTED_FIRST_SCRIPT_BYTES: usize = 42_754;
const EXPECTED_CHAINED_SCRIPT_BYTES: usize = 65_568;

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

fn static_non_push_opcodes(script: &bitcoin::ScriptBuf) -> usize {
    script
        .instructions()
        .map(|instruction| instruction.expect("generated script must parse"))
        .filter(
            |instruction| matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() > 0x60),
        )
        .count()
}

fn assert_output(
    execution: &bitcoin_lab::support::execution::ExecuteInfo,
    preserved: usize,
    expected: &[Vec<u8>],
) {
    assert!(execution.error.is_none(), "transition failed: {execution}");
    assert_eq!(execution.final_stack.len(), preserved + expected.len());
    for (index, item) in expected.iter().enumerate() {
        assert_eq!(execution.final_stack.get(preserved + index), *item);
    }
}

fn scriptnum_item(value: i32) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value));
    bytes[..length].to_vec()
}

fn hint_items(curve: i32, continuity: i32) -> Vec<Vec<u8>> {
    [continuity, curve]
        .into_iter()
        .map(scriptnum_item)
        .collect()
}

fn main() {
    let p = modulus();
    let montgomery_a = BigUint::from(486_662u32);

    // Deterministic algebraic fixture for the first relation pair.
    let u0 = hex(b"123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let a1 = hex(b"23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0");
    let b1 = hex(b"3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01");
    let lambda1 = hex(b"456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012");
    let lambda1_squared = mul_mod(&lambda1, &lambda1, &p);
    let u1 = sub_mod(
        &sub_mod(&sub_mod(&lambda1_squared, &u0, &p), &a1, &p),
        &montgomery_a,
        &p,
    );
    let first_slope_term = mul_mod(&lambda1, &sub_mod(&a1, &u0, &p), &p);
    let v0 = sub_mod(&b1, &first_slope_term, &p);
    let first_hints = first_transition_hints(&u0, &v0, &u1, &lambda1, &a1, &b1);
    let first_witness =
        first_transition_witness_items(&u0, &v0, &u1, &lambda1, &a1, &b1, first_hints);

    // The next deterministic fixture uses the first result as its prior
    // state and satisfies both chained equations by construction.
    let a2 = hex(b"56789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123");
    let lambda2 = hex(b"6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234");
    let lambda2_squared = mul_mod(&lambda2, &lambda2, &p);
    let u2 = sub_mod(
        &sub_mod(&sub_mod(&lambda2_squared, &u1, &p), &a2, &p),
        &montgomery_a,
        &p,
    );
    let term2a = mul_mod(&lambda2, &sub_mod(&a2, &u1, &p), &p);
    let term2b = mul_mod(&lambda1, &sub_mod(&a1, &u1, &p), &p);
    let b2 = sub_mod(&add_mod(&term2a, &term2b, &p), &b1, &p);
    let chained_hints = chained_transition_hints(&u1, &lambda1, &a1, &b1, &u2, &lambda2, &a2, &b2);
    let chained_witness = chained_transition_witness_items(
        &u1,
        &lambda1,
        &a1,
        &b1,
        &u2,
        &lambda2,
        &a2,
        &b2,
        chained_hints,
    );

    // Sign routing negates the selected b limbs literally. Choose a magnitude
    // around p/2 so that this representative provably differs from regrouping
    // the canonical residue p-b by exactly one modulus.
    let zero = BigUint::from(0u8);
    let negative_b1_magnitude = &p >> 1usize;
    let negative_b1_value = sub_mod(&zero, &negative_b1_magnitude, &p);
    let negative_v0 = sub_mod(&negative_b1_value, &first_slope_term, &p);
    let negative_initial = DirectCoordinateLimbs::from_canonical(&u0, &negative_v0);
    let negative_selected1 =
        DirectCoordinateLimbs::from_canonical(&a1, &negative_b1_magnitude).literal_negative();
    let canonical_selected1 = DirectCoordinateLimbs::from_canonical(&a1, &negative_b1_value);
    assert_ne!(negative_selected1.linear, canonical_selected1.linear);
    let negative_first_hints = first_transition_hints_from_direct_limbs(
        &negative_initial,
        &u1,
        &lambda1,
        &negative_selected1,
    );
    let regrouped_negative_first_hints =
        first_transition_hints(&u0, &negative_v0, &u1, &lambda1, &a1, &negative_b1_value);
    assert_ne!(
        negative_first_hints.continuity,
        regrouped_negative_first_hints.continuity
    );
    let negative_first_witness = first_transition_witness_items_from_direct_limbs(
        &negative_initial,
        &u1,
        &lambda1,
        &negative_selected1,
        negative_first_hints,
    );

    // Make transition #2 negative-selected as well. Its field value is fixed
    // by the continuity equation; sign routing starts from the opposite
    // magnitude and retains its literal limbwise negative.
    let continuity_sum = add_mod(&term2a, &term2b, &p);
    let negative_b2_value = sub_mod(&continuity_sum, &negative_b1_value, &p);
    let negative_b2_magnitude = sub_mod(&zero, &negative_b2_value, &p);
    let negative_selected2 =
        DirectCoordinateLimbs::from_canonical(&a2, &negative_b2_magnitude).literal_negative();
    let negative_chained_hints = chained_transition_hints_from_direct_limbs(
        &u1,
        &lambda1,
        &negative_selected1,
        &u2,
        &lambda2,
        &negative_selected2,
    );
    let regrouped_negative_chained_hints = chained_transition_hints(
        &u1,
        &lambda1,
        &a1,
        &negative_b1_value,
        &u2,
        &lambda2,
        &a2,
        &negative_b2_value,
    );
    assert_ne!(
        negative_chained_hints.continuity,
        regrouped_negative_chained_hints.continuity
    );
    let negative_chained_witness = chained_transition_witness_items_from_direct_limbs(
        &u1,
        &lambda1,
        &negative_selected1,
        &u2,
        &lambda2,
        &negative_selected2,
        negative_chained_hints,
    );

    let first_script = verify_first_transition(FIRST_PRESERVED_ITEMS as u32).compile_with_policy();
    let chained_script =
        verify_chained_transition(CHAINED_PRESERVED_ITEMS as u32).compile_with_policy();
    assert!(first_script.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert!(chained_script.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(first_script.len(), EXPECTED_FIRST_SCRIPT_BYTES);
    assert_eq!(chained_script.len(), EXPECTED_CHAINED_SCRIPT_BYTES);

    let sizes_only = std::env::args().any(|argument| argument == "--sizes-only");
    let mut first_peak = None;
    let mut chained_peak = None;
    let mut malformed_quotient_rejected = None;
    let mut negative_selected_first_passed = None;
    let mut negative_selected_chained_passed = None;
    if !sizes_only {
        let mut full_first_witness = vec![Vec::new(); FIRST_PRESERVED_ITEMS];
        full_first_witness.extend(first_witness.clone());
        let first_execution =
            execute_raw_script_with_inputs_strict(first_script.to_bytes(), full_first_witness);
        assert_output(
            &first_execution,
            FIRST_PRESERVED_ITEMS,
            &output_state_items(&u1, &lambda1, &a1, &b1),
        );
        first_peak = Some(first_execution.stats.max_nb_stack_items);

        // Keep the malformed check at the same H16 entry boundary.
        let mut malformed = first_witness.clone();
        let q_curve_index = 2 * 8 + PRODUCT_LIMB_COUNT + LINEAR_LIMB_COUNT + 1;
        malformed[q_curve_index] = scriptnum_item(first_hints.curve + 1);
        let mut malformed_full = vec![Vec::new(); FIRST_PRESERVED_ITEMS];
        malformed_full.extend(malformed);
        let malformed_execution =
            execute_raw_script_with_inputs_strict(first_script.to_bytes(), malformed_full);
        let rejected = malformed_execution.error.is_some();
        assert!(
            rejected,
            "false relation quotient was accepted: {malformed_execution}"
        );
        malformed_quotient_rejected = Some(rejected);

        let mut negative_first_full = vec![Vec::new(); FIRST_PRESERVED_ITEMS];
        negative_first_full.extend(negative_first_witness);
        let negative_first_execution =
            execute_raw_script_with_inputs_strict(first_script.to_bytes(), negative_first_full);
        assert_output(
            &negative_first_execution,
            FIRST_PRESERVED_ITEMS,
            &output_state_items_from_direct_limbs(&u1, &lambda1, &negative_selected1),
        );
        assert_eq!(
            negative_first_execution.stats.max_nb_stack_items,
            first_peak.expect("positive first transition ran")
        );
        negative_selected_first_passed = Some(true);

        let mut full_chained_witness = vec![Vec::new(); CHAINED_PRESERVED_ITEMS];
        full_chained_witness.extend(chained_witness.clone());
        let chained_execution =
            execute_raw_script_with_inputs_strict(chained_script.to_bytes(), full_chained_witness);
        assert_output(
            &chained_execution,
            CHAINED_PRESERVED_ITEMS,
            &output_state_items(&u2, &lambda2, &a2, &b2),
        );
        chained_peak = Some(chained_execution.stats.max_nb_stack_items);

        let mut negative_chained_full = vec![Vec::new(); CHAINED_PRESERVED_ITEMS];
        negative_chained_full.extend(negative_chained_witness);
        let negative_chained_execution =
            execute_raw_script_with_inputs_strict(chained_script.to_bytes(), negative_chained_full);
        assert_output(
            &negative_chained_execution,
            CHAINED_PRESERVED_ITEMS,
            &output_state_items_from_direct_limbs(&u2, &lambda2, &negative_selected2),
        );
        assert_eq!(
            negative_chained_execution.stats.max_nb_stack_items,
            chained_peak.expect("positive chained transition ran")
        );
        negative_selected_chained_passed = Some(true);
    }

    println!("first_locking_script_bytes={}", first_script.len());
    println!("chained_locking_script_bytes={}", chained_script.len());
    println!("whole_locking_script_optimized=false");
    println!("semantic_steps_policy_precompiled=true");
    println!("optimizer_cutoff_bytes={MAX_OPTIMIZER_INPUT_BYTES}");
    println!(
        "first_static_non_push_opcodes={}",
        static_non_push_opcodes(&first_script)
    );
    println!(
        "chained_static_non_push_opcodes={}",
        static_non_push_opcodes(&chained_script)
    );
    println!("incremental_hint_items_per_transition={HINT_ITEM_COUNT}");
    println!(
        "full_44_transition_hint_items={}",
        FULL_CHAIN_TRANSITIONS * HINT_ITEM_COUNT
    );
    println!("first_claimed_data_items={FIRST_CLAIMED_DATA_ITEM_COUNT}");
    println!("first_complete_input_items={FIRST_COMPLETE_INPUT_ITEM_COUNT}");
    println!("first_preserved_items={FIRST_PRESERVED_ITEMS}");
    println!(
        "first_complete_fragment_entry_items={}",
        FIRST_PRESERVED_ITEMS + FIRST_COMPLETE_INPUT_ITEM_COUNT
    );
    println!("chained_claimed_data_items={CHAINED_CLAIMED_DATA_ITEM_COUNT}");
    println!("chained_complete_input_items={CHAINED_COMPLETE_INPUT_ITEM_COUNT}");
    println!("chained_preserved_items={CHAINED_PRESERVED_ITEMS}");
    println!(
        "chained_complete_fragment_entry_items={}",
        CHAINED_PRESERVED_ITEMS + CHAINED_COMPLETE_INPUT_ITEM_COUNT
    );
    println!("output_state_items={OUTPUT_ITEM_COUNT}");
    println!(
        "first_local_witness_bytes={}",
        serialize(&Witness::from_slice(&first_witness)).len()
    );
    println!(
        "chained_local_witness_bytes={}",
        serialize(&Witness::from_slice(&chained_witness)).len()
    );
    println!(
        "first_hint_witness_bytes={}",
        serialize(&Witness::from_slice(&hint_items(
            first_hints.curve,
            first_hints.continuity
        )))
        .len()
    );
    println!(
        "chained_hint_witness_bytes={}",
        serialize(&Witness::from_slice(&hint_items(
            chained_hints.curve,
            chained_hints.continuity
        )))
        .len()
    );
    println!("first_quotients={:?}", first_hints);
    println!("chained_quotients={:?}", chained_hints);
    println!("negative_selected_first_quotients={negative_first_hints:?}");
    println!("negative_selected_chained_quotients={negative_chained_hints:?}");
    println!(
        "negative_selected_first_q_delta_from_regrouped={}",
        negative_first_hints.continuity - regrouped_negative_first_hints.continuity
    );
    println!(
        "negative_selected_chained_q_delta_from_regrouped={}",
        negative_chained_hints.continuity - regrouped_negative_chained_hints.continuity
    );
    println!(
        "first_strict_combined_stack_peak={}",
        first_peak
            .map(|value| value.to_string())
            .unwrap_or_else(|| "skipped".to_owned())
    );
    println!(
        "chained_strict_combined_stack_peak={}",
        chained_peak
            .map(|value| value.to_string())
            .unwrap_or_else(|| "skipped".to_owned())
    );
    if let (Some(first), Some(chained)) = (first_peak, chained_peak) {
        let first_local = first - FIRST_PRESERVED_ITEMS;
        let chained_local = chained - CHAINED_PRESERVED_ITEMS;
        println!("first_local_stack_peak={first_local}");
        println!("chained_local_stack_peak={chained_local}");
        println!(
            "g43_first_projected_combined_stack_peak={}",
            G43_FIRST_PRESERVED_ITEMS + first_local
        );
        println!(
            "g43_chained_projected_combined_stack_peak={}",
            G43_CHAINED_PRESERVED_ITEMS + chained_local
        );
    }
    println!(
        "valid_execution_samples_per_kernel={}",
        2 * usize::from(!sizes_only)
    );
    println!(
        "malformed_quotient_rejected={}",
        malformed_quotient_rejected
            .map(|value| value.to_string())
            .unwrap_or_else(|| "skipped".to_owned())
    );
    println!(
        "negative_selected_first_passed={}",
        negative_selected_first_passed
            .map(|value| value.to_string())
            .unwrap_or_else(|| "skipped".to_owned())
    );
    println!(
        "negative_selected_chained_passed={}",
        negative_selected_chained_passed
            .map(|value| value.to_string())
            .unwrap_or_else(|| "skipped".to_owned())
    );
    println!("execution_class=unclassified");
    println!("context=tapscript,strict_1000_item_stack,bitcoin-scriptexec");
    println!(
        "includes=fragment-only: transition verifier, hostile packed-field decoding, two quotient hints, selected/current data, and output-state retention; fixed tables and terminal predicate excluded"
    );
}
