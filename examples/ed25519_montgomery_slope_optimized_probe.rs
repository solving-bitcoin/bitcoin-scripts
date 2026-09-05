//! Bounded strict checks for the current zero-hint slope kernels.
//! Runs one kernel configuration per invocation; no whole scalar leaf.

use bitcoin_lab::{
    curves::ed25519::montgomery_slope as slope,
    fields::ed25519::{u5_balanced_table::modulus, u5_packed},
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation},
    },
};
use num_bigint::BigUint;

fn sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    (a + p - b) % p
}
fn mul(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    a * b % p
}
fn hex(s: &[u8]) -> BigUint {
    BigUint::parse_bytes(s, 16).unwrap()
}
fn item(n: i64) -> Vec<u8> {
    let mut bytes = [0; 8];
    let len = bitcoin::script::write_scriptint(&mut bytes, n);
    bytes[..len].to_vec()
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "first".into());
    let p = modulus();
    let a = BigUint::from(486_662u32);
    let u = hex(b"123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let ap = hex(b"23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0");
    let bp = hex(b"3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01");
    let lp = hex(b"456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012");
    let an = hex(b"56789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123");
    let ln = hex(b"6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234");
    let ui = sub(&sub(&sub(&mul(&lp, &lp, &p), &u, &p), &ap, &p), &a, &p);
    let vi = sub(&bp, &mul(&lp, &sub(&ap, &ui, &p), &p), &p);
    let un = sub(&sub(&sub(&mul(&ln, &ln, &p), &u, &p), &an, &p), &a, &p);
    let bn = sub(
        &(mul(&ln, &sub(&an, &u, &p), &p) + mul(&lp, &sub(&ap, &u, &p), &p)),
        &bp,
        &p,
    );
    let (fragment, witness, expected, preserved, alt_pool) = match mode.as_str() {
        "first" => (
            slope::verify_first_transition_derived_hybrid_state_shared_power_pool(787),
            slope::first_transition_derived_witness_items(&ui, &vi, &u, &lp, &ap, &bp),
            slope::hybrid_output_state_items(&u, &lp, &ap, &bp), 787, 0,
        ),
        "chained" | "persistent" | "finalize" => (
            match mode.as_str() {
                "chained" => slope::verify_chained_transition_derived_hybrid_state_initialize_persistent_shared_power_pool(771),
                "persistent" => slope::verify_chained_transition_derived_hybrid_state_persistent_shared_power_pool(754),
                _ => slope::verify_chained_transition_derived_hybrid_state_finalize_persistent_shared_power_pool(299),
            },
            slope::chained_transition_derived_hybrid_witness_items(&u, &lp, &ap, &bp, &un, &ln, &an, &bn),
            slope::hybrid_output_state_items(&un, &ln, &an, &bn),
            match mode.as_str() { "chained" => 771, "persistent" => 754, _ => 299 },
            if mode == "finalize" { 0 } else { 16 },
        ),
        "terminal" | "terminal-pooled" => (
            if mode == "terminal" {
                slope::verify_chained_transition_derived_hybrid_state_certified_u_next_u5_terminal(0)
            } else {
                slope::verify_chained_transition_derived_hybrid_state_certified_u_next_u5_terminal_finalize_persistent_shared_power_pool(0)
            },
            slope::chained_transition_derived_hybrid_u5_witness_items(&u, &lp, &ap, &bp, &un, &ln, &an, &bn),
            vec![item(1)], 0, 0,
        ),
        _ => panic!("use first, chained, persistent, finalize, terminal, or terminal-pooled"),
    };
    let compiled = fragment.compile_with_policy();
    let incoming_pool = matches!(mode.as_str(), "persistent" | "finalize" | "terminal-pooled");
    let setup = if incoming_pool {
        slope::initialize_hybrid_persistent_shared_power_pool()
    } else {
        Script::new("no incoming pool")
    };
    // Verify the exact outgoing pool separately; it is not a kernel byte cost.
    let check_pool = script! {
        for bit in slope::HYBRID_LATER_SHARED_POWER_BITS.iter().take(alt_pool) {
            OP_FROMALTSTACK { 1u32 << bit } OP_EQUALVERIFY
        }
    };
    let strict = script! { { setup } { compiled.clone() } { check_pool } }.compile_with_policy();
    let prefix = (0..preserved)
        .map(|i| item(1 + i as i64 % 97))
        .collect::<Vec<_>>();
    let args = prefix
        .iter()
        .cloned()
        .chain(witness.iter().cloned())
        .collect();
    let result = execute_raw_script_with_inputs_strict(strict.to_bytes(), args);
    assert!(result.error.is_none(), "honest {mode}: {result}");
    let outputs = prefix.iter().cloned().chain(expected).collect::<Vec<_>>();
    assert_eq!(result.final_stack.len(), outputs.len());
    for (index, value) in outputs.iter().enumerate() {
        assert_eq!(result.final_stack.get(index), *value);
    }
    assert!(result.stats.max_nb_stack_items < 1_000);
    // A canonical but incorrect u_next must fail the exact curve identity.
    let local_data_items = witness.len();
    let mut malformed = witness;
    if !mode.starts_with("terminal") {
        let original = if mode == "first" { &u } else { &un };
        malformed[..8].clone_from_slice(&u5_packed::packed_value_witness_items(
            &((original + BigUint::from(1u8)) % &p),
        ));
    } else {
        let changed = slope::chained_transition_derived_hybrid_u5_witness_items(
            &u,
            &lp,
            &ap,
            &bp,
            &((&un + BigUint::from(1u8)) % &p),
            &ln,
            &an,
            &bn,
        );
        malformed[..51].clone_from_slice(&changed[..51]);
    }
    let args = prefix.into_iter().chain(malformed).collect();
    let rejected = execute_raw_script_with_inputs_strict(strict.to_bytes(), args);
    assert!(
        rejected.error.is_some(),
        "accepted changed canonical coordinate"
    );
    println!("model=ed25519_montgomery_slope_optimized_probe");
    println!("configuration={mode}");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=isolated-strict-kernel-execution");
    println!("execution_class=unclassified");
    println!("policy_bytes={}", compiled.len());
    println!("whole_kernel_optimizer=NONE");
    println!("preserved_items={preserved}");
    println!("local_input_data_items={local_data_items}");
    println!("complete_entry_data_items={}", preserved + local_data_items);
    println!("all_entry_data_items_coexist=true");
    println!(
        "strict_combined_stack_peak={}",
        result.stats.max_nb_stack_items
    );
    println!(
        "local_stack_peak={}",
        result.stats.max_nb_stack_items - preserved
    );
    println!("auxiliary_hint_items=0");
    println!("script_authored_output_alt_pool_items={alt_pool}");
    println!(
        "script_authored_input_alt_pool_items={}",
        usize::from(incoming_pool) * 16
    );
    println!("canonical_coordinate_mutation_rejected=true");
    println!("whole_scalar_leaf_executed=false");
}
