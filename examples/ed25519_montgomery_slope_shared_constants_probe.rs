//! Focused probe for sharing high power-of-two constants across the two
//! quotient derivations in one hybrid Montgomery-slope transition.
//!
//! Default mode executes only the selected fifteen-power first kernel at the
//! exact G32-u5 frontier. The historical pre-Horner `--full-audit` is disabled:
//! its byte-splice oracle describes commit f7bb0c2 and cannot certify the new
//! quotient generator. Use `ed25519_slope_quotient_horner_probe` and
//! `ed25519_montgomery_slope_optimized_probe` for current focused checks.
//! Neither live mode builds a schedule, hash, scalar multiplication, or leaf.

use bitcoin::ScriptBuf;
use bitcoin_lab::{
    arithmetic::scriptint,
    curves::ed25519::{
        derive_streamed_relation_quotient,
        montgomery_slope::{
            chained_transition_derived_hybrid_u5_witness_items,
            chained_transition_derived_hybrid_witness_items,
            finalize_hybrid_persistent_shared_power_pool, first_transition_derived_witness_items,
            hybrid_output_state_items, initialize_hybrid_persistent_shared_power_pool,
            verify_chained_transition_derived_hybrid_state,
            verify_chained_transition_derived_hybrid_state_certified_u_next_u5,
            verify_chained_transition_derived_hybrid_state_certified_u_next_u5_terminal,
            verify_chained_transition_derived_hybrid_state_certified_u_next_u5_terminal_finalize_persistent_shared_power_pool,
            verify_chained_transition_derived_hybrid_state_certified_u_next_u5_terminal_persistent_shared_power_pool,
            verify_chained_transition_derived_hybrid_state_finalize_persistent_shared_power_pool,
            verify_chained_transition_derived_hybrid_state_initialize_persistent_shared_power_pool,
            verify_chained_transition_derived_hybrid_state_persistent_shared_power_pool,
            verify_chained_transition_derived_hybrid_state_shared_power_pool,
            verify_first_transition_derived_hybrid_state,
            verify_first_transition_derived_hybrid_state_shared_power_pool,
            CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX, CURVE_LOW_COEFFICIENT_ABS_MAX,
            FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX, HYBRID_FIRST_SHARED_POWER_BITS,
            HYBRID_STATE_ITEM_COUNT,
        },
        verify_streamed_relation_top_quotient,
    },
    fields::ed25519::u5_packed,
    support::{
        execution::{execute_raw_script_with_inputs_strict, ExecuteInfo},
        script::{script, Script, ScriptCompilation},
    },
};
use num_bigint::BigUint;

const FIELD_DIGIT_COUNT: usize = 51;
const LOW_QUOTIENT_COEFFICIENT_COUNT: usize = 5;
const NEGATIVE_NINETEEN_INVERSE_MOD_2POW22_23: u32 = 1_324_517;
const PRESERVED_PROBE_ITEMS: usize = 712;
const EXPECTED_EPHEMERAL_TWO_PHASE_SAVING: usize = 18_265;
const EXPECTED_PERSISTENT_TWO_PHASE_SAVING: usize = 19_301;
const EXPECTED_SPLIT_PERSISTENT_TWO_PHASE_SAVING: usize = 19_212;
const EXPECTED_FUSED_SPLIT_PERSISTENT_SAVING: usize = 19_365;
const EXPECTED_SELECTED_FIRST_KERNEL_POLICY_BYTES: usize = 33_409;
const EXPECTED_SELECTED_FIRST_LOCAL_PEAK: usize = 204;
const EXPECTED_SELECTED_FIRST_G32_PEAK: usize = 991;

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
        "shared-constant hybrid transition failed: {execution}"
    );
    assert_eq!(execution.final_stack.len(), expected.len());
    for (index, item) in expected.iter().enumerate() {
        assert_eq!(execution.final_stack.get(index), *item);
    }
}

fn assert_terminal(execution: &ExecuteInfo) {
    assert!(
        execution.error.is_none(),
        "shared-constant terminal transition failed: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);
    assert_eq!(execution.final_stack.get(0), vec![1]);
}

fn push_shared_constant_pool(shared_bits: &[usize]) -> Script {
    assert!(shared_bits.iter().all(|bit| (2..=30).contains(bit)));
    assert!(shared_bits.windows(2).all(|pair| pair[0] < pair[1]));
    if shared_bits.is_empty() {
        return Script::new("empty shared constant pool");
    }
    script! {
        { 1u32 << shared_bits[0] }
        for pair in shared_bits.windows(2) {
            { push_next_shared_power(pair[0], pair[1]) }
        }
    }
}

fn push_next_shared_power(previous_bit: usize, next_bit: usize) -> Script {
    let gap = next_bit - previous_bit;
    let addition_chain_bytes = 1 + 2 * gap;
    let literal_bytes = constant_literal_bytes(next_bit);
    if addition_chain_bytes < literal_bytes {
        script! {
            OP_DUP
            for _ in 0..gap { OP_DUP OP_ADD }
        }
    } else {
        script! { { 1u32 << next_bit } }
    }
}

fn power_access_counts(
    signed_width: usize,
    low_coefficient_abs_max: &[i64; LOW_QUOTIENT_COEFFICIENT_COUNT],
) -> [[usize; 2]; 31] {
    let mut counts = [[0usize; 2]; 31];
    let mut add = |bit: usize, items_above_pool: usize| {
        assert!(bit <= 30);
        assert!(items_above_pool == 1 || items_above_pool == 2);
        counts[bit][items_above_pool - 1] += 1;
    };
    for (coefficient, max_abs) in low_coefficient_abs_max.iter().copied().enumerate() {
        let width = signed_width - 5 * coefficient;
        let input_bits = i64::BITS as usize - max_abs.leading_zeros() as usize;
        for bit in width..input_bits {
            add(bit, 1);
        }
    }
    for bit in signed_width..=signed_width + 2 {
        add(bit, 1);
    }
    add(signed_width, 1);
    for bit in signed_width..signed_width + 8 {
        add(bit, 2);
        add(bit, 2);
    }
    for bit in signed_width..signed_width + 5 {
        add(bit, 1);
    }
    add(signed_width - 1, 2);
    add(signed_width, 1);
    counts
}

#[derive(Clone, Copy, Debug)]
enum PoolPositionClass {
    ExpensiveForBoth,
    ExpensiveForTwoItemOnly,
    CheapForBoth,
}

fn pool_position_class(pool_size: usize, position: usize) -> PoolPositionClass {
    assert!(pool_size <= 21);
    assert!(position < pool_size);
    if pool_size <= 15 {
        PoolPositionClass::CheapForBoth
    } else if position < pool_size - 16 {
        PoolPositionClass::ExpensiveForBoth
    } else if position == pool_size - 16 {
        PoolPositionClass::ExpensiveForTwoItemOnly
    } else {
        PoolPositionClass::CheapForBoth
    }
}

fn constant_literal_bytes(bit: usize) -> usize {
    script! { { 1u32 << bit } }.compile_with_policy().len()
}

fn candidate_access_score(
    bit: usize,
    position_class: PoolPositionClass,
    relation_profiles: &[([[usize; 2]; 31], usize)],
) -> i64 {
    let literal_bytes = constant_literal_bytes(bit);
    let [one_item_lookup_bytes, two_item_lookup_bytes] = match position_class {
        PoolPositionClass::ExpensiveForBoth => [3usize, 3usize],
        PoolPositionClass::ExpensiveForTwoItemOnly => [2usize, 3usize],
        PoolPositionClass::CheapForBoth => [2usize, 2usize],
    };
    let access_saving = relation_profiles
        .iter()
        .map(|(counts, multiplicity)| {
            i64::try_from(*multiplicity).expect("small multiplicity fits i64")
                * (i64::try_from(counts[bit][0]).expect("small access count fits i64")
                    * (i64::try_from(literal_bytes).unwrap()
                        - i64::try_from(one_item_lookup_bytes).unwrap())
                    + i64::try_from(counts[bit][1]).expect("small access count fits i64")
                        * (i64::try_from(literal_bytes).unwrap()
                            - i64::try_from(two_item_lookup_bytes).unwrap()))
        })
        .sum::<i64>();
    access_saving
}

#[derive(Clone, Debug)]
struct PoolSelection {
    score: i64,
    bits: Vec<usize>,
}

/// Exact ordered-subset optimizer. Constants are ascending on stack so an
/// adjacent next power can be built as `DUP DUP ADD`; a gap uses whichever is
/// smaller of repeated doubling and a fresh literal push.
fn best_pool_bits(pool_size: usize, relation_profiles: &[([[usize; 2]; 31], usize)]) -> Vec<usize> {
    assert!((1..=21).contains(&pool_size));
    let mut states = vec![vec![None::<PoolSelection>; 31]; pool_size + 1];
    for bit in 2..=30 {
        for selected_count in (1..=pool_size).rev() {
            let class = pool_position_class(pool_size, selected_count - 1);
            let access_score = candidate_access_score(bit, class, relation_profiles);
            let mut candidate = if selected_count == 1 {
                Some(PoolSelection {
                    score: access_score
                        - i64::try_from(constant_literal_bytes(bit))
                            .expect("constant push length fits i64"),
                    bits: vec![bit],
                })
            } else {
                None
            };
            if selected_count > 1 {
                for previous_bit in 2..bit {
                    let Some(previous) = &states[selected_count - 1][previous_bit] else {
                        continue;
                    };
                    let gap = bit - previous_bit;
                    let setup_increment = constant_literal_bytes(bit).min(1 + 2 * gap);
                    let score = previous.score + access_score
                        - i64::try_from(setup_increment).expect("setup increment fits i64");
                    if candidate
                        .as_ref()
                        .map_or(true, |current| score > current.score)
                    {
                        let mut bits = previous.bits.clone();
                        bits.push(bit);
                        candidate = Some(PoolSelection { score, bits });
                    }
                }
            }
            if let Some(candidate) = candidate {
                let slot = &mut states[selected_count][bit];
                if slot
                    .as_ref()
                    .map_or(true, |current| candidate.score > current.score)
                {
                    *slot = Some(candidate);
                }
            }
        }
    }
    states[pool_size]
        .iter()
        .filter_map(Option::as_ref)
        .max_by_key(|selection| selection.score)
        .expect("enough candidate powers exist for requested pool size")
        .bits
        .clone()
}

/// Copy `2^bit`. The pool is low-to-high, and `items_above_pool` counts all
/// live values above its five entries before the selector is pushed.
fn copy_power(bit: usize, items_above_pool: usize, shared_bits: &[usize]) -> Script {
    if let Some(position) = shared_bits.iter().position(|candidate| *candidate == bit) {
        let depth = items_above_pool + shared_bits.len() - 1 - position;
        script! { { depth as u32 } OP_PICK }
    } else {
        script! { { 1u32 << bit } }
    }
}

fn subtract_power_if_at_least(
    bit: usize,
    items_above_pool: usize,
    shared_bits: &[usize],
) -> Script {
    script! {
        { copy_power(bit, items_above_pool, shared_bits) }
        OP_2DUP OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
    }
}

fn signed_low_remainder(width: usize, max_abs: i64, shared_bits: &[usize]) -> Script {
    assert!((1..=30).contains(&width));
    assert!(max_abs > 0);
    let input_bits = i64::BITS as usize - max_abs.leading_zeros() as usize;
    assert!(input_bits <= 31);
    script! {
        OP_DUP 0 OP_LESSTHAN
        OP_DUP OP_TOALTSTACK
        OP_IF OP_NEGATE OP_ENDIF
        for bit in (width..input_bits).rev() {
            { subtract_power_if_at_least(bit, 1, shared_bits) }
        }
        OP_FROMALTSTACK OP_IF OP_NEGATE OP_ENDIF
    }
}

fn reduce_signed_five_term_sum(width: usize, shared_bits: &[usize]) -> Script {
    script! {
        OP_DUP 0 OP_LESSTHAN
        OP_DUP OP_TOALTSTACK
        OP_IF OP_NEGATE OP_ENDIF
        for bit in (width..=width + 2).rev() {
            { subtract_power_if_at_least(bit, 1, shared_bits) }
        }
        OP_FROMALTSTACK
        OP_IF
            OP_DUP OP_NOT OP_NOT OP_IF
                { copy_power(width, 1, shared_bits) }
                OP_SWAP OP_SUB
            OP_ENDIF
        OP_ENDIF
    }
}

fn reduce_nonnegative_factor(
    width: usize,
    factor: u32,
    items_above_pool: usize,
    shared_bits: &[usize],
) -> Script {
    assert!(factor > 0);
    let high_bits = if factor == 1 {
        0
    } else {
        (u32::BITS - (factor - 1).leading_zeros()) as usize
    };
    script! {
        for bit in (width..width + high_bits).rev() {
            { subtract_power_if_at_least(bit, items_above_pool, shared_bits) }
        }
    }
}

fn multiply_negative_nineteen_inverse(width: usize, shared_bits: &[usize]) -> Script {
    assert!(width == 22 || width == 23);
    assert_eq!(
        (233u32 * 196 + 5) * 29,
        NEGATIVE_NINETEEN_INVERSE_MOD_2POW22_23
    );
    script! {
        OP_DUP
        { scriptint::mul_by_constant(233) }
        { reduce_nonnegative_factor(width, 233, 2, shared_bits) }

        { scriptint::mul_by_constant(196) }
        1 OP_PICK
        { scriptint::mul_by_constant(5) }
        OP_ADD
        { reduce_nonnegative_factor(width, 201, 2, shared_bits) }

        OP_NIP
        { scriptint::mul_by_constant(29) }
        { reduce_nonnegative_factor(width, 29, 1, shared_bits) }
    }
}

/// `h[50..0] | pool -> h[50..0] | pool | q`.
fn derive_quotient_using_shared_pool(
    signed_width: usize,
    low_coefficient_abs_max: &[i64; LOW_QUOTIENT_COEFFICIENT_COUNT],
    shared_bits: &[usize],
) -> Script {
    assert!(signed_width == 22 || signed_width == 23);
    script! {
        for coefficient in 0..LOW_QUOTIENT_COEFFICIENT_COUNT {
            { (coefficient + shared_bits.len()) as u32 } OP_PICK
            { signed_low_remainder(
                signed_width - 5 * coefficient,
                low_coefficient_abs_max[coefficient],
                shared_bits,
            ) }
            OP_TOALTSTACK
        }

        OP_FROMALTSTACK
        for _coefficient in (0..LOW_QUOTIENT_COEFFICIENT_COUNT - 1).rev() {
            for _ in 0..5 { OP_DUP OP_ADD }
            OP_FROMALTSTACK OP_ADD
        }
        { reduce_signed_five_term_sum(signed_width, shared_bits) }
        { multiply_negative_nineteen_inverse(signed_width, shared_bits) }

        OP_DUP
        { copy_power(signed_width - 1, 2, shared_bits) }
        OP_GREATERTHANOREQUAL
        OP_IF
            { copy_power(signed_width, 1, shared_bits) }
            OP_SUB
        OP_ENDIF
    }
}

/// Verify `H=q*p` while leaving the five constants as the only output.
/// Input is `h[50..0] | pool | q`.
fn verify_relation_retaining_shared_pool(shared_constant_count: usize) -> Script {
    script! {
        OP_DUP
        for coefficient in (1..FIELD_DIGIT_COUNT).rev() {
            { (coefficient + 2 + shared_constant_count) as u32 } OP_ROLL
            OP_SWAP
            { scriptint::mul_by_constant(32) }
            OP_SWAP OP_SUB
        }

        OP_TOALTSTACK
        OP_DUP { scriptint::mul_by_constant(19) }
        { (shared_constant_count + 2) as u32 } OP_ROLL
        OP_ADD
        OP_FROMALTSTACK { scriptint::mul_by_constant(32) }
        OP_NUMEQUALVERIFY
        OP_DROP
    }
}

fn park_shared_pool(shared_constant_count: usize) -> Script {
    script! {
        for _ in 0..shared_constant_count { OP_TOALTSTACK }
    }
}

fn restore_shared_pool(shared_constant_count: usize) -> Script {
    script! {
        for _ in 0..shared_constant_count { OP_FROMALTSTACK }
    }
}

fn drop_shared_pool(shared_constant_count: usize) -> Script {
    script! {
        for _ in 0..shared_constant_count / 2 { OP_2DROP }
        if shared_constant_count % 2 != 0 { OP_DROP }
    }
}

fn first_relation_with_pool(
    signed_width: usize,
    bounds: &[i64; LOW_QUOTIENT_COEFFICIENT_COUNT],
    shared_bits: &[usize],
) -> ScriptBuf {
    script! {
        { push_shared_constant_pool(shared_bits) }
        { derive_quotient_using_shared_pool(signed_width, bounds, shared_bits) }
        { verify_relation_retaining_shared_pool(shared_bits.len()) }
        { park_shared_pool(shared_bits.len()) }
    }
    .compile_with_policy()
}

fn second_relation_with_pool(
    signed_width: usize,
    bounds: &[i64; LOW_QUOTIENT_COEFFICIENT_COUNT],
    shared_bits: &[usize],
) -> ScriptBuf {
    script! {
        { restore_shared_pool(shared_bits.len()) }
        { derive_quotient_using_shared_pool(signed_width, bounds, shared_bits) }
        { verify_relation_retaining_shared_pool(shared_bits.len()) }
        { drop_shared_pool(shared_bits.len()) }
    }
    .compile_with_policy()
}

/// One relation when the five constants remain parked below unrelated local
/// alt-stack temporaries between transition kernels.
fn globally_hoisted_relation(
    signed_width: usize,
    bounds: &[i64; LOW_QUOTIENT_COEFFICIENT_COUNT],
    shared_bits: &[usize],
) -> ScriptBuf {
    script! {
        { restore_shared_pool(shared_bits.len()) }
        { derive_quotient_using_shared_pool(signed_width, bounds, shared_bits) }
        { verify_relation_retaining_shared_pool(shared_bits.len()) }
        { park_shared_pool(shared_bits.len()) }
    }
    .compile_with_policy()
}

fn independent_relation_with_pool(
    signed_width: usize,
    bounds: &[i64; LOW_QUOTIENT_COEFFICIENT_COUNT],
    shared_bits: &[usize],
) -> ScriptBuf {
    script! {
        { push_shared_constant_pool(shared_bits) }
        { derive_quotient_using_shared_pool(signed_width, bounds, shared_bits) }
        { verify_relation_retaining_shared_pool(shared_bits.len()) }
        { drop_shared_pool(shared_bits.len()) }
    }
    .compile_with_policy()
}

fn occurrences(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    assert!(!needle.is_empty());
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(index, candidate)| (candidate == needle).then_some(index))
        .collect()
}

fn replace_once_from(
    bytes: &mut Vec<u8>,
    needle: &[u8],
    replacement: &[u8],
    start: usize,
) -> usize {
    let relative = bytes[start..]
        .windows(needle.len())
        .position(|candidate| candidate == needle)
        .expect("baseline quotient fragment is present exactly where expected");
    let index = start + relative;
    bytes.splice(index..index + needle.len(), replacement.iter().copied());
    index + replacement.len()
}

fn replace_relation_pair(
    baseline_kernel: ScriptBuf,
    first_needle: &[u8],
    first_replacement: &[u8],
    second_needle: &[u8],
    second_replacement: &[u8],
) -> ScriptBuf {
    let mut bytes = baseline_kernel.into_bytes();
    let after_first = replace_once_from(&mut bytes, first_needle, first_replacement, 0);
    replace_once_from(&mut bytes, second_needle, second_replacement, after_first);
    let transformed = ScriptBuf::from_bytes(bytes);
    // Apply the centralized whole-script policy too. These transition
    // kernels exceed 32 KiB, so this is byte-for-byte CompileOptions::NONE.
    Script::new("shared-constant transformed hybrid slope kernel")
        .push_script(transformed)
        .compile_with_policy()
}

fn wrap_globally_hoisted_kernel(kernel: ScriptBuf, shared_bits: &[usize]) -> ScriptBuf {
    let setup = script! {
        { push_shared_constant_pool(shared_bits) }
        { park_shared_pool(shared_bits.len()) }
    }
    .compile_with_policy();
    let cleanup = script! {
        { restore_shared_pool(shared_bits.len()) }
        { drop_shared_pool(shared_bits.len()) }
    }
    .compile_with_policy();
    script! {
        { setup }
        { kernel }
        { cleanup }
    }
    .compile_with_policy()
}

fn run_selected_first_kernel_probe() {
    assert_eq!(
        HYBRID_FIRST_SHARED_POWER_BITS,
        [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
    );
    let p = bitcoin_lab::fields::ed25519::u5_balanced_table::modulus();
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

    let preserved = 787usize;
    let mut witness = (0..preserved)
        .map(|index| scriptnum_item(1 + (index % 97) as i64))
        .collect::<Vec<_>>();
    let mut expected = witness.clone();
    witness.extend(first_transition_derived_witness_items(
        &u_initial,
        &v_initial,
        &u_prev,
        &lambda_prev,
        &a_prev,
        &b_prev,
    ));
    expected.extend(hybrid_output_state_items(
        &u_prev,
        &lambda_prev,
        &a_prev,
        &b_prev,
    ));
    let kernel = verify_first_transition_derived_hybrid_state_shared_power_pool(preserved as u32)
        .compile_with_policy();
    assert_eq!(kernel.len(), EXPECTED_SELECTED_FIRST_KERNEL_POLICY_BYTES);
    let execution = execute_raw_script_with_inputs_strict(kernel.to_bytes(), witness);
    assert_output(&execution, &expected);
    assert_eq!(
        execution.stats.max_nb_stack_items,
        EXPECTED_SELECTED_FIRST_G32_PEAK
    );
    assert_eq!(
        execution.stats.max_nb_stack_items - preserved,
        EXPECTED_SELECTED_FIRST_LOCAL_PEAK
    );

    println!("model=ed25519_montgomery_slope_shared_constants_probe");
    println!("mode=selected-first-kernel");
    println!("evidence=locally-reproduced");
    println!("execution_class=unclassified");
    println!("shared_constant_bits=16,17,18,19,20,21,22,23,24,25,26,27,28,29,30");
    println!("shared_constant_items=15");
    println!("shared_constants_are_script_authored=true");
    println!("auxiliary_hint_items_per_invocation=0");
    println!("witness_items_added=0");
    println!("kernel_policy_bytes={}", kernel.len());
    println!("preserved_items={preserved}");
    println!("kernel_local_strict_combined_peak={EXPECTED_SELECTED_FIRST_LOCAL_PEAK}");
    println!(
        "g32_u5_response_t0_strict_combined_peak={}",
        execution.stats.max_nb_stack_items
    );
    println!(
        "headroom_below_1000={}",
        1_000 - execution.stats.max_nb_stack_items
    );
    println!("full_audit_performed=false");
    println!("whole_scalar_leaf_built=false");
    println!("whole_scalar_leaf_executed=false");
}

fn run_full_audit() {
    // The remainder is retained as a historical research artifact. It
    // substitutes pre-Horner byte sequences and must not run against current
    // production generators. Keep the old entry point informative and cheap.
    if std::env::args().nth(1).as_deref() == Some("--full-audit") {
        println!("model=ed25519_montgomery_slope_shared_constants_historical_audit");
        println!("status=superseded-disabled");
        println!("historical_source_commit=f7bb0c29235b5a2fddefb6748888394ff5c1186a");
        println!("reason=pre-Horner byte-splice oracle no longer matches production");
        println!("replacement_quotient_probe=ed25519_slope_quotient_horner_probe");
        println!("replacement_kernel_probe=ed25519_montgomery_slope_optimized_probe");
        println!("whole_scalar_leaf_built=false");
        println!("whole_scalar_leaf_executed=false");
        return;
    }
    let shared_bits = HYBRID_FIRST_SHARED_POWER_BITS.as_slice();
    assert_eq!(shared_bits, [23, 24, 25, 26]);

    let baseline_q22 = script! {
        { derive_streamed_relation_quotient(
            22,
            &FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
        ) }
        { verify_streamed_relation_top_quotient() }
    }
    .compile_with_policy();
    let baseline_q23 = script! {
        { derive_streamed_relation_quotient(
            23,
            &CURVE_LOW_COEFFICIENT_ABS_MAX,
        ) }
        { verify_streamed_relation_top_quotient() }
    }
    .compile_with_policy();
    let baseline_q23_chained = script! {
        { derive_streamed_relation_quotient(
            23,
            &CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
        ) }
        { verify_streamed_relation_top_quotient() }
    }
    .compile_with_policy();
    assert_eq!(baseline_q23, baseline_q23_chained);

    let q22_profile = power_access_counts(22, &FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX);
    let q23_profile = power_access_counts(23, &CURVE_LOW_COEFFICIENT_ABS_MAX);
    assert_eq!(
        q23_profile,
        power_access_counts(23, &CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX)
    );
    let first_profiles = [(q22_profile, 1usize), (q23_profile, 1usize)];
    let chained_profiles = [(q23_profile, 2usize)];
    let mut marginal_rows = Vec::new();
    for pool_size in 0..=21 {
        if pool_size == 0 {
            marginal_rows.push((pool_size, Vec::new(), 0usize, Vec::new(), 0usize));
            continue;
        }
        let first_bits = best_pool_bits(pool_size, &first_profiles);
        let chained_bits = best_pool_bits(pool_size, &chained_profiles);
        let first_saving = baseline_q22.len() + baseline_q23.len()
            - first_relation_with_pool(22, &FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX, &first_bits)
                .len()
            - second_relation_with_pool(23, &CURVE_LOW_COEFFICIENT_ABS_MAX, &first_bits).len();
        let chained_saving = 2 * baseline_q23.len()
            - first_relation_with_pool(
                23,
                &CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
                &chained_bits,
            )
            .len()
            - second_relation_with_pool(23, &CURVE_LOW_COEFFICIENT_ABS_MAX, &chained_bits).len();
        marginal_rows.push((
            pool_size,
            first_bits,
            first_saving,
            chained_bits,
            chained_saving,
        ));
    }
    let optimal_first_five = marginal_rows[5].1.clone();
    let optimal_first_five_saving = marginal_rows[5].2;
    let selected_first_four = marginal_rows[4].1.clone();
    let selected_first_four_saving = marginal_rows[4].2;
    let optimal_first_six = marginal_rows[6].1.clone();
    let later_best_pool_size = (1..=21)
        .max_by_key(|pool_size| marginal_rows[*pool_size].4)
        .expect("nonempty later-pool search");
    let later_pool_bits = marginal_rows[later_best_pool_size].3.clone();
    let later_first_q23 = first_relation_with_pool(
        23,
        &CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
        &later_pool_bits,
    );
    let later_second_q23 =
        second_relation_with_pool(23, &CURVE_LOW_COEFFICIENT_ABS_MAX, &later_pool_bits);
    let later_chained_saving =
        2 * baseline_q23.len() - later_first_q23.len() - later_second_q23.len();
    assert_eq!(later_chained_saving, marginal_rows[later_best_pool_size].4);
    assert_eq!(optimal_first_five, vec![23, 24, 25, 26, 27]);
    assert_eq!(optimal_first_five_saving, 224);
    assert_eq!(selected_first_four, shared_bits);
    assert_eq!(selected_first_four_saving, 187);
    assert_eq!(optimal_first_five_saving - selected_first_four_saving, 37);
    assert_eq!(later_best_pool_size, 16);
    assert_eq!(
        later_pool_bits,
        vec![15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
    );
    assert_eq!(later_chained_saving, 393);
    assert_eq!(
        selected_first_four_saving + 46 * later_chained_saving,
        EXPECTED_EPHEMERAL_TWO_PHASE_SAVING
    );

    // Secondary model: transition one uses an ephemeral pool because its
    // surrounding scheduler state already reaches 995 items. Starting at
    // transition two, one pool can remain on the alt stack across the final
    // 45 chained kernels. Candidate scoring charges all 90 relation accesses.
    let persistent_profiles = [(q23_profile, 2usize * 45)];
    let mut persistent_rows = Vec::new();
    for pool_size in 1..=21 {
        let bits = best_pool_bits(pool_size, &persistent_profiles);
        let middle = globally_hoisted_relation(23, &CURVE_LOW_COEFFICIENT_ABS_MAX, &bits);
        let gross_chained_saving = 2 * baseline_q23.len() - 2 * middle.len();
        let setup = script! {
            { push_shared_constant_pool(&bits) }
            { park_shared_pool(bits.len()) }
        }
        .compile_with_policy()
        .len();
        let cleanup = script! {
            { restore_shared_pool(bits.len()) }
            { drop_shared_pool(bits.len()) }
        }
        .compile_with_policy()
        .len();
        let one_pool_net = 45 * gross_chained_saving - setup - cleanup;
        let two_pool_net = 45 * gross_chained_saving - 2 * (setup + cleanup);
        persistent_rows.push((
            pool_size,
            bits,
            gross_chained_saving,
            setup,
            cleanup,
            one_pool_net,
            two_pool_net,
        ));
    }
    let persistent_best = persistent_rows
        .iter()
        .max_by_key(|row| row.5)
        .expect("nonempty persistent-pool search")
        .clone();
    let persistent_middle =
        globally_hoisted_relation(23, &CURVE_LOW_COEFFICIENT_ABS_MAX, &persistent_best.1);
    assert_eq!(persistent_best.0, 16);
    assert_eq!(persistent_best.1, later_pool_bits);
    assert_eq!(
        selected_first_four_saving + later_chained_saving + persistent_best.5,
        EXPECTED_PERSISTENT_TWO_PHASE_SAVING
    );
    assert_eq!(
        selected_first_four_saving + later_chained_saving + persistent_best.6,
        EXPECTED_SPLIT_PERSISTENT_TWO_PHASE_SAVING
    );

    let pooled_first_q22 =
        first_relation_with_pool(22, &FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX, shared_bits);
    let pooled_first_q23 =
        first_relation_with_pool(23, &CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX, shared_bits);
    let pooled_second_q23 =
        second_relation_with_pool(23, &CURVE_LOW_COEFFICIENT_ABS_MAX, shared_bits);
    let pooled_independent_q22 =
        independent_relation_with_pool(22, &FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX, shared_bits);
    let pooled_independent_q23 =
        independent_relation_with_pool(23, &CURVE_LOW_COEFFICIENT_ABS_MAX, shared_bits);
    let global_q22 =
        globally_hoisted_relation(22, &FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX, shared_bits);
    let global_q23 = globally_hoisted_relation(23, &CURVE_LOW_COEFFICIENT_ABS_MAX, shared_bits);

    let baseline_first = verify_first_transition_derived_hybrid_state(0).compile_with_policy();
    let baseline_chained = verify_chained_transition_derived_hybrid_state(0).compile_with_policy();
    let baseline_u5 =
        verify_chained_transition_derived_hybrid_state_certified_u_next_u5(0).compile_with_policy();
    let baseline_u5_terminal =
        verify_chained_transition_derived_hybrid_state_certified_u_next_u5_terminal(0)
            .compile_with_policy();
    assert_eq!(
        occurrences(baseline_first.as_bytes(), baseline_q22.as_bytes()).len(),
        1
    );
    assert_eq!(
        occurrences(baseline_first.as_bytes(), baseline_q23.as_bytes()).len(),
        1
    );
    assert_eq!(
        occurrences(baseline_chained.as_bytes(), baseline_q23.as_bytes()).len(),
        2
    );
    assert_eq!(
        occurrences(baseline_u5.as_bytes(), baseline_q23.as_bytes()).len(),
        2
    );
    assert_eq!(
        occurrences(baseline_u5_terminal.as_bytes(), baseline_q23.as_bytes()).len(),
        2
    );

    let pooled_first = replace_relation_pair(
        baseline_first.clone(),
        baseline_q22.as_bytes(),
        pooled_first_q22.as_bytes(),
        baseline_q23.as_bytes(),
        pooled_second_q23.as_bytes(),
    );
    let pooled_chained = replace_relation_pair(
        baseline_chained.clone(),
        baseline_q23.as_bytes(),
        pooled_first_q23.as_bytes(),
        baseline_q23.as_bytes(),
        pooled_second_q23.as_bytes(),
    );
    let pooled_u5 = replace_relation_pair(
        baseline_u5.clone(),
        baseline_q23.as_bytes(),
        pooled_first_q23.as_bytes(),
        baseline_q23.as_bytes(),
        pooled_second_q23.as_bytes(),
    );
    let pooled_u5_terminal = replace_relation_pair(
        baseline_u5_terminal.clone(),
        baseline_q23.as_bytes(),
        pooled_first_q23.as_bytes(),
        baseline_q23.as_bytes(),
        pooled_second_q23.as_bytes(),
    );
    let first_six_q22 = first_relation_with_pool(
        22,
        &FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
        &optimal_first_six,
    );
    let first_six_q23 =
        second_relation_with_pool(23, &CURVE_LOW_COEFFICIENT_ABS_MAX, &optimal_first_six);
    let pooled_first_six = replace_relation_pair(
        baseline_first.clone(),
        baseline_q22.as_bytes(),
        first_six_q22.as_bytes(),
        baseline_q23.as_bytes(),
        first_six_q23.as_bytes(),
    );
    let later_pooled_chained = replace_relation_pair(
        baseline_chained.clone(),
        baseline_q23.as_bytes(),
        later_first_q23.as_bytes(),
        baseline_q23.as_bytes(),
        later_second_q23.as_bytes(),
    );
    let later_pooled_u5 = replace_relation_pair(
        baseline_u5.clone(),
        baseline_q23.as_bytes(),
        later_first_q23.as_bytes(),
        baseline_q23.as_bytes(),
        later_second_q23.as_bytes(),
    );
    let later_pooled_u5_terminal = replace_relation_pair(
        baseline_u5_terminal.clone(),
        baseline_q23.as_bytes(),
        later_first_q23.as_bytes(),
        baseline_q23.as_bytes(),
        later_second_q23.as_bytes(),
    );
    let global_first = replace_relation_pair(
        baseline_first.clone(),
        baseline_q22.as_bytes(),
        global_q22.as_bytes(),
        baseline_q23.as_bytes(),
        global_q23.as_bytes(),
    );
    let global_chained = replace_relation_pair(
        baseline_chained.clone(),
        baseline_q23.as_bytes(),
        global_q23.as_bytes(),
        baseline_q23.as_bytes(),
        global_q23.as_bytes(),
    );
    let global_u5 = replace_relation_pair(
        baseline_u5.clone(),
        baseline_q23.as_bytes(),
        global_q23.as_bytes(),
        baseline_q23.as_bytes(),
        global_q23.as_bytes(),
    );
    let persistent_global_chained = replace_relation_pair(
        baseline_chained.clone(),
        baseline_q23.as_bytes(),
        persistent_middle.as_bytes(),
        baseline_q23.as_bytes(),
        persistent_middle.as_bytes(),
    );
    let persistent_global_u5 = replace_relation_pair(
        baseline_u5.clone(),
        baseline_q23.as_bytes(),
        persistent_middle.as_bytes(),
        baseline_q23.as_bytes(),
        persistent_middle.as_bytes(),
    );
    let persistent_global_u5_terminal = replace_relation_pair(
        baseline_u5_terminal.clone(),
        baseline_q23.as_bytes(),
        persistent_middle.as_bytes(),
        baseline_q23.as_bytes(),
        persistent_middle.as_bytes(),
    );
    let wrapped_global_first = wrap_globally_hoisted_kernel(global_first.clone(), shared_bits);
    let wrapped_global_chained = wrap_globally_hoisted_kernel(global_chained.clone(), shared_bits);
    let wrapped_global_u5 = wrap_globally_hoisted_kernel(global_u5.clone(), shared_bits);
    let wrapped_persistent_global_u5 =
        wrap_globally_hoisted_kernel(persistent_global_u5, &persistent_best.1);
    let wrapped_persistent_global_u5_terminal =
        wrap_globally_hoisted_kernel(persistent_global_u5_terminal.clone(), &persistent_best.1);

    // The production generators must serialize identically to this independent
    // byte-splice oracle. The production path itself is source-level only.
    let source_pooled_first =
        verify_first_transition_derived_hybrid_state_shared_power_pool(0).compile_with_policy();
    let source_pooled_chained =
        verify_chained_transition_derived_hybrid_state_shared_power_pool(0).compile_with_policy();
    let source_persistent_chained =
        verify_chained_transition_derived_hybrid_state_persistent_shared_power_pool(0)
            .compile_with_policy();
    let source_initialize_persistent_chained =
        verify_chained_transition_derived_hybrid_state_initialize_persistent_shared_power_pool(0)
            .compile_with_policy();
    let source_finalize_persistent_chained =
        verify_chained_transition_derived_hybrid_state_finalize_persistent_shared_power_pool(0)
            .compile_with_policy();
    let source_persistent_terminal =
        verify_chained_transition_derived_hybrid_state_certified_u_next_u5_terminal_persistent_shared_power_pool(0)
            .compile_with_policy();
    let source_finalize_persistent_terminal =
        verify_chained_transition_derived_hybrid_state_certified_u_next_u5_terminal_finalize_persistent_shared_power_pool(0)
            .compile_with_policy();
    assert_eq!(source_pooled_first, pooled_first);
    assert_eq!(source_pooled_chained, later_pooled_chained);
    assert_eq!(source_persistent_chained, persistent_global_chained);
    assert_eq!(source_persistent_terminal, persistent_global_u5_terminal);
    assert_eq!(initialize_hybrid_persistent_shared_power_pool().len(), 65);
    assert_eq!(finalize_hybrid_persistent_shared_power_pool().len(), 24);
    assert_eq!(source_initialize_persistent_chained.len(), 49_921);
    assert_eq!(source_persistent_chained.len(), 49_888);
    assert_eq!(source_finalize_persistent_chained.len(), 49_880);
    assert_eq!(source_persistent_terminal.len(), 45_187);
    assert_eq!(source_finalize_persistent_terminal.len(), 45_179);
    let source_initialize_saving =
        baseline_chained.len() - source_initialize_persistent_chained.len();
    let source_persistent_saving = baseline_chained.len() - source_persistent_chained.len();
    let source_finalize_saving = baseline_chained.len() - source_finalize_persistent_chained.len();
    let source_terminal_finalize_saving =
        baseline_u5_terminal.len() - source_finalize_persistent_terminal.len();
    let fused_split_persistent_saving = selected_first_four_saving
        + 2 * source_initialize_saving
        + 42 * source_persistent_saving
        + source_finalize_saving
        + source_terminal_finalize_saving;
    assert_eq!(source_initialize_saving, 385);
    assert_eq!(source_persistent_saving, 418);
    assert_eq!(source_finalize_saving, 426);
    assert_eq!(source_terminal_finalize_saving, 426);
    assert_eq!(
        fused_split_persistent_saving,
        EXPECTED_FUSED_SPLIT_PERSISTENT_SAVING
    );

    let p = bitcoin_lab::fields::ed25519::u5_balanced_table::modulus();
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

    let first_witness = first_transition_derived_witness_items(
        &u_initial,
        &v_initial,
        &u_prev,
        &lambda_prev,
        &a_prev,
        &b_prev,
    );
    let chained_witness = chained_transition_derived_hybrid_witness_items(
        &u_prev,
        &lambda_prev,
        &a_prev,
        &b_prev,
        &u_next,
        &lambda_next,
        &a_next,
        &b_next,
    );
    let u5_witness = chained_transition_derived_hybrid_u5_witness_items(
        &u_prev,
        &lambda_prev,
        &a_prev,
        &b_prev,
        &u_next,
        &lambda_next,
        &a_next,
        &b_next,
    );
    let first_expected = hybrid_output_state_items(&u_prev, &lambda_prev, &a_prev, &b_prev);
    let expected = hybrid_output_state_items(&u_next, &lambda_next, &a_next, &b_next);
    assert_eq!(first_expected.len(), HYBRID_STATE_ITEM_COUNT);
    assert_eq!(expected.len(), HYBRID_STATE_ITEM_COUNT);

    let baseline_first_execution =
        execute_raw_script_with_inputs_strict(baseline_first.to_bytes(), first_witness.clone());
    let pooled_first_execution =
        execute_raw_script_with_inputs_strict(pooled_first.to_bytes(), first_witness);
    let global_first_execution = execute_raw_script_with_inputs_strict(
        wrapped_global_first.to_bytes(),
        first_transition_derived_witness_items(
            &u_initial,
            &v_initial,
            &u_prev,
            &lambda_prev,
            &a_prev,
            &b_prev,
        ),
    );
    let pooled_first_six_execution = execute_raw_script_with_inputs_strict(
        pooled_first_six.to_bytes(),
        first_transition_derived_witness_items(
            &u_initial,
            &v_initial,
            &u_prev,
            &lambda_prev,
            &a_prev,
            &b_prev,
        ),
    );
    assert_output(&baseline_first_execution, &first_expected);
    assert_output(&pooled_first_execution, &first_expected);
    assert_output(&global_first_execution, &first_expected);
    assert_output(&pooled_first_six_execution, &first_expected);

    let baseline_execution =
        execute_raw_script_with_inputs_strict(baseline_chained.to_bytes(), chained_witness.clone());
    let pooled_execution =
        execute_raw_script_with_inputs_strict(pooled_chained.to_bytes(), chained_witness.clone());
    let global_execution = execute_raw_script_with_inputs_strict(
        wrapped_global_chained.to_bytes(),
        chained_witness.clone(),
    );
    assert_output(&baseline_execution, &expected);
    assert_output(&pooled_execution, &expected);
    assert_output(&global_execution, &expected);

    let baseline_u5_execution =
        execute_raw_script_with_inputs_strict(baseline_u5.to_bytes(), u5_witness.clone());
    let pooled_u5_execution =
        execute_raw_script_with_inputs_strict(pooled_u5.to_bytes(), u5_witness.clone());
    let global_u5_execution = execute_raw_script_with_inputs_strict(
        wrapped_global_u5.to_bytes(),
        chained_transition_derived_hybrid_u5_witness_items(
            &u_prev,
            &lambda_prev,
            &a_prev,
            &b_prev,
            &u_next,
            &lambda_next,
            &a_next,
            &b_next,
        ),
    );
    let persistent_global_u5_execution = execute_raw_script_with_inputs_strict(
        wrapped_persistent_global_u5.to_bytes(),
        chained_transition_derived_hybrid_u5_witness_items(
            &u_prev,
            &lambda_prev,
            &a_prev,
            &b_prev,
            &u_next,
            &lambda_next,
            &a_next,
            &b_next,
        ),
    );
    let baseline_u5_terminal_execution = execute_raw_script_with_inputs_strict(
        baseline_u5_terminal.to_bytes(),
        chained_transition_derived_hybrid_u5_witness_items(
            &u_prev,
            &lambda_prev,
            &a_prev,
            &b_prev,
            &u_next,
            &lambda_next,
            &a_next,
            &b_next,
        ),
    );
    let pooled_u5_terminal_execution = execute_raw_script_with_inputs_strict(
        pooled_u5_terminal.to_bytes(),
        chained_transition_derived_hybrid_u5_witness_items(
            &u_prev,
            &lambda_prev,
            &a_prev,
            &b_prev,
            &u_next,
            &lambda_next,
            &a_next,
            &b_next,
        ),
    );
    let later_pooled_u5_terminal_execution = execute_raw_script_with_inputs_strict(
        later_pooled_u5_terminal.to_bytes(),
        chained_transition_derived_hybrid_u5_witness_items(
            &u_prev,
            &lambda_prev,
            &a_prev,
            &b_prev,
            &u_next,
            &lambda_next,
            &a_next,
            &b_next,
        ),
    );
    let persistent_global_u5_terminal_execution = execute_raw_script_with_inputs_strict(
        wrapped_persistent_global_u5_terminal.to_bytes(),
        chained_transition_derived_hybrid_u5_witness_items(
            &u_prev,
            &lambda_prev,
            &a_prev,
            &b_prev,
            &u_next,
            &lambda_next,
            &a_next,
            &b_next,
        ),
    );
    let source_initialize_then_cleanup = script! {
        { source_initialize_persistent_chained.clone() }
        { finalize_hybrid_persistent_shared_power_pool() }
    }
    .compile_with_policy();
    let source_initialize_execution = execute_raw_script_with_inputs_strict(
        source_initialize_then_cleanup.to_bytes(),
        chained_witness.clone(),
    );
    let source_setup_then_finalize = script! {
        { initialize_hybrid_persistent_shared_power_pool() }
        { source_finalize_persistent_chained.clone() }
    }
    .compile_with_policy();
    let source_finalize_execution = execute_raw_script_with_inputs_strict(
        source_setup_then_finalize.to_bytes(),
        chained_witness.clone(),
    );
    let source_setup_then_terminal_finalize = script! {
        { initialize_hybrid_persistent_shared_power_pool() }
        { source_finalize_persistent_terminal.clone() }
    }
    .compile_with_policy();
    let source_terminal_finalize_execution = execute_raw_script_with_inputs_strict(
        source_setup_then_terminal_finalize.to_bytes(),
        chained_transition_derived_hybrid_u5_witness_items(
            &u_prev,
            &lambda_prev,
            &a_prev,
            &b_prev,
            &u_next,
            &lambda_next,
            &a_next,
            &b_next,
        ),
    );
    assert_output(&baseline_u5_execution, &expected);
    assert_output(&pooled_u5_execution, &expected);
    assert_output(&global_u5_execution, &expected);
    assert_output(&persistent_global_u5_execution, &expected);
    assert_terminal(&baseline_u5_terminal_execution);
    assert_terminal(&pooled_u5_terminal_execution);
    assert_terminal(&later_pooled_u5_terminal_execution);
    assert_terminal(&persistent_global_u5_terminal_execution);
    assert_output(&source_initialize_execution, &expected);
    assert_output(&source_finalize_execution, &expected);
    assert_terminal(&source_terminal_finalize_execution);
    let later_pooled_execution = execute_raw_script_with_inputs_strict(
        later_pooled_chained.to_bytes(),
        chained_transition_derived_hybrid_witness_items(
            &u_prev,
            &lambda_prev,
            &a_prev,
            &b_prev,
            &u_next,
            &lambda_next,
            &a_next,
            &b_next,
        ),
    );
    let later_pooled_u5_execution =
        execute_raw_script_with_inputs_strict(later_pooled_u5.to_bytes(), u5_witness.clone());
    assert_output(&later_pooled_execution, &expected);
    assert_output(&later_pooled_u5_execution, &expected);

    // Keep the malformed field canonical while breaking both exact
    // relations. Constant sharing must not weaken the terminal recurrence.
    let malformed_u = (&u_next + BigUint::from(1u8)) % &p;
    let mut malformed = chained_transition_derived_hybrid_witness_items(
        &u_prev,
        &lambda_prev,
        &a_prev,
        &b_prev,
        &u_next,
        &lambda_next,
        &a_next,
        &b_next,
    );
    malformed[..u5_packed::PACKED_WORD_COUNT]
        .clone_from_slice(&u5_packed::packed_value_witness_items(&malformed_u));
    let malformed_execution =
        execute_raw_script_with_inputs_strict(later_pooled_chained.to_bytes(), malformed);
    assert!(
        malformed_execution.error.is_some(),
        "shared constants allowed a malformed canonical u_next"
    );

    let mut preserving_witness = (0..PRESERVED_PROBE_ITEMS)
        .map(|index| scriptnum_item(1 + (index % 97) as i64))
        .collect::<Vec<_>>();
    preserving_witness.extend(chained_witness);
    let baseline_preserved =
        verify_chained_transition_derived_hybrid_state(PRESERVED_PROBE_ITEMS as u32)
            .compile_with_policy();
    let pooled_preserved = replace_relation_pair(
        baseline_preserved.clone(),
        baseline_q23.as_bytes(),
        pooled_first_q23.as_bytes(),
        baseline_q23.as_bytes(),
        pooled_second_q23.as_bytes(),
    );
    let pooled_preserved_execution =
        execute_raw_script_with_inputs_strict(pooled_preserved.to_bytes(), preserving_witness);
    assert!(pooled_preserved_execution.error.is_none());
    let later_baseline_u5_preserved =
        verify_chained_transition_derived_hybrid_state_certified_u_next_u5(
            PRESERVED_PROBE_ITEMS as u32,
        )
        .compile_with_policy();
    let later_pooled_u5_preserved = replace_relation_pair(
        later_baseline_u5_preserved,
        baseline_q23.as_bytes(),
        later_first_q23.as_bytes(),
        baseline_q23.as_bytes(),
        later_second_q23.as_bytes(),
    );
    let mut later_u5_preserving_witness = (0..PRESERVED_PROBE_ITEMS)
        .map(|index| scriptnum_item(1 + (index % 97) as i64))
        .collect::<Vec<_>>();
    later_u5_preserving_witness.extend(u5_witness);
    let later_pooled_u5_preserved_execution = execute_raw_script_with_inputs_strict(
        later_pooled_u5_preserved.to_bytes(),
        later_u5_preserving_witness,
    );
    assert!(later_pooled_u5_preserved_execution.error.is_none());

    // Exact production G32-u5 response peaks at the three tight lifecycle
    // boundaries. Preserved prefix items remain live below each local input.
    let mut first_t0_witness = (0..787)
        .map(|index| scriptnum_item(1 + (index % 97) as i64))
        .collect::<Vec<_>>();
    first_t0_witness.extend(first_transition_derived_witness_items(
        &u_initial,
        &v_initial,
        &u_prev,
        &lambda_prev,
        &a_prev,
        &b_prev,
    ));
    let first_t0_execution = execute_raw_script_with_inputs_strict(
        verify_first_transition_derived_hybrid_state_shared_power_pool(787)
            .compile_with_policy()
            .to_bytes(),
        first_t0_witness,
    );
    assert!(first_t0_execution.error.is_none());
    assert_eq!(first_t0_execution.stats.max_nb_stack_items, 999);

    let mut initialize_t1_witness = (0..771)
        .map(|index| scriptnum_item(1 + (index % 97) as i64))
        .collect::<Vec<_>>();
    initialize_t1_witness.extend(chained_transition_derived_hybrid_witness_items(
        &u_prev,
        &lambda_prev,
        &a_prev,
        &b_prev,
        &u_next,
        &lambda_next,
        &a_next,
        &b_next,
    ));
    let initialize_t1_script = script! {
        { verify_chained_transition_derived_hybrid_state_initialize_persistent_shared_power_pool(771) }
        { finalize_hybrid_persistent_shared_power_pool() }
    }
    .compile_with_policy();
    let initialize_t1_execution = execute_raw_script_with_inputs_strict(
        initialize_t1_script.to_bytes(),
        initialize_t1_witness,
    );
    assert!(initialize_t1_execution.error.is_none());
    assert_eq!(initialize_t1_execution.stats.max_nb_stack_items, 995);

    let mut persistent_t2_witness = (0..754)
        .map(|index| scriptnum_item(1 + (index % 97) as i64))
        .collect::<Vec<_>>();
    persistent_t2_witness.extend(chained_transition_derived_hybrid_witness_items(
        &u_prev,
        &lambda_prev,
        &a_prev,
        &b_prev,
        &u_next,
        &lambda_next,
        &a_next,
        &b_next,
    ));
    let persistent_t2_script = script! {
        { initialize_hybrid_persistent_shared_power_pool() }
        { verify_chained_transition_derived_hybrid_state_persistent_shared_power_pool(754) }
        { finalize_hybrid_persistent_shared_power_pool() }
    }
    .compile_with_policy();
    let persistent_t2_execution = execute_raw_script_with_inputs_strict(
        persistent_t2_script.to_bytes(),
        persistent_t2_witness,
    );
    assert!(persistent_t2_execution.error.is_none());
    assert_eq!(persistent_t2_execution.stats.max_nb_stack_items, 994);

    let setup_bytes = push_shared_constant_pool(shared_bits)
        .compile_with_policy()
        .len();
    let park_bytes = park_shared_pool(shared_bits.len())
        .compile_with_policy()
        .len();
    let restore_bytes = restore_shared_pool(shared_bits.len())
        .compile_with_policy()
        .len();
    let drop_bytes = drop_shared_pool(shared_bits.len())
        .compile_with_policy()
        .len();
    let global_setup_bytes = script! {
        { push_shared_constant_pool(shared_bits) }
        { park_shared_pool(shared_bits.len()) }
    }
    .compile_with_policy()
    .len();
    let global_cleanup_bytes = script! {
        { restore_shared_pool(shared_bits.len()) }
        { drop_shared_pool(shared_bits.len()) }
    }
    .compile_with_policy()
    .len();
    let baseline_verifier_bytes = verify_streamed_relation_top_quotient()
        .compile_with_policy()
        .len();
    let pooled_verifier_bytes = verify_relation_retaining_shared_pool(shared_bits.len())
        .compile_with_policy()
        .len();
    let baseline_derive22_bytes =
        derive_streamed_relation_quotient(22, &FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX)
            .compile_with_policy()
            .len();
    let baseline_derive23_bytes =
        derive_streamed_relation_quotient(23, &CURVE_LOW_COEFFICIENT_ABS_MAX)
            .compile_with_policy()
            .len();
    let pooled_derive22_bytes = derive_quotient_using_shared_pool(
        22,
        &FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
        shared_bits,
    )
    .compile_with_policy()
    .len();
    let pooled_derive23_bytes =
        derive_quotient_using_shared_pool(23, &CURVE_LOW_COEFFICIENT_ABS_MAX, shared_bits)
            .compile_with_policy()
            .len();

    println!("model=ed25519_montgomery_slope_shared_constants_probe");
    println!("evidence=locally-reproduced");
    println!("execution_class=unclassified");
    println!("shared_constant_bits=23,24,25,26");
    println!("shared_constant_items=4");
    println!("shared_constants_are_script_authored=true");
    println!("auxiliary_hint_items_per_invocation=0");
    println!("witness_items_added=0");
    println!("pool_setup_bytes={setup_bytes}");
    println!("pool_park_bytes={park_bytes}");
    println!("pool_restore_bytes={restore_bytes}");
    println!("pool_drop_bytes={drop_bytes}");
    println!("global_pool_setup_and_park_bytes={global_setup_bytes}");
    println!("global_pool_restore_and_drop_bytes={global_cleanup_bytes}");
    println!("baseline_verifier_bytes={baseline_verifier_bytes}");
    println!("pooled_retaining_verifier_bytes={pooled_verifier_bytes}");
    println!(
        "pooled_verifier_routing_overhead_bytes={}",
        pooled_verifier_bytes - baseline_verifier_bytes
    );
    println!("baseline_derive22_bytes={baseline_derive22_bytes}");
    println!("pooled_derive22_without_setup_bytes={pooled_derive22_bytes}");
    println!(
        "derive22_constant_access_saving_bytes={}",
        baseline_derive22_bytes - pooled_derive22_bytes
    );
    println!("baseline_derive23_bytes={baseline_derive23_bytes}");
    println!("pooled_derive23_without_setup_bytes={pooled_derive23_bytes}");
    println!(
        "derive23_constant_access_saving_bytes={}",
        baseline_derive23_bytes - pooled_derive23_bytes
    );
    println!("baseline_q22_bytes={}", baseline_q22.len());
    println!("baseline_q23_bytes={}", baseline_q23.len());
    println!("pooled_first_q22_bytes={}", pooled_first_q22.len());
    println!("pooled_first_q23_bytes={}", pooled_first_q23.len());
    println!("pooled_second_q23_bytes={}", pooled_second_q23.len());
    println!(
        "pooled_independent_q22_bytes={}",
        pooled_independent_q22.len()
    );
    println!(
        "pooled_independent_q23_bytes={}",
        pooled_independent_q23.len()
    );
    println!("global_middle_q22_bytes={}", global_q22.len());
    println!("global_middle_q23_bytes={}", global_q23.len());
    println!("baseline_hybrid_first_bytes={}", baseline_first.len());
    println!("pooled_hybrid_first_bytes={}", pooled_first.len());
    println!(
        "pooled_hybrid_first_saving_bytes={}",
        baseline_first.len() - pooled_first.len()
    );
    println!("baseline_hybrid_chained_bytes={}", baseline_chained.len());
    println!("pooled_hybrid_chained_bytes={}", pooled_chained.len());
    println!(
        "pooled_hybrid_chained_saving_bytes={}",
        baseline_chained.len() - pooled_chained.len()
    );
    println!("baseline_hybrid_u5_bytes={}", baseline_u5.len());
    println!("pooled_hybrid_u5_bytes={}", pooled_u5.len());
    println!(
        "pooled_hybrid_u5_saving_bytes={}",
        baseline_u5.len() - pooled_u5.len()
    );
    println!(
        "baseline_hybrid_u5_terminal_bytes={}",
        baseline_u5_terminal.len()
    );
    println!(
        "pooled_hybrid_u5_terminal_bytes={}",
        pooled_u5_terminal.len()
    );
    println!(
        "pooled_hybrid_u5_terminal_saving_bytes={}",
        baseline_u5_terminal.len() - pooled_u5_terminal.len()
    );
    println!(
        "later_pool_hybrid_u5_terminal_bytes={}",
        later_pooled_u5_terminal.len()
    );
    println!(
        "later_pool_hybrid_u5_terminal_saving_bytes={}",
        baseline_u5_terminal.len() - later_pooled_u5_terminal.len()
    );
    println!(
        "global_first_kernel_bytes_excluding_setup_cleanup={}",
        global_first.len()
    );
    println!(
        "global_first_kernel_saving_excluding_setup_cleanup={}",
        baseline_first.len() - global_first.len()
    );
    println!(
        "global_chained_kernel_bytes_excluding_setup_cleanup={}",
        global_chained.len()
    );
    println!(
        "global_chained_kernel_saving_excluding_setup_cleanup={}",
        baseline_chained.len() - global_chained.len()
    );
    println!(
        "global_u5_kernel_bytes_excluding_setup_cleanup={}",
        global_u5.len()
    );
    println!(
        "global_u5_kernel_saving_excluding_setup_cleanup={}",
        baseline_u5.len() - global_u5.len()
    );
    println!(
        "global_47_transition_net_saving_one_pool={}",
        (baseline_first.len() - global_first.len())
            + 46 * (baseline_chained.len() - global_chained.len())
            - global_setup_bytes
            - global_cleanup_bytes
    );
    println!(
        "global_47_transition_net_saving_two_schedule_pools={}",
        (baseline_first.len() - global_first.len())
            + 46 * (baseline_chained.len() - global_chained.len())
            - 2 * (global_setup_bytes + global_cleanup_bytes)
    );
    println!(
        "baseline_first_local_strict_combined_peak={}",
        baseline_first_execution.stats.max_nb_stack_items
    );
    println!(
        "pooled_first_local_strict_combined_peak={}",
        pooled_first_execution.stats.max_nb_stack_items
    );
    println!(
        "global_first_local_strict_combined_peak={}",
        global_first_execution.stats.max_nb_stack_items
    );
    println!(
        "pooled_first_six_local_strict_combined_peak={}",
        pooled_first_six_execution.stats.max_nb_stack_items
    );
    println!(
        "baseline_chained_local_strict_combined_peak={}",
        baseline_execution.stats.max_nb_stack_items
    );
    println!(
        "pooled_chained_local_strict_combined_peak={}",
        pooled_execution.stats.max_nb_stack_items
    );
    println!(
        "global_chained_local_strict_combined_peak={}",
        global_execution.stats.max_nb_stack_items
    );
    println!(
        "baseline_u5_local_strict_combined_peak={}",
        baseline_u5_execution.stats.max_nb_stack_items
    );
    println!(
        "pooled_u5_local_strict_combined_peak={}",
        pooled_u5_execution.stats.max_nb_stack_items
    );
    println!(
        "global_u5_local_strict_combined_peak={}",
        global_u5_execution.stats.max_nb_stack_items
    );
    println!(
        "baseline_u5_terminal_local_strict_combined_peak={}",
        baseline_u5_terminal_execution.stats.max_nb_stack_items
    );
    println!(
        "pooled_u5_terminal_local_strict_combined_peak={}",
        pooled_u5_terminal_execution.stats.max_nb_stack_items
    );
    println!(
        "later_pool_u5_terminal_local_strict_combined_peak={}",
        later_pooled_u5_terminal_execution.stats.max_nb_stack_items
    );
    println!("preserved_probe_items={PRESERVED_PROBE_ITEMS}");
    println!(
        "pooled_preserved_strict_combined_peak={}",
        pooled_preserved_execution.stats.max_nb_stack_items
    );
    println!("strict_transition_execution_passed=true");
    println!("malformed_canonical_u_next_rejected=true");
    for (pool_size, first_bits, first_saving, chained_bits, chained_saving) in &marginal_rows {
        let first_bits = first_bits
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let chained_bits = chained_bits
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "pool_curve_size_{pool_size}=first_bits:{first_bits};first_saving:{first_saving};chained_bits:{chained_bits};chained_saving:{chained_saving}"
        );
    }
    println!(
        "optimal_first_five_bits={}",
        optimal_first_five
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    println!(
        "selected_first_four_bits={}",
        selected_first_four
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("selected_first_four_saving_bytes={selected_first_four_saving}");
    println!(
        "selected_first_four_headroom_cost_bytes={}",
        optimal_first_five_saving - selected_first_four_saving
    );
    println!("later_best_pool_size={later_best_pool_size}");
    println!(
        "later_best_pool_bits_bottom_to_top={}",
        later_pool_bits
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("later_best_pool_chained_saving_bytes={later_chained_saving}");
    println!(
        "two_phase_47_transition_saving_bytes={}",
        selected_first_four_saving + 46 * later_chained_saving
    );
    println!(
        "later_best_pool_chained_local_strict_combined_peak={}",
        later_pooled_execution.stats.max_nb_stack_items
    );
    println!(
        "later_best_pool_u5_local_strict_combined_peak={}",
        later_pooled_u5_execution.stats.max_nb_stack_items
    );
    println!(
        "later_best_pool_u5_plus_712_preserved_strict_combined_peak={}",
        later_pooled_u5_preserved_execution.stats.max_nb_stack_items
    );
    for (pool_size, bits, gross, setup, cleanup, one_pool, two_pool) in &persistent_rows {
        let bits = bits
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "persistent_curve_size_{pool_size}=bits_bottom_to_top:{bits};gross_chained_saving:{gross};setup:{setup};cleanup:{cleanup};later45_one_pool_net:{one_pool};later45_two_pool_net:{two_pool}"
        );
    }
    println!("persistent_best_pool_size={}", persistent_best.0);
    println!(
        "persistent_best_pool_bits_bottom_to_top={}",
        persistent_best
            .1
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    println!(
        "persistent_best_later45_one_pool_net_saving={}",
        persistent_best.5
    );
    println!(
        "persistent_best_later45_two_pool_net_saving={}",
        persistent_best.6
    );
    println!(
        "persistent_two_phase_one_pool_total_saving={}",
        selected_first_four_saving + later_chained_saving + persistent_best.5
    );
    println!(
        "persistent_two_phase_two_pool_total_saving={}",
        selected_first_four_saving + later_chained_saving + persistent_best.6
    );
    println!(
        "source_initialize_persistent_chained_bytes={}",
        source_initialize_persistent_chained.len()
    );
    println!(
        "source_persistent_chained_bytes={}",
        source_persistent_chained.len()
    );
    println!(
        "source_finalize_persistent_chained_bytes={}",
        source_finalize_persistent_chained.len()
    );
    println!(
        "source_finalize_persistent_terminal_bytes={}",
        source_finalize_persistent_terminal.len()
    );
    println!("source_initialize_kernel_saving={source_initialize_saving}");
    println!("source_persistent_kernel_saving={source_persistent_saving}");
    println!("source_finalize_kernel_saving={source_finalize_saving}");
    println!("source_terminal_finalize_kernel_saving={source_terminal_finalize_saving}");
    println!("fused_split_persistent_saving_bytes={fused_split_persistent_saving}");
    println!("fused_split_persistent_pool_phases=2");
    println!("fused_split_persistent_external_setup_cleanup_bytes=0");
    println!("fused_split_persistent_hash_boundary_alt_pool_items=0");
    println!("fused_split_persistent_final_alt_pool_items=0");
    println!(
        "source_initialize_strict_combined_peak={}",
        source_initialize_execution.stats.max_nb_stack_items
    );
    println!(
        "source_finalize_strict_combined_peak={}",
        source_finalize_execution.stats.max_nb_stack_items
    );
    println!(
        "source_terminal_finalize_strict_combined_peak={}",
        source_terminal_finalize_execution.stats.max_nb_stack_items
    );
    println!(
        "g32_u5_response_t0_strict_combined_peak={}",
        first_t0_execution.stats.max_nb_stack_items
    );
    println!(
        "g32_u5_response_t1_strict_combined_peak={}",
        initialize_t1_execution.stats.max_nb_stack_items
    );
    println!(
        "g32_u5_response_t2_strict_combined_peak={}",
        persistent_t2_execution.stats.max_nb_stack_items
    );
    println!(
        "persistent_best_global_u5_local_strict_combined_peak={}",
        persistent_global_u5_execution.stats.max_nb_stack_items
    );
    println!(
        "persistent_best_global_u5_terminal_local_strict_combined_peak={}",
        persistent_global_u5_terminal_execution
            .stats
            .max_nb_stack_items
    );
    println!("whole_scalar_leaf_built=false");
    println!("whole_scalar_leaf_executed=false");
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        None | Some("--selected-first") => run_selected_first_kernel_probe(),
        Some("--full-audit") => run_full_audit(),
        Some(_) => panic!("use --selected-first or --full-audit"),
    }
}
