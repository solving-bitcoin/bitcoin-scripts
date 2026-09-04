//! Focused differential probe for the symmetry-specialized lambda square.
//!
//! This runs only the isolated square accumulator. It does not build a slope
//! transition, scalar schedule, hash, fixed table, or whole leaf. Raw byte
//! accounting deliberately uses the repository policy's >32-KiB NONE path,
//! avoiding a slow isolated optimizer run. These are raw diagnostic bytes;
//! production policy-precompiles the sub-32-KiB semantic square step before
//! embedding it in a larger kernel.

use bitcoin::{script::Instruction, Script as BitcoinScript};
use bitcoin_lab::{
    curves::ed25519::{
        initialize_streamed_grouped_four_square_generic_preserving_rhs,
        initialize_streamed_grouped_four_square_preserving_rhs,
    },
    fields::ed25519::u5_balanced_table::{field_digits, modulus, FIELD_DIGIT_COUNT},
    support::{
        execution::{execute_raw_script_with_inputs_strict, ExecuteInfo},
        script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
    },
};
use num_bigint::{BigInt, BigUint};

const DIGIT_BIAS: i64 = 16;
const GROUPED_FOUR_LIMBS: usize = 13;
const GENERIC_UPDATE_COUNT: usize = GROUPED_FOUR_LIMBS * FIELD_DIGIT_COUNT;
const SPECIALIZED_OWN_UPDATE_COUNT: usize = FIELD_DIGIT_COUNT;
const SPECIALIZED_CROSS_UPDATE_COUNT: usize = 300;
const SPECIALIZED_UPDATE_COUNT: usize =
    SPECIALIZED_OWN_UPDATE_COUNT + SPECIALIZED_CROSS_UPDATE_COUNT;
const MAX_ABS_FOUR_DIGIT_LIMB: i64 = 541_200;
const MAX_ABS_TOP_THREE_DIGIT_LIMB: i64 = 16_912;
const MAX_ABS_DOUBLED_FOLDED_TABLE_VALUE: i64 = 2 * 19 * DIGIT_BIAS * MAX_ABS_FOUR_DIGIT_LIMB;

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn witness_items(digits: &[i32; FIELD_DIGIT_COUNT]) -> Vec<Vec<u8>> {
    digits
        .iter()
        .rev()
        .map(|digit| scriptnum_item(i64::from(*digit)))
        .collect()
}

fn grouped_limb(centered: &[i64; FIELD_DIGIT_COUNT], start: usize, width: usize) -> i64 {
    (0..width)
        .rev()
        .fold(0i64, |limb, digit| limb * 32 + centered[start + digit])
}

fn generic_folded_square(digits: &[i32; FIELD_DIGIT_COUNT]) -> [i64; FIELD_DIGIT_COUNT] {
    let centered = digits.map(|digit| i64::from(digit) - DIGIT_BIAS);
    let mut coefficients = [0i64; FIELD_DIGIT_COUNT];
    for limb in 0..GROUPED_FOUR_LIMBS {
        let start = 4 * limb;
        let width = (FIELD_DIGIT_COUNT - start).min(4);
        let lhs = grouped_limb(&centered, start, width);
        for rhs in 0..FIELD_DIGIT_COUNT {
            let raw = start + rhs;
            let (coefficient, scale) = if raw < FIELD_DIGIT_COUNT {
                (raw, 1)
            } else {
                (raw - FIELD_DIGIT_COUNT, 19)
            };
            coefficients[coefficient] += scale * lhs * centered[rhs];
        }
    }
    coefficients
}

fn specialized_folded_square(digits: &[i32; FIELD_DIGIT_COUNT]) -> [i64; FIELD_DIGIT_COUNT] {
    let centered = digits.map(|digit| i64::from(digit) - DIGIT_BIAS);
    let mut coefficients = [0i64; FIELD_DIGIT_COUNT];
    for limb in 0..GROUPED_FOUR_LIMBS {
        let start = 4 * limb;
        let width = (FIELD_DIGIT_COUNT - start).min(4);
        let lhs = grouped_limb(&centered, start, width);
        for rhs in start..FIELD_DIGIT_COUNT {
            let raw = start + rhs;
            let (coefficient, scale) = if raw < FIELD_DIGIT_COUNT {
                (raw, 1)
            } else {
                (raw - FIELD_DIGIT_COUNT, 19)
            };
            let symmetry = if rhs < start + width { 1 } else { 2 };
            coefficients[coefficient] += symmetry * scale * lhs * centered[rhs];
        }
    }
    coefficients
}

fn reconstruct(coefficients: &[i64; FIELD_DIGIT_COUNT]) -> BigInt {
    coefficients
        .iter()
        .rev()
        .fold(BigInt::from(0), |value, coefficient| {
            value * 32 + BigInt::from(*coefficient)
        })
}

fn expected_stack(
    digits: &[i32; FIELD_DIGIT_COUNT],
    coefficients: &[i64; FIELD_DIGIT_COUNT],
) -> Vec<Vec<u8>> {
    witness_items(digits)
        .into_iter()
        .chain(
            coefficients
                .iter()
                .rev()
                .map(|coefficient| scriptnum_item(*coefficient)),
        )
        .chain(std::iter::once(scriptnum_item(1)))
        .collect()
}

fn assert_output(
    label: &str,
    execution: &ExecuteInfo,
    digits: &[i32; FIELD_DIGIT_COUNT],
    coefficients: &[i64; FIELD_DIGIT_COUNT],
) {
    assert!(
        execution.error.is_none(),
        "{label} square execution failed: {execution}"
    );
    let expected = expected_stack(digits, coefficients);
    assert_eq!(execution.final_stack.len(), expected.len(), "{label}");
    for (index, item) in expected.iter().enumerate() {
        assert_eq!(
            execution.final_stack.get(index),
            *item,
            "{label} item {index}"
        );
    }
}

fn strict_executable(fragment: Script) -> bitcoin::ScriptBuf {
    script! {
        // Force the centralized policy's raw path. This focused probe validates
        // the generator's unoptimized semantics and intentionally does not run
        // CompileOptions::ALL; the production kernel separately policy-compiles
        // this small semantic step before embedding it.
        for _ in 0..=MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
        { fragment }
        1
    }
    .compile_with_policy()
}

fn checked_executable(fragment: Script, digits: &[i32; FIELD_DIGIT_COUNT]) -> bitcoin::ScriptBuf {
    let coefficients = specialized_folded_square(digits);
    script! {
        for _ in 0..=MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
        { fragment }
        for coefficient in coefficients { { coefficient } OP_NUMEQUALVERIFY }
        for digit in digits { { *digit } OP_NUMEQUALVERIFY }
        1
    }
    .compile_with_policy()
}

fn static_non_push_opcodes(script: &BitcoinScript) -> usize {
    script
        .instructions()
        .map(|instruction| instruction.expect("generated script parses"))
        .filter(
            |instruction| matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() > 0x60),
        )
        .count()
}

fn raw_fragment_metrics(fragment: &Script) -> (usize, usize) {
    let copies = MAX_OPTIMIZER_INPUT_BYTES.div_ceil(fragment.len().max(1)) + 1;
    let repeated = script! {
        for _ in 0..copies { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % copies, 0);
    let opcodes = static_non_push_opcodes(&repeated);
    assert_eq!(opcodes % copies, 0);
    (repeated.len() / copies, opcodes / copies)
}

fn correlation_free_coefficient_bounds() -> [i64; FIELD_DIGIT_COUNT] {
    let mut bounds = [0i64; FIELD_DIGIT_COUNT];
    for limb in 0..GROUPED_FOUR_LIMBS {
        let start = 4 * limb;
        let width = (FIELD_DIGIT_COUNT - start).min(4);
        let limb_bound = if width == 4 {
            MAX_ABS_FOUR_DIGIT_LIMB
        } else {
            MAX_ABS_TOP_THREE_DIGIT_LIMB
        };
        for rhs in start..FIELD_DIGIT_COUNT {
            let raw = start + rhs;
            let (coefficient, fold) = if raw < FIELD_DIGIT_COUNT {
                (raw, 1)
            } else {
                (raw - FIELD_DIGIT_COUNT, 19)
            };
            let symmetry = if rhs < start + width { 1 } else { 2 };
            bounds[coefficient] += symmetry * fold * DIGIT_BIAS * limb_bound;
        }
    }
    bounds
}

fn deterministic_values() -> Vec<BigUint> {
    let p = modulus();
    let mut values = vec![
        BigUint::from(0u8),
        BigUint::from(1u8),
        &p - BigUint::from(1u8),
        BigUint::parse_bytes(
            b"123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            16,
        )
        .expect("fixed hexadecimal fixture parses"),
    ];
    let mut state = 0x6a09_e667_f3bc_c909u64;
    for _ in 0..4 {
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_exact_mut(8) {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            chunk.copy_from_slice(&state.to_le_bytes());
        }
        values.push(BigUint::from_bytes_le(&bytes) % &p);
    }
    values
}

fn main() {
    assert_eq!(GENERIC_UPDATE_COUNT, 663);
    assert_eq!(SPECIALIZED_UPDATE_COUNT, 351);
    assert_eq!(SPECIALIZED_CROSS_UPDATE_COUNT, 300);
    assert!(MAX_ABS_DOUBLED_FOLDED_TABLE_VALUE < i64::from(i32::MAX));

    let coefficient_bounds = correlation_free_coefficient_bounds();
    let max_coefficient_bound = *coefficient_bounds
        .iter()
        .max()
        .expect("nonempty coefficient vector");
    assert_eq!(max_coefficient_bound, 1_982_956_800);
    assert!(max_coefficient_bound < i64::from(i32::MAX));

    let generic = initialize_streamed_grouped_four_square_generic_preserving_rhs();
    let specialized = initialize_streamed_grouped_four_square_preserving_rhs();
    let (generic_raw_bytes, generic_raw_opcodes) = raw_fragment_metrics(&generic);
    let (specialized_raw_bytes, specialized_raw_opcodes) = raw_fragment_metrics(&specialized);
    assert_eq!(generic_raw_bytes, 10_870);
    assert_eq!(specialized_raw_bytes, 7_984);
    assert_eq!(generic_raw_opcodes, 7_807);
    assert_eq!(specialized_raw_opcodes, 6_268);
    assert!(specialized_raw_bytes < generic_raw_bytes);

    let generic_executable = strict_executable(generic.clone());
    let specialized_executable = strict_executable(specialized.clone());
    let values = deterministic_values();
    let reference_digits = field_digits(&values[3]);
    let reference_generic = generic_folded_square(&reference_digits);
    let reference_specialized = specialized_folded_square(&reference_digits);
    assert_ne!(
        reference_generic, reference_specialized,
        "the two grouped fold orientations are not coefficient-identical"
    );
    let differing_reference_coefficients = reference_generic
        .iter()
        .zip(reference_specialized.iter())
        .filter(|(generic, specialized)| generic != specialized)
        .count();
    let max_reference_coefficient_delta = reference_generic
        .iter()
        .zip(reference_specialized.iter())
        .map(|(generic, specialized)| (generic - specialized).abs())
        .max()
        .expect("nonempty coefficient vectors");
    let reference_reconstruction_delta =
        reconstruct(&reference_generic) - reconstruct(&reference_specialized);
    let p = BigInt::from(modulus());
    assert_eq!(&reference_reconstruction_delta % &p, BigInt::from(0));
    let reference_quotient_shift = &reference_reconstruction_delta / &p;

    // One generic execution proves that the reference wrapper has the same
    // host coefficient/order contract. Exercise more boundary/deterministic
    // vectors through the new specialization only.
    let generic_execution = execute_raw_script_with_inputs_strict(
        generic_executable.to_bytes(),
        witness_items(&reference_digits),
    );
    assert_output(
        "generic",
        &generic_execution,
        &reference_digits,
        &reference_generic,
    );

    let mut specialized_peak = 0usize;
    for (index, value) in values.iter().enumerate() {
        let digits = field_digits(value);
        let execution = execute_raw_script_with_inputs_strict(
            specialized_executable.to_bytes(),
            witness_items(&digits),
        );
        let specialized_coefficients = specialized_folded_square(&digits);
        let p = BigInt::from(modulus());
        assert_eq!(
            (reconstruct(&generic_folded_square(&digits)) - reconstruct(&specialized_coefficients))
                % &p,
            BigInt::from(0),
            "specialized reconstruction is not field-equivalent on vector {index}"
        );
        assert_output(
            &format!("specialized vector {index}"),
            &execution,
            &digits,
            &specialized_coefficients,
        );
        specialized_peak = specialized_peak.max(execution.stats.max_nb_stack_items);
    }

    // A fixed expected relation must reject even a still-in-range mutation.
    // The square fragment itself is intentionally not a digit certifier.
    let checker = checked_executable(specialized, &reference_digits);
    let mut malformed = reference_digits;
    malformed[0] = (malformed[0] + 1) % 32;
    let malformed_execution =
        execute_raw_script_with_inputs_strict(checker.to_bytes(), witness_items(&malformed));
    assert!(
        malformed_execution.error.is_some(),
        "fixed square relation accepted a mutated canonical rhs digit"
    );
    let mut out_of_range = reference_digits;
    out_of_range[0] = 32;
    let out_of_range_execution =
        execute_raw_script_with_inputs_strict(checker.to_bytes(), witness_items(&out_of_range));
    assert!(
        out_of_range_execution.error.is_some(),
        "fixed square relation accepted the tested out-of-range rhs digit"
    );

    println!("model=ed25519_montgomery_slope_symmetric_square_probe");
    println!("evidence=differentially-validated");
    println!("execution_class=unclassified");
    println!("generic_table_updates={GENERIC_UPDATE_COUNT}");
    println!("specialized_own_table_updates={SPECIALIZED_OWN_UPDATE_COUNT}");
    println!("specialized_doubled_cross_table_updates={SPECIALIZED_CROSS_UPDATE_COUNT}");
    println!("specialized_total_table_updates={SPECIALIZED_UPDATE_COUNT}");
    println!("generic_raw_script_bytes={generic_raw_bytes}");
    println!("specialized_raw_script_bytes={specialized_raw_bytes}");
    println!(
        "specialized_raw_byte_saving={}",
        generic_raw_bytes - specialized_raw_bytes
    );
    println!("generic_raw_static_non_push_opcodes={generic_raw_opcodes}");
    println!("specialized_raw_static_non_push_opcodes={specialized_raw_opcodes}");
    println!(
        "generic_strict_combined_peak={}",
        generic_execution.stats.max_nb_stack_items
    );
    println!("specialized_strict_combined_peak={specialized_peak}");
    println!("max_abs_doubled_folded_table_value={MAX_ABS_DOUBLED_FOLDED_TABLE_VALUE}");
    println!("max_correlation_free_square_coefficient_bound={max_coefficient_bound}");
    println!(
        "i32_square_coefficient_margin={}",
        i64::from(i32::MAX) - max_coefficient_bound
    );
    println!("deterministic_host_vectors={}", values.len());
    println!("coefficient_vectors_identical=false");
    println!("reference_differing_coefficient_count={differing_reference_coefficients}");
    println!("reference_max_abs_coefficient_delta={max_reference_coefficient_delta}");
    println!("reference_exact_quotient_shift={reference_quotient_shift}");
    println!("all_reconstruction_deltas_are_multiples_of_p=true");
    println!("rhs_preserved_exactly=true");
    println!("mutated_canonical_rhs_rejected_by_fixed_relation=true");
    println!("tested_out_of_range_rhs_rejected_by_fixed_relation=true");
    println!("rhs_digit_certification=required_from_caller");
    println!("input_data_items={FIELD_DIGIT_COUNT}");
    println!("auxiliary_hint_items_per_invocation=0");
    println!("isolated_compile_optimizer_run=false");
    println!("whole_scalar_leaf_built=false");
    println!("whole_scalar_leaf_executed=false");
}
