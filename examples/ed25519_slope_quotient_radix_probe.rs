//! Focused constant-chain search for no-hint Ed25519 slope quotients.
//!
//! The legacy derivation multiplies a canonical 22- or 23-bit residue by
//! `1_324_517` modulo `2^width` with a width-two NAF chain. This probe compares
//! that frozen baseline with bounded unsigned Horner chains and the mixed
//! chain now selected by the production default.
//! Every Horner stage is reduced modulo `2^width` only after the complete
//! `base * accumulator + digit * source` expression.  The candidate list
//! includes radix 64 and 128 plus several three-digit bases selected for fewer
//! conditional power-of-two subtractions.
//!
//! Strict tests cover boundary and deterministic pseudorandom residues, the
//! three real low-coefficient bound vectors, exact accumulator preservation,
//! and complete derive-plus-close relations.  No slope transition, table,
//! hash, full linker, or long test suite is executed.

use bitcoin_lab::{
    arithmetic::scriptint,
    curves::ed25519::{
        montgomery_slope::{
            CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX, CHAINED_CONTINUITY_QUOTIENT_ABS_MAX,
            CURVE_LOW_COEFFICIENT_ABS_MAX, CURVE_QUOTIENT_MAX, CURVE_QUOTIENT_MIN,
            FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX, FIRST_CONTINUITY_QUOTIENT_ABS_MAX,
        },
        verify_streamed_relation_top_quotient,
    },
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
    },
};

const RADIX_BITS: usize = 5;
const COEFFICIENTS: usize = 51;
const LOW_COEFFICIENTS: usize = 5;
const INVERSE: u32 = 1_324_517;

#[derive(Clone, Copy)]
struct HornerCandidate {
    name: &'static str,
    base: u32,
    digits: &'static [u32],
}

const RADIX64_DIGITS: &[u32] = &[5, 3, 23, 37];
const RADIX128_DIGITS: &[u32] = &[80, 107, 101];
const BASE132_DIGITS: &[u32] = &[76, 2, 29];
const BASE146_DIGITS: &[u32] = &[62, 20, 5];
const BASE158_DIGITS: &[u32] = &[53, 9, 3];
const BASE166_DIGITS: &[u32] = &[48, 11, 3];

const HORNER_CANDIDATES: &[HornerCandidate] = &[
    HornerCandidate {
        name: "radix64_unsigned",
        base: 64,
        digits: RADIX64_DIGITS,
    },
    HornerCandidate {
        name: "radix128_unsigned",
        base: 128,
        digits: RADIX128_DIGITS,
    },
    HornerCandidate {
        name: "base132_unsigned",
        base: 132,
        digits: BASE132_DIGITS,
    },
    HornerCandidate {
        name: "base146_unsigned",
        base: 146,
        digits: BASE146_DIGITS,
    },
    HornerCandidate {
        name: "base158_unsigned",
        base: 158,
        digits: BASE158_DIGITS,
    },
    HornerCandidate {
        name: "base166_unsigned",
        base: 166,
        digits: BASE166_DIGITS,
    },
];

#[derive(Clone, Copy)]
enum Method {
    Naf,
    Horner(HornerCandidate),
    Mixed233x196Plus5x29,
}

impl Method {
    fn name(self) -> &'static str {
        match self {
            Self::Naf => "legacy_naf_baseline",
            Self::Horner(candidate) => candidate.name,
            Self::Mixed233x196Plus5x29 => "mixed_233x196_plus5_x29",
        }
    }

    fn multiplier(self, width: usize) -> Script {
        match self {
            Self::Naf => naf_multiplier(width),
            Self::Horner(candidate) => unsigned_horner_multiplier(width, candidate),
            Self::Mixed233x196Plus5x29 => mixed_233x196_plus5_x29_multiplier(width),
        }
    }
}

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn subtract_power_if_at_least(bit: usize) -> Script {
    script! {
        { 1u32 << bit } OP_2DUP OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
    }
}

fn signed_low_remainder(width: usize, max_abs: i64) -> Script {
    assert!((1..=30).contains(&width));
    assert!(max_abs > 0);
    let input_bits = i64::BITS as usize - max_abs.leading_zeros() as usize;
    assert!(input_bits <= 31);
    script! {
        OP_DUP 0 OP_LESSTHAN
        OP_DUP OP_TOALTSTACK
        OP_IF OP_NEGATE OP_ENDIF
        for bit in (width..input_bits).rev() {
            { subtract_power_if_at_least(bit) }
        }
        OP_FROMALTSTACK OP_IF OP_NEGATE OP_ENDIF
    }
}

fn reduce_signed_five_term_sum(width: usize) -> Script {
    script! {
        OP_DUP 0 OP_LESSTHAN
        OP_DUP OP_TOALTSTACK
        OP_IF OP_NEGATE OP_ENDIF
        for bit in (width..=width + 2).rev() {
            { subtract_power_if_at_least(bit) }
        }
        OP_FROMALTSTACK
        OP_IF
            OP_DUP OP_NOT OP_NOT OP_IF
                { 1u32 << width } OP_SWAP OP_SUB
            OP_ENDIF
        OP_ENDIF
    }
}

fn reduce_once(width: usize) -> Script {
    subtract_power_if_at_least(width)
}

/// Exact copy of the production width-two NAF multiplier for the baseline.
fn naf_multiplier(width: usize) -> Script {
    let mut remaining = INVERSE;
    let mut naf_low_to_high = Vec::new();
    while remaining != 0 {
        let digit = if remaining & 1 == 0 {
            0i8
        } else {
            2 - (remaining & 3) as i8
        };
        naf_low_to_high.push(digit);
        remaining = ((i64::from(remaining) - i64::from(digit)) / 2) as u32;
    }
    let naf_high_to_low = naf_low_to_high.into_iter().rev().collect::<Vec<_>>();
    assert_eq!(naf_high_to_low[0], 1);
    assert_eq!(
        naf_high_to_low.iter().filter(|digit| **digit != 0).count(),
        8
    );

    script! {
        OP_DUP
        for digit in naf_high_to_low.into_iter().skip(1) {
            OP_DUP OP_ADD
            { reduce_once(width) }
            if digit == 1 {
                1 OP_PICK OP_ADD
                { reduce_once(width) }
            } else if digit == -1 {
                1 OP_PICK OP_SUB
                OP_DUP 0 OP_LESSTHAN
                OP_IF { 1u32 << width } OP_ADD OP_ENDIF
            }
        }
        OP_NIP
    }
}

fn ceil_log2(value: u32) -> usize {
    if value <= 1 {
        0
    } else {
        (u32::BITS - (value - 1).leading_zeros()) as usize
    }
}

/// Reduce a known nonnegative value below `factor * 2^width`.
fn reduce_nonnegative_factor(width: usize, factor: u32) -> Script {
    let high_bits = ceil_log2(factor);
    script! {
        for bit in (width..width + high_bits).rev() {
            { subtract_power_if_at_least(bit) }
        }
    }
}

fn reconstruct_parts(base: u32, digits: &[u32]) -> u32 {
    digits.iter().copied().fold(0u32, |accumulator, digit| {
        accumulator
            .checked_mul(base)
            .and_then(|value| value.checked_add(digit))
            .expect("candidate constant fits u32")
    })
}

/// Return the exact count of conditional power-of-two subtractions and prove
/// that the final expression and every positive double-and-add subchain fit a
/// four-byte ScriptNum for all canonical width-bit inputs.
fn horner_is_safe(width: usize, base: u32, digits: &[u32]) -> bool {
    if reconstruct_parts(base, digits) != INVERSE
        || digits.len() < 2
        || !digits.iter().all(|digit| *digit < base)
    {
        return false;
    }
    let maximum_residue = (1u64 << width) - 1;
    let maximum_scriptnum = i64::from(i32::MAX) as u64;
    u64::from(digits[0]) * maximum_residue <= maximum_scriptnum
        && digits
            .iter()
            .copied()
            .skip(1)
            .all(|digit| u64::from(base + digit) * maximum_residue <= maximum_scriptnum)
}

fn assert_horner_safety_parts(width: usize, base: u32, digits: &[u32]) -> usize {
    assert!(horner_is_safe(width, base, digits));
    let mut reduction_count = ceil_log2(digits[0]);
    reduction_count += digits
        .iter()
        .copied()
        .skip(1)
        .map(|digit| ceil_log2(base + digit))
        .sum::<usize>();
    reduction_count
}

fn assert_horner_safety(width: usize, candidate: HornerCandidate) -> usize {
    assert_horner_safety_parts(width, candidate.base, candidate.digits)
}

/// Input/output is `x -> (INVERSE*x mod 2^width)`, retaining x only while the
/// unsigned Horner accumulator is live.
fn unsigned_horner_multiplier(width: usize, candidate: HornerCandidate) -> Script {
    unsigned_horner_multiplier_parts(width, candidate.base, candidate.digits)
}

fn unsigned_horner_multiplier_parts(width: usize, base: u32, digits: &[u32]) -> Script {
    assert!(width == 22 || width == 23);
    assert_horner_safety_parts(width, base, digits);
    let initial = digits[0];
    script! {
        OP_DUP
        { scriptint::mul_by_constant(initial) }
        { reduce_nonnegative_factor(width, initial) }
        for digit in digits.iter().copied().skip(1) {
            { scriptint::mul_by_constant(base) }
            1 OP_PICK
            { scriptint::mul_by_constant(digit) }
            OP_ADD
            { reduce_nonnegative_factor(width, base + digit) }
        }
        OP_NIP
    }
}

/// `INVERSE = (233*196 + 5)*29`. The source x remains below the first two
/// stages and is dropped before the final multiply. Exact unreduced factors
/// are 233, 201, and 29, requiring 8+8+5=21 conditional reductions.
fn mixed_233x196_plus5_x29_multiplier(width: usize) -> Script {
    assert!(width == 22 || width == 23);
    assert_eq!((233u32 * 196 + 5) * 29, INVERSE);
    factored_29_multiplier(width, 233, 196, 5)
}

fn factored_29_multiplier(width: usize, initial: u32, middle: u32, digit: u32) -> Script {
    assert_eq!((initial * middle + digit) * 29, INVERSE);
    let maximum_residue = (1u64 << width) - 1;
    for factor in [initial, middle + digit, 29] {
        assert!(u64::from(factor) * maximum_residue <= i64::from(i32::MAX) as u64);
    }
    script! {
        OP_DUP
        { scriptint::mul_by_constant(initial) }
        { reduce_nonnegative_factor(width, initial) }

        { scriptint::mul_by_constant(middle) }
        1 OP_PICK
        { scriptint::mul_by_constant(digit) }
        OP_ADD
        { reduce_nonnegative_factor(width, middle + digit) }

        OP_NIP
        { scriptint::mul_by_constant(29) }
        { reduce_nonnegative_factor(width, 29) }
    }
}

fn canonical_digits(base: u32) -> Vec<u32> {
    let mut remaining = INVERSE;
    let mut reversed = Vec::new();
    while remaining != 0 {
        reversed.push(remaining % base);
        remaining /= base;
    }
    reversed.reverse();
    reversed
}

struct SearchResult {
    base: u32,
    digits: Vec<u32>,
    raw_bytes: usize,
    policy_bytes: usize,
    conditional_subtractions: usize,
    maximum_factor: u32,
}

struct FactoredSearchResult {
    initial: u32,
    middle: u32,
    digit: u32,
    raw_bytes: usize,
    policy_bytes: usize,
    conditional_subtractions: usize,
    maximum_factor: u32,
}

/// Exhaust the small unsigned-base design space whose symbolic worst case
/// fits ScriptNum. This generates and policy-compiles candidates but does not
/// execute them; the winning static candidate is strict-tested separately.
fn search_safe_unsigned_bases(width: usize) -> SearchResult {
    let mut best = None::<SearchResult>;
    for base in 2..=512u32 {
        let digits = canonical_digits(base);
        if !horner_is_safe(width, base, &digits) {
            continue;
        }
        let fragment = unsigned_horner_multiplier_parts(width, base, &digits);
        let raw_bytes = fragment.len();
        let policy_bytes = fragment.compile_with_policy().len();
        let conditional_subtractions = assert_horner_safety_parts(width, base, &digits);
        let maximum_factor = digits
            .iter()
            .copied()
            .skip(1)
            .map(|digit| base + digit)
            .chain(std::iter::once(digits[0]))
            .max()
            .expect("canonical representation has digits");
        let result = SearchResult {
            base,
            digits,
            raw_bytes,
            policy_bytes,
            conditional_subtractions,
            maximum_factor,
        };
        if best.as_ref().is_none_or(|current| {
            (result.policy_bytes, result.raw_bytes) < (current.policy_bytes, current.raw_bytes)
        }) {
            best = Some(result);
        }
    }
    best.expect("at least one safe unsigned Horner base")
}

fn search_factored_29_chains(width: usize) -> FactoredSearchResult {
    assert_eq!(INVERSE % 29, 0);
    let inner = INVERSE / 29;
    let maximum_residue = (1u64 << width) - 1;
    let maximum_scriptnum = i64::from(i32::MAX) as u64;
    let mut best = None::<FactoredSearchResult>;
    for middle in 2..=512u32 {
        let initial = inner / middle;
        let digit = inner % middle;
        let factors = [initial, middle + digit, 29];
        if factors
            .iter()
            .any(|factor| u64::from(*factor) * maximum_residue > maximum_scriptnum)
        {
            continue;
        }
        let fragment = factored_29_multiplier(width, initial, middle, digit);
        let raw_bytes = fragment.len();
        let policy_bytes = fragment.compile_with_policy().len();
        let conditional_subtractions = factors.iter().copied().map(ceil_log2).sum::<usize>();
        let maximum_factor = *factors.iter().max().expect("three factors");
        let result = FactoredSearchResult {
            initial,
            middle,
            digit,
            raw_bytes,
            policy_bytes,
            conditional_subtractions,
            maximum_factor,
        };
        if best.as_ref().is_none_or(|current| {
            (result.policy_bytes, result.raw_bytes) < (current.policy_bytes, current.raw_bytes)
        }) {
            best = Some(result);
        }
    }
    best.expect("at least one safe factor-29 chain")
}

fn derive_relation_quotient(
    width: usize,
    low_coefficient_abs_max: [i64; LOW_COEFFICIENTS],
    multiplier: Script,
) -> Script {
    assert!(width == 22 || width == 23);
    script! {
        for coefficient in 0..LOW_COEFFICIENTS {
            { coefficient as u32 } OP_PICK
            { signed_low_remainder(
                width - RADIX_BITS * coefficient,
                low_coefficient_abs_max[coefficient],
            ) }
            OP_TOALTSTACK
        }

        OP_FROMALTSTACK
        for _coefficient in (0..LOW_COEFFICIENTS - 1).rev() {
            for _ in 0..RADIX_BITS { OP_DUP OP_ADD }
            OP_FROMALTSTACK OP_ADD
        }
        { reduce_signed_five_term_sum(width) }
        { multiplier }

        OP_DUP { 1u32 << (width - 1) } OP_GREATERTHANOREQUAL
        OP_IF { 1u32 << width } OP_SUB OP_ENDIF
    }
}

fn derive_and_verify(
    width: usize,
    low_coefficient_abs_max: [i64; LOW_COEFFICIENTS],
    method: Method,
) -> Script {
    script! {
        { derive_relation_quotient(
            width,
            low_coefficient_abs_max,
            method.multiplier(width),
        ) }
        { verify_streamed_relation_top_quotient() }
    }
}

fn raw_fragment_len(fragment: &Script) -> usize {
    let copies = MAX_OPTIMIZER_INPUT_BYTES.div_ceil(fragment.len().max(1)) + 1;
    let repeated = script! {
        for _ in 0..copies { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % copies, 0);
    repeated.len() / copies
}

fn modulus(width: usize) -> u64 {
    1u64 << width
}

fn expected_product(width: usize, residue: u32) -> u32 {
    ((u64::from(residue) * u64::from(INVERSE)) % modulus(width)) as u32
}

fn residue_inputs(width: usize) -> Vec<u32> {
    let modulus = 1u32 << width;
    let mut inputs = vec![
        0,
        1,
        2,
        modulus / 2 - 1,
        modulus / 2,
        modulus - 2,
        modulus - 1,
    ];
    let mut state = 0x6a09_e667_f3bc_c909u64 ^ width as u64;
    for _ in 0..24 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        inputs.push((state % u64::from(modulus)) as u32);
    }
    inputs
}

fn execute_multiplier(method: Method, width: usize) -> usize {
    let executable = script! {
        { method.multiplier(width) }
        OP_1
    }
    .compile_with_policy();
    let mut peak = 0usize;
    for residue in residue_inputs(width) {
        let execution = execute_raw_script_with_inputs_strict(
            executable.to_bytes(),
            vec![scriptnum_item(i64::from(residue))],
        );
        assert!(
            execution.error.is_none(),
            "{} width-{width} residue {residue}: {execution}",
            method.name()
        );
        assert_eq!(execution.final_stack.len(), 2);
        assert_eq!(
            execution.final_stack.get(0),
            scriptnum_item(i64::from(expected_product(width, residue)))
        );
        assert_eq!(execution.final_stack.get(1), scriptnum_item(1));
        peak = peak.max(execution.stats.max_nb_stack_items);
    }
    peak
}

fn expected_derived_quotient(width: usize, coefficients: &[i64; COEFFICIENTS]) -> i64 {
    let modulus = i128::from(1u64 << width);
    let mut power = 1i128;
    let mut low = 0i128;
    for coefficient in coefficients.iter().take(LOW_COEFFICIENTS) {
        low += i128::from(*coefficient) * power;
        power <<= RADIX_BITS;
    }
    let residue = low.rem_euclid(modulus);
    let product = (residue * i128::from(INVERSE)).rem_euclid(modulus);
    if product >= modulus / 2 {
        (product - modulus) as i64
    } else {
        product as i64
    }
}

fn coefficient_witness(coefficients: &[i64; COEFFICIENTS]) -> Vec<Vec<u8>> {
    coefficients
        .iter()
        .rev()
        .map(|coefficient| scriptnum_item(*coefficient))
        .collect()
}

fn coefficient_cases(bounds: [i64; LOW_COEFFICIENTS], seed: u64) -> Vec<[i64; COEFFICIENTS]> {
    let mut cases = Vec::new();
    cases.push([0i64; COEFFICIENTS]);
    for coefficient in 0..LOW_COEFFICIENTS {
        for sign in [-1i64, 1] {
            let mut values = [0i64; COEFFICIENTS];
            values[coefficient] = sign * bounds[coefficient];
            cases.push(values);
        }
    }
    let mut alternating = [0i64; COEFFICIENTS];
    for coefficient in 0..LOW_COEFFICIENTS {
        alternating[coefficient] = if coefficient % 2 == 0 {
            bounds[coefficient]
        } else {
            -bounds[coefficient]
        };
    }
    cases.push(alternating);

    let mut state = seed;
    for _ in 0..16 {
        let mut values = [0i64; COEFFICIENTS];
        for coefficient in 0..LOW_COEFFICIENTS {
            state = state
                .wrapping_mul(2_862_933_555_777_941_757)
                .wrapping_add(3_037_000_493);
            let span = (2 * bounds[coefficient] + 1) as u64;
            values[coefficient] = (state % span) as i64 - bounds[coefficient];
        }
        cases.push(values);
    }
    cases
}

fn execute_derivation_cases(
    method: Method,
    width: usize,
    bounds: [i64; LOW_COEFFICIENTS],
    seed: u64,
) -> usize {
    let derive = derive_relation_quotient(width, bounds, method.multiplier(width));
    let executable = script! { { derive } OP_1 }.compile_with_policy();
    let mut peak = 0usize;
    for coefficients in coefficient_cases(bounds, seed) {
        let witness = coefficient_witness(&coefficients);
        let execution =
            execute_raw_script_with_inputs_strict(executable.to_bytes(), witness.clone());
        assert!(
            execution.error.is_none(),
            "{} width-{width} coefficient derivation: {execution}",
            method.name()
        );
        assert_eq!(execution.final_stack.len(), COEFFICIENTS + 2);
        for (index, original) in witness.iter().enumerate() {
            assert_eq!(execution.final_stack.get(index), *original);
        }
        assert_eq!(
            execution.final_stack.get(COEFFICIENTS),
            scriptnum_item(expected_derived_quotient(width, &coefficients))
        );
        assert_eq!(
            execution.final_stack.get(COEFFICIENTS + 1),
            scriptnum_item(1)
        );
        peak = peak.max(execution.stats.max_nb_stack_items);
    }
    peak
}

fn relation_coefficients(q: i32) -> [i64; COEFFICIENTS] {
    let mut coefficients = [0i64; COEFFICIENTS];
    coefficients[0] = -19 * i64::from(q);
    coefficients[COEFFICIENTS - 1] = 32 * i64::from(q);
    coefficients
}

fn add_carry_noise(coefficients: &mut [i64; COEFFICIENTS]) {
    for (coefficient, carry) in [17i64, -29, 41, -53, 67].into_iter().enumerate() {
        coefficients[coefficient] += 32 * carry;
        coefficients[coefficient + 1] -= carry;
    }
}

fn execute_relation_cases(
    method: Method,
    width: usize,
    bounds: [i64; LOW_COEFFICIENTS],
    quotients: &[i32],
) -> usize {
    let relation = derive_and_verify(width, bounds, method);
    let executable = script! { { relation } OP_1 }.compile_with_policy();
    let mut peak = 0usize;
    for quotient in quotients.iter().copied() {
        let mut coefficients = relation_coefficients(quotient);
        add_carry_noise(&mut coefficients);
        let execution = execute_raw_script_with_inputs_strict(
            executable.to_bytes(),
            coefficient_witness(&coefficients),
        );
        assert!(
            execution.error.is_none(),
            "{} width-{width} q={quotient}: {execution}",
            method.name()
        );
        assert_eq!(execution.final_stack.len(), 1);
        peak = peak.max(execution.stats.max_nb_stack_items);
    }
    peak
}

struct MethodMetrics {
    name: &'static str,
    multiplier22_policy: usize,
    multiplier23_policy: usize,
    first_relation_policy: usize,
    curve_relation_policy: usize,
    chained_relation_policy: usize,
    projected_88_relation_bytes: usize,
}

fn measure_method(method: Method) -> MethodMetrics {
    let multiplier22 = method.multiplier(22);
    let multiplier23 = method.multiplier(23);
    let first_derive = derive_relation_quotient(
        22,
        FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
        method.multiplier(22),
    );
    let curve_derive =
        derive_relation_quotient(23, CURVE_LOW_COEFFICIENT_ABS_MAX, method.multiplier(23));
    let chained_derive = derive_relation_quotient(
        23,
        CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
        method.multiplier(23),
    );
    let first_relation = derive_and_verify(22, FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX, method);
    let curve_relation = derive_and_verify(23, CURVE_LOW_COEFFICIENT_ABS_MAX, method);
    let chained_relation =
        derive_and_verify(23, CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX, method);

    let multiplier22_peak = execute_multiplier(method, 22);
    let multiplier23_peak = execute_multiplier(method, 23);
    let derive22_peak = execute_derivation_cases(
        method,
        22,
        FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
        0x243f_6a88_85a3_08d3,
    );
    let derive_curve_peak = execute_derivation_cases(
        method,
        23,
        CURVE_LOW_COEFFICIENT_ABS_MAX,
        0x1319_8a2e_0370_7344,
    );
    let derive_chained_peak = execute_derivation_cases(
        method,
        23,
        CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
        0xa409_3822_299f_31d0,
    );
    let first_relation_peak = execute_relation_cases(
        method,
        22,
        FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
        &[
            -FIRST_CONTINUITY_QUOTIENT_ABS_MAX,
            -1,
            0,
            1,
            FIRST_CONTINUITY_QUOTIENT_ABS_MAX,
        ],
    );
    let curve_relation_peak = execute_relation_cases(
        method,
        23,
        CURVE_LOW_COEFFICIENT_ABS_MAX,
        &[CURVE_QUOTIENT_MIN, -1, 0, 1, CURVE_QUOTIENT_MAX],
    );
    let chained_relation_peak = execute_relation_cases(
        method,
        23,
        CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
        &[
            -CHAINED_CONTINUITY_QUOTIENT_ABS_MAX,
            -1,
            0,
            1,
            CHAINED_CONTINUITY_QUOTIENT_ABS_MAX,
        ],
    );

    let multiplier22_raw = raw_fragment_len(&multiplier22);
    let multiplier23_raw = raw_fragment_len(&multiplier23);
    let multiplier22_policy = multiplier22.compile_with_policy().len();
    let multiplier23_policy = multiplier23.compile_with_policy().len();
    let first_derive_raw = raw_fragment_len(&first_derive);
    let curve_derive_raw = raw_fragment_len(&curve_derive);
    let chained_derive_raw = raw_fragment_len(&chained_derive);
    let first_derive_policy = first_derive.compile_with_policy().len();
    let curve_derive_policy = curve_derive.compile_with_policy().len();
    let chained_derive_policy = chained_derive.compile_with_policy().len();
    let first_relation_raw = raw_fragment_len(&first_relation);
    let curve_relation_raw = raw_fragment_len(&curve_relation);
    let chained_relation_raw = raw_fragment_len(&chained_relation);
    let first_relation_policy = first_relation.compile_with_policy().len();
    let curve_relation_policy = curve_relation.compile_with_policy().len();
    let chained_relation_policy = chained_relation.compile_with_policy().len();
    let projected_88_relation_bytes =
        first_relation_policy + 44 * curve_relation_policy + 43 * chained_relation_policy;

    println!("method={}", method.name());
    if let Method::Horner(candidate) = method {
        println!("horner_base={}", candidate.base);
        println!("horner_digits={:?}", candidate.digits);
        println!(
            "width23_proven_conditional_subtractions={}",
            assert_horner_safety(23, candidate)
        );
        let maximum_factor = candidate
            .digits
            .iter()
            .copied()
            .skip(1)
            .map(|digit| candidate.base + digit)
            .chain(std::iter::once(candidate.digits[0]))
            .max()
            .expect("candidate has digits");
        println!("width23_maximum_unreduced_factor={maximum_factor}");
        println!(
            "width23_maximum_unreduced_value={}",
            u64::from(maximum_factor) * ((1u64 << 23) - 1)
        );
    } else if matches!(method, Method::Mixed233x196Plus5x29) {
        println!("mixed_expression=(233*196+5)*29");
        println!("width23_proven_conditional_subtractions=21");
        println!("width23_maximum_unreduced_factor=233");
        println!(
            "width23_maximum_unreduced_value={}",
            233u64 * ((1u64 << 23) - 1)
        );
    }
    println!("multiplier22_raw_bytes={multiplier22_raw}");
    println!("multiplier22_policy_bytes={multiplier22_policy}");
    println!("multiplier23_raw_bytes={multiplier23_raw}");
    println!("multiplier23_policy_bytes={multiplier23_policy}");
    println!("first_derive_raw_bytes={first_derive_raw}");
    println!("first_derive_policy_bytes={first_derive_policy}");
    println!("curve_derive_raw_bytes={curve_derive_raw}");
    println!("curve_derive_policy_bytes={curve_derive_policy}");
    println!("chained_derive_raw_bytes={chained_derive_raw}");
    println!("chained_derive_policy_bytes={chained_derive_policy}");
    println!("first_relation_raw_bytes={first_relation_raw}");
    println!("first_relation_policy_bytes={first_relation_policy}");
    println!("curve_relation_raw_bytes={curve_relation_raw}");
    println!("curve_relation_policy_bytes={curve_relation_policy}");
    println!("chained_relation_raw_bytes={chained_relation_raw}");
    println!("chained_relation_policy_bytes={chained_relation_policy}");
    println!("multiplier22_strict_peak={multiplier22_peak}");
    println!("multiplier23_strict_peak={multiplier23_peak}");
    println!("derive22_strict_peak={derive22_peak}");
    println!("derive_curve_strict_peak={derive_curve_peak}");
    println!("derive_chained_strict_peak={derive_chained_peak}");
    println!("first_relation_strict_peak={first_relation_peak}");
    println!("curve_relation_strict_peak={curve_relation_peak}");
    println!("chained_relation_strict_peak={chained_relation_peak}");
    println!("projected_88_relation_policy_bytes={projected_88_relation_bytes}");

    MethodMetrics {
        name: method.name(),
        multiplier22_policy,
        multiplier23_policy,
        first_relation_policy,
        curve_relation_policy,
        chained_relation_policy,
        projected_88_relation_bytes,
    }
}

fn main() {
    assert_eq!((19u64 * u64::from(INVERSE)) % (1 << 23), (1 << 23) - 1);
    let search22 = search_safe_unsigned_bases(22);
    let search23 = search_safe_unsigned_bases(23);
    let factored22 = search_factored_29_chains(22);
    let factored23 = search_factored_29_chains(23);
    let mut methods = vec![Method::Naf];
    methods.extend(HORNER_CANDIDATES.iter().copied().map(Method::Horner));
    methods.push(Method::Mixed233x196Plus5x29);
    let metrics = methods.into_iter().map(measure_method).collect::<Vec<_>>();
    let baseline = &metrics[0];
    let best = metrics
        .iter()
        .min_by_key(|metric| metric.projected_88_relation_bytes)
        .expect("at least one method");

    println!("model=ed25519_slope_quotient_radix_probe");
    println!("evidence=differentially-validated");
    println!("execution_class=unclassified");
    println!("incremental_hint_items_per_relation=0");
    println!("relation_invocations_projected=88");
    println!("baseline_method={}", baseline.name);
    println!("best_method={}", best.name);
    println!(
        "best_multiplier22_policy_delta={}",
        baseline.multiplier22_policy as isize - best.multiplier22_policy as isize
    );
    println!(
        "best_multiplier23_policy_delta={}",
        baseline.multiplier23_policy as isize - best.multiplier23_policy as isize
    );
    println!(
        "best_first_relation_policy_delta={}",
        baseline.first_relation_policy as isize - best.first_relation_policy as isize
    );
    println!(
        "best_curve_relation_policy_delta={}",
        baseline.curve_relation_policy as isize - best.curve_relation_policy as isize
    );
    println!(
        "best_chained_relation_policy_delta={}",
        baseline.chained_relation_policy as isize - best.chained_relation_policy as isize
    );
    println!(
        "projected_88_relation_policy_saving={}",
        baseline.projected_88_relation_bytes - best.projected_88_relation_bytes
    );
    println!("unsigned_safe_base_search_range=2..=512");
    println!("search22_best_base={}", search22.base);
    println!("search22_best_digits={:?}", search22.digits);
    println!("search22_best_raw_bytes={}", search22.raw_bytes);
    println!("search22_best_policy_bytes={}", search22.policy_bytes);
    println!(
        "search22_best_conditional_subtractions={}",
        search22.conditional_subtractions
    );
    println!("search22_best_maximum_factor={}", search22.maximum_factor);
    println!("search23_best_base={}", search23.base);
    println!("search23_best_digits={:?}", search23.digits);
    println!("search23_best_raw_bytes={}", search23.raw_bytes);
    println!("search23_best_policy_bytes={}", search23.policy_bytes);
    println!(
        "search23_best_conditional_subtractions={}",
        search23.conditional_subtractions
    );
    println!("search23_best_maximum_factor={}", search23.maximum_factor);
    println!("factor29_search_middle_range=2..=512");
    println!(
        "factor29_search22_best_expression=({}*{}+{})*29",
        factored22.initial, factored22.middle, factored22.digit
    );
    println!("factor29_search22_best_raw_bytes={}", factored22.raw_bytes);
    println!(
        "factor29_search22_best_policy_bytes={}",
        factored22.policy_bytes
    );
    println!(
        "factor29_search22_best_conditional_subtractions={}",
        factored22.conditional_subtractions
    );
    println!(
        "factor29_search22_best_maximum_factor={}",
        factored22.maximum_factor
    );
    println!(
        "factor29_search23_best_expression=({}*{}+{})*29",
        factored23.initial, factored23.middle, factored23.digit
    );
    println!("factor29_search23_best_raw_bytes={}", factored23.raw_bytes);
    println!(
        "factor29_search23_best_policy_bytes={}",
        factored23.policy_bytes
    );
    println!(
        "factor29_search23_best_conditional_subtractions={}",
        factored23.conditional_subtractions
    );
    println!(
        "factor29_search23_best_maximum_factor={}",
        factored23.maximum_factor
    );
    println!("strict_residue_boundaries_per_width=7");
    println!("strict_deterministic_random_residues_per_width=24");
    println!("strict_low_coefficient_cases_per_bound_vector=28");
    println!("accumulator_items_preserved_byte_for_byte=true");
    println!("whole_transition_or_leaf_executed=false");
    println!("production_default=mixed_233x196_plus5_x29");
    println!("probe_implementations_are_locally_isolated=true");
}
