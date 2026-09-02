//! Globally bound carry-RNS modular multiplication.
//!
//! This module closes the wraparound gap in the coordinate-only carry
//! verifier. Four hostile integers are supplied once as centered base-2^16
//! limbs. For every RNS prime, one exact dot-product carry derives the unique
//! canonical residue of each integer from those same limbs. The multiplication
//! relation therefore cannot mix coordinates belonging to different CRT
//! representatives.

use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};

use crate::{
    arithmetic::{scriptint, u31::U31_LOOKUP_STACK_LIMIT},
    support::script::*,
};

/// Prime basis selected for secp256k1-centered base-2^16 binding dot products.
///
/// Its product has 513 bits. Every prime also satisfies the exact worst-case
/// ScriptNum bound for a 16-term centered dot product.
pub const MODULI: [u32; 47] = [
    2, 17, 31, 41, 73, 113, 127, 241, 257, 283, 331, 337, 641, 673, 683, 1013, 1249, 1321, 1613,
    1801, 2089, 2113, 2351, 2731, 3121, 3203, 4051, 4513, 5153, 5419, 8123, 8161, 8191, 9719,
    12007, 13367, 14323, 14449, 15101, 15377, 17449, 18121, 20261, 21841, 43691, 61681, 65537,
];

/// Number of limbs in the shared unsigned 256-bit representation.
pub const LIMB_COUNT: u32 = 16;

/// Radix bit width of the shared representation.
pub const LIMB_BITS: u32 = 16;

/// Offset applied to each unsigned limb before it enters Script.
pub const LIMB_OFFSET: i32 = 1 << (LIMB_BITS - 1);

/// Number of residues in one bound RNS value.
pub const RESIDUE_COUNT: u32 = MODULI.len() as u32;

/// Four residue-binding carries plus one multiplication-relation carry.
pub const COORDINATE_HINT_ITEMS: u32 = 5;

/// Witness items consumed by one fused multiplication.
pub const HINTED_MUL_WITNESS_ITEMS: u32 = 4 * LIMB_COUNT + COORDINATE_HINT_ITEMS * RESIDUE_COUNT;

/// Exact strict combined-stack peak with no unrelated live items.
/// A regression test executes the measured path and locks this value down.
pub const HINTED_MUL_STACK_ITEMS: u32 = HINTED_MUL_WITNESS_ITEMS + 6;

/// Strict combined-stack peak for [`bind_value`] or [`bind_value_below`] with
/// no unrelated live items.
pub const BIND_VALUE_STACK_ITEMS: u32 = LIMB_COUNT + RESIDUE_COUNT + 10;

/// Exact byte attribution for the globally bound verifier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CostBreakdown {
    pub table_push: usize,
    pub table_drop: usize,
    pub range_checks: usize,
    pub residue_binding: usize,
    /// Includes whole-script optimizer effects across component boundaries.
    pub modular_relation: usize,
    pub routing_output: usize,
}

/// Exact byte attribution for certifying one reusable dual-representation
/// value with [`bind_value`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BindValueCostBreakdown {
    pub table_push: usize,
    pub table_drop: usize,
    pub limb_validation: usize,
    /// Includes whole-script optimizer effects across component boundaries.
    pub residue_binding: usize,
    pub routing_output: usize,
}

impl BindValueCostBreakdown {
    pub fn total(self) -> usize {
        self.table_push
            + self.table_drop
            + self.limb_validation
            + self.residue_binding
            + self.routing_output
    }
}

impl CostBreakdown {
    pub fn total(self) -> usize {
        self.table_push
            + self.table_drop
            + self.range_checks
            + self.residue_binding
            + self.modular_relation
            + self.routing_output
    }

    pub fn table_overhead(self) -> usize {
        self.table_push + self.table_drop
    }
}

fn center(residue: u32, modulus: u32) -> i32 {
    if residue > modulus / 2 {
        residue as i32 - modulus as i32
    } else {
        residue as i32
    }
}

#[cfg(test)]
fn is_prime(value: u32) -> bool {
    value >= 2 && (2..=((value as f64).sqrt() as u32)).all(|divisor| value % divisor != 0)
}

/// Return the product of the globally-bound basis.
pub fn modulus() -> BigUint {
    MODULI
        .iter()
        .fold(BigUint::one(), |product, modulus| product * modulus)
}

/// Encode an unsigned integer in the globally-bound basis.
pub fn encode(value: &BigUint) -> [u32; MODULI.len()] {
    std::array::from_fn(|index| {
        (value % MODULI[index])
            .to_u32()
            .expect("a residue must fit u32")
    })
}

/// Return the unique centered base-2^16 limb representation of `value`.
pub fn centered_limbs(value: &BigUint) -> [i32; LIMB_COUNT as usize] {
    assert!(value.bits() <= 256, "bound RNS value must fit in 256 bits");
    let mask = BigUint::from((1u32 << LIMB_BITS) - 1);
    std::array::from_fn(|index| {
        let limb = ((value >> (index as u32 * LIMB_BITS)) & &mask)
            .to_u32()
            .expect("a 16-bit limb must fit u32");
        limb as i32 - LIMB_OFFSET
    })
}

/// Push centered limbs with limb zero on top.
pub fn push_centered_limbs(limbs: &[i32; LIMB_COUNT as usize]) -> Script {
    script! {
        for limb in limbs.iter().rev() {
            { *limb }
        }
    }
}

/// Push the centered 256-bit representation of `value`.
pub fn push_value_limbs(value: &BigUint) -> Script {
    push_centered_limbs(&centered_limbs(value))
}

/// Push canonical RNS residues with coordinate zero on top.
pub fn push_residues(residues: &[u32; MODULI.len()]) -> Script {
    script! {
        for residue in residues.iter().rev() {
            { *residue }
        }
    }
}

/// Push the globally-bound RNS encoding of `value`.
pub fn push_value(value: &BigUint) -> Script {
    push_residues(&encode(value))
}

fn scaled_coordinate_coefficients(
    modulus: u32,
    scalar: u32,
) -> ([i32; LIMB_COUNT as usize], u32, u64) {
    let radix = (1u64 << LIMB_BITS) % u64::from(modulus);
    let mut power = scalar % modulus;
    let mut offset = 0i64;
    let mut sum_abs = 0u64;
    let coefficients = std::array::from_fn(|_| {
        let coefficient = center(power, modulus);
        offset += i64::from(coefficient) * i64::from(LIMB_OFFSET);
        sum_abs += u64::from(coefficient.unsigned_abs());
        power = (u64::from(power) * radix % u64::from(modulus)) as u32;
        coefficient
    });
    (
        coefficients,
        offset.rem_euclid(i64::from(modulus)) as u32,
        sum_abs,
    )
}

fn coordinate_coefficients(modulus: u32) -> ([i32; LIMB_COUNT as usize], u32, u64) {
    scaled_coordinate_coefficients(modulus, 1)
}

fn binding_carry_bound(modulus: u32) -> u32 {
    let (_, _, sum_abs) = coordinate_coefficients(modulus);
    let numerator_bound = u64::from(LIMB_OFFSET.unsigned_abs()) * sum_abs + 2 * u64::from(modulus);
    numerator_bound.div_ceil(u64::from(modulus)) as u32
}

fn safe_chain_mul(coefficient: i32, max_abs_input: u32) -> Option<Script> {
    if coefficient == 0 {
        return Some(script! { OP_DROP 0 });
    }
    if coefficient.unsigned_abs() > 1 << 16 {
        return None;
    }
    let predecessors = super::exact_chain_predecessors();
    let mut cursor = coefficient;
    let mut operations = Vec::new();
    let mut maximum = cursor.unsigned_abs();
    while cursor != 1 {
        let (previous, operation) = predecessors[super::exact_chain_index(cursor)]?;
        maximum = maximum.max(previous.unsigned_abs());
        operations.push(operation);
        cursor = previous;
    }
    if u64::from(maximum) * u64::from(max_abs_input) > u64::from(scriptint::MAX_SCRIPTNUM) {
        return None;
    }
    Some(super::exact_chain_mul(coefficient))
}

fn safe_exact_constant_mul(coefficient: i32, max_abs_input: u32) -> Script {
    let binary = script! {
        { scriptint::mul_by_constant(coefficient.unsigned_abs()) }
        if coefficient < 0 {
            OP_NEGATE
        }
    };
    let mut candidates = vec![binary];
    if let Some(chain) = safe_chain_mul(coefficient, max_abs_input) {
        candidates.push(chain);
    }
    candidates
        .into_iter()
        .min_by_key(|candidate| candidate.clone().compile_with_policy().len())
        .expect("constant multiplication has a safe candidate")
}

/// Derive the exact carry that binds each coordinate to one shared limb value.
pub fn binding_carries(value: &BigUint) -> [i32; MODULI.len()] {
    let limbs = centered_limbs(value);
    let residues = encode(value);
    std::array::from_fn(|index| {
        let modulus = i64::from(MODULI[index]);
        let (coefficients, offset, _) = coordinate_coefficients(MODULI[index]);
        let sum = coefficients
            .iter()
            .zip(limbs)
            .fold(i64::from(offset), |sum, (coefficient, limb)| {
                sum + i64::from(*coefficient) * i64::from(limb)
            });
        let numerator = sum - i64::from(residues[index]);
        assert_eq!(numerator % modulus, 0);
        i32::try_from(numerator / modulus).expect("a binding carry must fit i32")
    })
}

/// Derive the exact multiplication-relation carries.
pub fn relation_carries(
    lhs: &BigUint,
    rhs: &BigUint,
    quotient: &BigUint,
    remainder: &BigUint,
    target_modulus: &BigUint,
) -> [i32; MODULI.len()] {
    assert!(!target_modulus.is_zero(), "target modulus must be positive");
    assert!(
        target_modulus.bits() <= 256,
        "target modulus must fit in 256 bits"
    );
    assert!(lhs < target_modulus, "lhs must be below target modulus");
    assert!(rhs < target_modulus, "rhs must be below target modulus");
    assert!(quotient.bits() <= 256, "quotient must fit in 256 bits");
    assert!(
        remainder < target_modulus,
        "remainder must be below target modulus"
    );
    assert_eq!(lhs * rhs, quotient * target_modulus + remainder);

    let lhs = encode(lhs);
    let rhs = encode(rhs);
    let quotient = encode(quotient);
    let remainder = encode(remainder);
    let target = encode(target_modulus);
    std::array::from_fn(|index| {
        let modulus = i64::from(MODULI[index]);
        let _ = relation_carry_bound(MODULI[index], target[index]);
        let lhs = if centers_lhs_for_relation(MODULI[index], target[index]) {
            center(lhs[index], MODULI[index])
        } else {
            lhs[index] as i32
        };
        let numerator = i64::from(lhs) * i64::from(center(rhs[index], MODULI[index]))
            - i64::from(quotient[index]) * i64::from(center(target[index], MODULI[index]))
            - i64::from(remainder[index]);
        assert_eq!(numerator % modulus, 0);
        i32::try_from(numerator / modulus).expect("a relation carry must fit i32")
    })
}

/// Push the complete globally-bound multiplication witness.
///
/// The four limb vectors are pushed as `remainder | quotient | rhs | lhs` so
/// the three consumed vectors can be dropped without moving the returned
/// remainder limbs. Coordinate groups follow in reverse basis order and hold
/// `lhs_binding | rhs_binding | quotient_binding | remainder_binding |
/// relation`, leaving coordinate zero's relation carry on top.
pub fn push_hinted_witness(
    lhs: &BigUint,
    rhs: &BigUint,
    quotient: &BigUint,
    remainder: &BigUint,
    target_modulus: &BigUint,
) -> Script {
    let lhs_limbs = centered_limbs(lhs);
    let rhs_limbs = centered_limbs(rhs);
    let quotient_limbs = centered_limbs(quotient);
    let remainder_limbs = centered_limbs(remainder);
    let lhs_binding = binding_carries(lhs);
    let rhs_binding = binding_carries(rhs);
    let quotient_binding = binding_carries(quotient);
    let remainder_binding = binding_carries(remainder);
    let relation = relation_carries(lhs, rhs, quotient, remainder, target_modulus);

    script! {
        { push_centered_limbs(&remainder_limbs) }
        { push_centered_limbs(&quotient_limbs) }
        { push_centered_limbs(&rhs_limbs) }
        { push_centered_limbs(&lhs_limbs) }
        for index in (0..MODULI.len()).rev() {
            { lhs_binding[index] }
            { rhs_binding[index] }
            { quotient_binding[index] }
            { remainder_binding[index] }
            { relation[index] }
        }
    }
}

/// Push one reusable value-certification witness: 16 limbs followed by one
/// binding carry per coordinate, with coordinate zero's carry on top.
pub fn push_bind_value_witness(value: &BigUint) -> Script {
    let limbs = centered_limbs(value);
    let carries = binding_carries(value);
    script! {
        { push_centered_limbs(&limbs) }
        for carry in carries.iter().rev() {
            { *carry }
        }
    }
}

fn verify_limb_ranges(hint_items: u32) -> Script {
    script! {
        for index in 0..4 * LIMB_COUNT {
            { hint_items + index } OP_PICK
            { -LIMB_OFFSET } { LIMB_OFFSET }
            OP_WITHIN OP_VERIFY
        }
    }
}

fn fixed_centered_limbs(value: &BigUint) -> [i32; LIMB_COUNT as usize] {
    centered_limbs(value)
}

fn verify_vector_below_fixed(
    hint_items: u32,
    vector_from_top: u32,
    fixed: &[i32; LIMB_COUNT as usize],
) -> Script {
    let generic = script! {
        // Scan low to high. A more-significant comparison replaces the lower
        // result unless the current digits are equal.
        0
        for index in 0..LIMB_COUNT {
            { hint_items + vector_from_top * LIMB_COUNT + index + 1 } OP_PICK
            { fixed[index as usize] }
            OP_2DUP OP_EQUAL OP_TOALTSTACK
            OP_LESSTHAN
            OP_SWAP
            OP_FROMALTSTACK OP_BOOLAND
            OP_BOOLOR
        }
        OP_VERIFY
    };

    // secp256k1 is `ffff...ffff fffe ffff fc2f` in 16-bit limbs. Once limb
    // ranges are known, limbs 3..15 can only equal their all-ones target or
    // make the value smaller. Sum that run instead of repeating thirteen
    // full three-way lexicographic updates.
    let secp256k1_pattern = fixed[0] == 31_791
        && fixed[1] == 32_767
        && fixed[2] == 32_766
        && fixed[3..].iter().all(|limb| *limb == 32_767);
    if !secp256k1_pattern {
        return generic;
    }

    let base = hint_items + vector_from_top * LIMB_COUNT;
    let high_limb_sum = 13u32 * 32_767;
    let specialized = script! {
        // Limb one has the maximum valid value, so either it is already
        // smaller or limb zero decides the low 32 bits.
        { base } OP_PICK { fixed[0] } OP_LESSTHAN
        { base + 2 } OP_PICK { fixed[1] } OP_LESSTHAN OP_BOOLOR

        // Limb two may be smaller, equal, or greater than 0xfffe.
        { base + 3 } OP_PICK { fixed[2] }
        OP_2DUP OP_EQUAL OP_TOALTSTACK
        OP_LESSTHAN
        OP_SWAP
        OP_FROMALTSTACK OP_BOOLAND
        OP_BOOLOR

        // Every remaining target limb is the maximum valid centered limb.
        // Their sum reaches this constant iff all thirteen are equal.
        { base + 4 } OP_PICK
        for index in 4..LIMB_COUNT {
            { base + index + 2 } OP_PICK OP_ADD
        }
        { high_limb_sum } OP_LESSTHAN OP_BOOLOR
        OP_VERIFY
    };

    if specialized.clone().compile_with_policy().len() < generic.clone().compile_with_policy().len()
    {
        specialized
    } else {
        generic
    }
}

fn range_checks(target_modulus: &BigUint) -> Script {
    let target = fixed_centered_limbs(target_modulus);
    script! {
        // All coordinate hints have already moved to the altstack, leaving
        // the four limb vectors at shallow main-stack depths.
        { verify_limb_ranges(0) }
        // Limb vectors nearest the hints are lhs, rhs, quotient, remainder.
        { verify_vector_below_fixed(0, 0, &target) }
        { verify_vector_below_fixed(0, 1, &target) }
        { verify_vector_below_fixed(0, 3, &target) }
    }
}

fn independent_dot_sum(
    coefficients: &[i32; LIMB_COUNT as usize],
    offset: u32,
    limb_zero_depth: u32,
) -> Script {
    script! {
        { offset }
        for (index, coefficient) in coefficients.iter().copied().enumerate() {
            { limb_zero_depth + index as u32 + 1 } OP_PICK
            { safe_exact_constant_mul(coefficient, LIMB_OFFSET.unsigned_abs()) }
            OP_ADD
        }
    }
}

fn joint_naf_dot_core(coefficients: &[i32; LIMB_COUNT as usize], limb_zero_depth: u32) -> Script {
    let digits = coefficients.clone().map(|coefficient| {
        let sign = if coefficient < 0 { -1i8 } else { 1i8 };
        let mut remaining = coefficient.unsigned_abs();
        let mut scalar_digits = Vec::new();
        while remaining != 0 {
            if remaining & 1 == 0 {
                scalar_digits.push(0i8);
                remaining >>= 1;
            } else {
                let digit = 2i8 - (remaining % 4) as i8;
                scalar_digits.push(sign * digit);
                if digit > 0 {
                    remaining -= 1;
                } else {
                    remaining += 1;
                }
                remaining >>= 1;
            }
        }
        scalar_digits
    });
    let bit_count = digits.iter().map(Vec::len).max().unwrap_or(0);
    let mut initialized = false;
    let mut result = script! {};
    for bit in (0..bit_count).rev() {
        if initialized {
            result = script! { { result } OP_DUP OP_ADD };
        }
        for (index, scalar_digits) in digits.iter().enumerate() {
            let digit = scalar_digits.get(bit).copied().unwrap_or(0);
            if digit == 0 {
                continue;
            }
            let base = limb_zero_depth + index as u32;
            if !initialized {
                result = script! {
                    { result }
                    { base } OP_PICK
                    if digit < 0 { OP_NEGATE }
                };
                initialized = true;
            } else {
                result = script! {
                    { result }
                    { base + 1 } OP_PICK
                    if digit > 0 { OP_ADD } else { OP_SUB }
                };
            }
        }
    }
    if initialized {
        result
    } else {
        script! { 0 }
    }
}

fn gcd(mut lhs: u32, mut rhs: u32) -> u32 {
    while rhs != 0 {
        (lhs, rhs) = (rhs, lhs % rhs);
    }
    lhs
}

fn dot_sum(
    coefficients: &[i32; LIMB_COUNT as usize],
    offset: u32,
    future_hint_items: u32,
    prior_outputs: u32,
    vector_from_top: u32,
) -> Script {
    let limb_zero_depth = future_hint_items + prior_outputs + vector_from_top * LIMB_COUNT;
    let independent = independent_dot_sum(coefficients, offset, limb_zero_depth);
    let joint_core = joint_naf_dot_core(coefficients, limb_zero_depth);
    let joint = script! {
        { joint_core }
        if offset != 0 { { offset } OP_ADD }
    };

    let common = coefficients.iter().fold(0u32, |common, coefficient| {
        gcd(common, coefficient.unsigned_abs())
    });
    let factored = (common > 1).then(|| {
        let reduced = coefficients.map(|coefficient| coefficient / common as i32);
        let sum_abs = reduced
            .iter()
            .map(|coefficient| coefficient.unsigned_abs())
            .sum::<u32>();
        let maximum = LIMB_OFFSET.unsigned_abs() * sum_abs;
        script! {
            { joint_naf_dot_core(&reduced, limb_zero_depth) }
            { safe_exact_constant_mul(common as i32, maximum) }
            if offset != 0 { { offset } OP_ADD }
        }
    });
    [Some(independent), Some(joint), factored]
        .into_iter()
        .flatten()
        .min_by_key(|candidate| candidate.clone().compile_with_policy().len())
        .expect("dot sum has candidates")
}

fn binding_sum(
    modulus: u32,
    future_hint_items: u32,
    prior_outputs: u32,
    vector_from_top: u32,
) -> Script {
    let (coefficients, offset, _) = coordinate_coefficients(modulus);
    dot_sum(
        &coefficients,
        offset,
        future_hint_items,
        prior_outputs,
        vector_from_top,
    )
}

fn centers_lhs_for_product(modulus: u32) -> bool {
    u64::from(modulus - 1) * u64::from(modulus / 2) > u64::from(scriptint::MAX_SCRIPTNUM)
}

fn centers_lhs_for_relation(modulus: u32, target_residue: u32) -> bool {
    let product = u64::from(modulus - 1) * u64::from(modulus / 2);
    let quotient =
        u64::from(modulus - 1) * u64::from(center(target_residue, modulus).unsigned_abs());
    centers_lhs_for_product(modulus)
        || product + quotient + u64::from(modulus - 1) > u64::from(scriptint::MAX_SCRIPTNUM)
}

fn relation_numerator_bound(modulus: u32, target_residue: u32) -> u64 {
    let lhs_bound = if centers_lhs_for_relation(modulus, target_residue) {
        u64::from(modulus / 2)
    } else {
        u64::from(modulus - 1)
    };
    lhs_bound * u64::from(modulus / 2)
        + u64::from(modulus - 1) * u64::from(center(target_residue, modulus).unsigned_abs())
        + u64::from(modulus - 1)
}

fn relation_carry_bound(modulus: u32, target_residue: u32) -> u32 {
    let numerator_bound = relation_numerator_bound(modulus, target_residue);
    assert!(
        numerator_bound <= u64::from(scriptint::MAX_SCRIPTNUM),
        "target modulus is not ScriptNum-safe for the selected bound RNS basis"
    );
    numerator_bound.div_ceil(u64::from(modulus)) as u32
}

fn center_top(modulus: u32) -> Script {
    script! {
        { modulus } OP_OVER OP_SUB
        OP_2DUP OP_GREATERTHAN OP_TOALTSTACK
        OP_MIN
    }
}

fn exact_product(modulus: u32, center_lhs: bool) -> Script {
    if !center_lhs {
        return super::exact_centered_multiplier_mul(modulus);
    }
    script! {
        // Center lhs as well as rhs for the exceptional >16-bit coordinate.
        OP_SWAP
        { center_top(modulus) }
        OP_SWAP
        { super::exact_centered_multiplier_mul(modulus) }
        OP_FROMALTSTACK
        OP_IF OP_NEGATE OP_ENDIF
    }
}

struct CoordinateParts {
    binding: Script,
    relation: Script,
    route_output: Script,
}

fn coordinate_parts(index: usize, target_residue: u32) -> CoordinateParts {
    let modulus = MODULI[index];
    let prior_outputs = RESIDUE_COUNT - index as u32 - 1;
    let carry_bound = binding_carry_bound(modulus);
    let binding = script! {
        for value in 0..4u32 {
            { binding_sum(modulus, 0, prior_outputs + value, value) }
            OP_FROMALTSTACK
            { safe_exact_constant_mul(modulus as i32, carry_bound) }
            OP_SUB
            OP_DUP 0 { modulus } OP_WITHIN OP_VERIFY
        }
    };
    let centered_target = center(target_residue, modulus);
    let relation = script! {
        // Main: lhs_i | rhs_i | quotient_i | remainder_i.
        OP_FROMALTSTACK
        OP_SWAP OP_DUP OP_TOALTSTACK
        4 OP_ROLL 4 OP_ROLL
        { exact_product(modulus, centers_lhs_for_relation(modulus, target_residue)) }
        3 OP_ROLL
        { safe_exact_constant_mul(centered_target, modulus - 1) }
        OP_SUB OP_SWAP OP_SUB OP_SWAP
        {
            safe_exact_constant_mul(
                modulus as i32,
                relation_carry_bound(modulus, target_residue),
            )
        }
        OP_EQUALVERIFY
    };
    let route_output = script! {
        // The remainder was parked above the still-unconsumed hints while the
        // relation ran. Return it to the main stack before the next group.
        OP_FROMALTSTACK
    };
    CoordinateParts {
        binding,
        relation,
        route_output,
    }
}

fn move_coordinate_hints_to_altstack() -> Script {
    script! {
        // With the public reverse-coordinate witness order, moving every hint
        // at once leaves the highest coordinate's lhs carry on top. Coordinates can
        // then run high to low without deep limb picks through future hints.
        for _ in 0..COORDINATE_HINT_ITEMS * RESIDUE_COUNT {
            OP_TOALTSTACK
        }
    }
}

fn drop_consumed_limbs_and_restore_residues() -> Script {
    script! {
        // Residues were accumulated on the main stack from high coordinate to zero.
        // Park them now that the hint altstack is empty, expose and drop the
        // three consumed limb vectors, then restore coordinate zero on top.
        for _ in 0..RESIDUE_COUNT {
            OP_TOALTSTACK
        }
        // Witness ordering leaves the remainder limbs below the three
        // consumed vectors.
        for _ in 0..(3 * LIMB_COUNT) / 2 {
            OP_2DROP
        }
        for _ in 0..RESIDUE_COUNT {
            OP_FROMALTSTACK
        }
    }
}

fn bind_value_limb_validation() -> Script {
    script! {
        for index in 0..LIMB_COUNT {
            { RESIDUE_COUNT + index } OP_PICK
            { -LIMB_OFFSET } { LIMB_OFFSET }
            OP_WITHIN OP_VERIFY
        }
    }
}

fn bind_value_coordinate(index: usize) -> (Script, Script) {
    let modulus = MODULI[index];
    let future_carries = RESIDUE_COUNT - index as u32 - 1;
    let route = script! { OP_TOALTSTACK };
    let binding = script! {
        { binding_sum(modulus, future_carries, 0, 0) }
        OP_FROMALTSTACK
        { safe_exact_constant_mul(modulus as i32, binding_carry_bound(modulus)) }
        OP_SUB
        OP_DUP 0 { modulus } OP_WITHIN OP_VERIFY
        OP_TOALTSTACK
    };
    (route, binding)
}

fn restore_bound_value_residues() -> Script {
    script! {
        for _ in 0..RESIDUE_COUNT {
            OP_FROMALTSTACK
        }
    }
}

/// Bind one reusable 256-bit limb value to all 47 canonical RNS residues.
///
/// Input: `preserved | centered_limbs | binding_carries`. Output:
/// `preserved | centered_limbs | canonical_residues`. This proves the global
/// `<2^256` bound but deliberately does not compare the value with a field
/// modulus; callers can use [`bind_value_below`] when that predicate is needed.
pub fn bind_value(preserved_items: u32) -> Script {
    let peak = u64::from(preserved_items) + u64::from(BIND_VALUE_STACK_ITEMS);
    assert!(
        peak <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "bound RNS value certification exceeds Bitcoin Script's stack limit"
    );
    let coordinates = (0..MODULI.len())
        .map(bind_value_coordinate)
        .collect::<Vec<_>>();
    script! {
        { bind_value_limb_validation() }
        for (route, binding) in coordinates {
            { route }
            { binding }
        }
        { restore_bound_value_residues() }
    }
}

/// As [`bind_value`], additionally proving that the shared integer is below a
/// fixed positive 256-bit bound.
pub fn bind_value_below(bound: &BigUint, preserved_items: u32) -> Script {
    assert!(!bound.is_zero(), "bound must be positive");
    assert!(bound.bits() <= 256, "bound must fit in 256 bits");
    let peak = u64::from(preserved_items) + u64::from(BIND_VALUE_STACK_ITEMS);
    assert!(
        peak <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "bound RNS value certification exceeds Bitcoin Script's stack limit"
    );
    let fixed = centered_limbs(bound);
    let compare = verify_vector_below_fixed(RESIDUE_COUNT, 0, &fixed);
    let coordinates = (0..MODULI.len())
        .map(bind_value_coordinate)
        .collect::<Vec<_>>();
    script! {
        { bind_value_limb_validation() }
        { compare }
        // `bind_value` would repeat limb validation, so inline only its
        // coordinate certification and restoration.
        for (route, binding) in coordinates {
            { route }
            { binding }
        }
        { restore_bound_value_residues() }
    }
}

/// Exact cost split for [`bind_value`].
pub fn bind_value_cost_breakdown() -> BindValueCostBreakdown {
    let mut cost = BindValueCostBreakdown {
        limb_validation: bind_value_limb_validation().compile_with_policy().len(),
        routing_output: restore_bound_value_residues().compile_with_policy().len(),
        ..BindValueCostBreakdown::default()
    };
    for index in 0..MODULI.len() {
        let (route, binding) = bind_value_coordinate(index);
        cost.routing_output += route.compile_with_policy().len();
        cost.residue_binding += binding.compile_with_policy().len();
    }
    let independent_total = cost.total();
    let final_script_bytes = bind_value(0).compile_with_policy().len();
    attribute_compilation_delta(
        &mut cost.residue_binding,
        independent_total,
        final_script_bytes,
    );
    debug_assert_eq!(cost.total(), bind_value(0).compile_with_policy().len());
    cost
}

fn calculated_peak(preserved_items: u32) -> u64 {
    u64::from(preserved_items) + u64::from(HINTED_MUL_STACK_ITEMS)
}

/// Verify a globally-bound hinted modular multiplication.
///
/// The fragment proves that all four coordinate vectors come from the shared
/// unsigned 256-bit limb values, proves `lhs,rhs,remainder < target_modulus`,
/// and checks the 513-bit RNS product relation. It consumes lhs, rhs, and
/// quotient, returning both the 16 centered remainder limbs and its 47
/// canonical residues.
///
/// Consequently both `lhs * rhs` and `quotient * target_modulus + remainder`
/// are nonnegative and strictly below `2^512`. Their difference is divisible
/// by the 513-bit basis product, so the checked congruences imply the exact
/// integer equation rather than an equation after RNS wraparound.
///
/// The wide target-aware coordinates are optimized for secp256k1. Generation
/// rejects any other target whose exact relation prefixes could exceed the
/// four-byte ScriptNum arithmetic domain.
pub fn mul_mod_hinted(target_modulus: &BigUint, preserved_items: u32) -> Script {
    assert!(!target_modulus.is_zero(), "target modulus must be positive");
    assert!(
        target_modulus.bits() <= 256,
        "target modulus must fit in 256 bits"
    );
    assert!(
        calculated_peak(preserved_items) <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "globally-bound RNS multiplication exceeds Bitcoin Script's stack limit"
    );
    let target = encode(target_modulus);
    let coordinates = target
        .iter()
        .copied()
        .enumerate()
        .rev()
        .map(|(index, residue)| coordinate_parts(index, residue))
        .collect::<Vec<_>>();
    script! {
        { move_coordinate_hints_to_altstack() }
        { range_checks(target_modulus) }
        for coordinate in coordinates {
            { coordinate.binding }
            { coordinate.relation }
            { coordinate.route_output }
        }
        { drop_consumed_limbs_and_restore_residues() }
    }
}

/// Return exact static/computation byte attribution for [`mul_mod_hinted`].
pub fn cost_breakdown(target_modulus: &BigUint) -> CostBreakdown {
    assert!(!target_modulus.is_zero(), "target modulus must be positive");
    assert!(
        target_modulus.bits() <= 256,
        "target modulus must fit in 256 bits"
    );
    let target = encode(target_modulus);
    let mut cost = CostBreakdown {
        range_checks: range_checks(target_modulus).compile_with_policy().len(),
        routing_output: move_coordinate_hints_to_altstack()
            .compile_with_policy()
            .len()
            + drop_consumed_limbs_and_restore_residues()
                .compile_with_policy()
                .len(),
        ..CostBreakdown::default()
    };
    for (index, residue) in target.into_iter().enumerate().rev() {
        let coordinate = coordinate_parts(index, residue);
        cost.residue_binding += coordinate.binding.compile_with_policy().len();
        cost.modular_relation += coordinate.relation.compile_with_policy().len();
        cost.routing_output += coordinate.route_output.compile_with_policy().len();
    }
    let independent_total = cost.total();
    let final_script_bytes = mul_mod_hinted(target_modulus, 0)
        .compile_with_policy()
        .len();
    attribute_compilation_delta(
        &mut cost.modular_relation,
        independent_total,
        final_script_bytes,
    );
    debug_assert_eq!(
        cost.total(),
        mul_mod_hinted(target_modulus, 0)
            .compile_with_policy()
            .len()
    );
    cost
}

#[cfg(test)]
mod tests {
    use num_bigint::{BigUint, RandBigInt};
    use num_traits::{One, Zero};
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    fn secp256k1_modulus() -> BigUint {
        BigUint::parse_bytes(
            b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            16,
        )
        .unwrap()
    }

    fn execute_product(
        lhs: &BigUint,
        rhs: &BigUint,
        target: &BigUint,
    ) -> crate::support::execution::ExecuteInfo {
        let product = lhs * rhs;
        let quotient = &product / target;
        let remainder = &product % target;
        crate::support::execution::execute_script(script! {
            { push_hinted_witness(lhs, rhs, &quotient, &remainder, target) }
            { mul_mod_hinted(target, 0) }
            { push_value(&remainder) }
            for index in 0..RESIDUE_COUNT {
                { RESIDUE_COUNT - index } OP_ROLL OP_EQUALVERIFY
            }
            { push_value_limbs(&remainder) }
            for index in 0..LIMB_COUNT {
                { LIMB_COUNT - index } OP_ROLL OP_EQUALVERIFY
            }
            OP_TRUE
        })
    }

    #[test]
    fn basis_and_dot_products_fit_exact_scriptnum_bounds() {
        assert!(MODULI.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(MODULI.iter().all(|modulus| is_prime(*modulus)));
        assert!(modulus() > (BigUint::one() << 512usize));
        assert_eq!(modulus().bits(), 513);
        for modulus in MODULI {
            let (coefficients, _, sum_abs) = coordinate_coefficients(modulus);
            assert!(
                u64::from(LIMB_OFFSET.unsigned_abs()) * sum_abs + 2 * u64::from(modulus)
                    <= u64::from(scriptint::MAX_SCRIPTNUM)
            );
            for coefficient in coefficients {
                for limb in [-LIMB_OFFSET, LIMB_OFFSET - 1] {
                    let operation =
                        safe_exact_constant_mul(coefficient, LIMB_OFFSET.unsigned_abs());
                    let result = crate::support::execution::execute_script(script! {
                        { limb }
                        { operation }
                        { i64::from(limb) * i64::from(coefficient) }
                        OP_EQUAL
                    });
                    assert!(
                        result.success,
                        "{limb} * {coefficient} modulo-coordinate {modulus}: {result}"
                    );
                }
            }
        }
    }

    fn linear_extrema(coefficients: &[i32; LIMB_COUNT as usize], constant: i64) -> (i64, i64) {
        coefficients
            .iter()
            .fold((constant, constant), |(low, high), coefficient| {
                if *coefficient >= 0 {
                    (
                        low + i64::from(*coefficient) * -i64::from(LIMB_OFFSET),
                        high + i64::from(*coefficient) * i64::from(LIMB_OFFSET - 1),
                    )
                } else {
                    (
                        low + i64::from(*coefficient) * i64::from(LIMB_OFFSET - 1),
                        high + i64::from(*coefficient) * -i64::from(LIMB_OFFSET),
                    )
                }
            })
    }

    fn maximum_joint_naf_prefix(
        coefficients: &[i32; LIMB_COUNT as usize],
        final_offset: i64,
    ) -> u64 {
        let digits = coefficients.clone().map(|coefficient| {
            let sign = if coefficient < 0 { -1i8 } else { 1i8 };
            let mut remaining = coefficient.unsigned_abs();
            let mut scalar = Vec::new();
            while remaining != 0 {
                if remaining & 1 == 0 {
                    scalar.push(0);
                    remaining >>= 1;
                } else {
                    let digit = 2i8 - (remaining % 4) as i8;
                    scalar.push(sign * digit);
                    if digit > 0 {
                        remaining -= 1;
                    } else {
                        remaining += 1;
                    }
                    remaining >>= 1;
                }
            }
            scalar
        });
        let mut prefix = [0i32; LIMB_COUNT as usize];
        let mut initialized = false;
        let mut maximum = 0u64;
        let mut record = |prefix: &[i32; LIMB_COUNT as usize], constant| {
            let (low, high) = linear_extrema(prefix, constant);
            maximum = maximum.max(low.unsigned_abs()).max(high.unsigned_abs());
        };
        let bit_count = digits.iter().map(Vec::len).max().unwrap_or(0);
        for bit in (0..bit_count).rev() {
            if initialized {
                prefix.iter_mut().for_each(|coefficient| *coefficient *= 2);
                record(&prefix, 0);
            }
            for (index, scalar) in digits.iter().enumerate() {
                let digit = scalar.get(bit).copied().unwrap_or(0);
                if digit != 0 {
                    prefix[index] += i32::from(digit);
                    initialized = true;
                    record(&prefix, 0);
                }
            }
        }
        assert_eq!(&prefix, coefficients);
        record(&prefix, final_offset);
        maximum
    }

    #[test]
    fn every_joint_naf_prefix_fits_scriptnum() {
        let limit = i64::from(scriptint::MAX_SCRIPTNUM);
        let mut tightest = (u64::MAX, 0u32, 0i64);
        for modulus in MODULI {
            let (coefficients, offset, _) = coordinate_coefficients(modulus);
            let common = coefficients.iter().fold(0u32, |common, coefficient| {
                gcd(common, coefficient.unsigned_abs())
            });
            if common > 1 {
                let reduced = coefficients.map(|coefficient| coefficient / common as i32);
                assert!(
                    maximum_joint_naf_prefix(&reduced, 0) <= scriptint::MAX_SCRIPTNUM as u64,
                    "p={modulus}: gcd-factored inner dot prefix"
                );
            }
            let digits = coefficients.map(|coefficient| {
                let sign = if coefficient < 0 { -1i8 } else { 1i8 };
                let mut remaining = coefficient.unsigned_abs();
                let mut scalar = Vec::new();
                while remaining != 0 {
                    if remaining & 1 == 0 {
                        scalar.push(0);
                        remaining >>= 1;
                    } else {
                        let digit = 2i8 - (remaining % 4) as i8;
                        scalar.push(sign * digit);
                        if digit > 0 {
                            remaining -= 1;
                        } else {
                            remaining += 1;
                        }
                        remaining >>= 1;
                    }
                }
                scalar
            });
            let mut prefix = [0i32; LIMB_COUNT as usize];
            let mut initialized = false;
            let bit_count = digits.iter().map(Vec::len).max().unwrap_or(0);
            let mut check = |prefix: &[i32; LIMB_COUNT as usize], constant: i64| {
                let (low, high) = linear_extrema(prefix, constant);
                assert!(low >= -limit, "p={modulus}: prefix minimum {low}");
                assert!(high <= limit, "p={modulus}: prefix maximum {high}");
                let maximum = low.unsigned_abs().max(high.unsigned_abs());
                let margin = scriptint::MAX_SCRIPTNUM as u64 - maximum;
                if margin < tightest.0 {
                    tightest = (margin, modulus, maximum as i64);
                }
            };
            for bit in (0..bit_count).rev() {
                if initialized {
                    prefix.iter_mut().for_each(|coefficient| *coefficient *= 2);
                    check(&prefix, 0);
                }
                for (index, scalar) in digits.iter().enumerate() {
                    let digit = scalar.get(bit).copied().unwrap_or(0);
                    if digit != 0 {
                        prefix[index] += i32::from(digit);
                        initialized = true;
                        check(&prefix, 0);
                    }
                }
            }
            assert_eq!(prefix, coefficients);
            check(&prefix, i64::from(offset));
        }
        assert_eq!(tightest, (76_455, 43_691, 2_147_407_192));
    }

    #[test]
    fn relation_prefixes_and_double_centering_fit_scriptnum() {
        let target = secp256k1_modulus();
        let limit = u64::from(scriptint::MAX_SCRIPTNUM);
        for modulus in MODULI {
            let target_residue = (&target % modulus).to_u32().unwrap();
            assert!(relation_numerator_bound(modulus, target_residue) <= limit);
            let coefficient = center(target_residue, modulus);
            for quotient in [0, modulus - 1] {
                let result = crate::support::execution::execute_script(script! {
                    { quotient }
                    { safe_exact_constant_mul(coefficient, modulus - 1) }
                    { i64::from(quotient) * i64::from(coefficient) }
                    OP_EQUAL
                });
                assert!(result.success, "p={modulus}, q={quotient}: {result}");
            }
        }

        for modulus in [61_681u32, 65_537] {
            let target_residue = (&target % modulus).to_u32().unwrap();
            assert!(centers_lhs_for_relation(modulus, target_residue));
            for lhs in [0, modulus / 2, modulus / 2 + 1, modulus - 1] {
                for rhs in [0, modulus / 2, modulus / 2 + 1, modulus - 1] {
                    let expected =
                        i64::from(center(lhs, modulus)) * i64::from(center(rhs, modulus));
                    let result = crate::support::execution::execute_script(script! {
                        { lhs } { rhs }
                        { exact_product(modulus, true) }
                        { expected } OP_EQUAL
                    });
                    assert!(
                        result.success,
                        "p={modulus}, lhs={lhs}, rhs={rhs}: {result}"
                    );
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "target modulus is not ScriptNum-safe")]
    fn rejects_scriptnum_unsafe_target_profile() {
        let _ = mul_mod_hinted(&BigUint::from(32_768u32), 0);
    }

    #[test]
    fn bound_hinted_multiplication_accepts_boundaries_and_random_values() {
        let target = secp256k1_modulus();
        let mut rng = StdRng::seed_from_u64(0x424f_554e_445f_524e);
        let mut pairs = vec![
            (BigUint::zero(), BigUint::zero()),
            (BigUint::one(), &target - BigUint::one()),
            (&target - BigUint::one(), &target - BigUint::one()),
        ];
        for _ in 0..3 {
            pairs.push((
                rng.gen_biguint_below(&target),
                rng.gen_biguint_below(&target),
            ));
        }
        for (lhs, rhs) in pairs {
            let result = execute_product(&lhs, &rhs, &target);
            assert!(result.success, "{lhs} * {rhs}: {result}");
        }
    }

    #[test]
    fn rejects_wrong_binding_and_relation_carries() {
        let target = secp256k1_modulus();
        let lhs = BigUint::from(123_456_789u64);
        let rhs = &target - BigUint::from(77u32);
        let product = &lhs * &rhs;
        let quotient = &product / &target;
        let remainder = &product % &target;
        let lhs_limbs = centered_limbs(&lhs);
        let rhs_limbs = centered_limbs(&rhs);
        let quotient_limbs = centered_limbs(&quotient);
        let remainder_limbs = centered_limbs(&remainder);
        let lhs_binding = binding_carries(&lhs);
        let rhs_binding = binding_carries(&rhs);
        let quotient_binding = binding_carries(&quotient);
        let remainder_binding = binding_carries(&remainder);
        let relation = relation_carries(&lhs, &rhs, &quotient, &remainder, &target);

        for corrupted_class in 0..4 {
            let mut bindings = [
                lhs_binding,
                rhs_binding,
                quotient_binding,
                remainder_binding,
            ];
            bindings[corrupted_class][0] += 1;
            let bad_witness = script! {
                { push_centered_limbs(&remainder_limbs) }
                { push_centered_limbs(&quotient_limbs) }
                { push_centered_limbs(&rhs_limbs) }
                { push_centered_limbs(&lhs_limbs) }
                for index in (0..MODULI.len()).rev() {
                    { bindings[0][index] }
                    { bindings[1][index] }
                    { bindings[2][index] }
                    { bindings[3][index] }
                    { relation[index] }
                }
            };
            let result = crate::support::execution::execute_script(script! {
                { bad_witness }
                { mul_mod_hinted(&target, 0) }
                OP_TRUE
            });
            assert!(
                !result.success,
                "binding class {corrupted_class} accepted a bad carry"
            );
        }

        let mut bad_relation = relation;
        bad_relation[0] += 1;
        let bad_witness = script! {
            { push_centered_limbs(&remainder_limbs) }
            { push_centered_limbs(&quotient_limbs) }
            { push_centered_limbs(&rhs_limbs) }
            { push_centered_limbs(&lhs_limbs) }
            for index in (0..MODULI.len()).rev() {
                { lhs_binding[index] }
                { rhs_binding[index] }
                { quotient_binding[index] }
                { remainder_binding[index] }
                { bad_relation[index] }
            }
        };
        let result = crate::support::execution::execute_script(script! {
            { bad_witness }
            { mul_mod_hinted(&target, 0) }
            OP_TRUE
        });
        assert!(
            !result.success,
            "bad multiplication-relation carry accepted"
        );
    }

    #[test]
    fn rejects_detached_rns_wraparound_witness() {
        let target = secp256k1_modulus();
        let product_modulus = modulus();
        let detached_quotient = &product_modulus / &target;
        let remainder = &product_modulus % &target;
        assert!(detached_quotient.bits() > 256);
        assert_eq!(&detached_quotient * &target + &remainder, product_modulus);

        // Coordinatewise, `0 = detached_quotient * target + remainder`
        // holds modulo every RNS prime. The old unbound construction could
        // therefore accept this wrapped equation. Give the bounded verifier
        // the low 256 bits as its unrelated limb-level quotient while keeping
        // relation carries for the detached, oversized quotient coordinates.
        // Its limb-to-residue bindings must make those views disagree.
        let limb_mask = (BigUint::one() << 256usize) - BigUint::one();
        let bounded_quotient = &detached_quotient & limb_mask;
        let zero = BigUint::zero();
        let zero_limbs = centered_limbs(&zero);
        let quotient_limbs = centered_limbs(&bounded_quotient);
        let remainder_limbs = centered_limbs(&remainder);
        let zero_binding = binding_carries(&zero);
        let quotient_binding = binding_carries(&bounded_quotient);
        let remainder_binding = binding_carries(&remainder);

        let detached_quotient_residues = encode(&detached_quotient);
        let remainder_residues = encode(&remainder);
        let target_residues = encode(&target);
        let detached_relation: [i32; MODULI.len()] = std::array::from_fn(|index| {
            let prime = i64::from(MODULI[index]);
            let numerator = -i64::from(detached_quotient_residues[index])
                * i64::from(center(target_residues[index], MODULI[index]))
                - i64::from(remainder_residues[index]);
            assert_eq!(numerator % prime, 0);
            i32::try_from(numerator / prime).expect("detached relation carry fits i32")
        });

        let witness = script! {
            { push_centered_limbs(&remainder_limbs) }
            { push_centered_limbs(&quotient_limbs) }
            { push_centered_limbs(&zero_limbs) }
            { push_centered_limbs(&zero_limbs) }
            for index in (0..MODULI.len()).rev() {
                { zero_binding[index] }
                { zero_binding[index] }
                { quotient_binding[index] }
                { remainder_binding[index] }
                { detached_relation[index] }
            }
        };
        let result = crate::support::execution::execute_script(script! {
            { witness }
            { mul_mod_hinted(&target, 0) }
            OP_TRUE
        });
        assert!(
            !result.success,
            "detached coordinate wraparound witness was accepted"
        );
    }

    #[test]
    fn reusable_value_binding_returns_limbs_and_residues() {
        let target = secp256k1_modulus();
        for value in [BigUint::zero(), BigUint::one(), &target - BigUint::one()] {
            let result = crate::support::execution::execute_script(script! {
                { push_bind_value_witness(&value) }
                { bind_value_below(&target, 0) }
                { push_value(&value) }
                for index in 0..RESIDUE_COUNT {
                    { RESIDUE_COUNT - index } OP_ROLL OP_EQUALVERIFY
                }
                { push_value_limbs(&value) }
                for index in 0..LIMB_COUNT {
                    { LIMB_COUNT - index } OP_ROLL OP_EQUALVERIFY
                }
                OP_TRUE
            });
            assert!(result.success, "reusable binding for {value}: {result}");
        }

        let result = crate::support::execution::execute_script(script! {
            { push_bind_value_witness(&target) }
            { bind_value_below(&target, 0) }
            OP_TRUE
        });
        assert!(!result.success, "strict field bound accepted equality");
    }

    #[test]
    fn fixed_comparator_matches_unsigned_order_across_target_shapes() {
        let accepts = |value: &BigUint, target: &BigUint| {
            let fixed = fixed_centered_limbs(target);
            crate::support::execution::execute_script(script! {
                { push_value_limbs(value) }
                { verify_vector_below_fixed(0, 0, &fixed) }
                for _ in 0..LIMB_COUNT / 2 {
                    OP_2DROP
                }
                OP_TRUE
            })
            .success
        };

        let one = BigUint::one();
        let maximum = (&one << 256usize) - &one;
        let targets = [
            one.clone(),
            BigUint::from(2u32),
            BigUint::from(65_535u32),
            BigUint::from(65_536u32),
            BigUint::from(65_537u32),
            (&one << 128usize) + BigUint::from(0x1234_5678u32),
            maximum.clone(),
            secp256k1_modulus(),
        ];
        for target in targets {
            let below = &target - &one;
            assert!(accepts(&below, &target), "target {target}: target - 1");
            assert!(!accepts(&target, &target), "target {target}: equality");
            if target < maximum {
                let above = &target + &one;
                assert!(!accepts(&above, &target), "target {target}: target + 1");
            }
        }

        // Exercise comparisons decided above the low limb, including both
        // optimized secp256k1 branches around its 0xfffe limb.
        let wide_target = (&one << 128usize) + BigUint::from(0x1234_5678u32);
        assert!(accepts(&((&one << 128usize) - &one), &wide_target));
        let secp = secp256k1_modulus();
        assert!(accepts(&(&secp - (&one << 48usize)), &secp));
        assert!(!accepts(&(&secp + (&one << 32usize)), &secp));
    }

    #[test]
    fn reusable_value_binding_stack_guard_is_exact() {
        let target = secp256k1_modulus();
        let value = BigUint::zero();
        let preserved_items = U31_LOOKUP_STACK_LIMIT - BIND_VALUE_STACK_ITEMS;
        let output_items = preserved_items + LIMB_COUNT + RESIDUE_COUNT;

        for operation in [
            bind_value(preserved_items),
            bind_value_below(&target, preserved_items),
        ] {
            let result = crate::support::execution::execute_script(script! {
                for _ in 0..preserved_items {
                    0
                }
                { push_bind_value_witness(&value) }
                { operation }
                for _ in 0..output_items / 2 {
                    OP_2DROP
                }
                if output_items % 2 != 0 {
                    OP_DROP
                }
                OP_TRUE
            });
            assert!(result.success, "exact bind-value stack boundary: {result}");
            assert_eq!(
                result.stats.max_nb_stack_items,
                U31_LOOKUP_STACK_LIMIT as usize
            );
        }

        let rejected_items = preserved_items + 1;
        assert!(std::panic::catch_unwind(|| bind_value(rejected_items)).is_err());
        assert!(std::panic::catch_unwind(|| bind_value_below(&target, rejected_items)).is_err());
    }

    #[test]
    fn fused_verifier_rejects_field_range_violations() {
        let target = secp256k1_modulus();
        // The helper intentionally refuses invalid arithmetic witnesses, so
        // reuse a valid zero product's carries and replace only lhs limbs with
        // the exactly-equal-to-N encoding. The range prelude must fail before
        // any coordinate relation is considered.
        let zero = BigUint::zero();
        let zero_limbs = centered_limbs(&zero);
        let binding = binding_carries(&zero);
        let relation = relation_carries(&zero, &zero, &zero, &zero, &target);
        for violation in 0..3 {
            let mut limbs = [zero_limbs; 4];
            match violation {
                0 => limbs[3] = centered_limbs(&target), // lhs = N
                1 => limbs[2] = centered_limbs(&target), // rhs = N
                2 => limbs[0] = centered_limbs(&target), // remainder = N
                _ => unreachable!(),
            }
            let witness = script! {
                { push_centered_limbs(&limbs[0]) }
                { push_centered_limbs(&limbs[1]) }
                { push_centered_limbs(&limbs[2]) }
                { push_centered_limbs(&limbs[3]) }
                for index in (0..MODULI.len()).rev() {
                    { binding[index] }
                    { binding[index] }
                    { binding[index] }
                    { binding[index] }
                    { relation[index] }
                }
            };
            let result = crate::support::execution::execute_script(script! {
                { witness }
                { mul_mod_hinted(&target, 0) }
                OP_TRUE
            });
            assert!(!result.success, "range violation {violation} was accepted");
        }

        let mut bad_lhs_limbs = zero_limbs;
        bad_lhs_limbs[0] = LIMB_OFFSET;
        let witness = script! {
            { push_centered_limbs(&zero_limbs) }
            { push_centered_limbs(&zero_limbs) }
            { push_centered_limbs(&zero_limbs) }
            { push_centered_limbs(&bad_lhs_limbs) }
            for index in (0..MODULI.len()).rev() {
                { binding[index] }
                { binding[index] }
                { binding[index] }
                { binding[index] }
                { relation[index] }
            }
        };
        let result = crate::support::execution::execute_script(script! {
            { witness }
            { mul_mod_hinted(&target, 0) }
            OP_TRUE
        });
        assert!(!result.success, "out-of-range centered limb was accepted");
    }

    #[test]
    fn strict_peak_matches_the_declared_guard() {
        let target = secp256k1_modulus();
        let lhs = &target - BigUint::one();
        let product = &lhs * &lhs;
        let quotient = &product / &target;
        let remainder = &product % &target;
        let result = crate::support::execution::execute_script(script! {
            { push_hinted_witness(&lhs, &lhs, &quotient, &remainder, &target) }
            { mul_mod_hinted(&target, 0) }
            for _ in 0..(LIMB_COUNT + RESIDUE_COUNT) / 2 {
                OP_2DROP
            }
            if (LIMB_COUNT + RESIDUE_COUNT) % 2 != 0 { OP_DROP }
            OP_TRUE
        });
        assert!(result.success, "strict peak execution failed: {result}");
        assert_eq!(
            result.stats.max_nb_stack_items,
            HINTED_MUL_STACK_ITEMS as usize
        );

        let result = crate::support::execution::execute_script(script! {
            101 OP_TOALTSTACK
            102
            { push_hinted_witness(&lhs, &lhs, &quotient, &remainder, &target) }
            { mul_mod_hinted(&target, 2) }
            for _ in 0..(LIMB_COUNT + RESIDUE_COUNT) / 2 {
                OP_2DROP
            }
            if (LIMB_COUNT + RESIDUE_COUNT) % 2 != 0 { OP_DROP }
            102 OP_EQUALVERIFY
            OP_FROMALTSTACK 101 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "preserved-state execution failed: {result}");

        let preserved = U31_LOOKUP_STACK_LIMIT - HINTED_MUL_STACK_ITEMS;
        let result = crate::support::execution::execute_script(script! {
            for _ in 0..preserved {
                0
            }
            { push_hinted_witness(&lhs, &lhs, &quotient, &remainder, &target) }
            { mul_mod_hinted(&target, preserved) }
            for _ in 0..(LIMB_COUNT + RESIDUE_COUNT) / 2 {
                OP_2DROP
            }
            if (LIMB_COUNT + RESIDUE_COUNT) % 2 != 0 { OP_DROP }
            for _ in 0..preserved / 2 {
                OP_2DROP
            }
            if preserved % 2 != 0 {
                OP_DROP
            }
            OP_TRUE
        });
        assert!(result.success, "1,000-item execution failed: {result}");
        assert_eq!(result.stats.max_nb_stack_items, 1_000);
    }

    #[test]
    #[should_panic(
        expected = "globally-bound RNS multiplication exceeds Bitcoin Script's stack limit"
    )]
    fn rejects_one_item_beyond_the_stack_guard() {
        let target = secp256k1_modulus();
        let _ = mul_mod_hinted(&target, U31_LOOKUP_STACK_LIMIT - HINTED_MUL_STACK_ITEMS + 1);
    }

    #[test]
    fn exact_cost_breakdown_matches_generated_script() {
        let target = secp256k1_modulus();
        let cost = cost_breakdown(&target);
        assert_eq!(cost.table_push, 0);
        assert_eq!(cost.table_drop, 0);
        assert_eq!(
            cost.total(),
            mul_mod_hinted(&target, 0).compile_with_policy().len()
        );
        eprintln!("bound carry cost: {cost:?}, total={}", cost.total());

        let bind_cost = bind_value_cost_breakdown();
        assert_eq!(bind_cost.table_push, 0);
        assert_eq!(bind_cost.table_drop, 0);
        assert_eq!(bind_cost.total(), bind_value(0).compile_with_policy().len());
        eprintln!(
            "one-value bind cost: {bind_cost:?}, total={}",
            bind_cost.total()
        );
    }
}
