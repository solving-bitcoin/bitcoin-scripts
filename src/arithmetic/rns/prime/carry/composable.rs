//! Composable, globally sound secp256k1 residue multiplication.
//!
//! This module separates the global-binding cost from each multiplication.
//! [`bind_value`] introduces a field element by tying one centered 256-bit
//! limb vector to every residue in this module's basis. [`mul_mod_hinted`]
//! then consumes two such certified residue vectors, binds only the hostile
//! quotient and new remainder, and returns a certified remainder vector. A
//! returned vector can therefore feed the next multiplication directly.
//!
//! The multiplication fragment is sound only when both operand vectors were
//! established by [`bind_value`] (or an equivalent global proof binding every
//! coordinate to one shared secp256k1 field integer) and have remained on the
//! verified script path. Raw witness residue vectors and independent
//! coordinate-local proofs do not satisfy that precondition.

use num_bigint::BigUint;
use num_traits::{One, ToPrimitive};

use crate::{
    arithmetic::{scriptint, u31::U31_LOOKUP_STACK_LIMIT},
    support::script::*,
};

/// Prime basis selected for one reusable binding or two per multiplication.
///
/// Its product is strictly greater than `2^512`. The three primes above the
/// conventional signed-16-bit range use a centered-both product core; 65537
/// also exploits `2^16 = -1 (mod 65537)` in the limb bindings.
pub const MODULI: [u32; 46] = [
    17, 31, 41, 73, 113, 127, 241, 257, 331, 337, 397, 641, 673, 683, 1013, 1249, 1321, 1613, 1801,
    2089, 2113, 2351, 2731, 3121, 4051, 4057, 4513, 5153, 5419, 8123, 8161, 8191, 9719, 12007,
    13367, 14323, 14449, 15101, 15121, 15377, 17449, 20261, 21841, 43691, 61681, 65537,
];

/// Number of centered base-`2^16` limbs in one shared integer.
pub const LIMB_COUNT: u32 = super::bound::LIMB_COUNT;

/// Radix bit width of one shared-integer limb.
pub const LIMB_BITS: u32 = super::bound::LIMB_BITS;

/// Offset used to turn a centered limb into its unsigned base-`2^16` digit.
pub const LIMB_OFFSET: i32 = super::bound::LIMB_OFFSET;

/// Number of residues in one certified value.
pub const RESIDUE_COUNT: u32 = MODULI.len() as u32;

/// Quotient binding, remainder binding, and relation carry per coordinate.
pub const COORDINATE_HINT_ITEMS: u32 = 3;

/// Incremental witness items consumed by one multiplication.
///
/// The two certified operand vectors are live script state and are excluded.
pub const HINTED_MUL_WITNESS_ITEMS: u32 = 2 * LIMB_COUNT + COORDINATE_HINT_ITEMS * RESIDUE_COUNT;

/// Exact combined-stack peak for [`mul_mod_hinted`] without unrelated state.
pub const HINTED_MUL_STACK_ITEMS: u32 = 2 * RESIDUE_COUNT + HINTED_MUL_WITNESS_ITEMS + 5;

/// Witness items consumed by [`bind_value`].
pub const BIND_VALUE_WITNESS_ITEMS: u32 = LIMB_COUNT + RESIDUE_COUNT;

/// Exact combined-stack peak for [`bind_value`] without unrelated state.
pub const BIND_VALUE_STACK_ITEMS: u32 = BIND_VALUE_WITNESS_ITEMS + 10;

/// Exact byte attribution for the composable multiplication fragment.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CostBreakdown {
    pub table_push: usize,
    pub table_drop: usize,
    /// Quotient/remainder limb ranges plus the `remainder < secp256k1` check.
    pub field_validation: usize,
    pub quotient_binding: usize,
    pub remainder_binding: usize,
    pub modular_relation: usize,
    pub routing_output: usize,
}

impl CostBreakdown {
    pub fn total(self) -> usize {
        self.table_push
            + self.table_drop
            + self.field_validation
            + self.quotient_binding
            + self.remainder_binding
            + self.modular_relation
            + self.routing_output
    }

    pub fn table_overhead(self) -> usize {
        self.table_push + self.table_drop
    }
}

/// Exact byte attribution for introducing one certified field value.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BindValueCostBreakdown {
    pub table_push: usize,
    pub table_drop: usize,
    /// Limb ranges plus the `value < secp256k1` check.
    pub limb_and_field_validation: usize,
    pub residue_binding: usize,
    pub routing_output: usize,
}

impl BindValueCostBreakdown {
    pub fn total(self) -> usize {
        self.table_push
            + self.table_drop
            + self.limb_and_field_validation
            + self.residue_binding
            + self.routing_output
    }

    pub fn table_overhead(self) -> usize {
        self.table_push + self.table_drop
    }
}

fn target_modulus() -> BigUint {
    BigUint::parse_bytes(
        b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        16,
    )
    .expect("the secp256k1 modulus is valid hexadecimal")
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

/// Return the product of the composable basis.
pub fn modulus() -> BigUint {
    MODULI
        .iter()
        .fold(BigUint::one(), |product, modulus| product * modulus)
}

/// Encode an unsigned integer in the composable basis.
pub fn encode(value: &BigUint) -> [u32; MODULI.len()] {
    std::array::from_fn(|index| {
        (value % MODULI[index])
            .to_u32()
            .expect("a residue must fit u32")
    })
}

/// Return the centered base-`2^16` representation of a 256-bit integer.
pub fn centered_limbs(value: &BigUint) -> [i32; LIMB_COUNT as usize] {
    super::bound::centered_limbs(value)
}

/// Push centered limbs with limb zero on top.
pub fn push_centered_limbs(limbs: &[i32; LIMB_COUNT as usize]) -> Script {
    super::bound::push_centered_limbs(limbs)
}

/// Push canonical residues with coordinate zero on top.
pub fn push_residues(residues: &[u32; MODULI.len()]) -> Script {
    script! {
        for residue in residues.iter().rev() {
            { *residue }
        }
    }
}

/// Push the composable residue encoding of `value`.
pub fn push_value(value: &BigUint) -> Script {
    push_residues(&encode(value))
}

fn coordinate_coefficients(modulus: u32) -> ([i32; LIMB_COUNT as usize], u32, u64) {
    let radix = (1u64 << LIMB_BITS) % u64::from(modulus);
    let mut power = 1u32;
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

fn binding_carry_bound(modulus: u32) -> u32 {
    let (_, _, sum_abs) = coordinate_coefficients(modulus);
    let numerator_bound = u64::from(LIMB_OFFSET.unsigned_abs()) * sum_abs + 2 * u64::from(modulus);
    numerator_bound.div_ceil(u64::from(modulus)) as u32
}

fn safe_chain_mul(coefficient: i32, max_abs_input: u32) -> Option<Script> {
    if coefficient == 0 {
        return Some(script! { OP_DROP 0 });
    }
    if coefficient.unsigned_abs() > super::EXACT_CHAIN_BOUND as u32 {
        return None;
    }
    let predecessors = super::exact_chain_predecessors();
    let mut cursor = coefficient;
    let mut maximum = cursor.unsigned_abs();
    while cursor != 1 {
        let (previous, _) = predecessors[super::exact_chain_index(cursor)]?;
        maximum = maximum.max(previous.unsigned_abs());
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
        .min_by_key(|candidate| candidate.clone().compile().len())
        .expect("constant multiplication has a safe candidate")
}

fn independent_dot_sum(
    coefficients: &[i32; LIMB_COUNT as usize],
    offset: u32,
    limb_zero_depth: u32,
    check_limbs: bool,
) -> Script {
    script! {
        { offset }
        for (index, coefficient) in coefficients.iter().copied().enumerate() {
            { limb_zero_depth + index as u32 + 1 } OP_PICK
            if check_limbs {
                OP_DUP { -LIMB_OFFSET } { LIMB_OFFSET } OP_WITHIN OP_VERIFY
            }
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

fn limb_range_checks(limb_zero_depth: u32) -> Script {
    script! {
        for index in 0..LIMB_COUNT {
            { limb_zero_depth + index } OP_PICK
            { -LIMB_OFFSET } { LIMB_OFFSET } OP_WITHIN OP_VERIFY
        }
    }
}

fn dot_sum(
    coefficients: &[i32; LIMB_COUNT as usize],
    offset: u32,
    limb_zero_depth: u32,
    check_limbs: bool,
) -> Script {
    let independent = independent_dot_sum(coefficients, offset, limb_zero_depth, check_limbs);
    let checks = check_limbs.then(|| limb_range_checks(limb_zero_depth));
    let joint = script! {
        if let Some(checks) = checks.clone() { { checks } }
        { joint_naf_dot_core(coefficients, limb_zero_depth) }
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
            if let Some(checks) = checks { { checks } }
            { joint_naf_dot_core(&reduced, limb_zero_depth) }
            { safe_exact_constant_mul(common as i32, maximum) }
            if offset != 0 { { offset } OP_ADD }
        }
    });
    [Some(independent), Some(joint), factored]
        .into_iter()
        .flatten()
        .min_by_key(|candidate| candidate.clone().compile().len())
        .expect("dot sum has candidates")
}

fn centered_both_variable_mul(modulus: u32) -> Script {
    if modulus <= 32_767 {
        return super::exact_centered_multiplier_mul(modulus);
    }
    script! {
        OP_SWAP
        OP_DUP { modulus / 2 } OP_GREATERTHAN
        OP_IF
            { modulus } OP_SUB
        OP_ENDIF
        OP_SWAP
        { super::exact_centered_multiplier_mul(modulus) }
    }
}

fn variable_product_bound(modulus: u32) -> u64 {
    if modulus <= 32_767 {
        u64::from(modulus - 1) * u64::from(modulus / 2)
    } else {
        u64::from(modulus / 2).pow(2)
    }
}

fn relation_carry_bound(modulus: u32, target_residue: i32) -> u32 {
    let numerator_bound = variable_product_bound(modulus)
        + u64::from(modulus - 1) * u64::from(target_residue.unsigned_abs())
        + u64::from(modulus - 1);
    numerator_bound.div_ceil(u64::from(modulus)) as u32
}

/// Return every carry that binds `value` to its canonical residue vector.
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

/// Return every exact multiplication-relation carry.
pub fn relation_carries(
    lhs: &BigUint,
    rhs: &BigUint,
    quotient: &BigUint,
    remainder: &BigUint,
) -> [i32; MODULI.len()] {
    let target = target_modulus();
    assert!(lhs < &target, "lhs must be a field element");
    assert!(rhs < &target, "rhs must be a field element");
    assert!(quotient.bits() <= 256, "quotient must fit in 256 bits");
    assert!(remainder < &target, "remainder must be a field element");
    assert_eq!(lhs * rhs, quotient * &target + remainder);

    let lhs = encode(lhs);
    let rhs = encode(rhs);
    let quotient = encode(quotient);
    let remainder = encode(remainder);
    let target = encode(&target);
    std::array::from_fn(|index| {
        let modulus = MODULI[index];
        let lhs = if modulus <= 32_767 {
            lhs[index] as i32
        } else {
            center(lhs[index], modulus)
        };
        let numerator = i64::from(lhs) * i64::from(center(rhs[index], modulus))
            - i64::from(quotient[index]) * i64::from(center(target[index], modulus))
            - i64::from(remainder[index]);
        assert_eq!(numerator % i64::from(modulus), 0);
        i32::try_from(numerator / i64::from(modulus))
            .expect("a multiplication-relation carry must fit i32")
    })
}

/// Push one reusable field-value certification witness.
///
/// Limb zero and then coordinate zero's binding carry are nearest the top of
/// their respective groups.
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

/// Push the incremental witness for [`mul_mod_hinted`].
///
/// The caller first places certified `lhs` and `rhs` residue vectors. This
/// helper then pushes quotient limbs, remainder limbs, and reverse-coordinate
/// groups `q_binding | r_binding | relation`.
pub fn push_hinted_witness(
    lhs: &BigUint,
    rhs: &BigUint,
    quotient: &BigUint,
    remainder: &BigUint,
) -> Script {
    let quotient_limbs = centered_limbs(quotient);
    let remainder_limbs = centered_limbs(remainder);
    let quotient_binding = binding_carries(quotient);
    let remainder_binding = binding_carries(remainder);
    let relation = relation_carries(lhs, rhs, quotient, remainder);
    script! {
        { push_centered_limbs(&quotient_limbs) }
        { push_centered_limbs(&remainder_limbs) }
        for index in (0..MODULI.len()).rev() {
            { quotient_binding[index] }
            { remainder_binding[index] }
            { relation[index] }
        }
    }
}

fn binding_sum(modulus: u32, limb_zero_depth: u32, check_limbs: bool) -> Script {
    let (coefficients, offset, _) = coordinate_coefficients(modulus);
    dot_sum(&coefficients, offset, limb_zero_depth, check_limbs)
}

fn bind_from_main_carry(modulus: u32, limb_zero_depth: u32, check_limbs: bool) -> Script {
    script! {
        { binding_sum(modulus, limb_zero_depth, check_limbs) }
        OP_SWAP
        { safe_exact_constant_mul(modulus as i32, binding_carry_bound(modulus)) }
        OP_SUB
        OP_DUP 0 { modulus } OP_WITHIN OP_VERIFY
    }
}

fn verify_below_secp256k1(base: u32) -> Script {
    script! {
        // Centered target limbs are 0x7c2f, 0x7fff, 0x7ffe, then 0x7fff x13.
        { base } OP_PICK 31791 OP_LESSTHAN
        { base + 2 } OP_PICK 32767 OP_LESSTHAN OP_BOOLOR

        { base + 3 } OP_PICK 32766
        OP_2DUP OP_EQUAL OP_TOALTSTACK
        OP_LESSTHAN
        OP_SWAP OP_FROMALTSTACK OP_BOOLAND OP_BOOLOR

        { base + 4 } OP_PICK
        for index in 4..LIMB_COUNT {
            { base + index + 2 } OP_PICK OP_ADD
        }
        { 13 * 32767 } OP_LESSTHAN OP_BOOLOR
        OP_VERIFY
    }
}

fn restore_residues() -> Script {
    script! {
        for _ in 0..RESIDUE_COUNT {
            OP_FROMALTSTACK
        }
    }
}

fn bind_value_coordinate(index: usize, check_limbs: bool) -> (Script, Script) {
    let modulus = MODULI[index];
    let future_carries = RESIDUE_COUNT - index as u32 - 1;
    let route = script! { OP_TOALTSTACK };
    let binding = script! {
        { binding_sum(modulus, future_carries, check_limbs) }
        OP_FROMALTSTACK
        { safe_exact_constant_mul(modulus as i32, binding_carry_bound(modulus)) }
        OP_SUB
        OP_DUP 0 { modulus } OP_WITHIN OP_VERIFY
        OP_TOALTSTACK
    };
    (route, binding)
}

/// Certify one witness field element and return only its canonical residues.
///
/// Input: `preserved | centered_limbs | binding_carries`.
/// Output: `preserved | canonical_residues`, with coordinate zero on top.
/// `preserved_items` counts unrelated items across the main and alt stacks.
pub fn bind_value(preserved_items: u32) -> Script {
    assert!(
        u64::from(preserved_items) + u64::from(BIND_VALUE_STACK_ITEMS)
            <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "composable RNS value certification exceeds Bitcoin Script's stack limit"
    );
    let coordinates = (0..MODULI.len())
        .map(|index| bind_value_coordinate(index, index == 0))
        .collect::<Vec<_>>();
    script! {
        for (route, binding) in coordinates {
            { route }
            { binding }
        }
        // Outputs are on the altstack and the limbs are now shallow.
        { verify_below_secp256k1(0) }
        for _ in 0..LIMB_COUNT / 2 {
            OP_2DROP
        }
        { restore_residues() }
    }
}

struct CoordinateParts {
    route_operands: Script,
    quotient_binding: Script,
    remainder_binding: Script,
    relation: Script,
}

fn coordinate_parts_with_limb_checks(
    index: usize,
    target_residue: u32,
    check_limbs: bool,
) -> CoordinateParts {
    let modulus = MODULI[index];
    let prior_outputs = RESIDUE_COUNT - index as u32 - 1;
    let route_operands = script! {
        // Pull this coordinate from two ordinary coordinate-zero-on-top
        // vectors through the 32 witness limbs and prior outputs.
        { index as u32 + RESIDUE_COUNT + 2 * LIMB_COUNT } OP_ROLL
        { RESIDUE_COUNT + 2 * LIMB_COUNT } OP_ROLL
    };

    // Remainder limbs are above quotient limbs. The first coordinate folds
    // the two limb range proofs into the already-required dot-product picks.
    let quotient_depth = LIMB_COUNT + prior_outputs + 3;
    let quotient_binding = script! {
        OP_FROMALTSTACK
        { bind_from_main_carry(modulus, quotient_depth, check_limbs) }
    };
    let remainder_depth = prior_outputs + 4;
    let remainder_binding = script! {
        OP_FROMALTSTACK
        { bind_from_main_carry(modulus, remainder_depth, check_limbs) }
    };

    let centered_target = center(target_residue, modulus);
    let relation = script! {
        OP_FROMALTSTACK
        OP_SWAP
        OP_DUP OP_TOALTSTACK

        // lhs | rhs | q | carry | r -> exact coordinate equation.
        4 OP_ROLL
        4 OP_ROLL
        { centered_both_variable_mul(modulus) }
        3 OP_ROLL
        { safe_exact_constant_mul(centered_target, modulus - 1) }
        OP_SUB
        OP_SWAP OP_SUB
        OP_SWAP
        {
            safe_exact_constant_mul(
                modulus as i32,
                relation_carry_bound(modulus, centered_target),
            )
        }
        OP_EQUALVERIFY
        OP_FROMALTSTACK
    };

    CoordinateParts {
        route_operands,
        quotient_binding,
        remainder_binding,
        relation,
    }
}

fn coordinate_parts(index: usize, target_residue: u32) -> CoordinateParts {
    coordinate_parts_with_limb_checks(index, target_residue, index + 1 == MODULI.len())
}

fn route_all_hints() -> Script {
    script! {
        for _ in 0..COORDINATE_HINT_ITEMS * RESIDUE_COUNT {
            OP_TOALTSTACK
        }
    }
}

fn drop_limbs_and_restore_output() -> Script {
    script! {
        for _ in 0..RESIDUE_COUNT {
            OP_TOALTSTACK
        }
        for _ in 0..LIMB_COUNT {
            OP_2DROP
        }
        { restore_residues() }
    }
}

/// Multiply two previously certified secp256k1 field values.
///
/// Input, bottom to top:
/// `preserved | lhs_residues | rhs_residues | q_limbs | r_limbs | hints`.
/// Both residue vectors use coordinate zero on top. `hints` contains three
/// reverse-coordinate carries per [`push_hinted_witness`]. The fragment
/// consumes both operands and all hints and returns only canonical remainder
/// residues, again with coordinate zero on top.
/// `preserved_items` counts unrelated items across the main and alt stacks.
///
/// Soundness follows because the inherited operand certificates and local
/// q/r bindings identify four integers below `2^256`; lhs, rhs, and r are
/// field-bounded. The checked difference has magnitude below `2^512`, while
/// the basis product is greater than `2^512`, so RNS congruence implies the
/// exact integer product equation.
pub fn mul_mod_hinted(preserved_items: u32) -> Script {
    assert!(
        u64::from(preserved_items) + u64::from(HINTED_MUL_STACK_ITEMS)
            <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "composable RNS multiplication exceeds Bitcoin Script's stack limit"
    );
    let target = encode(&target_modulus());
    let coordinates = target
        .into_iter()
        .enumerate()
        .rev()
        .map(|(index, residue)| coordinate_parts(index, residue))
        .collect::<Vec<_>>();
    script! {
        { route_all_hints() }
        // Remainder is the top limb vector; limb ranges are checked in the
        // first coordinate binding immediately after this comparison.
        { verify_below_secp256k1(0) }
        for coordinate in coordinates {
            { coordinate.route_operands }
            { coordinate.quotient_binding }
            { coordinate.remainder_binding }
            { coordinate.relation }
        }
        { drop_limbs_and_restore_output() }
    }
}

/// Return exact byte attribution for [`mul_mod_hinted`].
pub fn cost_breakdown() -> CostBreakdown {
    let target = encode(&target_modulus());
    let mut cost = CostBreakdown {
        field_validation: verify_below_secp256k1(0).compile().len(),
        routing_output: route_all_hints().compile().len()
            + drop_limbs_and_restore_output().compile().len(),
        ..CostBreakdown::default()
    };
    for (index, residue) in target.into_iter().enumerate().rev() {
        let coordinate = coordinate_parts(index, residue);
        let unchecked = coordinate_parts_with_limb_checks(index, residue, false);
        cost.routing_output += coordinate.route_operands.compile().len();
        let checked_quotient = coordinate.quotient_binding.compile().len();
        let unchecked_quotient = unchecked.quotient_binding.compile().len();
        let checked_remainder = coordinate.remainder_binding.compile().len();
        let unchecked_remainder = unchecked.remainder_binding.compile().len();
        cost.field_validation += checked_quotient - unchecked_quotient;
        cost.field_validation += checked_remainder - unchecked_remainder;
        cost.quotient_binding += unchecked_quotient;
        cost.remainder_binding += unchecked_remainder;
        cost.modular_relation += coordinate.relation.compile().len();
    }
    debug_assert_eq!(cost.total(), mul_mod_hinted(0).compile().len());
    cost
}

/// Return exact byte attribution for [`bind_value`].
pub fn bind_value_cost_breakdown() -> BindValueCostBreakdown {
    let mut cost = BindValueCostBreakdown {
        limb_and_field_validation: verify_below_secp256k1(0).compile().len(),
        routing_output: (LIMB_COUNT / 2) as usize + restore_residues().compile().len(),
        ..BindValueCostBreakdown::default()
    };
    for index in 0..MODULI.len() {
        let (route, binding) = bind_value_coordinate(index, index == 0);
        let (_, unchecked) = bind_value_coordinate(index, false);
        cost.routing_output += route.compile().len();
        let checked_bytes = binding.compile().len();
        let unchecked_bytes = unchecked.compile().len();
        cost.limb_and_field_validation += checked_bytes - unchecked_bytes;
        cost.residue_binding += unchecked_bytes;
    }
    debug_assert_eq!(cost.total(), bind_value(0).compile().len());
    cost
}

#[cfg(test)]
mod tests {
    use bitcoin::{consensus::serialize, Witness};
    use num_bigint::{BigUint, RandBigInt};
    use num_traits::{One, Zero};
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    fn drop_items(items: u32) -> Script {
        script! {
            for _ in 0..items / 2 { OP_2DROP }
            if items % 2 != 0 { OP_DROP }
        }
    }

    fn scriptnum_item(value: i32) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let len = bitcoin::script::write_scriptint(&mut bytes, i64::from(value));
        bytes[..len].to_vec()
    }

    fn bind_value_witness_items(value: &BigUint) -> Vec<Vec<u8>> {
        centered_limbs(value)
            .into_iter()
            .rev()
            .chain(binding_carries(value).into_iter().rev())
            .map(scriptnum_item)
            .collect()
    }

    fn hinted_witness_items(
        lhs: &BigUint,
        rhs: &BigUint,
        quotient: &BigUint,
        remainder: &BigUint,
    ) -> Vec<Vec<u8>> {
        let quotient_binding = binding_carries(quotient);
        let remainder_binding = binding_carries(remainder);
        let relation = relation_carries(lhs, rhs, quotient, remainder);
        centered_limbs(quotient)
            .into_iter()
            .rev()
            .chain(centered_limbs(remainder).into_iter().rev())
            .chain((0..MODULI.len()).rev().flat_map(|index| {
                [
                    quotient_binding[index],
                    remainder_binding[index],
                    relation[index],
                ]
            }))
            .map(scriptnum_item)
            .collect()
    }

    fn custom_hinted_witness(
        quotient_limbs: &[i32; LIMB_COUNT as usize],
        remainder_limbs: &[i32; LIMB_COUNT as usize],
        quotient_binding: &[i32; MODULI.len()],
        remainder_binding: &[i32; MODULI.len()],
        relation: &[i32; MODULI.len()],
    ) -> Script {
        script! {
            { push_centered_limbs(quotient_limbs) }
            { push_centered_limbs(remainder_limbs) }
            for index in (0..MODULI.len()).rev() {
                { quotient_binding[index] }
                { remainder_binding[index] }
                { relation[index] }
            }
        }
    }

    fn execute_product(lhs: &BigUint, rhs: &BigUint) -> crate::support::execution::ExecuteInfo {
        let target = target_modulus();
        let product = lhs * rhs;
        let quotient = &product / &target;
        let remainder = &product % &target;
        crate::support::execution::execute_script(script! {
            { push_bind_value_witness(lhs) }
            { bind_value(0) }
            { push_bind_value_witness(rhs) }
            { bind_value(RESIDUE_COUNT) }
            { push_hinted_witness(lhs, rhs, &quotient, &remainder) }
            { mul_mod_hinted(0) }
            for residue in encode(&remainder) {
                { residue } OP_EQUALVERIFY
            }
            OP_TRUE
        })
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

    #[test]
    fn basis_and_every_joint_prefix_fit_scriptnum() {
        assert!(MODULI.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(MODULI.iter().all(|modulus| is_prime(*modulus)));
        assert!(modulus() > (BigUint::one() << 512usize));
        assert_eq!(modulus().bits(), 513);

        let limit = i64::from(scriptint::MAX_SCRIPTNUM);
        let mut tightest = (u64::MAX, 0u32, 0i64);
        for modulus in MODULI {
            let (coefficients, offset, sum_abs) = coordinate_coefficients(modulus);
            assert!(
                u64::from(LIMB_OFFSET.unsigned_abs()) * sum_abs + 2 * u64::from(modulus)
                    <= u64::from(scriptint::MAX_SCRIPTNUM)
            );
            let target = center(
                encode(&target_modulus())[MODULI
                    .iter()
                    .position(|candidate| *candidate == modulus)
                    .unwrap()],
                modulus,
            );
            let relation_bound = variable_product_bound(modulus)
                + u64::from(modulus - 1) * u64::from(target.unsigned_abs())
                + u64::from(modulus - 1);
            assert!(relation_bound <= u64::from(scriptint::MAX_SCRIPTNUM));

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
            let mut check = |prefix: &[i32; LIMB_COUNT as usize]| {
                let (low, high) = linear_extrema(prefix, 0);
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
                    check(&prefix);
                }
                for (index, scalar) in digits.iter().enumerate() {
                    let digit = scalar.get(bit).copied().unwrap_or(0);
                    if digit != 0 {
                        prefix[index] += i32::from(digit);
                        initialized = true;
                        check(&prefix);
                    }
                }
            }
            assert_eq!(prefix, coefficients);
            let (low, high) = linear_extrema(&prefix, i64::from(offset));
            assert!(low >= -limit && high <= limit);
        }
        assert_eq!(tightest, (76_455, 43_691, 2_147_407_192));
    }

    #[test]
    fn certified_products_accept_boundaries_and_random_values() {
        let target = target_modulus();
        let mut rng = StdRng::seed_from_u64(0x434f_4d50_4f53_4552);
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
            let result = execute_product(&lhs, &rhs);
            assert!(result.success, "{lhs} * {rhs}: {result}");
        }
    }

    #[test]
    fn wide_centered_products_accept_half_boundaries() {
        for modulus in [43_691u32, 61_681, 65_537] {
            let half = modulus / 2;
            for lhs_offset in 0..=1 {
                for rhs_offset in 0..=1 {
                    let lhs = BigUint::from(half + lhs_offset);
                    let rhs = BigUint::from(half + rhs_offset);
                    let coordinate = MODULI
                        .iter()
                        .position(|candidate| *candidate == modulus)
                        .expect("wide modulus is in the production basis");
                    assert_eq!(encode(&lhs)[coordinate], half + lhs_offset);
                    assert_eq!(encode(&rhs)[coordinate], half + rhs_offset);
                    let result = execute_product(&lhs, &rhs);
                    assert!(
                        result.success,
                        "p={modulus}, lhs={lhs}, rhs={rhs}: {result}"
                    );
                }
            }
        }
    }

    #[test]
    fn rejects_detached_257_bit_crt_quotient() {
        let target = target_modulus();
        let product_modulus = modulus();
        let detached_quotient = &product_modulus / &target;
        let detached_remainder = &product_modulus % &target;
        assert_eq!(
            &detached_quotient * &target + &detached_remainder,
            product_modulus
        );
        assert_eq!(detached_quotient.bits(), 257);

        // Only the low 256 bits can enter the 16-limb quotient binding. The
        // detached 257-bit residues would satisfy the bare CRT relations, but
        // they cannot also satisfy this global limb-to-residue certificate.
        let low_quotient = &detached_quotient - (BigUint::one() << 256usize);
        let quotient_limbs = centered_limbs(&low_quotient);
        let remainder_limbs = centered_limbs(&detached_remainder);
        let quotient_binding = binding_carries(&low_quotient);
        let remainder_binding = binding_carries(&detached_remainder);
        let quotient_residues = encode(&detached_quotient);
        let remainder_residues = encode(&detached_remainder);
        let target_residues = encode(&target);
        let detached_relation = std::array::from_fn(|index| {
            let modulus = MODULI[index];
            let numerator = -i64::from(quotient_residues[index])
                * i64::from(center(target_residues[index], modulus))
                - i64::from(remainder_residues[index]);
            assert_eq!(numerator % i64::from(modulus), 0);
            i32::try_from(numerator / i64::from(modulus))
                .expect("detached relation carry fits ScriptNum")
        });

        let zero = BigUint::zero();
        let result = crate::support::execution::execute_script(script! {
            { push_value(&zero) }
            { push_value(&zero) }
            {
                custom_hinted_witness(
                    &quotient_limbs,
                    &remainder_limbs,
                    &quotient_binding,
                    &remainder_binding,
                    &detached_relation,
                )
            }
            { mul_mod_hinted(0) }
            OP_TRUE
        });
        assert!(!result.success, "detached 257-bit quotient was accepted");
    }

    #[test]
    fn returned_certificate_composes_into_a_second_product() {
        let target = target_modulus();
        let lhs = &target - BigUint::from(12_345u32);
        let rhs = BigUint::from(987_654_321u64);
        let third = BigUint::from(4_242_424_243u64);
        let first_product = &lhs * &rhs;
        let first_quotient = &first_product / &target;
        let first_remainder = &first_product % &target;
        let second_product = &third * &first_remainder;
        let second_quotient = &second_product / &target;
        let second_remainder = &second_product % &target;

        let result = crate::support::execution::execute_script(script! {
            // Keep `third` below the first operation. Its certificate and the
            // newly returned certificate become the second operation's inputs.
            { push_bind_value_witness(&third) }
            { bind_value(0) }
            { push_bind_value_witness(&lhs) }
            { bind_value(RESIDUE_COUNT) }
            { push_bind_value_witness(&rhs) }
            { bind_value(2 * RESIDUE_COUNT) }
            { push_hinted_witness(&lhs, &rhs, &first_quotient, &first_remainder) }
            { mul_mod_hinted(RESIDUE_COUNT) }
            {
                push_hinted_witness(
                    &third,
                    &first_remainder,
                    &second_quotient,
                    &second_remainder,
                )
            }
            { mul_mod_hinted(0) }
            for residue in encode(&second_remainder) {
                { residue } OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(result.success, "two-operation chain: {result}");
    }

    #[test]
    fn rejects_each_malformed_carry_class() {
        let target = target_modulus();
        let lhs = &target - BigUint::from(123u32);
        let rhs = BigUint::from(987_654_321u64);
        let product = &lhs * &rhs;
        let quotient = &product / &target;
        let remainder = &product % &target;
        let q_limbs = centered_limbs(&quotient);
        let r_limbs = centered_limbs(&remainder);
        let q_binding = binding_carries(&quotient);
        let r_binding = binding_carries(&remainder);
        let relation = relation_carries(&lhs, &rhs, &quotient, &remainder);

        for index in 0..MODULI.len() {
            for class in 0..3 {
                let mut q_bad = q_binding;
                let mut r_bad = r_binding;
                let mut relation_bad = relation;
                match class {
                    0 => q_bad[index] += 1,
                    1 => r_bad[index] += 1,
                    2 => relation_bad[index] += 1,
                    _ => unreachable!(),
                }
                let result = crate::support::execution::execute_script(script! {
                    { push_value(&lhs) }
                    { push_value(&rhs) }
                    {
                        custom_hinted_witness(
                            &q_limbs,
                            &r_limbs,
                            &q_bad,
                            &r_bad,
                            &relation_bad,
                        )
                    }
                    { mul_mod_hinted(0) }
                    OP_TRUE
                });
                assert!(
                    !result.success,
                    "malformed carry class {class}, coordinate {index} was accepted"
                );
            }
        }
    }

    #[test]
    fn rejects_limb_and_field_range_violations() {
        let zero = BigUint::zero();
        let q_binding = binding_carries(&zero);
        let r_binding = binding_carries(&zero);
        let relation = relation_carries(&zero, &zero, &zero, &zero);
        let valid = centered_limbs(&zero);

        for limb in 0..LIMB_COUNT as usize {
            for vector in 0..2 {
                let mut q_limbs = valid;
                let mut r_limbs = valid;
                if vector == 0 {
                    q_limbs[limb] = LIMB_OFFSET;
                } else {
                    r_limbs[limb] = LIMB_OFFSET;
                }
                let result = crate::support::execution::execute_script(script! {
                    { push_value(&zero) }
                    { push_value(&zero) }
                    {
                        custom_hinted_witness(
                            &q_limbs,
                            &r_limbs,
                            &q_binding,
                            &r_binding,
                            &relation,
                        )
                    }
                    { mul_mod_hinted(0) }
                    OP_TRUE
                });
                assert!(
                    !result.success,
                    "out-of-range limb vector {vector}, limb {limb} was accepted"
                );
            }
        }

        let target = target_modulus();
        let result = crate::support::execution::execute_script(script! {
            { push_bind_value_witness(&target) }
            { bind_value(0) }
            OP_TRUE
        });
        assert!(
            !result.success,
            "field modulus was accepted as a field element"
        );

        let target_limbs = centered_limbs(&target);
        let target_binding = binding_carries(&target);
        let result = crate::support::execution::execute_script(script! {
            { push_value(&zero) }
            { push_value(&zero) }
            {
                custom_hinted_witness(
                    &valid,
                    &target_limbs,
                    &q_binding,
                    &target_binding,
                    &relation,
                )
            }
            { mul_mod_hinted(0) }
            OP_TRUE
        });
        assert!(!result.success, "field-modulus remainder was accepted");
    }

    #[test]
    fn preserves_unrelated_main_and_alt_state() {
        let target = target_modulus();
        let lhs = BigUint::from(123_456_789u64);
        let rhs = &target - BigUint::from(77u32);
        let product = &lhs * &rhs;
        let quotient = &product / &target;
        let remainder = &product % &target;
        let result = crate::support::execution::execute_script(script! {
            101 OP_TOALTSTACK
            102
            { push_value(&lhs) }
            { push_value(&rhs) }
            { push_hinted_witness(&lhs, &rhs, &quotient, &remainder) }
            { mul_mod_hinted(2) }
            { drop_items(RESIDUE_COUNT) }
            102 OP_EQUALVERIFY
            OP_FROMALTSTACK 101 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "preserved state: {result}");
    }

    #[test]
    fn strict_stack_peaks_and_guards_are_exact() {
        let target = target_modulus();
        let lhs = &target - BigUint::one();
        let product = &lhs * &lhs;
        let quotient = &product / &target;
        let remainder = &product % &target;
        let result = crate::support::execution::execute_script(script! {
            { push_value(&lhs) }
            { push_value(&lhs) }
            { push_hinted_witness(&lhs, &lhs, &quotient, &remainder) }
            { mul_mod_hinted(0) }
            { drop_items(RESIDUE_COUNT) }
            OP_TRUE
        });
        assert!(result.success, "multiplication peak: {result}");
        assert_eq!(
            result.stats.max_nb_stack_items,
            HINTED_MUL_STACK_ITEMS as usize
        );

        let preserved = U31_LOOKUP_STACK_LIMIT - HINTED_MUL_STACK_ITEMS;
        let result = crate::support::execution::execute_script(script! {
            for _ in 0..preserved { 0 }
            { push_value(&lhs) }
            { push_value(&lhs) }
            { push_hinted_witness(&lhs, &lhs, &quotient, &remainder) }
            { mul_mod_hinted(preserved) }
            { drop_items(RESIDUE_COUNT + preserved) }
            OP_TRUE
        });
        assert!(result.success, "1,000-item multiplication: {result}");
        assert_eq!(result.stats.max_nb_stack_items, 1_000);

        let result = crate::support::execution::execute_script(script! {
            { push_bind_value_witness(&lhs) }
            { bind_value(0) }
            { drop_items(RESIDUE_COUNT) }
            OP_TRUE
        });
        assert!(result.success, "binder peak: {result}");
        assert_eq!(
            result.stats.max_nb_stack_items,
            BIND_VALUE_STACK_ITEMS as usize
        );

        let bind_preserved = U31_LOOKUP_STACK_LIMIT - BIND_VALUE_STACK_ITEMS;
        let result = crate::support::execution::execute_script(script! {
            for _ in 0..bind_preserved { 0 }
            { push_bind_value_witness(&lhs) }
            { bind_value(bind_preserved) }
            { drop_items(RESIDUE_COUNT + bind_preserved) }
            OP_TRUE
        });
        assert!(result.success, "1,000-item binder: {result}");
        assert_eq!(result.stats.max_nb_stack_items, 1_000);

        assert!(std::panic::catch_unwind(|| {
            mul_mod_hinted(U31_LOOKUP_STACK_LIMIT - HINTED_MUL_STACK_ITEMS + 1)
        })
        .is_err());
        assert!(std::panic::catch_unwind(|| {
            bind_value(U31_LOOKUP_STACK_LIMIT - BIND_VALUE_STACK_ITEMS + 1)
        })
        .is_err());
    }

    #[test]
    fn exact_cost_breakdowns_match_generated_scripts() {
        let cost = cost_breakdown();
        assert_eq!(cost.table_push, 0);
        assert_eq!(cost.table_drop, 0);
        assert_eq!(cost.total(), mul_mod_hinted(0).compile().len());
        eprintln!(
            "composable multiplication cost: {cost:?}, total={}",
            cost.total()
        );

        let bind_cost = bind_value_cost_breakdown();
        assert_eq!(bind_cost.table_push, 0);
        assert_eq!(bind_cost.table_drop, 0);
        assert_eq!(bind_cost.total(), bind_value(0).compile().len());
        eprintln!(
            "composable binder cost: {bind_cost:?}, total={}",
            bind_cost.total()
        );
    }

    #[test]
    fn representative_witness_boundaries_are_exact() {
        let target = target_modulus();
        let lhs = &target - BigUint::one();
        let product = &lhs * &lhs;
        let quotient = &product / &target;
        let remainder = &product % &target;

        let hinted = hinted_witness_items(&lhs, &lhs, &quotient, &remainder);
        let binding = bind_value_witness_items(&lhs);
        assert_eq!(hinted.len(), HINTED_MUL_WITNESS_ITEMS as usize);
        assert_eq!(binding.len(), BIND_VALUE_WITNESS_ITEMS as usize);
        assert_eq!(serialize(&Witness::from_slice(&hinted)).len(), 471);
        assert_eq!(serialize(&Witness::from_slice(&binding)).len(), 195);
        eprintln!(
            "representative witness: multiplication={} bytes/{} items, binder={} bytes/{} items",
            serialize(&Witness::from_slice(&hinted)).len(),
            hinted.len(),
            serialize(&Witness::from_slice(&binding)).len(),
            binding.len(),
        );
    }
}
