//! Factor-16 Montgomery-domain multiplication in the secp256k1 base field.
//!
//! A logical field element `x` is stored as `E(x) = x / 16 (mod p)`. Given
//! encoded operands `a` and `b`, the gate derives
//!
//! `r = 16*a*b (mod p) = E(E^-1(a) * E^-1(b))`.
//!
//! With `B=512`, `p=16*B^28-32*B^3-977`. The verifier folds the exact
//! product polynomial to degree 28, then proves `G-t*p=r` with one residual
//! `t` and 28 exact radix-512 carries. The result is range checked as a
//! canonical field element. As in the parent backend, both encoded operands
//! must have been certified on the same verified script path.

use super::*;
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{ToPrimitive, Zero};

/// Number of signed residual values in one multiplication hint.
pub const RESIDUAL_ITEM_COUNT: usize = 1;
/// Number of exact radix-512 carries in one multiplication hint.
pub const RELATION_CARRY_COUNT: usize = 28;
/// Incremental witness items for one multiplication.
pub const HINT_ITEM_COUNT: usize = RESIDUAL_ITEM_COUNT + RELATION_CARRY_COUNT;
/// Complete witness items: two encoded operands and one hint group.
pub const MUL_WITNESS_ITEM_COUNT: usize = 2 * FIELD_DIGIT_COUNT + HINT_ITEM_COUNT;
/// Exact combined-stack peak with no unrelated live state.
pub const HINTED_MUL_STACK_ITEMS: u32 = 719;
/// Maximum unrelated state that can coexist under the 1,000-item limit.
pub const MAX_PRESERVED_ITEMS: u32 = U31_LOOKUP_STACK_LIMIT - HINTED_MUL_STACK_ITEMS;
/// Rigorous lower bound for every honest folded residual.
pub const RESIDUAL_MIN: i32 = -22_910;
/// Rigorous upper bound for every honest folded residual.
pub const RESIDUAL_MAX: i32 = 22_909;
/// Rigorous absolute bound for every honest relation carry.
pub const RELATION_CARRY_ABS_BOUND: i32 = 407_878;
/// Rigorous absolute bound before any radix-512 carry extraction.
pub const PRE_CARRY_ABS_BOUND: i32 = 208_833_836;

const STORED_COEFFICIENT_COUNT: usize = KARATSUBA_STORED_COEFFICIENTS;

/// Exact relation carries, least-significant first.
pub type RelationCarries = [i32; RELATION_CARRY_COUNT];

/// Host-generated witness for one factor-16 Montgomery multiplication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MulHints {
    /// Canonical encoded result `16*lhs*rhs mod p`.
    pub remainder: BigUint,
    /// Small signed quotient in the degree-28 folded relation `G-t*p=r`.
    pub residual: i32,
    /// Exact radix-512 carries, least-significant first.
    pub carries: RelationCarries,
}

impl MulHints {
    /// Push `t c[27] ... c[0]`, leaving `c[0]` on top.
    pub fn push_script(&self) -> Script {
        script! {
            { self.residual }
            for carry in self.carries.iter().rev() {
                { *carry }
            }
        }
    }

    /// Return raw Script-number witness items in push order.
    pub fn witness_items(&self) -> Vec<Vec<u8>> {
        std::iter::once(&self.residual)
            .chain(self.carries.iter().rev())
            .map(|value| scriptnum_item(*value))
            .collect()
    }
}

/// Exact byte categories for one private-table multiplication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OneShotCostBreakdown {
    /// Push the 513-entry quarter-square table.
    pub table_setup: usize,
    /// Drop the table after product generation.
    pub table_drop: usize,
    /// Normalized Karatsuba product generation, excluding the table drop.
    pub product_generation: usize,
    /// Degree-28 folded exact relation and derived output digits.
    pub folded_relation: usize,
    /// Drop inputs/temporaries, restore output, and prove canonical range.
    pub cleanup: usize,
}

impl OneShotCostBreakdown {
    /// Complete locking-script bytes for one certified-input gate.
    pub fn total(self) -> usize {
        self.table_setup
            + self.table_drop
            + self.product_generation
            + self.folded_relation
            + self.cleanup
    }

    /// Static table setup/drop bytes, reusable only in a future resident API.
    pub fn table_overhead(self) -> usize {
        self.table_setup + self.table_drop
    }

    /// Per-multiplication bytes excluding table setup/drop.
    pub fn computation(self) -> usize {
        self.product_generation + self.folded_relation + self.cleanup
    }
}

/// Encode a canonical ordinary field element as `x/16 mod p`.
pub fn encode(value: &BigUint) -> BigUint {
    let p = modulus();
    assert!(value < &p, "secp256k1 field value must be smaller than p");
    // Since p == -1 (mod 16), (p+1)/16 is 16^-1 modulo p.
    let inverse_16 = (&p + BigUint::from(1u32)) >> 4usize;
    value * inverse_16 % p
}

/// Decode a canonical factor-16 representation to an ordinary field value.
pub fn decode(value: &BigUint) -> BigUint {
    let p = modulus();
    assert!(value < &p, "encoded secp256k1 value must be smaller than p");
    value * BigUint::from(16u32) % p
}

fn folded_coefficients_from_product(product: &[i64; 57]) -> [i64; FIELD_DIGIT_COUNT] {
    std::array::from_fn(|index| {
        let mut coefficient = 0i64;
        if index <= 27 {
            coefficient += 16 * product[index];
            coefficient -= 47 * product[index + 28];
        }
        if (1..=28).contains(&index) {
            coefficient += 2 * product[index + 27];
        }
        if index == 28 {
            coefficient += 977 * product[56];
        }
        if (3..=27).contains(&index) {
            coefficient += 32 * product[index + 25];
        }
        // Second-fold the four degree-28..31 terms using
        // 32*B^28 = 64*B^3 - 94 + 4*B.
        for product_index in 53..=56 {
            let base = product_index - 53;
            if index == base {
                coefficient -= 94 * product[product_index];
            }
            if index == base + 1 {
                coefficient += 4 * product[product_index];
            }
            if index == base + 3 {
                coefficient += 64 * product[product_index];
            }
        }
        coefficient
    })
}

fn folded_coefficients(lhs: &FieldDigits, rhs: &FieldDigits) -> [i64; FIELD_DIGIT_COUNT] {
    folded_coefficients_from_product(&karatsuba_coefficients(lhs, rhs))
}

fn reconstruct_coefficients(coefficients: &[i64]) -> BigInt {
    coefficients
        .iter()
        .rev()
        .fold(BigInt::zero(), |value, coefficient| {
            value * RADIX + BigInt::from(*coefficient)
        })
}

/// Generate the residual/carry witness and encoded canonical result.
pub fn hinted_mul(lhs: &BigUint, rhs: &BigUint) -> MulHints {
    let p = modulus();
    assert!(lhs < &p, "left encoded operand must be canonical");
    assert!(rhs < &p, "right encoded operand must be canonical");
    let remainder = (lhs * rhs * BigUint::from(16u32)) % &p;
    let lhs_digits = field_digits(lhs);
    let rhs_digits = field_digits(rhs);
    let remainder_digits = field_digits(&remainder);
    let folded = folded_coefficients(&lhs_digits, &rhs_digits);
    let folded_integer = reconstruct_coefficients(&folded);
    let remainder_integer = BigInt::from_biguint(Sign::Plus, remainder.clone());
    let p_integer = BigInt::from_biguint(Sign::Plus, p);
    let delta = folded_integer - remainder_integer;
    assert_eq!(&delta % &p_integer, BigInt::zero());
    let residual_integer = &delta / &p_integer;
    let residual = residual_integer
        .to_i32()
        .unwrap_or_else(|| panic!("factor-16 residual exceeds ScriptNum: {residual_integer}"));
    assert!(
        (RESIDUAL_MIN..=RESIDUAL_MAX).contains(&residual),
        "factor-16 residual exceeds its proven interval"
    );

    let mut previous = 0i64;
    let mut carries = [0i32; RELATION_CARRY_COUNT];
    for coefficient_index in 0..FIELD_DIGIT_COUNT {
        let mut coefficient = previous + folded[coefficient_index];
        // 977*t is recoded as (-47+2B)*t.
        match coefficient_index {
            0 => coefficient -= 47 * i64::from(residual),
            1 => coefficient += 2 * i64::from(residual),
            3 => coefficient += 32 * i64::from(residual),
            28 => coefficient -= 16 * i64::from(residual),
            _ => {}
        }
        coefficient -= i64::from(remainder_digits[coefficient_index]);
        if coefficient_index < RELATION_CARRY_COUNT {
            assert_eq!(
                coefficient % i64::from(RADIX),
                0,
                "factor-16 relation coefficient {coefficient_index}"
            );
            previous = coefficient / i64::from(RADIX);
            carries[coefficient_index] =
                i32::try_from(previous).expect("factor-16 relation carry fits ScriptNum");
            assert!(
                carries[coefficient_index].unsigned_abs() <= RELATION_CARRY_ABS_BOUND as u32,
                "factor-16 relation carry exceeds its proven bound"
            );
        } else {
            assert_eq!(coefficient, 0, "final factor-16 relation coefficient");
        }
    }

    MulHints {
        remainder,
        residual,
        carries,
    }
}

/// Push two encoded canonical operands followed by one hint group.
pub fn push_mul_witness(lhs: &BigUint, rhs: &BigUint, hints: &MulHints) -> Script {
    script! {
        { push_value(lhs) }
        { push_value(rhs) }
        { hints.push_script() }
    }
}

fn operand_product_coefficient(
    lhs_offset: usize,
    rhs_offset: usize,
    digit_count: usize,
    coefficient_index: usize,
) -> Script {
    let first = coefficient_index.saturating_sub(digit_count - 1);
    let last = coefficient_index.min(digit_count - 1);
    let lhs_base_depth = TABLE_ITEM_COUNT
        + 1
        + RELATION_CARRY_COUNT as u32
        + (RESIDUAL_ITEM_COUNT + FIELD_DIGIT_COUNT) as u32;
    let rhs_base_depth =
        TABLE_ITEM_COUNT + 2 + RELATION_CARRY_COUNT as u32 + RESIDUAL_ITEM_COUNT as u32;
    script! {
        0
        for lhs_index in first..=last {
            { product_into_accumulator(
                lhs_base_depth + (lhs_offset + lhs_index) as u32,
                rhs_base_depth + (rhs_offset + coefficient_index - lhs_index) as u32,
                2,
            ) }
        }
        OP_TOALTSTACK
    }
}

fn normalize_lhs_difference() -> Script {
    let lhs_base_depth = TABLE_ITEM_COUNT
        + 1
        + RELATION_CARRY_COUNT as u32
        + (RESIDUAL_ITEM_COUNT + FIELD_DIGIT_COUNT) as u32;
    script! {
        for index in 0..KARATSUBA_DIFFERENCE_DIGITS {
            if index < KARATSUBA_SPLIT {
                { lhs_base_depth + index as u32 - u32::from(index == 0) } OP_PICK
                { lhs_base_depth + 1 + KARATSUBA_SPLIT as u32 + index as u32
                    - u32::from(index == 0) }
                OP_PICK OP_SUB
            } else {
                { lhs_base_depth + KARATSUBA_SPLIT as u32 + index as u32 }
                OP_PICK OP_NEGATE
            }
            if index != 0 {
                OP_ADD
            }
            if index + 1 == KARATSUBA_DIFFERENCE_DIGITS {
                OP_TOALTSTACK
            } else {
                { karatsuba_normalize_coefficient() }
            }
        }
    }
}

fn normalize_rhs_difference() -> Script {
    let rhs_base_depth =
        TABLE_ITEM_COUNT + 1 + RELATION_CARRY_COUNT as u32 + RESIDUAL_ITEM_COUNT as u32;
    script! {
        for index in 0..KARATSUBA_DIFFERENCE_DIGITS {
            if index < KARATSUBA_SPLIT {
                { rhs_base_depth + KARATSUBA_SPLIT as u32 + index as u32
                    - u32::from(index == 0) } OP_PICK
                { rhs_base_depth + 1 + index as u32 - u32::from(index == 0) } OP_PICK OP_SUB
            } else {
                { rhs_base_depth + KARATSUBA_SPLIT as u32 + index as u32 } OP_PICK
            }
            if index != 0 {
                OP_ADD
            }
            if index + 1 == KARATSUBA_DIFFERENCE_DIGITS {
                OP_TOALTSTACK
            } else {
                { karatsuba_normalize_coefficient() }
            }
        }
    }
}

fn difference_product_coefficient(coefficient_index: usize) -> Script {
    let first = coefficient_index.saturating_sub(KARATSUBA_DIFFERENCE_DIGITS - 1);
    let last = coefficient_index.min(KARATSUBA_DIFFERENCE_DIGITS - 1);
    script! {
        0
        for lhs_index in first..=last {
            { product_into_accumulator(
                1 + lhs_index as u32,
                2 + KARATSUBA_DIFFERENCE_DIGITS as u32
                    + (coefficient_index - lhs_index) as u32,
                2 + 2 * KARATSUBA_DIFFERENCE_DIGITS as u32,
            ) }
        }
        OP_TOALTSTACK
    }
}

fn product_arrays() -> Script {
    script! {
        for coefficient_index in 0..KARATSUBA_LOW_COEFFICIENTS {
            { operand_product_coefficient(0, 0, KARATSUBA_SPLIT, coefficient_index) }
        }
        for coefficient_index in 0..KARATSUBA_HIGH_COEFFICIENTS {
            { operand_product_coefficient(
                KARATSUBA_SPLIT,
                KARATSUBA_SPLIT,
                KARATSUBA_HIGH_DIGITS,
                coefficient_index,
            ) }
        }

        { normalize_lhs_difference() }
        { normalize_rhs_difference() }
        for _ in 0..2 * KARATSUBA_DIFFERENCE_DIGITS {
            OP_FROMALTSTACK
        }
        for coefficient_index in 0..KARATSUBA_DIFFERENCE_COEFFICIENTS {
            { difference_product_coefficient(coefficient_index) }
        }
        for _ in 0..KARATSUBA_DIFFERENCE_DIGITS {
            OP_2DROP
        }
        { table_drop() }
        for _ in 0..KARATSUBA_STORED_COEFFICIENTS {
            OP_FROMALTSTACK
        }
    }
}

// Add C[index] to a temporary accumulator. `extra_items` are live between
// that accumulator and the three stored Karatsuba arrays.
fn add_product_coefficient(coefficient_index: usize, extra_items: u32) -> Script {
    script! {
        if coefficient_index < KARATSUBA_LOW_COEFFICIENTS {
            { 1 + extra_items + coefficient_index as u32 } OP_PICK OP_ADD
        }
        if (KARATSUBA_SPLIT
            ..KARATSUBA_SPLIT + KARATSUBA_DIFFERENCE_COEFFICIENTS)
            .contains(&coefficient_index)
        {
            if coefficient_index - KARATSUBA_SPLIT < KARATSUBA_LOW_COEFFICIENTS {
                { 1 + extra_items + (coefficient_index - KARATSUBA_SPLIT) as u32 }
                OP_PICK OP_ADD
            }
            if coefficient_index - KARATSUBA_SPLIT < KARATSUBA_HIGH_COEFFICIENTS {
                { 1 + extra_items + KARATSUBA_LOW_COEFFICIENTS as u32
                    + (coefficient_index - KARATSUBA_SPLIT) as u32 }
                OP_PICK OP_ADD
            }
            { 1 + extra_items
                + (KARATSUBA_LOW_COEFFICIENTS + KARATSUBA_HIGH_COEFFICIENTS) as u32
                + (coefficient_index - KARATSUBA_SPLIT) as u32 }
            OP_PICK OP_ADD
        }
        if (2 * KARATSUBA_SPLIT
            ..2 * KARATSUBA_SPLIT + KARATSUBA_HIGH_COEFFICIENTS)
            .contains(&coefficient_index)
        {
            { 1 + extra_items + KARATSUBA_LOW_COEFFICIENTS as u32
                + (coefficient_index - 2 * KARATSUBA_SPLIT) as u32 }
            OP_PICK OP_ADD
        }
    }
}

fn add_scaled_product(
    coefficient_index: usize,
    multiplier: i32,
    has_outer_accumulator: bool,
    scratch_items: u32,
) -> Script {
    script! {
        0
        { add_product_coefficient(
            coefficient_index,
            scratch_items + u32::from(has_outer_accumulator),
        ) }
        { exact_small_constant_mul(multiplier.unsigned_abs()) }
        if multiplier < 0 {
            OP_NEGATE
        }
        if has_outer_accumulator {
            OP_ADD
        }
    }
}

// Input: `arrays | scratch | accumulator`. Append
// S_j=C[j+28]+2*C[j+53] for j<4, and S_j=C[j+28] otherwise.
fn build_pipeline_source(coefficient_index: usize, scratch_items: u32) -> Script {
    script! {
        0
        { add_product_coefficient(coefficient_index + 28, scratch_items + 1) }
        if coefficient_index <= 3 {
            0
            { add_product_coefficient(coefficient_index + 53, scratch_items + 2) }
            OP_DUP OP_ADD OP_ADD
        }
    }
}

// Input `... accumulator S`; output `... 32*S 2*S (accumulator-47*S)`.
fn pipeline_source_triple() -> Script {
    script! {
        OP_DUP
        for _ in 0..4 { OP_DUP OP_ADD }
        OP_OVER OP_DUP OP_ADD OP_TOALTSTACK
        OP_DUP OP_DUP OP_ADD OP_DUP OP_TOALTSTACK OP_ADD
        OP_SUB OP_ADD
        OP_FROMALTSTACK OP_FROMALTSTACK OP_ROT
    }
}

// S25..S27 have no 32*S tail: it was folded into S0..S3.
fn pipeline_source_pair() -> Script {
    script! {
        OP_DUP
        for _ in 0..4 { OP_DUP OP_ADD }
        OP_OVER OP_DUP OP_ADD OP_TOALTSTACK
        OP_DUP OP_DUP OP_ADD OP_ADD
        OP_SUB OP_ADD
        OP_FROMALTSTACK OP_SWAP
    }
}

fn residual_correction(coefficient_index: usize, residual_depth: u32) -> Script {
    let correction: i32 = match coefficient_index {
        0 => -47,
        1 => 2,
        3 => 32,
        28 => -16,
        _ => return script! {},
    };
    script! {
        { residual_depth } OP_PICK
        { exact_small_constant_mul(correction.unsigned_abs()) }
        if correction > 0 {
            OP_ADD
        } else {
            OP_SUB
        }
    }
}

fn coefficient_relation() -> Script {
    let mut body = Script::new("factor-16 Montgomery folded relation");
    let mut pending_32 = 0u32;
    for coefficient_index in 0..FIELD_DIGIT_COUNT {
        if coefficient_index != 0 {
            // The witnessed previous carry is on top; 2*S[j-1] is next.
            body = script! { { body } OP_SWAP OP_ADD };
        }

        if (3..=27).contains(&coefficient_index) {
            // Consume the oldest delayed 32*S contribution.
            body = script! { { body } { pending_32 } OP_ROLL OP_ADD };
            pending_32 -= 1;
        }

        if coefficient_index <= 27 {
            body = script! {
                { body }
                { add_scaled_product(
                    coefficient_index,
                    16,
                    coefficient_index != 0,
                    pending_32,
                ) }
                { build_pipeline_source(coefficient_index, pending_32) }
                if coefficient_index <= 24 {
                    { pipeline_source_triple() }
                } else {
                    { pipeline_source_pair() }
                }
            };
            if coefficient_index <= 24 {
                pending_32 += 1;
            }
        } else {
            debug_assert_eq!(pending_32, 0);
            body = script! { { body } { add_scaled_product(56, 977, true, 0) } };
        }

        let scratch_items = pending_32 + u32::from(coefficient_index <= 27);
        let remaining_carries = RELATION_CARRY_COUNT.saturating_sub(coefficient_index) as u32;
        body = script! {
            { body }
            { residual_correction(
                coefficient_index,
                1 + scratch_items + STORED_COEFFICIENT_COUNT as u32 + remaining_carries,
            ) }
        };

        if coefficient_index < RELATION_CARRY_COUNT {
            body = script! {
                { body }
                { 1 + scratch_items + STORED_COEFFICIENT_COUNT as u32 } OP_ROLL
                OP_TUCK { scriptint::mul_by_constant(RADIX as u32) }
                OP_SUB
                OP_DUP { -HALF_RADIX } { HALF_RADIX } OP_WITHIN OP_VERIFY
                OP_TOALTSTACK
            };
        } else {
            // Degree 28 has no outgoing carry; this is the derived top digit.
            body = script! { { body } OP_TOALTSTACK };
        }
    }
    body
}

fn cleanup() -> Script {
    script! {
        for _ in 0..STORED_COEFFICIENT_COUNT / 2 {
            OP_2DROP
        }
        if STORED_COEFFICIENT_COUNT % 2 != 0 {
            OP_DROP
        }
        for _ in 0..(2 * FIELD_DIGIT_COUNT + RESIDUAL_ITEM_COUNT) / 2 {
            OP_2DROP
        }
        if (2 * FIELD_DIGIT_COUNT + RESIDUAL_ITEM_COUNT) % 2 != 0 {
            OP_DROP
        }
        for _ in 0..FIELD_DIGIT_COUNT {
            OP_FROMALTSTACK
        }
        { verify_field_range_keep_at_depth(0) }
    }
}

/// Verify one multiplication with a private quarter-square table.
///
/// Input (top at right): `preserved | lhs[28..0] rhs[28..0] t c[27..0]`.
/// Both encoded operands must already be certified canonical values. The
/// fragment consumes operands and hints and returns `r[28] ... r[0]`, with
/// digit zero on top.
pub fn mul_mod_hinted(preserved_items: u32) -> Script {
    assert_stack_peak(
        preserved_items,
        HINTED_MUL_STACK_ITEMS,
        "factor-16 secp256k1 hinted multiplication",
    );
    script! {
        { table_setup_unchecked() }
        { product_arrays() }
        { coefficient_relation() }
        { cleanup() }
    }
}

/// Certify both encoded operands in the raw witness layout.
pub fn certify_mul_operands() -> Script {
    script! {
        { certify_value_at_depth(HINT_ITEM_COUNT as u32) }
        { certify_value_at_depth((HINT_ITEM_COUNT + FIELD_DIGIT_COUNT) as u32) }
    }
}

/// Standalone sound gate that also certifies both raw witness operands.
pub fn mul_mod_hinted_from_raw_witness(preserved_items: u32) -> Script {
    assert_stack_peak(
        preserved_items,
        HINTED_MUL_STACK_ITEMS,
        "raw factor-16 secp256k1 hinted multiplication",
    );
    script! {
        { certify_mul_operands() }
        { mul_mod_hinted(preserved_items) }
    }
}

/// Compile the exact certified-input one-shot byte categories.
pub fn one_shot_cost_breakdown() -> OneShotCostBreakdown {
    let table_drop = table_drop().compile().len();
    OneShotCostBreakdown {
        table_setup: table_setup_unchecked().compile().len(),
        table_drop,
        product_generation: product_arrays().compile().len() - table_drop,
        folded_relation: coefficient_relation().compile().len(),
        cleanup: cleanup().compile().len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{consensus::encode::serialize, Witness};
    use num_bigint::RandBigInt;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::support::execution::execute_script;

    fn expected_check(value: &BigUint) -> Script {
        let digits = field_digits(value);
        script! {
            for digit in digits {
                { digit } OP_EQUALVERIFY
            }
            OP_TRUE
        }
    }

    fn execute_case(lhs: &BigUint, rhs: &BigUint) -> (MulHints, usize) {
        let hints = hinted_mul(lhs, rhs);
        let execution = execute_script(script! {
            { push_mul_witness(lhs, rhs, &hints) }
            { mul_mod_hinted(0) }
            { expected_check(&hints.remainder) }
        });
        assert!(execution.success, "factor-16 execution: {execution}");
        (hints, execution.stats.max_nb_stack_items)
    }

    fn pipeline_fold_from_product(product: &[i64; 57]) -> [i64; FIELD_DIGIT_COUNT] {
        let sources: [i64; 28] = std::array::from_fn(|index| {
            product[index + 28]
                + if index <= 3 {
                    2 * product[index + 53]
                } else {
                    0
                }
        });
        std::array::from_fn(|index| {
            let mut coefficient = if index <= 27 {
                16 * product[index] - 47 * sources[index]
            } else {
                977 * product[56]
            };
            if index >= 1 {
                coefficient += 2 * sources[index - 1];
            }
            if (3..=27).contains(&index) {
                coefficient += 32 * sources[index - 3];
            }
            coefficient
        })
    }

    #[test]
    fn exhaustive_product_coefficient_mapping_is_exact() {
        let p = BigInt::from_biguint(Sign::Plus, modulus());
        let radix = BigInt::from(RADIX);
        for product_index in 0..57 {
            for basis_value in [-1i64, 1] {
                let mut product = [0i64; 57];
                product[product_index] = basis_value;
                let direct = folded_coefficients_from_product(&product);
                let pipelined = pipeline_fold_from_product(&product);
                assert_eq!(pipelined, direct, "product coefficient {product_index}");

                let folded = reconstruct_coefficients(&direct);
                let original = BigInt::from(16 * basis_value)
                    * radix.pow(u32::try_from(product_index).unwrap());
                assert_eq!((folded - original) % &p, BigInt::zero());
            }
        }
    }

    fn convolution_bounds(lhs: &[u64], rhs: &[u64]) -> Vec<u64> {
        let mut result = vec![0u64; lhs.len() + rhs.len() - 1];
        for (lhs_index, lhs_bound) in lhs.iter().enumerate() {
            for (rhs_index, rhs_bound) in rhs.iter().enumerate() {
                result[lhs_index + rhs_index] += lhs_bound * rhs_bound;
            }
        }
        result
    }

    #[test]
    fn analytic_residual_carry_and_scriptnum_bounds() {
        let low_bounds = [HALF_RADIX as u64; KARATSUBA_SPLIT];
        let mut high_bounds = [HALF_RADIX as u64; KARATSUBA_HIGH_DIGITS];
        high_bounds[KARATSUBA_HIGH_DIGITS - 1] = 16;
        let mut difference_bounds = [HALF_RADIX as u64; KARATSUBA_DIFFERENCE_DIGITS];
        difference_bounds[KARATSUBA_DIFFERENCE_DIGITS - 1] = 17;
        let z0 = convolution_bounds(&low_bounds, &low_bounds);
        let z2 = convolution_bounds(&high_bounds, &high_bounds);
        let zd = convolution_bounds(&difference_bounds, &difference_bounds);
        let product_bounds: [u64; 57] = std::array::from_fn(|index| {
            z0.get(index).copied().unwrap_or(0)
                + index
                    .checked_sub(KARATSUBA_SPLIT)
                    .and_then(|relative| z0.get(relative))
                    .copied()
                    .unwrap_or(0)
                + index
                    .checked_sub(KARATSUBA_SPLIT)
                    .and_then(|relative| z2.get(relative))
                    .copied()
                    .unwrap_or(0)
                + index
                    .checked_sub(KARATSUBA_SPLIT)
                    .and_then(|relative| zd.get(relative))
                    .copied()
                    .unwrap_or(0)
                + index
                    .checked_sub(2 * KARATSUBA_SPLIT)
                    .and_then(|relative| z2.get(relative))
                    .copied()
                    .unwrap_or(0)
        });
        let source_bounds: [u64; 28] = std::array::from_fn(|index| {
            product_bounds[index + 28]
                + if index <= 3 {
                    2 * product_bounds[index + 53]
                } else {
                    0
                }
        });
        let maximum_source = source_bounds.into_iter().max().unwrap();
        let maximum_pipeline_live = 48 * maximum_source;
        let maximum_low_scaled = product_bounds[..28]
            .iter()
            .map(|bound| 16 * bound)
            .max()
            .unwrap();
        let conservative_residual_chain = 1_024 * RESIDUAL_MIN.unsigned_abs() as u64;
        assert_eq!(maximum_source, 2_916_864);
        assert_eq!(maximum_pipeline_live, 140_009_472);
        assert_eq!(maximum_low_scaled, 44_040_192);
        assert_eq!(conservative_residual_chain, 23_459_840);
        for intermediate in [
            maximum_pipeline_live,
            maximum_low_scaled,
            conservative_residual_chain,
            1_024 * product_bounds[56],
        ] {
            assert!(intermediate < u64::from(scriptint::MAX_SCRIPTNUM));
        }
        let folded_bounds: [u64; FIELD_DIGIT_COUNT] = std::array::from_fn(|index| {
            let mut bound = 0u64;
            if index <= 27 {
                bound += 16 * product_bounds[index] + 47 * product_bounds[index + 28];
            }
            if (1..=28).contains(&index) {
                bound += 2 * product_bounds[index + 27];
            }
            if index == 28 {
                bound += 977 * product_bounds[56];
            }
            if (3..=27).contains(&index) {
                bound += 32 * product_bounds[index + 25];
            }
            for product_index in 53..=56 {
                let base = product_index - 53;
                if index == base {
                    bound += 94 * product_bounds[product_index];
                }
                if index == base + 1 {
                    bound += 4 * product_bounds[product_index];
                }
                if index == base + 3 {
                    bound += 64 * product_bounds[product_index];
                }
            }
            bound
        });
        let folded_abs = folded_bounds
            .iter()
            .rev()
            .fold(BigUint::zero(), |value, coefficient| {
                value * u32::try_from(RADIX).unwrap() + BigUint::from(*coefficient)
            });
        let p = modulus();
        let positive_residual = (&folded_abs / &p).to_i32().unwrap();
        let negative_residual_abs = ((&folded_abs + &p - BigUint::from(1u32)) / &p)
            .to_i32()
            .unwrap();
        assert_eq!(positive_residual, RESIDUAL_MAX);
        assert_eq!(-negative_residual_abs, RESIDUAL_MIN);

        let mut carry_bound = 0u64;
        let mut maximum_carry = 0u64;
        let mut maximum_pre_carry = 0u64;
        for coefficient_index in 0..RELATION_CARRY_COUNT {
            let residual_multiplier = match coefficient_index {
                0 => 47,
                1 => 2,
                3 => 32,
                _ => 0,
            };
            let pre_carry = carry_bound
                + folded_bounds[coefficient_index]
                + residual_multiplier * RESIDUAL_MIN.unsigned_abs() as u64
                + HALF_RADIX as u64;
            maximum_pre_carry = maximum_pre_carry.max(pre_carry);
            carry_bound = pre_carry / RADIX as u64;
            maximum_carry = maximum_carry.max(carry_bound);
        }
        assert_eq!(maximum_carry, RELATION_CARRY_ABS_BOUND as u64);
        assert_eq!(maximum_pre_carry, PRE_CARRY_ABS_BOUND as u64);
        assert!(maximum_pre_carry < u64::from(scriptint::MAX_SCRIPTNUM));
    }

    #[test]
    fn exactly_267_boundary_and_seeded_cases_execute() {
        let p = modulus();
        let zero = BigUint::zero();
        let one = BigUint::from(1u32);
        let two = BigUint::from(2u32);
        let p_minus_one = &p - &one;
        let p_minus_two = &p - &two;
        let half = &p >> 1usize;
        let boundary_pairs = vec![
            (zero.clone(), zero.clone()),
            (zero.clone(), p_minus_one.clone()),
            (one.clone(), one.clone()),
            (one.clone(), p_minus_one.clone()),
            (two.clone(), p_minus_two.clone()),
            (BigUint::from(255u32), BigUint::from(256u32)),
            (BigUint::from(256u32), BigUint::from(257u32)),
            (half.clone(), half),
            (p_minus_one.clone(), p_minus_one.clone()),
            (p_minus_one.clone(), p_minus_two.clone()),
            (p_minus_two.clone(), p_minus_two),
        ];
        assert_eq!(boundary_pairs.len(), 11);

        let mut maximum_peak = 0usize;
        for (lhs, rhs) in boundary_pairs {
            maximum_peak = maximum_peak.max(execute_case(&lhs, &rhs).1);
        }
        let mut rng = ChaCha20Rng::seed_from_u64(0x4d4f_4e54_3136);
        for _ in 0..256 {
            let lhs = rng.gen_biguint_below(&p);
            let rhs = rng.gen_biguint_below(&p);
            maximum_peak = maximum_peak.max(execute_case(&lhs, &rhs).1);
        }
        assert_eq!(maximum_peak, HINTED_MUL_STACK_ITEMS as usize);
    }

    #[test]
    fn encoding_is_closed_under_multiplication_and_chaining() {
        let p = modulus();
        let logical_values = [
            BigUint::zero(),
            BigUint::from(1u32),
            BigUint::from(2u32),
            BigUint::from(255u32),
            BigUint::from(256u32),
            BigUint::from(257u32),
            &p >> 1usize,
            &p - BigUint::from(2u32),
            &p - BigUint::from(1u32),
        ];
        for logical_lhs in &logical_values {
            for logical_rhs in &logical_values {
                let lhs = encode(logical_lhs);
                let rhs = encode(logical_rhs);
                let hints = hinted_mul(&lhs, &rhs);
                let logical_product = logical_lhs * logical_rhs % &p;
                assert_eq!(hints.remainder, encode(&logical_product));
                assert_eq!(decode(&hints.remainder), logical_product);
            }
        }

        let mut encoded_accumulator = encode(&BigUint::from(1u32));
        let mut logical_accumulator = BigUint::from(1u32);
        for logical_factor in logical_values.iter().skip(1) {
            let encoded_factor = encode(logical_factor);
            let hints = hinted_mul(&encoded_accumulator, &encoded_factor);
            execute_case(&encoded_accumulator, &encoded_factor);
            encoded_accumulator = hints.remainder;
            logical_accumulator = logical_accumulator * logical_factor % &p;
            assert_eq!(decode(&encoded_accumulator), logical_accumulator);
        }
    }

    #[test]
    fn every_hint_item_is_bound_and_output_order_is_stable() {
        let p = modulus();
        let lhs = &p - BigUint::from(1u32);
        let rhs = &p - BigUint::from(2u32);
        let hints = hinted_mul(&lhs, &rhs);
        for carry_index in 0..RELATION_CARRY_COUNT {
            let mut malformed = hints.clone();
            malformed.carries[carry_index] += 1;
            let rejected = execute_script(script! {
                { push_mul_witness(&lhs, &rhs, &malformed) }
                { mul_mod_hinted(0) }
                OP_TRUE
            });
            assert!(!rejected.success, "tampered carry {carry_index} accepted");
        }
        for delta in [-1, 1] {
            let mut malformed = hints.clone();
            malformed.residual += delta;
            let rejected = execute_script(script! {
                { push_mul_witness(&lhs, &rhs, &malformed) }
                { mul_mod_hinted(0) }
                OP_TRUE
            });
            assert!(!rejected.success, "tampered residual {delta} accepted");
        }

        let output = execute_script(script! {
            { push_mul_witness(&lhs, &rhs, &hints) }
            { mul_mod_hinted(0) }
        });
        assert!(output.error.is_none(), "output-order execution: {output}");
        assert_eq!(output.final_stack.len(), FIELD_DIGIT_COUNT);
        for (index, digit) in field_digits(&hints.remainder).iter().rev().enumerate() {
            assert_eq!(output.final_stack.get(index), scriptnum_item(*digit));
        }
    }

    #[test]
    fn exact_stack_limit_preserves_main_and_alt_state_and_plus_one_is_guarded() {
        const PRESERVED_MAIN: usize = 100;
        const PRESERVED_ALT: usize = MAX_PRESERVED_ITEMS as usize - PRESERVED_MAIN;
        let p = modulus();
        let lhs = &p - BigUint::from(1u32);
        let rhs = &p - BigUint::from(2u32);
        let hints = hinted_mul(&lhs, &rhs);
        let exact = execute_script(script! {
            for item in 1..=PRESERVED_MAIN { { 10_000 + item as i32 } }
            for item in 1..=PRESERVED_ALT {
                { 20_000 + item as i32 } OP_TOALTSTACK
            }
            { push_mul_witness(&lhs, &rhs, &hints) }
            { mul_mod_hinted(MAX_PRESERVED_ITEMS) }
            { expected_check(&hints.remainder) } OP_VERIFY
            for item in (1..=PRESERVED_MAIN).rev() {
                { 10_000 + item as i32 } OP_EQUALVERIFY
            }
            for item in (1..=PRESERVED_ALT).rev() {
                OP_FROMALTSTACK { 20_000 + item as i32 } OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(exact.success, "exact 1,000-item audit: {exact}");
        assert_eq!(
            exact.stats.max_nb_stack_items,
            U31_LOOKUP_STACK_LIMIT as usize
        );

        assert!(std::panic::catch_unwind(|| mul_mod_hinted(MAX_PRESERVED_ITEMS + 1)).is_err());
    }

    #[test]
    fn exact_cost_and_witness_metrics_are_stable() {
        let cost = one_shot_cost_breakdown();
        assert_eq!(cost.table_setup, 1_538);
        assert_eq!(cost.table_drop, 257);
        assert_eq!(cost.product_generation, 15_615);
        assert_eq!(cost.folded_relation, 2_674);
        assert_eq!(cost.cleanup, 417);
        assert_eq!(cost.table_overhead(), 1_795);
        assert_eq!(cost.computation(), 18_706);
        assert_eq!(cost.total(), 20_501);

        let p = modulus();
        let hints = hinted_mul(&(&p - BigUint::from(1u32)), &(&p - BigUint::from(1u32)));
        assert_eq!(hints.witness_items().len(), HINT_ITEM_COUNT);
        assert_eq!(
            serialize(&Witness::from_slice(&hints.witness_items())).len(),
            37
        );
    }
}
