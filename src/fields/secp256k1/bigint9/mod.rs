//! Exact hinted multiplication in the secp256k1 base field.
//!
//! Field elements use 29 balanced radix-`2^9` digits. Multiplication uses the
//! exact quarter-square identity
//!
//! `x*y = floor((|x+y|)^2/4) - floor((|x-y|)^2/4)`
//!
//! and one shared 513-item table. Reduction is not an RNS congruence: 56
//! witnessed carries verify the exact integer identity `lhs*rhs = q*p + r`,
//! where `p = 2^256 - 2^32 - 977`. The returned digits are range checked and
//! proved to encode `0 <= r < p`, so there is no CRT-wraparound ambiguity.
//!
//! The multiplication fragments require both operands to have passed
//! [`certify_value`] (or an equivalent exact binding) on the same verified
//! script path. Quotient digits intentionally are not range checked. They are
//! existential coefficients of one exact integer `q`, are never returned, and
//! cannot create a false field result; oversized hostile values fail closed in
//! four-byte Script arithmetic.

use num_bigint::BigUint;
use num_traits::{One, ToPrimitive};

use crate::{
    arithmetic::{scriptint, u31::U31_LOOKUP_STACK_LIMIT},
    support::script::*,
};

/// Factor-16 Montgomery-domain multiplication with a 29-item hint witness.
pub mod factor16;

/// Number of balanced radix-512 digits in a field value.
pub const FIELD_DIGIT_COUNT: usize = 29;

/// Number of mixed-width balanced digits used for the quotient hint.
pub const QUOTIENT_DIGIT_COUNT: usize = 11;

/// Number of exact radix-512 relation carries.
pub const RELATION_CARRY_COUNT: usize = 56;

/// Incremental witness items for one multiplication: quotient plus carries.
pub const HINT_ITEM_COUNT: usize = QUOTIENT_DIGIT_COUNT + RELATION_CARRY_COUNT;

/// Complete preloaded items for one multiplication: two operands plus hints.
pub const MUL_WITNESS_ITEM_COUNT: usize = 2 * FIELD_DIGIT_COUNT + HINT_ITEM_COUNT;

/// Complete preloaded items for one square: one operand plus hints.
pub const SQUARE_WITNESS_ITEM_COUNT: usize = FIELD_DIGIT_COUNT + HINT_ITEM_COUNT;

/// Operand/quotient items left below a resident table after one relation.
const CONSUMED_RELATION_ITEMS: usize = 2 * FIELD_DIGIT_COUNT + QUOTIENT_DIGIT_COUNT;

/// Operand/quotient items left below the table after one square relation.
const CONSUMED_SQUARE_RELATION_ITEMS: usize = FIELD_DIGIT_COUNT + QUOTIENT_DIGIT_COUNT;

/// Maximum number of complete witness groups that fit beside the table and
/// product temporaries under Bitcoin Script's 1,000-item combined-stack limit.
/// The three-gate case uses a compact destructive coefficient schedule.
pub const MAX_PRELOADED_BATCH_SIZE: usize = 3;

/// Maximum strict-stack preloaded square batch size.
pub const MAX_PRELOADED_SQUARE_BATCH_SIZE: usize = 5;

/// Items in the resident quarter-square table.
pub const TABLE_ITEM_COUNT: u32 = 513;

/// Measured combined-stack peak of either multiplication layout with no
/// unrelated live state. The 1,000-item guard is also enforced at generation.
pub const HINTED_MUL_STACK_ITEMS: u32 = 757;

/// Exact combined-stack peak of the compact three-multiplication batch.
const COMPACT_MUL_BATCH_STACK_ITEMS: u32 = 993;

/// Exact combined-stack peak of one hinted square without unrelated state.
pub const HINTED_SQUARE_STACK_ITEMS: u32 = 614;

const RADIX_BITS: usize = 9;
const RADIX: i32 = 512;
const HALF_RADIX: i32 = 256;
const TABLE_MAX: usize = 512;
const TABLE_BIAS: i32 = 32_752;
// The three 26-bit chunks start where -p's base-512 correction has maximum
// coefficient 47 (and the selected chain has maximum live coefficient 48).
// All other non-top chunks are 22 or 23 bits. The final chunk starts at bit
// 234 and is an unsigned top chunk of at most 22 bits.
const QUOTIENT_WIDTHS: [usize; QUOTIENT_DIGIT_COUNT] = [26, 23, 23, 26, 23, 23, 23, 22, 23, 22, 22];
const QUOTIENT_STARTS: [usize; QUOTIENT_DIGIT_COUNT] =
    [0, 26, 49, 72, 98, 121, 144, 167, 189, 212, 234];

/// Balanced radix-512 representation, least-significant digit first.
pub type FieldDigits = [i32; FIELD_DIGIT_COUNT];

/// Mixed-radix quotient representation, least-significant digit first.
pub type QuotientDigits = [i32; QUOTIENT_DIGIT_COUNT];

/// Exact coefficient carries, least-significant carry first.
pub type RelationCarries = [i32; RELATION_CARRY_COUNT];

/// Host-generated hints for one exact modular multiplication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MulHints {
    /// Canonical field result corresponding to these hints.
    pub remainder: BigUint,
    /// Existential quotient coefficients. Canonicality is not a verifier
    /// requirement, but the host generator emits balanced lower chunks and a
    /// bounded unsigned top chunk.
    pub quotient: QuotientDigits,
    /// Exact radix-512 relation carries.
    pub carries: RelationCarries,
}

impl MulHints {
    /// Push quotient digits and carries in the order consumed by the gate.
    ///
    /// Stack after: `... q[10] ... q[0] c[55] ... c[0]`, with `c[0]` on top.
    pub fn push_script(&self) -> Script {
        script! {
            { push_balanced(&self.quotient) }
            for carry in self.carries.iter().rev() {
                { *carry }
            }
        }
    }

    /// Return raw Script-number witness items in push order.
    pub fn witness_items(&self) -> Vec<Vec<u8>> {
        self.quotient
            .iter()
            .rev()
            .chain(self.carries.iter().rev())
            .map(|value| scriptnum_item(*value))
            .collect()
    }
}

/// Host-generated hints for one exact modular square.
///
/// Carries use the direct symmetric schoolbook coefficient basis of the square
/// gate. They are deliberately a distinct type from [`MulHints`], whose
/// carries use the normalized-Karatsuba multiplication basis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SquareHints {
    /// Canonical field result corresponding to these hints.
    pub remainder: BigUint,
    /// Existential mixed-width quotient coefficients.
    pub quotient: QuotientDigits,
    /// Exact radix-512 carries in the square gate's coefficient basis.
    pub carries: RelationCarries,
}

impl SquareHints {
    /// Push quotient digits and carries in the order consumed by the gate.
    pub fn push_script(&self) -> Script {
        script! {
            { push_balanced(&self.quotient) }
            for carry in self.carries.iter().rev() {
                { *carry }
            }
        }
    }

    /// Return raw Script-number witness items in push order.
    pub fn witness_items(&self) -> Vec<Vec<u8>> {
        self.quotient
            .iter()
            .rev()
            .chain(self.carries.iter().rev())
            .map(|value| scriptnum_item(*value))
            .collect()
    }
}

/// Exact locking-script attribution for the self-contained one-shot gate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OneShotCostBreakdown {
    /// Push the 513 biased quarter-square entries.
    pub table_setup: usize,
    /// Drop the 513 entries after this multiplication.
    pub table_drop: usize,
    /// The 196 low-block and 225 high-block signed digit products.
    pub raw_digit_products: usize,
    /// The 225 signed products of the two normalized block differences.
    pub difference_digit_products: usize,
    /// Carry-normalize both signed block differences to 15 balanced digits.
    pub difference_normalization: usize,
    /// Restore/drop the difference and product coefficient arrays.
    pub coefficient_routing: usize,
    /// Recombine the three product arrays coefficient by coefficient.
    pub coefficient_recombination: usize,
    /// Quotient correction, carry equations, operand cleanup, and result validation.
    pub relation_and_output: usize,
}

impl OneShotCostBreakdown {
    /// Complete one-shot fragment size.
    pub fn total(self) -> usize {
        self.table_setup
            + self.table_drop
            + self.raw_digit_products
            + self.difference_digit_products
            + self.difference_normalization
            + self.coefficient_routing
            + self.coefficient_recombination
            + self.relation_and_output
    }

    /// Static lookup-memory overhead.
    pub fn table_overhead(self) -> usize {
        self.table_setup + self.table_drop
    }

    /// Actual per-multiplication computation, excluding table push/drop.
    pub fn computation(self) -> usize {
        self.raw_digit_products
            + self.difference_digit_products
            + self.difference_normalization
            + self.coefficient_routing
            + self.coefficient_recombination
            + self.relation_and_output
    }
}

/// Exact locking-script attribution for one specialized square.
///
/// This path uses the same biased table as multiplication. Each of the 29
/// diagonal lookups adds back [`TABLE_BIAS`]; despite those corrections, the
/// common biased setup is three bytes smaller than a private unbiased table.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SquareOneShotCostBreakdown {
    /// Push the common 513-item biased quarter-square table.
    pub table_setup: usize,
    /// Drop the table after this square.
    pub table_drop: usize,
    /// The 29 one-lookup diagonal terms.
    pub diagonal_products: usize,
    /// The 406 doubled off-diagonal products.
    pub off_diagonal_products: usize,
    /// Quotient correction, carry equations, cleanup, and result validation.
    pub relation_and_output: usize,
}

impl SquareOneShotCostBreakdown {
    pub fn total(self) -> usize {
        self.table_setup
            + self.table_drop
            + self.diagonal_products
            + self.off_diagonal_products
            + self.relation_and_output
    }

    pub fn table_overhead(self) -> usize {
        self.table_setup + self.table_drop
    }

    pub fn computation(self) -> usize {
        self.diagonal_products + self.off_diagonal_products + self.relation_and_output
    }
}

/// Exact locking-script attribution when the table remains resident.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResidentCostBreakdown {
    /// One-time table setup.
    pub table_setup: usize,
    /// One multiplication that leaves the table resident.
    pub mul_with_table: usize,
    /// Route one result around the final table drop.
    pub final_cleanup: usize,
}

impl ResidentCostBreakdown {
    /// Setup, one resident multiplication, and final cleanup.
    pub fn one_multiplication_total(self) -> usize {
        self.table_setup + self.mul_with_table + self.final_cleanup
    }
}

/// Exact attribution for a square using a resident common biased table.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SquareResidentCostBreakdown {
    pub table_setup: usize,
    pub square_with_table: usize,
    pub final_cleanup: usize,
}

impl SquareResidentCostBreakdown {
    pub fn one_square_total(self) -> usize {
        self.table_setup + self.square_with_table + self.final_cleanup
    }
}

/// Generation-time strategy selected for a multiplication batch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MulBatchStrategy {
    /// The ordinary private-table gate, optimal for one multiplication.
    #[default]
    OneShot,
    /// The 85-coefficient resident-table gate, optimal for two multiplications.
    ResidentKaratsuba,
    /// The destructive 57-coefficient schedule required to fit three gates.
    CompactStackKaratsuba,
}

/// Exact locking-script attribution for a preloaded table-sharing batch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BatchCostBreakdown {
    /// Number of multiplications in this batch.
    pub multiplication_count: usize,
    /// Generation-time strategy selected for this batch size.
    pub strategy: MulBatchStrategy,
    /// One-time push of the 513 quarter-square entries.
    pub table_setup: usize,
    /// Exact relation body for each multiplication under the selected strategy.
    /// This excludes the separately attributed table drop.
    pub relation_per_multiplication: usize,
    /// One-time drop of the resident table.
    pub table_drop: usize,
    /// Drop all consumed operand and quotient items after the relations.
    pub consumed_input_cleanup: usize,
    /// Restore and field-validate every derived result.
    pub output_restore_and_validation: usize,
}

impl BatchCostBreakdown {
    /// Complete batch fragment size.
    pub fn total(self) -> usize {
        self.table_setup
            + self.relation_per_multiplication * self.multiplication_count
            + self.table_drop
            + self.consumed_input_cleanup
            + self.output_restore_and_validation
    }

    /// One-time lookup-memory overhead shared by the entire batch.
    pub fn table_overhead(self) -> usize {
        self.table_setup + self.table_drop
    }

    /// All non-table computation and cleanup in the batch.
    pub fn computation(self) -> usize {
        self.total() - self.table_overhead()
    }
}

/// Exact attribution for a square-only preloaded batch.
///
/// Unlike the single/resident square API, this batch owns an unbiased table.
/// Omitting 29 bias corrections per relation saves `116*n - 119` bytes for
/// every supported batch size `n >= 2`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SquareBatchCostBreakdown {
    pub square_count: usize,
    /// One-time push of the square-only unbiased table.
    pub unbiased_table_setup: usize,
    pub relation_per_square: usize,
    pub table_drop: usize,
    pub consumed_input_cleanup: usize,
    pub output_restore_and_validation: usize,
}

impl SquareBatchCostBreakdown {
    pub fn total(self) -> usize {
        self.unbiased_table_setup
            + self.relation_per_square * self.square_count
            + self.table_drop
            + self.consumed_input_cleanup
            + self.output_restore_and_validation
    }

    pub fn table_overhead(self) -> usize {
        self.unbiased_table_setup + self.table_drop
    }

    pub fn computation(self) -> usize {
        self.total() - self.table_overhead()
    }
}

/// Return `p = 2^256 - 2^32 - 977`.
pub fn modulus() -> BigUint {
    (BigUint::one() << 256usize) - (BigUint::one() << 32usize) - BigUint::from(977u32)
}

fn balanced_digits_unchecked(value: &BigUint) -> FieldDigits {
    let mut value = value.clone();
    std::array::from_fn(|index| {
        if index + 1 == FIELD_DIGIT_COUNT {
            return value.to_i32().expect("top field digit fits i32");
        }
        let unsigned = (&value & BigUint::from((RADIX - 1) as u32))
            .to_u32()
            .expect("a radix-512 digit fits u32") as i32;
        let digit = if unsigned >= HALF_RADIX {
            unsigned - RADIX
        } else {
            unsigned
        };
        if digit >= 0 {
            value -= BigUint::from(digit as u32);
        } else {
            value += BigUint::from((-digit) as u32);
        }
        value >>= RADIX_BITS;
        digit
    })
}

/// Encode a canonical field value as exact balanced radix-512 digits.
pub fn field_digits(value: &BigUint) -> FieldDigits {
    assert!(
        value < &modulus(),
        "secp256k1 field value must be smaller than p"
    );
    balanced_digits_unchecked(value)
}

fn quotient_digits(value: &BigUint) -> QuotientDigits {
    let mut value = value.clone();
    std::array::from_fn(|index| {
        if index + 1 == QUOTIENT_DIGIT_COUNT {
            return value.to_i32().expect("top quotient digit fits i32");
        }
        let radix = 1i32 << QUOTIENT_WIDTHS[index];
        let half_radix = radix / 2;
        let unsigned = (&value & BigUint::from((radix - 1) as u32))
            .to_u32()
            .expect("a quotient digit fits u32") as i32;
        let digit = if unsigned >= half_radix {
            unsigned - radix
        } else {
            unsigned
        };
        if digit >= 0 {
            value -= BigUint::from(digit as u32);
        } else {
            value += BigUint::from((-digit) as u32);
        }
        value >>= QUOTIENT_WIDTHS[index];
        digit
    })
}

/// Centered radix-512 coefficients of
/// `2^bit_remainder * (977 + 2^32 - 2^256) = -2^bit_remainder*p`.
fn correction_terms(bit_remainder: usize) -> Vec<(usize, i32)> {
    let mut coefficients = [0i32; 32];
    coefficients[0] += 977i32 << bit_remainder;
    coefficients[(32 + bit_remainder) / RADIX_BITS] += 1i32 << ((32 + bit_remainder) % RADIX_BITS);
    coefficients[(256 + bit_remainder) / RADIX_BITS] -=
        1i32 << ((256 + bit_remainder) % RADIX_BITS);
    for index in 0..coefficients.len() - 1 {
        while coefficients[index] > 255 {
            coefficients[index] -= RADIX;
            coefficients[index + 1] += 1;
        }
        while coefficients[index] < -256 {
            coefficients[index] += RADIX;
            coefficients[index + 1] -= 1;
        }
    }
    coefficients
        .into_iter()
        .enumerate()
        .filter(|(_, coefficient)| *coefficient != 0)
        .collect()
}

fn quotient_terms_at(coefficient_index: usize) -> Vec<(usize, i32)> {
    let mut terms = Vec::new();
    for quotient_index in 0..QUOTIENT_DIGIT_COUNT {
        let exponent = QUOTIENT_STARTS[quotient_index];
        let base_index = exponent / RADIX_BITS;
        let remainder = exponent % RADIX_BITS;
        for (relative_index, coefficient) in correction_terms(remainder) {
            if base_index + relative_index == coefficient_index {
                terms.push((quotient_index, coefficient));
            }
        }
    }
    terms
}

fn normalized_difference(lhs: &[i32], rhs: &[i32]) -> [i32; KARATSUBA_DIFFERENCE_DIGITS] {
    let mut carry = 0i32;
    let result = std::array::from_fn(|index| {
        let coefficient =
            carry + lhs.get(index).copied().unwrap_or(0) - rhs.get(index).copied().unwrap_or(0);
        let (digit, next_carry) = if coefficient >= HALF_RADIX {
            (coefficient - RADIX, 1)
        } else if coefficient < -HALF_RADIX {
            (coefficient + RADIX, -1)
        } else {
            (coefficient, 0)
        };
        carry = next_carry;
        digit
    });
    assert_eq!(
        carry, 0,
        "asymmetric field split difference must fit 15 digits"
    );
    result
}

fn convolution(lhs: &[i32], rhs: &[i32]) -> Vec<i64> {
    let mut result = vec![0i64; lhs.len() + rhs.len() - 1];
    for (lhs_index, lhs_digit) in lhs.iter().enumerate() {
        for (rhs_index, rhs_digit) in rhs.iter().enumerate() {
            result[lhs_index + rhs_index] += i64::from(*lhs_digit) * i64::from(*rhs_digit);
        }
    }
    result
}

/// Coefficients verified by the normalized one-level Karatsuba gate.
///
/// Normalizing either difference changes its formal coefficient polynomial by
/// a multiple of `X - 512`, so these coefficients are intentionally not the
/// schoolbook coefficients. Their evaluation at `X = 512` is still exactly
/// `lhs * rhs`; the carry witness must therefore be generated in this same
/// basis.
fn karatsuba_coefficients(lhs: &FieldDigits, rhs: &FieldDigits) -> [i64; 57] {
    let z0 = convolution(&lhs[..KARATSUBA_SPLIT], &rhs[..KARATSUBA_SPLIT]);
    let z2 = convolution(&lhs[KARATSUBA_SPLIT..], &rhs[KARATSUBA_SPLIT..]);
    let lhs_difference = normalized_difference(&lhs[..KARATSUBA_SPLIT], &lhs[KARATSUBA_SPLIT..]);
    let rhs_difference = normalized_difference(&rhs[KARATSUBA_SPLIT..], &rhs[..KARATSUBA_SPLIT]);
    let difference_product = convolution(&lhs_difference, &rhs_difference);
    std::array::from_fn(|coefficient_index| {
        let mut coefficient = z0.get(coefficient_index).copied().unwrap_or(0);
        if coefficient_index >= KARATSUBA_SPLIT {
            let cross_index = coefficient_index - KARATSUBA_SPLIT;
            coefficient += z0.get(cross_index).copied().unwrap_or(0);
            coefficient += z2.get(cross_index).copied().unwrap_or(0);
            coefficient += difference_product.get(cross_index).copied().unwrap_or(0);
        }
        if coefficient_index >= 2 * KARATSUBA_SPLIT {
            coefficient += z2
                .get(coefficient_index - 2 * KARATSUBA_SPLIT)
                .copied()
                .unwrap_or(0);
        }
        coefficient
    })
}

fn relation_carries(
    lhs: &FieldDigits,
    rhs: &FieldDigits,
    quotient: &QuotientDigits,
    remainder: &FieldDigits,
) -> RelationCarries {
    let product = karatsuba_coefficients(lhs, rhs);
    let mut previous = 0i64;
    std::array::from_fn(|coefficient_index| {
        let mut coefficient = previous + product[coefficient_index];
        for (quotient_index, multiplier) in quotient_terms_at(coefficient_index) {
            coefficient += i64::from(multiplier) * i64::from(quotient[quotient_index]);
        }
        if coefficient_index < FIELD_DIGIT_COUNT {
            coefficient -= i64::from(remainder[coefficient_index]);
        }
        assert_eq!(
            coefficient % i64::from(RADIX),
            0,
            "exact relation coefficient {coefficient_index} is not divisible by 512"
        );
        let next = coefficient / i64::from(RADIX);
        previous = next;
        i32::try_from(next).expect("honest relation carry fits ScriptNum")
    })
}

/// Generate the quotient/carry witness and canonical result for `lhs*rhs mod p`.
pub fn hinted_mul(lhs: &BigUint, rhs: &BigUint) -> MulHints {
    let p = modulus();
    assert!(lhs < &p, "left operand must be canonical");
    assert!(rhs < &p, "right operand must be canonical");
    let product = lhs * rhs;
    let quotient_value = &product / &p;
    let remainder = &product % &p;
    let lhs_digits = balanced_digits_unchecked(lhs);
    let rhs_digits = balanced_digits_unchecked(rhs);
    let quotient = quotient_digits(&quotient_value);
    let remainder_digits = balanced_digits_unchecked(&remainder);
    let carries = relation_carries(&lhs_digits, &rhs_digits, &quotient, &remainder_digits);
    let final_coefficient = i64::from(carries[RELATION_CARRY_COUNT - 1])
        + karatsuba_coefficients(&lhs_digits, &rhs_digits)[2 * FIELD_DIGIT_COUNT - 2]
        + quotient_terms_at(2 * FIELD_DIGIT_COUNT - 2)
            .into_iter()
            .map(|(index, multiplier)| i64::from(multiplier) * i64::from(quotient[index]))
            .sum::<i64>();
    assert_eq!(final_coefficient, 0, "final exact relation coefficient");
    MulHints {
        remainder,
        quotient,
        carries,
    }
}

fn square_coefficients(value: &FieldDigits) -> [i64; 57] {
    let coefficients = convolution(value, value);
    std::array::from_fn(|index| coefficients[index])
}

fn square_relation_carries(
    value: &FieldDigits,
    quotient: &QuotientDigits,
    remainder: &FieldDigits,
) -> RelationCarries {
    let product = square_coefficients(value);
    let mut previous = 0i64;
    std::array::from_fn(|coefficient_index| {
        let mut coefficient = previous + product[coefficient_index];
        for (quotient_index, multiplier) in quotient_terms_at(coefficient_index) {
            coefficient += i64::from(multiplier) * i64::from(quotient[quotient_index]);
        }
        if coefficient_index < FIELD_DIGIT_COUNT {
            coefficient -= i64::from(remainder[coefficient_index]);
        }
        assert_eq!(
            coefficient % i64::from(RADIX),
            0,
            "exact square coefficient {coefficient_index} is not divisible by 512"
        );
        let next = coefficient / i64::from(RADIX);
        previous = next;
        i32::try_from(next).expect("honest square relation carry fits ScriptNum")
    })
}

/// Generate the quotient/carry witness and canonical result for `value^2 mod p`.
pub fn hinted_square(value: &BigUint) -> SquareHints {
    let p = modulus();
    assert!(value < &p, "square operand must be canonical");
    let product = value * value;
    let quotient_value = &product / &p;
    let remainder = &product % &p;
    let value_digits = balanced_digits_unchecked(value);
    let quotient = quotient_digits(&quotient_value);
    let remainder_digits = balanced_digits_unchecked(&remainder);
    let carries = square_relation_carries(&value_digits, &quotient, &remainder_digits);
    let final_coefficient = i64::from(carries[RELATION_CARRY_COUNT - 1])
        + square_coefficients(&value_digits)[2 * FIELD_DIGIT_COUNT - 2]
        + quotient_terms_at(2 * FIELD_DIGIT_COUNT - 2)
            .into_iter()
            .map(|(index, multiplier)| i64::from(multiplier) * i64::from(quotient[index]))
            .sum::<i64>();
    assert_eq!(
        final_coefficient, 0,
        "final exact square relation coefficient"
    );
    SquareHints {
        remainder,
        quotient,
        carries,
    }
}

fn push_balanced(digits: &[i32]) -> Script {
    script! {
        for digit in digits.iter().rev() {
            { *digit }
        }
    }
}

/// Push a canonical field value with digit zero on top.
pub fn push_value(value: &BigUint) -> Script {
    push_balanced(&field_digits(value))
}

/// Push two canonical operands followed by one multiplication's hints.
///
/// This is a convenience for complete witness tests. Composable protocols
/// normally keep certified operands as live script state and push only
/// [`MulHints::push_script`].
pub fn push_mul_witness(lhs: &BigUint, rhs: &BigUint, hints: &MulHints) -> Script {
    script! {
        { push_value(lhs) }
        { push_value(rhs) }
        { hints.push_script() }
    }
}

/// Push one canonical square operand followed by its square-basis hints.
pub fn push_square_witness(value: &BigUint, hints: &SquareHints) -> Script {
    script! {
        { push_value(value) }
        { hints.push_script() }
    }
}

fn scriptnum_item(value: i32) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value));
    bytes[..length].to_vec()
}

fn assert_stack_peak(preserved_items: u32, operation_peak: u32, operation: &str) {
    assert!(
        u64::from(preserved_items) + u64::from(operation_peak) <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "{operation} exceeds Bitcoin Script's stack limit"
    );
}

fn table_setup_unchecked() -> Script {
    script! {
        for value in (0..=TABLE_MAX).rev() {
            { ((value * value) / 4) as i32 - TABLE_BIAS }
        }
    }
}

/// Square-only batches use exact Q values. This setup is 119 bytes larger than
/// the common biased table but removes a four-byte bias correction from every
/// one of 29 diagonals in each relation.
fn square_batch_table_setup_unchecked() -> Script {
    script! {
        for value in (0..=TABLE_MAX).rev() {
            { ((value * value) / 4) as i32 }
        }
    }
}

/// Push the 513 biased quarter-square entries, with entry zero on top.
///
/// `preserved_items` is the number of items already live below the table.
pub fn table_setup(preserved_items: u32) -> Script {
    assert_stack_peak(
        preserved_items,
        TABLE_ITEM_COUNT,
        "secp256k1 quarter-square table setup",
    );
    table_setup_unchecked()
}

/// Drop a quarter-square table that is directly on top of the main stack.
pub fn table_drop() -> Script {
    script! {
        for _ in 0..TABLE_MAX / 2 {
            OP_2DROP
        }
        OP_DROP
    }
}

/// Drop a resident table directly below one 29-digit field value.
///
/// Input: `... table value`. Output: `... value`.
pub fn final_table_cleanup_with_one_value() -> Script {
    script! {
        for _ in 0..FIELD_DIGIT_COUNT {
            OP_TOALTSTACK
        }
        { table_drop() }
        for _ in 0..FIELD_DIGIT_COUNT {
            OP_FROMALTSTACK
        }
    }
}

/// Verify that already range-checked balanced digits encode `0 <= value < p`.
fn verify_field_range_keep_at_depth(value_depth: u32) -> Script {
    let p = balanced_digits_unchecked(&modulus());
    debug_assert_eq!(p[FIELD_DIGIT_COUNT - 1], 16);
    script! {
        { value_depth + (FIELD_DIGIT_COUNT - 1) as u32 } OP_PICK
        OP_DUP 0 17 OP_WITHIN OP_VERIFY

        // Top digits 1..15 imply 0 < value < p regardless of the tail.
        OP_DUP 0 OP_GREATERTHAN
        OP_OVER 16 OP_LESSTHAN
        OP_BOOLAND
        OP_IF
            OP_DROP
        OP_ELSE
            // At the two boundaries, scan low-to-high. Every nonzero
            // difference replaces the status, so the final status is the
            // most-significant nonzero difference.
            16 OP_EQUAL
            0
            for index in 0..FIELD_DIGIT_COUNT - 1 {
                { value_depth + index as u32 + 2 } OP_PICK
                if p[index] != 0 {
                    2 OP_PICK
                    OP_IF
                        { p[index] } OP_SUB
                    OP_ENDIF
                }
                OP_DUP OP_0NOTEQUAL
                OP_IF
                    OP_NIP
                OP_ELSE
                    OP_DROP
                OP_ENDIF
            }

            // top=16 needs tail<p_tail (negative status); top=0 needs a
            // nonnegative tail. Equality of these booleans proves the range.
            OP_DUP 0 OP_LESSTHAN
            OP_ROT OP_EQUALVERIFY
            OP_DROP
        OP_ENDIF
    }
}

/// Certify one balanced-radix value in place as a canonical field element.
///
/// Input/output: `... d[28] ... d[0]`, with digit zero on top. Lower digits
/// are checked in `[-256,256)`; the field-range verifier supplies the stronger
/// `0..=16` constraint on the top digit and proves the exact integer is below
/// the secp256k1 modulus.
pub fn certify_value() -> Script {
    certify_value_at_depth(0)
}

/// Certify a balanced field value below `items_above` live stack items.
///
/// The value and every item above it are preserved. Digit zero is the nearest
/// digit of the value to the top, at depth `items_above`.
pub fn certify_value_at_depth(items_above: u32) -> Script {
    assert!(
        u64::from(items_above) + FIELD_DIGIT_COUNT as u64 + 4 <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "secp256k1 field certification exceeds Bitcoin Script's stack limit"
    );
    script! {
        for index in 0..FIELD_DIGIT_COUNT - 1 {
            { items_above + index as u32 } OP_PICK
            { -HALF_RADIX } { HALF_RADIX } OP_WITHIN OP_VERIFY
        }
        { verify_field_range_keep_at_depth(items_above) }
    }
}

fn product_into_accumulator(lhs_depth: u32, rhs_depth_after_lhs: u32, table_depth: u32) -> Script {
    let first_lookup_depth = table_depth + 1;
    let second_lookup_depth = table_depth - 1;
    script! {
        { lhs_depth } OP_PICK
        { rhs_depth_after_lhs } OP_PICK
        // Q(|x+y|) - Q(|x-y|). The common table bias cancels.
        OP_2DUP OP_SUB OP_ABS
        { first_lookup_depth } OP_ADD OP_PICK OP_TOALTSTACK
        OP_ADD OP_ABS
        if second_lookup_depth == 1 {
            OP_1ADD
        } else {
            { second_lookup_depth } OP_ADD
        }
        OP_PICK OP_FROMALTSTACK
        OP_SUB
        OP_ADD
    }
}

fn square_off_diagonal_into_accumulator(
    first_depth: u32,
    second_depth_after_first: u32,
    table_depth: u32,
) -> Script {
    let first_lookup_depth = table_depth + 1;
    let second_lookup_depth = table_depth - 1;
    script! {
        { first_depth } OP_PICK
        { second_depth_after_first } OP_PICK
        OP_2DUP OP_SUB OP_ABS
        { first_lookup_depth } OP_ADD OP_PICK OP_TOALTSTACK
        OP_ADD OP_ABS
        if second_lookup_depth == 1 {
            OP_1ADD
        } else {
            { second_lookup_depth } OP_ADD
        }
        OP_PICK OP_FROMALTSTACK
        OP_SUB
        // Symmetry contributes x_i*x_j at both (i,j) and (j,i).
        OP_DUP OP_ADD
        OP_ADD
    }
}

fn square_diagonal_into_accumulator(
    digit_depth: u32,
    table_lookup_depth: u32,
    biased_table: bool,
) -> Script {
    script! {
        { digit_depth } OP_PICK
        // x^2 = Q(|2x|), so a diagonal needs only one lookup.
        OP_DUP OP_ADD OP_ABS
        if table_lookup_depth == 1 {
            OP_1ADD
        } else {
            { table_lookup_depth } OP_ADD
        }
        OP_PICK
        if biased_table {
            { TABLE_BIAS } OP_ADD
        }
        OP_ADD
    }
}

fn exact_naf_mul(coefficient: u32) -> Script {
    let mut remaining = coefficient;
    let mut digits = Vec::new();
    while remaining != 0 {
        if remaining & 1 == 0 {
            digits.push(0i8);
            remaining >>= 1;
        } else {
            let digit = 2i8 - (remaining % 4) as i8;
            digits.push(digit);
            if digit > 0 {
                remaining -= 1;
            } else {
                remaining += 1;
            }
            remaining >>= 1;
        }
    }
    digits.reverse();
    script! {
        if digits.is_empty() {
            OP_DROP 0
        } else {
            OP_DUP
            for digit in digits.into_iter().skip(1) {
                OP_DUP OP_ADD
                if digit == 1 {
                    OP_OVER OP_ADD
                } else if digit == -1 {
                    OP_OVER OP_SUB
                }
            }
            OP_NIP
        }
    }
}

/// Precomputed shortest chains found by breadth-first search over Script stack
/// operations, with at most five live items and every affine coefficient in
/// `[-511,511]`. Thus even the largest live multiple at an honest quotient
/// endpoint is `511*2^22 < MAX_SCRIPTNUM`.
fn exact_precomputed_mul(coefficient: u32) -> Option<Script> {
    Some(match coefficient {
        1 => script! {},
        2 => script! { OP_DUP OP_ADD },
        4 => script! { OP_DUP OP_ADD OP_DUP OP_ADD },
        8 => script! { OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD },
        15 => script! {
            OP_DUP OP_DUP OP_ADD OP_DUP OP_ADD OP_ADD
            OP_DUP OP_DUP OP_ADD OP_ADD
        },
        16 => script! {
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
        },
        23 => script! {
            OP_DUP OP_DUP OP_ADD OP_2DUP OP_ADD OP_ADD
            OP_2DUP OP_ADD OP_ADD OP_DUP OP_ADD OP_ADD
        },
        31 => script! {
            OP_DUP OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_DUP OP_ADD OP_DUP OP_ADD OP_SWAP OP_SUB
        },
        32 => script! {
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_DUP OP_ADD
        },
        47 => script! {
            OP_DUP OP_2DUP OP_ADD OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_DUP OP_ADD OP_DUP OP_ADD OP_SWAP OP_SUB
        },
        61 => script! {
            OP_DUP OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_2DUP OP_SUB OP_SUB OP_DUP OP_ADD OP_DUP OP_ADD OP_ADD
        },
        64 => script! {
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_DUP OP_ADD OP_DUP OP_ADD
        },
        94 => script! {
            OP_DUP OP_ADD OP_DUP OP_2DUP OP_ADD OP_ADD OP_DUP OP_ADD
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_SWAP OP_SUB
        },
        122 => script! {
            OP_DUP OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_2DUP OP_SUB OP_SUB OP_DUP OP_ADD OP_DUP OP_ADD OP_ADD
            OP_DUP OP_ADD
        },
        128 => script! {
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
        },
        136 => script! {
            OP_DUP OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
        },
        188 => script! {
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_2DUP OP_ADD OP_ADD
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_SWAP OP_SUB
        },
        240 => script! {
            OP_DUP OP_DUP OP_ADD OP_DUP OP_ADD OP_ADD OP_DUP OP_DUP OP_ADD
            OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
        },
        244 => script! {
            OP_DUP OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_2DUP OP_SUB OP_SUB OP_DUP OP_ADD OP_DUP OP_ADD OP_ADD
            OP_DUP OP_ADD OP_DUP OP_ADD
        },
        256 => script! {
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
        },
        _ => return None,
    })
}

fn exact_small_constant_mul(coefficient: u32) -> Script {
    if coefficient <= 1 {
        return script! {};
    }
    let mut candidates = vec![
        scriptint::mul_by_constant(coefficient),
        exact_naf_mul(coefficient),
    ];
    if let Some(chain) = exact_precomputed_mul(coefficient) {
        candidates.push(chain);
    }
    candidates
        .into_iter()
        .min_by_key(|candidate| candidate.clone().compile_with_policy().len())
        .expect("at least one exact multiplication chain")
}

fn signed_naf_digits(coefficient: i32) -> Vec<i8> {
    let sign = if coefficient < 0 { -1 } else { 1 };
    let mut remaining = coefficient.unsigned_abs();
    let mut digits = Vec::new();
    while remaining != 0 {
        if remaining & 1 == 0 {
            digits.push(0);
            remaining >>= 1;
        } else {
            let digit = 2i8 - (remaining % 4) as i8;
            digits.push(digit * sign);
            if digit > 0 {
                remaining -= 1;
            } else {
                remaining += 1;
            }
            remaining >>= 1;
        }
    }
    digits
}

fn separate_quotient_correction(terms: &[(usize, i32)], base_depth: u32) -> Script {
    script! {
        for (quotient_index, multiplier) in terms {
            { base_depth + *quotient_index as u32 } OP_PICK
            { exact_small_constant_mul(multiplier.unsigned_abs()) }
            if *multiplier > 0 {
                OP_ADD
            } else {
                OP_SUB
            }
        }
    }
}

/// Evaluate all correction terms through one joint width-two NAF Horner chain,
/// sharing doubles between the (at most two) quotient digits at a coefficient.
fn joint_naf_quotient_correction(terms: &[(usize, i32)], base_depth: u32) -> Script {
    if terms.is_empty() {
        return script! {};
    }
    let digits: Vec<_> = terms
        .iter()
        .map(|(_, coefficient)| signed_naf_digits(*coefficient))
        .collect();
    let bit_count = digits.iter().map(Vec::len).max().unwrap();
    let mut result = Script::new("joint secp256k1 quotient correction");
    let mut started = false;
    for bit in (0..bit_count).rev() {
        if started {
            result = script! { { result } OP_DUP OP_ADD };
        }
        for (term_index, (quotient_index, _)) in terms.iter().enumerate() {
            let digit = digits[term_index].get(bit).copied().unwrap_or(0);
            if digit == 0 {
                continue;
            }
            // Once the dot-product accumulator exists, it adds one item above
            // the persistent quotient block.
            let depth = base_depth + *quotient_index as u32 + u32::from(started);
            result = script! {
                { result }
                { depth } OP_PICK
                if started {
                    if digit > 0 {
                        OP_ADD
                    } else {
                        OP_SUB
                    }
                } else if digit < 0 {
                    OP_NEGATE
                }
            };
            started = true;
        }
    }
    debug_assert!(started);
    // Add the completed dot product to the outer coefficient accumulator.
    script! { { result } OP_ADD }
}

fn quotient_correction(terms: &[(usize, i32)], base_depth: u32) -> Script {
    [
        separate_quotient_correction(terms, base_depth),
        joint_naf_quotient_correction(terms, base_depth),
    ]
    .into_iter()
    .min_by_key(|candidate| candidate.clone().compile_with_policy().len())
    .expect("one quotient-correction strategy")
}

const KARATSUBA_SPLIT: usize = 14;
const KARATSUBA_LOW_COEFFICIENTS: usize = 2 * KARATSUBA_SPLIT - 1;
const KARATSUBA_HIGH_DIGITS: usize = FIELD_DIGIT_COUNT - KARATSUBA_SPLIT;
const KARATSUBA_HIGH_COEFFICIENTS: usize = 2 * KARATSUBA_HIGH_DIGITS - 1;
const KARATSUBA_DIFFERENCE_DIGITS: usize = KARATSUBA_HIGH_DIGITS;
const KARATSUBA_DIFFERENCE_COEFFICIENTS: usize = 2 * KARATSUBA_DIFFERENCE_DIGITS - 1;
const KARATSUBA_STORED_COEFFICIENTS: usize =
    KARATSUBA_LOW_COEFFICIENTS + KARATSUBA_HIGH_COEFFICIENTS + KARATSUBA_DIFFERENCE_COEFFICIENTS;
const KARATSUBA_PRODUCT_COEFFICIENTS: usize = 2 * FIELD_DIGIT_COUNT - 1;
const KARATSUBA_SAVED_LOW_COEFFICIENTS: usize = KARATSUBA_LOW_COEFFICIENTS - KARATSUBA_SPLIT;

fn karatsuba_operand_product_coefficient(
    table_above_inputs: bool,
    dead_items_below_table: u32,
    lhs_offset: usize,
    rhs_offset: usize,
    digit_count: usize,
    coefficient_index: usize,
) -> Script {
    let first = coefficient_index.saturating_sub(digit_count - 1);
    let last = coefficient_index.min(digit_count - 1);
    let (lhs_base_depth, rhs_base_depth, table_depth) = if table_above_inputs {
        (
            TABLE_ITEM_COUNT
                + 1
                + dead_items_below_table
                + RELATION_CARRY_COUNT as u32
                + (QUOTIENT_DIGIT_COUNT + FIELD_DIGIT_COUNT) as u32,
            TABLE_ITEM_COUNT
                + 2
                + dead_items_below_table
                + RELATION_CARRY_COUNT as u32
                + QUOTIENT_DIGIT_COUNT as u32,
            2,
        )
    } else {
        (
            1 + RELATION_CARRY_COUNT as u32 + (QUOTIENT_DIGIT_COUNT + FIELD_DIGIT_COUNT) as u32,
            2 + RELATION_CARRY_COUNT as u32 + QUOTIENT_DIGIT_COUNT as u32,
            (2 * FIELD_DIGIT_COUNT + QUOTIENT_DIGIT_COUNT + RELATION_CARRY_COUNT) as u32 + 2,
        )
    };
    script! {
        0
        for lhs_index in first..=last {
            { product_into_accumulator(
                lhs_base_depth + (lhs_offset + lhs_index) as u32,
                rhs_base_depth + (rhs_offset + coefficient_index - lhs_index) as u32,
                table_depth,
            ) }
        }
        OP_TOALTSTACK
    }
}

// Input is one signed raw coefficient on top. Output is its radix-512 carry
// on the main stack and its balanced digit on the altstack.
fn karatsuba_normalize_coefficient() -> Script {
    script! {
        OP_DUP { HALF_RADIX } OP_GREATERTHANOREQUAL
        OP_IF
            { RADIX } OP_SUB 1
        OP_ELSE
            OP_DUP { -HALF_RADIX } OP_LESSTHAN
            OP_IF
                { RADIX } OP_ADD -1
            OP_ELSE
                0
            OP_ENDIF
        OP_ENDIF
        OP_SWAP OP_TOALTSTACK
    }
}

// Normalize lhs_low-lhs_high to 15 balanced digits. Canonical field inputs
// make the 15-digit high block nonnegative and below 2^131, while the
// 14-digit low block has magnitude below 2^125, so the final carry is zero.
fn karatsuba_normalize_lhs_difference(
    table_above_inputs: bool,
    dead_items_below_table: u32,
) -> Script {
    let lhs_base_depth = if table_above_inputs {
        TABLE_ITEM_COUNT
            + 1
            + dead_items_below_table
            + RELATION_CARRY_COUNT as u32
            + (QUOTIENT_DIGIT_COUNT + FIELD_DIGIT_COUNT) as u32
    } else {
        1 + RELATION_CARRY_COUNT as u32 + (QUOTIENT_DIGIT_COUNT + FIELD_DIGIT_COUNT) as u32
    };
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
                // The only source digit here is canonical digit 28, hence
                // 0..=16. Together with carry -1..=1, this coefficient is
                // already balanced and the outgoing carry is zero.
                OP_TOALTSTACK
            } else {
                { karatsuba_normalize_coefficient() }
            }
        }
    }
}

// Normalize rhs_high-rhs_low to 15 balanced digits under the same bound.
fn karatsuba_normalize_rhs_difference(
    table_above_inputs: bool,
    dead_items_below_table: u32,
) -> Script {
    let rhs_base_depth = if table_above_inputs {
        TABLE_ITEM_COUNT
            + 1
            + dead_items_below_table
            + RELATION_CARRY_COUNT as u32
            + QUOTIENT_DIGIT_COUNT as u32
    } else {
        1 + RELATION_CARRY_COUNT as u32 + QUOTIENT_DIGIT_COUNT as u32
    };
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
                // As above, canonical digit 28 is 0..=16, so this final
                // coefficient needs neither balancing nor a carry check.
                OP_TOALTSTACK
            } else {
                { karatsuba_normalize_coefficient() }
            }
        }
    }
}

fn karatsuba_difference_product_coefficient(
    table_above_inputs: bool,
    coefficient_index: usize,
) -> Script {
    let first = coefficient_index.saturating_sub(KARATSUBA_DIFFERENCE_DIGITS - 1);
    let last = coefficient_index.min(KARATSUBA_DIFFERENCE_DIGITS - 1);
    let table_depth = if table_above_inputs {
        2 + 2 * KARATSUBA_DIFFERENCE_DIGITS as u32
    } else {
        (2 * FIELD_DIGIT_COUNT + QUOTIENT_DIGIT_COUNT + RELATION_CARRY_COUNT) as u32
            + 2
            + 2 * KARATSUBA_DIFFERENCE_DIGITS as u32
    };
    script! {
        0
        for lhs_index in first..=last {
            { product_into_accumulator(
                1 + lhs_index as u32,
                2 + KARATSUBA_DIFFERENCE_DIGITS as u32
                    + (coefficient_index - lhs_index) as u32,
                table_depth,
            ) }
        }
        OP_TOALTSTACK
    }
}

fn karatsuba_product_arrays(
    table_above_inputs: bool,
    dead_items_below_table: u32,
    keep_table_resident: bool,
) -> Script {
    assert!(
        table_above_inputs || (dead_items_below_table == 0 && keep_table_resident),
        "resident-table inputs cannot have dead items or consume their table"
    );
    assert!(
        dead_items_below_table == 0 || keep_table_resident,
        "a preloaded batch must keep its shared table resident"
    );
    script! {
        for coefficient_index in 0..KARATSUBA_LOW_COEFFICIENTS {
            { karatsuba_operand_product_coefficient(
                table_above_inputs,
                dead_items_below_table,
                0,
                0,
                KARATSUBA_SPLIT,
                coefficient_index,
            ) }
        }
        for coefficient_index in 0..KARATSUBA_HIGH_COEFFICIENTS {
            { karatsuba_operand_product_coefficient(
                table_above_inputs,
                dead_items_below_table,
                KARATSUBA_SPLIT,
                KARATSUBA_SPLIT,
                KARATSUBA_HIGH_DIGITS,
                coefficient_index,
            ) }
        }

        { karatsuba_normalize_lhs_difference(
            table_above_inputs,
            dead_items_below_table,
        ) }
        { karatsuba_normalize_rhs_difference(
            table_above_inputs,
            dead_items_below_table,
        ) }
        for _ in 0..2 * KARATSUBA_DIFFERENCE_DIGITS {
            OP_FROMALTSTACK
        }

        for coefficient_index in 0..KARATSUBA_DIFFERENCE_COEFFICIENTS {
            { karatsuba_difference_product_coefficient(
                table_above_inputs,
                coefficient_index,
            ) }
        }

        for _ in 0..KARATSUBA_DIFFERENCE_DIGITS {
            OP_2DROP
        }
        if table_above_inputs && !keep_table_resident {
            { table_drop() }
        }
        for _ in 0..KARATSUBA_STORED_COEFFICIENTS {
            OP_FROMALTSTACK
        }
    }
}

fn karatsuba_add_product_coefficient(coefficient_index: usize) -> Script {
    script! {
        if coefficient_index < KARATSUBA_LOW_COEFFICIENTS {
            { 1 + coefficient_index as u32 } OP_PICK OP_ADD
        }
        if (KARATSUBA_SPLIT
            ..KARATSUBA_SPLIT + KARATSUBA_DIFFERENCE_COEFFICIENTS)
            .contains(&coefficient_index)
        {
            if coefficient_index - KARATSUBA_SPLIT < KARATSUBA_LOW_COEFFICIENTS {
                { 1 + (coefficient_index - KARATSUBA_SPLIT) as u32 }
                OP_PICK OP_ADD
            }
            if coefficient_index - KARATSUBA_SPLIT < KARATSUBA_HIGH_COEFFICIENTS {
                { 1 + KARATSUBA_LOW_COEFFICIENTS as u32
                    + (coefficient_index - KARATSUBA_SPLIT) as u32 }
                OP_PICK OP_ADD
            }
            { 1 + (KARATSUBA_LOW_COEFFICIENTS + KARATSUBA_HIGH_COEFFICIENTS) as u32
                + (coefficient_index - KARATSUBA_SPLIT) as u32 }
            OP_PICK OP_ADD
        }
        if (2 * KARATSUBA_SPLIT
            ..2 * KARATSUBA_SPLIT + KARATSUBA_HIGH_COEFFICIENTS)
            .contains(&coefficient_index)
        {
            { 1 + KARATSUBA_LOW_COEFFICIENTS as u32
                + (coefficient_index - 2 * KARATSUBA_SPLIT) as u32 }
            OP_PICK OP_ADD
        }
    }
}

fn hinted_mul_relation(
    table_above_inputs: bool,
    dead_items_below_table: u32,
    keep_table_resident: bool,
) -> Script {
    let items_between_arrays_and_carries = if table_above_inputs && keep_table_resident {
        TABLE_ITEM_COUNT + dead_items_below_table
    } else {
        0
    };
    let carry_depth = 1 + KARATSUBA_STORED_COEFFICIENTS as u32 + items_between_arrays_and_carries;
    let mut body = Script::new("normalized-Karatsuba secp256k1 hinted multiplication");
    body = script! {
        { body }
        { karatsuba_product_arrays(
            table_above_inputs,
            dead_items_below_table,
            keep_table_resident,
        ) }
        0
    };
    for coefficient_index in 0..=2 * FIELD_DIGIT_COUNT - 2 {
        let remaining_carries = RELATION_CARRY_COUNT.saturating_sub(coefficient_index) as u32;
        let quotient_terms = quotient_terms_at(coefficient_index);
        body = script! {
            { body }
            { karatsuba_add_product_coefficient(coefficient_index) }
            { quotient_correction(
                &quotient_terms,
                carry_depth + remaining_carries,
            ) }
        };

        if coefficient_index < RELATION_CARRY_COUNT {
            body = script! {
                { body }
                { carry_depth } OP_ROLL
            };
            if coefficient_index < FIELD_DIGIT_COUNT {
                body = script! {
                    { body }
                    OP_TUCK { scriptint::mul_by_constant(RADIX as u32) }
                    OP_SUB
                    if coefficient_index + 1 < FIELD_DIGIT_COUNT {
                        OP_DUP { -HALF_RADIX } { HALF_RADIX } OP_WITHIN OP_VERIFY
                    }
                    OP_TOALTSTACK
                };
            } else {
                body = script! {
                    { body }
                    OP_TUCK { scriptint::mul_by_constant(RADIX as u32) }
                    OP_EQUALVERIFY
                };
            }
        } else {
            body = script! { { body } 0 OP_EQUALVERIFY };
        }
    }

    script! {
        { body }
        for _ in 0..KARATSUBA_STORED_COEFFICIENTS / 2 {
            OP_2DROP
        }
        if KARATSUBA_STORED_COEFFICIENTS % 2 != 0 {
            OP_DROP
        }
    }
}

// Compact three-gate schedule. It starts with one 57-slot direct coefficient
// array C, where C[0..26]=z0, C[27]=0, and C[28..56]=z2. Each middle target
// C[14+m] is removed as soon as z0[m]+z2[m]+zd[m] has been accumulated into
// it. Only z0[14..26] needs a 13-item saved copy.
fn compact_difference_product_accumulator(coefficient_index: usize) -> Script {
    let first = coefficient_index.saturating_sub(KARATSUBA_DIFFERENCE_DIGITS - 1);
    let last = coefficient_index.min(KARATSUBA_DIFFERENCE_DIGITS - 1);
    script! {
        0
        for lhs_index in first..=last {
            { product_into_accumulator(
                71 - coefficient_index as u32 + lhs_index as u32,
                87 - coefficient_index as u32
                    + (coefficient_index - lhs_index) as u32,
                102 - coefficient_index as u32,
            ) }
        }
    }
}

fn compact_middle_coefficient(coefficient_index: usize) -> Script {
    script! {
        { compact_difference_product_accumulator(coefficient_index) }
        if coefficient_index < KARATSUBA_LOW_COEFFICIENTS {
            if coefficient_index < KARATSUBA_SPLIT {
                { 14 + coefficient_index as u32 } OP_PICK OP_ADD
            } else {
                // Saved z0[14] is nearest the top; the accumulator adds one.
                { coefficient_index as u32 - 13 } OP_PICK OP_ADD
            }
        }
        if coefficient_index < KARATSUBA_HIGH_COEFFICIENTS {
            // Removing C[14+m] exactly cancels the increasing z2 index.
            42 OP_PICK OP_ADD
        }
        // Direct C[14+m] is always the fifteenth remaining direct slot.
        28 OP_ROLL OP_ADD OP_TOALTSTACK
    }
}

// Output mapping, nearest item first:
// final[14..42], final[0..13], final[43..56].
fn compact_karatsuba_product_block(dead_items_below_table: u32) -> Script {
    script! {
        for coefficient_index in 0..KARATSUBA_LOW_COEFFICIENTS {
            { karatsuba_operand_product_coefficient(
                true,
                dead_items_below_table,
                0,
                0,
                KARATSUBA_SPLIT,
                coefficient_index,
            ) }
        }
        0 OP_TOALTSTACK
        for coefficient_index in 0..KARATSUBA_HIGH_COEFFICIENTS {
            { karatsuba_operand_product_coefficient(
                true,
                dead_items_below_table,
                KARATSUBA_SPLIT,
                KARATSUBA_SPLIT,
                KARATSUBA_HIGH_DIGITS,
                coefficient_index,
            ) }
        }

        { karatsuba_normalize_lhs_difference(true, dead_items_below_table) }
        { karatsuba_normalize_rhs_difference(true, dead_items_below_table) }
        for _ in 0..2 * KARATSUBA_DIFFERENCE_DIGITS {
            OP_FROMALTSTACK
        }
        for _ in 0..KARATSUBA_PRODUCT_COEFFICIENTS {
            OP_FROMALTSTACK
        }

        // Repeated depth-26 copies save C[26], C[25], ..., C[14], leaving
        // saved C[14] nearest the top.
        for _ in 0..KARATSUBA_SAVED_LOW_COEFFICIENTS {
            26 OP_PICK
        }
        for coefficient_index in 0..KARATSUBA_DIFFERENCE_COEFFICIENTS {
            { compact_middle_coefficient(coefficient_index) }
        }

        for _ in 0..KARATSUBA_SAVED_LOW_COEFFICIENTS / 2 {
            OP_2DROP
        }
        if KARATSUBA_SAVED_LOW_COEFFICIENTS % 2 != 0 {
            OP_DROP
        }
        for _ in 0..KARATSUBA_PRODUCT_COEFFICIENTS - KARATSUBA_DIFFERENCE_COEFFICIENTS {
            OP_TOALTSTACK
        }
        for _ in 0..KARATSUBA_DIFFERENCE_DIGITS {
            OP_2DROP
        }
        for _ in 0..KARATSUBA_PRODUCT_COEFFICIENTS {
            OP_FROMALTSTACK
        }
    }
}

fn compact_add_product_coefficient(coefficient_index: usize) -> Script {
    let depth = if coefficient_index < KARATSUBA_SPLIT {
        30 + coefficient_index
    } else if coefficient_index < KARATSUBA_SPLIT + KARATSUBA_DIFFERENCE_COEFFICIENTS {
        coefficient_index - 13
    } else {
        coefficient_index + 1
    };
    script! { { depth as u32 } OP_PICK OP_ADD }
}

// Consume one preloaded gate's carries and append its result to the altstack,
// leaving the shared table and its consumed lhs/rhs/q block resident.
fn hinted_mul_compact_relation(dead_items_below_table: u32) -> Script {
    let carry_depth =
        1 + KARATSUBA_PRODUCT_COEFFICIENTS as u32 + TABLE_ITEM_COUNT + dead_items_below_table;
    let mut body = Script::new("compact-stack Karatsuba secp256k1 multiplication");
    body = script! {
        { body }
        { compact_karatsuba_product_block(dead_items_below_table) }
        0
    };
    for coefficient_index in 0..=2 * FIELD_DIGIT_COUNT - 2 {
        let remaining_carries = RELATION_CARRY_COUNT.saturating_sub(coefficient_index) as u32;
        let quotient_terms = quotient_terms_at(coefficient_index);
        body = script! {
            { body }
            { compact_add_product_coefficient(coefficient_index) }
            { quotient_correction(
                &quotient_terms,
                carry_depth + remaining_carries,
            ) }
        };

        if coefficient_index < RELATION_CARRY_COUNT {
            body = script! {
                { body }
                { carry_depth } OP_ROLL
            };
            if coefficient_index < FIELD_DIGIT_COUNT {
                body = script! {
                    { body }
                    OP_TUCK { scriptint::mul_by_constant(RADIX as u32) }
                    OP_SUB
                    if coefficient_index + 1 < FIELD_DIGIT_COUNT {
                        OP_DUP { -HALF_RADIX } { HALF_RADIX } OP_WITHIN OP_VERIFY
                    }
                    OP_TOALTSTACK
                };
            } else {
                body = script! {
                    { body }
                    OP_TUCK { scriptint::mul_by_constant(RADIX as u32) }
                    OP_EQUALVERIFY
                };
            }
        } else {
            body = script! { { body } 0 OP_EQUALVERIFY };
        }
    }

    script! {
        { body }
        for _ in 0..KARATSUBA_PRODUCT_COEFFICIENTS / 2 {
            OP_2DROP
        }
        if KARATSUBA_PRODUCT_COEFFICIENTS % 2 != 0 {
            OP_DROP
        }
    }
}

fn hinted_mul_gate(table_above_inputs: bool) -> Script {
    script! {
        { hinted_mul_relation(table_above_inputs, 0, !table_above_inputs) }
        // Drop quotient and both consumed operands.
        for _ in 0..(2 * FIELD_DIGIT_COUNT + QUOTIENT_DIGIT_COUNT) / 2 {
            OP_2DROP
        }
        if (2 * FIELD_DIGIT_COUNT + QUOTIENT_DIGIT_COUNT) % 2 != 0 {
            OP_DROP
        }
        // Restore r with its least-significant digit on top.
        for _ in 0..FIELD_DIGIT_COUNT {
            OP_FROMALTSTACK
        }
        { verify_field_range_keep_at_depth(0) }
    }
}

fn hinted_square_relation(
    table_above_inputs: bool,
    dead_items_below_table: u32,
    biased_table: bool,
) -> Script {
    assert!(
        table_above_inputs || dead_items_below_table == 0,
        "resident square inputs cannot have dead items below their table"
    );
    let mut body = Script::new("symmetric secp256k1 hinted square");
    body = script! { { body } 0 };
    for coefficient_index in 0..=2 * FIELD_DIGIT_COUNT - 2 {
        let remaining_carries = RELATION_CARRY_COUNT.saturating_sub(coefficient_index) as u32;
        let (digit_base_depth, table_depth, diagonal_table_depth) = if table_above_inputs {
            (
                TABLE_ITEM_COUNT
                    + 1
                    + dead_items_below_table
                    + remaining_carries
                    + QUOTIENT_DIGIT_COUNT as u32,
                2,
                1,
            )
        } else {
            (
                1 + remaining_carries + QUOTIENT_DIGIT_COUNT as u32,
                (FIELD_DIGIT_COUNT + QUOTIENT_DIGIT_COUNT) as u32 + remaining_carries + 2,
                (FIELD_DIGIT_COUNT + QUOTIENT_DIGIT_COUNT) as u32 + remaining_carries + 1,
            )
        };

        for first_index in 0..FIELD_DIGIT_COUNT {
            if coefficient_index < first_index
                || coefficient_index - first_index >= FIELD_DIGIT_COUNT
            {
                continue;
            }
            let second_index = coefficient_index - first_index;
            if first_index > second_index {
                continue;
            }
            body = if first_index == second_index {
                script! {
                    { body }
                    { square_diagonal_into_accumulator(
                        digit_base_depth + first_index as u32,
                        diagonal_table_depth,
                        biased_table,
                    ) }
                }
            } else {
                script! {
                    { body }
                    { square_off_diagonal_into_accumulator(
                        digit_base_depth + first_index as u32,
                        digit_base_depth + second_index as u32 + 1,
                        table_depth,
                    ) }
                }
            };
        }

        let quotient_terms = quotient_terms_at(coefficient_index);
        let quotient_base_depth = if table_above_inputs {
            TABLE_ITEM_COUNT + 1 + dead_items_below_table + remaining_carries
        } else {
            1 + remaining_carries
        };
        body = script! {
            { body }
            { quotient_correction(&quotient_terms, quotient_base_depth) }
        };

        if coefficient_index < RELATION_CARRY_COUNT {
            body = if table_above_inputs {
                script! {
                    { body }
                    { TABLE_ITEM_COUNT + 1 + dead_items_below_table } OP_ROLL
                }
            } else {
                script! { { body } OP_SWAP }
            };
            if coefficient_index < FIELD_DIGIT_COUNT {
                body = script! {
                    { body }
                    OP_TUCK { scriptint::mul_by_constant(RADIX as u32) }
                    OP_SUB
                    if coefficient_index + 1 < FIELD_DIGIT_COUNT {
                        OP_DUP { -HALF_RADIX } { HALF_RADIX } OP_WITHIN OP_VERIFY
                    }
                    OP_TOALTSTACK
                };
            } else {
                body = script! {
                    { body }
                    OP_TUCK { scriptint::mul_by_constant(RADIX as u32) }
                    OP_EQUALVERIFY
                };
            }
        } else {
            body = script! { { body } 0 OP_EQUALVERIFY };
        }
    }
    body
}

fn hinted_square_gate(table_above_inputs: bool) -> Script {
    script! {
        { hinted_square_relation(table_above_inputs, 0, true) }
        if table_above_inputs {
            { table_drop() }
        }
        for _ in 0..CONSUMED_SQUARE_RELATION_ITEMS / 2 {
            OP_2DROP
        }
        if CONSUMED_SQUARE_RELATION_ITEMS % 2 != 0 {
            OP_DROP
        }
        for _ in 0..FIELD_DIGIT_COUNT {
            OP_FROMALTSTACK
        }
        { verify_field_range_keep_at_depth(0) }
    }
}

/// Verify one modular multiplication with a private table.
///
/// Input layout (top at right):
/// `preserved | lhs[28..0] rhs[28..0] q[10..0] c[55..0]`.
/// Both operands must already be certified canonical values. The fragment
/// consumes operands and hints, pushes/drops its table, and returns one
/// certified result as `r[28] ... r[0]`.
pub fn mul_mod_hinted(preserved_items: u32) -> Script {
    assert_stack_peak(
        preserved_items,
        HINTED_MUL_STACK_ITEMS,
        "secp256k1 hinted multiplication",
    );
    script! {
        { table_setup_unchecked() }
        { hinted_mul_gate(true) }
    }
}

/// Certify both operands in the raw multiplication-witness layout.
///
/// Input/output is `lhs rhs q carries`; every item is preserved. This turns
/// the operand precondition of [`mul_mod_hinted`] into an explicit proof for a
/// standalone leaf.
pub fn certify_mul_operands() -> Script {
    script! {
        { certify_value_at_depth(HINT_ITEM_COUNT as u32) }
        { certify_value_at_depth((HINT_ITEM_COUNT + FIELD_DIGIT_COUNT) as u32) }
    }
}

/// Standalone sound multiplication from raw witness values.
///
/// This is [`certify_mul_operands`] followed by [`mul_mod_hinted`]. It is
/// larger than the composable gate because both input bindings are charged on
/// every call.
pub fn mul_mod_hinted_from_raw_witness(preserved_items: u32) -> Script {
    assert_stack_peak(
        preserved_items,
        HINTED_MUL_STACK_ITEMS,
        "standalone secp256k1 hinted multiplication",
    );
    script! {
        { certify_mul_operands() }
        { mul_mod_hinted(preserved_items) }
    }
}

/// Verify one specialized modular square with the common biased table.
///
/// Input is `preserved | value[28..0] q[10..0] c[55..0]`. The operand must
/// already be certified. The fragment consumes the operand and hints and
/// returns one certified result. Its table is byte-for-byte the same table
/// pushed by [`table_setup`] for multiplication.
pub fn square_mod_hinted(preserved_items: u32) -> Script {
    assert_stack_peak(
        preserved_items,
        HINTED_SQUARE_STACK_ITEMS,
        "secp256k1 hinted square",
    );
    script! {
        { table_setup_unchecked() }
        { hinted_square_gate(true) }
    }
}

/// Certify the operand in the raw square-witness layout, preserving all hints.
pub fn certify_square_operand() -> Script {
    certify_value_at_depth(HINT_ITEM_COUNT as u32)
}

/// Standalone sound square from a raw witness operand.
pub fn square_mod_hinted_from_raw_witness(preserved_items: u32) -> Script {
    assert_stack_peak(
        preserved_items,
        HINTED_SQUARE_STACK_ITEMS,
        "standalone secp256k1 hinted square",
    );
    script! {
        { certify_square_operand() }
        { square_mod_hinted(preserved_items) }
    }
}

/// Verify one square while leaving a common biased table resident.
///
/// Input is `preserved | biased_table | value q carries`; output is
/// `preserved | biased_table | result`. Construct the required table with
/// [`table_setup`]. The unbiased square-only batch table is not compatible.
pub fn square_mod_hinted_with_table(preserved_items: u32) -> Script {
    assert_stack_peak(
        preserved_items,
        HINTED_SQUARE_STACK_ITEMS,
        "resident-table secp256k1 hinted square",
    );
    hinted_square_gate(false)
}

fn assert_batch_size(multiplication_count: usize) {
    assert!(
        (1..=MAX_PRELOADED_BATCH_SIZE).contains(&multiplication_count),
        "preloaded secp256k1 batch size must be in 1..={MAX_PRELOADED_BATCH_SIZE}"
    );
}

/// Exact combined-stack peak for a preloaded batch with no unrelated state.
pub fn preloaded_batch_stack_items(multiplication_count: usize) -> u32 {
    assert_batch_size(multiplication_count);
    match multiplication_count {
        1 => HINTED_MUL_STACK_ITEMS,
        2 => {
            HINTED_MUL_STACK_ITEMS
                + u32::try_from(MUL_WITNESS_ITEM_COUNT)
                    .expect("supported batch stack count fits u32")
        }
        3 => COMPACT_MUL_BATCH_STACK_ITEMS,
        _ => unreachable!("batch size was checked"),
    }
}

/// Certify all operands in the preloaded batch layout.
///
/// Every item is preserved. Group zero is nearest the top and is processed
/// first by [`mul_mod_hinted_batch`].
pub fn certify_mul_batch_operands(multiplication_count: usize) -> Script {
    assert_batch_size(multiplication_count);
    script! {
        for gate_index in 0..multiplication_count {
            { certify_value_at_depth(
                (gate_index * MUL_WITNESS_ITEM_COUNT + HINT_ITEM_COUNT) as u32,
            ) }
            { certify_value_at_depth(
                (gate_index * MUL_WITNESS_ITEM_COUNT
                    + HINT_ITEM_COUNT
                    + FIELD_DIGIT_COUNT) as u32,
            ) }
        }
    }
}

fn consumed_batch_input_cleanup(multiplication_count: usize) -> Script {
    let item_count = multiplication_count * CONSUMED_RELATION_ITEMS;
    script! {
        for _ in 0..item_count / 2 {
            OP_2DROP
        }
        if item_count % 2 != 0 {
            OP_DROP
        }
    }
}

fn batch_output_restore_and_validation(multiplication_count: usize) -> Script {
    script! {
        for _ in 0..multiplication_count {
            for _ in 0..FIELD_DIGIT_COUNT {
                OP_FROMALTSTACK
            }
            { verify_field_range_keep_at_depth(0) }
        }
    }
}

/// Verify up to three preloaded multiplications while sharing one table.
///
/// Define `G_i = lhs_i[28..0] rhs_i[28..0] q_i[10..0] c_i[55..0]`, with
/// `c_i[0]` at the top of a group. Input and output layouts are:
///
/// - input: `preserved | G_(n-1) | ... | G_1 | G_0`
/// - output: `preserved | r_(n-1)[28..0] | ... | r_1[28..0] | r_0[28..0]`
///
/// Thus group zero is processed first and result zero's least-significant
/// digit is on top. Every operand must already have passed
/// [`certify_mul_batch_operands`] or an equivalent exact binding on the same
/// verified path. All witness groups are loaded before the table, matching an
/// actual Bitcoin witness rather than the synthetic resident-table layout.
pub fn mul_mod_hinted_batch(multiplication_count: usize, preserved_items: u32) -> Script {
    assert_batch_size(multiplication_count);
    assert_stack_peak(
        preserved_items,
        preloaded_batch_stack_items(multiplication_count),
        "preloaded-batch secp256k1 hinted multiplication",
    );
    match multiplication_count {
        // The ordinary private-table path is 69 bytes smaller than retaining
        // its table and deferring cleanup for a batch of one.
        1 => mul_mod_hinted(preserved_items),
        2 => script! {
            { table_setup_unchecked() }
            for gate_index in 0..multiplication_count {
                { hinted_mul_relation(
                    true,
                    (gate_index * CONSUMED_RELATION_ITEMS) as u32,
                    true,
                ) }
            }
            { table_drop() }
            { consumed_batch_input_cleanup(multiplication_count) }
            { batch_output_restore_and_validation(multiplication_count) }
        },
        3 => script! {
            { table_setup_unchecked() }
            for gate_index in 0..multiplication_count {
                { hinted_mul_compact_relation(
                    (gate_index * CONSUMED_RELATION_ITEMS) as u32,
                ) }
            }
            { table_drop() }
            { consumed_batch_input_cleanup(multiplication_count) }
            { batch_output_restore_and_validation(multiplication_count) }
        },
        _ => unreachable!("batch size was checked"),
    }
}

/// Standalone sound preloaded batch from raw witness operands.
pub fn mul_mod_hinted_batch_from_raw_witness(
    multiplication_count: usize,
    preserved_items: u32,
) -> Script {
    assert_batch_size(multiplication_count);
    script! {
        { certify_mul_batch_operands(multiplication_count) }
        { mul_mod_hinted_batch(multiplication_count, preserved_items) }
    }
}

fn assert_square_batch_size(square_count: usize) {
    assert!(
        (2..=MAX_PRELOADED_SQUARE_BATCH_SIZE).contains(&square_count),
        "preloaded secp256k1 square batch size must be in 2..={MAX_PRELOADED_SQUARE_BATCH_SIZE}"
    );
}

/// Exact combined-stack peak for a square-only preloaded batch.
pub fn preloaded_square_batch_stack_items(square_count: usize) -> u32 {
    assert_square_batch_size(square_count);
    HINTED_SQUARE_STACK_ITEMS
        + u32::try_from((square_count - 1) * SQUARE_WITNESS_ITEM_COUNT)
            .expect("supported square batch stack count fits u32")
}

/// Certify every operand in the preloaded square-batch layout.
pub fn certify_square_batch_operands(square_count: usize) -> Script {
    assert_square_batch_size(square_count);
    script! {
        for gate_index in 0..square_count {
            { certify_value_at_depth(
                (gate_index * SQUARE_WITNESS_ITEM_COUNT + HINT_ITEM_COUNT) as u32,
            ) }
        }
    }
}

fn consumed_square_batch_input_cleanup(square_count: usize) -> Script {
    let item_count = square_count * CONSUMED_SQUARE_RELATION_ITEMS;
    script! {
        for _ in 0..item_count / 2 {
            OP_2DROP
        }
        if item_count % 2 != 0 {
            OP_DROP
        }
    }
}

/// Verify two to five preloaded squares with one square-only unbiased table.
///
/// Let `S_i = value_i[28..0] q_i[10..0] c_i[55..0]`. Input and output are:
///
/// - input: `preserved | S_(n-1) | ... | S_1 | S_0`
/// - output: `preserved | r_(n-1) | ... | r_1 | r_0`
///
/// This API deliberately owns an unbiased table and cannot share the biased
/// multiplication table. For `n >= 2`, removing all diagonal bias corrections
/// outweighs the larger setup. Use [`square_mod_hinted_with_table`] when table
/// interoperability is more important than a square-only batch optimum.
pub fn square_mod_hinted_batch(square_count: usize, preserved_items: u32) -> Script {
    assert_square_batch_size(square_count);
    assert_stack_peak(
        preserved_items,
        preloaded_square_batch_stack_items(square_count),
        "preloaded-batch secp256k1 hinted square",
    );
    script! {
        { square_batch_table_setup_unchecked() }
        for gate_index in 0..square_count {
            { hinted_square_relation(
                true,
                (gate_index * CONSUMED_SQUARE_RELATION_ITEMS) as u32,
                false,
            ) }
        }
        { table_drop() }
        { consumed_square_batch_input_cleanup(square_count) }
        { batch_output_restore_and_validation(square_count) }
    }
}

/// Standalone sound square-only batch from raw witness operands.
pub fn square_mod_hinted_batch_from_raw_witness(
    square_count: usize,
    preserved_items: u32,
) -> Script {
    assert_square_batch_size(square_count);
    script! {
        { certify_square_batch_operands(square_count) }
        { square_mod_hinted_batch(square_count, preserved_items) }
    }
}

/// Verify one multiplication while leaving a shared table resident.
///
/// Input layout:
/// `preserved | table | lhs[28..0] rhs[28..0] q[10..0] c[55..0]`.
/// The table must be the exact script-owned biased table produced by
/// [`table_setup`] and sit directly below this gate's state; witness-supplied
/// entries are not trusted lookup memory. Output is
/// `preserved | table | r[28..0]`. The operands carry the same prior
/// certification requirement as [`mul_mod_hinted`].
pub fn mul_mod_hinted_with_table(preserved_items: u32) -> Script {
    assert_stack_peak(
        preserved_items,
        HINTED_MUL_STACK_ITEMS,
        "resident-table secp256k1 hinted multiplication",
    );
    hinted_mul_gate(false)
}

fn square_product_costs(table_above_inputs: bool, biased_table: bool) -> (usize, usize) {
    let mut diagonals = 0usize;
    let mut off_diagonals = 0usize;
    for coefficient_index in 0..=2 * FIELD_DIGIT_COUNT - 2 {
        let remaining_carries = RELATION_CARRY_COUNT.saturating_sub(coefficient_index) as u32;
        let (digit_base_depth, table_depth, diagonal_table_depth) = if table_above_inputs {
            (
                TABLE_ITEM_COUNT + 1 + remaining_carries + QUOTIENT_DIGIT_COUNT as u32,
                2,
                1,
            )
        } else {
            (
                1 + remaining_carries + QUOTIENT_DIGIT_COUNT as u32,
                (FIELD_DIGIT_COUNT + QUOTIENT_DIGIT_COUNT) as u32 + remaining_carries + 2,
                (FIELD_DIGIT_COUNT + QUOTIENT_DIGIT_COUNT) as u32 + remaining_carries + 1,
            )
        };
        for first_index in 0..FIELD_DIGIT_COUNT {
            if coefficient_index < first_index
                || coefficient_index - first_index >= FIELD_DIGIT_COUNT
            {
                continue;
            }
            let second_index = coefficient_index - first_index;
            if first_index > second_index {
                continue;
            }
            if first_index == second_index {
                diagonals += square_diagonal_into_accumulator(
                    digit_base_depth + first_index as u32,
                    diagonal_table_depth,
                    biased_table,
                )
                .compile_with_policy()
                .len();
            } else {
                off_diagonals += square_off_diagonal_into_accumulator(
                    digit_base_depth + first_index as u32,
                    digit_base_depth + second_index as u32 + 1,
                    table_depth,
                )
                .compile_with_policy()
                .len();
            }
        }
    }
    (diagonals, off_diagonals)
}

/// Exact byte attribution for [`square_mod_hinted`].
pub fn square_one_shot_cost_breakdown() -> SquareOneShotCostBreakdown {
    let table_setup = table_setup_unchecked().compile_with_policy().len();
    let table_drop = table_drop().compile_with_policy().len();
    let (diagonal_products, off_diagonal_products) = square_product_costs(true, true);
    let gate = hinted_square_gate(true).compile_with_policy().len();
    SquareOneShotCostBreakdown {
        table_setup,
        table_drop,
        diagonal_products,
        off_diagonal_products,
        relation_and_output: gate - table_drop - diagonal_products - off_diagonal_products,
    }
}

/// Exact bytes for certifying one raw square operand.
pub fn square_operand_certification_bytes() -> usize {
    certify_square_operand().compile_with_policy().len()
}

/// Exact bytes for [`square_mod_hinted_from_raw_witness`].
pub fn standalone_square_bytes() -> usize {
    square_mod_hinted_from_raw_witness(0)
        .compile_with_policy()
        .len()
}

/// Exact attribution for [`square_mod_hinted_with_table`].
pub fn square_resident_cost_breakdown() -> SquareResidentCostBreakdown {
    SquareResidentCostBreakdown {
        table_setup: table_setup_unchecked().compile_with_policy().len(),
        square_with_table: hinted_square_gate(false).compile_with_policy().len(),
        final_cleanup: final_table_cleanup_with_one_value()
            .compile_with_policy()
            .len(),
    }
}

/// Exact byte attribution for [`square_mod_hinted_batch`].
pub fn square_batch_cost_breakdown(square_count: usize) -> SquareBatchCostBreakdown {
    assert_square_batch_size(square_count);
    let relation_per_square = hinted_square_relation(true, 0, false)
        .compile_with_policy()
        .len();
    for gate_index in 1..square_count {
        let positioned = hinted_square_relation(
            true,
            (gate_index * CONSUMED_SQUARE_RELATION_ITEMS) as u32,
            false,
        )
        .compile_with_policy()
        .len();
        assert_eq!(
            positioned, relation_per_square,
            "supported square-batch positions must have identical relation size"
        );
    }
    SquareBatchCostBreakdown {
        square_count,
        unbiased_table_setup: square_batch_table_setup_unchecked()
            .compile_with_policy()
            .len(),
        relation_per_square,
        table_drop: table_drop().compile_with_policy().len(),
        consumed_input_cleanup: consumed_square_batch_input_cleanup(square_count)
            .compile_with_policy()
            .len(),
        output_restore_and_validation: batch_output_restore_and_validation(square_count)
            .compile_with_policy()
            .len(),
    }
}

/// Exact bytes for certifying every operand in a raw square-only batch.
pub fn square_batch_operand_certification_bytes(square_count: usize) -> usize {
    certify_square_batch_operands(square_count)
        .compile_with_policy()
        .len()
}

/// Exact bytes for [`square_mod_hinted_batch_from_raw_witness`].
pub fn standalone_square_batch_bytes(square_count: usize) -> usize {
    square_mod_hinted_batch_from_raw_witness(square_count, 0)
        .compile_with_policy()
        .len()
}

/// Exact byte attribution for [`mul_mod_hinted`].
pub fn one_shot_cost_breakdown() -> OneShotCostBreakdown {
    let table_setup = table_setup_unchecked().compile_with_policy().len();
    let table_drop = table_drop().compile_with_policy().len();
    let raw_digit_products = (0..KARATSUBA_LOW_COEFFICIENTS)
        .map(|coefficient_index| {
            karatsuba_operand_product_coefficient(true, 0, 0, 0, KARATSUBA_SPLIT, coefficient_index)
                .compile_with_policy()
                .len()
        })
        .sum::<usize>()
        + (0..KARATSUBA_HIGH_COEFFICIENTS)
            .map(|coefficient_index| {
                karatsuba_operand_product_coefficient(
                    true,
                    0,
                    KARATSUBA_SPLIT,
                    KARATSUBA_SPLIT,
                    KARATSUBA_HIGH_DIGITS,
                    coefficient_index,
                )
                .compile_with_policy()
                .len()
            })
            .sum::<usize>();
    let difference_digit_products = (0..KARATSUBA_DIFFERENCE_COEFFICIENTS)
        .map(|coefficient_index| {
            karatsuba_difference_product_coefficient(true, coefficient_index)
                .compile_with_policy()
                .len()
        })
        .sum::<usize>();
    let difference_normalization = karatsuba_normalize_lhs_difference(true, 0)
        .compile_with_policy()
        .len()
        + karatsuba_normalize_rhs_difference(true, 0)
            .compile_with_policy()
            .len();
    let coefficient_routing = 2 * KARATSUBA_DIFFERENCE_DIGITS
        + KARATSUBA_DIFFERENCE_DIGITS
        + KARATSUBA_STORED_COEFFICIENTS
        + KARATSUBA_STORED_COEFFICIENTS / 2
        + KARATSUBA_STORED_COEFFICIENTS % 2;
    let coefficient_recombination = (0..=2 * FIELD_DIGIT_COUNT - 2)
        .map(|coefficient_index| {
            karatsuba_add_product_coefficient(coefficient_index)
                .compile_with_policy()
                .len()
        })
        .sum::<usize>();
    let gate = hinted_mul_gate(true).compile_with_policy().len();
    let relation_and_output = gate
        - table_drop
        - raw_digit_products
        - difference_digit_products
        - difference_normalization
        - coefficient_routing
        - coefficient_recombination;
    OneShotCostBreakdown {
        table_setup,
        table_drop,
        raw_digit_products,
        difference_digit_products,
        difference_normalization,
        coefficient_routing,
        coefficient_recombination,
        relation_and_output,
    }
}

/// Exact bytes for binding both operands in the raw witness layout.
pub fn operand_certification_bytes() -> usize {
    certify_mul_operands().compile_with_policy().len()
}

/// Exact bytes for [`mul_mod_hinted_from_raw_witness`].
pub fn standalone_mul_bytes() -> usize {
    mul_mod_hinted_from_raw_witness(0)
        .compile_with_policy()
        .len()
}

/// Exact byte attribution for [`mul_mod_hinted_batch`].
pub fn batch_cost_breakdown(multiplication_count: usize) -> BatchCostBreakdown {
    assert_batch_size(multiplication_count);
    let table_setup = table_setup_unchecked().compile_with_policy().len();
    let table_drop = table_drop().compile_with_policy().len();
    let consumed_input_cleanup = consumed_batch_input_cleanup(multiplication_count)
        .compile_with_policy()
        .len();
    let output_restore_and_validation = batch_output_restore_and_validation(multiplication_count)
        .compile_with_policy()
        .len();
    let (strategy, relation_per_multiplication) = match multiplication_count {
        1 => (
            MulBatchStrategy::OneShot,
            mul_mod_hinted(0).compile_with_policy().len()
                - table_setup
                - table_drop
                - consumed_input_cleanup
                - output_restore_and_validation,
        ),
        2 => {
            let relation = hinted_mul_relation(true, 0, true)
                .compile_with_policy()
                .len();
            let positioned = hinted_mul_relation(true, CONSUMED_RELATION_ITEMS as u32, true)
                .compile_with_policy()
                .len();
            assert_eq!(positioned, relation, "batch positions must have equal size");
            (MulBatchStrategy::ResidentKaratsuba, relation)
        }
        3 => {
            let relation = hinted_mul_compact_relation(0).compile_with_policy().len();
            for gate_index in 1..multiplication_count {
                let positioned =
                    hinted_mul_compact_relation((gate_index * CONSUMED_RELATION_ITEMS) as u32)
                        .compile_with_policy()
                        .len();
                assert_eq!(positioned, relation, "batch positions must have equal size");
            }
            (MulBatchStrategy::CompactStackKaratsuba, relation)
        }
        _ => unreachable!("batch size was checked"),
    };
    let breakdown = BatchCostBreakdown {
        multiplication_count,
        strategy,
        table_setup,
        relation_per_multiplication,
        table_drop,
        consumed_input_cleanup,
        output_restore_and_validation,
    };
    debug_assert_eq!(
        breakdown.total(),
        mul_mod_hinted_batch(multiplication_count, 0)
            .compile_with_policy()
            .len()
    );
    breakdown
}

/// Exact bytes for binding every operand in a raw preloaded batch.
pub fn batch_operand_certification_bytes(multiplication_count: usize) -> usize {
    certify_mul_batch_operands(multiplication_count)
        .compile_with_policy()
        .len()
}

/// Exact bytes for [`mul_mod_hinted_batch_from_raw_witness`].
pub fn standalone_batch_bytes(multiplication_count: usize) -> usize {
    mul_mod_hinted_batch_from_raw_witness(multiplication_count, 0)
        .compile_with_policy()
        .len()
}

/// Exact byte attribution for the resident-table API.
pub fn resident_cost_breakdown() -> ResidentCostBreakdown {
    ResidentCostBreakdown {
        table_setup: table_setup_unchecked().compile_with_policy().len(),
        mul_with_table: hinted_mul_gate(false).compile_with_policy().len(),
        final_cleanup: final_table_cleanup_with_one_value()
            .compile_with_policy()
            .len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::{BigInt, RandBigInt, Sign};
    use num_traits::Zero;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::support::execution::execute_script;

    fn reconstruct(digits: &FieldDigits) -> BigInt {
        digits
            .iter()
            .rev()
            .fold(BigInt::zero(), |value, digit| value * RADIX + digit)
    }

    fn signed_balanced_digits(value: &BigInt) -> FieldDigits {
        let mut value = value.clone();
        std::array::from_fn(|index| {
            if index + 1 == FIELD_DIGIT_COUNT {
                return value.to_i32().expect("signed top digit fits i32");
            }
            let mut remainder = (&value % RADIX).to_i32().unwrap();
            if remainder < 0 {
                remainder += RADIX;
            }
            let digit = if remainder >= HALF_RADIX {
                remainder - RADIX
            } else {
                remainder
            };
            value = (value.clone() - digit) / RADIX;
            digit
        })
    }

    fn push_custom_witness(
        lhs: &FieldDigits,
        rhs: &FieldDigits,
        quotient: &QuotientDigits,
        carries: &RelationCarries,
    ) -> Script {
        script! {
            { push_balanced(lhs) }
            { push_balanced(rhs) }
            { push_balanced(quotient) }
            for carry in carries.iter().rev() {
                { *carry }
            }
        }
    }

    fn push_custom_square_witness(
        value: &FieldDigits,
        quotient: &QuotientDigits,
        carries: &RelationCarries,
    ) -> Script {
        script! {
            { push_balanced(value) }
            { push_balanced(quotient) }
            for carry in carries.iter().rev() {
                { *carry }
            }
        }
    }

    fn expected_check(value: &BigUint) -> Script {
        let digits = field_digits(value);
        script! {
            for digit in digits {
                { digit } OP_EQUALVERIFY
            }
            OP_TRUE
        }
    }

    #[test]
    fn exact_constant_chains_cover_quotient_endpoints() {
        for coefficient in [
            1u32, 2, 4, 8, 15, 16, 23, 31, 32, 47, 61, 64, 94, 122, 128, 136, 188, 240, 244, 256,
        ] {
            let endpoint = 1 << 22;
            for value in [-endpoint, -endpoint + 1, -1, 0, 1, endpoint - 1] {
                let result = execute_script(script! {
                    { value }
                    { exact_small_constant_mul(coefficient) }
                    { i64::from(value) * i64::from(coefficient) }
                    OP_EQUAL
                });
                assert!(result.success, "{coefficient} * {value}: {result}");
            }
        }
        // The only 26-bit chunks occur at remainder zero, whose largest
        // correction multiplier is 47 and whose selected chain peaks at 48x.
        for value in [-(1 << 25), -(1 << 25) + 1, (1 << 25) - 1] {
            let result = execute_script(script! {
                { value }
                { exact_small_constant_mul(47) }
                { i64::from(value) * 47 }
                OP_EQUAL
            });
            assert!(result.success, "47 * {value}: {result}");
        }
    }

    #[test]
    fn honest_intermediates_have_scriptnum_headroom() {
        let max_scriptnum = u64::from(scriptint::MAX_SCRIPTNUM);
        let convolution_bounds = |lhs: &[u64], rhs: &[u64]| {
            let mut bounds = vec![0u64; lhs.len() + rhs.len() - 1];
            for (lhs_index, lhs_bound) in lhs.iter().enumerate() {
                for (rhs_index, rhs_bound) in rhs.iter().enumerate() {
                    bounds[lhs_index + rhs_index] += lhs_bound * rhs_bound;
                }
            }
            bounds
        };
        let mut field_bounds = vec![HALF_RADIX as u64; FIELD_DIGIT_COUNT];
        field_bounds[FIELD_DIGIT_COUNT - 1] = 16;
        let z0_bounds = convolution_bounds(
            &field_bounds[..KARATSUBA_SPLIT],
            &field_bounds[..KARATSUBA_SPLIT],
        );
        let z2_bounds = convolution_bounds(
            &field_bounds[KARATSUBA_SPLIT..],
            &field_bounds[KARATSUBA_SPLIT..],
        );
        let mut difference_bounds = vec![HALF_RADIX as u64; KARATSUBA_DIFFERENCE_DIGITS];
        // The unmatched canonical top digit is 0..=16 and the incoming
        // balanced-normalization carry is -1..=1.
        difference_bounds[KARATSUBA_DIFFERENCE_DIGITS - 1] = 17;
        let difference_product_bounds = convolution_bounds(&difference_bounds, &difference_bounds);
        for (name, bounds) in [
            ("z0", &z0_bounds),
            ("z2", &z2_bounds),
            ("difference", &difference_product_bounds),
        ] {
            for (coefficient_index, bound) in bounds.iter().enumerate() {
                assert!(
                    *bound <= max_scriptnum,
                    "{name} coefficient {coefficient_index} can overflow"
                );
            }
        }
        // This is also a bound on every partial sum in the verifier's fixed
        // z0, z2, difference-product, z2 recombination order.
        let product_bounds: [u64; 2 * FIELD_DIGIT_COUNT - 1] =
            std::array::from_fn(|coefficient_index| {
                let mut bound = z0_bounds.get(coefficient_index).copied().unwrap_or(0);
                if coefficient_index >= KARATSUBA_SPLIT {
                    let cross_index = coefficient_index - KARATSUBA_SPLIT;
                    bound += z0_bounds.get(cross_index).copied().unwrap_or(0);
                    bound += z2_bounds.get(cross_index).copied().unwrap_or(0);
                    bound += difference_product_bounds
                        .get(cross_index)
                        .copied()
                        .unwrap_or(0);
                }
                if coefficient_index >= 2 * KARATSUBA_SPLIT {
                    bound += z2_bounds
                        .get(coefficient_index - 2 * KARATSUBA_SPLIT)
                        .copied()
                        .unwrap_or(0);
                }
                assert!(
                    bound <= max_scriptnum,
                    "recombined coefficient {coefficient_index} can overflow"
                );
                bound
            });
        let quotient_bound = |index: usize| {
            if index + 1 == QUOTIENT_DIGIT_COUNT {
                // The unsigned top starts at bit 234.
                1u64 << (256 - QUOTIENT_STARTS[index])
            } else {
                1u64 << (QUOTIENT_WIDTHS[index] - 1)
            }
        };
        let mut previous_carry_bound = 0u64;
        for coefficient_index in 0..=2 * FIELD_DIGIT_COUNT - 2 {
            let product_bound = product_bounds[coefficient_index];
            let correction_bound = quotient_terms_at(coefficient_index)
                .into_iter()
                .map(|(index, multiplier)| {
                    let digit_bound = quotient_bound(index);
                    u64::from(multiplier.unsigned_abs()) * digit_bound
                })
                .sum::<u64>();
            let accumulator_bound = previous_carry_bound + product_bound + correction_bound;
            assert!(
                accumulator_bound <= max_scriptnum,
                "coefficient {coefficient_index} accumulator can overflow"
            );
            let next_carry_bound =
                (accumulator_bound + HALF_RADIX as u64 + RADIX as u64 - 1) / RADIX as u64;
            assert!(
                next_carry_bound * RADIX as u64 <= max_scriptnum,
                "coefficient {coefficient_index} carry multiply can overflow"
            );
            previous_carry_bound = next_carry_bound;
        }
        // The specialized square deliberately uses the direct symmetric
        // schoolbook coefficients rather than the multiplication gate's
        // normalized-Karatsuba basis. Bound that independent accumulator and
        // its carry recurrence as well.
        let square_product_bounds = convolution_bounds(&field_bounds, &field_bounds);
        let mut previous_square_carry_bound = 0u64;
        for (coefficient_index, product_bound) in square_product_bounds.iter().enumerate() {
            assert!(
                *product_bound <= max_scriptnum,
                "square coefficient {coefficient_index} can overflow"
            );
            let correction_bound = quotient_terms_at(coefficient_index)
                .into_iter()
                .map(|(index, multiplier)| {
                    u64::from(multiplier.unsigned_abs()) * quotient_bound(index)
                })
                .sum::<u64>();
            let accumulator_bound = previous_square_carry_bound + product_bound + correction_bound;
            assert!(
                accumulator_bound <= max_scriptnum,
                "square coefficient {coefficient_index} accumulator can overflow"
            );
            let next_carry_bound =
                (accumulator_bound + HALF_RADIX as u64 + RADIX as u64 - 1) / RADIX as u64;
            assert!(
                next_carry_bound * RADIX as u64 <= max_scriptnum,
                "square coefficient {coefficient_index} carry multiply can overflow"
            );
            previous_square_carry_bound = next_carry_bound;
        }
        // Exercise every selected joint/separate correction at every signed
        // endpoint. Linear intermediate extrema occur at these corners.
        for coefficient_index in 0..=2 * FIELD_DIGIT_COUNT - 2 {
            let terms = quotient_terms_at(coefficient_index);
            assert!(terms.len() <= 2);
            let corner_count = 1usize << terms.len();
            for corner in 0..corner_count {
                let mut quotient = [0i32; QUOTIENT_DIGIT_COUNT];
                let mut expected = 0i64;
                for (term_index, (quotient_index, multiplier)) in terms.iter().enumerate() {
                    let bound = i32::try_from(quotient_bound(*quotient_index)).unwrap();
                    let value = if corner & (1 << term_index) == 0 {
                        -bound
                    } else {
                        bound - 1
                    };
                    quotient[*quotient_index] = value;
                    expected += i64::from(value) * i64::from(*multiplier);
                }
                let checked = execute_script(script! {
                    { push_balanced(&quotient) }
                    0
                    { quotient_correction(&terms, 1) }
                    { expected } OP_EQUALVERIFY
                    for _ in 0..QUOTIENT_DIGIT_COUNT {
                        OP_DROP
                    }
                    OP_TRUE
                });
                assert!(
                    checked.success,
                    "correction coefficient {coefficient_index}, corner {corner}: {checked}"
                );
            }
        }
    }

    #[test]
    fn multiplication_accepts_boundaries_and_seeded_random_values() {
        let p = modulus();
        let mut rng = ChaCha20Rng::seed_from_u64(0x5153_5541_5245);
        let mut cases = vec![
            (BigUint::zero(), BigUint::zero()),
            (BigUint::one(), &p - BigUint::one()),
            (&p - BigUint::one(), &p - BigUint::one()),
        ];
        for _ in 0..256 {
            cases.push((rng.gen_biguint_below(&p), rng.gen_biguint_below(&p)));
        }

        for (lhs, rhs) in cases {
            let hints = hinted_mul(&lhs, &rhs);
            assert_eq!(
                reconstruct(&field_digits(&lhs)),
                BigInt::from_biguint(Sign::Plus, lhs.clone())
            );
            assert_eq!(
                reconstruct(&field_digits(&rhs)),
                BigInt::from_biguint(Sign::Plus, rhs.clone())
            );

            let one_shot = execute_script(script! {
                { push_mul_witness(&lhs, &rhs, &hints) }
                { mul_mod_hinted_from_raw_witness(0) }
                { expected_check(&hints.remainder) }
            });
            assert!(one_shot.success, "lhs={lhs} rhs={rhs}: {one_shot}");
            assert!(
                one_shot.stats.max_nb_stack_items <= HINTED_MUL_STACK_ITEMS as usize,
                "unexpected one-shot stack peak: {one_shot}"
            );

            let resident = execute_script(script! {
                { table_setup(0) }
                { push_mul_witness(&lhs, &rhs, &hints) }
                { mul_mod_hinted_with_table(0) }
                { final_table_cleanup_with_one_value() }
                { expected_check(&hints.remainder) }
            });
            assert!(resident.success, "resident lhs={lhs} rhs={rhs}: {resident}");
            assert!(
                resident.stats.max_nb_stack_items <= HINTED_MUL_STACK_ITEMS as usize,
                "unexpected resident stack peak: {resident}"
            );

            for value in [&lhs, &rhs, &hints.remainder] {
                let certified = execute_script(script! {
                    { push_value(value) }
                    { certify_value() }
                    for _ in 0..FIELD_DIGIT_COUNT {
                        OP_DROP
                    }
                    OP_TRUE
                });
                assert!(
                    certified.success,
                    "certificate rejected {value}: {certified}"
                );
            }
        }
    }

    #[test]
    fn square_accepts_boundaries_and_seeded_random_values() {
        let p = modulus();
        let mut rng = ChaCha20Rng::seed_from_u64(0x5351_5541_5245);
        let mut cases = vec![BigUint::zero(), BigUint::one(), &p - BigUint::one()];
        for _ in 0..64 {
            cases.push(rng.gen_biguint_below(&p));
        }

        for value in cases {
            let hints = hinted_square(&value);
            let multiplication = hinted_mul(&value, &value);
            assert_eq!(hints.remainder, multiplication.remainder);

            let one_shot = execute_script(script! {
                { push_square_witness(&value, &hints) }
                { square_mod_hinted_from_raw_witness(0) }
                { expected_check(&hints.remainder) }
            });
            assert!(one_shot.success, "square value={value}: {one_shot}");
            assert!(
                one_shot.stats.max_nb_stack_items <= HINTED_SQUARE_STACK_ITEMS as usize,
                "unexpected square stack peak: {one_shot}"
            );

            let resident = execute_script(script! {
                { table_setup(0) }
                { push_square_witness(&value, &hints) }
                { square_mod_hinted_with_table(0) }
                { final_table_cleanup_with_one_value() }
                { expected_check(&hints.remainder) }
            });
            assert!(
                resident.success,
                "resident square value={value}: {resident}"
            );
            assert!(
                resident.stats.max_nb_stack_items <= HINTED_SQUARE_STACK_ITEMS as usize,
                "unexpected resident square stack peak: {resident}"
            );
        }
    }

    #[test]
    fn preloaded_batches_share_one_table_and_preserve_output_order() {
        let p = modulus();
        let inputs = [
            (&p - BigUint::one(), &p - BigUint::one()),
            (
                BigUint::from(0x1234_5678_9abcu64),
                BigUint::from(0xfedc_ba98_7654u64),
            ),
            (
                (BigUint::one() << 255usize) + BigUint::from(17u8),
                (BigUint::one() << 192usize) + BigUint::from(29u8),
            ),
        ];
        let cases = inputs
            .into_iter()
            .map(|(lhs, rhs)| {
                let hints = hinted_mul(&lhs, &rhs);
                (lhs, rhs, hints)
            })
            .collect::<Vec<_>>();
        let preserved = [111i32, 222, 333];
        let expected_totals = [20_503usize, 39_358, 59_145];
        let expected_relations = [18_331usize, 18_405, 18_740];
        let expected_strategies = [
            MulBatchStrategy::OneShot,
            MulBatchStrategy::ResidentKaratsuba,
            MulBatchStrategy::CompactStackKaratsuba,
        ];

        for multiplication_count in 1..=MAX_PRELOADED_BATCH_SIZE {
            let mut witness = Script::new("preloaded secp256k1 batch witness");
            for (lhs, rhs, hints) in cases[..multiplication_count].iter().rev() {
                witness = script! {
                    { witness }
                    { push_mul_witness(lhs, rhs, hints) }
                };
            }
            let mut result_checks = Script::new("preloaded secp256k1 batch outputs");
            // Result zero is on top, followed by results one and two.
            for (_, _, hints) in &cases[..multiplication_count] {
                let digits = field_digits(&hints.remainder);
                result_checks = script! {
                    { result_checks }
                    for digit in digits {
                        { digit } OP_EQUALVERIFY
                    }
                };
            }
            let result = execute_script(script! {
                for item in preserved {
                    { item }
                }
                { witness }
                { mul_mod_hinted_batch_from_raw_witness(
                    multiplication_count,
                    preserved.len() as u32,
                ) }
                for output_index in 0..multiplication_count {
                    { certify_value_at_depth((output_index * FIELD_DIGIT_COUNT) as u32) }
                }
                { result_checks }
                for item in preserved.into_iter().rev() {
                    { item } OP_EQUALVERIFY
                }
                OP_TRUE
            });
            assert!(
                result.success,
                "{multiplication_count}-multiplication batch: {result}"
            );
            assert_eq!(
                result.stats.max_nb_stack_items,
                preloaded_batch_stack_items(multiplication_count) as usize + preserved.len(),
                "unexpected strict batch peak"
            );

            let cost = batch_cost_breakdown(multiplication_count);
            assert_eq!(
                cost.total(),
                mul_mod_hinted_batch(multiplication_count, 0)
                    .compile_with_policy()
                    .len()
            );
            assert_eq!(cost.table_setup, 1_538);
            assert_eq!(cost.strategy, expected_strategies[multiplication_count - 1]);
            assert_eq!(
                cost.relation_per_multiplication,
                expected_relations[multiplication_count - 1]
            );
            assert_eq!(cost.table_drop, 257);
            assert_eq!(
                cost.output_restore_and_validation,
                342 * multiplication_count
            );
            assert_eq!(
                standalone_batch_bytes(multiplication_count),
                batch_operand_certification_bytes(multiplication_count) + cost.total()
            );
            assert_eq!(cost.total(), expected_totals[multiplication_count - 1]);
        }

        assert_eq!(batch_cost_breakdown(1).consumed_input_cleanup, 35);
        assert_eq!(batch_cost_breakdown(1).total(), 20_503);
        assert_eq!(batch_cost_breakdown(2).consumed_input_cleanup, 69);
        assert_eq!(batch_cost_breakdown(2).total(), 39_358);
        assert_eq!(batch_cost_breakdown(3).consumed_input_cleanup, 104);
        assert_eq!(batch_cost_breakdown(3).total(), 59_145);
    }

    #[test]
    fn compact_three_mul_batch_hits_exact_limit_and_preserves_both_stacks() {
        let p = modulus();
        let value = &p - BigUint::one();
        let hints = hinted_mul(&value, &value);
        let expected = field_digits(&hints.remainder);
        let result = execute_script(script! {
            111 222
            333 OP_TOALTSTACK
            444 OP_TOALTSTACK
            555 OP_TOALTSTACK
            666 OP_TOALTSTACK
            777 OP_TOALTSTACK
            for _ in 0..MAX_PRELOADED_BATCH_SIZE {
                { push_mul_witness(&value, &value, &hints) }
            }
            { mul_mod_hinted_batch_from_raw_witness(
                MAX_PRELOADED_BATCH_SIZE,
                7,
            ) }
            for _ in 0..MAX_PRELOADED_BATCH_SIZE {
                for digit in expected {
                    { digit } OP_EQUALVERIFY
                }
            }
            222 OP_EQUALVERIFY
            111 OP_EQUALVERIFY
            OP_FROMALTSTACK 777 OP_EQUALVERIFY
            OP_FROMALTSTACK 666 OP_EQUALVERIFY
            OP_FROMALTSTACK 555 OP_EQUALVERIFY
            OP_FROMALTSTACK 444 OP_EQUALVERIFY
            OP_FROMALTSTACK 333 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "exact-limit compact batch: {result}");
        assert_eq!(
            result.stats.max_nb_stack_items,
            U31_LOOKUP_STACK_LIMIT as usize
        );
        assert_eq!(preloaded_batch_stack_items(3), 993);
    }

    #[test]
    fn compact_three_mul_batch_rejects_a_malformed_middle_relation() {
        let p = modulus();
        let value = &p - BigUint::one();
        let honest = hinted_mul(&value, &value);
        let mut malformed = honest.clone();
        malformed.carries[RELATION_CARRY_COUNT / 2] += 1;
        let result = execute_script(script! {
            // Input is G2 | G1 | G0, so the malformed group is processed
            // through the nonzero dead-item depth of the second relation.
            { push_mul_witness(&value, &value, &honest) }
            { push_mul_witness(&value, &value, &malformed) }
            { push_mul_witness(&value, &value, &honest) }
            { mul_mod_hinted_batch_from_raw_witness(3, 0) }
            OP_TRUE
        });
        assert!(!result.success, "malformed compact relation was accepted");
    }

    #[test]
    fn preloaded_square_batches_use_unbiased_table_and_preserve_order() {
        let p = modulus();
        let values = [
            &p - BigUint::one(),
            BigUint::from(0x1234_5678_9abcu64),
            (BigUint::one() << 255usize) + BigUint::from(17u8),
            &p / BigUint::from(3u8),
            &p / BigUint::from(7u8),
        ];
        let cases = values
            .into_iter()
            .map(|value| {
                let hints = hinted_square(&value);
                (value, hints)
            })
            .collect::<Vec<_>>();
        let preserved = [111i32, 222];
        let expected_totals = [27_174usize, 39_804, 52_434, 65_064];
        let expected_peaks = [710usize, 806, 902, 998];

        for square_count in 2..=MAX_PRELOADED_SQUARE_BATCH_SIZE {
            let mut witness = Script::new("preloaded secp256k1 square witness");
            for (value, hints) in cases[..square_count].iter().rev() {
                witness = script! {
                    { witness }
                    { push_square_witness(value, hints) }
                };
            }
            let mut result_checks = Script::new("preloaded secp256k1 square outputs");
            for (_, hints) in &cases[..square_count] {
                let digits = field_digits(&hints.remainder);
                result_checks = script! {
                    { result_checks }
                    for digit in digits {
                        { digit } OP_EQUALVERIFY
                    }
                };
            }
            let result = execute_script(script! {
                for item in preserved {
                    { item }
                }
                { witness }
                { square_mod_hinted_batch_from_raw_witness(
                    square_count,
                    preserved.len() as u32,
                ) }
                for output_index in 0..square_count {
                    { certify_value_at_depth((output_index * FIELD_DIGIT_COUNT) as u32) }
                }
                { result_checks }
                for item in preserved.into_iter().rev() {
                    { item } OP_EQUALVERIFY
                }
                OP_TRUE
            });
            assert!(result.success, "{square_count}-square batch: {result}");
            assert_eq!(
                result.stats.max_nb_stack_items,
                expected_peaks[square_count - 2] + preserved.len(),
                "unexpected strict square-batch peak"
            );

            let cost = square_batch_cost_breakdown(square_count);
            assert_eq!(
                cost.total(),
                square_mod_hinted_batch(square_count, 0)
                    .compile_with_policy()
                    .len()
            );
            assert_eq!(cost.unbiased_table_setup, 1_657);
            assert_eq!(cost.relation_per_square, 12_268);
            assert_eq!(cost.table_drop, 257);
            assert_eq!(cost.consumed_input_cleanup, 20 * square_count);
            assert_eq!(cost.output_restore_and_validation, 342 * square_count);
            assert_eq!(cost.total(), expected_totals[square_count - 2]);
            // The standalone wrappers exceed the optimizer cutoff, while the
            // independently measured certification and gate fragments do not.
            // Their policy-produced sizes are therefore intentionally not
            // additive across this boundary.
            assert!(standalone_square_batch_bytes(square_count) > cost.total());
        }
    }

    #[test]
    fn exact_relation_rejects_malformed_hints_and_non_field_results() {
        let p = modulus();
        let lhs = &p - BigUint::one();
        let rhs = lhs.clone();
        let hints = hinted_mul(&lhs, &rhs);
        let lhs_digits = field_digits(&lhs);
        let rhs_digits = field_digits(&rhs);

        for carry_index in [0, RELATION_CARRY_COUNT / 2, RELATION_CARRY_COUNT - 1] {
            let mut wrong_carries = hints.carries;
            wrong_carries[carry_index] += 1;
            let wrong_carry = execute_script(script! {
                { table_setup(0) }
                { push_custom_witness(&lhs_digits, &rhs_digits, &hints.quotient, &wrong_carries) }
                { mul_mod_hinted_with_table(0) }
                OP_TRUE
            });
            assert!(
                !wrong_carry.success,
                "wrong carry {carry_index} was accepted"
            );
        }

        for quotient_index in [0, QUOTIENT_DIGIT_COUNT / 2, QUOTIENT_DIGIT_COUNT - 1] {
            let mut wrong_quotient = hints.quotient;
            wrong_quotient[quotient_index] += 1;
            let wrong_quotient_result = execute_script(script! {
                { table_setup(0) }
                { push_custom_witness(&lhs_digits, &rhs_digits, &wrong_quotient, &hints.carries) }
                { mul_mod_hinted_with_table(0) }
                OP_TRUE
            });
            assert!(
                !wrong_quotient_result.success,
                "wrong quotient digit {quotient_index} was accepted"
            );
        }

        let product = &lhs * &rhs;
        let quotient_value = &product / &p;
        let remainder = &product % &p;
        for (bad_quotient, bad_remainder) in [
            (
                &quotient_value + BigUint::one(),
                BigInt::from_biguint(Sign::Plus, remainder.clone())
                    - BigInt::from_biguint(Sign::Plus, p.clone()),
            ),
            (
                &quotient_value - BigUint::one(),
                BigInt::from_biguint(Sign::Plus, remainder.clone())
                    + BigInt::from_biguint(Sign::Plus, p.clone()),
            ),
        ] {
            let quotient = quotient_digits(&bad_quotient);
            let remainder_digits = signed_balanced_digits(&bad_remainder);
            let carries = relation_carries(&lhs_digits, &rhs_digits, &quotient, &remainder_digits);
            let rejected = execute_script(script! {
                { table_setup(0) }
                { push_custom_witness(&lhs_digits, &rhs_digits, &quotient, &carries) }
                { mul_mod_hinted_with_table(0) }
                OP_TRUE
            });
            assert!(!rejected.success, "non-field remainder was accepted");
        }
    }

    #[test]
    fn square_relation_rejects_malformed_hints_and_non_field_results() {
        let p = modulus();
        let value = &p - BigUint::one();
        let hints = hinted_square(&value);
        let value_digits = field_digits(&value);

        for carry_index in [0, RELATION_CARRY_COUNT / 2, RELATION_CARRY_COUNT - 1] {
            let mut wrong_carries = hints.carries;
            wrong_carries[carry_index] += 1;
            let rejected = execute_script(script! {
                { table_setup(0) }
                { push_custom_square_witness(&value_digits, &hints.quotient, &wrong_carries) }
                { square_mod_hinted_with_table(0) }
                OP_TRUE
            });
            assert!(
                !rejected.success,
                "wrong square carry {carry_index} was accepted"
            );
        }

        for quotient_index in [0, QUOTIENT_DIGIT_COUNT / 2, QUOTIENT_DIGIT_COUNT - 1] {
            let mut wrong_quotient = hints.quotient;
            wrong_quotient[quotient_index] += 1;
            let rejected = execute_script(script! {
                { table_setup(0) }
                { push_custom_square_witness(
                    &value_digits,
                    &wrong_quotient,
                    &hints.carries,
                ) }
                { square_mod_hinted_with_table(0) }
                OP_TRUE
            });
            assert!(
                !rejected.success,
                "wrong square quotient digit {quotient_index} was accepted"
            );
        }

        // Multiplication and square carries attest different coefficient
        // bases and must not be interchangeable when Karatsuba difference
        // normalization changes the formal coefficient polynomial.
        let mut basis_digits = [0i32; FIELD_DIGIT_COUNT];
        basis_digits[..KARATSUBA_SPLIT].fill(-255);
        basis_digits[KARATSUBA_SPLIT..FIELD_DIGIT_COUNT - 1].fill(255);
        let basis_value = BigUint::try_from(reconstruct(&basis_digits))
            .expect("crafted basis-separating field value is positive");
        assert!(basis_value < p);
        let basis_square_hints = hinted_square(&basis_value);
        let multiplication_hints = hinted_mul(&basis_value, &basis_value);
        let basis_value_digits = field_digits(&basis_value);
        assert_ne!(basis_square_hints.carries, multiplication_hints.carries);
        let wrong_basis = execute_script(script! {
            { table_setup(0) }
            { push_custom_square_witness(
                &basis_value_digits,
                &basis_square_hints.quotient,
                &multiplication_hints.carries,
            ) }
            { square_mod_hinted_with_table(0) }
            OP_TRUE
        });
        assert!(
            !wrong_basis.success,
            "Karatsuba-basis carries were accepted"
        );

        let square = &value * &value;
        let quotient_value = &square / &p;
        let remainder = &square % &p;
        for (bad_quotient, bad_remainder) in [
            (
                &quotient_value + BigUint::one(),
                BigInt::from_biguint(Sign::Plus, remainder.clone())
                    - BigInt::from_biguint(Sign::Plus, p.clone()),
            ),
            (
                &quotient_value - BigUint::one(),
                BigInt::from_biguint(Sign::Plus, remainder.clone())
                    + BigInt::from_biguint(Sign::Plus, p.clone()),
            ),
        ] {
            let quotient = quotient_digits(&bad_quotient);
            let remainder_digits = signed_balanced_digits(&bad_remainder);
            let carries = square_relation_carries(&value_digits, &quotient, &remainder_digits);
            let rejected = execute_script(script! {
                { table_setup(0) }
                { push_custom_square_witness(&value_digits, &quotient, &carries) }
                { square_mod_hinted_with_table(0) }
                OP_TRUE
            });
            assert!(!rejected.success, "non-field square remainder was accepted");
        }
    }

    #[test]
    fn quotient_digits_need_not_be_canonical() {
        let p = modulus();
        let lhs = &p - BigUint::one();
        let rhs = lhs.clone();
        let hints = hinted_mul(&lhs, &rhs);
        let lhs_digits = field_digits(&lhs);
        let rhs_digits = field_digits(&rhs);
        let remainder_digits = field_digits(&hints.remainder);
        let mut quotient = hints.quotient;
        // Rewrite one safe interior chunk by carrying to its neighbor. The
        // exact integer q is unchanged even though these digits are outside
        // the host generator's balanced convention.
        quotient[6] += 1 << QUOTIENT_WIDTHS[6];
        quotient[7] -= 1;
        let carries = relation_carries(&lhs_digits, &rhs_digits, &quotient, &remainder_digits);
        let accepted = execute_script(script! {
            { table_setup(0) }
            { push_custom_witness(&lhs_digits, &rhs_digits, &quotient, &carries) }
            { mul_mod_hinted_with_table(0) }
            { final_table_cleanup_with_one_value() }
            { expected_check(&hints.remainder) }
        });
        assert!(accepted.success, "equivalent quotient encoding: {accepted}");
    }

    #[test]
    fn square_quotient_digits_need_not_be_canonical() {
        let p = modulus();
        let value = &p - BigUint::one();
        let hints = hinted_square(&value);
        let value_digits = field_digits(&value);
        let remainder_digits = field_digits(&hints.remainder);
        let mut quotient = hints.quotient;
        quotient[6] += 1 << QUOTIENT_WIDTHS[6];
        quotient[7] -= 1;
        let carries = square_relation_carries(&value_digits, &quotient, &remainder_digits);
        let accepted = execute_script(script! {
            { table_setup(0) }
            { push_custom_square_witness(&value_digits, &quotient, &carries) }
            { square_mod_hinted_with_table(0) }
            { final_table_cleanup_with_one_value() }
            { expected_check(&hints.remainder) }
        });
        assert!(
            accepted.success,
            "equivalent square quotient encoding: {accepted}"
        );
    }

    #[test]
    fn field_certificate_rejects_boundaries_and_bad_digits() {
        for invalid in [
            balanced_digits_unchecked(&modulus()),
            signed_balanced_digits(&BigInt::from(-1)),
            {
                let mut digits = balanced_digits_unchecked(&BigUint::zero());
                digits[0] = HALF_RADIX;
                digits
            },
        ] {
            let rejected = execute_script(script! {
                { push_balanced(&invalid) }
                { certify_value() }
                OP_TRUE
            });
            assert!(!rejected.success, "invalid field value was accepted");
        }
    }

    #[test]
    fn cost_attribution_is_exact() {
        let one_shot = one_shot_cost_breakdown();
        assert_eq!(
            one_shot.table_setup,
            table_setup_unchecked().compile_with_policy().len()
        );
        assert_eq!(
            one_shot.table_drop,
            table_drop().compile_with_policy().len()
        );
        assert_eq!(
            [
                one_shot.table_setup,
                one_shot.table_drop,
                one_shot.raw_digit_products,
                one_shot.difference_digit_products,
                one_shot.difference_normalization,
                one_shot.coefficient_routing,
                one_shot.coefficient_recombination,
                one_shot.relation_and_output,
            ],
            [1_538, 257, 9_374, 4_993, 1_103, 173, 530, 2_535]
        );
        assert_eq!(
            one_shot.total(),
            mul_mod_hinted(0).compile_with_policy().len()
        );
        assert_eq!(
            standalone_mul_bytes(),
            operand_certification_bytes() + one_shot.total()
        );

        let resident = resident_cost_breakdown();
        assert_eq!(
            resident.mul_with_table,
            mul_mod_hinted_with_table(0).compile_with_policy().len()
        );
        assert_eq!(
            resident.final_cleanup,
            final_table_cleanup_with_one_value()
                .compile_with_policy()
                .len()
        );

        let square = square_one_shot_cost_breakdown();
        assert_eq!(
            [
                square.table_setup,
                square.table_drop,
                square.diagonal_products,
                square.off_diagonal_products,
                square.relation_and_output,
            ],
            [1_538, 257, 406, 9_744, 2_596]
        );
        assert_eq!(
            square.total(),
            square_mod_hinted(0).compile_with_policy().len()
        );
        assert_eq!(square.total(), 14_541);
        assert_eq!(square.table_overhead(), 1_795);
        assert_eq!(square.computation(), 12_746);
        assert_eq!(
            standalone_square_bytes(),
            square_operand_certification_bytes() + square.total()
        );

        let square_resident = square_resident_cost_breakdown();
        assert_eq!(square_resident.table_setup, 1_538);
        assert_eq!(
            square_resident.square_with_table,
            square_mod_hinted_with_table(0).compile_with_policy().len()
        );
        assert_eq!(
            square_resident.final_cleanup,
            final_table_cleanup_with_one_value()
                .compile_with_policy()
                .len()
        );
    }

    #[test]
    fn exact_stack_limit_preserves_main_and_alt_state() {
        const PRESERVED_MAIN: usize = 117;
        const PRESERVED_ALT: usize =
            U31_LOOKUP_STACK_LIMIT as usize - HINTED_MUL_STACK_ITEMS as usize - PRESERVED_MAIN;
        let p = modulus();
        let lhs = &p - BigUint::one();
        let rhs = lhs.clone();
        let hints = hinted_mul(&lhs, &rhs);
        let result = execute_script(script! {
            for value in 1..=PRESERVED_MAIN {
                { value as i32 }
            }
            for value in 1..=PRESERVED_ALT {
                { 1_000 + value as i32 } OP_TOALTSTACK
            }
            { push_mul_witness(&lhs, &rhs, &hints) }
            { mul_mod_hinted((PRESERVED_MAIN + PRESERVED_ALT) as u32) }
            { expected_check(&hints.remainder) }
            OP_VERIFY
            for value in (1..=PRESERVED_MAIN).rev() {
                { value as i32 } OP_EQUALVERIFY
            }
            for value in (1..=PRESERVED_ALT).rev() {
                OP_FROMALTSTACK { 1_000 + value as i32 } OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(result.success, "exact-limit multiplication: {result}");
        assert_eq!(
            result.stats.max_nb_stack_items, U31_LOOKUP_STACK_LIMIT as usize,
            "the declared Karatsuba peak must be exact"
        );
    }

    #[test]
    fn square_exact_stack_limit_preserves_main_and_alt_state() {
        const PRESERVED_MAIN: usize = 117;
        const PRESERVED_ALT: usize =
            U31_LOOKUP_STACK_LIMIT as usize - HINTED_SQUARE_STACK_ITEMS as usize - PRESERVED_MAIN;
        let p = modulus();
        let value = &p - BigUint::one();
        let hints = hinted_square(&value);
        let result = execute_script(script! {
            for item in 1..=PRESERVED_MAIN {
                { item as i32 }
            }
            for item in 1..=PRESERVED_ALT {
                { 2_000 + item as i32 } OP_TOALTSTACK
            }
            { push_square_witness(&value, &hints) }
            { square_mod_hinted((PRESERVED_MAIN + PRESERVED_ALT) as u32) }
            { expected_check(&hints.remainder) }
            OP_VERIFY
            for item in (1..=PRESERVED_MAIN).rev() {
                { item as i32 } OP_EQUALVERIFY
            }
            for item in (1..=PRESERVED_ALT).rev() {
                OP_FROMALTSTACK { 2_000 + item as i32 } OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(result.success, "exact-limit square: {result}");
        assert_eq!(
            result.stats.max_nb_stack_items, U31_LOOKUP_STACK_LIMIT as usize,
            "the declared square peak must be exact"
        );
    }

    #[test]
    #[should_panic(expected = "exceeds Bitcoin Script's stack limit")]
    fn multiplication_rejects_excess_preserved_state() {
        let _ = mul_mod_hinted(U31_LOOKUP_STACK_LIMIT - HINTED_MUL_STACK_ITEMS + 1);
    }

    #[test]
    #[should_panic(expected = "exceeds Bitcoin Script's stack limit")]
    fn square_rejects_excess_preserved_state() {
        let _ = square_mod_hinted(U31_LOOKUP_STACK_LIMIT - HINTED_SQUARE_STACK_ITEMS + 1);
    }

    #[test]
    #[should_panic(expected = "preloaded secp256k1 batch size must be in 1..=3")]
    fn preloaded_batch_rejects_four_multiplications() {
        let _ = mul_mod_hinted_batch(MAX_PRELOADED_BATCH_SIZE + 1, 0);
    }

    #[test]
    #[should_panic(expected = "exceeds Bitcoin Script's stack limit")]
    fn preloaded_batch_rejects_excess_preserved_state() {
        let peak = preloaded_batch_stack_items(MAX_PRELOADED_BATCH_SIZE);
        let _ = mul_mod_hinted_batch(MAX_PRELOADED_BATCH_SIZE, U31_LOOKUP_STACK_LIMIT - peak + 1);
    }

    #[test]
    #[should_panic(expected = "preloaded secp256k1 square batch size must be in 2..=5")]
    fn preloaded_square_batch_rejects_one_square() {
        let _ = square_mod_hinted_batch(1, 0);
    }

    #[test]
    #[should_panic(expected = "preloaded secp256k1 square batch size must be in 2..=5")]
    fn preloaded_square_batch_rejects_six_squares() {
        let _ = square_mod_hinted_batch(MAX_PRELOADED_SQUARE_BATCH_SIZE + 1, 0);
    }

    #[test]
    #[should_panic(expected = "exceeds Bitcoin Script's stack limit")]
    fn preloaded_square_batch_rejects_excess_preserved_state() {
        let peak = preloaded_square_batch_stack_items(MAX_PRELOADED_SQUARE_BATCH_SIZE);
        let _ = square_mod_hinted_batch(
            MAX_PRELOADED_SQUARE_BATCH_SIZE,
            U31_LOOKUP_STACK_LIMIT - peak + 1,
        );
    }

    #[test]
    #[should_panic(expected = "field certification exceeds Bitcoin Script's stack limit")]
    fn certification_rejects_excess_depth() {
        let _ = certify_value_at_depth(U31_LOOKUP_STACK_LIMIT);
    }
}
