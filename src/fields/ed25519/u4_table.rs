//! Radix-16 Ed25519 field multiplication with operand-specific lookup tables.
//!
//! A field value is 64 unsigned nibbles. The left operand is grouped into
//! sixteen 16-bit limbs. For each limb, Script constructs the exact table
//! `{d*a_i | d in 0..15}` from the certified operand. The right operand's
//! already-certified nibbles select those tables directly, so each of the
//! 1,024 schoolbook products needs one lookup rather than two quarter-square
//! lookups. A factor-8 representation turns `8*16^63 = p+19` into a direct
//! pseudo-Mersenne fold.

use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, ToPrimitive, Zero};

use crate::{
    arithmetic::{scriptint, u31::U31_LOOKUP_STACK_LIMIT},
    support::script::*,
};

pub const FIELD_DIGIT_COUNT: usize = 64;
pub const LIMB_COUNT: usize = 16;
pub const DIGITS_PER_LIMB: usize = 4;
pub const TABLE_SIZE: usize = 16;
pub const TABLE_ITEM_COUNT: usize = LIMB_COUNT * TABLE_SIZE;
pub const PRODUCT_COEFFICIENT_COUNT: usize = 124;
pub const RELATION_CARRY_COUNT: usize = 63;
pub const HINT_ITEM_COUNT: usize = 1 + RELATION_CARRY_COUNT;
pub const MUL_WITNESS_ITEM_COUNT: usize = 2 * FIELD_DIGIT_COUNT + HINT_ITEM_COUNT;

// Exact peak measured by strict generated-script execution.
pub const HINTED_MUL_STACK_ITEMS: u32 = 389;
pub const MAX_PRESERVED_ITEMS: u32 = U31_LOOKUP_STACK_LIMIT - HINTED_MUL_STACK_ITEMS;

const RADIX: i32 = 16;
const LOW_BYTE_BOUND: i32 = 0xed;

pub type FieldDigits = [i32; FIELD_DIGIT_COUNT];
pub type RelationCarries = [i32; RELATION_CARRY_COUNT];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MulHints {
    pub remainder: BigUint,
    pub residual: i32,
    pub carries: RelationCarries,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MulCostBreakdown {
    pub table_setup: usize,
    pub folded_relation: usize,
    pub cleanup: usize,
}

impl MulCostBreakdown {
    pub const fn total(self) -> usize {
        self.table_setup + self.folded_relation + self.cleanup
    }
}

impl MulHints {
    pub fn push_script(&self) -> Script {
        script! {
            { self.residual }
            for carry in self.carries.iter().rev() {
                { *carry }
            }
        }
    }

    pub fn witness_items(&self) -> Vec<Vec<u8>> {
        std::iter::once(&self.residual)
            .chain(self.carries.iter().rev())
            .map(|value| scriptnum_item(*value))
            .collect()
    }
}

pub fn modulus() -> BigUint {
    (BigUint::one() << 255usize) - BigUint::from(19u32)
}

fn field_digits_unchecked(value: &BigUint) -> FieldDigits {
    let mut value = value.clone();
    std::array::from_fn(|_| {
        let digit = (&value & BigUint::from(15u32))
            .to_i32()
            .expect("nibble fits i32");
        value >>= 4usize;
        digit
    })
}

pub fn field_digits(value: &BigUint) -> FieldDigits {
    assert!(value < &modulus(), "Ed25519 field value must be canonical");
    field_digits_unchecked(value)
}

#[cfg(test)]
fn reconstruct_digits(digits: &FieldDigits) -> BigInt {
    digits
        .iter()
        .rev()
        .fold(BigInt::zero(), |value, digit| value * RADIX + digit)
}

pub fn encode(value: &BigUint) -> BigUint {
    let p = modulus();
    assert!(value < &p, "Ed25519 field value must be canonical");
    let inverse_8 = (&p * BigUint::from(3u32) + BigUint::one()) >> 3usize;
    value * inverse_8 % p
}

pub fn decode(value: &BigUint) -> BigUint {
    let p = modulus();
    assert!(value < &p, "encoded Ed25519 value must be canonical");
    value * BigUint::from(8u32) % p
}

fn limbs(digits: &FieldDigits) -> [i32; LIMB_COUNT] {
    std::array::from_fn(|limb_index| {
        (0..DIGITS_PER_LIMB).rev().fold(0i32, |value, digit_index| {
            value * RADIX + digits[DIGITS_PER_LIMB * limb_index + digit_index]
        })
    })
}

fn product_coefficients(lhs: &FieldDigits, rhs: &FieldDigits) -> [i64; PRODUCT_COEFFICIENT_COUNT] {
    let lhs = limbs(lhs);
    let mut product = [0i64; PRODUCT_COEFFICIENT_COUNT];
    for (limb_index, limb) in lhs.into_iter().enumerate() {
        for (rhs_index, rhs_digit) in rhs.iter().copied().enumerate() {
            product[DIGITS_PER_LIMB * limb_index + rhs_index] +=
                i64::from(limb) * i64::from(rhs_digit);
        }
    }
    product
}

fn folded_coefficients(product: &[i64; PRODUCT_COEFFICIENT_COUNT]) -> [i64; FIELD_DIGIT_COUNT] {
    std::array::from_fn(|index| {
        let low = if index < 63 { 8 * product[index] } else { 0 };
        let high = product.get(index + 63).copied().unwrap_or(0);
        low + 19 * high
    })
}

fn reconstruct_coefficients(coefficients: &[i64]) -> BigInt {
    coefficients
        .iter()
        .rev()
        .fold(BigInt::zero(), |value, coefficient| {
            value * RADIX + coefficient
        })
}

pub fn hinted_mul(lhs: &BigUint, rhs: &BigUint) -> MulHints {
    let p = modulus();
    assert!(lhs < &p, "left encoded operand must be canonical");
    assert!(rhs < &p, "right encoded operand must be canonical");
    let remainder = lhs * rhs * BigUint::from(8u32) % &p;
    let lhs_digits = field_digits(lhs);
    let rhs_digits = field_digits(rhs);
    let remainder_digits = field_digits(&remainder);
    let product = product_coefficients(&lhs_digits, &rhs_digits);
    let folded = folded_coefficients(&product);
    let folded_integer = reconstruct_coefficients(&folded);
    let remainder_integer = BigInt::from_biguint(Sign::Plus, remainder.clone());
    let p_integer = BigInt::from_biguint(Sign::Plus, p);
    let delta = folded_integer - remainder_integer;
    assert_eq!(&delta % &p_integer, BigInt::zero());
    let residual_integer = delta / &p_integer;
    let residual = residual_integer
        .to_i32()
        .unwrap_or_else(|| panic!("radix-16 residual exceeds ScriptNum: {residual_integer}"));

    let mut previous = 0i64;
    let mut carries = [0i32; RELATION_CARRY_COUNT];
    for coefficient_index in 0..FIELD_DIGIT_COUNT {
        let mut coefficient = previous + folded[coefficient_index];
        if coefficient_index == 0 {
            coefficient += 19 * i64::from(residual);
        }
        if coefficient_index + 1 == FIELD_DIGIT_COUNT {
            coefficient -= 8 * i64::from(residual);
        }
        coefficient -= i64::from(remainder_digits[coefficient_index]);
        if coefficient_index < RELATION_CARRY_COUNT {
            assert_eq!(coefficient % i64::from(RADIX), 0);
            previous = coefficient / i64::from(RADIX);
            carries[coefficient_index] =
                i32::try_from(previous).expect("radix-16 carry fits ScriptNum");
        } else {
            assert_eq!(coefficient, 0, "final radix-16 relation coefficient");
        }
    }

    MulHints {
        remainder,
        residual,
        carries,
    }
}

fn push_digits(digits: &[i32]) -> Script {
    script! {
        for digit in digits.iter().rev() {
            { *digit }
        }
    }
}

pub fn push_value(value: &BigUint) -> Script {
    push_digits(&field_digits(value))
}

pub fn push_mul_witness(lhs: &BigUint, rhs: &BigUint, hints: &MulHints) -> Script {
    script! {
        { push_value(lhs) }
        { push_value(rhs) }
        { hints.push_script() }
    }
}

fn scriptnum_item(value: i32) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value));
    bytes[..length].to_vec()
}

fn verify_field_range_keep_at_depth(value_depth: u32) -> Script {
    script! {
        // The top digit has already been checked in [0,8). Only values with
        // top digit seven can reach the 19-value noncanonical gap above p.
        { value_depth + 63 } OP_PICK 7 OP_NUMEQUAL
        OP_IF
            { value_depth + 2 } OP_PICK
            for index in 3..=62 {
                { value_depth + index + 1 } OP_PICK OP_MIN
            }
            15 OP_NUMEQUAL
            OP_IF
                { value_depth + 1 } OP_PICK
                { scriptint::mul_by_constant(16) }
                { value_depth + 1 } OP_PICK OP_ADD
                { LOW_BYTE_BOUND } OP_LESSTHAN OP_VERIFY
            OP_ENDIF
        OP_ENDIF
    }
}

pub fn certify_value() -> Script {
    certify_value_at_depth(0)
}

pub fn certify_value_at_depth(items_above: u32) -> Script {
    assert!(
        u64::from(items_above) + FIELD_DIGIT_COUNT as u64 + 3 <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "radix-16 Ed25519 certification exceeds the stack limit"
    );
    script! {
        for index in 0..63 {
            { items_above + index } OP_PICK 0 16 OP_WITHIN OP_VERIFY
        }
        { items_above + 63 } OP_PICK 0 8 OP_WITHIN OP_VERIFY
        { verify_field_range_keep_at_depth(items_above) }
    }
}

fn park_rhs_and_hints() -> Script {
    script! {
        for _ in 0..RELATION_CARRY_COUNT { OP_TOALTSTACK }
        OP_TOALTSTACK
        for _ in 0..FIELD_DIGIT_COUNT { OP_TOALTSTACK }
    }
}

fn restore_rhs_and_hints() -> Script {
    script! {
        for _ in 0..FIELD_DIGIT_COUNT { OP_FROMALTSTACK }
        OP_FROMALTSTACK
        for _ in 0..RELATION_CARRY_COUNT { OP_FROMALTSTACK }
    }
}

fn build_lhs_limb(table_items: usize) -> Script {
    script! {
        { (table_items + DIGITS_PER_LIMB - 1) as u32 } OP_ROLL
        for digit_index in (0..DIGITS_PER_LIMB - 1).rev() {
            { scriptint::mul_by_constant(16) }
            { (table_items + digit_index + 1) as u32 } OP_ROLL
            OP_ADD
        }
    }
}

// Input: `... a`; output: `... 15a 14a ... 0` with zero nearest the top.
fn build_descending_multiple_table() -> Script {
    script! {
        OP_DUP { scriptint::mul_by_constant(15) } OP_SWAP
        for _ in 0..15 {
            OP_2DUP OP_SUB OP_SWAP
        }
        OP_DROP
    }
}

fn table_setup() -> Script {
    script! {
        { park_rhs_and_hints() }
        for limb_index in 0..LIMB_COUNT {
            { build_lhs_limb(limb_index * TABLE_SIZE) }
            { build_descending_multiple_table() }
        }
        { restore_rhs_and_hints() }
    }
}

fn product_pairs(product_index: usize) -> Vec<(usize, usize)> {
    (0..LIMB_COUNT)
        .filter_map(|limb_index| {
            product_index
                .checked_sub(DIGITS_PER_LIMB * limb_index)
                .filter(|rhs_index| *rhs_index < FIELD_DIGIT_COUNT)
                .map(|rhs_index| (limb_index, rhs_index))
        })
        .collect()
}

struct ProductLayout {
    remaining_rhs_uses: [u8; FIELD_DIGIT_COUNT],
    active_rhs: [bool; FIELD_DIGIT_COUNT],
}

impl ProductLayout {
    fn new() -> Self {
        Self {
            remaining_rhs_uses: [LIMB_COUNT as u8; FIELD_DIGIT_COUNT],
            active_rhs: [true; FIELD_DIGIT_COUNT],
        }
    }

    fn active_count(&self) -> usize {
        self.active_rhs.iter().filter(|active| **active).count()
    }

    fn active_above(&self, rhs_index: usize) -> usize {
        self.active_rhs[..rhs_index]
            .iter()
            .filter(|active| **active)
            .count()
    }

    fn take_use(&mut self, rhs_index: usize) -> bool {
        let uses = &mut self.remaining_rhs_uses[rhs_index];
        assert!(*uses > 0, "right digit used too many times");
        *uses -= 1;
        let last = *uses == 0;
        if last {
            assert!(self.active_rhs[rhs_index]);
            self.active_rhs[rhs_index] = false;
        }
        last
    }

    fn is_last_use(&self, rhs_index: usize) -> bool {
        self.remaining_rhs_uses[rhs_index] == 1
    }
}

fn add_table_product(
    limb_index: usize,
    rhs_index: usize,
    remaining_carries: usize,
    work_items_below: usize,
    has_accumulator: bool,
    layout: &mut ProductLayout,
) -> Script {
    let active_rhs = layout.active_count();
    let accumulator_items = usize::from(has_accumulator);
    let rhs_depth = remaining_carries
        + 1
        + accumulator_items
        + work_items_below
        + layout.active_above(rhs_index);
    let last_use = layout.take_use(rhs_index);
    // OP_PICK consumes the computed index before applying it, so this is the
    // zero entry's depth after that index has left the stack.
    let table_base = remaining_carries
        + active_rhs
        + usize::from(!last_use)
        + accumulator_items
        + work_items_below
        + (LIMB_COUNT - 1 - limb_index) * TABLE_SIZE;
    let select_rhs = if last_use {
        script! { { rhs_depth as u32 } OP_ROLL }
    } else {
        script! { { rhs_depth as u32 } OP_PICK }
    };
    let combine = if has_accumulator {
        script! { OP_ADD }
    } else {
        Script::new("seed product accumulator")
    };
    script! {
        { select_rhs }
        { table_base as u32 } OP_ADD OP_PICK
        { combine }
    }
}

fn product_sum(
    product_index: usize,
    remaining_carries: usize,
    work_items_below: usize,
    layout: &mut ProductLayout,
) -> Script {
    let mut pairs = product_pairs(product_index);
    pairs.sort_by_key(|(_, rhs_index)| (!layout.is_last_use(*rhs_index), *rhs_index));
    let terms = pairs
        .into_iter()
        .enumerate()
        .map(|(term_index, (limb_index, rhs_index))| {
            add_table_product(
                limb_index,
                rhs_index,
                remaining_carries,
                work_items_below,
                term_index != 0,
                layout,
            )
        })
        .collect::<Vec<_>>();
    script! {
        for term in terms {
            { term }
        }
    }
}

// Input: `... low high`; output: `... 8*low + 19*high`.
fn combine_8_low_19_high() -> Script {
    script! {
        OP_DUP OP_DUP OP_ADD OP_ROT OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_OVER OP_ADD
        OP_DUP OP_ADD
        OP_ADD
    }
}

fn coefficient_step(coefficient_index: usize, layout: &mut ProductLayout) -> Script {
    let remaining_carries = RELATION_CARRY_COUNT.saturating_sub(coefficient_index);
    let has_previous_carry = coefficient_index != 0;
    let has_high = coefficient_index + 63 < PRODUCT_COEFFICIENT_COUNT;
    let low = if coefficient_index < 63 {
        let low_sum = product_sum(
            coefficient_index,
            remaining_carries,
            usize::from(has_previous_carry),
            layout,
        );
        if has_high {
            low_sum
        } else {
            script! {
                { low_sum }
                { scriptint::mul_by_constant(8) }
                OP_ADD
            }
        }
    } else {
        Script::new("empty low coefficient")
    };
    let high = if has_high {
        let high_sum = product_sum(
            coefficient_index + 63,
            remaining_carries,
            1 + usize::from(has_previous_carry),
            layout,
        );
        let merge_residual = if coefficient_index == 0 {
            script! {
                { (remaining_carries + 2) as u32 } OP_PICK
                OP_ADD
            }
        } else {
            Script::new("no low-column residual")
        };
        script! {
            { high_sum }
            { merge_residual }
            { combine_8_low_19_high() }
            if has_previous_carry { OP_ADD }
        }
    } else {
        Script::new("empty high coefficient")
    };
    let residual = if coefficient_index + 1 == FIELD_DIGIT_COUNT {
        script! { OP_SWAP { scriptint::mul_by_constant(8) } OP_SUB }
    } else {
        Script::new("empty residual coefficient")
    };
    let carry = if coefficient_index < RELATION_CARRY_COUNT {
        script! {
            OP_OVER { scriptint::mul_by_constant(16) } OP_SUB
            OP_DUP 0 16 OP_WITHIN OP_VERIFY
            OP_TOALTSTACK
        }
    } else {
        script! {
            OP_DUP 0 8 OP_WITHIN OP_VERIFY
            OP_TOALTSTACK
        }
    };
    script! { { low } { high } { residual } { carry } }
}

fn coefficient_relation() -> Script {
    let mut layout = ProductLayout::new();
    let steps = (0..FIELD_DIGIT_COUNT)
        .map(|coefficient_index| coefficient_step(coefficient_index, &mut layout))
        .collect::<Vec<_>>();
    assert!(layout.active_rhs.iter().all(|active| !active));
    script! {
        for step in steps {
            { step }
        }
    }
}

fn restore_result_and_verify_canonical() -> Script {
    script! {
        // Results arrive high-to-low from altstack. Preserve that output order
        // while threading min(d62..d2) through the restoration pass.
        OP_FROMALTSTACK
        OP_FROMALTSTACK OP_DUP
        for _ in 0..60 {
            OP_FROMALTSTACK
            OP_SWAP OP_OVER OP_MIN
        }
        OP_FROMALTSTACK OP_SWAP
        OP_FROMALTSTACK OP_SWAP
        15 OP_NUMEQUAL
        OP_IF
            63 OP_PICK 7 OP_NUMEQUAL
            OP_IF
                OP_OVER { scriptint::mul_by_constant(16) }
                OP_OVER OP_ADD
                { LOW_BYTE_BOUND } OP_LESSTHAN OP_VERIFY
            OP_ENDIF
        OP_ENDIF
    }
}

fn cleanup() -> Script {
    const CONSUMED_MAIN_ITEMS: usize = TABLE_ITEM_COUNT;
    script! {
        for _ in 0..CONSUMED_MAIN_ITEMS / 2 { OP_2DROP }
        if CONSUMED_MAIN_ITEMS % 2 != 0 { OP_DROP }
        { restore_result_and_verify_canonical() }
    }
}

pub fn mul_mod_hinted(preserved_items: u32) -> Script {
    assert!(
        u64::from(preserved_items) + u64::from(HINTED_MUL_STACK_ITEMS)
            <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "radix-16 Ed25519 multiplication exceeds the stack limit"
    );
    script! {
        { table_setup() }
        { coefficient_relation() }
        { cleanup() }
    }
}

pub fn certify_mul_operands() -> Script {
    script! {
        { certify_value_at_depth(HINT_ITEM_COUNT as u32) }
        { certify_value_at_depth((HINT_ITEM_COUNT + FIELD_DIGIT_COUNT) as u32) }
    }
}

pub fn mul_mod_hinted_from_raw_witness(preserved_items: u32) -> Script {
    script! {
        { certify_mul_operands() }
        { mul_mod_hinted(preserved_items) }
    }
}

pub fn one_shot_cost_breakdown() -> MulCostBreakdown {
    let mut cost = MulCostBreakdown {
        table_setup: table_setup().compile_with_policy().len(),
        folded_relation: coefficient_relation().compile_with_policy().len(),
        cleanup: cleanup().compile_with_policy().len(),
    };
    let independently_compiled = cost.total();
    let whole = mul_mod_hinted(0).compile_with_policy().len();
    attribute_compilation_delta(&mut cost.folded_relation, independently_compiled, whole);
    debug_assert_eq!(cost.total(), whole);
    cost
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::RandBigInt;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::support::execution::execute_raw_script_with_inputs_strict;

    fn witness_items(lhs: &BigUint, rhs: &BigUint, hints: &MulHints) -> Vec<Vec<u8>> {
        field_digits(lhs)
            .iter()
            .rev()
            .chain(field_digits(rhs).iter().rev())
            .map(|digit| scriptnum_item(*digit))
            .chain(hints.witness_items())
            .collect()
    }

    #[test]
    fn factor8_encoding_and_host_relation_are_exact() {
        let p = modulus();
        let mut rng = ChaCha20Rng::seed_from_u64(0x7534_4544_3235_3531);
        for _ in 0..128 {
            let logical_lhs = rng.gen_biguint_below(&p);
            let logical_rhs = rng.gen_biguint_below(&p);
            let lhs = encode(&logical_lhs);
            let rhs = encode(&logical_rhs);
            let hints = hinted_mul(&lhs, &rhs);
            assert_eq!(decode(&hints.remainder), logical_lhs * logical_rhs % &p);
            assert_eq!(
                reconstruct_digits(&field_digits(&hints.remainder)),
                BigInt::from(hints.remainder)
            );
        }
    }

    #[test]
    #[ignore = "expensive generated-script diagnostic; run explicitly with --ignored"]
    fn table_lookups_match_host_product_coefficients() {
        let p = modulus();
        let logical = &p - BigUint::one();
        let lhs = encode(&logical);
        let rhs = lhs.clone();
        let hints = hinted_mul(&lhs, &rhs);
        let product = product_coefficients(&field_digits(&lhs), &field_digits(&rhs));
        let witness = witness_items(&lhs, &rhs, &hints);

        for product_index in [0usize, 1, 62, 63, 64, 122, 123] {
            let mut layout = ProductLayout::new();
            let sum = product_sum(product_index, RELATION_CARRY_COUNT, 0, &mut layout);
            let script = script! {
                { table_setup() }
                { sum }
                { product[product_index] }
                OP_EQUAL
            }
            .compile_with_policy();
            let execution =
                execute_raw_script_with_inputs_strict(script.to_bytes(), witness.clone());
            assert!(
                execution.error.is_none(),
                "coefficient {product_index}: {execution}"
            );
        }

        let mut layout = ProductLayout::new();
        let sum = product_sum(63, RELATION_CARRY_COUNT, 1, &mut layout);
        let script = script! {
            { table_setup() }
            0
            { sum }
            { product[63] }
            OP_EQUAL
        }
        .compile_with_policy();
        let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), witness);
        assert!(execution.error.is_none(), "offset coefficient: {execution}");
    }

    #[test]
    #[ignore = "expensive generated-script diagnostic; run explicitly with --ignored"]
    fn first_folded_coefficient_matches_host_relation() {
        let p = modulus();
        let logical = &p - BigUint::one();
        let lhs = encode(&logical);
        let rhs = lhs.clone();
        let hints = hinted_mul(&lhs, &rhs);
        let product = product_coefficients(&field_digits(&lhs), &field_digits(&rhs));
        let expected_accumulator =
            8 * product[0] + 19 * product[63] + 19 * i64::from(hints.residual);
        let expected_digit = field_digits(&hints.remainder)[0];
        let expected_carry = hints.carries[0];
        let witness = witness_items(&lhs, &rhs, &hints);
        let mut layout = ProductLayout::new();
        let low = product_sum(0, RELATION_CARRY_COUNT, 0, &mut layout);
        let high = product_sum(63, RELATION_CARRY_COUNT, 1, &mut layout);
        let script = script! {
            { table_setup() }
            { low }
            { scriptint::mul_by_constant(8) }
            { high }
            { scriptint::mul_by_constant(19) }
            OP_ADD
            { (RELATION_CARRY_COUNT + 1) as u32 } OP_PICK
            { scriptint::mul_by_constant(19) }
            OP_ADD
            OP_DUP { expected_accumulator } OP_EQUALVERIFY
            OP_SWAP
            OP_TUCK { scriptint::mul_by_constant(16) } OP_SUB
            { expected_digit } OP_EQUALVERIFY
            { expected_carry } OP_EQUAL
        }
        .compile_with_policy();
        let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), witness);
        assert!(execution.error.is_none(), "first coefficient: {execution}");
    }

    #[test]
    #[ignore = "expensive generated-script diagnostic; run explicitly with --ignored"]
    fn generated_first_coefficient_step_matches_host_relation() {
        let p = modulus();
        let logical = &p - BigUint::one();
        let lhs = encode(&logical);
        let rhs = lhs.clone();
        let hints = hinted_mul(&lhs, &rhs);
        let expected_digit = field_digits(&hints.remainder)[0];
        let expected_carry = hints.carries[0];
        let witness = witness_items(&lhs, &rhs, &hints);
        let mut layout = ProductLayout::new();
        let step0 = coefficient_step(0, &mut layout);
        let script = script! {
            { table_setup() }
            { step0 }
            OP_FROMALTSTACK { expected_digit } OP_EQUALVERIFY
            { expected_carry } OP_EQUAL
        }
        .compile_with_policy();
        let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), witness);
        assert!(
            execution.error.is_none(),
            "generated first coefficient: {execution}"
        );

        let witness = witness_items(&lhs, &rhs, &hints);
        let mut layout = ProductLayout::new();
        let step0 = coefficient_step(0, &mut layout);
        let script = script! {
            { table_setup() }
            { step0 }
            OP_1
        }
        .compile_with_policy();
        let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), witness);
        assert!(
            execution.error.is_none(),
            "standalone first coefficient: {execution}"
        );

        let witness = witness_items(&lhs, &rhs, &hints);
        let mut layout = ProductLayout::new();
        let step0 = coefficient_step(0, &mut layout);
        let step1 = coefficient_step(1, &mut layout);
        let script = script! {
            { table_setup() }
            { step0 }
            { step1 }
            OP_1
        }
        .compile_with_policy();
        let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), witness);
        assert!(
            execution.error.is_none(),
            "first two coefficients: {execution}"
        );
    }

    #[test]
    #[ignore = "expensive generated-script execution; run explicitly with --ignored"]
    fn strict_boundary_and_seeded_execution() {
        let p = modulus();
        let cases = [
            (BigUint::zero(), BigUint::zero()),
            (encode(&BigUint::one()), encode(&(&p - BigUint::one()))),
            (
                encode(&(&p - BigUint::one())),
                encode(&(&p - BigUint::one())),
            ),
        ];
        let script = mul_mod_hinted_from_raw_witness(0)
            .compile_with_policy()
            .to_bytes();
        for (lhs, rhs) in cases {
            let hints = hinted_mul(&lhs, &rhs);
            let execution = execute_raw_script_with_inputs_strict(
                script.clone(),
                witness_items(&lhs, &rhs, &hints),
            );
            assert!(execution.error.is_none(), "strict execution: {execution}");
            assert!(execution.stats.max_nb_stack_items <= HINTED_MUL_STACK_ITEMS as usize);
        }
    }
}
