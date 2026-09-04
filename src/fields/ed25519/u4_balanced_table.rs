//! Radix-16 Ed25519 field multiplication with balanced 20-bit left limbs.
//!
//! Both field elements are certified as 64 unsigned radix-16 digits. The left
//! operand is then regrouped, in Script, into twelve balanced radix-2^20 limbs
//! and one nonnegative 15-bit top limb. For each limb Script constructs the
//! exact table `{d*a_i | d in 0..15}`. The right operand's certified nibbles
//! select those tables, reducing the schoolbook kernel to 13 * 64 = 832 table
//! lookups.
//!
//! The field representation is scaled by 1/8. Consequently a product is
//! represented by `8*a*b`, and `8*16^63 = p+19` gives the direct folded
//! relation used below. Balancing makes the folded coefficients signed, so the
//! quotient is supplied as one signed ScriptNum. Its proven absolute bound is
//! 6,324,521. Column zero folds it into the high product sum before the shared
//! `8*low + 19*high` chain; column 63 consumes it in the `-8*q` term.

use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed, ToPrimitive, Zero};

use crate::{
    arithmetic::{scriptint, u31::U31_LOOKUP_STACK_LIMIT},
    support::script::*,
};

pub const FIELD_DIGIT_COUNT: usize = 64;
pub const LIMB_COUNT: usize = 13;
pub const DIGITS_PER_LIMB: usize = 5;
pub const TABLE_SIZE: usize = 16;
pub const TABLE_ITEM_COUNT: usize = LIMB_COUNT * TABLE_SIZE;
pub const PRODUCT_TERM_COUNT: usize = LIMB_COUNT * FIELD_DIGIT_COUNT;
pub const PRODUCT_COEFFICIENT_COUNT: usize = 124;
pub const RELATION_CARRY_COUNT: usize = FIELD_DIGIT_COUNT - 1;
pub const HINT_ITEM_COUNT: usize = 1 + RELATION_CARRY_COUNT;
pub const MUL_WITNESS_ITEM_COUNT: usize = 2 * FIELD_DIGIT_COUNT + HINT_ITEM_COUNT;

// Exact data-independent peak measured by strict generated-Script execution.
// Table construction and the relation's control-flow stack effects do not
// depend on operand values; the optional canonicality branch runs far below
// this peak.
pub const HINTED_MUL_STACK_ITEMS: u32 = 341;
pub const MAX_PRESERVED_ITEMS: u32 = U31_LOOKUP_STACK_LIMIT - HINTED_MUL_STACK_ITEMS;

pub const MAX_ABS_TABLE_ENTRY: i64 = 7_864_320;
pub const MAX_ABS_PRODUCT_COEFFICIENT: i64 = 94_863_360;
pub const MAX_ABS_FOLDED_COEFFICIENT: i64 = 1_865_318_400;
pub const MAX_ABS_QUOTIENT: i64 = 6_324_521;
pub const MAX_ABS_QUOTIENT_TIMES_19: i64 = 120_165_899;
pub const MAX_ABS_QUOTIENT_TIMES_8: i64 = 50_596_168;
pub const MAX_ABS_HIGH_PLUS_QUOTIENT: i64 = 101_187_881;
pub const MAX_ABS_SCALED_HIGH_PLUS_QUOTIENT: i64 = 1_922_569_739;
pub const MAX_ABS_FOLDED_PLUS_QUOTIENT: i64 = 1_985_484_299;
pub const MAX_ABS_RELATION_PRE_CARRY: i64 = 1_985_484_314;
pub const MAX_ABS_RELATION_CARRY: i64 = 124_092_770;
pub const MAX_ABS_SCALED_CARRY: i64 = 1_985_484_320;
pub const MAX_ABS_FINAL_RELATION_ACCUMULATOR: i64 = 174_688_938;

const RADIX: i32 = 16;
const LIMB_RADIX: i32 = 1 << 20;
const LIMB_HALF_RADIX: i32 = 1 << 19;
const LOW_BYTE_BOUND: i32 = 0xed;

pub type FieldDigits = [i32; FIELD_DIGIT_COUNT];
pub type BalancedLimbs = [i32; LIMB_COUNT];
pub type RelationCarries = [i32; RELATION_CARRY_COUNT];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MulHints {
    pub remainder: BigUint,
    pub quotient: i32,
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
            { self.quotient }
            for carry in self.carries.iter().rev() {
                { *carry }
            }
        }
    }

    pub fn witness_items(&self) -> Vec<Vec<u8>> {
        std::iter::once(&self.quotient)
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
    reconstruct_coefficients(digits)
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

fn balanced_limbs(digits: &FieldDigits) -> BalancedLimbs {
    let mut carry = 0i32;
    std::array::from_fn(|limb_index| {
        let digit_count = if limb_index + 1 == LIMB_COUNT { 4 } else { 5 };
        let start = DIGITS_PER_LIMB * limb_index;
        let raw = (0..digit_count).rev().fold(0i32, |value, digit_index| {
            value * RADIX + digits[start + digit_index]
        }) + carry;

        if limb_index + 1 == LIMB_COUNT {
            assert!((0..=1 << 15).contains(&raw));
            carry = 0;
            raw
        } else if raw >= LIMB_HALF_RADIX {
            carry = 1;
            raw - LIMB_RADIX
        } else {
            carry = 0;
            raw
        }
    })
}

#[cfg(test)]
fn reconstruct_limbs(limbs: &BalancedLimbs) -> BigInt {
    limbs
        .iter()
        .rev()
        .fold(BigInt::zero(), |value, limb| value * LIMB_RADIX + limb)
}

fn product_coefficients(lhs: &FieldDigits, rhs: &FieldDigits) -> [i64; PRODUCT_COEFFICIENT_COUNT] {
    let lhs = balanced_limbs(lhs);
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

fn reconstruct_coefficients<T>(coefficients: &[T]) -> BigInt
where
    T: Copy,
    BigInt: From<T>,
{
    coefficients
        .iter()
        .rev()
        .fold(BigInt::zero(), |value, coefficient| {
            value * RADIX + BigInt::from(*coefficient)
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
    let quotient = delta / &p_integer;
    assert!(quotient.abs() <= BigInt::from(MAX_ABS_QUOTIENT));
    let quotient = quotient
        .to_i32()
        .expect("balanced radix-16 quotient fits ScriptNum");
    let quotient_i64 = i64::from(quotient);
    assert!((19 * quotient_i64).abs() <= MAX_ABS_QUOTIENT_TIMES_19);
    assert!((8 * quotient_i64).abs() <= MAX_ABS_QUOTIENT_TIMES_8);
    let high_plus_quotient = product[63] + quotient_i64;
    assert!(high_plus_quotient.abs() <= MAX_ABS_HIGH_PLUS_QUOTIENT);
    assert!((19 * high_plus_quotient).abs() <= MAX_ABS_SCALED_HIGH_PLUS_QUOTIENT);
    assert!((8 * product[0] + 19 * high_plus_quotient).abs() <= MAX_ABS_FOLDED_PLUS_QUOTIENT);

    let mut previous = 0i64;
    let mut carries = [0i32; RELATION_CARRY_COUNT];
    for coefficient_index in 0..FIELD_DIGIT_COUNT {
        let mut coefficient = previous + folded[coefficient_index];
        if coefficient_index == 0 {
            coefficient += 19 * i64::from(quotient);
        }
        if coefficient_index + 1 == FIELD_DIGIT_COUNT {
            coefficient -= 8 * i64::from(quotient);
            assert!(coefficient.abs() <= MAX_ABS_FINAL_RELATION_ACCUMULATOR);
        }
        coefficient -= i64::from(remainder_digits[coefficient_index]);

        assert!(coefficient.abs() <= MAX_ABS_RELATION_PRE_CARRY);
        if coefficient_index < RELATION_CARRY_COUNT {
            assert_eq!(coefficient % i64::from(RADIX), 0);
            previous = coefficient / i64::from(RADIX);
            assert!(previous.abs() <= MAX_ABS_RELATION_CARRY);
            assert!((16 * previous).abs() <= MAX_ABS_SCALED_CARRY);
            carries[coefficient_index] =
                i32::try_from(previous).expect("radix-16 relation carry fits ScriptNum");
        } else {
            assert_eq!(coefficient, 0, "final radix-16 relation coefficient");
        }
    }

    MulHints {
        remainder,
        quotient,
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

// Destructively consumes one little-endian group of left-operand nibbles.
// Existing table entries sit above those nibbles on the main stack.
fn build_unsigned_lhs_limb(table_items: usize, digit_count: usize) -> Script {
    script! {
        { (table_items + digit_count - 1) as u32 } OP_ROLL
        for digit_index in (0..digit_count - 1).rev() {
            { scriptint::mul_by_constant(16) }
            { (table_items + digit_index + 1) as u32 } OP_ROLL
            OP_ADD
        }
    }
}

// Input: `... x`; output: `... balanced carry`, where
// x = balanced + carry*2^20 and balanced is in [-2^19,2^19).
fn balance_limb() -> Script {
    script! {
        OP_DUP { LIMB_HALF_RADIX } OP_GREATERTHANOREQUAL
        OP_IF
            { LIMB_RADIX } OP_SUB
            1
        OP_ELSE
            0
        OP_ENDIF
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

fn build_balanced_lhs_tables() -> Script {
    script! {
        for limb_index in 0..LIMB_COUNT {
            { build_unsigned_lhs_limb(
                limb_index * TABLE_SIZE,
                if limb_index + 1 == LIMB_COUNT { 4 } else { 5 },
            ) }
            if limb_index != 0 {
                OP_FROMALTSTACK OP_ADD
            }
            if limb_index + 1 != LIMB_COUNT {
                { balance_limb() }
                OP_TOALTSTACK
            }
            { build_descending_multiple_table() }
        }
    }
}

fn table_setup() -> Script {
    script! {
        { park_rhs_and_hints() }
        { build_balanced_lhs_tables() }
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
    assert!(!terms.is_empty());
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

fn folded_coefficient(coefficient_index: usize, layout: &mut ProductLayout) -> Script {
    let remaining_carries = RELATION_CARRY_COUNT.saturating_sub(coefficient_index);
    if coefficient_index >= 63 {
        return Script::new("previous carry is the folded accumulator");
    }

    let has_previous_carry = coefficient_index != 0;
    let has_high = coefficient_index + 63 < PRODUCT_COEFFICIENT_COUNT;
    let low_sum = product_sum(
        coefficient_index,
        remaining_carries,
        usize::from(has_previous_carry),
        layout,
    );
    if !has_high {
        return script! {
            { low_sum }
            { scriptint::mul_by_constant(8) }
            OP_ADD
        };
    }

    let high_sum = product_sum(
        coefficient_index + 63,
        remaining_carries,
        1 + usize::from(has_previous_carry),
        layout,
    );
    let merge_quotient = if coefficient_index == 0 {
        script! {
            { (remaining_carries + 2) as u32 } OP_PICK
            OP_ADD
        }
    } else {
        Script::new("no low-column quotient")
    };
    script! {
        { low_sum }
        { high_sum }
        { merge_quotient }
        { combine_8_low_19_high() }
        if has_previous_carry { OP_ADD }
    }
}

fn high_quotient_coefficient(coefficient_index: usize) -> Script {
    if coefficient_index + 1 == FIELD_DIGIT_COUNT {
        // This is the quotient's second and final use, so consume it.
        script! {
            OP_SWAP
            { scriptint::mul_by_constant(8) }
            OP_SUB
        }
    } else {
        Script::new("no high quotient coefficient")
    }
}

fn relation_carry_step(coefficient_index: usize) -> Script {
    if coefficient_index < RELATION_CARRY_COUNT {
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
    }
}

fn coefficient_step(coefficient_index: usize, layout: &mut ProductLayout) -> Script {
    script! {
        { folded_coefficient(coefficient_index, layout) }
        { high_quotient_coefficient(coefficient_index) }
        { relation_carry_step(coefficient_index) }
    }
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
    script! {
        for _ in 0..TABLE_ITEM_COUNT / 2 { OP_2DROP }
        if TABLE_ITEM_COUNT % 2 != 0 { OP_DROP }
        { restore_result_and_verify_canonical() }
    }
}

/// Verifies a multiplication whose two operands were already certified.
pub fn mul_mod_hinted(preserved_items: u32) -> Script {
    assert!(
        u64::from(preserved_items) + u64::from(HINTED_MUL_STACK_ITEMS)
            <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "balanced radix-16 Ed25519 multiplication exceeds the stack limit"
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

    fn ceil_div_nonnegative(value: &BigInt, divisor: &BigInt) -> BigInt {
        (value + divisor - 1) / divisor
    }

    #[test]
    fn balancing_is_exact_and_bounded() {
        let p = modulus();
        let cases = [
            BigUint::zero(),
            BigUint::one(),
            (BigUint::one() << 19usize) - BigUint::one(),
            BigUint::one() << 19usize,
            (BigUint::one() << 20usize) - BigUint::one(),
            &p - BigUint::one(),
        ];
        for value in cases {
            let digits = field_digits(&value);
            let limbs = balanced_limbs(&digits);
            assert_eq!(reconstruct_limbs(&limbs), BigInt::from(value));
            assert!(limbs[..12]
                .iter()
                .all(|limb| (-LIMB_HALF_RADIX..LIMB_HALF_RADIX).contains(limb)));
            assert!((0..=1 << 15).contains(&limbs[12]));
        }

        let mut rng = ChaCha20Rng::seed_from_u64(0xb420_4544_3235_3531);
        for _ in 0..256 {
            let value = rng.gen_biguint_below(&p);
            let limbs = balanced_limbs(&field_digits(&value));
            assert_eq!(reconstruct_limbs(&limbs), BigInt::from(value));
        }
    }

    #[test]
    fn factor8_encoding_and_host_relation_are_exact() {
        let p = modulus();
        let mut rng = ChaCha20Rng::seed_from_u64(0xb816_4544_3235_3531);
        for _ in 0..256 {
            let logical_lhs = rng.gen_biguint_below(&p);
            let logical_rhs = rng.gen_biguint_below(&p);
            let lhs = encode(&logical_lhs);
            let rhs = encode(&logical_rhs);
            let hints = hinted_mul(&lhs, &rhs);
            assert_eq!(decode(&hints.remainder), logical_lhs * logical_rhs % &p);
            assert!(i64::from(hints.quotient).abs() <= MAX_ABS_QUOTIENT);
            assert_eq!(
                reconstruct_digits(&field_digits(&hints.remainder)),
                BigInt::from(hints.remainder)
            );
        }
    }

    #[test]
    fn analytic_scriptnum_bounds_hold() {
        let mut product_bounds = [0i64; PRODUCT_COEFFICIENT_COUNT];
        for limb_index in 0..LIMB_COUNT {
            let limb_bound = if limb_index + 1 == LIMB_COUNT {
                1i64 << 15
            } else {
                1i64 << 19
            };
            for rhs_index in 0..FIELD_DIGIT_COUNT {
                product_bounds[DIGITS_PER_LIMB * limb_index + rhs_index] += 15 * limb_bound;
            }
        }
        assert_eq!(
            product_bounds.iter().copied().max().unwrap(),
            MAX_ABS_PRODUCT_COEFFICIENT
        );
        assert_eq!(15 * (1i64 << 19), MAX_ABS_TABLE_ENTRY);

        let folded_bounds: [i64; FIELD_DIGIT_COUNT] = std::array::from_fn(|index| {
            (if index < 63 {
                8 * product_bounds[index]
            } else {
                0
            }) + 19 * product_bounds.get(index + 63).copied().unwrap_or(0)
        });
        assert_eq!(
            folded_bounds.iter().copied().max().unwrap(),
            MAX_ABS_FOLDED_COEFFICIENT
        );

        // If P=L+16^63*H, then F=8L+19H and the quotient is
        // (F-r)/p. Bounding every folded coefficient independently loses the
        // cancellation between L and H and overstates the quotient by 16x.
        // Instead, |L| is bounded directly by the first 63 product columns.
        // Since P<p^2 and 16^63=2^252, |H|<16p; the final +1 covers r<p.
        let p = BigInt::from(modulus());
        let split_radix = BigInt::one() << 252usize;
        let low_integer_bound = reconstruct_coefficients(&product_bounds[..63]);
        assert!(
            &p * &p + &low_integer_bound < BigInt::from(16) * &p * split_radix,
            "high product half must have magnitude below 16p"
        );
        let scaled_low_bound = ceil_div_nonnegative(&(8 * low_integer_bound), &p);
        let quotient_bound = scaled_low_bound + 19 * 16 + 1;
        assert_eq!(quotient_bound, BigInt::from(MAX_ABS_QUOTIENT));
        assert_eq!(19 * MAX_ABS_QUOTIENT, MAX_ABS_QUOTIENT_TIMES_19);
        assert_eq!(8 * MAX_ABS_QUOTIENT, MAX_ABS_QUOTIENT_TIMES_8);

        let high_plus_quotient = product_bounds[63] + MAX_ABS_QUOTIENT;
        assert_eq!(high_plus_quotient, MAX_ABS_HIGH_PLUS_QUOTIENT);
        assert_eq!(19 * high_plus_quotient, MAX_ABS_SCALED_HIGH_PLUS_QUOTIENT);
        assert_eq!(
            8 * product_bounds[0] + 19 * high_plus_quotient,
            MAX_ABS_FOLDED_PLUS_QUOTIENT
        );

        let mut carry_bound = 0i64;
        let mut max_pre_carry = 0i64;
        let mut max_carry = 0i64;
        for coefficient_index in 0..FIELD_DIGIT_COUNT {
            let mut pre_carry = carry_bound + folded_bounds[coefficient_index];
            if coefficient_index == 0 {
                pre_carry += 19 * MAX_ABS_QUOTIENT;
            }
            if coefficient_index + 1 == FIELD_DIGIT_COUNT {
                pre_carry += 8 * MAX_ABS_QUOTIENT;
            }
            if coefficient_index < 63 {
                pre_carry += 15;
            } else {
                pre_carry += 7;
            }
            max_pre_carry = max_pre_carry.max(pre_carry);
            if coefficient_index < RELATION_CARRY_COUNT {
                carry_bound = (pre_carry + 15) / 16;
                max_carry = max_carry.max(carry_bound);
            }
        }
        assert_eq!(max_pre_carry, MAX_ABS_RELATION_PRE_CARRY);
        assert_eq!(max_carry, MAX_ABS_RELATION_CARRY);
        assert_eq!(16 * max_carry, MAX_ABS_SCALED_CARRY);
        assert_eq!(
            max_carry + MAX_ABS_QUOTIENT_TIMES_8,
            MAX_ABS_FINAL_RELATION_ACCUMULATOR
        );
        assert!(MAX_ABS_QUOTIENT_TIMES_19 < i64::from(i32::MAX));
        assert!(MAX_ABS_QUOTIENT_TIMES_8 < i64::from(i32::MAX));
        assert!(MAX_ABS_SCALED_HIGH_PLUS_QUOTIENT < i64::from(i32::MAX));
        assert!(MAX_ABS_FOLDED_PLUS_QUOTIENT < i64::from(i32::MAX));
        assert!(max_pre_carry < i64::from(i32::MAX));
        assert!(MAX_ABS_SCALED_CARRY < i64::from(i32::MAX));
        assert!(MAX_ABS_FINAL_RELATION_ACCUMULATOR < i64::from(i32::MAX));
    }

    #[test]
    fn schoolbook_schedule_has_exactly_832_lookups() {
        let term_count: usize = (0..PRODUCT_COEFFICIENT_COUNT)
            .map(|index| product_pairs(index).len())
            .sum();
        assert_eq!(term_count, PRODUCT_TERM_COUNT);
        assert_eq!(term_count, 832);
    }

    #[test]
    #[should_panic(expected = "balanced radix-16 Ed25519 multiplication exceeds the stack limit")]
    fn stack_guard_rejects_one_extra_preserved_item() {
        let _ = mul_mod_hinted(MAX_PRESERVED_ITEMS + 1);
    }

    #[test]
    #[ignore = "strict generated-Script execution is intentionally opt-in"]
    fn generated_multiplication_is_strictly_validated() {
        let p = modulus();
        let cases = [
            (BigUint::zero(), BigUint::zero()),
            (BigUint::one(), &p - BigUint::one()),
            (&p - BigUint::one(), &p - BigUint::one()),
        ];
        let script = mul_mod_hinted_from_raw_witness(0).compile_with_policy();
        for (logical_lhs, logical_rhs) in cases {
            let lhs = encode(&logical_lhs);
            let rhs = encode(&logical_rhs);
            let hints = hinted_mul(&lhs, &rhs);
            let execution = execute_raw_script_with_inputs_strict(
                script.to_bytes(),
                witness_items(&lhs, &rhs, &hints),
            );
            assert!(execution.error.is_none(), "{execution}");
            assert!(execution.stats.max_nb_stack_items <= HINTED_MUL_STACK_ITEMS as usize);
            assert_eq!(execution.final_stack.len(), FIELD_DIGIT_COUNT);
            for (index, digit) in field_digits(&hints.remainder).iter().rev().enumerate() {
                assert_eq!(execution.final_stack.get(index), scriptnum_item(*digit));
            }
        }
    }

    #[test]
    #[ignore = "strict generated-Script adversarial execution is intentionally opt-in"]
    fn generated_tampered_scalar_hints_are_rejected() {
        let p = modulus();
        let lhs = encode(&(&p - BigUint::from(2u32)));
        let rhs = encode(&(&p - BigUint::from(3u32)));
        let hints = hinted_mul(&lhs, &rhs);
        let script = mul_mod_hinted_from_raw_witness(0).compile_with_policy();

        let mut bad_quotient = hints.clone();
        bad_quotient.quotient += 1;
        let rejected = execute_raw_script_with_inputs_strict(
            script.to_bytes(),
            witness_items(&lhs, &rhs, &bad_quotient),
        );
        assert!(
            rejected.error.is_some(),
            "tampered quotient accepted: {rejected}"
        );

        let mut bad_carry = hints.clone();
        bad_carry.carries[RELATION_CARRY_COUNT / 2] += 1;
        let rejected = execute_raw_script_with_inputs_strict(
            script.to_bytes(),
            witness_items(&lhs, &rhs, &bad_carry),
        );
        assert!(
            rejected.error.is_some(),
            "tampered carry accepted: {rejected}"
        );
    }

    #[test]
    #[ignore = "strict generated-Script adversarial execution is intentionally opt-in"]
    fn generated_malformed_and_noncanonical_operands_are_rejected() {
        let p = modulus();
        let lhs = encode(&BigUint::from(7u32));
        let rhs = encode(&BigUint::from(11u32));
        let hints = hinted_mul(&lhs, &rhs);
        let script = mul_mod_hinted_from_raw_witness(0).compile_with_policy();

        let mut malformed = witness_items(&lhs, &rhs, &hints);
        malformed[FIELD_DIGIT_COUNT - 1] = scriptnum_item(16);
        let rejected = execute_raw_script_with_inputs_strict(script.to_bytes(), malformed);
        assert!(
            rejected.error.is_some(),
            "out-of-range digit accepted: {rejected}"
        );

        let mut noncanonical = witness_items(&lhs, &rhs, &hints);
        for (slot, digit) in noncanonical[..FIELD_DIGIT_COUNT]
            .iter_mut()
            .zip(field_digits_unchecked(&p).iter().rev())
        {
            *slot = scriptnum_item(*digit);
        }
        let rejected = execute_raw_script_with_inputs_strict(script.to_bytes(), noncanonical);
        assert!(
            rejected.error.is_some(),
            "noncanonical field value accepted: {rejected}"
        );
    }
}
