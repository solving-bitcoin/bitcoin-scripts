//! Radix-32 Ed25519 field multiplication with operand-specific lookup tables.
//!
//! A canonical field element is represented directly by 51 unsigned base-32
//! digits. The left operand is grouped into seventeen 15-bit limbs. For each
//! limb, Script constructs the exact table `{d*a_i | d in 0..31}` from the
//! certified operand. The right operand's certified digits select those
//! tables directly, so every schoolbook product needs one lookup.
//!
//! The radix is chosen so that `32^51 = p + 19`. Product coefficients at
//! positions 51 through 98 therefore fold into positions 0 through 47 with a
//! single multiply by 19. If the folded product is `f`, the canonical result
//! is `r`, and `f - r = t*p`, then the verifier checks
//! `f - r + 19*t = t*32^51` as one base-32 carry chain. The final carry must
//! equal the residual `t`.

use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, ToPrimitive, Zero};

use crate::{
    arithmetic::{scriptint, u31::U31_LOOKUP_STACK_LIMIT},
    support::script::*,
};

pub const FIELD_DIGIT_COUNT: usize = 51;
pub const LIMB_COUNT: usize = 17;
pub const DIGITS_PER_LIMB: usize = 3;
pub const TABLE_SIZE: usize = 32;
pub const TABLE_ITEM_COUNT: usize = LIMB_COUNT * TABLE_SIZE;
pub const PRODUCT_COEFFICIENT_COUNT: usize = 99;
pub const RELATION_CARRY_COUNT: usize = FIELD_DIGIT_COUNT;
pub const HINT_ITEM_COUNT: usize = 1 + RELATION_CARRY_COUNT;
pub const MUL_WITNESS_ITEM_COUNT: usize = 2 * FIELD_DIGIT_COUNT + HINT_ITEM_COUNT;

// Exact peak measured by strict generated-script execution.
pub const HINTED_MUL_STACK_ITEMS: u32 = 652;
pub const MAX_PRESERVED_ITEMS: u32 = U31_LOOKUP_STACK_LIMIT - HINTED_MUL_STACK_ITEMS;

const RADIX: i32 = 32;
const LOW_DIGIT_BOUND: i32 = 13;

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
        let digit = (&value & BigUint::from(31u32))
            .to_i32()
            .expect("base-32 digit fits i32");
        value >>= 5usize;
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

/// Radix-32 uses the ordinary field domain, so encoding is the identity.
pub fn encode(value: &BigUint) -> BigUint {
    assert!(value < &modulus(), "Ed25519 field value must be canonical");
    value.clone()
}

/// Radix-32 uses the ordinary field domain, so decoding is the identity.
pub fn decode(value: &BigUint) -> BigUint {
    assert!(
        value < &modulus(),
        "encoded Ed25519 value must be canonical"
    );
    value.clone()
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
        product[index] + 19 * product.get(index + FIELD_DIGIT_COUNT).copied().unwrap_or(0)
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
    assert!(lhs < &p, "left operand must be canonical");
    assert!(rhs < &p, "right operand must be canonical");
    let remainder = lhs * rhs % &p;
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
        .unwrap_or_else(|| panic!("radix-32 residual exceeds ScriptNum: {residual_integer}"));

    let mut previous = 0i64;
    let mut carries = [0i32; RELATION_CARRY_COUNT];
    for coefficient_index in 0..FIELD_DIGIT_COUNT {
        let mut coefficient =
            previous + folded[coefficient_index] - i64::from(remainder_digits[coefficient_index]);
        if coefficient_index == 0 {
            coefficient += 19 * i64::from(residual);
        }
        assert_eq!(coefficient % i64::from(RADIX), 0);
        previous = coefficient / i64::from(RADIX);
        carries[coefficient_index] =
            i32::try_from(previous).expect("radix-32 carry fits ScriptNum");
    }
    assert_eq!(previous, i64::from(residual), "final carry equals residual");

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
        // p = 32^51 - 19 has digits [13, 31, ..., 31]. The only
        // noncanonical encodings in the 255-bit radix range therefore have
        // every digit above d0 equal to 31 and d0 at least 13.
        { value_depth + 1 } OP_PICK
        for index in 2..FIELD_DIGIT_COUNT as u32 {
            { value_depth + index + 1 } OP_PICK OP_MIN
        }
        31 OP_NUMEQUAL
        OP_IF
            { value_depth } OP_PICK { LOW_DIGIT_BOUND } OP_LESSTHAN OP_VERIFY
        OP_ENDIF
    }
}

pub fn certify_value() -> Script {
    certify_value_at_depth(0)
}

pub fn certify_value_at_depth(items_above: u32) -> Script {
    assert!(
        u64::from(items_above) + FIELD_DIGIT_COUNT as u64 + 3 <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "radix-32 Ed25519 certification exceeds the stack limit"
    );
    script! {
        for index in 0..FIELD_DIGIT_COUNT as u32 {
            { items_above + index } OP_PICK 0 32 OP_WITHIN OP_VERIFY
        }
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
            { scriptint::mul_by_constant(32) }
            { (table_items + digit_index + 1) as u32 } OP_ROLL
            OP_ADD
        }
    }
}

// Input: `... a`; output: `... 31a 30a ... 0` with zero nearest the top.
fn build_descending_multiple_table() -> Script {
    script! {
        OP_DUP { scriptint::mul_by_constant(31) } OP_SWAP
        for _ in 0..31 {
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
    // OP_PICK consumes the computed index before applying it. This is the
    // selected table's zero-entry depth after that index has left the stack.
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

fn coefficient_step(coefficient_index: usize, layout: &mut ProductLayout) -> Script {
    let remaining_carries = RELATION_CARRY_COUNT - coefficient_index;
    let previous_carry_items = usize::from(coefficient_index != 0);
    let high_product_index = coefficient_index + FIELD_DIGIT_COUNT;
    let high = if high_product_index < PRODUCT_COEFFICIENT_COUNT {
        let high_sum = product_sum(high_product_index, remaining_carries, 1, layout);
        if coefficient_index == 0 {
            script! {
                { high_sum }
                { (remaining_carries + 2) as u32 } OP_PICK
                OP_ADD
                { scriptint::mul_by_constant(19) }
                OP_ADD
            }
        } else {
            script! {
                { high_sum }
                { scriptint::mul_by_constant(19) }
                OP_ADD
            }
        }
    } else {
        Script::new("empty high coefficient")
    };
    let final_carry_check = if coefficient_index + 1 == FIELD_DIGIT_COUNT {
        script! { OP_EQUALVERIFY }
    } else {
        Script::new("non-final carry")
    };
    script! {
        { product_sum(coefficient_index, remaining_carries, previous_carry_items, layout) }
        if coefficient_index != 0 { OP_ADD }
        { high }
        OP_OVER { scriptint::mul_by_constant(32) } OP_SUB
        OP_DUP 0 32 OP_WITHIN OP_VERIFY
        OP_TOALTSTACK
        { final_carry_check }
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
        // Results were produced low-to-high on altstack, so restoration is a
        // free high-to-low pass. Thread the minimum of d50..d1 through that
        // pass instead of re-reading fifty deep stack items afterward.
        OP_FROMALTSTACK
        OP_DUP
        for _ in 1..FIELD_DIGIT_COUNT - 1 {
            OP_FROMALTSTACK
            OP_SWAP OP_OVER OP_MIN
        }
        OP_FROMALTSTACK
        OP_SWAP
        31 OP_NUMEQUAL
        OP_IF
            OP_DUP { LOW_DIGIT_BOUND } OP_LESSTHAN OP_VERIFY
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
        "radix-32 Ed25519 multiplication exceeds the stack limit"
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
    fn ordinary_encoding_and_host_relation_are_exact() {
        let p = modulus();
        let boundary_values = [
            BigUint::zero(),
            BigUint::one(),
            BigUint::from(12u32),
            BigUint::from(13u32),
            &p - BigUint::one(),
        ];
        for lhs in &boundary_values {
            for rhs in &boundary_values {
                let hints = hinted_mul(lhs, rhs);
                assert_eq!(hints.remainder, lhs * rhs % &p);
                assert_eq!(hints.carries[RELATION_CARRY_COUNT - 1], hints.residual);
                assert_eq!(
                    reconstruct_digits(&field_digits(&hints.remainder)),
                    BigInt::from(hints.remainder.clone())
                );
            }
        }

        let mut rng = ChaCha20Rng::seed_from_u64(0x7535_4544_3235_3531);
        for _ in 0..128 {
            let lhs = rng.gen_biguint_below(&p);
            let rhs = rng.gen_biguint_below(&p);
            let hints = hinted_mul(&lhs, &rhs);
            assert_eq!(decode(&hints.remainder), lhs * rhs % &p);
            assert_eq!(hints.carries[RELATION_CARRY_COUNT - 1], hints.residual);
        }
    }

    #[test]
    fn folding_matches_the_unfolded_product_mod_p() {
        let p = modulus();
        let mut rng = ChaCha20Rng::seed_from_u64(0x7535_464f_4c44_3531);
        for _ in 0..128 {
            let lhs = rng.gen_biguint_below(&p);
            let rhs = rng.gen_biguint_below(&p);
            let lhs_digits = field_digits(&lhs);
            let rhs_digits = field_digits(&rhs);
            let product = product_coefficients(&lhs_digits, &rhs_digits);
            let folded = reconstruct_coefficients(&folded_coefficients(&product));
            let expected = BigInt::from_biguint(Sign::Plus, lhs * rhs % &p);
            assert_eq!(
                (folded - expected) % BigInt::from(p.clone()),
                BigInt::zero()
            );
        }
    }

    #[test]
    #[ignore = "expensive generated-script execution; run explicitly with --ignored"]
    fn strict_boundary_and_seeded_execution() {
        let p = modulus();
        let cases = [
            (BigUint::zero(), BigUint::zero()),
            (BigUint::one(), &p - BigUint::one()),
            (&p - BigUint::one(), &p - BigUint::one()),
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
