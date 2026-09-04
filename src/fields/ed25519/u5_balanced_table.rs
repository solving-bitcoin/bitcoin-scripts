//! Centered radix-32 Ed25519 field multiplication.
//!
//! Public stack digits are biased: `e_i = d_i + 16` is in `[0, 31]`, while
//! arithmetic uses the centered digit `d_i` in `[-16, 15]`. If
//! `S = 1 + 32 + ... + 32^50`, the centered vectors cover `[-16*S, 15*S]`.
//! Removing the largest 19 integers leaves exactly `p = 32^51 - 19`
//! consecutive representatives. In biased form this is the familiar
//! canonical condition `0 <= sum(e_i*32^i) < p`: reject precisely the vectors
//! with `e_1..e_50 = 31` and `e_0 >= 13`.
//!
//! The left operand is grouped into twelve four-digit limbs and one top
//! three-digit limb. Script subtracts the limb bias once, then builds an exact
//! signed 32-entry table. Right digits index it directly, so the schoolbook
//! kernel has `13 * 51 = 663` lookups and no per-product selector adjustment.
//! The first table has a fused `+16` affine offset. It contributes once to
//! every low coefficient, so relation outputs are already biased stack digits
//! and need no per-column biasing opcode pair.
//! Since `32^51 = p + 19`, high coefficients fold by 19. The witness supplies
//! a scalar quotient and 50 carries; the omitted final carry equals the
//! quotient itself. A separate verified-product gate accepts an already-
//! certified claimed result and walks the same equations backward, deriving
//! every carry from the quotient. That boundary uses one auxiliary hint, but a
//! fresh claimed result is still 51 witness/data items and therefore does not
//! improve the 1,000-item composition bound of a compute-output multiplication.

use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed, ToPrimitive, Zero};

use crate::{
    arithmetic::{scriptint, u31::U31_LOOKUP_STACK_LIMIT},
    support::script::*,
};

pub const FIELD_DIGIT_COUNT: usize = 51;
pub const LIMB_COUNT: usize = 13;
pub const DIGITS_PER_LIMB: usize = 4;
pub const TABLE_SIZE: usize = 32;
pub const TABLE_ITEM_COUNT: usize = LIMB_COUNT * TABLE_SIZE;
pub const PRODUCT_TERM_COUNT: usize = LIMB_COUNT * FIELD_DIGIT_COUNT;
pub const PRODUCT_COEFFICIENT_COUNT: usize = 99;
pub const RELATION_CARRY_COUNT: usize = FIELD_DIGIT_COUNT - 1;
pub const HINT_ITEM_COUNT: usize = 1 + RELATION_CARRY_COUNT;
pub const MUL_WITNESS_ITEM_COUNT: usize = 2 * FIELD_DIGIT_COUNT + HINT_ITEM_COUNT;
pub const VERIFIED_PRODUCT_HINT_ITEM_COUNT: usize = 1;
pub const VERIFIED_PRODUCT_WITNESS_ITEM_COUNT: usize =
    3 * FIELD_DIGIT_COUNT + VERIFIED_PRODUCT_HINT_ITEM_COUNT;

// Data-independent strict peak reproduced by the benchmark execution.
pub const HINTED_MUL_STACK_ITEMS: u32 = 523;
pub const MAX_PRESERVED_ITEMS: u32 = U31_LOOKUP_STACK_LIMIT - HINTED_MUL_STACK_ITEMS;
// Data-independent strict peak reproduced by the verified-product example.
// This includes the complete main-plus-alt-stack population.
pub const VERIFIED_PRODUCT_STACK_ITEMS: u32 = 525;
pub const MAX_VERIFIED_PRODUCT_PRESERVED_ITEMS: u32 =
    U31_LOOKUP_STACK_LIMIT - VERIFIED_PRODUCT_STACK_ITEMS;

pub const MIN_LHS_LIMB: i64 = -541_200;
pub const MAX_LHS_LIMB: i64 = 507_375;
pub const MAX_ABS_TABLE_ENTRY: i64 = 8_659_216;
pub const MAX_ABS_PRODUCT_COEFFICIENT: i64 = 104_180_992;
pub const MAX_ABS_AFFINE_PRODUCT_COEFFICIENT: i64 = 104_181_008;
pub const MIN_FOLDED_COEFFICIENT: i64 = -1_709_599_920;
pub const MAX_FOLDED_COEFFICIENT: i64 = 1_823_573_248;
pub const MIN_AFFINE_FOLDED_COEFFICIENT: i64 = -1_709_599_904;
pub const MAX_AFFINE_FOLDED_COEFFICIENT: i64 = 1_823_573_264;
pub const MIN_QUOTIENT: i64 = -3_150_640;
pub const MAX_QUOTIENT: i64 = 3_360_683;
pub const MAX_ABS_QUOTIENT: i64 = 3_360_683;
pub const MAX_QUOTIENT_SCRIPTNUM_PAYLOAD_BYTES: usize = 3;
pub const MAX_ABS_QUOTIENT_TIMES_19: i64 = 63_852_977;
pub const MAX_ABS_QUOTIENT_TIMES_32: i64 = 107_541_856;
pub const MAX_ABS_HIGH_PLUS_QUOTIENT: i64 = 98_882_475;
pub const MAX_ABS_SCALED_HIGH_PLUS_QUOTIENT: i64 = 1_878_767_025;
pub const MAX_ABS_RELATION_ACCUMULATOR: i64 = 1_887_426_241;
pub const MAX_ABS_RELATION_PRE_CARRY: i64 = 1_887_426_241;
pub const MAX_ABS_RELATION_CARRY: i64 = 58_982_071;
pub const MAX_ABS_SCALED_CARRY: i64 = 1_887_426_272;
pub const MAX_ABS_FINAL_ACCUMULATOR: i64 = 107_541_840;

const RADIX: i32 = 32;
const DIGIT_BIAS: i32 = 16;
const FULL_LIMB_BIAS: i32 = 541_200;
const TOP_LIMB_BIAS: i32 = 16_912;
const LOW_DIGIT_BOUND: i32 = 13;

pub type FieldDigits = [i32; FIELD_DIGIT_COUNT];
pub type SignedLimbs = [i32; LIMB_COUNT];
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

fn full_digit_span() -> BigInt {
    ((BigInt::one() << 255usize) - BigInt::one()) / BigInt::from(31u32)
}

pub fn canonical_min_integer() -> BigInt {
    -BigInt::from(DIGIT_BIAS) * full_digit_span()
}

pub fn canonical_max_integer() -> BigInt {
    BigInt::from(15) * full_digit_span() - BigInt::from(19)
}

fn centered_representative(value: &BigUint) -> BigInt {
    let p = modulus();
    assert!(value < &p, "Ed25519 field value must be canonical");
    let value = BigInt::from_biguint(Sign::Plus, value.clone());
    if value > canonical_max_integer() {
        value - BigInt::from_biguint(Sign::Plus, p)
    } else {
        value
    }
}

/// Returns the biased stack digits for a conventional residue in `[0, p)`.
pub fn field_digits(value: &BigUint) -> FieldDigits {
    let representative = centered_representative(value);
    let mut biased = (representative - canonical_min_integer())
        .to_biguint()
        .expect("centered representative lies above the interval minimum");
    let digits = std::array::from_fn(|_| {
        let digit = (&biased & BigUint::from(31u32))
            .to_i32()
            .expect("radix-32 digit fits i32");
        biased >>= 5usize;
        digit
    });
    assert!(biased.is_zero());
    debug_assert!(is_canonical_digits(&digits));
    digits
}

fn arithmetic_digits(stored: &FieldDigits) -> FieldDigits {
    stored.map(|digit| digit - DIGIT_BIAS)
}

fn reconstruct_centered_digits(stored: &FieldDigits) -> BigInt {
    reconstruct_coefficients(&arithmetic_digits(stored))
}

pub fn is_canonical_digits(digits: &FieldDigits) -> bool {
    digits.iter().all(|digit| (0..RADIX).contains(digit))
        && !(digits[1..].iter().all(|digit| *digit == 31) && digits[0] >= LOW_DIGIT_BOUND)
}

/// Converts biased stack digits back to the represented residue.
pub fn value_from_field_digits(digits: &FieldDigits) -> BigUint {
    assert!(
        is_canonical_digits(digits),
        "field digits must be canonical"
    );
    let centered = reconstruct_centered_digits(digits);
    let value = if centered.is_negative() {
        centered + BigInt::from_biguint(Sign::Plus, modulus())
    } else {
        centered
    };
    value
        .to_biguint()
        .expect("decoded centered representative is nonnegative")
}

/// Host values remain in the ordinary field domain.
pub fn encode(value: &BigUint) -> BigUint {
    assert!(value < &modulus(), "Ed25519 field value must be canonical");
    value.clone()
}

/// Host values remain in the ordinary field domain.
pub fn decode(value: &BigUint) -> BigUint {
    assert!(
        value < &modulus(),
        "encoded Ed25519 value must be canonical"
    );
    value.clone()
}

fn signed_limbs(stored: &FieldDigits) -> SignedLimbs {
    let digits = arithmetic_digits(stored);
    std::array::from_fn(|limb_index| {
        let digit_count = if limb_index + 1 == LIMB_COUNT { 3 } else { 4 };
        let start = DIGITS_PER_LIMB * limb_index;
        (0..digit_count).rev().fold(0i32, |value, digit_index| {
            value * RADIX + digits[start + digit_index]
        })
    })
}

#[cfg(test)]
fn reconstruct_limbs(limbs: &SignedLimbs) -> BigInt {
    limbs
        .iter()
        .enumerate()
        .fold(BigInt::zero(), |value, (index, limb)| {
            value + (BigInt::from(*limb) << (5 * DIGITS_PER_LIMB * index))
        })
}

fn product_coefficients(lhs: &FieldDigits, rhs: &FieldDigits) -> [i64; PRODUCT_COEFFICIENT_COUNT] {
    let lhs = signed_limbs(lhs);
    let rhs = arithmetic_digits(rhs);
    let mut product = [0i64; PRODUCT_COEFFICIENT_COUNT];
    for (limb_index, limb) in lhs.into_iter().enumerate() {
        for (rhs_index, rhs_digit) in rhs.into_iter().enumerate() {
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
    assert!(lhs < &p, "left operand must be canonical");
    assert!(rhs < &p, "right operand must be canonical");
    let remainder = lhs * rhs % &p;
    let lhs_digits = field_digits(lhs);
    let rhs_digits = field_digits(rhs);
    let remainder_stored = field_digits(&remainder);
    let remainder_digits = arithmetic_digits(&remainder_stored);
    let product = product_coefficients(&lhs_digits, &rhs_digits);
    assert!(product
        .iter()
        .all(|value| value.abs() <= MAX_ABS_PRODUCT_COEFFICIENT));
    let folded = folded_coefficients(&product);
    assert!(folded
        .iter()
        .all(|value| { (MIN_FOLDED_COEFFICIENT..=MAX_FOLDED_COEFFICIENT).contains(value) }));
    let folded_integer = reconstruct_coefficients(&folded);
    let remainder_integer = reconstruct_coefficients(&remainder_digits);
    let p_integer = BigInt::from_biguint(Sign::Plus, p);
    let delta = folded_integer - remainder_integer;
    assert_eq!(&delta % &p_integer, BigInt::zero());
    let quotient_integer = delta / &p_integer;
    assert!((BigInt::from(MIN_QUOTIENT)..=BigInt::from(MAX_QUOTIENT)).contains(&quotient_integer));
    let quotient = quotient_integer
        .to_i32()
        .expect("centered radix-32 quotient fits ScriptNum");
    let quotient_i64 = i64::from(quotient);
    assert!((19 * quotient_i64).abs() <= MAX_ABS_QUOTIENT_TIMES_19);
    assert!((32 * quotient_i64).abs() <= MAX_ABS_QUOTIENT_TIMES_32);
    let high_plus_quotient = product[FIELD_DIGIT_COUNT] + quotient_i64;
    assert!(high_plus_quotient.abs() <= MAX_ABS_HIGH_PLUS_QUOTIENT);
    assert!((19 * high_plus_quotient).abs() <= MAX_ABS_SCALED_HIGH_PLUS_QUOTIENT);

    let mut previous = 0i64;
    let mut carries = [0i32; RELATION_CARRY_COUNT];
    for coefficient_index in 0..FIELD_DIGIT_COUNT {
        let mut accumulator = previous + folded[coefficient_index];
        if coefficient_index == 0 {
            accumulator += 19 * quotient_i64;
        }
        // Table zero fuses the +16 output bias into every low product column.
        let script_accumulator = accumulator + i64::from(DIGIT_BIAS);
        assert!(script_accumulator.abs() <= MAX_ABS_RELATION_ACCUMULATOR);
        if coefficient_index + 1 == FIELD_DIGIT_COUNT {
            assert!(script_accumulator.abs() <= MAX_ABS_FINAL_ACCUMULATOR);
        }
        let coefficient = script_accumulator - i64::from(remainder_stored[coefficient_index]);
        assert!(coefficient.abs() <= MAX_ABS_RELATION_PRE_CARRY);
        if coefficient_index < RELATION_CARRY_COUNT {
            assert_eq!(coefficient % i64::from(RADIX), 0);
            previous = coefficient / i64::from(RADIX);
            assert!(previous.abs() <= MAX_ABS_RELATION_CARRY);
            assert!((i64::from(RADIX) * previous).abs() <= MAX_ABS_SCALED_CARRY);
            carries[coefficient_index] =
                i32::try_from(previous).expect("radix-32 relation carry fits ScriptNum");
        } else {
            assert_eq!(coefficient, i64::from(RADIX) * quotient_i64);
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

/// Push `lhs | rhs | claimed_product | quotient` for [`verify_product_hinted`].
pub fn push_verified_product_witness(
    lhs: &BigUint,
    rhs: &BigUint,
    claimed_product: &BigUint,
    quotient: i32,
) -> Script {
    script! {
        { push_value(lhs) }
        { push_value(rhs) }
        { push_value(claimed_product) }
        { quotient }
    }
}

fn scriptnum_item(value: i32) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value));
    bytes[..length].to_vec()
}

fn verify_field_range_keep_at_depth(value_depth: u32) -> Script {
    script! {
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
        "centered radix-32 Ed25519 certification exceeds the stack limit"
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

fn build_lhs_limb(table_items: usize, digit_count: usize, top_limb: bool) -> Script {
    script! {
        { (table_items + digit_count - 1) as u32 } OP_ROLL
        for digit_index in (0..digit_count - 1).rev() {
            { scriptint::mul_by_constant(32) }
            { (table_items + digit_index + 1) as u32 } OP_ROLL
            OP_ADD
        }
        if top_limb {
            { TOP_LIMB_BIAS } OP_SUB
        } else {
            // A shared copy of the full-limb bias lives atop altstack.
            OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_SUB
        }
    }
}

// Input: `... a`; output: `... 15a+offset 14a+offset ... -16a+offset`,
// with selector zero nearest top.
fn build_descending_signed_table(offset: i32) -> Script {
    script! {
        // Keep `a` while deriving 15a as 16a-a. This is one serialized byte
        // smaller than the generic signed-digit chain for multiplication by 15.
        OP_DUP
        for _ in 0..4 { OP_DUP OP_ADD }
        OP_OVER OP_SUB
        if offset != 0 { { offset } OP_ADD }
        OP_SWAP
        for _ in 0..31 {
            OP_2DUP OP_SUB OP_SWAP
        }
        OP_DROP
    }
}

fn table_setup() -> Script {
    script! {
        { park_rhs_and_hints() }
        { FULL_LIMB_BIAS } OP_TOALTSTACK
        for limb_index in 0..LIMB_COUNT {
            { build_lhs_limb(
                limb_index * TABLE_SIZE,
                if limb_index + 1 == LIMB_COUNT { 3 } else { 4 },
                limb_index + 1 == LIMB_COUNT,
            ) }
            { build_descending_signed_table(if limb_index == 0 {
                DIGIT_BIAS
            } else {
                0
            }) }
        }
        OP_FROMALTSTACK OP_DROP
        { restore_rhs_and_hints() }
    }
}

fn park_verified_product_inputs() -> Script {
    script! {
        // Park q, then the claimed product, then rhs. Lhs remains on main for
        // table construction. The reverse order on altstack restores rhs,
        // claimed product, q.
        OP_TOALTSTACK
        for _ in 0..FIELD_DIGIT_COUNT { OP_TOALTSTACK }
        for _ in 0..FIELD_DIGIT_COUNT { OP_TOALTSTACK }
    }
}

fn restore_verified_product_inputs() -> Script {
    script! {
        for _ in 0..FIELD_DIGIT_COUNT { OP_FROMALTSTACK }
        for _ in 0..FIELD_DIGIT_COUNT { OP_FROMALTSTACK }
        OP_FROMALTSTACK
    }
}

fn verified_product_table_setup() -> Script {
    script! {
        { park_verified_product_inputs() }
        { FULL_LIMB_BIAS } OP_TOALTSTACK
        for limb_index in 0..LIMB_COUNT {
            { build_lhs_limb(
                limb_index * TABLE_SIZE,
                if limb_index + 1 == LIMB_COUNT { 3 } else { 4 },
                limb_index + 1 == LIMB_COUNT,
            ) }
            { build_descending_signed_table(if limb_index == 0 {
                DIGIT_BIAS
            } else {
                0
            }) }
        }
        OP_FROMALTSTACK OP_DROP
        { restore_verified_product_inputs() }
        // Keep q on main while parking claimed digits low-to-high. They then
        // emerge high-to-low, exactly matching the reverse recurrence. This
        // lets early product columns use much shallower table indices.
        for _ in 0..FIELD_DIGIT_COUNT { OP_SWAP OP_TOALTSTACK }
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

fn nonnegative_scriptnum_push_len(value: usize) -> usize {
    match value {
        0..=16 => 1,
        17..=127 => 2,
        128..=32_767 => 3,
        _ => panic!("lookup depth exceeds the two-byte ScriptNum range"),
    }
}

fn byte_optimal_pair_order(
    pairs: &[(usize, usize)],
    remaining_carries: usize,
    work_items_below: usize,
    has_initial_accumulator: bool,
    layout: &ProductLayout,
) -> Vec<(usize, usize)> {
    let state_count = 1usize << pairs.len();
    let mut costs = vec![usize::MAX; state_count];
    let mut predecessor = vec![None; state_count];
    costs[0] = 0;

    for scheduled in 0..state_count {
        if costs[scheduled] == usize::MAX {
            continue;
        }
        let accumulator_items = usize::from(has_initial_accumulator || scheduled != 0);
        let removed_count = pairs
            .iter()
            .enumerate()
            .filter(|(index, (_, rhs))| scheduled & (1 << index) != 0 && layout.is_last_use(*rhs))
            .count();
        let active_rhs = layout.active_count() - removed_count;

        for (pair_index, &(limb_index, rhs_index)) in pairs.iter().enumerate() {
            let pair_bit = 1usize << pair_index;
            if scheduled & pair_bit != 0 {
                continue;
            }
            let removed_above = pairs
                .iter()
                .enumerate()
                .filter(|(index, (_, rhs))| {
                    scheduled & (1 << index) != 0 && *rhs < rhs_index && layout.is_last_use(*rhs)
                })
                .count();
            let rhs_depth = remaining_carries
                + 1
                + accumulator_items
                + work_items_below
                + layout.active_above(rhs_index)
                - removed_above;
            let last_use = layout.is_last_use(rhs_index);
            let table_base = remaining_carries
                + active_rhs
                + usize::from(!last_use)
                + accumulator_items
                + work_items_below
                + (LIMB_COUNT - 1 - limb_index) * TABLE_SIZE;
            let next = scheduled | pair_bit;
            let next_cost = costs[scheduled]
                + nonnegative_scriptnum_push_len(rhs_depth)
                + nonnegative_scriptnum_push_len(table_base);
            if next_cost < costs[next] {
                costs[next] = next_cost;
                predecessor[next] = Some((scheduled, pair_index));
            }
        }
    }

    let mut ordered = Vec::with_capacity(pairs.len());
    let mut state = state_count - 1;
    while state != 0 {
        let (previous, pair_index) = predecessor[state].expect("complete pair schedule");
        ordered.push(pairs[pair_index]);
        state = previous;
    }
    ordered.reverse();
    ordered
}

fn product_sum(
    product_index: usize,
    remaining_carries: usize,
    work_items_below: usize,
    has_initial_accumulator: bool,
    layout: &mut ProductLayout,
) -> Script {
    let pairs = byte_optimal_pair_order(
        &product_pairs(product_index),
        remaining_carries,
        work_items_below,
        has_initial_accumulator,
        layout,
    );
    let terms = pairs
        .into_iter()
        .enumerate()
        .map(|(term_index, (limb_index, rhs_index))| {
            add_table_product(
                limb_index,
                rhs_index,
                remaining_carries,
                work_items_below,
                has_initial_accumulator || term_index != 0,
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

// Input: `... low high`; output: `... low + 19*high`.
// Every intermediate high multiple has magnitude at most 19*|high|.
fn combine_low_19_high() -> Script {
    script! {
        OP_DUP OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_2DUP OP_ADD OP_ADD
        OP_DUP OP_ADD OP_ADD OP_ADD
    }
}

fn coefficient_step(coefficient_index: usize, layout: &mut ProductLayout) -> Script {
    let remaining_carries = RELATION_CARRY_COUNT.saturating_sub(coefficient_index);
    let previous_carry_items = usize::from(coefficient_index != 0);
    // Advance the destructive-right-digit layout in execution order. Some
    // digits reach their last use in these final columns, so the high sum's
    // depths must observe every preceding low-sum use.
    let low = product_sum(
        coefficient_index,
        remaining_carries,
        0,
        previous_carry_items != 0,
        layout,
    );
    let high_product_index = coefficient_index + FIELD_DIGIT_COUNT;
    let high = if high_product_index < PRODUCT_COEFFICIENT_COUNT {
        let high_sum = product_sum(high_product_index, remaining_carries, 1, false, layout);
        if coefficient_index == 0 {
            script! {
                { high_sum }
                { (remaining_carries + 2) as u32 } OP_PICK
                OP_ADD
                { combine_low_19_high() }
            }
        } else {
            script! {
                { high_sum }
                { combine_low_19_high() }
            }
        }
    } else {
        Script::new("empty high coefficient")
    };
    let carry_and_output = if coefficient_index < RELATION_CARRY_COUNT {
        script! {
            OP_OVER { scriptint::mul_by_constant(32) } OP_SUB
            OP_DUP 0 32 OP_WITHIN OP_VERIFY
            OP_TOALTSTACK
        }
    } else {
        script! {
            // Consume the scalar quotient when it serves as the final carry.
            OP_SWAP { scriptint::mul_by_constant(32) } OP_SUB
            OP_DUP 0 32 OP_WITHIN OP_VERIFY
            OP_TOALTSTACK
        }
    };
    script! {
        { low }
        { high }
        { carry_and_output }
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

fn verified_product_coefficient(
    coefficient_index: usize,
    produced_product_items: usize,
    layout: &mut ProductLayout,
) -> Script {
    // The ordinary product scheduler's `remaining_carries + 1` prefix is only
    // a stack-depth quantity. Here already-returned product digits play the
    // role of `remaining_carries`, while the saved quotient is the `+1`.
    let low = product_sum(coefficient_index, produced_product_items, 1, false, layout);
    let high_product_index = coefficient_index + FIELD_DIGIT_COUNT;
    let folded = if high_product_index < PRODUCT_COEFFICIENT_COUNT {
        let high = product_sum(high_product_index, produced_product_items, 2, false, layout);
        script! {
            { low }
            { high }
            { combine_low_19_high() }
        }
    } else {
        low
    };
    folded
}

fn verified_product_relation() -> Script {
    let mut layout = ProductLayout::new();
    let reverse_steps = (1..FIELD_DIGIT_COUNT)
        .rev()
        .map(|coefficient_index| {
            let produced_product_items = FIELD_DIGIT_COUNT - 1 - coefficient_index;
            let coefficient = verified_product_coefficient(
                coefficient_index,
                produced_product_items,
                &mut layout,
            );
            script! {
                // Altstack supplies e_i. Rotate the current carry around A_i,
                // then leave e_i below the newly derived carry so the claimed
                // product is reconstructed in its original stack order.
                { coefficient }
                OP_FROMALTSTACK
                OP_ROT { scriptint::mul_by_constant(32) }
                OP_ROT OP_SUB OP_OVER OP_ADD
            }
        })
        .collect::<Vec<_>>();
    let low_coefficient = verified_product_coefficient(0, FIELD_DIGIT_COUNT - 1, &mut layout);
    assert!(layout.active_rhs.iter().all(|active| !active));
    script! {
        // Hostile q is the sole auxiliary hint. Bounding its numeric value
        // prevents the first reverse step from entering an avoidable
        // oversized-arithmetic path; the equations below bind that value.
        OP_DUP { MIN_QUOTIENT } { MAX_QUOTIENT + 1 } OP_WITHIN OP_VERIFY
        OP_DUP
        for step in reverse_steps {
            { step }
        }
        // Close the remaining low-column equation:
        // A_0 + 19*q - e_0 = 32*carry_0.
        { low_coefficient }
        OP_FROMALTSTACK
        OP_ROT { scriptint::mul_by_constant(32) } OP_ROT
        { (FIELD_DIGIT_COUNT + 2) as u32 } OP_PICK
        { scriptint::mul_by_constant(19) } OP_ADD
        2 OP_PICK OP_SUB
        OP_NUMEQUALVERIFY
    }
}

fn restore_result_and_verify_canonical() -> Script {
    script! {
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
    script! {
        for _ in 0..TABLE_ITEM_COUNT / 2 { OP_2DROP }
        if TABLE_ITEM_COUNT % 2 != 0 { OP_DROP }
        { restore_result_and_verify_canonical() }
    }
}

fn verified_product_cleanup() -> Script {
    script! {
        // Product scheduling has destructively consumed rhs. Preserve the
        // claimed product across removal of q and the 416-entry lhs tables.
        for _ in 0..FIELD_DIGIT_COUNT { OP_TOALTSTACK }
        OP_DROP
        for _ in 0..TABLE_ITEM_COUNT / 2 { OP_2DROP }
        if TABLE_ITEM_COUNT % 2 != 0 { OP_DROP }
        for _ in 0..FIELD_DIGIT_COUNT { OP_FROMALTSTACK }
    }
}

/// Multiply two already-certified field values and return a certified product.
///
/// Main-stack input, bottom to top, is
/// `lhs[50..0] | rhs[50..0] | quotient | carries[49..0]`, with `carries[0]`
/// nearest the top. Both operand digit vectors must already have passed
/// [`certify_value`] on the same verified path. The fragment consumes all
/// inputs and returns `product[50..0]`; it does not append a terminal predicate.
pub fn mul_mod_hinted(preserved_items: u32) -> Script {
    assert!(
        u64::from(preserved_items) + u64::from(HINTED_MUL_STACK_ITEMS)
            <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "centered radix-32 Ed25519 multiplication exceeds the stack limit"
    );
    script! {
        { table_setup() }
        { coefficient_relation() }
        { cleanup() }
    }
}

/// Verify a claimed product of three already-certified field values using only `q`.
///
/// Main-stack input, bottom to top, is
/// `lhs[50..0] | rhs[50..0] | claimed_product[50..0] | quotient`, with digit
/// zero nearest the top of each vector. All three vectors must already have
/// passed [`certify_value`] on the same verified path. The quotient is the one
/// from [`hinted_mul`]. The fragment consumes `lhs`, `rhs`, and `quotient`, and
/// returns the unchanged, certified `claimed_product[50..0]`; it does not add
/// a terminal predicate.
///
/// The incremental auxiliary-hint cost is exactly one stack item. A standalone
/// hostile-witness invocation has 154 input items: 51 digits for each of the
/// three field values plus the quotient. The 51 claimed-product digits are
/// circuit data, not auxiliary carry hints, but they coexist at script entry
/// unless the caller already has that certified value live on stack. Thus a
/// fresh claimed product plus q adds 52 entry items, not one. At this gate's
/// 525-item arithmetic peak, at most 475 unrelated items may be preserved; even
/// with every operand already available, that holds only nine pending 52-item
/// product-plus-q groups under the 1,000-item limit. The bounded quotient has
/// at most 22 magnitude bits and occupies at most three minimally encoded
/// ScriptNum payload bytes.
pub fn verify_product_hinted(preserved_items: u32) -> Script {
    assert!(
        u64::from(preserved_items) + u64::from(VERIFIED_PRODUCT_STACK_ITEMS)
            <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "centered radix-32 Ed25519 verified product exceeds the stack limit"
    );
    script! {
        { verified_product_table_setup() }
        { verified_product_relation() }
        { verified_product_cleanup() }
    }
}

/// Certify hostile `lhs`, `rhs`, and claimed-product vectors below one quotient.
pub fn certify_verified_product_inputs() -> Script {
    script! {
        { certify_value_at_depth(VERIFIED_PRODUCT_HINT_ITEM_COUNT as u32) }
        { certify_value_at_depth(
            (VERIFIED_PRODUCT_HINT_ITEM_COUNT + FIELD_DIGIT_COUNT) as u32,
        ) }
        { certify_value_at_depth(
            (VERIFIED_PRODUCT_HINT_ITEM_COUNT + 2 * FIELD_DIGIT_COUNT) as u32,
        ) }
    }
}

/// Certify three hostile field vectors, verify their product, and return the product.
pub fn verify_product_hinted_from_raw_witness(preserved_items: u32) -> Script {
    script! {
        { certify_verified_product_inputs() }
        { verify_product_hinted(preserved_items) }
    }
}

/// Certify the two raw operand vectors beneath one complete multiplication hint.
pub fn certify_mul_operands() -> Script {
    script! {
        { certify_value_at_depth(HINT_ITEM_COUNT as u32) }
        { certify_value_at_depth((HINT_ITEM_COUNT + FIELD_DIGIT_COUNT) as u32) }
    }
}

/// Certify hostile raw operand digits, multiply them, and return a certified product.
///
/// This has the same input and output order as [`mul_mod_hinted`]. It is still
/// a fragment rather than a complete clean-stack locking predicate.
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

pub fn verified_product_cost_breakdown() -> MulCostBreakdown {
    let mut cost = MulCostBreakdown {
        table_setup: verified_product_table_setup().compile_with_policy().len(),
        folded_relation: verified_product_relation().compile_with_policy().len(),
        cleanup: verified_product_cleanup().compile_with_policy().len(),
    };
    let independently_compiled = cost.total();
    let whole = verify_product_hinted(0).compile_with_policy().len();
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

    #[derive(Clone, Copy)]
    struct Interval {
        min: i64,
        max: i64,
    }

    impl Interval {
        fn add(self, rhs: Self) -> Self {
            Self {
                min: self.min + rhs.min,
                max: self.max + rhs.max,
            }
        }

        fn scale(self, factor: i64) -> Self {
            Self {
                min: factor * self.min,
                max: factor * self.max,
            }
        }

        fn max_abs(self) -> i64 {
            self.min.abs().max(self.max.abs())
        }
    }

    fn witness_items(lhs: &BigUint, rhs: &BigUint, hints: &MulHints) -> Vec<Vec<u8>> {
        field_digits(lhs)
            .iter()
            .rev()
            .chain(field_digits(rhs).iter().rev())
            .map(|digit| scriptnum_item(*digit))
            .chain(hints.witness_items())
            .collect()
    }

    fn verified_product_witness_items(
        lhs: &BigUint,
        rhs: &BigUint,
        product: &BigUint,
        quotient: i32,
    ) -> Vec<Vec<u8>> {
        [lhs, rhs, product]
            .into_iter()
            .flat_map(|value| field_digits(value).into_iter().rev().map(scriptnum_item))
            .chain(std::iter::once(scriptnum_item(quotient)))
            .collect()
    }

    fn ceil_div_nonnegative(value: &BigInt, divisor: &BigInt) -> BigInt {
        (value + divisor - 1) / divisor
    }

    fn floor_div(value: &BigInt, divisor: &BigInt) -> BigInt {
        if value.is_negative() {
            -ceil_div_nonnegative(&(-value), divisor)
        } else {
            value / divisor
        }
    }

    #[test]
    fn centered_encoding_is_unique_and_roundtrips() {
        let p = modulus();
        assert_eq!(
            canonical_max_integer() - canonical_min_integer() + 1,
            BigInt::from(p.clone())
        );
        for value in [BigUint::zero(), BigUint::one(), &p - BigUint::one()] {
            let digits = field_digits(&value);
            assert!(is_canonical_digits(&digits));
            assert_eq!(value_from_field_digits(&digits), value);
        }
        let mut gap = [31; FIELD_DIGIT_COUNT];
        gap[0] = 12;
        assert!(is_canonical_digits(&gap));
        gap[0] = 13;
        assert!(!is_canonical_digits(&gap));

        let mut rng = ChaCha20Rng::seed_from_u64(0xb532_4544_3235_3531);
        for _ in 0..256 {
            let value = rng.gen_biguint_below(&p);
            let digits = field_digits(&value);
            assert_eq!(value_from_field_digits(&digits), value);
            assert_eq!(
                reconstruct_limbs(&signed_limbs(&digits)),
                reconstruct_centered_digits(&digits)
            );
        }
    }

    #[test]
    fn host_multiplication_relation_is_exact() {
        let p = modulus();
        let cases = [BigUint::zero(), BigUint::one(), &p - BigUint::one()];
        for lhs in &cases {
            for rhs in &cases {
                let hints = hinted_mul(lhs, rhs);
                assert_eq!(hints.remainder, lhs * rhs % &p);
            }
        }
        let mut rng = ChaCha20Rng::seed_from_u64(0xb532_4d55_4c35_3531);
        for _ in 0..256 {
            let lhs = rng.gen_biguint_below(&p);
            let rhs = rng.gen_biguint_below(&p);
            let hints = hinted_mul(&lhs, &rhs);
            assert_eq!(hints.remainder, lhs * rhs % &p);
        }
    }

    #[test]
    fn reverse_relation_derives_every_forward_carry() {
        fn check(lhs: &BigUint, rhs: &BigUint) {
            let hints = hinted_mul(lhs, rhs);
            let product = product_coefficients(&field_digits(lhs), &field_digits(rhs));
            let folded = folded_coefficients(&product);
            let claimed = field_digits(&hints.remainder);
            let mut current = i64::from(hints.quotient);
            let mut reverse = [0i32; RELATION_CARRY_COUNT];
            for index in (1..FIELD_DIGIT_COUNT).rev() {
                current = i64::from(RADIX) * current - (folded[index] + i64::from(DIGIT_BIAS))
                    + i64::from(claimed[index]);
                reverse[index - 1] =
                    i32::try_from(current).expect("honest reverse-derived carry fits ScriptNum");
            }
            assert_eq!(reverse, hints.carries);
            assert_eq!(
                folded[0] + i64::from(DIGIT_BIAS) + 19 * i64::from(hints.quotient)
                    - i64::from(claimed[0]),
                i64::from(RADIX) * current,
            );
        }

        let p = modulus();
        for (lhs, rhs) in [
            (BigUint::zero(), BigUint::zero()),
            (BigUint::one(), &p - BigUint::one()),
            (&p - BigUint::from(2u32), &p - BigUint::from(3u32)),
        ] {
            check(&lhs, &rhs);
        }
        let mut rng = ChaCha20Rng::seed_from_u64(0xb532_5245_5635_3531);
        for _ in 0..256 {
            check(&rng.gen_biguint_below(&p), &rng.gen_biguint_below(&p));
        }
    }

    #[test]
    fn analytic_scriptnum_bounds_hold() {
        let limb_bounds: [Interval; LIMB_COUNT] = std::array::from_fn(|index| {
            let digits = if index + 1 == LIMB_COUNT { 3 } else { 4 };
            let span = ((1i64 << (5 * digits)) - 1) / 31;
            Interval {
                min: -16 * span,
                max: 15 * span,
            }
        });
        assert_eq!(
            (limb_bounds[0].min, limb_bounds[0].max),
            (MIN_LHS_LIMB, MAX_LHS_LIMB)
        );
        let term_bounds = limb_bounds.map(|limb| {
            let values = [limb.min * -16, limb.min * 15, limb.max * -16, limb.max * 15];
            Interval {
                min: *values.iter().min().unwrap(),
                max: *values.iter().max().unwrap(),
            }
        });
        let affine_table_zero = term_bounds[0].add(Interval { min: 16, max: 16 });
        assert_eq!(affine_table_zero.max_abs(), MAX_ABS_TABLE_ENTRY);
        let product_bounds: [Interval; PRODUCT_COEFFICIENT_COUNT] = std::array::from_fn(|column| {
            (0..LIMB_COUNT)
                .filter_map(|limb| {
                    column
                        .checked_sub(DIGITS_PER_LIMB * limb)
                        .filter(|rhs| *rhs < FIELD_DIGIT_COUNT)
                        .map(|_| term_bounds[limb])
                })
                .fold(Interval { min: 0, max: 0 }, Interval::add)
        });
        assert_eq!(
            product_bounds.iter().map(|x| x.max_abs()).max().unwrap(),
            MAX_ABS_PRODUCT_COEFFICIENT
        );
        let affine_product_bounds: [Interval; PRODUCT_COEFFICIENT_COUNT] =
            std::array::from_fn(|index| {
                product_bounds[index].add(if index < FIELD_DIGIT_COUNT {
                    Interval { min: 16, max: 16 }
                } else {
                    Interval { min: 0, max: 0 }
                })
            });
        assert_eq!(
            affine_product_bounds
                .iter()
                .map(|x| x.max_abs())
                .max()
                .unwrap(),
            MAX_ABS_AFFINE_PRODUCT_COEFFICIENT
        );
        let folded_bounds: [Interval; FIELD_DIGIT_COUNT] = std::array::from_fn(|index| {
            product_bounds[index].add(
                product_bounds
                    .get(index + FIELD_DIGIT_COUNT)
                    .copied()
                    .unwrap_or(Interval { min: 0, max: 0 })
                    .scale(19),
            )
        });
        assert_eq!(
            folded_bounds.iter().map(|x| x.min).min().unwrap(),
            MIN_FOLDED_COEFFICIENT
        );
        assert_eq!(
            folded_bounds.iter().map(|x| x.max).max().unwrap(),
            MAX_FOLDED_COEFFICIENT
        );
        let affine_folded_bounds = folded_bounds.map(|bound| {
            bound.add(Interval {
                min: DIGIT_BIAS.into(),
                max: DIGIT_BIAS.into(),
            })
        });
        assert_eq!(
            affine_folded_bounds.iter().map(|x| x.min).min().unwrap(),
            MIN_AFFINE_FOLDED_COEFFICIENT
        );
        assert_eq!(
            affine_folded_bounds.iter().map(|x| x.max).max().unwrap(),
            MAX_AFFINE_FOLDED_COEFFICIENT
        );

        let folded_min = reconstruct_coefficients(&folded_bounds.map(|x| x.min));
        let folded_max = reconstruct_coefficients(&folded_bounds.map(|x| x.max));
        let p = BigInt::from(modulus());
        assert_eq!(
            floor_div(&(folded_min - canonical_max_integer()), &p),
            BigInt::from(MIN_QUOTIENT)
        );
        assert_eq!(
            ceil_div_nonnegative(&(folded_max - canonical_min_integer()), &p),
            BigInt::from(MAX_QUOTIENT)
        );
        assert_eq!(19 * MAX_ABS_QUOTIENT, MAX_ABS_QUOTIENT_TIMES_19);
        assert_eq!(32 * MAX_ABS_QUOTIENT, MAX_ABS_QUOTIENT_TIMES_32);
        assert!(MAX_ABS_QUOTIENT < (1 << 22));
        assert_eq!(
            scriptnum_item(i32::try_from(MIN_QUOTIENT).unwrap()).len(),
            MAX_QUOTIENT_SCRIPTNUM_PAYLOAD_BYTES
        );
        assert_eq!(
            scriptnum_item(i32::try_from(MAX_QUOTIENT).unwrap()).len(),
            MAX_QUOTIENT_SCRIPTNUM_PAYLOAD_BYTES
        );

        let high_plus_q = product_bounds[FIELD_DIGIT_COUNT].add(Interval {
            min: MIN_QUOTIENT,
            max: MAX_QUOTIENT,
        });
        assert_eq!(high_plus_q.max_abs(), MAX_ABS_HIGH_PLUS_QUOTIENT);
        assert_eq!(
            high_plus_q.scale(19).max_abs(),
            MAX_ABS_SCALED_HIGH_PLUS_QUOTIENT
        );

        let mut carry = Interval { min: 0, max: 0 };
        let mut max_acc = 0;
        let mut max_pre = 0;
        let mut max_carry = 0;
        for (index, folded) in affine_folded_bounds.into_iter().enumerate() {
            let mut accumulator = carry.add(folded);
            if index == 0 {
                accumulator = accumulator.add(Interval {
                    min: 19 * MIN_QUOTIENT,
                    max: 19 * MAX_QUOTIENT,
                });
            }
            max_acc = max_acc.max(accumulator.max_abs());
            // Script directly emits biased digits e in [0,31].
            let pre = accumulator.add(Interval { min: -31, max: 0 });
            max_pre = max_pre.max(pre.max_abs());
            if index < RELATION_CARRY_COUNT {
                carry = Interval {
                    min: pre.min.div_euclid(i64::from(RADIX)),
                    max: (pre.max + i64::from(RADIX) - 1).div_euclid(i64::from(RADIX)),
                };
                max_carry = max_carry.max(carry.max_abs());
            } else {
                assert_eq!(accumulator.max_abs(), MAX_ABS_FINAL_ACCUMULATOR);
            }
        }
        assert_eq!(max_acc, MAX_ABS_RELATION_ACCUMULATOR);
        assert_eq!(max_pre, MAX_ABS_RELATION_PRE_CARRY);
        assert_eq!(max_carry, MAX_ABS_RELATION_CARRY);
        assert_eq!(32 * max_carry, MAX_ABS_SCALED_CARRY);
        for bound in [
            MAX_ABS_TABLE_ENTRY,
            MAX_ABS_PRODUCT_COEFFICIENT,
            MAX_ABS_AFFINE_PRODUCT_COEFFICIENT,
            MAX_FOLDED_COEFFICIENT,
            MAX_AFFINE_FOLDED_COEFFICIENT,
            MAX_ABS_SCALED_HIGH_PLUS_QUOTIENT,
            MAX_ABS_RELATION_ACCUMULATOR,
            MAX_ABS_RELATION_PRE_CARRY,
            MAX_ABS_SCALED_CARRY,
            MAX_ABS_FINAL_ACCUMULATOR,
        ] {
            assert!(bound < i64::from(i32::MAX));
        }
    }

    #[test]
    fn schoolbook_schedule_has_exactly_663_lookups() {
        let count: usize = (0..PRODUCT_COEFFICIENT_COUNT)
            .map(|i| product_pairs(i).len())
            .sum();
        assert_eq!(count, PRODUCT_TERM_COUNT);
        assert_eq!(count, 663);
    }

    #[test]
    #[should_panic(expected = "centered radix-32 Ed25519 multiplication exceeds the stack limit")]
    fn stack_guard_rejects_one_extra_preserved_item() {
        let _ = mul_mod_hinted(MAX_PRESERVED_ITEMS + 1);
    }

    #[test]
    #[should_panic(expected = "centered radix-32 Ed25519 verified product exceeds the stack limit")]
    fn verified_product_stack_guard_rejects_one_extra_preserved_item() {
        let _ = verify_product_hinted(MAX_VERIFIED_PRODUCT_PRESERVED_ITEMS + 1);
    }

    #[test]
    #[ignore = "strict generated-Script execution is intentionally opt-in"]
    fn generated_verified_product_is_strictly_validated() {
        let p = modulus();
        let lhs = &p - BigUint::from(2u32);
        let rhs = &p - BigUint::from(3u32);
        let hints = hinted_mul(&lhs, &rhs);
        let script = verify_product_hinted_from_raw_witness(0).compile_with_policy();
        let witness = verified_product_witness_items(&lhs, &rhs, &hints.remainder, hints.quotient);
        let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), witness);
        assert!(execution.error.is_none(), "{execution}");
        assert!(
            execution.stats.max_nb_stack_items <= VERIFIED_PRODUCT_STACK_ITEMS as usize,
            "measured peak exceeds documented bound: {execution}"
        );
        assert_eq!(execution.final_stack.len(), FIELD_DIGIT_COUNT);
        for (index, digit) in field_digits(&hints.remainder).iter().rev().enumerate() {
            assert_eq!(execution.final_stack.get(index), scriptnum_item(*digit));
        }
    }

    #[test]
    #[ignore = "strict generated-Script execution is intentionally opt-in"]
    fn generated_multiplication_is_strictly_validated() {
        let p = modulus();
        let script = mul_mod_hinted_from_raw_witness(0).compile_with_policy();
        for (lhs, rhs) in [
            (BigUint::zero(), BigUint::zero()),
            (BigUint::one(), &p - BigUint::one()),
            (&p - BigUint::from(2u32), &p - BigUint::from(3u32)),
        ] {
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
    fn generated_tampered_hints_are_rejected() {
        let p = modulus();
        let lhs = &p - BigUint::from(2u32);
        let rhs = &p - BigUint::from(3u32);
        let hints = hinted_mul(&lhs, &rhs);
        let script = mul_mod_hinted_from_raw_witness(0).compile_with_policy();
        let mut bad = hints.clone();
        bad.quotient += 1;
        let execution = execute_raw_script_with_inputs_strict(
            script.to_bytes(),
            witness_items(&lhs, &rhs, &bad),
        );
        assert!(
            execution.error.is_some(),
            "tampered quotient accepted: {execution}"
        );
    }

    #[test]
    #[ignore = "strict generated-Script adversarial execution is intentionally opt-in"]
    fn generated_malformed_and_gap_operands_are_rejected() {
        let lhs = BigUint::from(7u32);
        let rhs = BigUint::from(11u32);
        let hints = hinted_mul(&lhs, &rhs);
        let script = mul_mod_hinted_from_raw_witness(0).compile_with_policy();
        let mut malformed = witness_items(&lhs, &rhs, &hints);
        malformed[FIELD_DIGIT_COUNT - 1] = scriptnum_item(32);
        let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), malformed);
        assert!(
            execution.error.is_some(),
            "out-of-range operand accepted: {execution}"
        );

        let mut gap = witness_items(&lhs, &rhs, &hints);
        for slot in &mut gap[..FIELD_DIGIT_COUNT] {
            *slot = scriptnum_item(31);
        }
        gap[FIELD_DIGIT_COUNT - 1] = scriptnum_item(13);
        let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), gap);
        assert!(
            execution.error.is_some(),
            "19-value duplicate-gap operand accepted: {execution}"
        );
    }
}
