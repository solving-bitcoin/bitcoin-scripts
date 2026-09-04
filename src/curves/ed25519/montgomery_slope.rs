//! Montgomery slope-chain transition verifiers for the Ed25519 field.
//!
//! Selected Montgomery `a` coordinates use sixteen centered `[4x3,3x13]`
//! limbs because they feed the two-product continuity relation. Selected `b`
//! coordinates use the staggered nine-limb `[4,6x7,5]` layout because they
//! enter only as sparse linear coefficients. This removes packed decoders
//! while keeping every product, carry, and verifier arithmetic value inside
//! four-byte ScriptNum arithmetic. Legacy kernels take two exact relation
//! quotients as witness hints; derived kernels reconstruct both quotients from
//! the relation accumulators and take zero hint items. Direct limbs are an
//! authenticated table/state boundary: these fragments do not range-check
//! them internally.

use num_bigint::BigUint;

use crate::{
    fields::ed25519::{
        u5_balanced_table::{field_digits, modulus, FIELD_DIGIT_COUNT},
        u5_packed,
    },
    support::script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
};

use super::{
    absorb_relation_quotient, accumulate_streamed_limb_product_grouping,
    accumulate_streamed_limb_product_preserving_rhs, add_folded_product, arithmetic_digits,
    centered_digits_to_limbs, drop_streamed_relation_shared_power_pool, exact_quotient,
    initialize_streamed_grouped_four_square_preserving_rhs, move_block_to_top,
    park_streamed_relation_shared_power_pool, push_relation_accumulator,
    push_streamed_relation_shared_power_pool, restore_streamed_relation_shared_power_pool,
    verify_streamed_relation, verify_streamed_relation_absorbed,
    verify_streamed_relation_derived_with_multiplier,
    verify_streamed_relation_derived_with_multiplier_shared_power_pool, Grouping,
    SharedPowerPoolRelationBoundary, StreamedRelationQuotientMultiplier, ACCUMULATOR_COUNT,
};

pub const PRODUCT_LIMB_COUNT: usize = 16;
pub const LINEAR_LIMB_COUNT: usize = 9;
pub const HINT_ITEM_COUNT: usize = 2;
pub const FIRST_CLAIMED_DATA_ITEM_COUNT: usize =
    2 * u5_packed::PACKED_WORD_COUNT + 2 * PRODUCT_LIMB_COUNT + 2 * LINEAR_LIMB_COUNT;
pub const FIRST_COMPLETE_INPUT_ITEM_COUNT: usize = FIRST_CLAIMED_DATA_ITEM_COUNT + HINT_ITEM_COUNT;
pub const CHAINED_CLAIMED_DATA_ITEM_COUNT: usize =
    4 * u5_packed::PACKED_WORD_COUNT + 2 * PRODUCT_LIMB_COUNT + 2 * LINEAR_LIMB_COUNT;
pub const CHAINED_COMPLETE_INPUT_ITEM_COUNT: usize =
    CHAINED_CLAIMED_DATA_ITEM_COUNT + HINT_ITEM_COUNT;
/// No-hint variants derive both exact relation quotients from the completed
/// coefficient accumulators, so their complete input is claimed data only.
pub const FIRST_DERIVED_COMPLETE_INPUT_ITEM_COUNT: usize = FIRST_CLAIMED_DATA_ITEM_COUNT;
pub const CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT: usize = CHAINED_CLAIMED_DATA_ITEM_COUNT;
pub const OUTPUT_ITEM_COUNT: usize =
    2 * u5_packed::PACKED_WORD_COUNT + PRODUCT_LIMB_COUNT + LINEAR_LIMB_COUNT;
/// Experimental expanded chained state, physically ordered bottom-to-top as
/// `b[9] | a[16] | lambda_biased[51] | u[16]` for direct next-kernel reuse.
pub const HYBRID_STATE_ITEM_COUNT: usize =
    PRODUCT_LIMB_COUNT + FIELD_DIGIT_COUNT + PRODUCT_LIMB_COUNT + LINEAR_LIMB_COUNT;
/// Four script-authored powers used by the first response kernel. They add
/// zero witness/hint items and raise that kernel's local stack peak by four.
/// The five-power byte optimum reaches the consensus stack ceiling exactly;
/// this profile deliberately spends 37 bytes to retain one item of headroom.
pub const HYBRID_FIRST_SHARED_POWER_BITS: [usize; 4] = [23, 24, 25, 26];
/// Sixteen script-authored powers used by every later response/challenge
/// kernel. A persistent phase keeps these items on alt between callbacks;
/// they are not witness hints but must count toward the 1,000-item peak.
pub const HYBRID_LATER_SHARED_POWER_BITS: [usize; 16] = [
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
];
pub const HYBRID_FIRST_SHARED_POWER_ITEM_COUNT: usize = HYBRID_FIRST_SHARED_POWER_BITS.len();
pub const HYBRID_LATER_SHARED_POWER_ITEM_COUNT: usize = HYBRID_LATER_SHARED_POWER_BITS.len();
/// A packed next u/lambda pair and selected a/b limbs below one expanded
/// previous state. All 133 items are circuit data; there are zero hint items.
pub const HYBRID_CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT: usize = 2
    * u5_packed::PACKED_WORD_COUNT
    + PRODUCT_LIMB_COUNT
    + LINEAR_LIMB_COUNT
    + HYBRID_STATE_ITEM_COUNT;
/// Final-transition hybrid boundary when u_next arrives as an already
/// certified canonical biased radix-32 vector rather than eight packed words.
pub const HYBRID_CHAINED_U5_DERIVED_COMPLETE_INPUT_ITEM_COUNT: usize = FIELD_DIGIT_COUNT
    + u5_packed::PACKED_WORD_COUNT
    + PRODUCT_LIMB_COUNT
    + LINEAR_LIMB_COUNT
    + HYBRID_STATE_ITEM_COUNT;

/// Hostile-input quotient bounds covering both the legacy generic curve
/// square and the symmetric hybrid square.
///
/// The wider symmetric interval still has a unique signed 23-bit carrier.
/// Its reverse carry is at most 63,966,197 in magnitude and the largest
/// verifier arithmetic value is 2,046,918,304, leaving 100,565,343 below the
/// four-byte ScriptNum limit.
pub const CURVE_QUOTIENT_MIN: i32 = -3_404_320;
pub const CURVE_QUOTIENT_MAX: i32 = 3_631_275;
/// The first-transition continuity quotient needs a signed 22-bit carrier.
/// Its audited absolute bound is 1,843,466; its largest verifier arithmetic
/// value is 1,615,479,104 when the selected b limbs may be sign-routed.
pub const FIRST_CONTINUITY_QUOTIENT_ABS_MAX: i32 = 1_843_466;
/// A chained-transition continuity quotient needs a signed 23-bit carrier.
/// Its audited absolute bound is 3,686,931; its largest verifier arithmetic
/// value is 2,122,579,552 (24,904,095 below `i32::MAX`).
pub const CHAINED_CONTINUITY_QUOTIENT_ABS_MAX: i32 = 3_686_931;

/// Correlation-free absolute bounds for h0 through h4 covering both curve
/// accumulator representations. The generic square controls h0/h4; the
/// symmetric hybrid square controls h1..h3. Every bound remains a 31-bit
/// magnitude, so the derived-q23 reducer has exactly its prior byte shape.
pub const CURVE_LOW_COEFFICIENT_ABS_MAX: [i64; 5] = [
    1_824_710_186,
    1_982_956_800,
    1_982_956_800,
    1_982_956_800,
    1_669_331_248,
];
/// Exact h0-through-h4 bounds for the symmetric hybrid square orientation.
pub const SYMMETRIC_CURVE_LOW_COEFFICIENT_ABS_MAX: [i64; 5] = [
    1_819_568_938,
    1_982_956_800,
    1_982_956_800,
    1_982_956_800,
    1_664_190_000,
];
/// Exact h0-through-h4 bounds for the first continuity relation. The first
/// four coefficients are below 2^30; h4 needs the full 31-bit reducer path.
pub const FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX: [i64; 5] = [
    784_888_384,
    783_805_984,
    783_805_984,
    783_805_984,
    1_590_195_040,
];
/// Exact h0-through-h4 bounds for a chained continuity relation.
pub const CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX: [i64; 5] = [
    1_568_694_368,
    1_567_611_968,
    1_567_611_968,
    1_567_611_968,
    2_072_011_424,
];

const MONTGOMERY_A: i32 = 486_662;

/// Low-to-high direct limbs for a coordinate used in a slope product.
pub type ProductLimbs = [i32; PRODUCT_LIMB_COUNT];
/// Low-to-high direct limbs for a coordinate used only as a sparse term.
pub type LinearLimbs = [i32; LINEAR_LIMB_COUNT];

/// Exact direct-limb representative emitted by the authenticated fixed table.
///
/// `product` is the Montgomery u/a coordinate. `linear` is the v/b
/// coordinate. A negative selected point is represented by negating every
/// `linear` limb literally; that representation is generally different from
/// regrouping the canonical field residue `p-v`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectCoordinateLimbs {
    pub product: ProductLimbs,
    pub linear: LinearLimbs,
}

impl DirectCoordinateLimbs {
    /// Convert two canonical field values into their direct table limbs.
    pub fn from_canonical(product: &BigUint, linear: &BigUint) -> Self {
        check_inputs(&[product, linear]);
        Self {
            product: grouped_limbs(product, Grouping::SlopeMixed)
                .try_into()
                .expect("slope product grouping has 16 limbs"),
            linear: grouped_limbs(linear, Grouping::SlopeLinear)
                .try_into()
                .expect("slope linear grouping has nine limbs"),
        }
    }

    /// Match sign routing's literal per-limb `OP_NEGATE` on v/b.
    pub fn literal_negative(mut self) -> Self {
        self.linear = self
            .linear
            .map(|limb| limb.checked_neg().expect("direct limb is not i32::MIN"));
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlopeHints {
    /// Quotient for `lambda_i^2-u_prev-a_i-u_i-A=0`.
    pub curve: i32,
    /// Quotient for the first or chained continuity relation.
    pub continuity: i32,
}

/// Host-only audit of one exact relation consumed by a derived-quotient
/// verifier. The carry extrema cover the 50 radix-32 carries in the complete
/// relation, including both endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlopeRelationHostAudit {
    pub quotient: i32,
    pub reverse_carry_min: i64,
    pub reverse_carry_max: i64,
}

/// Host-only audit of the two exact relations in one slope transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlopeTransitionHostAudit {
    pub curve: SlopeRelationHostAudit,
    pub continuity: SlopeRelationHostAudit,
}

impl SlopeTransitionHostAudit {
    pub const fn hints(self) -> SlopeHints {
        SlopeHints {
            curve: self.curve.quotient,
            continuity: self.continuity.quotient,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Block {
    UNextPacked,
    LambdaNextPacked,
    ASelectedLimbs,
    BSelectedLimbs,
    QContinuity,
    QCurve,
    UInitialLimbs,
    VInitialLimbs,
    UPrevPacked,
    LambdaPrevPacked,
    APrevLimbs,
    BPrevLimbs,
    UNextDigits,
    LambdaNextDigits,
    LambdaSquareLimbs,
    UNextLimbs,
    UPrevDigits,
    UPrevLimbs,
    LambdaPrevDigits,
    DifferenceLimbs,
    Accumulator,
}

#[derive(Clone, Debug)]
struct Layout {
    blocks: Vec<(Block, usize)>,
}

impl Layout {
    fn first() -> Self {
        Self {
            blocks: vec![
                (Block::UNextPacked, u5_packed::PACKED_WORD_COUNT),
                (Block::LambdaNextPacked, u5_packed::PACKED_WORD_COUNT),
                (Block::ASelectedLimbs, PRODUCT_LIMB_COUNT),
                (Block::BSelectedLimbs, LINEAR_LIMB_COUNT),
                (Block::QContinuity, 1),
                (Block::QCurve, 1),
                (Block::VInitialLimbs, LINEAR_LIMB_COUNT),
                (Block::UInitialLimbs, PRODUCT_LIMB_COUNT),
            ],
        }
    }

    fn first_derived() -> Self {
        Self {
            blocks: vec![
                (Block::UNextPacked, u5_packed::PACKED_WORD_COUNT),
                (Block::LambdaNextPacked, u5_packed::PACKED_WORD_COUNT),
                (Block::ASelectedLimbs, PRODUCT_LIMB_COUNT),
                (Block::BSelectedLimbs, LINEAR_LIMB_COUNT),
                (Block::VInitialLimbs, LINEAR_LIMB_COUNT),
                (Block::UInitialLimbs, PRODUCT_LIMB_COUNT),
            ],
        }
    }

    fn chained() -> Self {
        Self {
            blocks: vec![
                (Block::UNextPacked, u5_packed::PACKED_WORD_COUNT),
                (Block::LambdaNextPacked, u5_packed::PACKED_WORD_COUNT),
                (Block::ASelectedLimbs, PRODUCT_LIMB_COUNT),
                (Block::BSelectedLimbs, LINEAR_LIMB_COUNT),
                (Block::QContinuity, 1),
                (Block::QCurve, 1),
                (Block::BPrevLimbs, LINEAR_LIMB_COUNT),
                (Block::APrevLimbs, PRODUCT_LIMB_COUNT),
                (Block::LambdaPrevPacked, u5_packed::PACKED_WORD_COUNT),
                (Block::UPrevPacked, u5_packed::PACKED_WORD_COUNT),
            ],
        }
    }

    fn chained_derived() -> Self {
        Self {
            blocks: vec![
                (Block::UNextPacked, u5_packed::PACKED_WORD_COUNT),
                (Block::LambdaNextPacked, u5_packed::PACKED_WORD_COUNT),
                (Block::ASelectedLimbs, PRODUCT_LIMB_COUNT),
                (Block::BSelectedLimbs, LINEAR_LIMB_COUNT),
                (Block::BPrevLimbs, LINEAR_LIMB_COUNT),
                (Block::APrevLimbs, PRODUCT_LIMB_COUNT),
                (Block::LambdaPrevPacked, u5_packed::PACKED_WORD_COUNT),
                (Block::UPrevPacked, u5_packed::PACKED_WORD_COUNT),
            ],
        }
    }

    fn chained_hybrid_derived() -> Self {
        Self {
            blocks: vec![
                (Block::UNextPacked, u5_packed::PACKED_WORD_COUNT),
                (Block::LambdaNextPacked, u5_packed::PACKED_WORD_COUNT),
                (Block::ASelectedLimbs, PRODUCT_LIMB_COUNT),
                (Block::BSelectedLimbs, LINEAR_LIMB_COUNT),
                (Block::BPrevLimbs, LINEAR_LIMB_COUNT),
                (Block::APrevLimbs, PRODUCT_LIMB_COUNT),
                (Block::LambdaPrevDigits, FIELD_DIGIT_COUNT),
                (Block::UPrevLimbs, PRODUCT_LIMB_COUNT),
            ],
        }
    }

    fn chained_hybrid_u5_derived() -> Self {
        Self {
            blocks: vec![
                (Block::UNextDigits, FIELD_DIGIT_COUNT),
                (Block::LambdaNextPacked, u5_packed::PACKED_WORD_COUNT),
                (Block::ASelectedLimbs, PRODUCT_LIMB_COUNT),
                (Block::BSelectedLimbs, LINEAR_LIMB_COUNT),
                (Block::BPrevLimbs, LINEAR_LIMB_COUNT),
                (Block::APrevLimbs, PRODUCT_LIMB_COUNT),
                (Block::LambdaPrevDigits, FIELD_DIGIT_COUNT),
                (Block::UPrevLimbs, PRODUCT_LIMB_COUNT),
            ],
        }
    }

    fn items(&self) -> usize {
        self.blocks.iter().map(|(_, items)| *items).sum()
    }

    fn move_to_top(&mut self, block: Block) -> Script {
        let index = self
            .blocks
            .iter()
            .position(|(candidate, _)| *candidate == block)
            .expect("scheduled block must be live");
        let block_items = self.blocks[index].1;
        let items_above = self.blocks[index + 1..]
            .iter()
            .map(|(_, items)| *items)
            .sum();
        let script = move_block_to_top(block_items, items_above);
        let entry = self.blocks.remove(index);
        self.blocks.push(entry);
        script
    }

    fn replace_top(&mut self, expected: Block, replacements: &[(Block, usize)]) {
        let removed = self.blocks.pop().expect("layout must not be empty");
        assert_eq!(removed.0, expected, "unexpected layout top");
        self.blocks.extend_from_slice(replacements);
    }

    fn push(&mut self, block: Block, items: usize) {
        self.blocks.push((block, items));
    }

    fn drop(&mut self, block: Block) -> Script {
        let moved = self.move_to_top(block);
        let (_, items) = self.blocks.pop().expect("moved block remains live");
        script! {
            { moved }
            for _ in 0..items / 2 { OP_2DROP }
            if items % 2 != 0 { OP_DROP }
        }
    }

    fn assert_top(&self, expected: &[(Block, usize)]) {
        assert!(self.blocks.ends_with(expected), "unexpected layout suffix");
    }
}

fn duplicate_top_field_digits() -> Script {
    script! {
        // Copy digit 50 first. Each prior copy increases the next original
        // digit's depth by one, so the selector stays constant.
        for _ in 0..FIELD_DIGIT_COUNT {
            { (FIELD_DIGIT_COUNT - 1) as u32 } OP_PICK
        }
    }
}

/// Add sparse grouped limbs to a 51-coefficient accumulator.
///
/// Input is `limbs[n-1..0] | h[50..0]`, where `n` is determined by
/// `grouping`. The limbs may be retained or consumed. This boundary requires
/// no hint items.
fn add_sparse_limbs_to_accumulator(
    grouping: Grouping,
    negative: bool,
    preserve_limbs: bool,
) -> Script {
    script! {
        for coefficient in 0..FIELD_DIGIT_COUNT {
            if let Some(limb_index) = (0..grouping.limb_count())
                .find(|limb| grouping.limb_start(*limb) == coefficient)
            {
                if preserve_limbs {
                    { (FIELD_DIGIT_COUNT - coefficient + limb_index) as u32 } OP_PICK
                } else {
                    { (FIELD_DIGIT_COUNT - coefficient) as u32 } OP_ROLL
                }
                if negative { OP_SUB } else { OP_ADD }
            }
            OP_TOALTSTACK
        }
        for _ in 0..ACCUMULATOR_COUNT { OP_FROMALTSTACK }
    }
}

fn add_sparse_constants_to_accumulator(
    grouping: Grouping,
    limbs: &[i32],
    negative: bool,
) -> Script {
    assert_eq!(limbs.len(), grouping.limb_count());
    script! {
        for coefficient in 0..FIELD_DIGIT_COUNT {
            if let Some(limb_index) = (0..grouping.limb_count())
                .find(|limb| grouping.limb_start(*limb) == coefficient)
            {
                { limbs[limb_index] }
                if negative { OP_SUB } else { OP_ADD }
            }
            OP_TOALTSTACK
        }
        for _ in 0..ACCUMULATOR_COUNT { OP_FROMALTSTACK }
    }
}

/// Copy `lhs-rhs` without consuming either centered limb vector.
fn copy_limb_difference() -> Script {
    script! {
        // Input is lhs[15..0] | rhs[15..0]. Emit high limbs first so limb
        // zero is nearest the top in the completed difference.
        for (copies, limb) in (0..PRODUCT_LIMB_COUNT).rev().enumerate() {
            { (PRODUCT_LIMB_COUNT + limb + copies) as u32 } OP_PICK
            { (limb + copies + 1) as u32 } OP_PICK
            OP_SUB
        }
    }
}

fn grouped_limbs(value: &BigUint, grouping: Grouping) -> Vec<i32> {
    let digits = arithmetic_digits(value);
    (0..grouping.limb_count())
        .map(|limb_index| {
            let start = grouping.limb_start(limb_index);
            (0..grouping.limb_digits(limb_index))
                .rev()
                .fold(0, |limb, digit| limb * 32 + digits[start + digit])
        })
        .collect()
}

fn limb_span(width: usize) -> i64 {
    (0..width).fold(0, |span, _| span * 32 + 1)
}

fn check_product_limbs(limbs: &ProductLimbs) {
    for (limb_index, limb) in limbs.iter().copied().enumerate() {
        let span = limb_span(Grouping::SlopeMixed.limb_digits(limb_index));
        assert!(
            (-16 * span..=15 * span).contains(&i64::from(limb)),
            "direct product limb exceeds its certified centered range"
        );
    }
}

fn check_canonical_linear_limbs(limbs: &LinearLimbs) {
    for (limb_index, limb) in limbs.iter().copied().enumerate() {
        let span = limb_span(Grouping::SlopeLinear.limb_digits(limb_index));
        assert!(
            (-16 * span..=15 * span).contains(&i64::from(limb)),
            "direct canonical linear limb exceeds its centered range"
        );
    }
}

fn check_sign_routed_linear_limbs(limbs: &LinearLimbs) {
    for (limb_index, limb) in limbs.iter().copied().enumerate() {
        let span = limb_span(Grouping::SlopeLinear.limb_digits(limb_index));
        assert!(
            (-16 * span..=16 * span).contains(&i64::from(limb)),
            "direct sign-routed linear limb exceeds its audited range"
        );
    }
}

fn check_direct_coordinate(coordinate: &DirectCoordinateLimbs, sign_routed: bool) {
    check_product_limbs(&coordinate.product);
    if sign_routed {
        check_sign_routed_linear_limbs(&coordinate.linear);
    } else {
        check_canonical_linear_limbs(&coordinate.linear);
    }
}

fn add_sparse_limbs_host(
    accumulator: &mut [i64; FIELD_DIGIT_COUNT],
    limbs: &[i32],
    sign: i64,
    grouping: Grouping,
) {
    assert_eq!(limbs.len(), grouping.limb_count());
    for (limb_index, limb) in limbs.iter().copied().enumerate() {
        accumulator[grouping.limb_start(limb_index)] += sign * i64::from(limb);
    }
}

fn add_folded_limb_product_host(
    accumulator: &mut [i64; FIELD_DIGIT_COUNT],
    lhs_limbs: &ProductLimbs,
    rhs_digits: &[i32; FIELD_DIGIT_COUNT],
    sign: i64,
) {
    for (limb_index, lhs) in lhs_limbs.iter().copied().enumerate() {
        let lhs_offset = Grouping::SlopeMixed.limb_start(limb_index);
        for (rhs_index, rhs) in rhs_digits.iter().copied().enumerate() {
            let coefficient = lhs_offset + rhs_index;
            let (folded, scale) = if coefficient < FIELD_DIGIT_COUNT {
                (coefficient, 1i64)
            } else {
                (coefficient - FIELD_DIGIT_COUNT, 19)
            };
            accumulator[folded] += sign * scale * i64::from(lhs) * i64::from(rhs);
        }
    }
}

// Match `initialize_streamed_grouped_four_square_preserving_rhs` exactly.
// Each grouped-four limb owns its within-block square and its products with
// later rhs blocks; only the latter are doubled. This coefficient vector can
// differ from the generic limb-by-all-digits square, but their reconstructed
// integers are congruent modulo p.
fn add_symmetric_folded_square_host(
    accumulator: &mut [i64; FIELD_DIGIT_COUNT],
    digits: &[i32; FIELD_DIGIT_COUNT],
) {
    for limb_index in 0..Grouping::Four.limb_count() {
        let start = Grouping::Four.limb_start(limb_index);
        let width = Grouping::Four.limb_digits(limb_index);
        let limb = (0..width).rev().fold(0i64, |limb, digit| {
            limb * 32 + i64::from(digits[start + digit])
        });
        for rhs_index in start..FIELD_DIGIT_COUNT {
            let coefficient = start + rhs_index;
            let (folded, scale) = if coefficient < FIELD_DIGIT_COUNT {
                (coefficient, 1i64)
            } else {
                (coefficient - FIELD_DIGIT_COUNT, 19)
            };
            let symmetry = if rhs_index < start + width { 1 } else { 2 };
            accumulator[folded] += symmetry * scale * limb * i64::from(digits[rhs_index]);
        }
    }
}

fn limb_difference(lhs: &ProductLimbs, rhs: &ProductLimbs) -> ProductLimbs {
    std::array::from_fn(|index| {
        lhs[index]
            .checked_sub(rhs[index])
            .expect("audited direct-limb difference fits i32")
    })
}

fn push_literal_limb_items(items: &mut Vec<Vec<u8>>, limbs: &[i32]) {
    items.extend(limbs.iter().rev().copied().map(scriptnum_item));
}

fn scriptnum_item(value: i32) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value));
    bytes[..length].to_vec()
}

fn check_inputs(values: &[&BigUint]) {
    let p = modulus();
    assert!(
        values.iter().all(|value| *value < &p),
        "Montgomery coordinates must be canonical field values"
    );
}

fn relation_host_audit(coefficients: &[i64; FIELD_DIGIT_COUNT]) -> SlopeRelationHostAudit {
    const RADIX: i64 = 32;

    let quotient = exact_quotient(coefficients);
    let quotient = i64::from(quotient);
    let low_numerator = coefficients[0] + 19 * quotient;
    assert_eq!(low_numerator.rem_euclid(RADIX), 0);
    let mut carry = low_numerator / RADIX;
    let mut carry_min = carry;
    let mut carry_max = carry;
    let mut forward_carries = Vec::with_capacity(FIELD_DIGIT_COUNT - 1);
    forward_carries.push(carry);
    for coefficient in coefficients.iter().take(FIELD_DIGIT_COUNT - 1).skip(1) {
        let numerator = coefficient + carry;
        assert_eq!(numerator.rem_euclid(RADIX), 0);
        carry = numerator / RADIX;
        carry_min = carry_min.min(carry);
        carry_max = carry_max.max(carry);
        forward_carries.push(carry);
    }
    assert_eq!(
        coefficients[FIELD_DIGIT_COUNT - 1] + carry,
        RADIX * quotient
    );
    assert_eq!(forward_carries.len(), FIELD_DIGIT_COUNT - 1);

    // This is the recurrence used by the Script verifier after deriving q:
    // recover c49 from 32q-h50, then recover c48..c0 top-down. Comparing it
    // with the forward normalization makes the per-relation audit independent
    // of the BigInt divisibility assertion in `exact_quotient`.
    let mut reverse_carry = RADIX * quotient - coefficients[FIELD_DIGIT_COUNT - 1];
    assert_eq!(reverse_carry, forward_carries[FIELD_DIGIT_COUNT - 2]);
    for coefficient_index in (1..FIELD_DIGIT_COUNT - 1).rev() {
        reverse_carry = RADIX * reverse_carry - coefficients[coefficient_index];
        assert_eq!(reverse_carry, forward_carries[coefficient_index - 1]);
    }
    assert_eq!(RADIX * reverse_carry, coefficients[0] + 19 * quotient);

    SlopeRelationHostAudit {
        quotient: i32::try_from(quotient).expect("audited quotient fits i32"),
        reverse_carry_min: carry_min,
        reverse_carry_max: carry_max,
    }
}

/// Host quotients for the top/first transition.
pub fn first_transition_hints(
    u_initial: &BigUint,
    v_initial: &BigUint,
    u_next: &BigUint,
    lambda_next: &BigUint,
    a_selected: &BigUint,
    b_selected: &BigUint,
) -> SlopeHints {
    let initial = DirectCoordinateLimbs::from_canonical(u_initial, v_initial);
    let selected = DirectCoordinateLimbs::from_canonical(a_selected, b_selected);
    first_transition_hints_from_direct_limbs(&initial, u_next, lambda_next, &selected)
}

/// Host quotients from the exact direct limbs supplied to the first verifier.
///
/// Unlike [`first_transition_hints`], this preserves a table branch's literal
/// sign-routed b representative instead of regrouping its canonical residue.
pub fn first_transition_hints_from_direct_limbs(
    initial: &DirectCoordinateLimbs,
    u_next: &BigUint,
    lambda_next: &BigUint,
    selected: &DirectCoordinateLimbs,
) -> SlopeHints {
    first_transition_host_audit_from_direct_limbs(initial, u_next, lambda_next, selected).hints()
}

/// Host audit of both derived quotient relations for the first verifier.
///
/// This performs the exact polynomial divisibility check and independently
/// checks the complete forward and reverse radix-32 carry recurrences.
pub fn first_transition_host_audit_from_direct_limbs(
    initial: &DirectCoordinateLimbs,
    u_next: &BigUint,
    lambda_next: &BigUint,
    selected: &DirectCoordinateLimbs,
) -> SlopeTransitionHostAudit {
    first_transition_host_audit_from_direct_limbs_with_square(
        initial,
        u_next,
        lambda_next,
        selected,
        false,
    )
}

/// Host audit matching the symmetric square coefficient orientation used by
/// [`verify_first_transition_derived_hybrid_state`].
pub fn first_transition_hybrid_host_audit_from_direct_limbs(
    initial: &DirectCoordinateLimbs,
    u_next: &BigUint,
    lambda_next: &BigUint,
    selected: &DirectCoordinateLimbs,
) -> SlopeTransitionHostAudit {
    first_transition_host_audit_from_direct_limbs_with_square(
        initial,
        u_next,
        lambda_next,
        selected,
        true,
    )
}

fn first_transition_host_audit_from_direct_limbs_with_square(
    initial: &DirectCoordinateLimbs,
    u_next: &BigUint,
    lambda_next: &BigUint,
    selected: &DirectCoordinateLimbs,
    symmetric_square: bool,
) -> SlopeTransitionHostAudit {
    check_inputs(&[u_next, lambda_next]);
    check_direct_coordinate(initial, false);
    check_direct_coordinate(selected, true);
    let lambda = arithmetic_digits(lambda_next);
    let u_next_limbs: ProductLimbs = grouped_limbs(u_next, Grouping::SlopeMixed)
        .try_into()
        .expect("slope product grouping has 16 limbs");
    let montgomery_a_limbs =
        grouped_limbs(&BigUint::from(MONTGOMERY_A as u32), Grouping::SlopeLinear);
    let mut curve = [0i64; FIELD_DIGIT_COUNT];
    if symmetric_square {
        add_symmetric_folded_square_host(&mut curve, &lambda);
    } else {
        add_folded_product(&mut curve, &lambda, &lambda, 1, Grouping::Four);
    }
    for limbs in [&initial.product, &selected.product, &u_next_limbs] {
        add_sparse_limbs_host(&mut curve, limbs, -1, Grouping::SlopeMixed);
    }
    add_sparse_limbs_host(&mut curve, &montgomery_a_limbs, -1, Grouping::SlopeLinear);

    let mut continuity = [0i64; FIELD_DIGIT_COUNT];
    add_folded_limb_product_host(
        &mut continuity,
        &limb_difference(&selected.product, &initial.product),
        &lambda,
        1,
    );
    add_sparse_limbs_host(&mut continuity, &selected.linear, -1, Grouping::SlopeLinear);
    add_sparse_limbs_host(&mut continuity, &initial.linear, 1, Grouping::SlopeLinear);
    let audit = SlopeTransitionHostAudit {
        curve: relation_host_audit(&curve),
        continuity: relation_host_audit(&continuity),
    };
    assert!((CURVE_QUOTIENT_MIN..=CURVE_QUOTIENT_MAX).contains(&audit.curve.quotient));
    assert!(audit.continuity.quotient.abs() <= FIRST_CONTINUITY_QUOTIENT_ABS_MAX);
    audit
}

/// Host quotients for one chained transition.
pub fn chained_transition_hints(
    u_prev: &BigUint,
    lambda_prev: &BigUint,
    a_prev: &BigUint,
    b_prev: &BigUint,
    u_next: &BigUint,
    lambda_next: &BigUint,
    a_selected: &BigUint,
    b_selected: &BigUint,
) -> SlopeHints {
    let previous = DirectCoordinateLimbs::from_canonical(a_prev, b_prev);
    let selected = DirectCoordinateLimbs::from_canonical(a_selected, b_selected);
    chained_transition_hints_from_direct_limbs(
        u_prev,
        lambda_prev,
        &previous,
        u_next,
        lambda_next,
        &selected,
    )
}

/// Host quotients from the exact direct limbs supplied to a chained verifier.
///
/// Both b vectors may be literal per-limb negatives retained from authenticated
/// sign-routing branches.
pub fn chained_transition_hints_from_direct_limbs(
    u_prev: &BigUint,
    lambda_prev: &BigUint,
    previous: &DirectCoordinateLimbs,
    u_next: &BigUint,
    lambda_next: &BigUint,
    selected: &DirectCoordinateLimbs,
) -> SlopeHints {
    chained_transition_host_audit_from_direct_limbs(
        u_prev,
        lambda_prev,
        previous,
        u_next,
        lambda_next,
        selected,
    )
    .hints()
}

/// Host audit of both derived quotient relations for a chained verifier.
///
/// Both b vectors may be literal per-limb negatives retained from authenticated
/// sign-routing branches.
pub fn chained_transition_host_audit_from_direct_limbs(
    u_prev: &BigUint,
    lambda_prev: &BigUint,
    previous: &DirectCoordinateLimbs,
    u_next: &BigUint,
    lambda_next: &BigUint,
    selected: &DirectCoordinateLimbs,
) -> SlopeTransitionHostAudit {
    chained_transition_host_audit_from_direct_limbs_with_square(
        u_prev,
        lambda_prev,
        previous,
        u_next,
        lambda_next,
        selected,
        false,
    )
}

/// Host audit matching the symmetric square coefficient orientation used by
/// [`verify_chained_transition_derived_hybrid_state`].
pub fn chained_transition_hybrid_host_audit_from_direct_limbs(
    u_prev: &BigUint,
    lambda_prev: &BigUint,
    previous: &DirectCoordinateLimbs,
    u_next: &BigUint,
    lambda_next: &BigUint,
    selected: &DirectCoordinateLimbs,
) -> SlopeTransitionHostAudit {
    chained_transition_host_audit_from_direct_limbs_with_square(
        u_prev,
        lambda_prev,
        previous,
        u_next,
        lambda_next,
        selected,
        true,
    )
}

fn chained_transition_host_audit_from_direct_limbs_with_square(
    u_prev: &BigUint,
    lambda_prev: &BigUint,
    previous: &DirectCoordinateLimbs,
    u_next: &BigUint,
    lambda_next: &BigUint,
    selected: &DirectCoordinateLimbs,
    symmetric_square: bool,
) -> SlopeTransitionHostAudit {
    check_inputs(&[u_prev, lambda_prev, u_next, lambda_next]);
    check_direct_coordinate(previous, true);
    check_direct_coordinate(selected, true);
    let lambda = arithmetic_digits(lambda_next);
    let lambda_prev = arithmetic_digits(lambda_prev);
    let u_prev_limbs: ProductLimbs = grouped_limbs(u_prev, Grouping::SlopeMixed)
        .try_into()
        .expect("slope product grouping has 16 limbs");
    let u_next_limbs: ProductLimbs = grouped_limbs(u_next, Grouping::SlopeMixed)
        .try_into()
        .expect("slope product grouping has 16 limbs");
    let montgomery_a_limbs =
        grouped_limbs(&BigUint::from(MONTGOMERY_A as u32), Grouping::SlopeLinear);
    let mut curve = [0i64; FIELD_DIGIT_COUNT];
    if symmetric_square {
        add_symmetric_folded_square_host(&mut curve, &lambda);
    } else {
        add_folded_product(&mut curve, &lambda, &lambda, 1, Grouping::Four);
    }
    for limbs in [&u_prev_limbs, &selected.product, &u_next_limbs] {
        add_sparse_limbs_host(&mut curve, limbs, -1, Grouping::SlopeMixed);
    }
    add_sparse_limbs_host(&mut curve, &montgomery_a_limbs, -1, Grouping::SlopeLinear);

    let mut continuity = [0i64; FIELD_DIGIT_COUNT];
    for (difference, slope) in [
        (limb_difference(&selected.product, &u_prev_limbs), &lambda),
        (
            limb_difference(&previous.product, &u_prev_limbs),
            &lambda_prev,
        ),
    ] {
        add_folded_limb_product_host(&mut continuity, &difference, slope, 1);
    }
    add_sparse_limbs_host(&mut continuity, &selected.linear, -1, Grouping::SlopeLinear);
    add_sparse_limbs_host(&mut continuity, &previous.linear, -1, Grouping::SlopeLinear);
    let audit = SlopeTransitionHostAudit {
        curve: relation_host_audit(&curve),
        continuity: relation_host_audit(&continuity),
    };
    assert!((CURVE_QUOTIENT_MIN..=CURVE_QUOTIENT_MAX).contains(&audit.curve.quotient));
    assert!(audit.continuity.quotient.abs() <= CHAINED_CONTINUITY_QUOTIENT_ABS_MAX);
    audit
}

fn decode_preserving(
    layout: &mut Layout,
    packed: Block,
    digits: Block,
    preserved_items: u32,
    steps: &mut Vec<Script>,
) {
    steps.push(layout.move_to_top(packed));
    let below = usize::try_from(preserved_items).expect("u32 fits usize") + layout.items()
        - u5_packed::PACKED_WORD_COUNT;
    steps.push(u5_packed::decode_fast_preserving(
        u32::try_from(below).expect("decoder preserved count fits u32"),
    ));
    layout.replace_top(
        packed,
        &[
            (packed, u5_packed::PACKED_WORD_COUNT),
            (digits, FIELD_DIGIT_COUNT),
        ],
    );
}

fn decode_consuming(
    layout: &mut Layout,
    packed: Block,
    digits: Block,
    preserved_items: u32,
    steps: &mut Vec<Script>,
) {
    steps.push(layout.move_to_top(packed));
    let below = usize::try_from(preserved_items).expect("u32 fits usize") + layout.items()
        - u5_packed::PACKED_WORD_COUNT;
    steps.push(u5_packed::decode_fast(
        u32::try_from(below).expect("decoder preserved count fits u32"),
    ));
    layout.replace_top(packed, &[(digits, FIELD_DIGIT_COUNT)]);
}

fn convert_top_digits_to_limbs(layout: &mut Layout, digits: Block, limbs: Block) -> Script {
    let script = centered_digits_to_limbs(Grouping::SlopeMixed, true);
    layout.replace_top(digits, &[(limbs, PRODUCT_LIMB_COUNT)]);
    script
}

fn add_limb_block(
    layout: &mut Layout,
    limb_block: Block,
    accumulator: Block,
    grouping: Grouping,
    negative: bool,
    preserve: bool,
    steps: &mut Vec<Script>,
) {
    steps.push(layout.move_to_top(limb_block));
    steps.push(layout.move_to_top(accumulator));
    layout.assert_top(&[
        (limb_block, grouping.limb_count()),
        (accumulator, ACCUMULATOR_COUNT),
    ]);
    steps.push(add_sparse_limbs_to_accumulator(
        grouping, negative, preserve,
    ));
    if !preserve {
        layout.blocks.remove(layout.blocks.len() - 2);
    }
}

fn build_curve_relation(
    layout: &mut Layout,
    preserved_items: u32,
    quotient_multiplier: Option<StreamedRelationQuotientMultiplier>,
    steps: &mut Vec<Script>,
) {
    decode_preserving(
        layout,
        Block::LambdaNextPacked,
        Block::LambdaNextDigits,
        preserved_items,
        steps,
    );
    steps.push(duplicate_top_field_digits());
    layout.push(Block::LambdaNextDigits, FIELD_DIGIT_COUNT);
    steps.push(centered_digits_to_limbs(Grouping::Four, true));
    layout.replace_top(
        Block::LambdaNextDigits,
        &[(Block::LambdaSquareLimbs, Grouping::Four.limb_count())],
    );
    steps.push(layout.move_to_top(Block::LambdaNextDigits));
    steps.push(layout.move_to_top(Block::LambdaSquareLimbs));
    // Put the 51-digit rhs back above the compact lhs.
    steps.push(move_block_to_top(
        FIELD_DIGIT_COUNT,
        Grouping::Four.limb_count(),
    ));
    let rhs = layout.blocks.remove(layout.blocks.len() - 2);
    layout.blocks.push(rhs);
    steps.push(push_relation_accumulator());
    layout.push(Block::Accumulator, ACCUMULATOR_COUNT);
    layout.assert_top(&[
        (Block::LambdaSquareLimbs, Grouping::Four.limb_count()),
        (Block::LambdaNextDigits, FIELD_DIGIT_COUNT),
        (Block::Accumulator, ACCUMULATOR_COUNT),
    ]);
    steps.push(accumulate_streamed_limb_product_preserving_rhs(true, false));
    layout.blocks.remove(layout.blocks.len() - 3);
    steps.push(layout.drop(Block::LambdaNextDigits));

    if layout
        .blocks
        .iter()
        .any(|(block, _)| *block == Block::UInitialLimbs)
    {
        add_limb_block(
            layout,
            Block::UInitialLimbs,
            Block::Accumulator,
            Grouping::SlopeMixed,
            true,
            true,
            steps,
        );
    } else {
        decode_preserving(
            layout,
            Block::UPrevPacked,
            Block::UPrevDigits,
            preserved_items,
            steps,
        );
        steps.push(convert_top_digits_to_limbs(
            layout,
            Block::UPrevDigits,
            Block::UPrevLimbs,
        ));
        steps.push(layout.drop(Block::UPrevPacked));
        add_limb_block(
            layout,
            Block::UPrevLimbs,
            Block::Accumulator,
            Grouping::SlopeMixed,
            true,
            true,
            steps,
        );
    }
    add_limb_block(
        layout,
        Block::ASelectedLimbs,
        Block::Accumulator,
        Grouping::SlopeMixed,
        true,
        true,
        steps,
    );
    decode_preserving(
        layout,
        Block::UNextPacked,
        Block::UNextDigits,
        preserved_items,
        steps,
    );
    steps.push(convert_top_digits_to_limbs(
        layout,
        Block::UNextDigits,
        Block::UNextLimbs,
    ));
    add_limb_block(
        layout,
        Block::UNextLimbs,
        Block::Accumulator,
        Grouping::SlopeMixed,
        true,
        false,
        steps,
    );
    let a_limbs = grouped_limbs(&BigUint::from(MONTGOMERY_A as u32), Grouping::SlopeLinear);
    steps.push(layout.move_to_top(Block::Accumulator));
    steps.push(add_sparse_constants_to_accumulator(
        Grouping::SlopeLinear,
        &a_limbs,
        true,
    ));
    if let Some(multiplier) = quotient_multiplier {
        layout.assert_top(&[(Block::Accumulator, ACCUMULATOR_COUNT)]);
        steps.push(verify_streamed_relation_derived_with_multiplier(
            23,
            &CURVE_LOW_COEFFICIENT_ABS_MAX,
            multiplier,
        ));
        layout.blocks.pop();
    } else {
        steps.push(layout.move_to_top(Block::QCurve));
        steps.push(layout.move_to_top(Block::Accumulator));
        layout.assert_top(&[(Block::QCurve, 1), (Block::Accumulator, ACCUMULATOR_COUNT)]);
        steps.push(verify_streamed_relation(false));
        layout.blocks.truncate(layout.blocks.len() - 2);
    }
}

fn initialize_continuity(layout: &mut Layout, derive_quotient: bool, steps: &mut Vec<Script>) {
    steps.push(push_relation_accumulator());
    layout.push(Block::Accumulator, ACCUMULATOR_COUNT);
    if !derive_quotient {
        steps.push(layout.move_to_top(Block::QContinuity));
        steps.push(layout.move_to_top(Block::Accumulator));
        layout.assert_top(&[
            (Block::QContinuity, 1),
            (Block::Accumulator, ACCUMULATOR_COUNT),
        ]);
        steps.push(absorb_relation_quotient());
        layout.blocks.remove(layout.blocks.len() - 2);
    }
}

fn add_difference_product(
    layout: &mut Layout,
    lhs: Block,
    rhs: Block,
    slope_packed: Block,
    slope_digits: Block,
    preserve_slope: bool,
    preserved_items: u32,
    steps: &mut Vec<Script>,
) {
    steps.push(layout.move_to_top(lhs));
    steps.push(layout.move_to_top(rhs));
    steps.push(copy_limb_difference());
    layout.push(Block::DifferenceLimbs, PRODUCT_LIMB_COUNT);
    if preserve_slope {
        decode_preserving(layout, slope_packed, slope_digits, preserved_items, steps);
    } else {
        decode_consuming(layout, slope_packed, slope_digits, preserved_items, steps);
    }
    steps.push(layout.move_to_top(Block::DifferenceLimbs));
    steps.push(layout.move_to_top(slope_digits));
    steps.push(layout.move_to_top(Block::Accumulator));
    layout.assert_top(&[
        (Block::DifferenceLimbs, PRODUCT_LIMB_COUNT),
        (slope_digits, FIELD_DIGIT_COUNT),
        (Block::Accumulator, ACCUMULATOR_COUNT),
    ]);
    steps.push(accumulate_streamed_limb_product_grouping(
        Grouping::SlopeMixed,
        false,
        false,
    ));
    layout.blocks.truncate(layout.blocks.len() - 3);
    layout.push(Block::Accumulator, ACCUMULATOR_COUNT);
}

// Add `(lhs-rhs)*slope` when slope is already a canonical biased 51-digit
// vector. The difference limbs are temporary; `preserve_slope` controls
// whether the decoded slope remains available to the following relation.
fn add_difference_product_from_digits(
    layout: &mut Layout,
    lhs: Block,
    rhs: Block,
    slope_digits: Block,
    preserve_slope: bool,
    steps: &mut Vec<Script>,
) {
    steps.push(layout.move_to_top(lhs));
    steps.push(layout.move_to_top(rhs));
    steps.push(copy_limb_difference());
    layout.push(Block::DifferenceLimbs, PRODUCT_LIMB_COUNT);
    steps.push(layout.move_to_top(Block::DifferenceLimbs));
    steps.push(layout.move_to_top(slope_digits));
    steps.push(layout.move_to_top(Block::Accumulator));
    layout.assert_top(&[
        (Block::DifferenceLimbs, PRODUCT_LIMB_COUNT),
        (slope_digits, FIELD_DIGIT_COUNT),
        (Block::Accumulator, ACCUMULATOR_COUNT),
    ]);
    steps.push(accumulate_streamed_limb_product_grouping(
        Grouping::SlopeMixed,
        false,
        preserve_slope,
    ));
    if preserve_slope {
        layout.blocks.remove(layout.blocks.len() - 3);
    } else {
        layout.blocks.truncate(layout.blocks.len() - 3);
        layout.push(Block::Accumulator, ACCUMULATOR_COUNT);
    }
}

fn retain_outputs(layout: &mut Layout, steps: &mut Vec<Script>) {
    for block in [
        Block::UInitialLimbs,
        Block::VInitialLimbs,
        Block::UPrevLimbs,
        Block::UPrevPacked,
        Block::LambdaPrevPacked,
        Block::APrevLimbs,
        Block::BPrevLimbs,
    ] {
        if layout
            .blocks
            .iter()
            .any(|(candidate, _)| *candidate == block)
        {
            steps.push(layout.drop(block));
        }
    }
    for block in [
        Block::UNextPacked,
        Block::LambdaNextPacked,
        Block::ASelectedLimbs,
        Block::BSelectedLimbs,
    ] {
        steps.push(layout.move_to_top(block));
    }
    layout.assert_top(&[
        (Block::UNextPacked, u5_packed::PACKED_WORD_COUNT),
        (Block::LambdaNextPacked, u5_packed::PACKED_WORD_COUNT),
        (Block::ASelectedLimbs, PRODUCT_LIMB_COUNT),
        (Block::BSelectedLimbs, LINEAR_LIMB_COUNT),
    ]);
}

fn policy_precompile_steps(steps: Vec<Script>, name: &'static str) -> Script {
    let mut result = Script::new(name);
    for step in steps {
        let compiled = step.compile_with_policy();
        // The centralized policy returns raw bytecode whenever its input is
        // larger than the cutoff. This assertion therefore also proves that
        // no optimizer pass was attempted on a >32 KiB semantic step.
        assert!(compiled.len() <= MAX_OPTIMIZER_INPUT_BYTES);
        result = result.push_script(compiled);
    }
    result
}

/// Verify the top/first Montgomery transition.
///
/// Input is `u_i_packed | lambda_i_packed | a_i_limbs | b_i_limbs |
/// q_continuity | q_curve | v_0_limbs | u_0_limbs`. Packed fields have eight
/// items, each `a`/`u` product field has 16 limbs, and each `b`/`v` linear
/// field has nine limbs. Exactly two of the 68 input items are auxiliary
/// quotient hints. The fragment returns the 41-item chained state
/// `u_i_packed | lambda_i_packed | a_i_limbs | b_i_limbs` and appends no
/// terminal predicate. The four direct limb vectors must already be certified
/// by the two-field initializer or authenticated fixed-table selection.
fn verify_first_transition_inner(
    preserved_items: u32,
    quotient_multiplier: Option<StreamedRelationQuotientMultiplier>,
) -> Script {
    let derive_quotients = quotient_multiplier.is_some();
    let mut layout = if derive_quotients {
        Layout::first_derived()
    } else {
        Layout::first()
    };
    assert_eq!(
        layout.items(),
        if derive_quotients {
            FIRST_DERIVED_COMPLETE_INPUT_ITEM_COUNT
        } else {
            FIRST_COMPLETE_INPUT_ITEM_COUNT
        }
    );
    let mut steps = Vec::new();
    build_curve_relation(
        &mut layout,
        preserved_items,
        quotient_multiplier,
        &mut steps,
    );
    initialize_continuity(&mut layout, derive_quotients, &mut steps);
    add_limb_block(
        &mut layout,
        Block::BSelectedLimbs,
        Block::Accumulator,
        Grouping::SlopeLinear,
        true,
        true,
        &mut steps,
    );
    add_limb_block(
        &mut layout,
        Block::VInitialLimbs,
        Block::Accumulator,
        Grouping::SlopeLinear,
        false,
        false,
        &mut steps,
    );
    add_difference_product(
        &mut layout,
        Block::ASelectedLimbs,
        Block::UInitialLimbs,
        Block::LambdaNextPacked,
        Block::LambdaNextDigits,
        true,
        preserved_items,
        &mut steps,
    );
    if let Some(multiplier) = quotient_multiplier {
        steps.push(verify_streamed_relation_derived_with_multiplier(
            22,
            &FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
            multiplier,
        ));
    } else {
        steps.push(verify_streamed_relation_absorbed());
    }
    layout.replace_top(Block::Accumulator, &[]);
    retain_outputs(&mut layout, &mut steps);
    policy_precompile_steps(
        steps,
        if derive_quotients {
            "policy-precompiled no-hint first Montgomery slope transition"
        } else {
            "policy-precompiled first Montgomery slope transition"
        },
    )
}

pub fn verify_first_transition(preserved_items: u32) -> Script {
    verify_first_transition_inner(preserved_items, None)
}

/// Verify the first Montgomery transition while deriving both exact relation
/// quotients from the completed accumulators. Its 66 local inputs are all
/// claimed data; it requires exactly zero auxiliary witness hint items and
/// returns the same 41-item chained state as [`verify_first_transition`].
pub fn verify_first_transition_derived(preserved_items: u32) -> Script {
    verify_first_transition_inner(
        preserved_items,
        Some(StreamedRelationQuotientMultiplier::Mixed233x196Plus5x29),
    )
}

/// Legacy width-two-NAF version of [`verify_first_transition_derived`].
/// Retained only to reproduce already-published G29/q-free byte metrics; new
/// constructions should use the smaller default derived transition.
pub fn verify_first_transition_derived_legacy_naf(preserved_items: u32) -> Script {
    verify_first_transition_inner(
        preserved_items,
        Some(StreamedRelationQuotientMultiplier::LegacyNaf),
    )
}

/// Verify a chained Montgomery transition.
///
/// Input is `u_i_packed | lambda_i_packed | a_i_limbs | b_i_limbs |
/// q_continuity | q_curve | b_prev_limbs | a_prev_limbs |
/// lambda_prev_packed | u_prev_packed`. Packed fields have eight items, each
/// `a`/`u` product field has 16 limbs, and each `b` linear field has nine
/// limbs. Exactly two of the 84 inputs are auxiliary quotient hints. It
/// returns the same 41-item state as [`verify_first_transition`]. The selected
/// direct limbs must come from an authenticated table and the previous direct
/// limbs from a successfully verified predecessor; this fragment does not
/// range-check either vector itself.
fn verify_chained_transition_inner(
    preserved_items: u32,
    quotient_multiplier: Option<StreamedRelationQuotientMultiplier>,
) -> Script {
    let derive_quotients = quotient_multiplier.is_some();
    let mut layout = if derive_quotients {
        Layout::chained_derived()
    } else {
        Layout::chained()
    };
    assert_eq!(
        layout.items(),
        if derive_quotients {
            CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT
        } else {
            CHAINED_COMPLETE_INPUT_ITEM_COUNT
        }
    );
    let mut steps = Vec::new();
    build_curve_relation(
        &mut layout,
        preserved_items,
        quotient_multiplier,
        &mut steps,
    );
    initialize_continuity(&mut layout, derive_quotients, &mut steps);
    add_limb_block(
        &mut layout,
        Block::BSelectedLimbs,
        Block::Accumulator,
        Grouping::SlopeLinear,
        true,
        true,
        &mut steps,
    );
    add_limb_block(
        &mut layout,
        Block::BPrevLimbs,
        Block::Accumulator,
        Grouping::SlopeLinear,
        true,
        false,
        &mut steps,
    );
    add_difference_product(
        &mut layout,
        Block::ASelectedLimbs,
        Block::UPrevLimbs,
        Block::LambdaNextPacked,
        Block::LambdaNextDigits,
        true,
        preserved_items,
        &mut steps,
    );
    add_difference_product(
        &mut layout,
        Block::APrevLimbs,
        Block::UPrevLimbs,
        Block::LambdaPrevPacked,
        Block::LambdaPrevDigits,
        false,
        preserved_items,
        &mut steps,
    );
    if let Some(multiplier) = quotient_multiplier {
        steps.push(verify_streamed_relation_derived_with_multiplier(
            23,
            &CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
            multiplier,
        ));
    } else {
        steps.push(verify_streamed_relation_absorbed());
    }
    layout.replace_top(Block::Accumulator, &[]);
    retain_outputs(&mut layout, &mut steps);
    policy_precompile_steps(
        steps,
        if derive_quotients {
            "policy-precompiled no-hint chained Montgomery slope transition"
        } else {
            "policy-precompiled chained Montgomery slope transition"
        },
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HybridSharedPowerPoolMode {
    Disabled,
    EphemeralFirst,
    EphemeralLater,
    InitializePersistentLater,
    PersistentLater,
    FinalizePersistentLater,
}

fn push_hybrid_derived_relation(
    steps: &mut Vec<Script>,
    signed_width: usize,
    low_coefficient_abs_max: &[i64; 5],
    mode: HybridSharedPowerPoolMode,
    relation_index: usize,
) {
    assert!(relation_index < 2);
    match mode {
        HybridSharedPowerPoolMode::Disabled => {
            steps.push(verify_streamed_relation_derived_with_multiplier(
                signed_width,
                low_coefficient_abs_max,
                StreamedRelationQuotientMultiplier::Mixed233x196Plus5x29,
            ));
        }
        HybridSharedPowerPoolMode::EphemeralFirst
        | HybridSharedPowerPoolMode::EphemeralLater
        | HybridSharedPowerPoolMode::InitializePersistentLater
        | HybridSharedPowerPoolMode::PersistentLater
        | HybridSharedPowerPoolMode::FinalizePersistentLater => {
            let shared_bits = if mode == HybridSharedPowerPoolMode::EphemeralFirst {
                HYBRID_FIRST_SHARED_POWER_BITS.as_slice()
            } else {
                HYBRID_LATER_SHARED_POWER_BITS.as_slice()
            };
            let boundary = match (mode, relation_index) {
                (HybridSharedPowerPoolMode::EphemeralFirst, 0)
                | (HybridSharedPowerPoolMode::EphemeralLater, 0) => {
                    SharedPowerPoolRelationBoundary::PushAndPark
                }
                (HybridSharedPowerPoolMode::EphemeralFirst, 1)
                | (HybridSharedPowerPoolMode::EphemeralLater, 1) => {
                    SharedPowerPoolRelationBoundary::RestoreAndDrop
                }
                (HybridSharedPowerPoolMode::InitializePersistentLater, 0) => {
                    SharedPowerPoolRelationBoundary::PushAndPark
                }
                (HybridSharedPowerPoolMode::InitializePersistentLater, 1)
                | (HybridSharedPowerPoolMode::PersistentLater, _)
                | (HybridSharedPowerPoolMode::FinalizePersistentLater, 0) => {
                    SharedPowerPoolRelationBoundary::RestoreAndPark
                }
                (HybridSharedPowerPoolMode::FinalizePersistentLater, 1) => {
                    SharedPowerPoolRelationBoundary::RestoreAndDrop
                }
                _ => unreachable!("all relation indices were bounded above"),
            };
            steps.push(
                verify_streamed_relation_derived_with_multiplier_shared_power_pool(
                    signed_width,
                    low_coefficient_abs_max,
                    StreamedRelationQuotientMultiplier::Mixed233x196Plus5x29,
                    shared_bits,
                    boundary,
                ),
            );
        }
    }
}

// Close continuity before the curve relation. The previous-lambda product is
// consumed before lambda_next is decoded, so the two 51-digit slope vectors
// never coexist. Old b/lambda/a state is discarded as soon as its last use;
// only u_prev survives into the curve relation.
fn build_hybrid_chained_continuity(
    layout: &mut Layout,
    preserved_items: u32,
    shared_power_pool_mode: HybridSharedPowerPoolMode,
    steps: &mut Vec<Script>,
) {
    initialize_continuity(layout, true, steps);
    add_limb_block(
        layout,
        Block::BSelectedLimbs,
        Block::Accumulator,
        Grouping::SlopeLinear,
        true,
        true,
        steps,
    );
    add_limb_block(
        layout,
        Block::BPrevLimbs,
        Block::Accumulator,
        Grouping::SlopeLinear,
        true,
        false,
        steps,
    );
    add_difference_product_from_digits(
        layout,
        Block::APrevLimbs,
        Block::UPrevLimbs,
        Block::LambdaPrevDigits,
        false,
        steps,
    );
    steps.push(layout.drop(Block::APrevLimbs));

    decode_consuming(
        layout,
        Block::LambdaNextPacked,
        Block::LambdaNextDigits,
        preserved_items,
        steps,
    );
    add_difference_product_from_digits(
        layout,
        Block::ASelectedLimbs,
        Block::UPrevLimbs,
        Block::LambdaNextDigits,
        true,
        steps,
    );
    push_hybrid_derived_relation(
        steps,
        23,
        &CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
        shared_power_pool_mode,
        0,
    );
    layout.replace_top(Block::Accumulator, &[]);
}

fn build_hybrid_curve(
    layout: &mut Layout,
    previous_u_limbs: Block,
    preserved_items: u32,
    shared_power_pool_mode: HybridSharedPowerPoolMode,
    steps: &mut Vec<Script>,
) {
    // Retain the decoder's canonical biased lambda digits as next state. The
    // symmetric square builds each grouped-four limb just in time from those
    // original digits, keeps own-block products once, and doubles only later
    // cross-block products. This avoids both a 51-item duplicate and the
    // mirrored half of the generic limb-by-digit updates.
    steps.push(layout.move_to_top(Block::LambdaNextDigits));
    steps.push(initialize_streamed_grouped_four_square_preserving_rhs());
    layout.push(Block::Accumulator, ACCUMULATOR_COUNT);
    layout.assert_top(&[
        (Block::LambdaNextDigits, FIELD_DIGIT_COUNT),
        (Block::Accumulator, ACCUMULATOR_COUNT),
    ]);

    add_limb_block(
        layout,
        previous_u_limbs,
        Block::Accumulator,
        Grouping::SlopeMixed,
        true,
        false,
        steps,
    );
    add_limb_block(
        layout,
        Block::ASelectedLimbs,
        Block::Accumulator,
        Grouping::SlopeMixed,
        true,
        true,
        steps,
    );
    if layout
        .blocks
        .iter()
        .any(|(block, _)| *block == Block::UNextPacked)
    {
        decode_consuming(
            layout,
            Block::UNextPacked,
            Block::UNextDigits,
            preserved_items,
            steps,
        );
    } else {
        // The final-R boundary already certified this canonical biased u5
        // vector, so only route it to the conversion point.
        steps.push(layout.move_to_top(Block::UNextDigits));
    }
    steps.push(convert_top_digits_to_limbs(
        layout,
        Block::UNextDigits,
        Block::UNextLimbs,
    ));
    add_limb_block(
        layout,
        Block::UNextLimbs,
        Block::Accumulator,
        Grouping::SlopeMixed,
        true,
        true,
        steps,
    );
    let a_limbs = grouped_limbs(&BigUint::from(MONTGOMERY_A as u32), Grouping::SlopeLinear);
    steps.push(layout.move_to_top(Block::Accumulator));
    steps.push(add_sparse_constants_to_accumulator(
        Grouping::SlopeLinear,
        &a_limbs,
        true,
    ));
    push_hybrid_derived_relation(
        steps,
        23,
        &SYMMETRIC_CURVE_LOW_COEFFICIENT_ABS_MAX,
        shared_power_pool_mode,
        1,
    );
    layout.replace_top(Block::Accumulator, &[]);
}

// First-transition counterpart of the chained continuity-first schedule. It
// consumes v_initial before decoding lambda_next, then retains the one decoded
// biased lambda vector for both the selected product and the curve square.
fn build_hybrid_first_continuity(
    layout: &mut Layout,
    preserved_items: u32,
    shared_power_pool_mode: HybridSharedPowerPoolMode,
    steps: &mut Vec<Script>,
) {
    initialize_continuity(layout, true, steps);
    add_limb_block(
        layout,
        Block::BSelectedLimbs,
        Block::Accumulator,
        Grouping::SlopeLinear,
        true,
        true,
        steps,
    );
    add_limb_block(
        layout,
        Block::VInitialLimbs,
        Block::Accumulator,
        Grouping::SlopeLinear,
        false,
        false,
        steps,
    );
    decode_consuming(
        layout,
        Block::LambdaNextPacked,
        Block::LambdaNextDigits,
        preserved_items,
        steps,
    );
    add_difference_product_from_digits(
        layout,
        Block::ASelectedLimbs,
        Block::UInitialLimbs,
        Block::LambdaNextDigits,
        true,
        steps,
    );
    push_hybrid_derived_relation(
        steps,
        22,
        &FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
        shared_power_pool_mode,
        0,
    );
    layout.replace_top(Block::Accumulator, &[]);
}

fn retain_hybrid_outputs(layout: &mut Layout, steps: &mut Vec<Script>) {
    for block in [
        Block::BSelectedLimbs,
        Block::ASelectedLimbs,
        Block::LambdaNextDigits,
        Block::UNextLimbs,
    ] {
        steps.push(layout.move_to_top(block));
    }
    layout.assert_top(&[
        (Block::BSelectedLimbs, LINEAR_LIMB_COUNT),
        (Block::ASelectedLimbs, PRODUCT_LIMB_COUNT),
        (Block::LambdaNextDigits, FIELD_DIGIT_COUNT),
        (Block::UNextLimbs, PRODUCT_LIMB_COUNT),
    ]);
    assert_eq!(layout.items(), HYBRID_STATE_ITEM_COUNT);
}

/// Experimental zero-hint chained transition with a 92-item expanded state.
///
/// Input, bottom to top, is `u_next_packed[8] | lambda_next_packed[8] |
/// a_selected_limbs[16] | b_selected_limbs[9] | b_prev_limbs[9] |
/// a_prev_limbs[16] | lambda_prev_biased_digits[51] | u_prev_limbs[16]`.
/// Output is `b_selected_limbs[9] | a_selected_limbs[16] |
/// lambda_next_biased_digits[51] | u_next_limbs[16]`. The packed next fields are
/// decoded exactly once; lambda_next's certified biased digits are reused by
/// continuity and the curve relation. All 133 local input items are circuit
/// data and the auxiliary witness-hint count is exactly zero.
fn verify_chained_transition_derived_hybrid_state_inner(
    preserved_items: u32,
    shared_power_pool_mode: HybridSharedPowerPoolMode,
) -> Script {
    let mut layout = Layout::chained_hybrid_derived();
    assert_eq!(
        layout.items(),
        HYBRID_CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT
    );
    let mut steps = Vec::new();
    build_hybrid_chained_continuity(
        &mut layout,
        preserved_items,
        shared_power_pool_mode,
        &mut steps,
    );
    build_hybrid_curve(
        &mut layout,
        Block::UPrevLimbs,
        preserved_items,
        shared_power_pool_mode,
        &mut steps,
    );
    retain_hybrid_outputs(&mut layout, &mut steps);
    policy_precompile_steps(
        steps,
        "policy-precompiled hybrid-state no-hint chained Montgomery slope transition",
    )
}

pub fn verify_chained_transition_derived_hybrid_state(preserved_items: u32) -> Script {
    verify_chained_transition_derived_hybrid_state_inner(
        preserved_items,
        HybridSharedPowerPoolMode::Disabled,
    )
}

/// Chained hybrid transition with a local 16-item script-authored power pool.
/// The pool is created and consumed within this invocation, so the exact
/// auxiliary hint-item and witness-item increments are both zero. Its live
/// entries are included in its measured 224-item local combined peak.
pub fn verify_chained_transition_derived_hybrid_state_shared_power_pool(
    preserved_items: u32,
) -> Script {
    verify_chained_transition_derived_hybrid_state_inner(
        preserved_items,
        HybridSharedPowerPoolMode::EphemeralLater,
    )
}

/// Chained hybrid transition using the 16 powers already parked on alt. It
/// restores/re-parks the pool around each relation and leaves all 16 entries
/// parked for the next callback. Its local combined peak is 240 items; the
/// exact hint/witness increment is zero.
pub fn verify_chained_transition_derived_hybrid_state_persistent_shared_power_pool(
    preserved_items: u32,
) -> Script {
    verify_chained_transition_derived_hybrid_state_inner(
        preserved_items,
        HybridSharedPowerPoolMode::PersistentLater,
    )
}

/// First transition of a persistent later-kernel phase. It constructs the
/// 16-item pool inside relation one and leaves it parked after relation two,
/// avoiding a separate setup fragment. The exact hint/witness increment is
/// zero, its measured local combined peak is 224 items, and the 16 authored
/// items remain live across following callbacks.
pub fn verify_chained_transition_derived_hybrid_state_initialize_persistent_shared_power_pool(
    preserved_items: u32,
) -> Script {
    verify_chained_transition_derived_hybrid_state_inner(
        preserved_items,
        HybridSharedPowerPoolMode::InitializePersistentLater,
    )
}

/// Last transition of a persistent later-kernel phase. It consumes the pool
/// inside relation two and therefore guarantees that the alt stack has no
/// pool residue at the following hash/phase boundary. It adds zero hints and
/// zero witness items; its measured local combined peak is 240 items.
pub fn verify_chained_transition_derived_hybrid_state_finalize_persistent_shared_power_pool(
    preserved_items: u32,
) -> Script {
    verify_chained_transition_derived_hybrid_state_inner(
        preserved_items,
        HybridSharedPowerPoolMode::FinalizePersistentLater,
    )
}

/// Final-transition form of
/// [`verify_chained_transition_derived_hybrid_state`] for an already
/// certified u_next biased-u5 vector.
///
/// Input replaces the bottom eight `u_next_packed` words with 51 canonical
/// biased digits, for 176 circuit-data items total and exactly zero auxiliary
/// hints. The caller must bind and range/canonicality-certify those digits;
/// this fragment consumes them into the retained 16 grouped u limbs. Its
/// 92-item output remains `b9 | a16 | lambda_biased51 | u16`.
pub fn verify_chained_transition_derived_hybrid_state_certified_u_next_u5(
    preserved_items: u32,
) -> Script {
    verify_chained_transition_derived_hybrid_state_certified_u_next_u5_inner(
        preserved_items,
        true,
        HybridSharedPowerPoolMode::Disabled,
    )
}

fn verify_chained_transition_derived_hybrid_state_certified_u_next_u5_inner(
    preserved_items: u32,
    retain_output: bool,
    shared_power_pool_mode: HybridSharedPowerPoolMode,
) -> Script {
    let mut layout = Layout::chained_hybrid_u5_derived();
    assert_eq!(
        layout.items(),
        HYBRID_CHAINED_U5_DERIVED_COMPLETE_INPUT_ITEM_COUNT
    );
    let mut steps = Vec::new();
    build_hybrid_chained_continuity(
        &mut layout,
        preserved_items,
        shared_power_pool_mode,
        &mut steps,
    );
    build_hybrid_curve(
        &mut layout,
        Block::UPrevLimbs,
        preserved_items,
        shared_power_pool_mode,
        &mut steps,
    );
    if retain_output {
        retain_hybrid_outputs(&mut layout, &mut steps);
    } else {
        assert_eq!(layout.items(), HYBRID_STATE_ITEM_COUNT);
        steps.push(script! {
            for _ in 0..HYBRID_STATE_ITEM_COUNT / 2 { OP_2DROP }
            if HYBRID_STATE_ITEM_COUNT % 2 != 0 { OP_DROP }
            OP_1
        });
        layout.blocks.clear();
    }
    policy_precompile_steps(
        steps,
        if retain_output {
            "policy-precompiled certified-u5 final hybrid Montgomery slope transition"
        } else {
            "policy-precompiled terminal certified-u5 hybrid Montgomery slope transition"
        },
    )
}

/// Terminal-specific certified-u5 hybrid transition. It verifies the same two
/// relations as
/// [`verify_chained_transition_derived_hybrid_state_certified_u_next_u5`],
/// then consumes all 92 authenticated next-state items because no successor
/// transition needs them. Input is 176 circuit-data items and output is one
/// clean truthy item. The auxiliary hint count is exactly zero.
pub fn verify_chained_transition_derived_hybrid_state_certified_u_next_u5_terminal(
    preserved_items: u32,
) -> Script {
    verify_chained_transition_derived_hybrid_state_certified_u_next_u5_inner(
        preserved_items,
        false,
        HybridSharedPowerPoolMode::Disabled,
    )
}

/// Terminal certified-u5 transition using a persistent 16-item shared-power
/// pool. It returns one truthy main-stack item and leaves the pool parked on
/// alt for [`finalize_hybrid_persistent_shared_power_pool`] to consume. There
/// are exactly zero auxiliary hint items and zero added witness items.
pub fn verify_chained_transition_derived_hybrid_state_certified_u_next_u5_terminal_persistent_shared_power_pool(
    preserved_items: u32,
) -> Script {
    verify_chained_transition_derived_hybrid_state_certified_u_next_u5_inner(
        preserved_items,
        false,
        HybridSharedPowerPoolMode::PersistentLater,
    )
}

/// Terminal persistent-pool variant that restores the pool for relation one,
/// consumes it inside relation two, and returns a clean single truth item with
/// no pool residue on alt. Its auxiliary hint and added witness counts are
/// exactly zero and its measured local combined peak is 283 items.
pub fn verify_chained_transition_derived_hybrid_state_certified_u_next_u5_terminal_finalize_persistent_shared_power_pool(
    preserved_items: u32,
) -> Script {
    verify_chained_transition_derived_hybrid_state_certified_u_next_u5_inner(
        preserved_items,
        false,
        HybridSharedPowerPoolMode::FinalizePersistentLater,
    )
}

/// Experimental zero-hint first transition that directly produces the
/// 92-item expanded state consumed by
/// [`verify_chained_transition_derived_hybrid_state`]. Its physical 66-item
/// input is identical to [`verify_first_transition_derived`]:
/// `u_next_packed[8] | lambda_next_packed[8] | a_selected_limbs[16] |
/// b_selected_limbs[9] | v_initial_limbs[9] | u_initial_limbs[16]`.
/// Output is `b_selected_limbs[9] | a_selected_limbs[16] |
/// lambda_next_biased_digits[51] | u_next_limbs[16]`. There are exactly zero
/// auxiliary witness-hint items.
fn verify_first_transition_derived_hybrid_state_inner(
    preserved_items: u32,
    shared_power_pool_mode: HybridSharedPowerPoolMode,
) -> Script {
    let mut layout = Layout::first_derived();
    assert_eq!(layout.items(), FIRST_DERIVED_COMPLETE_INPUT_ITEM_COUNT);
    let mut steps = Vec::new();
    build_hybrid_first_continuity(
        &mut layout,
        preserved_items,
        shared_power_pool_mode,
        &mut steps,
    );
    build_hybrid_curve(
        &mut layout,
        Block::UInitialLimbs,
        preserved_items,
        shared_power_pool_mode,
        &mut steps,
    );
    retain_hybrid_outputs(&mut layout, &mut steps);
    policy_precompile_steps(
        steps,
        "policy-precompiled hybrid-state no-hint first Montgomery slope transition",
    )
}

pub fn verify_first_transition_derived_hybrid_state(preserved_items: u32) -> Script {
    verify_first_transition_derived_hybrid_state_inner(
        preserved_items,
        HybridSharedPowerPoolMode::Disabled,
    )
}

/// First hybrid transition with an invocation-local four-power pool. These
/// constants are script-authored, add exactly zero hint/witness items, and
/// increase the measured local combined stack peak from 208 to 212 items.
pub fn verify_first_transition_derived_hybrid_state_shared_power_pool(
    preserved_items: u32,
) -> Script {
    verify_first_transition_derived_hybrid_state_inner(
        preserved_items,
        HybridSharedPowerPoolMode::EphemeralFirst,
    )
}

/// Construct and park the 16-item later-kernel power pool. The returned
/// fragment adds no witness/hint items; callers must count the 16 authored
/// constants in every combined main-plus-alt peak until finalization.
pub fn initialize_hybrid_persistent_shared_power_pool() -> Script {
    let fragment = script! {
        { push_streamed_relation_shared_power_pool(&HYBRID_LATER_SHARED_POWER_BITS) }
        { park_streamed_relation_shared_power_pool(HYBRID_LATER_SHARED_POWER_ITEM_COUNT) }
    };
    Script::new("policy-precompiled initialize persistent hybrid shared-power pool")
        .push_script(fragment.compile_with_policy())
}

/// Restore and consume the 16-item persistent power pool. This works with an
/// arbitrary main-stack suffix (including the terminal truth item), provided
/// the pool is the complete alt-stack suffix at this phase boundary.
pub fn finalize_hybrid_persistent_shared_power_pool() -> Script {
    let fragment = script! {
        { restore_streamed_relation_shared_power_pool(HYBRID_LATER_SHARED_POWER_ITEM_COUNT) }
        { drop_streamed_relation_shared_power_pool(HYBRID_LATER_SHARED_POWER_ITEM_COUNT) }
    };
    Script::new("policy-precompiled finalize persistent hybrid shared-power pool")
        .push_script(fragment.compile_with_policy())
}

pub fn verify_chained_transition(preserved_items: u32) -> Script {
    verify_chained_transition_inner(preserved_items, None)
}

/// Verify a chained Montgomery transition with zero quotient hint items.
/// Both exact signed-23 quotients are recovered from h0 through h4 of their
/// respective accumulators. The 82 local inputs are claimed data only.
pub fn verify_chained_transition_derived(preserved_items: u32) -> Script {
    verify_chained_transition_inner(
        preserved_items,
        Some(StreamedRelationQuotientMultiplier::Mixed233x196Plus5x29),
    )
}

/// Legacy width-two-NAF version of [`verify_chained_transition_derived`].
/// Retained only to reproduce already-published G29/q-free byte metrics; new
/// constructions should use the smaller default derived transition.
pub fn verify_chained_transition_derived_legacy_naf(preserved_items: u32) -> Script {
    verify_chained_transition_inner(
        preserved_items,
        Some(StreamedRelationQuotientMultiplier::LegacyNaf),
    )
}

/// Host data for [`verify_first_transition`]. All items coexist at fragment
/// entry; exactly two items are hints.
pub fn first_transition_witness_items(
    u_initial: &BigUint,
    v_initial: &BigUint,
    u_next: &BigUint,
    lambda_next: &BigUint,
    a_selected: &BigUint,
    b_selected: &BigUint,
    hints: SlopeHints,
) -> Vec<Vec<u8>> {
    let initial = DirectCoordinateLimbs::from_canonical(u_initial, v_initial);
    let selected = DirectCoordinateLimbs::from_canonical(a_selected, b_selected);
    first_transition_witness_items_from_direct_limbs(
        &initial,
        u_next,
        lambda_next,
        &selected,
        hints,
    )
}

/// Host data retaining the exact literal direct limbs used for hint creation.
pub fn first_transition_witness_items_from_direct_limbs(
    initial: &DirectCoordinateLimbs,
    u_next: &BigUint,
    lambda_next: &BigUint,
    selected: &DirectCoordinateLimbs,
    hints: SlopeHints,
) -> Vec<Vec<u8>> {
    check_inputs(&[u_next, lambda_next]);
    check_direct_coordinate(initial, false);
    check_direct_coordinate(selected, true);
    assert!((CURVE_QUOTIENT_MIN..=CURVE_QUOTIENT_MAX).contains(&hints.curve));
    assert!(hints.continuity.abs() <= FIRST_CONTINUITY_QUOTIENT_ABS_MAX);
    let mut items = Vec::with_capacity(FIRST_COMPLETE_INPUT_ITEM_COUNT);
    for value in [u_next, lambda_next] {
        items.extend(u5_packed::packed_value_witness_items(value));
    }
    push_literal_limb_items(&mut items, &selected.product);
    push_literal_limb_items(&mut items, &selected.linear);
    items.push(scriptnum_item(hints.continuity));
    items.push(scriptnum_item(hints.curve));
    push_literal_limb_items(&mut items, &initial.linear);
    push_literal_limb_items(&mut items, &initial.product);
    assert_eq!(items.len(), FIRST_COMPLETE_INPUT_ITEM_COUNT);
    items
}

/// Claimed data for [`verify_first_transition_derived`]. All 66 items coexist
/// at entry and none is an auxiliary hint.
pub fn first_transition_derived_witness_items(
    u_initial: &BigUint,
    v_initial: &BigUint,
    u_next: &BigUint,
    lambda_next: &BigUint,
    a_selected: &BigUint,
    b_selected: &BigUint,
) -> Vec<Vec<u8>> {
    let initial = DirectCoordinateLimbs::from_canonical(u_initial, v_initial);
    let selected = DirectCoordinateLimbs::from_canonical(a_selected, b_selected);
    first_transition_derived_witness_items_from_direct_limbs(
        &initial,
        u_next,
        lambda_next,
        &selected,
    )
}

/// No-hint first-transition data retaining literal table representatives.
pub fn first_transition_derived_witness_items_from_direct_limbs(
    initial: &DirectCoordinateLimbs,
    u_next: &BigUint,
    lambda_next: &BigUint,
    selected: &DirectCoordinateLimbs,
) -> Vec<Vec<u8>> {
    check_inputs(&[u_next, lambda_next]);
    check_direct_coordinate(initial, false);
    check_direct_coordinate(selected, true);
    let mut items = Vec::with_capacity(FIRST_DERIVED_COMPLETE_INPUT_ITEM_COUNT);
    for value in [u_next, lambda_next] {
        items.extend(u5_packed::packed_value_witness_items(value));
    }
    push_literal_limb_items(&mut items, &selected.product);
    push_literal_limb_items(&mut items, &selected.linear);
    push_literal_limb_items(&mut items, &initial.linear);
    push_literal_limb_items(&mut items, &initial.product);
    assert_eq!(items.len(), FIRST_DERIVED_COMPLETE_INPUT_ITEM_COUNT);
    items
}

/// Host data for [`verify_chained_transition`]. All items coexist at fragment
/// entry; exactly two items are hints.
pub fn chained_transition_witness_items(
    u_prev: &BigUint,
    lambda_prev: &BigUint,
    a_prev: &BigUint,
    b_prev: &BigUint,
    u_next: &BigUint,
    lambda_next: &BigUint,
    a_selected: &BigUint,
    b_selected: &BigUint,
    hints: SlopeHints,
) -> Vec<Vec<u8>> {
    let previous = DirectCoordinateLimbs::from_canonical(a_prev, b_prev);
    let selected = DirectCoordinateLimbs::from_canonical(a_selected, b_selected);
    chained_transition_witness_items_from_direct_limbs(
        u_prev,
        lambda_prev,
        &previous,
        u_next,
        lambda_next,
        &selected,
        hints,
    )
}

/// Host data retaining the previous and selected literal direct limbs.
pub fn chained_transition_witness_items_from_direct_limbs(
    u_prev: &BigUint,
    lambda_prev: &BigUint,
    previous: &DirectCoordinateLimbs,
    u_next: &BigUint,
    lambda_next: &BigUint,
    selected: &DirectCoordinateLimbs,
    hints: SlopeHints,
) -> Vec<Vec<u8>> {
    check_inputs(&[u_prev, lambda_prev, u_next, lambda_next]);
    check_direct_coordinate(previous, true);
    check_direct_coordinate(selected, true);
    assert!((CURVE_QUOTIENT_MIN..=CURVE_QUOTIENT_MAX).contains(&hints.curve));
    assert!(hints.continuity.abs() <= CHAINED_CONTINUITY_QUOTIENT_ABS_MAX);
    let mut items = Vec::with_capacity(CHAINED_COMPLETE_INPUT_ITEM_COUNT);
    for value in [u_next, lambda_next] {
        items.extend(u5_packed::packed_value_witness_items(value));
    }
    push_literal_limb_items(&mut items, &selected.product);
    push_literal_limb_items(&mut items, &selected.linear);
    items.push(scriptnum_item(hints.continuity));
    items.push(scriptnum_item(hints.curve));
    push_literal_limb_items(&mut items, &previous.linear);
    push_literal_limb_items(&mut items, &previous.product);
    for value in [lambda_prev, u_prev] {
        items.extend(u5_packed::packed_value_witness_items(value));
    }
    assert_eq!(items.len(), CHAINED_COMPLETE_INPUT_ITEM_COUNT);
    items
}

/// Claimed data for [`verify_chained_transition_derived`]. The complete local
/// boundary is 82 data items and exactly zero hint items.
#[allow(clippy::too_many_arguments)]
pub fn chained_transition_derived_witness_items(
    u_prev: &BigUint,
    lambda_prev: &BigUint,
    a_prev: &BigUint,
    b_prev: &BigUint,
    u_next: &BigUint,
    lambda_next: &BigUint,
    a_selected: &BigUint,
    b_selected: &BigUint,
) -> Vec<Vec<u8>> {
    let previous = DirectCoordinateLimbs::from_canonical(a_prev, b_prev);
    let selected = DirectCoordinateLimbs::from_canonical(a_selected, b_selected);
    chained_transition_derived_witness_items_from_direct_limbs(
        u_prev,
        lambda_prev,
        &previous,
        u_next,
        lambda_next,
        &selected,
    )
}

/// No-hint chained-transition data retaining literal table representatives.
pub fn chained_transition_derived_witness_items_from_direct_limbs(
    u_prev: &BigUint,
    lambda_prev: &BigUint,
    previous: &DirectCoordinateLimbs,
    u_next: &BigUint,
    lambda_next: &BigUint,
    selected: &DirectCoordinateLimbs,
) -> Vec<Vec<u8>> {
    check_inputs(&[u_prev, lambda_prev, u_next, lambda_next]);
    check_direct_coordinate(previous, true);
    check_direct_coordinate(selected, true);
    let mut items = Vec::with_capacity(CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT);
    for value in [u_next, lambda_next] {
        items.extend(u5_packed::packed_value_witness_items(value));
    }
    push_literal_limb_items(&mut items, &selected.product);
    push_literal_limb_items(&mut items, &selected.linear);
    push_literal_limb_items(&mut items, &previous.linear);
    push_literal_limb_items(&mut items, &previous.product);
    for value in [lambda_prev, u_prev] {
        items.extend(u5_packed::packed_value_witness_items(value));
    }
    assert_eq!(items.len(), CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT);
    items
}

/// Claimed data for [`verify_chained_transition_derived_hybrid_state`]. The
/// complete 133-item boundary contains exactly zero auxiliary hint items.
#[allow(clippy::too_many_arguments)]
pub fn chained_transition_derived_hybrid_witness_items(
    u_prev: &BigUint,
    lambda_prev: &BigUint,
    a_prev: &BigUint,
    b_prev: &BigUint,
    u_next: &BigUint,
    lambda_next: &BigUint,
    a_selected: &BigUint,
    b_selected: &BigUint,
) -> Vec<Vec<u8>> {
    let previous = DirectCoordinateLimbs::from_canonical(a_prev, b_prev);
    let selected = DirectCoordinateLimbs::from_canonical(a_selected, b_selected);
    chained_transition_derived_hybrid_witness_items_from_direct_limbs(
        u_prev,
        lambda_prev,
        &previous,
        u_next,
        lambda_next,
        &selected,
    )
}

/// Hybrid-state claimed data retaining literal sign-routed table limbs.
pub fn chained_transition_derived_hybrid_witness_items_from_direct_limbs(
    u_prev: &BigUint,
    lambda_prev: &BigUint,
    previous: &DirectCoordinateLimbs,
    u_next: &BigUint,
    lambda_next: &BigUint,
    selected: &DirectCoordinateLimbs,
) -> Vec<Vec<u8>> {
    check_inputs(&[u_prev, lambda_prev, u_next, lambda_next]);
    check_direct_coordinate(previous, true);
    check_direct_coordinate(selected, true);
    let mut items = Vec::with_capacity(HYBRID_CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT);
    for value in [u_next, lambda_next] {
        items.extend(u5_packed::packed_value_witness_items(value));
    }
    push_literal_limb_items(&mut items, &selected.product);
    push_literal_limb_items(&mut items, &selected.linear);
    push_literal_limb_items(&mut items, &previous.linear);
    push_literal_limb_items(&mut items, &previous.product);
    push_literal_limb_items(&mut items, &field_digits(lambda_prev));
    push_literal_limb_items(&mut items, &grouped_limbs(u_prev, Grouping::SlopeMixed));
    assert_eq!(
        items.len(),
        HYBRID_CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT
    );
    items
}

/// Claimed data for the certified-u5 final hybrid transition. The u_next
/// digits are circuit data supplied in canonical biased form, not hints.
#[allow(clippy::too_many_arguments)]
pub fn chained_transition_derived_hybrid_u5_witness_items(
    u_prev: &BigUint,
    lambda_prev: &BigUint,
    a_prev: &BigUint,
    b_prev: &BigUint,
    u_next: &BigUint,
    lambda_next: &BigUint,
    a_selected: &BigUint,
    b_selected: &BigUint,
) -> Vec<Vec<u8>> {
    let previous = DirectCoordinateLimbs::from_canonical(a_prev, b_prev);
    let selected = DirectCoordinateLimbs::from_canonical(a_selected, b_selected);
    chained_transition_derived_hybrid_u5_witness_items_from_direct_limbs(
        u_prev,
        lambda_prev,
        &previous,
        u_next,
        lambda_next,
        &selected,
    )
}

/// Certified-u5 final-hybrid data retaining literal table representatives.
pub fn chained_transition_derived_hybrid_u5_witness_items_from_direct_limbs(
    u_prev: &BigUint,
    lambda_prev: &BigUint,
    previous: &DirectCoordinateLimbs,
    u_next: &BigUint,
    lambda_next: &BigUint,
    selected: &DirectCoordinateLimbs,
) -> Vec<Vec<u8>> {
    check_inputs(&[u_prev, lambda_prev, u_next, lambda_next]);
    check_direct_coordinate(previous, true);
    check_direct_coordinate(selected, true);
    let mut items = Vec::with_capacity(HYBRID_CHAINED_U5_DERIVED_COMPLETE_INPUT_ITEM_COUNT);
    push_literal_limb_items(&mut items, &field_digits(u_next));
    items.extend(u5_packed::packed_value_witness_items(lambda_next));
    push_literal_limb_items(&mut items, &selected.product);
    push_literal_limb_items(&mut items, &selected.linear);
    push_literal_limb_items(&mut items, &previous.linear);
    push_literal_limb_items(&mut items, &previous.product);
    push_literal_limb_items(&mut items, &field_digits(lambda_prev));
    push_literal_limb_items(&mut items, &grouped_limbs(u_prev, Grouping::SlopeMixed));
    assert_eq!(
        items.len(),
        HYBRID_CHAINED_U5_DERIVED_COMPLETE_INPUT_ITEM_COUNT
    );
    items
}

/// The 92-item expanded state returned by the experimental hybrid verifier.
pub fn hybrid_output_state_items(
    u: &BigUint,
    lambda: &BigUint,
    a: &BigUint,
    b: &BigUint,
) -> Vec<Vec<u8>> {
    let direct = DirectCoordinateLimbs::from_canonical(a, b);
    hybrid_output_state_items_from_direct_limbs(u, lambda, &direct)
}

/// Expanded output preserving an exact literal selected-table representative.
pub fn hybrid_output_state_items_from_direct_limbs(
    u: &BigUint,
    lambda: &BigUint,
    direct: &DirectCoordinateLimbs,
) -> Vec<Vec<u8>> {
    check_inputs(&[u, lambda]);
    check_direct_coordinate(direct, true);
    let mut items = Vec::with_capacity(HYBRID_STATE_ITEM_COUNT);
    push_literal_limb_items(&mut items, &direct.linear);
    push_literal_limb_items(&mut items, &direct.product);
    push_literal_limb_items(&mut items, &field_digits(lambda));
    push_literal_limb_items(&mut items, &grouped_limbs(u, Grouping::SlopeMixed));
    assert_eq!(items.len(), HYBRID_STATE_ITEM_COUNT);
    items
}

/// The 41-item state returned by either verifier.
pub fn output_state_items(u: &BigUint, lambda: &BigUint, a: &BigUint, b: &BigUint) -> Vec<Vec<u8>> {
    let direct = DirectCoordinateLimbs::from_canonical(a, b);
    output_state_items_from_direct_limbs(u, lambda, &direct)
}

/// The verifier output using the exact direct-limb representative retained on
/// stack, including a literal sign-routed b vector.
pub fn output_state_items_from_direct_limbs(
    u: &BigUint,
    lambda: &BigUint,
    direct: &DirectCoordinateLimbs,
) -> Vec<Vec<u8>> {
    check_inputs(&[u, lambda]);
    check_direct_coordinate(direct, true);
    let mut items = Vec::with_capacity(OUTPUT_ITEM_COUNT);
    for value in [u, lambda] {
        items.extend(u5_packed::packed_value_witness_items(value));
    }
    push_literal_limb_items(&mut items, &direct.product);
    push_literal_limb_items(&mut items, &direct.linear);
    assert_eq!(items.len(), OUTPUT_ITEM_COUNT);
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_hint_accounting() {
        assert_eq!(FIRST_CLAIMED_DATA_ITEM_COUNT, 66);
        assert_eq!(FIRST_COMPLETE_INPUT_ITEM_COUNT, 68);
        assert_eq!(CHAINED_CLAIMED_DATA_ITEM_COUNT, 82);
        assert_eq!(CHAINED_COMPLETE_INPUT_ITEM_COUNT, 84);
        assert_eq!(FIRST_DERIVED_COMPLETE_INPUT_ITEM_COUNT, 66);
        assert_eq!(CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT, 82);
        assert_eq!(HINT_ITEM_COUNT, 2);
        assert_eq!(OUTPUT_ITEM_COUNT, 41);
        assert_eq!(HYBRID_STATE_ITEM_COUNT, 92);
        assert_eq!(HYBRID_CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT, 133);
        assert_eq!(HYBRID_CHAINED_U5_DERIVED_COMPLETE_INPUT_ITEM_COUNT, 176);
    }
}
