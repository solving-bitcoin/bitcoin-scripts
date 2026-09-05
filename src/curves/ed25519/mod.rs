//! Experimental affine Ed25519 transition verifier.
//!
//! For a fixed affine point `Q = (a, b)`, define
//! `tau = d*a*b*x*y`, `A = x+y`, `B = x-y`, `A' = x'+y'`, and
//! `B' = x'-y'`.  Affine addition by `Q` is certified by three field
//! relations:
//!
//! ```text
//! x*y       - K*tau       = 0,  K = (d*a*b)^-1
//! A' + B'*tau - A*(a+b)   = 0
//! B' + A'*tau - B*(b-a)   = 0
//! ```
//!
//! Each relation is checked as one polynomial identity modulo
//! `p = 2^255-19`.  The verifier streams a single 32-entry signed lookup
//! table at a time and keeps one 51-coefficient accumulator.  Coefficients
//! above degree 50 are folded by 19 before the reverse carry recurrence, so
//! the only auxiliary witness values are the three relation quotients.
//!
//! This is a research kernel, not yet a complete scalar-multiplication
//! verifier. Positive-only entry points exclude `a*b = 0`; the controlled
//! shared-tau entry points normalize identity to synthetic `K=C+=C-=1` and
//! authenticate it through explicit sign/nonzero table controls.

use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, ToPrimitive, Zero};

use crate::{
    arithmetic::scriptint,
    fields::ed25519::{
        u5_balanced_table::{field_digits, modulus, FieldDigits, FIELD_DIGIT_COUNT},
        u5_packed,
    },
    support::script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
};

pub mod montgomery_slope;

pub const RELATION_COUNT: usize = 3;
pub const HINT_ITEM_COUNT: usize = RELATION_COUNT;
pub const FIXED_CLAIMED_FIELD_COUNT: usize = 5;
pub const FIXED_CLAIMED_FIELD_ITEM_COUNT: usize = FIXED_CLAIMED_FIELD_COUNT * FIELD_DIGIT_COUNT;
pub const FIXED_COMPLETE_INPUT_ITEM_COUNT: usize = FIXED_CLAIMED_FIELD_ITEM_COUNT + HINT_ITEM_COUNT;
pub const RUNTIME_CLAIMED_FIELD_COUNT: usize = 8;
pub const RUNTIME_CLAIMED_FIELD_ITEM_COUNT: usize = RUNTIME_CLAIMED_FIELD_COUNT * FIELD_DIGIT_COUNT;
pub const RUNTIME_COMPLETE_INPUT_ITEM_COUNT: usize =
    RUNTIME_CLAIMED_FIELD_ITEM_COUNT + HINT_ITEM_COUNT;
/// Eight packed fields (`x`, `y`, `tau`, `x'`, `y'`, `K`, `C+`, `C-`).
pub const PACKED_POSITIVE_CLAIMED_FIELD_COUNT: usize = 8;
pub const PACKED_POSITIVE_CLAIMED_FIELD_ITEM_COUNT: usize =
    PACKED_POSITIVE_CLAIMED_FIELD_COUNT * u5_packed::PACKED_WORD_COUNT;
/// The packed positive-transition wrapper takes exactly three direct quotient
/// hints in addition to its 64 claimed-field items.
pub const PACKED_POSITIVE_COMPLETE_INPUT_ITEM_COUNT: usize =
    PACKED_POSITIVE_CLAIMED_FIELD_ITEM_COUNT + HINT_ITEM_COUNT;
pub const PACKED_POSITIVE_OUTPUT_ITEM_COUNT: usize = 2 * u5_packed::PACKED_WORD_COUNT;
pub const EXPANDED_CURRENT_PACKED_TRACE_INPUT_ITEM_COUNT: usize =
    2 * FIELD_DIGIT_COUNT + 6 * u5_packed::PACKED_WORD_COUNT + HINT_ITEM_COUNT;
pub const DIRECT_K_LIMB_COUNT: usize = 13;
pub const PACKED_POSITIVE_DIRECT_K_INPUT_ITEM_COUNT: usize =
    7 * u5_packed::PACKED_WORD_COUNT + DIRECT_K_LIMB_COUNT + HINT_ITEM_COUNT;
pub const PACKED_SIGNED_DIRECT_K_INPUT_ITEM_COUNT: usize =
    PACKED_POSITIVE_DIRECT_K_INPUT_ITEM_COUNT + 2;
pub const EXPANDED_CURRENT_DIRECT_K_INPUT_ITEM_COUNT: usize = 2 * FIELD_DIGIT_COUNT
    + 5 * u5_packed::PACKED_WORD_COUNT
    + DIRECT_K_LIMB_COUNT
    + HINT_ITEM_COUNT;
pub const EXPANDED_CURRENT_SIGNED_DIRECT_K_INPUT_ITEM_COUNT: usize =
    EXPANDED_CURRENT_DIRECT_K_INPUT_ITEM_COUNT + 2;
/// Packed current point plus packed next point/tau, with K as 13 centered
/// limbs and C-/C+ as two certified 51-digit vectors.
pub const PACKED_CURRENT_DIRECT_CONSTANTS_INPUT_ITEM_COUNT: usize = 4
    * u5_packed::PACKED_WORD_COUNT
    + 2 * FIELD_DIGIT_COUNT
    + DIRECT_K_LIMB_COUNT
    + HINT_ITEM_COUNT;
/// Expanded current point plus packed next point/tau, with K/C-/C+ supplied
/// directly by an authenticated table selection.
pub const EXPANDED_CURRENT_DIRECT_CONSTANTS_INPUT_ITEM_COUNT: usize = 2 * FIELD_DIGIT_COUNT
    + 3 * u5_packed::PACKED_WORD_COUNT
    + 2 * FIELD_DIGIT_COUNT
    + DIRECT_K_LIMB_COUNT
    + HINT_ITEM_COUNT;
/// Signed/identity shared boundary: the direct-constant boundary plus one
/// authenticated `negative` boolean and one authenticated `nonzero` boolean.
pub const EXPANDED_CURRENT_SIGNED_DIRECT_CONSTANTS_INPUT_ITEM_COUNT: usize =
    EXPANDED_CURRENT_DIRECT_CONSTANTS_INPUT_ITEM_COUNT + 2;
// Backwards-compatible names for the fixed-constant prototype boundary.
pub const CLAIMED_FIELD_ITEM_COUNT: usize = FIXED_CLAIMED_FIELD_ITEM_COUNT;
pub const COMPLETE_INPUT_ITEM_COUNT: usize = FIXED_COMPLETE_INPUT_ITEM_COUNT;

const RADIX: i32 = 32;
const DIGIT_BIAS: i32 = 16;
const TABLE_SIZE: usize = 32;
const HALF_TABLE_SIZE: usize = 16;
const ACCUMULATOR_COUNT: usize = FIELD_DIGIT_COUNT;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Grouping {
    Three,
    Four,
    /// Three four-digit limbs followed by thirteen three-digit limbs. This
    /// 16-limb layout keeps the Montgomery slope chain's two-product
    /// continuity accumulator inside four-byte ScriptNum arithmetic.
    SlopeMixed,
    /// One four-digit, seven six-digit, and one five-digit limb. Montgomery
    /// `b`/`v` coordinates use this staggered sparse-linear layout; the wide
    /// coefficients deliberately avoid the slope product's worst offsets.
    SlopeLinear,
    /// Six four-digit and nine three-digit limbs. The concrete order has a
    /// hostile-input two-product R0 coefficient bound below i32::MAX.
    MixedRZero,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CoordinateFormula {
    Difference,
    RawSumCentered,
    SumWithTwiceRawYCentered,
    RestoreRawFromCenteredSum,
}

impl Grouping {
    const fn limb_count(self) -> usize {
        match self {
            Self::Three => FIELD_DIGIT_COUNT.div_ceil(3),
            Self::Four => FIELD_DIGIT_COUNT.div_ceil(4),
            Self::SlopeMixed => 16,
            Self::SlopeLinear => 9,
            Self::MixedRZero => 15,
        }
    }

    const fn limb_start(self, limb_index: usize) -> usize {
        match self {
            Self::Three => limb_index * 3,
            Self::Four => limb_index * 4,
            Self::SlopeMixed => {
                if limb_index < 3 {
                    limb_index * 4
                } else {
                    12 + (limb_index - 3) * 3
                }
            }
            Self::SlopeLinear => {
                if limb_index == 0 {
                    0
                } else if limb_index < 8 {
                    4 + (limb_index - 1) * 6
                } else {
                    46
                }
            }
            Self::MixedRZero => {
                let mut start = 0;
                let mut index = 0;
                while index < limb_index {
                    start += self.limb_digits(index);
                    index += 1;
                }
                start
            }
        }
    }

    const fn limb_digits(self, limb_index: usize) -> usize {
        assert!(limb_index < self.limb_count());
        match self {
            Self::Three => {
                let remaining = FIELD_DIGIT_COUNT - 3 * limb_index;
                if remaining < 3 {
                    remaining
                } else {
                    3
                }
            }
            Self::Four => {
                let remaining = FIELD_DIGIT_COUNT - 4 * limb_index;
                if remaining < 4 {
                    remaining
                } else {
                    4
                }
            }
            Self::SlopeMixed => {
                if limb_index < 3 {
                    4
                } else {
                    3
                }
            }
            Self::SlopeLinear => {
                if limb_index == 0 {
                    4
                } else if limb_index < 8 {
                    6
                } else {
                    5
                }
            }
            // [4 x 6, 3 x 9]
            Self::MixedRZero => {
                if limb_index < 6 {
                    4
                } else {
                    3
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Field {
    X,
    Y,
    Tau,
    XNext,
    YNext,
    K,
    Cp,
    Cm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LimbSource {
    Direct(Field),
    Sum(Field, Field),
    Difference(Field, Field),
}

#[derive(Clone, Copy)]
enum RhsSource<'a> {
    Field(Field),
    Constant(&'a FieldDigits),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinearTerm {
    None,
    Sum(Field, Field),
    Difference(Field, Field),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedPointConstants {
    pub a: BigUint,
    pub b: BigUint,
    pub cp: BigUint,
    pub cm: BigUint,
    pub k: BigUint,
    cp_digits: FieldDigits,
    cm_digits: FieldDigits,
    k_digits: FieldDigits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionHints {
    /// Quotients for `R0`, `R+`, and `R-`, in that order.
    pub quotients: [i32; RELATION_COUNT],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionCostBreakdown {
    pub r0: usize,
    pub r_plus: usize,
    pub r_minus: usize,
    pub cleanup: usize,
}

impl TransitionCostBreakdown {
    pub const fn total(self) -> usize {
        self.r0 + self.r_plus + self.r_minus + self.cleanup
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamedKernelCostBreakdown {
    pub accumulator_initialization: usize,
    pub r0_products: usize,
    pub r_plus_products: usize,
    pub r_minus_products: usize,
    pub relation_closes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedScheduleKernelCostBreakdown {
    pub xy_product: usize,
    pub k_tau_product: usize,
    pub a_cp_product: usize,
    pub b_next_tau_product: usize,
    pub b_cm_product: usize,
    pub a_next_tau_product: usize,
    pub accumulator_setup: usize,
    pub linear_add: usize,
    pub relation_closes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedPositiveTransitionCostBreakdown {
    pub decoding: usize,
    pub encoding: usize,
    pub six_products: usize,
    pub relation_closes: usize,
    pub accumulator_setup: usize,
    pub coordinate_derivation: usize,
    pub routing_and_cleanup: usize,
}

impl PackedPositiveTransitionCostBreakdown {
    pub const fn total(self) -> usize {
        self.decoding
            + self.encoding
            + self.six_products
            + self.relation_closes
            + self.accumulator_setup
            + self.coordinate_derivation
            + self.routing_and_cleanup
    }
}

impl PackedScheduleKernelCostBreakdown {
    pub const fn total(self) -> usize {
        self.xy_product
            + self.k_tau_product
            + self.a_cp_product
            + self.b_next_tau_product
            + self.b_cm_product
            + self.a_next_tau_product
            + self.accumulator_setup
            + self.linear_add
            + self.relation_closes
    }
}

impl StreamedKernelCostBreakdown {
    pub const fn total(self) -> usize {
        self.accumulator_initialization
            + self.r0_products
            + self.r_plus_products
            + self.r_minus_products
            + self.relation_closes
    }
}

impl TransitionHints {
    /// Pushes exactly three auxiliary stack items.
    pub fn push_script(&self) -> Script {
        script! {
            for quotient in self.quotients {
                { quotient }
            }
        }
    }

    pub fn witness_items(&self) -> Vec<Vec<u8>> {
        self.quotients.into_iter().map(scriptnum_item).collect()
    }
}

fn reduce(value: BigUint) -> BigUint {
    value % modulus()
}

fn add_mod(lhs: &BigUint, rhs: &BigUint) -> BigUint {
    reduce(lhs + rhs)
}

fn sub_mod(lhs: &BigUint, rhs: &BigUint) -> BigUint {
    let p = modulus();
    if lhs >= rhs {
        lhs - rhs
    } else {
        &p - (rhs - lhs)
    }
}

fn mul_mod(lhs: &BigUint, rhs: &BigUint) -> BigUint {
    reduce(lhs * rhs)
}

fn invert(value: &BigUint) -> BigUint {
    let p = modulus();
    assert!(!value.is_zero(), "cannot invert zero in the Ed25519 field");
    value.modpow(&(&p - BigUint::from(2u32)), &p)
}

pub fn edwards_d() -> BigUint {
    let p = modulus();
    let numerator = &p - BigUint::from(121_665u32);
    mul_mod(&numerator, &invert(&BigUint::from(121_666u32)))
}

impl FixedPointConstants {
    pub fn new(a: BigUint, b: BigUint) -> Self {
        let p = modulus();
        assert!(a < p && b < p, "fixed point coordinates must be canonical");

        let d = edwards_d();
        let ab = mul_mod(&a, &b);
        let dab = mul_mod(&d, &ab);
        assert!(
            !dab.is_zero(),
            "the affine transition kernel excludes identity/zero-coordinate table entries"
        );

        // -a^2 + b^2 = 1 + d*a^2*b^2.
        let a2 = mul_mod(&a, &a);
        let b2 = mul_mod(&b, &b);
        let curve_lhs = sub_mod(&b2, &a2);
        let curve_rhs = add_mod(&BigUint::one(), &mul_mod(&d, &mul_mod(&a2, &b2)));
        assert_eq!(curve_lhs, curve_rhs, "fixed point is not on Ed25519");

        let cp = add_mod(&a, &b);
        let cm = sub_mod(&b, &a);
        let k = invert(&dab);
        Self {
            cp_digits: field_digits(&cp),
            cm_digits: field_digits(&cm),
            k_digits: field_digits(&k),
            a,
            b,
            cp,
            cm,
            k,
        }
    }
}

/// RFC 8032's Ed25519 base point.
pub fn basepoint_constants() -> FixedPointConstants {
    let a = BigUint::parse_bytes(
        b"15112221349535400772501151409588531511454012693041857206046113283949847762202",
        10,
    )
    .expect("constant decimal parses");
    let b = BigUint::parse_bytes(
        b"46316835694926478169428394003475163141307993866256225615783033603165251855960",
        10,
    )
    .expect("constant decimal parses");
    FixedPointConstants::new(a, b)
}

/// Compute the affine addition result and the transition's `tau` value.
pub fn affine_add(
    x: &BigUint,
    y: &BigUint,
    fixed: &FixedPointConstants,
) -> (BigUint, BigUint, BigUint) {
    let p = modulus();
    assert!(
        x < &p && y < &p,
        "input point coordinates must be canonical"
    );
    let d = edwards_d();
    let tau = mul_mod(&mul_mod(&mul_mod(&d, &fixed.a), &fixed.b), &mul_mod(x, y));
    let x_numerator = add_mod(&mul_mod(x, &fixed.b), &mul_mod(&fixed.a, y));
    let y_numerator = add_mod(&mul_mod(y, &fixed.b), &mul_mod(x, &fixed.a));
    let x_next = mul_mod(&x_numerator, &invert(&add_mod(&BigUint::one(), &tau)));
    let y_next = mul_mod(&y_numerator, &invert(&sub_mod(&BigUint::one(), &tau)));
    (x_next, y_next, tau)
}

fn arithmetic_digits(value: &BigUint) -> [i32; FIELD_DIGIT_COUNT] {
    field_digits(value).map(|digit| digit - DIGIT_BIAS)
}

fn convolution(
    lhs_digits: &[i32; FIELD_DIGIT_COUNT],
    rhs_digits: &[i32; FIELD_DIGIT_COUNT],
    grouping: Grouping,
) -> [i64; 99] {
    let mut product = [0i64; 99];
    for limb_index in 0..grouping.limb_count() {
        let start = grouping.limb_start(limb_index);
        let limb = (0..grouping.limb_digits(limb_index))
            .rev()
            .fold(0i32, |value, digit| {
                value * RADIX + lhs_digits[start + digit]
            });
        for (rhs_index, rhs) in rhs_digits.iter().copied().enumerate() {
            product[start + rhs_index] += i64::from(limb) * i64::from(rhs);
        }
    }
    product
}

fn add_folded_product(
    accumulator: &mut [i64; FIELD_DIGIT_COUNT],
    lhs: &[i32; FIELD_DIGIT_COUNT],
    rhs: &[i32; FIELD_DIGIT_COUNT],
    sign: i64,
    grouping: Grouping,
) {
    let product = convolution(lhs, rhs, grouping);
    for (index, coefficient) in product.into_iter().enumerate() {
        let (folded_index, scale) = if index < FIELD_DIGIT_COUNT {
            (index, 1)
        } else {
            (index - FIELD_DIGIT_COUNT, 19)
        };
        accumulator[folded_index] += sign * scale * coefficient;
    }
}

fn reconstruct(coefficients: &[i64; FIELD_DIGIT_COUNT]) -> BigInt {
    coefficients
        .iter()
        .rev()
        .fold(BigInt::zero(), |value, coefficient| {
            value * RADIX + BigInt::from(*coefficient)
        })
}

fn exact_quotient(coefficients: &[i64; FIELD_DIGIT_COUNT]) -> i32 {
    let relation = reconstruct(coefficients);
    let p = BigInt::from_biguint(Sign::Plus, modulus());
    assert_eq!(
        &relation % &p,
        BigInt::zero(),
        "transition relation is false"
    );
    let quotient = relation / p;
    let quotient = quotient
        .to_i32()
        .expect("transition quotient must fit a four-byte ScriptNum");
    assert!(
        i64::from(quotient).abs() * i64::from(RADIX) <= i64::from(i32::MAX),
        "transition quotient times 32 must fit ScriptNum arithmetic"
    );
    quotient
}

pub fn transition_hints(
    x: &BigUint,
    y: &BigUint,
    tau: &BigUint,
    x_next: &BigUint,
    y_next: &BigUint,
    fixed: &FixedPointConstants,
) -> TransitionHints {
    transition_hints_with_groupings(
        x,
        y,
        tau,
        x_next,
        y_next,
        fixed,
        Grouping::Four,
        Grouping::Four,
        Grouping::Three,
    )
}

/// Conservative hint generation with three-digit limbs in all products.
///
/// The quotient-only reverse carry recurrence, not just each folded
/// coefficient, must fit four-byte ScriptNum arithmetic. The all-three-digit
/// layout is the currently executable conservative boundary.
pub fn conservative_transition_hints(
    x: &BigUint,
    y: &BigUint,
    tau: &BigUint,
    x_next: &BigUint,
    y_next: &BigUint,
    fixed: &FixedPointConstants,
) -> TransitionHints {
    transition_hints_with_groupings(
        x,
        y,
        tau,
        x_next,
        y_next,
        fixed,
        Grouping::Three,
        Grouping::Three,
        Grouping::Three,
    )
}

/// Hint generation for the proved asymmetric R0 schedule used by the packed
/// wrapper: `x*y` uses three-digit limbs, `K*tau` four-digit limbs, and R+/R-
/// retain three-digit limbs.
///
/// Correlation-free intervals bound the actual-order two-product accumulator
/// by 1,900,945,648, the reverse carry by 61,482,558, and every four-byte
/// arithmetic intermediate by 1,967,441,867. R0's quotient is signed 23-bit.
pub fn asymmetric_r0_transition_hints(
    x: &BigUint,
    y: &BigUint,
    tau: &BigUint,
    x_next: &BigUint,
    y_next: &BigUint,
    fixed: &FixedPointConstants,
) -> TransitionHints {
    transition_hints_with_groupings(
        x,
        y,
        tau,
        x_next,
        y_next,
        fixed,
        Grouping::Three,
        Grouping::Four,
        Grouping::Three,
    )
}

/// Hint generation for the packed wrapper that shares one `tau` lookup table
/// between R+ and R-.  Its coefficient representation is
///
/// `R+ = A' + tau*x' - tau*y' - A*C+`
/// `R- = B' + tau*x' + tau*y' - B*C-`.
///
/// Although these are field-equivalent to the ordinary B'/A' products, the
/// quotient is tied to this exact radix-32 coefficient representation.  The
/// returned witness still contains exactly three quotient stack items.
pub fn shared_tau_transition_hints(
    x: &BigUint,
    y: &BigUint,
    tau: &BigUint,
    x_next: &BigUint,
    y_next: &BigUint,
    fixed: &FixedPointConstants,
) -> TransitionHints {
    shared_tau_transition_hints_with_negative_grouping(
        x,
        y,
        tau,
        x_next,
        y_next,
        fixed,
        Grouping::Three,
    )
}

/// Shared-tau hints for the 15-limb `[4x6,3x9]` negative A*C+/B*C-
/// products. The hostile-input proof bounds every arithmetic intermediate by
/// 1,987,147,066 for R+ and 1,935,550,777 for R-. All three relation
/// quotients require signed 23-bit representation; the witness remains
/// exactly three logical hint items.
pub fn shared_tau_mixed_transition_hints(
    x: &BigUint,
    y: &BigUint,
    tau: &BigUint,
    x_next: &BigUint,
    y_next: &BigUint,
    fixed: &FixedPointConstants,
) -> TransitionHints {
    shared_tau_transition_hints_with_negative_grouping(
        x,
        y,
        tau,
        x_next,
        y_next,
        fixed,
        Grouping::MixedRZero,
    )
}

/// Host quotients for the signed/identity shared-tau wrapper.
///
/// `tau` and `k` are magnitudes. `cp`/`cm` must already be oriented for the
/// selected point: swap them for a negative table entry and use `(1,1)` for
/// identity. Identity additionally uses `k=1`, `tau=0`, `negative=false`, and
/// `nonzero=false`. The result remains exactly three logical hint items.
pub fn controlled_shared_tau_mixed_transition_hints(
    x: &BigUint,
    y: &BigUint,
    tau: &BigUint,
    x_next: &BigUint,
    y_next: &BigUint,
    k: &BigUint,
    cp: &BigUint,
    cm: &BigUint,
    negative: bool,
    nonzero: bool,
) -> TransitionHints {
    assert!(
        nonzero || !negative,
        "identity cannot carry a negative sign"
    );
    let p = modulus();
    for value in [x, y, tau, x_next, y_next, k, cp, cm] {
        assert!(value < &p, "controlled transition field must be canonical");
    }

    let x = arithmetic_digits(x);
    let y = arithmetic_digits(y);
    let tau = arithmetic_digits(tau);
    let x_next = arithmetic_digits(x_next);
    let y_next = arithmetic_digits(y_next);
    let k = arithmetic_digits(k);
    let cp = arithmetic_digits(cp);
    let cm = arithmetic_digits(cm);
    let sum = |lhs: &[i32; FIELD_DIGIT_COUNT], rhs: &[i32; FIELD_DIGIT_COUNT]| {
        std::array::from_fn(|index| lhs[index] + rhs[index])
    };
    let difference = |lhs: &[i32; FIELD_DIGIT_COUNT], rhs: &[i32; FIELD_DIGIT_COUNT]| {
        std::array::from_fn(|index| lhs[index] - rhs[index])
    };
    let a = sum(&x, &y);
    let b = difference(&x, &y);
    let a_next = sum(&x_next, &y_next);
    let b_next = difference(&x_next, &y_next);

    let mut r0 = [0i64; FIELD_DIGIT_COUNT];
    if nonzero {
        add_folded_product(&mut r0, &x, &y, 1, Grouping::Three);
    }
    add_folded_product(&mut r0, &k, &tau, -1, Grouping::Four);

    let tau_sign = if negative { -1 } else { 1 };
    let mut r_plus = a_next.map(i64::from);
    add_folded_product(&mut r_plus, &tau, &x_next, tau_sign, Grouping::Three);
    add_folded_product(&mut r_plus, &tau, &y_next, -tau_sign, Grouping::Three);
    add_folded_product(&mut r_plus, &a, &cp, -1, Grouping::MixedRZero);

    let mut r_minus = b_next.map(i64::from);
    add_folded_product(&mut r_minus, &tau, &x_next, tau_sign, Grouping::Three);
    add_folded_product(&mut r_minus, &tau, &y_next, tau_sign, Grouping::Three);
    add_folded_product(&mut r_minus, &b, &cm, -1, Grouping::MixedRZero);

    TransitionHints {
        quotients: [
            exact_quotient(&r0),
            exact_quotient(&r_plus),
            exact_quotient(&r_minus),
        ],
    }
}

fn shared_tau_transition_hints_with_negative_grouping(
    x: &BigUint,
    y: &BigUint,
    tau: &BigUint,
    x_next: &BigUint,
    y_next: &BigUint,
    fixed: &FixedPointConstants,
    negative_grouping: Grouping,
) -> TransitionHints {
    let p = modulus();
    for value in [x, y, tau, x_next, y_next] {
        assert!(value < &p, "transition field input must be canonical");
    }

    let x = arithmetic_digits(x);
    let y = arithmetic_digits(y);
    let tau = arithmetic_digits(tau);
    let x_next = arithmetic_digits(x_next);
    let y_next = arithmetic_digits(y_next);
    let k = arithmetic_digits(&fixed.k);
    let cp = arithmetic_digits(&fixed.cp);
    let cm = arithmetic_digits(&fixed.cm);
    let sum = |lhs: &[i32; FIELD_DIGIT_COUNT], rhs: &[i32; FIELD_DIGIT_COUNT]| {
        std::array::from_fn(|index| lhs[index] + rhs[index])
    };
    let difference = |lhs: &[i32; FIELD_DIGIT_COUNT], rhs: &[i32; FIELD_DIGIT_COUNT]| {
        std::array::from_fn(|index| lhs[index] - rhs[index])
    };
    let a = sum(&x, &y);
    let b = difference(&x, &y);
    let a_next = sum(&x_next, &y_next);
    let b_next = difference(&x_next, &y_next);

    let mut r0 = [0i64; FIELD_DIGIT_COUNT];
    add_folded_product(&mut r0, &x, &y, 1, Grouping::Three);
    add_folded_product(&mut r0, &k, &tau, -1, Grouping::Four);

    let mut r_plus = a_next.map(i64::from);
    add_folded_product(&mut r_plus, &tau, &x_next, 1, Grouping::Three);
    add_folded_product(&mut r_plus, &tau, &y_next, -1, Grouping::Three);
    add_folded_product(&mut r_plus, &a, &cp, -1, negative_grouping);

    let mut r_minus = b_next.map(i64::from);
    add_folded_product(&mut r_minus, &tau, &x_next, 1, Grouping::Three);
    add_folded_product(&mut r_minus, &tau, &y_next, 1, Grouping::Three);
    add_folded_product(&mut r_minus, &b, &cm, -1, negative_grouping);

    TransitionHints {
        quotients: [
            exact_quotient(&r0),
            exact_quotient(&r_plus),
            exact_quotient(&r_minus),
        ],
    }
}

fn transition_hints_with_groupings(
    x: &BigUint,
    y: &BigUint,
    tau: &BigUint,
    x_next: &BigUint,
    y_next: &BigUint,
    fixed: &FixedPointConstants,
    r0_lhs_grouping: Grouping,
    r0_rhs_grouping: Grouping,
    relation_grouping: Grouping,
) -> TransitionHints {
    let p = modulus();
    for value in [x, y, tau, x_next, y_next] {
        assert!(value < &p, "transition field input must be canonical");
    }

    let x = arithmetic_digits(x);
    let y = arithmetic_digits(y);
    let tau = arithmetic_digits(tau);
    let x_next = arithmetic_digits(x_next);
    let y_next = arithmetic_digits(y_next);
    let k = arithmetic_digits(&fixed.k);
    let cp = arithmetic_digits(&fixed.cp);
    let cm = arithmetic_digits(&fixed.cm);
    let sum = |lhs: &[i32; FIELD_DIGIT_COUNT], rhs: &[i32; FIELD_DIGIT_COUNT]| {
        std::array::from_fn(|index| lhs[index] + rhs[index])
    };
    let difference = |lhs: &[i32; FIELD_DIGIT_COUNT], rhs: &[i32; FIELD_DIGIT_COUNT]| {
        std::array::from_fn(|index| lhs[index] - rhs[index])
    };

    let a = sum(&x, &y);
    let b = difference(&x, &y);
    let a_next = sum(&x_next, &y_next);
    let b_next = difference(&x_next, &y_next);

    let mut r0 = [0i64; FIELD_DIGIT_COUNT];
    add_folded_product(&mut r0, &x, &y, 1, r0_lhs_grouping);
    // The quotient binds the coefficient representation, not merely the
    // residue. Match the Script schedule's cached K limbs exactly; swapping
    // K/tau is field-equivalent but can shift q by a multiple of p.
    add_folded_product(&mut r0, &k, &tau, -1, r0_rhs_grouping);

    let mut r_plus = a_next.map(i64::from);
    add_folded_product(&mut r_plus, &b_next, &tau, 1, relation_grouping);
    add_folded_product(&mut r_plus, &a, &cp, -1, relation_grouping);

    let mut r_minus = b_next.map(i64::from);
    add_folded_product(&mut r_minus, &a_next, &tau, 1, relation_grouping);
    add_folded_product(&mut r_minus, &b, &cm, -1, relation_grouping);

    TransitionHints {
        quotients: [
            exact_quotient(&r0),
            exact_quotient(&r_plus),
            exact_quotient(&r_minus),
        ],
    }
}

fn scriptnum_item(value: i32) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value));
    bytes[..length].to_vec()
}

fn base_depth(field: Field, digit: usize, runtime_constants: bool) -> usize {
    assert!(digit < FIELD_DIGIT_COUNT);
    let field_offset = match (runtime_constants, field) {
        (false, Field::YNext) => 0,
        (false, Field::XNext) => 1,
        (false, Field::Tau) => 2,
        (false, Field::Y) => 3,
        (false, Field::X) => 4,
        (false, Field::K | Field::Cp | Field::Cm) => {
            panic!("fixed-constant layout has no runtime constant fields")
        }
        (true, Field::Cm) => 0,
        (true, Field::Cp) => 1,
        (true, Field::K) => 2,
        (true, Field::YNext) => 3,
        (true, Field::XNext) => 4,
        (true, Field::Tau) => 5,
        (true, Field::Y) => 6,
        (true, Field::X) => 7,
    };
    HINT_ITEM_COUNT + field_offset * FIELD_DIGIT_COUNT + digit
}

fn pick_field_digit(
    field: Field,
    digit: usize,
    items_above_base: usize,
    transient_items: usize,
    runtime_constants: bool,
) -> Script {
    script! {
        { (base_depth(field, digit, runtime_constants) + items_above_base + transient_items) as u32 }
        OP_PICK
    }
}

fn combine_digit(
    source: LimbSource,
    digit: usize,
    items_above_base: usize,
    transient_items: usize,
    runtime_constants: bool,
) -> Script {
    match source {
        LimbSource::Direct(field) => pick_field_digit(
            field,
            digit,
            items_above_base,
            transient_items,
            runtime_constants,
        ),
        LimbSource::Sum(lhs, rhs) => script! {
            { pick_field_digit(lhs, digit, items_above_base, transient_items, runtime_constants) }
            { pick_field_digit(rhs, digit, items_above_base, transient_items + 1, runtime_constants) }
            OP_ADD
        },
        LimbSource::Difference(lhs, rhs) => script! {
            { pick_field_digit(lhs, digit, items_above_base, transient_items, runtime_constants) }
            { pick_field_digit(rhs, digit, items_above_base, transient_items + 1, runtime_constants) }
            OP_SUB
        },
    }
}

fn limb_bias(source: LimbSource, digit_count: usize) -> i32 {
    let span = (0..digit_count).fold(0, |value, _| value * RADIX + 1);
    let multiplicity = match source {
        LimbSource::Direct(_) => 1,
        LimbSource::Sum(_, _) => 2,
        LimbSource::Difference(_, _) => 0,
    };
    multiplicity * DIGIT_BIAS * span
}

fn build_lhs_limb(
    source: LimbSource,
    limb_index: usize,
    grouping: Grouping,
    items_above_base: usize,
    negative: bool,
    scaled_by_19: bool,
    runtime_constants: bool,
) -> Script {
    let low = grouping.limb_start(limb_index);
    let digit_count = grouping.limb_digits(limb_index);
    let bias = limb_bias(source, digit_count);
    script! {
        { combine_digit(
            source,
            low + digit_count - 1,
            items_above_base,
            0,
            runtime_constants,
        ) }
        for digit in (0..digit_count - 1).rev() {
            { scriptint::mul_by_constant(RADIX as u32) }
            { combine_digit(source, low + digit, items_above_base, 1, runtime_constants) }
            OP_ADD
        }
        if bias != 0 {
            { bias } OP_SUB
        }
        if negative { OP_NEGATE }
        if scaled_by_19 { { scriptint::mul_by_constant(19) } }
    }
}

// Input: `... a`; output: `... 15a 14a ... -16a`, selector zero nearest top.
fn build_descending_signed_table() -> Script {
    script! {
        OP_DUP
        for _ in 0..4 { OP_DUP OP_ADD }
        OP_OVER OP_SUB
        OP_SWAP
        for _ in 0..31 {
            OP_2DUP OP_SUB OP_SWAP
        }
        OP_DROP
    }
}

fn drop_table() -> Script {
    script! {
        for _ in 0..TABLE_SIZE / 2 { OP_2DROP }
    }
}

// Input `a`; output `0,a,...,15a`, with 15a nearest the top. This compact
// table is used only by the byte-for-stack first-transition schedule.
fn build_ascending_half_table() -> Script {
    script! {
        0
        for multiple in 1..HALF_TABLE_SIZE {
            OP_DUP { (multiple + 1) as u32 } OP_PICK OP_ADD
        }
        { HALF_TABLE_SIZE as u32 } OP_ROLL OP_DROP
    }
}

fn drop_half_table() -> Script {
    script! { for _ in 0..HALF_TABLE_SIZE / 2 { OP_2DROP } }
}

// Input `x[50..0] | y[50..0] | h[50..0] | nonzero`; output keeps x/y/h and
// consumes the authenticated boolean. For the identity-table leaf, omitting
// x*y changes R0 into `-K*tau=0` and therefore binds tau to zero. Keeping the
// condition on top avoids routing three 51-item blocks around a one-item flag.
fn accumulate_r0_xy_if_nonzero() -> Script {
    script! {
        OP_IF
            { accumulate_streamed_product_preserving_grouping(
                false,
                Grouping::Three,
                false,
            ) }
        OP_ENDIF
    }
}

// Input `values[last..0] | negative`; output keeps the vector in the same
// order and consumes the authenticated minimally-encoded boolean.
fn conditionally_negate_top_items(items: usize) -> Script {
    script! {
        OP_IF
            for _ in 0..items { OP_NEGATE OP_TOALTSTACK }
            for _ in 0..items { OP_FROMALTSTACK }
        OP_ENDIF
    }
}

fn select_rhs(
    source: RhsSource<'_>,
    rhs_digit: usize,
    items_above_base: usize,
    runtime_constants: bool,
) -> Script {
    match source {
        RhsSource::Field(field) => {
            pick_field_digit(field, rhs_digit, items_above_base, 0, runtime_constants)
        }
        RhsSource::Constant(digits) => script! { { digits[rhs_digit] } },
    }
}

fn update_nearest_accumulator(
    rhs: RhsSource<'_>,
    rhs_digit: usize,
    unprocessed_accumulators: usize,
    runtime_constants: bool,
) -> Script {
    script! {
        { select_rhs(
            rhs,
            rhs_digit,
            TABLE_SIZE + unprocessed_accumulators,
            runtime_constants,
        ) }
        OP_PICK
        { (TABLE_SIZE + 1) as u32 } OP_ROLL
        OP_ADD
        OP_TOALTSTACK
    }
}

fn apply_product(
    lhs: LimbSource,
    rhs: RhsSource<'_>,
    negative: bool,
    grouping: Grouping,
    runtime_constants: bool,
) -> Script {
    let limbs = (0..grouping.limb_count())
        .map(|limb_index| {
            let offset = grouping.limb_start(limb_index);
            let scaled_updates = if offset == 0 {
                Script::new("no wrapped coefficients")
            } else {
                script! {
                    { build_lhs_limb(
                        lhs,
                        limb_index,
                        grouping,
                        ACCUMULATOR_COUNT,
                        negative,
                        true,
                        runtime_constants,
                    ) }
                    { build_descending_signed_table() }
                    for coefficient in 0..offset {
                        { update_nearest_accumulator(
                            rhs,
                            FIELD_DIGIT_COUNT + coefficient - offset,
                            ACCUMULATOR_COUNT - coefficient,
                            runtime_constants,
                        ) }
                    }
                    { drop_table() }
                }
            };
            script! {
                { scaled_updates }

                // The updated wrapped coefficients remain on altstack. The
                // normal coefficients are pushed above them, so restoring all
                // 51 items recreates h[50]..h[0] without a needless
                // restore-and-repark round trip.
                { build_lhs_limb(
                    lhs,
                    limb_index,
                    grouping,
                    ACCUMULATOR_COUNT - offset,
                    negative,
                    false,
                    runtime_constants,
                ) }
                { build_descending_signed_table() }
                for coefficient in offset..FIELD_DIGIT_COUNT {
                    { update_nearest_accumulator(
                        rhs,
                        coefficient - offset,
                        ACCUMULATOR_COUNT - coefficient,
                        runtime_constants,
                    ) }
                }
                { drop_table() }
                for _ in 0..ACCUMULATOR_COUNT { OP_FROMALTSTACK }
            }
        })
        .collect::<Vec<_>>();
    script! {
        for limb in limbs { { limb } }
    }
}

fn add_linear_term(term: LinearTerm, digit: usize, runtime_constants: bool) -> Script {
    match term {
        LinearTerm::None => Script::new("no linear coefficient"),
        LinearTerm::Sum(lhs, rhs) => script! {
            { pick_field_digit(lhs, digit, 2, 0, runtime_constants) }
            { pick_field_digit(rhs, digit, 2, 1, runtime_constants) }
            OP_ADD
            { 2 * DIGIT_BIAS } OP_SUB
            OP_ADD
        },
        LinearTerm::Difference(lhs, rhs) => script! {
            { pick_field_digit(lhs, digit, 2, 0, runtime_constants) }
            { pick_field_digit(rhs, digit, 2, 1, runtime_constants) }
            OP_SUB
            OP_ADD
        },
    }
}

fn verify_accumulator(
    quotient_depth: usize,
    linear: LinearTerm,
    runtime_constants: bool,
) -> Script {
    script! {
        // h[0] is nearest the top.  Moving all coefficients to altstack makes
        // h[50] emerge first for the quotient-only reverse carry recurrence.
        for _ in 0..ACCUMULATOR_COUNT { OP_TOALTSTACK }
        { quotient_depth as u32 } OP_PICK
        for coefficient in (1..FIELD_DIGIT_COUNT).rev() {
            OP_FROMALTSTACK
            { add_linear_term(linear, coefficient, runtime_constants) }
            OP_SWAP
            { scriptint::mul_by_constant(RADIX as u32) }
            OP_SWAP OP_SUB
        }

        OP_FROMALTSTACK
        { add_linear_term(linear, 0, runtime_constants) }
        { (quotient_depth + 2) as u32 } OP_PICK
        { scriptint::mul_by_constant(19) }
        OP_ADD
        OP_SWAP
        { scriptint::mul_by_constant(RADIX as u32) }
        OP_NUMEQUALVERIFY
    }
}

fn verify_relation(
    quotient_depth: usize,
    linear: LinearTerm,
    lhs_a: LimbSource,
    rhs_a: RhsSource<'_>,
    negative_a: bool,
    lhs_b: LimbSource,
    rhs_b: RhsSource<'_>,
    negative_b: bool,
    grouping: Grouping,
    runtime_constants: bool,
) -> Script {
    script! {
        for _ in 0..ACCUMULATOR_COUNT { 0 }
        { apply_product(lhs_a, rhs_a, negative_a, grouping, runtime_constants) }
        { apply_product(lhs_b, rhs_b, negative_b, grouping, runtime_constants) }
        { verify_accumulator(quotient_depth, linear, runtime_constants) }
    }
}

fn retain_next_point(runtime_constants: bool) -> Script {
    script! {
        // Drop q0, q+, q-.
        OP_2DROP OP_DROP
        if runtime_constants {
            // K, C+, and C- were supplied by the caller's fixed-table
            // selection and are consumed by this transition.
            for _ in 0..(3 * FIELD_DIGIT_COUNT) / 2 { OP_2DROP }
            if (3 * FIELD_DIGIT_COUNT) % 2 != 0 { OP_DROP }
        }
        // Park y' then x', discard x/y/tau, and restore x' | y'.
        for _ in 0..FIELD_DIGIT_COUNT { OP_TOALTSTACK }
        for _ in 0..FIELD_DIGIT_COUNT { OP_TOALTSTACK }
        for _ in 0..(3 * FIELD_DIGIT_COUNT) / 2 { OP_2DROP }
        if (3 * FIELD_DIGIT_COUNT) % 2 != 0 { OP_DROP }
        for _ in 0..(2 * FIELD_DIGIT_COUNT) { OP_FROMALTSTACK }
    }
}

/// Push a zeroed 51-coefficient relation accumulator.
///
/// A packed trace scheduler can keep this accumulator live while it decodes
/// exactly two operands for each call to [`accumulate_streamed_product`].
pub fn push_relation_accumulator() -> Script {
    script! {
        for _ in 0..ACCUMULATOR_COUNT { 0 }
    }
}

fn pick_streamed_lhs_digit(
    digit: usize,
    live_accumulators: usize,
    transient_items: usize,
) -> Script {
    // Input below scratch is lhs[50..0] | rhs[50..0] | live accumulators.
    script! {
        { (live_accumulators + FIELD_DIGIT_COUNT + digit + transient_items) as u32 }
        OP_PICK
    }
}

fn build_streamed_lhs_limb(
    limb_index: usize,
    grouping: Grouping,
    live_accumulators: usize,
    lhs_is_centered: bool,
    negative: bool,
    scaled_by_19: bool,
) -> Script {
    let low = grouping.limb_start(limb_index);
    let digit_count = grouping.limb_digits(limb_index);
    let bias = if lhs_is_centered {
        0
    } else {
        DIGIT_BIAS * (0..digit_count).fold(0, |value, _| value * RADIX + 1)
    };
    script! {
        { pick_streamed_lhs_digit(low + digit_count - 1, live_accumulators, 0) }
        for digit in (0..digit_count - 1).rev() {
            { scriptint::mul_by_constant(RADIX as u32) }
            { pick_streamed_lhs_digit(low + digit, live_accumulators, 1) }
            OP_ADD
        }
        if bias != 0 { { bias } OP_SUB }
        if negative { OP_NEGATE }
        if scaled_by_19 { { scriptint::mul_by_constant(19) } }
    }
}

fn update_streamed_accumulator(rhs_digit: usize, unprocessed_accumulators: usize) -> Script {
    script! {
        // The rhs vector is immediately below the remaining accumulators.
        { (TABLE_SIZE + unprocessed_accumulators + rhs_digit) as u32 } OP_PICK
        OP_PICK
        { (TABLE_SIZE + 1) as u32 } OP_ROLL
        OP_ADD OP_TOALTSTACK
    }
}

fn cleanup_streamed_product_operands() -> Script {
    script! {
        for _ in 0..ACCUMULATOR_COUNT { OP_TOALTSTACK }
        for _ in 0..FIELD_DIGIT_COUNT { OP_2DROP }
        for _ in 0..ACCUMULATOR_COUNT { OP_FROMALTSTACK }
    }
}

fn take_streamed_limb(
    live_accumulators: usize,
    negative: bool,
    scaled_by_19: bool,
    copy: bool,
) -> Script {
    let depth = FIELD_DIGIT_COUNT + live_accumulators;
    let select = if copy {
        script! { { depth as u32 } OP_PICK }
    } else {
        script! { { depth as u32 } OP_ROLL }
    };
    script! {
        { select }
        if negative { OP_NEGATE }
        if scaled_by_19 { { scriptint::mul_by_constant(19) } }
    }
}

fn cleanup_streamed_limb_product_rhs() -> Script {
    script! {
        for _ in 0..ACCUMULATOR_COUNT { OP_TOALTSTACK }
        for _ in 0..FIELD_DIGIT_COUNT / 2 { OP_2DROP }
        if FIELD_DIGIT_COUNT % 2 != 0 { OP_DROP }
        for _ in 0..ACCUMULATOR_COUNT { OP_FROMALTSTACK }
    }
}

/// Add one product to a live relation accumulator using one table at a time.
///
/// Input is `... | lhs[50..0] | rhs[50..0] | h[50..0]`; output is
/// `... | h'[50..0]`. `rhs` is always a biased, certified field vector.
/// `lhs` is either another biased field vector (`lhs_is_centered = false`) or
/// a digitwise centered linear combination such as `A=x+y` or `B=x-y`
/// (`lhs_is_centered = true`). Set `four_digit_lhs` only when the caller's
/// complete accumulator-bound proof permits it; it is safe for the two R0
/// products, while R+/R- use three-digit limbs. `negative` subtracts instead
/// of adding the product.
///
/// The fragment has 153 local input items, no hint items, and a data-
/// independent local peak of 187 combined stack items. Every unrelated item
/// below `lhs` is preserved and adds one-for-one to that peak.
pub fn accumulate_streamed_product(
    lhs_is_centered: bool,
    four_digit_lhs: bool,
    negative: bool,
) -> Script {
    script! {
        { accumulate_streamed_product_inner(
            lhs_is_centered,
            if four_digit_lhs { Grouping::Four } else { Grouping::Three },
            negative,
        ) }
        { cleanup_streamed_product_operands() }
    }
}

fn accumulate_streamed_product_inner(
    lhs_is_centered: bool,
    grouping: Grouping,
    negative: bool,
) -> Script {
    let limbs = (0..grouping.limb_count())
        .map(|limb_index| {
            let offset = grouping.limb_start(limb_index);
            let scaled = if offset == 0 {
                Script::new("no wrapped coefficients")
            } else {
                script! {
                    { build_streamed_lhs_limb(
                        limb_index,
                        grouping,
                        ACCUMULATOR_COUNT,
                        lhs_is_centered,
                        negative,
                        true,
                    ) }
                    { build_descending_signed_table() }
                    for coefficient in 0..offset {
                        { update_streamed_accumulator(
                            FIELD_DIGIT_COUNT + coefficient - offset,
                            ACCUMULATOR_COUNT - coefficient,
                        ) }
                    }
                    { drop_table() }
                }
            };
            script! {
                { scaled }
                { build_streamed_lhs_limb(
                    limb_index,
                    grouping,
                    ACCUMULATOR_COUNT - offset,
                    lhs_is_centered,
                    negative,
                    false,
                ) }
                { build_descending_signed_table() }
                for coefficient in offset..FIELD_DIGIT_COUNT {
                    { update_streamed_accumulator(
                        coefficient - offset,
                        ACCUMULATOR_COUNT - coefficient,
                    ) }
                }
                { drop_table() }
                for _ in 0..ACCUMULATOR_COUNT { OP_FROMALTSTACK }
            }
        })
        .collect::<Vec<_>>();
    script! { for limb in limbs { { limb } } }
}

/// Add one product while retaining both expanded operands.
///
/// Input and output are both
/// `... | lhs[50..0] | rhs[50..0] | h[50..0]`. The updated accumulator is
/// still the top 51-item block. This form is useful when one decoded operand
/// feeds a later relation. It has exactly the same 153 local inputs and
/// 187-item data-independent local peak as [`accumulate_streamed_product`],
/// but deliberately omits operand cleanup. It requires no hint items.
pub fn accumulate_streamed_product_preserving_operands(
    lhs_is_centered: bool,
    four_digit_lhs: bool,
    negative: bool,
) -> Script {
    accumulate_streamed_product_inner(
        lhs_is_centered,
        if four_digit_lhs {
            Grouping::Four
        } else {
            Grouping::Three
        },
        negative,
    )
}

fn accumulate_streamed_product_preserving_grouping(
    lhs_is_centered: bool,
    grouping: Grouping,
    negative: bool,
) -> Script {
    accumulate_streamed_product_inner(lhs_is_centered, grouping, negative)
}

/// Add a product whose centered left operand is already cached as limbs.
///
/// Input is `... | lhs_limbs[last..0] | rhs[50..0] | h[50..0]`; output is
/// `... | h'[50..0]`. The four-digit form consumes 13 limbs and the three-
/// digit form consumes 17. Limb zero is nearest the rhs vector. The rhs is a
/// biased certified field vector. Cached limbs are expected to have been
/// derived from certified fields on the same path; this fragment does not
/// independently bind or range-check hostile limb witnesses.
///
/// The four-digit form has 115 local inputs and a 148-item strict peak. The
/// three-digit form has 119 local inputs and a 152-item strict peak. It has no
/// hint items. Unrelated packed state below the limbs is preserved and adds
/// one-for-one to those peaks.
pub fn accumulate_streamed_limb_product(four_digit_lhs: bool, negative: bool) -> Script {
    script! {
        { accumulate_streamed_limb_product_inner(
            if four_digit_lhs { Grouping::Four } else { Grouping::Three },
            negative,
        ) }
        { cleanup_streamed_limb_product_rhs() }
    }
}

fn accumulate_streamed_limb_product_inner(grouping: Grouping, negative: bool) -> Script {
    let limbs = (0..grouping.limb_count())
        .map(|limb_index| {
            let offset = grouping.limb_start(limb_index);
            let scaled = if offset == 0 {
                Script::new("no wrapped coefficients")
            } else {
                script! {
                    { take_streamed_limb(ACCUMULATOR_COUNT, negative, true, true) }
                    { build_descending_signed_table() }
                    for coefficient in 0..offset {
                        { update_streamed_accumulator(
                            FIELD_DIGIT_COUNT + coefficient - offset,
                            ACCUMULATOR_COUNT - coefficient,
                        ) }
                    }
                    { drop_table() }
                }
            };
            script! {
                { scaled }
                // This is the limb's last use, so OP_ROLL also advances the
                // cached-limb queue for the following pass.
                { take_streamed_limb(
                    ACCUMULATOR_COUNT - offset,
                    negative,
                    false,
                    false,
                ) }
                { build_descending_signed_table() }
                for coefficient in offset..FIELD_DIGIT_COUNT {
                    { update_streamed_accumulator(
                        coefficient - offset,
                        ACCUMULATOR_COUNT - coefficient,
                    ) }
                }
                { drop_table() }
                for _ in 0..ACCUMULATOR_COUNT { OP_FROMALTSTACK }
            }
        })
        .collect::<Vec<_>>();
    script! { for limb in limbs { { limb } } }
}

/// Cached-limb product that consumes its left limbs but retains its rhs.
///
/// Input is `... | lhs_limbs[last..0] | rhs[50..0] | h[50..0]`; output is
/// `... | rhs[50..0] | h'[50..0]`. The three-digit form has 119 local input
/// items and a 152-item local peak. The four-digit form has 115/148. It
/// requires no hint items.
pub fn accumulate_streamed_limb_product_preserving_rhs(
    four_digit_lhs: bool,
    negative: bool,
) -> Script {
    accumulate_streamed_limb_product_inner(
        if four_digit_lhs {
            Grouping::Four
        } else {
            Grouping::Three
        },
        negative,
    )
}

fn accumulate_streamed_limb_product_grouping(
    grouping: Grouping,
    negative: bool,
    preserve_rhs: bool,
) -> Script {
    script! {
        { accumulate_streamed_limb_product_inner(grouping, negative) }
        if !preserve_rhs { { cleanup_streamed_limb_product_rhs() } }
    }
}

/// Reference grouped-four square used to compare the symmetric specialization.
///
/// Input is one externally certified biased radix-32 field vector
/// `rhs[50..0]`. Output is `rhs[50..0] | h[50..0]`, where `h` is the folded
/// coefficient accumulator for `(rhs-16)^2`. The rhs is retained byte-for-byte.
/// This is the former generic 13-limb by 51-digit path: it duplicates the
/// field, compacts one copy to limbs, and performs 663 table updates. It
/// requires exactly zero witness-hint items and does not certify hostile rhs
/// digits itself.
pub fn initialize_streamed_grouped_four_square_generic_preserving_rhs() -> Script {
    script! {
        // Copy digit 50 first. Each copy raises the next original digit by
        // one slot, so the selector remains constant.
        for _ in 0..FIELD_DIGIT_COUNT {
            { (FIELD_DIGIT_COUNT - 1) as u32 } OP_PICK
        }
        { centered_digits_to_limbs(Grouping::Four, true) }
        { move_block_to_top(FIELD_DIGIT_COUNT, Grouping::Four.limb_count()) }
        { push_relation_accumulator() }
        { accumulate_streamed_limb_product_preserving_rhs(true, false) }
    }
}

fn build_streamed_square_limb(limb_index: usize, live_accumulators: usize) -> Script {
    let low = Grouping::Four.limb_start(limb_index);
    let width = Grouping::Four.limb_digits(limb_index);
    let bias = DIGIT_BIAS * (0..width).fold(0, |value, _| value * RADIX + 1);
    script! {
        // The certified rhs is immediately below the live accumulator. After
        // the first digit copy, the partial limb adds one transient item.
        { (live_accumulators + low + width - 1) as u32 } OP_PICK
        for digit in (0..width - 1).rev() {
            { scriptint::mul_by_constant(RADIX as u32) }
            { (live_accumulators + low + digit + 1) as u32 } OP_PICK
            OP_ADD
        }
        { bias } OP_SUB
    }
}

fn update_streamed_square_accumulator(
    rhs_digit: usize,
    unprocessed_accumulators: usize,
    retained_limb_items: usize,
    double_cross_product: bool,
    fold_selected_by_19: bool,
) -> Script {
    script! {
        // A retained unscaled limb can sit between the accumulator and the
        // table while the folded x19 pass is in progress.
        { (TABLE_SIZE
            + retained_limb_items
            + unprocessed_accumulators
            + rhs_digit) as u32 }
        OP_PICK
        OP_PICK
        if double_cross_product { OP_DUP OP_ADD }
        if fold_selected_by_19 { { scriptint::mul_by_constant(19) } }
        { (TABLE_SIZE + retained_limb_items + 1) as u32 } OP_ROLL
        OP_ADD OP_TOALTSTACK
    }
}

fn park_streamed_square_accumulator(retained_limb_items: usize) -> Script {
    script! {
        { (TABLE_SIZE + retained_limb_items) as u32 } OP_ROLL
        OP_TOALTSTACK
    }
}

/// Symmetry-specialized grouped-four square with a preserved canonical rhs.
///
/// Input is one externally certified biased radix-32 field vector
/// `rhs[50..0]`. Output is `rhs[50..0] | h[50..0]`, where `h` is the folded
/// coefficient accumulator for `(rhs-16)^2`. The rhs is retained byte-for-byte
/// for later relations/state. Each four-digit block multiplies only its own
/// block and later rhs digits; later-block cross products are doubled. Terms
/// above coefficient 50 are folded through the ordinary x19 table path.
/// This reduces the generic square from 663 to exactly 351 table updates.
///
/// This fragment consumes exactly zero witness-hint items. It intentionally
/// relies on its caller to certify every rhs digit as canonical biased u5 data;
/// its table selector is not an independent hostile-input range check.
pub fn initialize_streamed_grouped_four_square_preserving_rhs() -> Script {
    let limbs = (0..Grouping::Four.limb_count())
        .map(|limb_index| {
            let start = Grouping::Four.limb_start(limb_index);
            let width = Grouping::Four.limb_digits(limb_index);
            let has_normal_products = 2 * start < FIELD_DIGIT_COUNT;
            let low_prepark = if has_normal_products {
                0
            } else {
                2 * start - FIELD_DIGIT_COUNT
            };
            let rebuild_after_middle = start == 20 || start == 24;
            let retain_for_normal = usize::from(has_normal_products && !rebuild_after_middle);
            let folded_updates = (low_prepark..start)
                .map(|coefficient| {
                    let rhs_digit = FIELD_DIGIT_COUNT + coefficient - start;
                    if rhs_digit >= start {
                        update_streamed_square_accumulator(
                            rhs_digit,
                            ACCUMULATOR_COUNT - coefficient,
                            retain_for_normal,
                            rhs_digit >= start + width,
                            false,
                        )
                    } else {
                        park_streamed_square_accumulator(retain_for_normal)
                    }
                })
                .collect::<Vec<_>>();
            let normal_updates = (start..FIELD_DIGIT_COUNT)
                .map(|coefficient| {
                    let rhs_digit = coefficient - start;
                    if rhs_digit >= start {
                        update_streamed_square_accumulator(
                            rhs_digit,
                            ACCUMULATOR_COUNT - coefficient,
                            0,
                            rhs_digit >= start + width,
                            false,
                        )
                    } else {
                        park_streamed_square_accumulator(0)
                    }
                })
                .collect::<Vec<_>>();
            let rebuilt_normal_updates = (2 * start..FIELD_DIGIT_COUNT)
                .map(|coefficient| {
                    let rhs_digit = coefficient - start;
                    update_streamed_square_accumulator(
                        rhs_digit,
                        ACCUMULATOR_COUNT - coefficient,
                        0,
                        rhs_digit >= start + width,
                        false,
                    )
                })
                .collect::<Vec<_>>();

            // For s=4 and s=8, multiplying only the handful of folded
            // selections by 19 is smaller than building a second x19 table.
            // Larger early blocks cross the break-even point.
            let share_raw_table = start == 4 || start == 8;
            let shared_table_updates = (0..FIELD_DIGIT_COUNT)
                .map(|coefficient| {
                    if coefficient < start {
                        let rhs_digit = FIELD_DIGIT_COUNT + coefficient - start;
                        update_streamed_square_accumulator(
                            rhs_digit,
                            ACCUMULATOR_COUNT - coefficient,
                            0,
                            true,
                            true,
                        )
                    } else {
                        let rhs_digit = coefficient - start;
                        if rhs_digit >= start {
                            update_streamed_square_accumulator(
                                rhs_digit,
                                ACCUMULATOR_COUNT - coefficient,
                                0,
                                rhs_digit >= start + width,
                                false,
                            )
                        } else {
                            park_streamed_square_accumulator(0)
                        }
                    }
                })
                .collect::<Vec<_>>();

            let folded = if start == 0 {
                Script::new("first square limb has no folded products")
            } else {
                script! {
                    if has_normal_products && !rebuild_after_middle { OP_DUP }
                    { scriptint::mul_by_constant(19) }
                    { build_descending_signed_table() }
                    for update in folded_updates { { update } }
                    { drop_table() }
                }
            };

            let normal = if rebuild_after_middle {
                script! {
                    // For the two shortest surviving normal tails, retaining
                    // a limb beneath the folded table costs more than parking
                    // the contiguous mirrored gap and rebuilding the limb.
                    for _ in start..2 * start { OP_TOALTSTACK }
                    { build_streamed_square_limb(
                        limb_index,
                        ACCUMULATOR_COUNT - 2 * start,
                    ) }
                    { build_descending_signed_table() }
                    for update in rebuilt_normal_updates { { update } }
                    { drop_table() }
                }
            } else if has_normal_products {
                script! {
                    { build_descending_signed_table() }
                    for update in normal_updates { { update } }
                    { drop_table() }
                }
            } else {
                // Every remaining normal coefficient belongs to a mirrored
                // product already covered by an earlier block.
                script! {
                    for _ in start..FIELD_DIGIT_COUNT { OP_TOALTSTACK }
                }
            };

            if share_raw_table {
                script! {
                    { build_streamed_square_limb(limb_index, ACCUMULATOR_COUNT) }
                    { build_descending_signed_table() }
                    for update in shared_table_updates { { update } }
                    { drop_table() }
                    for _ in 0..ACCUMULATOR_COUNT { OP_FROMALTSTACK }
                }
            } else {
                script! {
                    // Late limbs have a contiguous low coefficient range with
                    // no surviving symmetric term. Park it before scratch is
                    // built so each omission costs one byte, not OP_ROLL.
                    for _ in 0..low_prepark { OP_TOALTSTACK }
                    { build_streamed_square_limb(
                        limb_index,
                        ACCUMULATOR_COUNT - low_prepark,
                    ) }
                    { folded }
                    { normal }
                    for _ in 0..ACCUMULATOR_COUNT { OP_FROMALTSTACK }
                }
            }
        })
        .collect::<Vec<_>>();

    script! {
        { push_relation_accumulator() }
        for limb in limbs { { limb } }
    }
}

/// Treat a centered 51-item linear vector as a fresh accumulator.
///
/// This is intentionally zero bytes: the two stack representations coincide.
/// It documents the boundary used when `A'` initializes `R+` or `B'`
/// initializes `R-`.
pub fn initialize_relation_accumulator_from_linear() -> Script {
    Script::new("centered linear vector is already an accumulator")
}

/// Add and consume a centered linear vector below a live accumulator.
///
/// Input is `... | linear[50..0] | h[50..0]`; output is
/// `... | (h+linear)[50..0]`. The local input count is 102 and the strict
/// local peak is 103; there are no hint items.
pub fn add_linear_to_relation_accumulator() -> Script {
    script! {
        for coefficient in 0..FIELD_DIGIT_COUNT {
            { (FIELD_DIGIT_COUNT - coefficient) as u32 } OP_ROLL
            OP_ADD OP_TOALTSTACK
        }
        for _ in 0..FIELD_DIGIT_COUNT { OP_FROMALTSTACK }
    }
}

// Move one contiguous block through `items_above` unrelated items while
// preserving the order within both regions.
fn move_block_to_top(block_items: usize, items_above: usize) -> Script {
    if items_above == 0 {
        return Script::new("block is already at the top");
    }
    let depth = block_items + items_above - 1;
    script! {
        for _ in 0..block_items { { depth as u32 } OP_ROLL }
    }
}

fn drop_top_items(items: usize) -> Script {
    script! {
        for _ in 0..items / 2 { OP_2DROP }
        if items % 2 != 0 { OP_DROP }
    }
}

// Input is one centered digit vector; output uses the selected limb partition,
// last limb first and limb zero nearest the top. The biased form first
// interprets each input digit as digit-16.
fn centered_digits_to_limbs(grouping: Grouping, biased_input: bool) -> Script {
    let limb_scripts = (0..grouping.limb_count())
        .map(|limb_index| {
            let width = grouping.limb_digits(limb_index);
            let bias = DIGIT_BIAS * (0..width).fold(0, |value, _| value * RADIX + 1);
            script! {
                { (width - 1) as u32 } OP_ROLL
                for digit in (0..width - 1).rev() {
                    { scriptint::mul_by_constant(RADIX as u32) }
                    { (digit + 1) as u32 } OP_ROLL OP_ADD
                }
                if biased_input { { bias } OP_SUB }
                OP_TOALTSTACK
            }
        })
        .collect::<Vec<_>>();
    script! {
        for limb in limb_scripts { { limb } }
        for _ in 0..grouping.limb_count() { OP_FROMALTSTACK }
    }
}

// `x | y | h` -> `B_limbs | A_limbs | h`, consuming the two raw biased
// coordinate vectors. A=x+y and B=x-y are centered digitwise values.
fn derive_current_sum_difference_limbs(grouping: Grouping) -> Script {
    script! {
        for _ in 0..ACCUMULATOR_COUNT { OP_TOALTSTACK }

        // Consume x/y low digit first. Keep A on main stack and B on the
        // altstack, without ever duplicating a complete coordinate.
        for digit in 0..FIELD_DIGIT_COUNT {
            if digit != 0 { { digit as u32 } OP_ROLL }
            { FIELD_DIGIT_COUNT as u32 } OP_ROLL
            OP_SWAP
            OP_2DUP OP_SUB OP_TOALTSTACK
            OP_ADD { 2 * DIGIT_BIAS } OP_SUB
        }

        // A was emitted low first; reverse it to the public vector order.
        for depth in 1..FIELD_DIGIT_COUNT { { depth as u32 } OP_ROLL }
        // B was parked low first and therefore restores in public order.
        for _ in 0..FIELD_DIGIT_COUNT { OP_FROMALTSTACK }

        // Convert B, move A above it, then convert A. The relation
        // accumulator remains below these temporary altstack values.
        { centered_digits_to_limbs(grouping, false) }
        { move_block_to_top(FIELD_DIGIT_COUNT, grouping.limb_count()) }
        { centered_digits_to_limbs(grouping, false) }
        for _ in 0..ACCUMULATOR_COUNT { OP_FROMALTSTACK }
    }
}

fn apply_coordinate_formula(formula: CoordinateFormula) -> Script {
    match formula {
        CoordinateFormula::Difference => script! { OP_SUB },
        CoordinateFormula::RawSumCentered => script! {
            OP_ADD { 2 * DIGIT_BIAS } OP_SUB
        },
        CoordinateFormula::SumWithTwiceRawYCentered => script! {
            OP_DUP OP_ADD OP_ADD { 2 * DIGIT_BIAS } OP_SUB
        },
        CoordinateFormula::RestoreRawFromCenteredSum => script! {
            OP_SUB { 2 * DIGIT_BIAS } OP_ADD
        },
    }
}

// Consume the first vector while retaining the second:
// `first[50..0] | raw_y[50..0]` -> `raw_y[50..0] | result[50..0]`.
// Processing high digits first creates the result directly in public order.
fn transform_coordinate_with_raw_y(formula: CoordinateFormula) -> Script {
    script! {
        for _ in (0..FIELD_DIGIT_COUNT).rev() {
            { (2 * FIELD_DIGIT_COUNT - 1) as u32 } OP_ROLL
            { FIELD_DIGIT_COUNT as u32 } OP_PICK
            { apply_coordinate_formula(formula) }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NextLinearFormula {
    SumFromDifference,
    DifferenceFromSum,
}

// Preserve the two coordinate vectors and add their derived linear vector to
// a live accumulator. Input/output is `raw_y | derived_x | h`.
fn add_next_linear_to_accumulator(formula: NextLinearFormula) -> Script {
    let derive = match formula {
        NextLinearFormula::SumFromDifference => script! {
            // A' = B' + 2*y'_raw - 32.
            OP_DUP OP_ADD OP_ADD { 2 * DIGIT_BIAS } OP_SUB
        },
        NextLinearFormula::DifferenceFromSum => script! {
            // B' = A' - 2*y'_raw + 32.
            OP_DUP OP_ADD OP_SUB { 2 * DIGIT_BIAS } OP_ADD
        },
    };
    script! {
        for _ in 0..FIELD_DIGIT_COUNT {
            // Removing earlier accumulator coefficients keeps both operand
            // depths constant across all 51 iterations.
            { FIELD_DIGIT_COUNT as u32 } OP_PICK
            { (2 * FIELD_DIGIT_COUNT + 1) as u32 } OP_PICK
            { derive.clone() }
            OP_ADD OP_TOALTSTACK
        }
        for _ in 0..ACCUMULATOR_COUNT { OP_FROMALTSTACK }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RawCoordinateLinearFormula {
    Sum,
    Difference,
}

// Preserve raw x/y and add x+y-32 or x-y to an accumulator.
// Input/output is `x_raw | y_raw | h`.
fn add_raw_coordinate_linear_to_accumulator(formula: RawCoordinateLinearFormula) -> Script {
    let derive = match formula {
        RawCoordinateLinearFormula::Sum => script! {
            OP_ADD { 2 * DIGIT_BIAS } OP_SUB
        },
        RawCoordinateLinearFormula::Difference => script! {
            OP_SWAP OP_SUB
        },
    };
    script! {
        for _ in 0..FIELD_DIGIT_COUNT {
            { FIELD_DIGIT_COUNT as u32 } OP_PICK
            { (2 * FIELD_DIGIT_COUNT + 1) as u32 } OP_PICK
            { derive.clone() }
            OP_ADD OP_TOALTSTACK
        }
        for _ in 0..ACCUMULATOR_COUNT { OP_FROMALTSTACK }
    }
}

// `h_minus | h_plus` -> coefficient-interleaved
// `h_minus[50],h_plus[50],...,h_minus[0],h_plus[0]`.
fn interleave_relation_accumulators() -> Script {
    script! {
        for coefficient in 0..FIELD_DIGIT_COUNT {
            OP_TOALTSTACK
            { (FIELD_DIGIT_COUNT - coefficient - 1) as u32 } OP_ROLL
            OP_TOALTSTACK
        }
        for _ in 0..2 * FIELD_DIGIT_COUNT { OP_FROMALTSTACK }
    }
}

// Inverse of `interleave_relation_accumulators`.
fn deinterleave_relation_accumulators() -> Script {
    script! {
        for coefficient in 0..FIELD_DIGIT_COUNT {
            if coefficient != 0 { { coefficient as u32 } OP_ROLL }
            OP_TOALTSTACK
        }
        for _ in 0..FIELD_DIGIT_COUNT { OP_FROMALTSTACK }
    }
}

fn take_shared_tau_limb(live_coefficients: usize, scaled_by_19: bool, copy: bool) -> Script {
    let depth = 2 * FIELD_DIGIT_COUNT + 2 * live_coefficients;
    let select = if copy {
        script! { { depth as u32 } OP_PICK }
    } else {
        script! { { depth as u32 } OP_ROLL }
    };
    script! {
        { select }
        if scaled_by_19 { { scriptint::mul_by_constant(19) } }
    }
}

fn select_shared_coordinate_product(
    x_coordinate: bool,
    rhs_digit: usize,
    unprocessed_coefficients: usize,
    transient_items: usize,
) -> Script {
    let coordinate_offset = if x_coordinate { FIELD_DIGIT_COUNT } else { 0 };
    let depth =
        TABLE_SIZE + 2 * unprocessed_coefficients + coordinate_offset + rhs_digit + transient_items;
    script! {
        { depth as u32 } OP_PICK
        // A previously selected product remains above the table while the
        // second selector is evaluated, so translate the raw digit index past
        // that transient item as well as shifting its source depth.
        if transient_items != 0 { { transient_items as u32 } OP_ADD }
        OP_PICK
    }
}

// Select tau*x and tau*y once each, then route x-y to R+ and x+y to R-.
fn update_shared_relation_pair(rhs_digit: usize, unprocessed_coefficients: usize) -> Script {
    script! {
        { select_shared_coordinate_product(
            true,
            rhs_digit,
            unprocessed_coefficients,
            0,
        ) }
        { select_shared_coordinate_product(
            false,
            rhs_digit,
            unprocessed_coefficients,
            1,
        ) }

        // Retain x/y while consuming their difference into R+ first. The
        // remaining pair then sums directly for R-, avoiding an altstack
        // round trip and a swap for every coefficient update.
        OP_2DUP OP_SUB
        { (TABLE_SIZE + 3) as u32 } OP_ROLL OP_ADD OP_TOALTSTACK
        OP_ADD
        { (TABLE_SIZE + 1) as u32 } OP_ROLL OP_ADD OP_TOALTSTACK
    }
}

/// Add both tau products while constructing each signed tau-limb table once.
///
/// Input is
/// `tau_limbs[last..0] | x'[50..0] | y'[50..0] | interleaved(R-,R+)`.
/// The 17 tau limbs are consumed; x'/y' and both updated interleaved
/// accumulators remain. This has 221 local input items, no hint items, and an
/// analytic 257-item local peak. It is kept as an explicit measurement
/// boundary because table sharing may trade fewer table builds for more
/// accumulator routing bytes.
pub fn accumulate_shared_tau_relations() -> Script {
    let grouping = Grouping::Three;
    let limbs = (0..grouping.limb_count())
        .map(|limb_index| {
            let offset = grouping.limb_start(limb_index);
            let scaled = if offset == 0 {
                Script::new("no wrapped coefficients")
            } else {
                script! {
                    { take_shared_tau_limb(FIELD_DIGIT_COUNT, true, true) }
                    { build_descending_signed_table() }
                    for coefficient in 0..offset {
                        { update_shared_relation_pair(
                            FIELD_DIGIT_COUNT + coefficient - offset,
                            FIELD_DIGIT_COUNT - coefficient,
                        ) }
                    }
                    { drop_table() }
                }
            };
            script! {
                { scaled }
                { take_shared_tau_limb(FIELD_DIGIT_COUNT - offset, false, false) }
                { build_descending_signed_table() }
                for coefficient in offset..FIELD_DIGIT_COUNT {
                    { update_shared_relation_pair(
                        coefficient - offset,
                        FIELD_DIGIT_COUNT - coefficient,
                    ) }
                }
                { drop_table() }
                for _ in 0..2 * FIELD_DIGIT_COUNT { OP_FROMALTSTACK }
            }
        })
        .collect::<Vec<_>>();
    script! { for limb in limbs { { limb } } }
}

fn take_single_tau_limb(live_coefficients: usize, scaled_by_19: bool, copy: bool) -> Script {
    let depth = 2 * FIELD_DIGIT_COUNT + live_coefficients;
    let select = if copy {
        script! { { depth as u32 } OP_PICK }
    } else {
        script! { { depth as u32 } OP_ROLL }
    };
    script! {
        { select }
        if scaled_by_19 { { scriptint::mul_by_constant(19) } }
    }
}

fn select_single_coordinate_product(
    x_coordinate: bool,
    rhs_digit: usize,
    unprocessed_coefficients: usize,
    transient_items: usize,
) -> Script {
    let coordinate_offset = if x_coordinate { FIELD_DIGIT_COUNT } else { 0 };
    let depth =
        TABLE_SIZE + unprocessed_coefficients + coordinate_offset + rhs_digit + transient_items;
    script! {
        { depth as u32 } OP_PICK
        if transient_items != 0 { { transient_items as u32 } OP_ADD }
        OP_PICK
    }
}

fn select_half_table_coordinate_product(
    x_coordinate: bool,
    rhs_digit: usize,
    unprocessed_coefficients: usize,
) -> Script {
    let coordinate_offset = if x_coordinate { FIELD_DIGIT_COUNT } else { 0 };
    let depth = HALF_TABLE_SIZE + unprocessed_coefficients + coordinate_offset + rhs_digit;
    script! {
        { depth as u32 } OP_PICK
        OP_DUP { HALF_TABLE_SIZE as u32 } OP_LESSTHAN
        OP_IF
            // e in 0..15: select e*a then subtract 16a. Recover a from the
            // adjacent 15a/14a table entries without retaining a separately.
            { (HALF_TABLE_SIZE - 1) as u32 } OP_SWAP OP_SUB OP_PICK
            1 OP_PICK
            3 OP_PICK OP_SUB
            for _ in 0..4 { OP_DUP OP_ADD }
            OP_SUB
        OP_ELSE
            // e in 16..31: select (e-16)*a directly.
            { HALF_TABLE_SIZE as u32 } OP_SUB
            { (HALF_TABLE_SIZE - 1) as u32 } OP_SWAP OP_SUB OP_PICK
        OP_ENDIF
    }
}

fn update_single_tau_relation(
    rhs_digit: usize,
    unprocessed_coefficients: usize,
    sum_coordinates: bool,
    compact_table: bool,
) -> Script {
    let table_size = if compact_table {
        HALF_TABLE_SIZE
    } else {
        TABLE_SIZE
    };
    let select = |x_coordinate, unprocessed_coefficients| {
        if compact_table {
            select_half_table_coordinate_product(x_coordinate, rhs_digit, unprocessed_coefficients)
        } else {
            select_single_coordinate_product(x_coordinate, rhs_digit, unprocessed_coefficients, 0)
        }
    };
    script! {
        { select(true, unprocessed_coefficients) }
        // Consume Tx into the coefficient before selecting Ty. Keeping only
        // one selected product live at a time saves the decisive one stack
        // item in the first-transition schedule.
        { (table_size + 1) as u32 } OP_ROLL OP_ADD OP_TOALTSTACK
        { select(false, unprocessed_coefficients - 1) }
        if !sum_coordinates { OP_NEGATE }
        OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
    }
}

/// Stack-minimal single-relation tau product over raw next coordinates.
///
/// Input is `tau_limbs[16..0] | x'[50..0] | y'[50..0] | h[50..0]`.
/// The tau limbs are consumed while x'/y' and the updated accumulator remain.
/// `sum_coordinates=false` adds `tau*(x'-y')`; `true` adds
/// `tau*(x'+y'-32)`, where the constant bias cancels in the product because
/// each table lookup interprets its raw selector as a centered digit. There
/// are 170 local input items, zero hints, and at most 203 local stack items.
pub fn accumulate_single_tau_relation(sum_coordinates: bool) -> Script {
    accumulate_single_tau_relation_with_table(sum_coordinates, false)
}

fn accumulate_single_tau_relation_with_table(sum_coordinates: bool, compact_table: bool) -> Script {
    let grouping = Grouping::Three;
    let limbs = (0..grouping.limb_count())
        .map(|limb_index| {
            // The stack-minimal mixed first-transition kernel uses the
            // 16-entry half-table only while persistent state is largest:
            // three scaled passes, but just two normal passes. Each completed
            // limb removes one cached tau limb, so later passes return to the
            // byte-cheaper 32-entry table.
            let compact_scaled = compact_table && limb_index < 3;
            let compact_normal = compact_table && limb_index < 2;
            let offset = grouping.limb_start(limb_index);
            let scaled = if offset == 0 {
                Script::new("no wrapped coefficients")
            } else {
                script! {
                    { take_single_tau_limb(FIELD_DIGIT_COUNT, true, true) }
                    if compact_scaled {
                        { build_ascending_half_table() }
                    } else {
                        { build_descending_signed_table() }
                    }
                    for coefficient in 0..offset {
                        { update_single_tau_relation(
                            FIELD_DIGIT_COUNT + coefficient - offset,
                            FIELD_DIGIT_COUNT - coefficient,
                            sum_coordinates,
                            compact_scaled,
                        ) }
                    }
                    if compact_scaled { { drop_half_table() } } else { { drop_table() } }
                }
            };
            script! {
                { scaled }
                { take_single_tau_limb(FIELD_DIGIT_COUNT - offset, false, false) }
                if compact_normal {
                    { build_ascending_half_table() }
                } else {
                    { build_descending_signed_table() }
                }
                for coefficient in offset..FIELD_DIGIT_COUNT {
                    { update_single_tau_relation(
                        coefficient - offset,
                        FIELD_DIGIT_COUNT - coefficient,
                        sum_coordinates,
                        compact_normal,
                    ) }
                }
                if compact_normal { { drop_half_table() } } else { { drop_table() } }
                for _ in 0..FIELD_DIGIT_COUNT { OP_FROMALTSTACK }
            }
        })
        .collect::<Vec<_>>();
    script! { for limb in limbs { { limb } } }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackedTransitionBlock {
    XNextPacked,
    YNextPacked,
    CmPacked,
    CpPacked,
    CmDigits,
    CpDigits,
    TauPacked,
    KPacked,
    Negative,
    NonZero,
    QMinus,
    QPlus,
    QZero,
    YPacked,
    XPacked,
    XDigits,
    YDigits,
    RZeroAccumulator,
    BCurrentLimbs,
    ACurrentLimbs,
    KLimbs,
    TauLimbs,
    TauDigits,
    RPlusAccumulator,
    RMinusAccumulator,
    PairedAccumulators,
    XNextDigits,
    YNextDigits,
    BNextDigits,
    ANextDigits,
}

struct PackedTransitionLayout {
    blocks: Vec<(PackedTransitionBlock, usize)>,
}

impl PackedTransitionLayout {
    fn new(
        current_is_expanded: bool,
        k_is_direct_limbs: bool,
        constants_are_direct_digits: bool,
        signed_control: bool,
    ) -> Self {
        use PackedTransitionBlock::*;
        let mut blocks = vec![
            (XNextPacked, u5_packed::PACKED_WORD_COUNT),
            (YNextPacked, u5_packed::PACKED_WORD_COUNT),
        ];
        blocks.extend_from_slice(if constants_are_direct_digits {
            &[(CmDigits, FIELD_DIGIT_COUNT), (CpDigits, FIELD_DIGIT_COUNT)]
        } else {
            &[
                (CmPacked, u5_packed::PACKED_WORD_COUNT),
                (CpPacked, u5_packed::PACKED_WORD_COUNT),
            ]
        });
        blocks.push((TauPacked, u5_packed::PACKED_WORD_COUNT));
        blocks.push(if k_is_direct_limbs {
            (KLimbs, DIRECT_K_LIMB_COUNT)
        } else {
            (KPacked, u5_packed::PACKED_WORD_COUNT)
        });
        blocks.extend_from_slice(&[(QMinus, 1), (QPlus, 1), (QZero, 1)]);
        if current_is_expanded {
            blocks.extend_from_slice(&[(YDigits, FIELD_DIGIT_COUNT), (XDigits, FIELD_DIGIT_COUNT)]);
        } else {
            blocks.extend_from_slice(&[
                (YPacked, u5_packed::PACKED_WORD_COUNT),
                (XPacked, u5_packed::PACKED_WORD_COUNT),
            ]);
        }
        if signed_control {
            // Topmost controls are parked on altstack immediately, restoring
            // the exact unsigned main-stack layout and all of its depths.
            blocks.extend_from_slice(&[(NonZero, 1), (Negative, 1)]);
        }
        Self {
            // Bottom-to-top public witness order. Keeping x/y last lets the
            // first decoder start without routing either coordinate.
            blocks,
        }
    }

    fn items(&self) -> usize {
        self.blocks.iter().map(|(_, items)| *items).sum()
    }

    fn move_to_top(&mut self, block: PackedTransitionBlock) -> Script {
        let index = self
            .blocks
            .iter()
            .position(|(candidate, _)| *candidate == block)
            .expect("scheduled block is live");
        let (_, block_items) = self.blocks[index];
        let items_above = self.blocks[index + 1..]
            .iter()
            .map(|(_, items)| *items)
            .sum();
        let moved = move_block_to_top(block_items, items_above);
        let entry = self.blocks.remove(index);
        self.blocks.push(entry);
        moved
    }

    fn assert_suffix(&self, expected: &[(PackedTransitionBlock, usize)]) {
        assert!(
            self.blocks.ends_with(expected),
            "unexpected packed transition layout: live={:?}, expected suffix={expected:?}",
            self.blocks
        );
    }

    fn replace_suffix(
        &mut self,
        expected: &[(PackedTransitionBlock, usize)],
        replacement: &[(PackedTransitionBlock, usize)],
    ) {
        self.assert_suffix(expected);
        self.blocks.truncate(self.blocks.len() - expected.len());
        self.blocks.extend_from_slice(replacement);
    }

    fn push(&mut self, block: PackedTransitionBlock, items: usize) {
        self.blocks.push((block, items));
    }

    fn drop(&mut self, block: PackedTransitionBlock) -> Script {
        let moved = self.move_to_top(block);
        let (_, items) = self.blocks.pop().expect("moved block remains live");
        script! { { moved } { drop_top_items(items) } }
    }
}

/// Measured data-independent local combined-stack peak of the packed positive
/// transition wrapper. Preserved items below the wrapper add one-for-one.
pub const PACKED_POSITIVE_LOCAL_STACK_PEAK: u32 = 289;
pub const PACKED_POSITIVE_MAX_PRESERVED_ITEMS: u32 = 1_000 - PACKED_POSITIVE_LOCAL_STACK_PEAK;
/// Measured local peak of the first-transition sequential direct-K boundary.
pub const FIRST_SEQUENTIAL_DIRECT_K_LOCAL_STACK_PEAK: u32 = 237;
/// Mixed-negative counterpart. Its earliest scaled/normal tau passes
/// deliberately use a 16-entry half-table; later passes return to the
/// byte-cheaper 32-entry table as persistent live state falls.
pub const FIRST_SEQUENTIAL_MIXED_LOCAL_STACK_PEAK: u32 = 233;
pub const FIRST_SEQUENTIAL_MIXED_MAX_PRESERVED_ITEMS: u32 =
    1_000 - FIRST_SEQUENTIAL_MIXED_LOCAL_STACK_PEAK;
/// Measured local peak of either packed-constant shared-tau boundary.
pub const SHARED_TAU_DIRECT_K_LOCAL_STACK_PEAK: u32 = 256;
pub const SHARED_TAU_DIRECT_K_MAX_PRESERVED_ITEMS: u32 =
    1_000 - SHARED_TAU_DIRECT_K_LOCAL_STACK_PEAK;
/// Measured local peak of either chained sequential direct-K boundary.
pub const CHAINED_SEQUENTIAL_DIRECT_K_LOCAL_STACK_PEAK: u32 = 242;
/// Measured local peak when C+/C- are direct 51-digit table outputs.
pub const DIRECT_CONSTANTS_SEQUENTIAL_LOCAL_STACK_PEAK: u32 = 328;
pub const DIRECT_CONSTANTS_SHARED_LOCAL_STACK_PEAK: u32 = 329;
/// Signed controls are consumed before the packed-constant shared hot loop,
/// so its measured peak remains unchanged.
pub const SIGNED_SHARED_TAU_DIRECT_K_LOCAL_STACK_PEAK: u32 = 256;
/// Direct C+/C- keep one more selected-data item live at the measured hot
/// loop after sign/identity routing.
pub const SIGNED_DIRECT_CONSTANTS_SHARED_LOCAL_STACK_PEAK: u32 = 330;

fn packed_transition_local_stack_peak(
    current_is_expanded: bool,
    constants_are_direct_digits: bool,
    shared_tau: bool,
    sequential_relations: bool,
    mixed_negative_products: bool,
    signed_control: bool,
) -> u32 {
    if signed_control {
        return if constants_are_direct_digits {
            SIGNED_DIRECT_CONSTANTS_SHARED_LOCAL_STACK_PEAK
        } else {
            SIGNED_SHARED_TAU_DIRECT_K_LOCAL_STACK_PEAK
        };
    }
    let unsigned_peak = if constants_are_direct_digits {
        if shared_tau {
            DIRECT_CONSTANTS_SHARED_LOCAL_STACK_PEAK
        } else if sequential_relations {
            DIRECT_CONSTANTS_SEQUENTIAL_LOCAL_STACK_PEAK
        } else {
            PACKED_POSITIVE_LOCAL_STACK_PEAK
        }
    } else if shared_tau {
        SHARED_TAU_DIRECT_K_LOCAL_STACK_PEAK
    } else if sequential_relations && current_is_expanded {
        CHAINED_SEQUENTIAL_DIRECT_K_LOCAL_STACK_PEAK
    } else if sequential_relations && mixed_negative_products {
        FIRST_SEQUENTIAL_MIXED_LOCAL_STACK_PEAK
    } else if sequential_relations {
        FIRST_SEQUENTIAL_DIRECT_K_LOCAL_STACK_PEAK
    } else {
        PACKED_POSITIVE_LOCAL_STACK_PEAK
    };
    unsigned_peak
}

fn packed_positive_transition_script(
    preserved_items: u32,
    current_is_expanded: bool,
    k_is_direct_limbs: bool,
    constants_are_direct_digits: bool,
    packed_output: bool,
    shared_tau: bool,
    sequential_relations: bool,
    mixed_negative_products: bool,
    signed_control: bool,
) -> Script {
    use PackedTransitionBlock::*;

    let local_stack_peak = packed_transition_local_stack_peak(
        current_is_expanded,
        constants_are_direct_digits,
        shared_tau,
        sequential_relations,
        mixed_negative_products,
        signed_control,
    );
    assert!(
        preserved_items <= 1_000 - local_stack_peak,
        "packed positive Ed25519 transition exceeds the 1,000-item stack limit"
    );
    assert!(
        !(shared_tau && sequential_relations),
        "shared-tau and sequential-relation schedules are distinct"
    );
    assert!(
        !signed_control || shared_tau,
        "signed/identity control currently requires the shared-tau schedule"
    );
    let negative_grouping = if mixed_negative_products {
        Grouping::MixedRZero
    } else {
        Grouping::Three
    };
    let mut layout = PackedTransitionLayout::new(
        current_is_expanded,
        k_is_direct_limbs,
        constants_are_direct_digits,
        signed_control,
    );
    let current_items = if current_is_expanded {
        2 * FIELD_DIGIT_COUNT
    } else {
        2 * u5_packed::PACKED_WORD_COUNT
    };
    let k_items = if k_is_direct_limbs {
        DIRECT_K_LIMB_COUNT
    } else {
        u5_packed::PACKED_WORD_COUNT
    };
    let constant_items = if constants_are_direct_digits {
        2 * FIELD_DIGIT_COUNT
    } else {
        2 * u5_packed::PACKED_WORD_COUNT
    };
    let expected_input_items = current_items
        + 3 * u5_packed::PACKED_WORD_COUNT
        + k_items
        + constant_items
        + 2 * usize::from(signed_control)
        + HINT_ITEM_COUNT;
    assert_eq!(layout.items(), expected_input_items,);
    let mut steps = Vec::new();
    if signed_control {
        // Input ends in `nonzero | negative`. Pop negative first, then
        // nonzero, so OP_FROMALTSTACK retrieves nonzero for R0 and negative
        // later for tau routing. Every nested fragment balances altstack.
        steps.push(script! { OP_TOALTSTACK OP_TOALTSTACK });
        layout.replace_suffix(&[(NonZero, 1), (Negative, 1)], &[]);
    }

    let decode = |layout: &mut PackedTransitionLayout,
                  packed: PackedTransitionBlock,
                  digits: PackedTransitionBlock,
                  steps: &mut Vec<Script>| {
        steps.push(layout.move_to_top(packed));
        let below = usize::try_from(preserved_items).expect("u32 fits usize") + layout.items()
            - u5_packed::PACKED_WORD_COUNT;
        steps.push(u5_packed::decode_fast(
            u32::try_from(below).expect("packed decoder preserved count fits u32"),
        ));
        layout.replace_suffix(
            &[(packed, u5_packed::PACKED_WORD_COUNT)],
            &[(digits, FIELD_DIGIT_COUNT)],
        );
    };
    let decode_preserving = |layout: &mut PackedTransitionLayout,
                             packed: PackedTransitionBlock,
                             digits: PackedTransitionBlock,
                             steps: &mut Vec<Script>| {
        steps.push(layout.move_to_top(packed));
        let below = usize::try_from(preserved_items).expect("u32 fits usize") + layout.items()
            - u5_packed::PACKED_WORD_COUNT;
        steps.push(u5_packed::decode_fast_preserving(
            u32::try_from(below).expect("packed decoder preserved count fits u32"),
        ));
        layout.replace_suffix(
            &[(packed, u5_packed::PACKED_WORD_COUNT)],
            &[
                (packed, u5_packed::PACKED_WORD_COUNT),
                (digits, FIELD_DIGIT_COUNT),
            ],
        );
    };

    if sequential_relations && !current_is_expanded {
        // R0 is deliberately evaluated K*tau first. Retaining only tau's
        // eight packed words while x/y expand avoids ever co-locating three
        // full 51-digit fields at the R0 table peak.
        if k_is_direct_limbs {
            steps.push(layout.move_to_top(KLimbs));
        } else {
            decode(&mut layout, KPacked, XDigits, &mut steps);
            steps.push(centered_digits_to_limbs(Grouping::Four, true));
            layout.replace_suffix(
                &[(XDigits, FIELD_DIGIT_COUNT)],
                &[(KLimbs, Grouping::Four.limb_count())],
            );
        }
        decode_preserving(&mut layout, TauPacked, TauDigits, &mut steps);
        steps.push(push_relation_accumulator());
        layout.push(RZeroAccumulator, ACCUMULATOR_COUNT);
        steps.push(layout.move_to_top(QZero));
        steps.push(layout.move_to_top(RZeroAccumulator));
        layout.assert_suffix(&[(QZero, 1), (RZeroAccumulator, ACCUMULATOR_COUNT)]);
        steps.push(absorb_relation_quotient());
        layout.replace_suffix(
            &[(QZero, 1), (RZeroAccumulator, ACCUMULATOR_COUNT)],
            &[(RZeroAccumulator, ACCUMULATOR_COUNT)],
        );
        steps.push(layout.move_to_top(KLimbs));
        steps.push(layout.move_to_top(TauDigits));
        steps.push(layout.move_to_top(RZeroAccumulator));
        layout.assert_suffix(&[
            (KLimbs, Grouping::Four.limb_count()),
            (TauDigits, FIELD_DIGIT_COUNT),
            (RZeroAccumulator, ACCUMULATOR_COUNT),
        ]);
        steps.push(accumulate_streamed_limb_product_grouping(
            Grouping::Four,
            true,
            false,
        ));
        layout.replace_suffix(
            &[
                (KLimbs, Grouping::Four.limb_count()),
                (TauDigits, FIELD_DIGIT_COUNT),
                (RZeroAccumulator, ACCUMULATOR_COUNT),
            ],
            &[(RZeroAccumulator, ACCUMULATOR_COUNT)],
        );

        if !current_is_expanded {
            decode(&mut layout, XPacked, XDigits, &mut steps);
            decode(&mut layout, YPacked, YDigits, &mut steps);
        } else {
            steps.push(layout.move_to_top(XDigits));
            steps.push(layout.move_to_top(YDigits));
        }
        steps.push(layout.move_to_top(RZeroAccumulator));
        if signed_control {
            steps.push(script! { OP_FROMALTSTACK });
            layout.push(NonZero, 1);
            layout.assert_suffix(&[
                (XDigits, FIELD_DIGIT_COUNT),
                (YDigits, FIELD_DIGIT_COUNT),
                (RZeroAccumulator, ACCUMULATOR_COUNT),
                (NonZero, 1),
            ]);
            steps.push(accumulate_r0_xy_if_nonzero());
            layout.replace_suffix(
                &[
                    (XDigits, FIELD_DIGIT_COUNT),
                    (YDigits, FIELD_DIGIT_COUNT),
                    (RZeroAccumulator, ACCUMULATOR_COUNT),
                    (NonZero, 1),
                ],
                &[
                    (XDigits, FIELD_DIGIT_COUNT),
                    (YDigits, FIELD_DIGIT_COUNT),
                    (RZeroAccumulator, ACCUMULATOR_COUNT),
                ],
            );
        } else {
            layout.assert_suffix(&[
                (XDigits, FIELD_DIGIT_COUNT),
                (YDigits, FIELD_DIGIT_COUNT),
                (RZeroAccumulator, ACCUMULATOR_COUNT),
            ]);
            steps.push(accumulate_streamed_product_preserving_grouping(
                false,
                Grouping::Three,
                false,
            ));
        }
        steps.push(derive_current_sum_difference_limbs(negative_grouping));
        layout.replace_suffix(
            &[
                (XDigits, FIELD_DIGIT_COUNT),
                (YDigits, FIELD_DIGIT_COUNT),
                (RZeroAccumulator, ACCUMULATOR_COUNT),
            ],
            &[
                (BCurrentLimbs, negative_grouping.limb_count()),
                (ACurrentLimbs, negative_grouping.limb_count()),
                (RZeroAccumulator, ACCUMULATOR_COUNT),
            ],
        );
        steps.push(verify_streamed_relation_absorbed());
        layout.replace_suffix(&[(RZeroAccumulator, ACCUMULATOR_COUNT)], &[]);

        // Decode tau a second time and collapse it immediately to 17 limbs;
        // the packed copy is retained for R-.
        decode_preserving(&mut layout, TauPacked, TauDigits, &mut steps);
        steps.push(layout.move_to_top(TauDigits));
        steps.push(centered_digits_to_limbs(Grouping::Three, true));
        layout.replace_suffix(
            &[(TauDigits, FIELD_DIGIT_COUNT)],
            &[(TauLimbs, Grouping::Three.limb_count())],
        );
    } else {
        if !current_is_expanded {
            decode(&mut layout, XPacked, XDigits, &mut steps);
            decode(&mut layout, YPacked, YDigits, &mut steps);
        } else {
            steps.push(layout.move_to_top(YDigits));
        }
        steps.push(push_relation_accumulator());
        layout.push(RZeroAccumulator, ACCUMULATOR_COUNT);
        if sequential_relations {
            steps.push(layout.move_to_top(QZero));
            steps.push(layout.move_to_top(RZeroAccumulator));
            layout.assert_suffix(&[(QZero, 1), (RZeroAccumulator, ACCUMULATOR_COUNT)]);
            steps.push(absorb_relation_quotient());
            layout.replace_suffix(
                &[(QZero, 1), (RZeroAccumulator, ACCUMULATOR_COUNT)],
                &[(RZeroAccumulator, ACCUMULATOR_COUNT)],
            );
            steps.push(layout.move_to_top(XDigits));
            steps.push(layout.move_to_top(YDigits));
            steps.push(layout.move_to_top(RZeroAccumulator));
        }
        if signed_control {
            steps.push(script! { OP_FROMALTSTACK });
            layout.push(NonZero, 1);
            layout.assert_suffix(&[
                (XDigits, FIELD_DIGIT_COUNT),
                (YDigits, FIELD_DIGIT_COUNT),
                (RZeroAccumulator, ACCUMULATOR_COUNT),
                (NonZero, 1),
            ]);
            steps.push(accumulate_r0_xy_if_nonzero());
            layout.replace_suffix(
                &[
                    (XDigits, FIELD_DIGIT_COUNT),
                    (YDigits, FIELD_DIGIT_COUNT),
                    (RZeroAccumulator, ACCUMULATOR_COUNT),
                    (NonZero, 1),
                ],
                &[
                    (XDigits, FIELD_DIGIT_COUNT),
                    (YDigits, FIELD_DIGIT_COUNT),
                    (RZeroAccumulator, ACCUMULATOR_COUNT),
                ],
            );
        } else {
            layout.assert_suffix(&[
                (XDigits, FIELD_DIGIT_COUNT),
                (YDigits, FIELD_DIGIT_COUNT),
                (RZeroAccumulator, ACCUMULATOR_COUNT),
            ]);
            steps.push(accumulate_streamed_product_preserving_grouping(
                false,
                Grouping::Three,
                false,
            ));
        }
        steps.push(derive_current_sum_difference_limbs(negative_grouping));
        layout.replace_suffix(
            &[
                (XDigits, FIELD_DIGIT_COUNT),
                (YDigits, FIELD_DIGIT_COUNT),
                (RZeroAccumulator, ACCUMULATOR_COUNT),
            ],
            &[
                (BCurrentLimbs, negative_grouping.limb_count()),
                (ACurrentLimbs, negative_grouping.limb_count()),
                (RZeroAccumulator, ACCUMULATOR_COUNT),
            ],
        );

        if k_is_direct_limbs {
            steps.push(layout.move_to_top(KLimbs));
        } else {
            decode(&mut layout, KPacked, XDigits, &mut steps);
            steps.push(centered_digits_to_limbs(Grouping::Four, true));
            layout.replace_suffix(
                &[(XDigits, FIELD_DIGIT_COUNT)],
                &[(KLimbs, Grouping::Four.limb_count())],
            );
        }
        if sequential_relations {
            decode_preserving(&mut layout, TauPacked, TauDigits, &mut steps);
            steps.push(layout.move_to_top(KLimbs));
            steps.push(layout.move_to_top(TauDigits));
        } else {
            decode(&mut layout, TauPacked, TauDigits, &mut steps);
        }
        steps.push(layout.move_to_top(RZeroAccumulator));
        layout.assert_suffix(&[
            (KLimbs, Grouping::Four.limb_count()),
            (TauDigits, FIELD_DIGIT_COUNT),
            (RZeroAccumulator, ACCUMULATOR_COUNT),
        ]);
        steps.push(accumulate_streamed_limb_product_grouping(
            Grouping::Four,
            true,
            !sequential_relations,
        ));
        if sequential_relations {
            layout.replace_suffix(
                &[
                    (KLimbs, Grouping::Four.limb_count()),
                    (TauDigits, FIELD_DIGIT_COUNT),
                    (RZeroAccumulator, ACCUMULATOR_COUNT),
                ],
                &[(RZeroAccumulator, ACCUMULATOR_COUNT)],
            );
            steps.push(verify_streamed_relation_absorbed());
            layout.replace_suffix(&[(RZeroAccumulator, ACCUMULATOR_COUNT)], &[]);
            decode_preserving(&mut layout, TauPacked, TauDigits, &mut steps);
            steps.push(layout.move_to_top(TauDigits));
            steps.push(centered_digits_to_limbs(Grouping::Three, true));
            layout.replace_suffix(
                &[(TauDigits, FIELD_DIGIT_COUNT)],
                &[(TauLimbs, Grouping::Three.limb_count())],
            );
        } else {
            layout.replace_suffix(
                &[
                    (KLimbs, Grouping::Four.limb_count()),
                    (TauDigits, FIELD_DIGIT_COUNT),
                    (RZeroAccumulator, ACCUMULATOR_COUNT),
                ],
                &[
                    (TauDigits, FIELD_DIGIT_COUNT),
                    (RZeroAccumulator, ACCUMULATOR_COUNT),
                ],
            );
            steps.push(layout.move_to_top(QZero));
            steps.push(layout.move_to_top(RZeroAccumulator));
            layout.assert_suffix(&[(QZero, 1), (RZeroAccumulator, ACCUMULATOR_COUNT)]);
            steps.push(verify_streamed_relation(false));
            layout.replace_suffix(&[(QZero, 1), (RZeroAccumulator, ACCUMULATOR_COUNT)], &[]);
        }
    }

    if shared_tau {
        // Tau is not needed by the cached negative products. Collapse it as
        // soon as R0 closes so those product tables also avoid carrying 34
        // unnecessary digit items.
        steps.push(layout.move_to_top(TauDigits));
        steps.push(centered_digits_to_limbs(Grouping::Three, true));
        layout.replace_suffix(
            &[(TauDigits, FIELD_DIGIT_COUNT)],
            &[(TauLimbs, Grouping::Three.limb_count())],
        );
        if signed_control {
            steps.push(script! { OP_FROMALTSTACK });
            layout.push(Negative, 1);
            layout.assert_suffix(&[(TauLimbs, Grouping::Three.limb_count()), (Negative, 1)]);
            steps.push(conditionally_negate_top_items(Grouping::Three.limb_count()));
            layout.replace_suffix(
                &[(TauLimbs, Grouping::Three.limb_count()), (Negative, 1)],
                &[(TauLimbs, Grouping::Three.limb_count())],
            );
        }
    }

    if !sequential_relations {
        // Build -B*C- early. Its accumulator stays compact while the next
        // point is decoded in the byte-minimized schedules.
        steps.push(layout.move_to_top(BCurrentLimbs));
        if constants_are_direct_digits {
            steps.push(layout.move_to_top(CmDigits));
        } else {
            decode(&mut layout, CmPacked, CmDigits, &mut steps);
        }
        steps.push(push_relation_accumulator());
        layout.push(RMinusAccumulator, ACCUMULATOR_COUNT);
        layout.assert_suffix(&[
            (BCurrentLimbs, negative_grouping.limb_count()),
            (CmDigits, FIELD_DIGIT_COUNT),
            (RMinusAccumulator, ACCUMULATOR_COUNT),
        ]);
        steps.push(accumulate_streamed_limb_product_grouping(
            negative_grouping,
            true,
            false,
        ));
        layout.replace_suffix(
            &[
                (BCurrentLimbs, negative_grouping.limb_count()),
                (CmDigits, FIELD_DIGIT_COUNT),
                (RMinusAccumulator, ACCUMULATOR_COUNT),
            ],
            &[(RMinusAccumulator, ACCUMULATOR_COUNT)],
        );
        steps.push(layout.move_to_top(QMinus));
        steps.push(layout.move_to_top(RMinusAccumulator));
        layout.assert_suffix(&[(QMinus, 1), (RMinusAccumulator, ACCUMULATOR_COUNT)]);
        steps.push(absorb_relation_quotient());
        layout.replace_suffix(
            &[(QMinus, 1), (RMinusAccumulator, ACCUMULATOR_COUNT)],
            &[(RMinusAccumulator, ACCUMULATOR_COUNT)],
        );
    }

    steps.push(layout.move_to_top(ACurrentLimbs));
    if constants_are_direct_digits {
        steps.push(layout.move_to_top(CpDigits));
    } else {
        decode(&mut layout, CpPacked, CpDigits, &mut steps);
    }
    steps.push(push_relation_accumulator());
    layout.push(RPlusAccumulator, ACCUMULATOR_COUNT);
    layout.assert_suffix(&[
        (ACurrentLimbs, negative_grouping.limb_count()),
        (CpDigits, FIELD_DIGIT_COUNT),
        (RPlusAccumulator, ACCUMULATOR_COUNT),
    ]);
    steps.push(accumulate_streamed_limb_product_grouping(
        negative_grouping,
        true,
        false,
    ));
    layout.replace_suffix(
        &[
            (ACurrentLimbs, negative_grouping.limb_count()),
            (CpDigits, FIELD_DIGIT_COUNT),
            (RPlusAccumulator, ACCUMULATOR_COUNT),
        ],
        &[(RPlusAccumulator, ACCUMULATOR_COUNT)],
    );
    steps.push(layout.move_to_top(QPlus));
    steps.push(layout.move_to_top(RPlusAccumulator));
    layout.assert_suffix(&[(QPlus, 1), (RPlusAccumulator, ACCUMULATOR_COUNT)]);
    steps.push(absorb_relation_quotient());
    layout.replace_suffix(
        &[(QPlus, 1), (RPlusAccumulator, ACCUMULATOR_COUNT)],
        &[(RPlusAccumulator, ACCUMULATOR_COUNT)],
    );

    decode(&mut layout, XNextPacked, XNextDigits, &mut steps);
    decode(&mut layout, YNextPacked, YNextDigits, &mut steps);
    layout.assert_suffix(&[
        (XNextDigits, FIELD_DIGIT_COUNT),
        (YNextDigits, FIELD_DIGIT_COUNT),
    ]);

    if shared_tau {
        // Add A'=x'+y' and B'=x'-y' directly from the certified raw
        // coordinates, preserving both vectors for the paired tau product.
        steps.push(layout.move_to_top(XNextDigits));
        steps.push(layout.move_to_top(YNextDigits));
        steps.push(layout.move_to_top(RPlusAccumulator));
        layout.assert_suffix(&[
            (XNextDigits, FIELD_DIGIT_COUNT),
            (YNextDigits, FIELD_DIGIT_COUNT),
            (RPlusAccumulator, ACCUMULATOR_COUNT),
        ]);
        steps.push(add_raw_coordinate_linear_to_accumulator(
            RawCoordinateLinearFormula::Sum,
        ));

        steps.push(layout.move_to_top(XNextDigits));
        steps.push(layout.move_to_top(YNextDigits));
        steps.push(layout.move_to_top(RMinusAccumulator));
        layout.assert_suffix(&[
            (XNextDigits, FIELD_DIGIT_COUNT),
            (YNextDigits, FIELD_DIGIT_COUNT),
            (RMinusAccumulator, ACCUMULATOR_COUNT),
        ]);
        steps.push(add_raw_coordinate_linear_to_accumulator(
            RawCoordinateLinearFormula::Difference,
        ));

        // Pair corresponding coefficients so each selected tau*x'/tau*y'
        // value can update both relations without moving a 51-item block.
        steps.push(layout.move_to_top(RMinusAccumulator));
        steps.push(layout.move_to_top(RPlusAccumulator));
        layout.assert_suffix(&[
            (RMinusAccumulator, ACCUMULATOR_COUNT),
            (RPlusAccumulator, ACCUMULATOR_COUNT),
        ]);
        steps.push(interleave_relation_accumulators());
        layout.replace_suffix(
            &[
                (RMinusAccumulator, ACCUMULATOR_COUNT),
                (RPlusAccumulator, ACCUMULATOR_COUNT),
            ],
            &[(PairedAccumulators, 2 * ACCUMULATOR_COUNT)],
        );

        steps.push(layout.move_to_top(TauLimbs));
        steps.push(layout.move_to_top(XNextDigits));
        steps.push(layout.move_to_top(YNextDigits));
        steps.push(layout.move_to_top(PairedAccumulators));
        layout.assert_suffix(&[
            (TauLimbs, Grouping::Three.limb_count()),
            (XNextDigits, FIELD_DIGIT_COUNT),
            (YNextDigits, FIELD_DIGIT_COUNT),
            (PairedAccumulators, 2 * ACCUMULATOR_COUNT),
        ]);
        steps.push(accumulate_shared_tau_relations());
        layout.replace_suffix(
            &[
                (TauLimbs, Grouping::Three.limb_count()),
                (XNextDigits, FIELD_DIGIT_COUNT),
                (YNextDigits, FIELD_DIGIT_COUNT),
                (PairedAccumulators, 2 * ACCUMULATOR_COUNT),
            ],
            &[
                (XNextDigits, FIELD_DIGIT_COUNT),
                (YNextDigits, FIELD_DIGIT_COUNT),
                (PairedAccumulators, 2 * ACCUMULATOR_COUNT),
            ],
        );
        steps.push(deinterleave_relation_accumulators());
        layout.replace_suffix(
            &[(PairedAccumulators, 2 * ACCUMULATOR_COUNT)],
            &[
                (RMinusAccumulator, ACCUMULATOR_COUNT),
                (RPlusAccumulator, ACCUMULATOR_COUNT),
            ],
        );
        steps.push(verify_streamed_relation_absorbed());
        layout.replace_suffix(&[(RPlusAccumulator, ACCUMULATOR_COUNT)], &[]);
        steps.push(verify_streamed_relation_absorbed());
        layout.replace_suffix(&[(RMinusAccumulator, ACCUMULATOR_COUNT)], &[]);

        // Normalize to the common output boundary `y' | x'`.
        steps.push(layout.move_to_top(XNextDigits));
        layout.assert_suffix(&[
            (YNextDigits, FIELD_DIGIT_COUNT),
            (XNextDigits, FIELD_DIGIT_COUNT),
        ]);
    } else if sequential_relations {
        // Complete R+ from raw next coordinates with tau held in 17 limbs,
        // then collapse the next point back to its packed representation
        // before allocating R-. This deliberately spends two encoders and a
        // second decode to minimize the full-trace stack peak.
        steps.push(layout.move_to_top(XNextDigits));
        steps.push(layout.move_to_top(YNextDigits));
        steps.push(layout.move_to_top(RPlusAccumulator));
        layout.assert_suffix(&[
            (XNextDigits, FIELD_DIGIT_COUNT),
            (YNextDigits, FIELD_DIGIT_COUNT),
            (RPlusAccumulator, ACCUMULATOR_COUNT),
        ]);
        steps.push(add_raw_coordinate_linear_to_accumulator(
            RawCoordinateLinearFormula::Sum,
        ));
        steps.push(layout.move_to_top(TauLimbs));
        steps.push(layout.move_to_top(XNextDigits));
        steps.push(layout.move_to_top(YNextDigits));
        steps.push(layout.move_to_top(RPlusAccumulator));
        layout.assert_suffix(&[
            (TauLimbs, Grouping::Three.limb_count()),
            (XNextDigits, FIELD_DIGIT_COUNT),
            (YNextDigits, FIELD_DIGIT_COUNT),
            (RPlusAccumulator, ACCUMULATOR_COUNT),
        ]);
        let compact_first_transition = mixed_negative_products && !current_is_expanded;
        steps.push(accumulate_single_tau_relation_with_table(
            false,
            compact_first_transition,
        ));
        layout.replace_suffix(
            &[
                (TauLimbs, Grouping::Three.limb_count()),
                (XNextDigits, FIELD_DIGIT_COUNT),
                (YNextDigits, FIELD_DIGIT_COUNT),
                (RPlusAccumulator, ACCUMULATOR_COUNT),
            ],
            &[
                (XNextDigits, FIELD_DIGIT_COUNT),
                (YNextDigits, FIELD_DIGIT_COUNT),
                (RPlusAccumulator, ACCUMULATOR_COUNT),
            ],
        );
        steps.push(verify_streamed_relation_absorbed());
        layout.replace_suffix(&[(RPlusAccumulator, ACCUMULATOR_COUNT)], &[]);

        steps.push(layout.move_to_top(XNextDigits));
        let encode_x_preserved = usize::try_from(preserved_items).expect("u32 fits usize")
            + layout.items()
            - FIELD_DIGIT_COUNT;
        steps.push(u5_packed::encode_certified(
            u32::try_from(encode_x_preserved).expect("encoder preserved count fits u32"),
        ));
        layout.replace_suffix(
            &[(XNextDigits, FIELD_DIGIT_COUNT)],
            &[(XNextPacked, u5_packed::PACKED_WORD_COUNT)],
        );
        steps.push(layout.move_to_top(YNextDigits));
        let encode_y_preserved = usize::try_from(preserved_items).expect("u32 fits usize")
            + layout.items()
            - FIELD_DIGIT_COUNT;
        steps.push(u5_packed::encode_certified(
            u32::try_from(encode_y_preserved).expect("encoder preserved count fits u32"),
        ));
        layout.replace_suffix(
            &[(YNextDigits, FIELD_DIGIT_COUNT)],
            &[(YNextPacked, u5_packed::PACKED_WORD_COUNT)],
        );

        steps.push(layout.move_to_top(BCurrentLimbs));
        if constants_are_direct_digits {
            steps.push(layout.move_to_top(CmDigits));
        } else {
            decode(&mut layout, CmPacked, CmDigits, &mut steps);
        }
        steps.push(push_relation_accumulator());
        layout.push(RMinusAccumulator, ACCUMULATOR_COUNT);
        layout.assert_suffix(&[
            (BCurrentLimbs, negative_grouping.limb_count()),
            (CmDigits, FIELD_DIGIT_COUNT),
            (RMinusAccumulator, ACCUMULATOR_COUNT),
        ]);
        steps.push(accumulate_streamed_limb_product_grouping(
            negative_grouping,
            true,
            false,
        ));
        layout.replace_suffix(
            &[
                (BCurrentLimbs, negative_grouping.limb_count()),
                (CmDigits, FIELD_DIGIT_COUNT),
                (RMinusAccumulator, ACCUMULATOR_COUNT),
            ],
            &[(RMinusAccumulator, ACCUMULATOR_COUNT)],
        );
        steps.push(layout.move_to_top(QMinus));
        steps.push(layout.move_to_top(RMinusAccumulator));
        layout.assert_suffix(&[(QMinus, 1), (RMinusAccumulator, ACCUMULATOR_COUNT)]);
        steps.push(absorb_relation_quotient());
        layout.replace_suffix(
            &[(QMinus, 1), (RMinusAccumulator, ACCUMULATOR_COUNT)],
            &[(RMinusAccumulator, ACCUMULATOR_COUNT)],
        );

        decode(&mut layout, TauPacked, TauDigits, &mut steps);
        steps.push(centered_digits_to_limbs(Grouping::Three, true));
        layout.replace_suffix(
            &[(TauDigits, FIELD_DIGIT_COUNT)],
            &[(TauLimbs, Grouping::Three.limb_count())],
        );
        decode(&mut layout, XNextPacked, XNextDigits, &mut steps);
        decode(&mut layout, YNextPacked, YNextDigits, &mut steps);
        steps.push(layout.move_to_top(XNextDigits));
        steps.push(layout.move_to_top(YNextDigits));
        steps.push(layout.move_to_top(RMinusAccumulator));
        layout.assert_suffix(&[
            (XNextDigits, FIELD_DIGIT_COUNT),
            (YNextDigits, FIELD_DIGIT_COUNT),
            (RMinusAccumulator, ACCUMULATOR_COUNT),
        ]);
        steps.push(add_raw_coordinate_linear_to_accumulator(
            RawCoordinateLinearFormula::Difference,
        ));
        steps.push(layout.move_to_top(TauLimbs));
        steps.push(layout.move_to_top(XNextDigits));
        steps.push(layout.move_to_top(YNextDigits));
        steps.push(layout.move_to_top(RMinusAccumulator));
        layout.assert_suffix(&[
            (TauLimbs, Grouping::Three.limb_count()),
            (XNextDigits, FIELD_DIGIT_COUNT),
            (YNextDigits, FIELD_DIGIT_COUNT),
            (RMinusAccumulator, ACCUMULATOR_COUNT),
        ]);
        steps.push(accumulate_single_tau_relation_with_table(true, false));
        layout.replace_suffix(
            &[
                (TauLimbs, Grouping::Three.limb_count()),
                (XNextDigits, FIELD_DIGIT_COUNT),
                (YNextDigits, FIELD_DIGIT_COUNT),
                (RMinusAccumulator, ACCUMULATOR_COUNT),
            ],
            &[
                (XNextDigits, FIELD_DIGIT_COUNT),
                (YNextDigits, FIELD_DIGIT_COUNT),
                (RMinusAccumulator, ACCUMULATOR_COUNT),
            ],
        );
        steps.push(verify_streamed_relation_absorbed());
        layout.replace_suffix(&[(RMinusAccumulator, ACCUMULATOR_COUNT)], &[]);
        steps.push(layout.move_to_top(XNextDigits));
        layout.assert_suffix(&[
            (YNextDigits, FIELD_DIGIT_COUNT),
            (XNextDigits, FIELD_DIGIT_COUNT),
        ]);
    } else {
        steps.push(transform_coordinate_with_raw_y(
            CoordinateFormula::Difference,
        ));
        layout.replace_suffix(
            &[
                (XNextDigits, FIELD_DIGIT_COUNT),
                (YNextDigits, FIELD_DIGIT_COUNT),
            ],
            &[
                (YNextDigits, FIELD_DIGIT_COUNT),
                (BNextDigits, FIELD_DIGIT_COUNT),
            ],
        );

        steps.push(layout.move_to_top(RPlusAccumulator));
        layout.assert_suffix(&[
            (YNextDigits, FIELD_DIGIT_COUNT),
            (BNextDigits, FIELD_DIGIT_COUNT),
            (RPlusAccumulator, ACCUMULATOR_COUNT),
        ]);
        steps.push(add_next_linear_to_accumulator(
            NextLinearFormula::SumFromDifference,
        ));
        steps.push(layout.move_to_top(BNextDigits));
        steps.push(layout.move_to_top(TauDigits));
        steps.push(layout.move_to_top(RPlusAccumulator));
        layout.assert_suffix(&[
            (BNextDigits, FIELD_DIGIT_COUNT),
            (TauDigits, FIELD_DIGIT_COUNT),
            (RPlusAccumulator, ACCUMULATOR_COUNT),
        ]);
        steps.push(accumulate_streamed_product_preserving_grouping(
            true,
            Grouping::Three,
            false,
        ));
        steps.push(verify_streamed_relation_absorbed());
        layout.replace_suffix(&[(RPlusAccumulator, ACCUMULATOR_COUNT)], &[]);

        if sequential_relations {
            // The first decoders retained the packed next point. Discard its
            // expanded R+ working copy before allocating R-, then decode the
            // same certified packed words again. This is intentionally a
            // byte-for-stack trade used only while the global trace is full.
            steps.push(layout.drop(BNextDigits));
            steps.push(layout.drop(YNextDigits));

            steps.push(layout.move_to_top(BCurrentLimbs));
            if constants_are_direct_digits {
                steps.push(layout.move_to_top(CmDigits));
            } else {
                decode(&mut layout, CmPacked, CmDigits, &mut steps);
            }
            steps.push(push_relation_accumulator());
            layout.push(RMinusAccumulator, ACCUMULATOR_COUNT);
            layout.assert_suffix(&[
                (BCurrentLimbs, negative_grouping.limb_count()),
                (CmDigits, FIELD_DIGIT_COUNT),
                (RMinusAccumulator, ACCUMULATOR_COUNT),
            ]);
            steps.push(accumulate_streamed_limb_product_grouping(
                negative_grouping,
                true,
                false,
            ));
            layout.replace_suffix(
                &[
                    (BCurrentLimbs, negative_grouping.limb_count()),
                    (CmDigits, FIELD_DIGIT_COUNT),
                    (RMinusAccumulator, ACCUMULATOR_COUNT),
                ],
                &[(RMinusAccumulator, ACCUMULATOR_COUNT)],
            );
            steps.push(layout.move_to_top(QMinus));
            steps.push(layout.move_to_top(RMinusAccumulator));
            layout.assert_suffix(&[(QMinus, 1), (RMinusAccumulator, ACCUMULATOR_COUNT)]);
            steps.push(absorb_relation_quotient());
            layout.replace_suffix(
                &[(QMinus, 1), (RMinusAccumulator, ACCUMULATOR_COUNT)],
                &[(RMinusAccumulator, ACCUMULATOR_COUNT)],
            );

            decode(&mut layout, XNextPacked, XNextDigits, &mut steps);
            decode(&mut layout, YNextPacked, YNextDigits, &mut steps);
            steps.push(layout.move_to_top(XNextDigits));
            steps.push(layout.move_to_top(YNextDigits));
            layout.assert_suffix(&[
                (XNextDigits, FIELD_DIGIT_COUNT),
                (YNextDigits, FIELD_DIGIT_COUNT),
            ]);
            steps.push(transform_coordinate_with_raw_y(
                CoordinateFormula::RawSumCentered,
            ));
            layout.replace_suffix(
                &[
                    (XNextDigits, FIELD_DIGIT_COUNT),
                    (YNextDigits, FIELD_DIGIT_COUNT),
                ],
                &[
                    (YNextDigits, FIELD_DIGIT_COUNT),
                    (ANextDigits, FIELD_DIGIT_COUNT),
                ],
            );
        } else {
            // B' + 2*y'_centered is A'. This single in-place pass replaces
            // the restore-X-then-form-A pair of passes.
            steps.push(layout.move_to_top(BNextDigits));
            steps.push(layout.move_to_top(YNextDigits));
            layout.assert_suffix(&[
                (BNextDigits, FIELD_DIGIT_COUNT),
                (YNextDigits, FIELD_DIGIT_COUNT),
            ]);
            steps.push(transform_coordinate_with_raw_y(
                CoordinateFormula::SumWithTwiceRawYCentered,
            ));
            layout.replace_suffix(
                &[
                    (BNextDigits, FIELD_DIGIT_COUNT),
                    (YNextDigits, FIELD_DIGIT_COUNT),
                ],
                &[
                    (YNextDigits, FIELD_DIGIT_COUNT),
                    (ANextDigits, FIELD_DIGIT_COUNT),
                ],
            );
        }

        steps.push(layout.move_to_top(RMinusAccumulator));
        layout.assert_suffix(&[
            (YNextDigits, FIELD_DIGIT_COUNT),
            (ANextDigits, FIELD_DIGIT_COUNT),
            (RMinusAccumulator, ACCUMULATOR_COUNT),
        ]);
        steps.push(add_next_linear_to_accumulator(
            NextLinearFormula::DifferenceFromSum,
        ));
        steps.push(layout.move_to_top(ANextDigits));
        steps.push(layout.move_to_top(TauDigits));
        steps.push(layout.move_to_top(RMinusAccumulator));
        layout.assert_suffix(&[
            (ANextDigits, FIELD_DIGIT_COUNT),
            (TauDigits, FIELD_DIGIT_COUNT),
            (RMinusAccumulator, ACCUMULATOR_COUNT),
        ]);
        steps.push(accumulate_streamed_product_preserving_grouping(
            true,
            Grouping::Three,
            false,
        ));
        steps.push(verify_streamed_relation_absorbed());
        layout.replace_suffix(&[(RMinusAccumulator, ACCUMULATOR_COUNT)], &[]);

        steps.push(layout.move_to_top(ANextDigits));
        steps.push(layout.move_to_top(YNextDigits));
        layout.assert_suffix(&[
            (ANextDigits, FIELD_DIGIT_COUNT),
            (YNextDigits, FIELD_DIGIT_COUNT),
        ]);
        steps.push(transform_coordinate_with_raw_y(
            CoordinateFormula::RestoreRawFromCenteredSum,
        ));
        layout.replace_suffix(
            &[
                (ANextDigits, FIELD_DIGIT_COUNT),
                (YNextDigits, FIELD_DIGIT_COUNT),
            ],
            &[
                (YNextDigits, FIELD_DIGIT_COUNT),
                (XNextDigits, FIELD_DIGIT_COUNT),
            ],
        );
        steps.push(layout.drop(TauDigits));
    }

    if packed_output {
        // X' is already on top. Encode it, then move and encode Y'.
        let encode_x_preserved = usize::try_from(preserved_items).expect("u32 fits usize")
            + layout.items()
            - FIELD_DIGIT_COUNT;
        steps.push(u5_packed::encode_certified(
            u32::try_from(encode_x_preserved).expect("encoder preserved count fits u32"),
        ));
        layout.replace_suffix(
            &[(XNextDigits, FIELD_DIGIT_COUNT)],
            &[(XNextPacked, u5_packed::PACKED_WORD_COUNT)],
        );
        steps.push(layout.move_to_top(YNextDigits));
        let encode_y_preserved = usize::try_from(preserved_items).expect("u32 fits usize")
            + layout.items()
            - FIELD_DIGIT_COUNT;
        steps.push(u5_packed::encode_certified(
            u32::try_from(encode_y_preserved).expect("encoder preserved count fits u32"),
        ));
        layout.replace_suffix(
            &[(YNextDigits, FIELD_DIGIT_COUNT)],
            &[(YNextPacked, u5_packed::PACKED_WORD_COUNT)],
        );
        layout.assert_suffix(&[
            (XNextPacked, u5_packed::PACKED_WORD_COUNT),
            (YNextPacked, u5_packed::PACKED_WORD_COUNT),
        ]);
        assert_eq!(layout.items(), PACKED_POSITIVE_OUTPUT_ITEM_COUNT);
    } else {
        steps.push(layout.move_to_top(YNextDigits));
        layout.assert_suffix(&[
            (XNextDigits, FIELD_DIGIT_COUNT),
            (YNextDigits, FIELD_DIGIT_COUNT),
        ]);
        assert_eq!(layout.items(), 2 * FIELD_DIGIT_COUNT);
    }

    if signed_control {
        // The three signed/identity transition wrappers used by G29 are
        // larger than the repository's 32 KiB optimizer cutoff. Compile each
        // boundary-preserving semantic step under the centralized policy
        // before concatenating it, so routine local rewrites are retained
        // when the final transition takes the raw path. Each step has the
        // same stack contract as its source `Script`; no state is inserted,
        // removed, or reordered between step boundaries.
        let mut result = Script::new("policy-precompiled signed Ed25519 transition steps");
        for step in steps {
            result = result.push_script(step.compile_with_policy());
        }
        result
    } else {
        // Preserve the established bytecode and metrics of every unsigned
        // packed-transition API.
        script! { for step in steps { { step } } }
    }
}

/// Verify one positive, non-identity affine transition from hostile packed
/// field inputs and return canonical packed `x' | y'`.
///
/// Complete input, bottom to top, is:
///
/// `x'_packed | y'_packed | C-_packed | C+_packed | tau_packed | K_packed |
/// q- | q+ | q0 | y_packed | x_packed`.
///
/// Every packed field occupies eight items. The fragment therefore has 64
/// claimed-field/data items and **exactly three auxiliary quotient hint
/// items**, all coexisting at entry: 67 local items total. It consumes every
/// local input and returns 16 packed coordinate items. `preserved_items`
/// counts unrelated items below this boundary and may be at most
/// [`PACKED_POSITIVE_MAX_PRESERVED_ITEMS`]. Inputs are fully decoded and
/// certified; no separate packed-codec certification wrapper is required.
pub fn verify_packed_positive_transition(preserved_items: u32) -> Script {
    packed_positive_transition_script(
        preserved_items,
        false,
        false,
        false,
        true,
        false,
        false,
        false,
        false,
    )
}

/// Expanded-output form of [`verify_packed_positive_transition`].
///
/// This returns certified raw radix-32 `x'[50..0] | y'[50..0]` (102 items),
/// allowing a multi-transition scheduler to avoid decoding the current point
/// again. Its exact hint cost remains three direct quotient items.
pub fn verify_packed_positive_transition_expanded(preserved_items: u32) -> Script {
    packed_positive_transition_script(
        preserved_items,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
    )
}

/// Chained-trace form with an already-certified expanded current point.
///
/// Input uses the same order as [`verify_packed_positive_transition`] except
/// the final `y_packed | x_packed` blocks are replaced by certified
/// `y[50..0] | x[50..0]`. It therefore takes 150 claimed-field items plus
/// exactly three direct quotient hints (153 local items total), and returns
/// certified expanded `x'[50..0] | y'[50..0]`. This saves two raw field
/// decoders and both output encoders on every chained transition.
pub fn verify_packed_positive_transition_chained(preserved_items: u32) -> Script {
    packed_positive_transition_script(
        preserved_items,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
    )
}

/// Packed-current/output wrapper whose selected table entry supplies K as 13
/// already-certified centered four-digit limbs (`K[last] .. K[0]`).
///
/// Input order otherwise matches [`verify_packed_positive_transition`]. The
/// K block replaces eight packed words, so this boundary has 69 claimed data
/// items plus exactly three direct quotient hints: 72 local input items. The
/// limbs must be bound to the same authenticated table selection that supplies
/// C+/C-; they are not accepted as unverified auxiliary hints.
pub fn verify_packed_positive_transition_direct_k(preserved_items: u32) -> Script {
    packed_positive_transition_script(
        preserved_items,
        false,
        true,
        false,
        true,
        false,
        false,
        false,
        false,
    )
}

/// Packed-current/output counterpart using the shared-`tau` relation layout.
/// It has the same 69 claimed-data plus three direct-hint input contract as
/// [`verify_packed_positive_transition_direct_k`].
pub fn verify_packed_positive_transition_direct_k_shared_tau(preserved_items: u32) -> Script {
    packed_positive_transition_script(
        preserved_items,
        false,
        true,
        false,
        true,
        true,
        false,
        false,
        false,
    )
}

/// First-transition direct-K form: packed current point, certified expanded
/// output, and a one-accumulator sequential R+/R- schedule. Input is 69
/// claimed-data items plus exactly three direct quotient hints; output is 102
/// coordinate digits.
pub fn verify_packed_positive_transition_expanded_direct_k_sequential(
    preserved_items: u32,
) -> Script {
    packed_positive_transition_script(
        preserved_items,
        false,
        true,
        false,
        false,
        false,
        true,
        false,
        false,
    )
}

/// Mixed-negative-limb first-transition sequential form. It keeps the same
/// 72-item input and 102-item output contract, but all three q hints are
/// signed 23-bit and must come from [`shared_tau_mixed_transition_hints`].
pub fn verify_packed_positive_transition_expanded_direct_k_sequential_mixed(
    preserved_items: u32,
) -> Script {
    packed_positive_transition_script(
        preserved_items,
        false,
        true,
        false,
        false,
        false,
        true,
        true,
        false,
    )
}

/// Byte-minimized shared-`tau` counterpart to
/// [`verify_packed_positive_transition_expanded_direct_k_sequential`]. It has
/// the same 72-item input and 102-item output contract.
pub fn verify_packed_positive_transition_expanded_direct_k_shared_tau(
    preserved_items: u32,
) -> Script {
    packed_positive_transition_script(
        preserved_items,
        false,
        true,
        false,
        false,
        true,
        false,
        false,
        false,
    )
}

/// Mixed-negative-limb first-transition shared-tau form. Input is 69 claimed
/// data plus three signed-23-bit quotient hints; output is 102 digits.
pub fn verify_packed_positive_transition_expanded_direct_k_shared_tau_mixed(
    preserved_items: u32,
) -> Script {
    packed_positive_transition_script(
        preserved_items,
        false,
        true,
        false,
        false,
        true,
        false,
        true,
        false,
    )
}

/// Signed/identity first-transition shared-tau mixed boundary. Selected
/// packed C+/C- are pre-oriented by the table branch. Input is 71
/// authenticated data/control items plus exactly three quotient hints (74
/// total); output is 102 certified coordinate digits.
pub fn verify_packed_signed_transition_expanded_direct_k_shared_tau_mixed(
    preserved_items: u32,
) -> Script {
    packed_positive_transition_script(
        preserved_items,
        false,
        true,
        false,
        false,
        true,
        false,
        true,
        true,
    )
}

/// Chained expanded-current/output counterpart to
/// [`verify_packed_positive_transition_direct_k`].
///
/// It takes 155 claimed data items plus exactly three direct quotient hints
/// (158 local items) and returns 102 certified expanded coordinate digits.
pub fn verify_packed_positive_transition_chained_direct_k(preserved_items: u32) -> Script {
    packed_positive_transition_script(
        preserved_items,
        true,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
    )
}

/// One-accumulator chained direct-K schedule. Input is 155 claimed-data items
/// plus exactly three direct quotient hints; output is 102 coordinate digits.
pub fn verify_packed_positive_transition_chained_direct_k_sequential(
    preserved_items: u32,
) -> Script {
    packed_positive_transition_script(
        preserved_items,
        true,
        true,
        false,
        false,
        false,
        true,
        false,
        false,
    )
}

/// Mixed-negative-limb chained sequential form, retaining the same 158-item
/// complete local input and 102-item output boundary.
pub fn verify_packed_positive_transition_chained_direct_k_sequential_mixed(
    preserved_items: u32,
) -> Script {
    packed_positive_transition_script(
        preserved_items,
        true,
        true,
        false,
        false,
        false,
        true,
        true,
        false,
    )
}

/// Chained direct-K transition using one shared 32-entry `tau` table for the
/// two next-coordinate products.  The input/output and three-item hint
/// contract match [`verify_packed_positive_transition_chained_direct_k`], but
/// the quotient values must come from [`shared_tau_transition_hints`].
pub fn verify_packed_positive_transition_chained_direct_k_shared_tau(
    preserved_items: u32,
) -> Script {
    packed_positive_transition_script(
        preserved_items,
        true,
        true,
        false,
        false,
        true,
        false,
        false,
        false,
    )
}

/// Shared-tau chained boundary using the proved 15-limb mixed layout for the
/// packed C+/C- products. Input is 155 claimed-data items plus exactly three
/// signed-23-bit quotient hints; output is 102 coordinate digits.
pub fn verify_packed_positive_transition_chained_direct_k_shared_tau_mixed(
    preserved_items: u32,
) -> Script {
    packed_positive_transition_script(
        preserved_items,
        true,
        true,
        false,
        false,
        true,
        false,
        true,
        false,
    )
}

/// Signed/identity chained shared-tau mixed boundary. Selected packed C+/C-
/// are pre-oriented by the table branch. Input is 157 authenticated
/// data/control items plus exactly three quotient hints (160 total); output
/// is 102 certified coordinate digits.
pub fn verify_packed_signed_transition_chained_direct_k_shared_tau_mixed(
    preserved_items: u32,
) -> Script {
    packed_positive_transition_script(
        preserved_items,
        true,
        true,
        false,
        false,
        true,
        false,
        true,
        true,
    )
}

/// Chained one-accumulator boundary for a table entry that supplies K as 13
/// centered limbs and C-/C+ as two certified biased 51-digit vectors.
/// Complete local input is 241 claimed-data items plus exactly three quotient
/// hints (244 total); output is 102 certified coordinate digits.
pub fn verify_packed_positive_transition_chained_direct_constants_sequential(
    preserved_items: u32,
) -> Script {
    packed_positive_transition_script(
        preserved_items,
        true,
        true,
        true,
        false,
        false,
        true,
        false,
        false,
    )
}

/// Byte-minimized shared-`tau` counterpart for direct K/C-/C+ table data.
/// Input/output and exact three-item hint cost match
/// [`verify_packed_positive_transition_chained_direct_constants_sequential`].
pub fn verify_packed_positive_transition_chained_direct_constants_shared_tau(
    preserved_items: u32,
) -> Script {
    packed_positive_transition_script(
        preserved_items,
        true,
        true,
        true,
        false,
        true,
        false,
        false,
        false,
    )
}

/// Direct-K/C+/C- counterpart using 15 mixed limbs for both negative
/// products. The exact input remains 241 authenticated data items plus three
/// signed-23-bit quotient hints (244 total); output remains 102 digits.
pub fn verify_packed_positive_transition_chained_direct_constants_shared_tau_mixed(
    preserved_items: u32,
) -> Script {
    packed_positive_transition_script(
        preserved_items,
        true,
        true,
        true,
        false,
        true,
        false,
        true,
        false,
    )
}

/// Unified positive/negative/identity counterpart to the mixed shared-tau
/// direct-constant boundary.
///
/// Complete local input, bottom to top, is
/// `x'_packed | y'_packed | selected_C-[50..0] | selected_C+[50..0] |
/// tau_magnitude_packed | K_magnitude[12..0] | q- | q+ | q0 | y[50..0] |
/// x[50..0] | nonzero | negative`.
///
/// The selected table must emit C+/C- already oriented for the signed point:
/// positive uses `(a+b,b-a)`, negative swaps them, and identity uses `(1,1)`.
/// K is the positive magnitude for either sign and is `1` for identity.
/// `negative` negates tau only after R0; `nonzero=0` omits x*y from R0, so
/// `-K*tau=0` binds identity tau to zero. Both controls are authenticated data,
/// not hints. This boundary therefore has 243 claimed/control data items plus
/// exactly three quotient hints (246 local inputs), and returns 102 digits.
pub fn verify_packed_signed_transition_chained_direct_constants_shared_tau_mixed(
    preserved_items: u32,
) -> Script {
    packed_positive_transition_script(
        preserved_items,
        true,
        true,
        true,
        false,
        true,
        false,
        true,
        true,
    )
}

const LOW_QUOTIENT_COEFFICIENT_COUNT: usize = 5;
const NEGATIVE_NINETEEN_INVERSE_MOD_2POW22_23: u32 = 1_324_517;

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
        // Keep the source itself as the sign carrier. This avoids routing a
        // separate sign bit through alt while reducing its absolute value.
        OP_DUP OP_ABS
        for bit in (width..input_bits).rev() {
            { subtract_power_if_at_least(bit) }
        }
        OP_SWAP 0 OP_LESSTHAN OP_IF OP_NEGATE OP_ENDIF
    }
}

fn reduce_once_mod_power_of_two(width: usize) -> Script {
    subtract_power_if_at_least(width)
}

fn multiply_negative_nineteen_inverse_mod_power_of_two_legacy_naf(width: usize) -> Script {
    let mut remaining = NEGATIVE_NINETEEN_INVERSE_MOD_2POW22_23;
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
            { reduce_once_mod_power_of_two(width) }
            if digit == 1 {
                1 OP_PICK OP_ADD
                { reduce_once_mod_power_of_two(width) }
            } else if digit == -1 {
                1 OP_PICK OP_SUB
                OP_DUP 0 OP_LESSTHAN
                OP_IF { 1u32 << width } OP_ADD OP_ENDIF
            }
        }
        OP_NIP
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamedRelationQuotientMultiplier {
    Mixed233x196Plus5x29,
    LegacyNaf,
}

fn reduce_nonnegative_factor_mod_power_of_two(width: usize, factor: u32) -> Script {
    assert!(factor > 0);
    let high_bits = if factor == 1 {
        0
    } else {
        (u32::BITS - (factor - 1).leading_zeros()) as usize
    };
    script! {
        for bit in (width..width + high_bits).rev() {
            { subtract_power_if_at_least(bit) }
        }
    }
}

/// Multiply by `1_324_517 = (233*196 + 5)*29` modulo `2^width`.
///
/// The original residue remains below the first two stages. Their exact
/// unreduced factors are 233 and 201; after the source is dropped, the last
/// factor is 29. For width 23 the maximum possible intermediate is
/// `233*(2^23-1) = 1_954_545_431`, strictly below `i32::MAX`. The three stages
/// need 8+8+5 conditional power-of-two subtractions.
fn multiply_negative_nineteen_inverse_mod_power_of_two_mixed(width: usize) -> Script {
    assert!(width == 22 || width == 23);
    assert_eq!(
        (233u32 * 196 + 5) * 29,
        NEGATIVE_NINETEEN_INVERSE_MOD_2POW22_23
    );
    let maximum_residue = (1u64 << width) - 1;
    for factor in [233u32, 201, 29] {
        assert!(u64::from(factor) * maximum_residue <= u64::from(scriptint::MAX_SCRIPTNUM));
    }
    script! {
        OP_DUP
        { scriptint::mul_by_constant(233) }
        { reduce_nonnegative_factor_mod_power_of_two(width, 233) }

        { scriptint::mul_by_constant(196) }
        1 OP_PICK
        { scriptint::mul_by_constant(5) }
        OP_ADD
        { reduce_nonnegative_factor_mod_power_of_two(width, 201) }

        OP_NIP
        { scriptint::mul_by_constant(29) }
        { reduce_nonnegative_factor_mod_power_of_two(width, 29) }
    }
}

fn multiply_negative_nineteen_inverse_mod_power_of_two(
    width: usize,
    multiplier: StreamedRelationQuotientMultiplier,
) -> Script {
    match multiplier {
        StreamedRelationQuotientMultiplier::Mixed233x196Plus5x29 => {
            multiply_negative_nineteen_inverse_mod_power_of_two_mixed(width)
        }
        StreamedRelationQuotientMultiplier::LegacyNaf => {
            multiply_negative_nineteen_inverse_mod_power_of_two_legacy_naf(width)
        }
    }
}

/// Reducing during Horner composition avoids materializing five residues and
/// subsequently reducing their sum. At stage i the temporary is
/// `h_i + 32*r_(i+1)`, and its explicit bound is checked below. Every supported
/// slope profile stays within four-byte ScriptNum arithmetic on hostile data.
fn low_quotient_horner_stage_bounds(
    signed_width: usize,
    low_coefficient_abs_max: &[i64; LOW_QUOTIENT_COEFFICIENT_COUNT],
) -> [i64; LOW_QUOTIENT_COEFFICIENT_COUNT] {
    assert!(signed_width == 22 || signed_width == 23);
    core::array::from_fn(|coefficient| {
        let previous_remainder_bound = if coefficient + 1 == LOW_QUOTIENT_COEFFICIENT_COUNT {
            0
        } else {
            32 * ((1i64 << (signed_width - 5 * (coefficient + 1))) - 1)
        };
        let bound = low_coefficient_abs_max[coefficient] + previous_remainder_bound;
        assert!(bound > 0 && bound <= i64::from(scriptint::MAX_SCRIPTNUM));
        bound
    })
}

/// Derive an exact signed relation quotient from the accumulator itself.
///
/// Input/output is `h[50..0] -> h[50..0] | q`, with h0 nearest the top on
/// entry and q nearest the top on exit. For `H=sum(h_i*32^i)` and
/// `p=32^51-19`, an accepted relation has `H=q*p`; hence
/// `q = signed_w(1_324_517 * H mod 2^w)`. Exact slope bounds restrict q to
/// one signed 22- or 23-bit residue, and only h0 through h4 affect it.
/// The bounded `(233*196+5)*29` multiplier is unchanged. Horner reduction
/// preserves H modulo 2^w: each discarded term, after its remaining shifts,
/// is a multiple of 2^w. This fragment takes zero auxiliary witness hints.
fn derive_streamed_relation_quotient_with_multiplier(
    signed_width: usize,
    low_coefficient_abs_max: &[i64; LOW_QUOTIENT_COEFFICIENT_COUNT],
    multiplier: StreamedRelationQuotientMultiplier,
) -> Script {
    assert!(signed_width == 22 || signed_width == 23);
    let stage_bounds = low_quotient_horner_stage_bounds(signed_width, low_coefficient_abs_max);
    script! {
        { (LOW_QUOTIENT_COEFFICIENT_COUNT - 1) as u32 } OP_PICK
        { signed_low_remainder(signed_width - 20, stage_bounds[4]) }
        for coefficient in (0..LOW_QUOTIENT_COEFFICIENT_COUNT - 1).rev() {
            for _ in 0..5 { OP_DUP OP_ADD }
            { (coefficient + 1) as u32 } OP_PICK OP_ADD
            { signed_low_remainder(
                signed_width - 5 * coefficient,
                stage_bounds[coefficient],
            ) }
        }
        OP_DUP 0 OP_LESSTHAN
        OP_IF { 1u32 << signed_width } OP_ADD OP_ENDIF
        { multiply_negative_nineteen_inverse_mod_power_of_two(signed_width, multiplier) }

        OP_DUP { 1u32 << (signed_width - 1) } OP_GREATERTHANOREQUAL
        OP_IF { 1u32 << signed_width } OP_SUB OP_ENDIF
    }
}

pub fn derive_streamed_relation_quotient(
    signed_width: usize,
    low_coefficient_abs_max: &[i64; LOW_QUOTIENT_COEFFICIENT_COUNT],
) -> Script {
    derive_streamed_relation_quotient_with_multiplier(
        signed_width,
        low_coefficient_abs_max,
        StreamedRelationQuotientMultiplier::Mixed233x196Plus5x29,
    )
}

/// Close a streamed relation when its derived quotient is nearest the top.
///
/// Input is `h[50..0] | q`. This has the same exact equality semantics as
/// [`verify_streamed_relation`] but avoids rotating q below all 51
/// coefficients. It consumes the accumulator and q and requires zero hints.
/// Negating q lets the recurrence add each coefficient: `d'=32*d+h_i`.
/// Its magnitude equals the previous subtraction recurrence at every step,
/// while addition avoids reversing the operands for every coefficient.
pub fn verify_streamed_relation_top_quotient() -> Script {
    script! {
        OP_NEGATE OP_DUP
        for coefficient in (1..FIELD_DIGIT_COUNT).rev() {
            { (coefficient + 2) as u32 } OP_ROLL
            OP_SWAP
            { scriptint::mul_by_constant(RADIX as u32) }
            OP_ADD
        }

        OP_TOALTSTACK
        OP_DUP { scriptint::mul_by_constant(19) }
        OP_ROT OP_SUB
        OP_FROMALTSTACK { scriptint::mul_by_constant(RADIX as u32) }
        OP_NUMEQUALVERIFY
        OP_DROP
    }
}

/// How one pooled quotient relation acquires and releases its script-authored
/// powers of two. The pool entries are verifier constants, not witness hints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SharedPowerPoolRelationBoundary {
    /// Construct the pool on main before the relation and park it on alt after.
    PushAndPark,
    /// Restore an already parked pool and consume it after the relation.
    RestoreAndDrop,
    /// Restore an already parked pool and park it again after the relation.
    RestoreAndPark,
}

fn validate_shared_power_pool_bits(shared_bits: &[usize]) {
    assert!(!shared_bits.is_empty());
    assert!(shared_bits.iter().all(|bit| (2..=30).contains(bit)));
    assert!(shared_bits.windows(2).all(|pair| pair[0] < pair[1]));
}

fn shared_power_literal_bytes(bit: usize) -> usize {
    script! { { 1u32 << bit } }.compile_with_policy().len()
}

fn push_next_shared_power(previous_bit: usize, next_bit: usize) -> Script {
    let gap = next_bit - previous_bit;
    let addition_chain_bytes = 1 + 2 * gap;
    if addition_chain_bytes < shared_power_literal_bytes(next_bit) {
        script! {
            OP_DUP
            for _ in 0..gap { OP_DUP OP_ADD }
        }
    } else {
        script! { { 1u32 << next_bit } }
    }
}

/// Push an ascending pool of powers of two using literals or a shortest local
/// doubling chain. These items are authored by the locking script: this adds
/// exactly zero witness items and zero auxiliary hint items.
pub(crate) fn push_streamed_relation_shared_power_pool(shared_bits: &[usize]) -> Script {
    validate_shared_power_pool_bits(shared_bits);
    script! {
        { 1u32 << shared_bits[0] }
        for pair in shared_bits.windows(2) {
            { push_next_shared_power(pair[0], pair[1]) }
        }
    }
}

/// Move every shared power from main to alt, retaining ascending order when
/// later restored. This changes neither witness-item nor hint-item counts.
pub(crate) fn park_streamed_relation_shared_power_pool(shared_constant_count: usize) -> Script {
    assert!(shared_constant_count > 0);
    script! {
        for _ in 0..shared_constant_count { OP_TOALTSTACK }
    }
}

/// Restore a shared-power pool from alt to main in its original order.
pub(crate) fn restore_streamed_relation_shared_power_pool(shared_constant_count: usize) -> Script {
    assert!(shared_constant_count > 0);
    script! {
        for _ in 0..shared_constant_count { OP_FROMALTSTACK }
    }
}

/// Consume a shared-power pool from main.
pub(crate) fn drop_streamed_relation_shared_power_pool(shared_constant_count: usize) -> Script {
    assert!(shared_constant_count > 0);
    script! {
        for _ in 0..shared_constant_count / 2 { OP_2DROP }
        if shared_constant_count % 2 != 0 { OP_DROP }
    }
}

fn copy_streamed_relation_shared_power(
    bit: usize,
    items_above_pool: usize,
    shared_bits: &[usize],
) -> Script {
    if let Some(position) = shared_bits.iter().position(|candidate| *candidate == bit) {
        let depth = items_above_pool + shared_bits.len() - 1 - position;
        script! { { depth as u32 } OP_PICK }
    } else {
        script! { { 1u32 << bit } }
    }
}

fn subtract_shared_power_if_at_least(
    bit: usize,
    items_above_pool: usize,
    shared_bits: &[usize],
) -> Script {
    script! {
        { copy_streamed_relation_shared_power(bit, items_above_pool, shared_bits) }
        OP_2DUP OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
    }
}

fn signed_low_remainder_with_shared_power_pool(
    width: usize,
    max_abs: i64,
    shared_bits: &[usize],
) -> Script {
    assert!((1..=30).contains(&width));
    assert!(max_abs > 0);
    let input_bits = i64::BITS as usize - max_abs.leading_zeros() as usize;
    assert!(input_bits <= 31);
    script! {
        OP_DUP OP_ABS
        for bit in (width..input_bits).rev() {
            { subtract_shared_power_if_at_least(bit, 2, shared_bits) }
        }
        OP_SWAP 0 OP_LESSTHAN OP_IF OP_NEGATE OP_ENDIF
    }
}

fn reduce_nonnegative_factor_with_shared_power_pool(
    width: usize,
    factor: u32,
    items_above_pool: usize,
    shared_bits: &[usize],
) -> Script {
    assert!(factor > 0);
    let high_bits = if factor == 1 {
        0
    } else {
        (u32::BITS - (factor - 1).leading_zeros()) as usize
    };
    script! {
        for bit in (width..width + high_bits).rev() {
            { subtract_shared_power_if_at_least(bit, items_above_pool, shared_bits) }
        }
    }
}

fn multiply_negative_nineteen_inverse_with_shared_power_pool(
    width: usize,
    multiplier: StreamedRelationQuotientMultiplier,
    shared_bits: &[usize],
) -> Script {
    assert_eq!(
        multiplier,
        StreamedRelationQuotientMultiplier::Mixed233x196Plus5x29
    );
    assert!(width == 22 || width == 23);
    script! {
        OP_DUP
        { scriptint::mul_by_constant(233) }
        { reduce_nonnegative_factor_with_shared_power_pool(width, 233, 2, shared_bits) }

        { scriptint::mul_by_constant(196) }
        1 OP_PICK
        { scriptint::mul_by_constant(5) }
        OP_ADD
        { reduce_nonnegative_factor_with_shared_power_pool(width, 201, 2, shared_bits) }

        OP_NIP
        { scriptint::mul_by_constant(29) }
        { reduce_nonnegative_factor_with_shared_power_pool(width, 29, 1, shared_bits) }
    }
}

/// Derive q while retaining a script-authored shared-power pool below it.
///
/// Input/output is `h[50..0] | pool -> h[50..0] | pool | q`. Pool lookups
/// merely replace pushes of the same exact powers of two; arithmetic and the
/// accepted relation are unchanged. This fragment requires zero hint items.
fn derive_streamed_relation_quotient_with_shared_power_pool(
    signed_width: usize,
    low_coefficient_abs_max: &[i64; LOW_QUOTIENT_COEFFICIENT_COUNT],
    multiplier: StreamedRelationQuotientMultiplier,
    shared_bits: &[usize],
) -> Script {
    assert!(signed_width == 22 || signed_width == 23);
    validate_shared_power_pool_bits(shared_bits);
    let stage_bounds = low_quotient_horner_stage_bounds(signed_width, low_coefficient_abs_max);
    script! {
        { (LOW_QUOTIENT_COEFFICIENT_COUNT - 1 + shared_bits.len()) as u32 } OP_PICK
        { signed_low_remainder_with_shared_power_pool(signed_width - 20, stage_bounds[4], shared_bits) }
        for coefficient in (0..LOW_QUOTIENT_COEFFICIENT_COUNT - 1).rev() {
            for _ in 0..5 { OP_DUP OP_ADD }
            { (coefficient + 1 + shared_bits.len()) as u32 } OP_PICK OP_ADD
            { signed_low_remainder_with_shared_power_pool(
                signed_width - 5 * coefficient,
                stage_bounds[coefficient],
                shared_bits,
            ) }
        }
        OP_DUP 0 OP_LESSTHAN
        OP_IF
            { copy_streamed_relation_shared_power(signed_width, 1, shared_bits) }
            OP_ADD
        OP_ENDIF
        { multiply_negative_nineteen_inverse_with_shared_power_pool(
            signed_width,
            multiplier,
            shared_bits,
        ) }

        OP_DUP
        { copy_streamed_relation_shared_power(signed_width - 1, 2, shared_bits) }
        OP_GREATERTHANOREQUAL
        OP_IF
            { copy_streamed_relation_shared_power(signed_width, 1, shared_bits) }
            OP_SUB
        OP_ENDIF
    }
}

/// Close `H=q*p` while retaining `shared_constant_count` pool items.
/// Input is `h[50..0] | pool | q`; output is exactly `pool`.
fn verify_streamed_relation_top_quotient_retaining_shared_power_pool(
    shared_constant_count: usize,
) -> Script {
    assert!(shared_constant_count > 0);
    script! {
        OP_NEGATE OP_DUP
        for coefficient in (1..FIELD_DIGIT_COUNT).rev() {
            { (coefficient + 2 + shared_constant_count) as u32 } OP_ROLL
            OP_SWAP
            { scriptint::mul_by_constant(RADIX as u32) }
            OP_ADD
        }

        OP_TOALTSTACK
        OP_DUP { scriptint::mul_by_constant(19) }
        { (shared_constant_count + 2) as u32 } OP_ROLL
        OP_SUB
        OP_FROMALTSTACK { scriptint::mul_by_constant(RADIX as u32) }
        OP_NUMEQUALVERIFY
        OP_DROP
    }
}

/// Derive and close one zero-hint relation using shared script constants.
///
/// The boundary controls whether the pool is local to a pair of relations or
/// persists across kernels on alt. In every case the exact witness-hint cost
/// is zero. Callers must count the `shared_bits.len()` script-authored live
/// items in their combined main-plus-alt stack peak.
pub(crate) fn verify_streamed_relation_derived_with_multiplier_shared_power_pool(
    signed_width: usize,
    low_coefficient_abs_max: &[i64; LOW_QUOTIENT_COEFFICIENT_COUNT],
    multiplier: StreamedRelationQuotientMultiplier,
    shared_bits: &[usize],
    boundary: SharedPowerPoolRelationBoundary,
) -> Script {
    validate_shared_power_pool_bits(shared_bits);
    let acquire = match boundary {
        SharedPowerPoolRelationBoundary::PushAndPark => {
            push_streamed_relation_shared_power_pool(shared_bits)
        }
        SharedPowerPoolRelationBoundary::RestoreAndDrop
        | SharedPowerPoolRelationBoundary::RestoreAndPark => {
            restore_streamed_relation_shared_power_pool(shared_bits.len())
        }
    };
    let release = match boundary {
        SharedPowerPoolRelationBoundary::RestoreAndDrop => {
            drop_streamed_relation_shared_power_pool(shared_bits.len())
        }
        SharedPowerPoolRelationBoundary::PushAndPark
        | SharedPowerPoolRelationBoundary::RestoreAndPark => {
            park_streamed_relation_shared_power_pool(shared_bits.len())
        }
    };
    script! {
        { acquire }
        { derive_streamed_relation_quotient_with_shared_power_pool(
            signed_width,
            low_coefficient_abs_max,
            multiplier,
            shared_bits,
        ) }
        { verify_streamed_relation_top_quotient_retaining_shared_power_pool(
            shared_bits.len(),
        ) }
        { release }
    }
}

/// Derive and close one quotient-only radix-32 relation with no hint item.
pub fn verify_streamed_relation_derived(
    signed_width: usize,
    low_coefficient_abs_max: &[i64; LOW_QUOTIENT_COEFFICIENT_COUNT],
) -> Script {
    verify_streamed_relation_derived_with_multiplier(
        signed_width,
        low_coefficient_abs_max,
        StreamedRelationQuotientMultiplier::Mixed233x196Plus5x29,
    )
}

pub(crate) fn verify_streamed_relation_derived_with_multiplier(
    signed_width: usize,
    low_coefficient_abs_max: &[i64; LOW_QUOTIENT_COEFFICIENT_COUNT],
    multiplier: StreamedRelationQuotientMultiplier,
) -> Script {
    script! {
        { derive_streamed_relation_quotient_with_multiplier(
            signed_width,
            low_coefficient_abs_max,
            multiplier,
        ) }
        { verify_streamed_relation_top_quotient() }
    }
}

/// Close a quotient-only relation accumulated by streamed products.
///
/// Without a linear term, input is `... | q | h[50..0]`. With a linear term,
/// input is `... | linear[50..0] | q | h[50..0]`, where `linear` contains
/// centered (not biased) coefficients. The fragment consumes all local items.
/// Its exact hint cost is one quotient stack item. Local input/peak counts are
/// 52/55 items without a linear term and 103/106 with one; preserved packed
/// trace items below the boundary add one-for-one.
pub fn verify_streamed_relation(has_linear_term: bool) -> Script {
    script! {
        for _ in 0..ACCUMULATOR_COUNT { OP_TOALTSTACK }
        OP_DUP
        for coefficient in (1..FIELD_DIGIT_COUNT).rev() {
            OP_FROMALTSTACK
            if has_linear_term {
                { (coefficient + 3) as u32 } OP_PICK OP_ADD
            }
            OP_SWAP
            { scriptint::mul_by_constant(RADIX as u32) }
            OP_SWAP OP_SUB
        }
        OP_FROMALTSTACK
        if has_linear_term { 3 OP_PICK OP_ADD }
        2 OP_PICK { scriptint::mul_by_constant(19) } OP_ADD
        OP_SWAP { scriptint::mul_by_constant(RADIX as u32) }
        OP_NUMEQUALVERIFY
        OP_DROP
        if has_linear_term {
            for _ in 0..FIELD_DIGIT_COUNT / 2 { OP_2DROP }
            if FIELD_DIGIT_COUNT % 2 != 0 { OP_DROP }
        }
    }
}

/// Absorb one relation quotient into the low and high coefficients.
///
/// Input is `... | q | h[50..0]`; output is a quotient-free adjusted
/// accumulator `... | h'[50..0]` with `h'[0]=h[0]+19q` and
/// `h'[50]=h[50]-32q`. This lets a scheduler consume a direct quotient before
/// a later product's stack peak. It consumes exactly one hint item and has
/// 52 local inputs / a 53-item local combined-stack peak.
pub fn absorb_relation_quotient() -> Script {
    script! {
        // Update and park h[50].
        { FIELD_DIGIT_COUNT as u32 } OP_PICK
        { scriptint::mul_by_constant(RADIX as u32) }
        { FIELD_DIGIT_COUNT as u32 } OP_ROLL
        OP_SWAP OP_SUB OP_TOALTSTACK

        // Update h[0] while it is nearest the top.
        { (FIELD_DIGIT_COUNT - 1) as u32 } OP_PICK
        { scriptint::mul_by_constant(19) }
        OP_ADD

        // Restore h[50] below h[49..0], then consume q.
        OP_FROMALTSTACK
        { move_block_to_top(FIELD_DIGIT_COUNT - 1, 1) }
        { FIELD_DIGIT_COUNT as u32 } OP_ROLL OP_DROP
    }
}

/// Close an accumulator whose quotient was consumed by
/// [`absorb_relation_quotient`].
///
/// Input is 51 adjusted accumulator items and output is empty. This fragment
/// requires no live hint items at its boundary.
pub fn verify_streamed_relation_absorbed() -> Script {
    script! {
        for _ in 0..ACCUMULATOR_COUNT { OP_TOALTSTACK }
        0
        for _ in (1..FIELD_DIGIT_COUNT).rev() {
            OP_FROMALTSTACK
            OP_SWAP
            { scriptint::mul_by_constant(RADIX as u32) }
            OP_SWAP OP_SUB
        }
        OP_FROMALTSTACK
        OP_SWAP { scriptint::mul_by_constant(RADIX as u32) }
        OP_NUMEQUALVERIFY
    }
}

/// Verify one fixed-point affine addition using three quotient hints.
///
/// The certified main-stack input, bottom to top, is
/// `x[50..0] | y[50..0] | tau[50..0] | x'[50..0] | y'[50..0] | q0 | q+ | q-`.
/// Digit zero is nearest the top of each field vector.  The fragment consumes
/// the five input fields and exactly three auxiliary hint items, and returns
/// `x'[50..0] | y'[50..0]`.  It does not certify raw input digits or append a
/// terminal predicate.
pub fn verify_affine_transition(fixed: &FixedPointConstants) -> Script {
    script! {
        { verify_relation(
            2,
            LinearTerm::None,
            LimbSource::Direct(Field::X),
            RhsSource::Field(Field::Y),
            false,
            LimbSource::Direct(Field::Tau),
            RhsSource::Constant(&fixed.k_digits),
            true,
            Grouping::Four,
            false,
        ) }
        { verify_relation(
            1,
            LinearTerm::Sum(Field::XNext, Field::YNext),
            LimbSource::Difference(Field::XNext, Field::YNext),
            RhsSource::Field(Field::Tau),
            false,
            LimbSource::Sum(Field::X, Field::Y),
            RhsSource::Constant(&fixed.cp_digits),
            true,
            Grouping::Three,
            false,
        ) }
        { verify_relation(
            0,
            LinearTerm::Difference(Field::XNext, Field::YNext),
            LimbSource::Sum(Field::XNext, Field::YNext),
            RhsSource::Field(Field::Tau),
            false,
            LimbSource::Difference(Field::X, Field::Y),
            RhsSource::Constant(&fixed.cm_digits),
            true,
            Grouping::Three,
            false,
        ) }
        { retain_next_point(false) }
    }
}

/// Runtime-constant form of [`verify_affine_transition`].
///
/// The certified input is
/// `x | y | tau | x' | y' | K | C+ | C- | q0 | q+ | q-`, where every field
/// occupies 51 stack items. The three constant fields are expected to come
/// from an externally verified fixed-table selection. This fragment consumes
/// all but `x' | y'`. Its exact auxiliary-hint cost is three items; its full
/// standalone input boundary is 411 items.
pub fn verify_affine_transition_runtime_constants() -> Script {
    script! {
        { runtime_r0() }
        { runtime_r_plus() }
        { runtime_r_minus() }
        { retain_next_point(true) }
    }
}

fn runtime_r0() -> Script {
    runtime_r0_grouped(Grouping::Four)
}

fn runtime_r0_grouped(grouping: Grouping) -> Script {
    verify_relation(
        2,
        LinearTerm::None,
        LimbSource::Direct(Field::X),
        RhsSource::Field(Field::Y),
        false,
        LimbSource::Direct(Field::Tau),
        RhsSource::Field(Field::K),
        true,
        grouping,
        true,
    )
}

/// Conservative runtime-constant transition using three-digit R0 limbs.
///
/// This is larger than [`verify_affine_transition_runtime_constants`] but its
/// two-product coefficient accumulator has a direct worst-case ScriptNum
/// bound. Supply hints from [`conservative_transition_hints`].
pub fn verify_affine_transition_runtime_constants_conservative() -> Script {
    script! {
        { runtime_r0_grouped(Grouping::Three) }
        { runtime_r_plus() }
        { runtime_r_minus() }
        { retain_next_point(true) }
    }
}

fn runtime_r_plus() -> Script {
    verify_relation(
        1,
        LinearTerm::Sum(Field::XNext, Field::YNext),
        LimbSource::Difference(Field::XNext, Field::YNext),
        RhsSource::Field(Field::Tau),
        false,
        LimbSource::Sum(Field::X, Field::Y),
        RhsSource::Field(Field::Cp),
        true,
        Grouping::Three,
        true,
    )
}

fn runtime_r_minus() -> Script {
    verify_relation(
        0,
        LinearTerm::Difference(Field::XNext, Field::YNext),
        LimbSource::Sum(Field::XNext, Field::YNext),
        RhsSource::Field(Field::Tau),
        false,
        LimbSource::Difference(Field::X, Field::Y),
        RhsSource::Field(Field::Cm),
        true,
        Grouping::Three,
        true,
    )
}

pub fn push_transition_witness(
    x: &BigUint,
    y: &BigUint,
    tau: &BigUint,
    x_next: &BigUint,
    y_next: &BigUint,
    hints: &TransitionHints,
) -> Script {
    script! {
        for value in [x, y, tau, x_next, y_next] {
            for digit in field_digits(value).iter().rev() {
                { *digit }
            }
        }
        { hints.push_script() }
    }
}

pub fn transition_witness_items(
    x: &BigUint,
    y: &BigUint,
    tau: &BigUint,
    x_next: &BigUint,
    y_next: &BigUint,
    hints: &TransitionHints,
) -> Vec<Vec<u8>> {
    [x, y, tau, x_next, y_next]
        .into_iter()
        .flat_map(|value| field_digits(value).into_iter().rev().map(scriptnum_item))
        .chain(hints.witness_items())
        .collect()
}

pub fn runtime_transition_witness_items(
    x: &BigUint,
    y: &BigUint,
    tau: &BigUint,
    x_next: &BigUint,
    y_next: &BigUint,
    fixed: &FixedPointConstants,
    hints: &TransitionHints,
) -> Vec<Vec<u8>> {
    [x, y, tau, x_next, y_next, &fixed.k, &fixed.cp, &fixed.cm]
        .into_iter()
        .flat_map(|value| field_digits(value).into_iter().rev().map(scriptnum_item))
        .chain(hints.witness_items())
        .collect()
}

/// Host witness for [`verify_packed_positive_transition`].
///
/// This returns exactly 67 items in the wrapper's documented bottom-to-top
/// order. Of those, exactly three (`q-`, `q+`, `q0`) are auxiliary hints; the
/// other 64 items are the eight packed claimed fields.
pub fn packed_positive_transition_witness_items(
    x: &BigUint,
    y: &BigUint,
    tau: &BigUint,
    x_next: &BigUint,
    y_next: &BigUint,
    fixed: &FixedPointConstants,
    hints: &TransitionHints,
) -> Vec<Vec<u8>> {
    let p = modulus();
    for value in [x, y, tau, x_next, y_next, &fixed.k, &fixed.cp, &fixed.cm] {
        assert!(value < &p, "packed transition field must be canonical");
    }

    let mut items = Vec::with_capacity(PACKED_POSITIVE_COMPLETE_INPUT_ITEM_COUNT);
    for value in [x_next, y_next, &fixed.cm, &fixed.cp, tau, &fixed.k] {
        items.extend(u5_packed::packed_value_witness_items(value));
    }
    for quotient in [hints.quotients[2], hints.quotients[1], hints.quotients[0]] {
        items.push(scriptnum_item(quotient));
    }
    for value in [y, x] {
        items.extend(u5_packed::packed_value_witness_items(value));
    }
    assert_eq!(items.len(), PACKED_POSITIVE_COMPLETE_INPUT_ITEM_COUNT);
    items
}

/// The selected K value in the direct table representation consumed by the
/// direct-K wrappers. Limb zero is returned at index zero; witness order is
/// the reverse of this array.
pub fn direct_k_limbs(fixed: &FixedPointConstants) -> [i32; DIRECT_K_LIMB_COUNT] {
    direct_four_digit_limbs(&fixed.k)
}

fn direct_four_digit_limbs(value: &BigUint) -> [i32; DIRECT_K_LIMB_COUNT] {
    let digits = arithmetic_digits(value);
    std::array::from_fn(|limb_index| {
        let start = Grouping::Four.limb_start(limb_index);
        (0..Grouping::Four.limb_digits(limb_index))
            .rev()
            .fold(0, |value, digit| value * RADIX + digits[start + digit])
    })
}

/// Host witness for [`verify_packed_positive_transition_direct_k`].
///
/// This has exactly 72 items: 69 authenticated claimed-data items and three
/// direct quotient hints. The direct K limbs are table data, not hints.
pub fn packed_positive_transition_direct_k_witness_items(
    x: &BigUint,
    y: &BigUint,
    tau: &BigUint,
    x_next: &BigUint,
    y_next: &BigUint,
    fixed: &FixedPointConstants,
    hints: &TransitionHints,
) -> Vec<Vec<u8>> {
    let mut items = Vec::with_capacity(PACKED_POSITIVE_DIRECT_K_INPUT_ITEM_COUNT);
    for value in [x_next, y_next, &fixed.cm, &fixed.cp, tau] {
        items.extend(u5_packed::packed_value_witness_items(value));
    }
    items.extend(direct_k_limbs(fixed).into_iter().rev().map(scriptnum_item));
    for quotient in [hints.quotients[2], hints.quotients[1], hints.quotients[0]] {
        items.push(scriptnum_item(quotient));
    }
    for value in [y, x] {
        items.extend(u5_packed::packed_value_witness_items(value));
    }
    assert_eq!(items.len(), PACKED_POSITIVE_DIRECT_K_INPUT_ITEM_COUNT);
    items
}

/// Expanded-current host boundary for the chained direct-K wrappers.
/// It contains 155 claimed-data items and exactly three quotient hints.
pub fn chained_direct_k_witness_items(
    x: &BigUint,
    y: &BigUint,
    tau: &BigUint,
    x_next: &BigUint,
    y_next: &BigUint,
    fixed: &FixedPointConstants,
    hints: &TransitionHints,
) -> Vec<Vec<u8>> {
    let mut items = Vec::with_capacity(EXPANDED_CURRENT_DIRECT_K_INPUT_ITEM_COUNT);
    for value in [x_next, y_next, &fixed.cm, &fixed.cp, tau] {
        items.extend(u5_packed::packed_value_witness_items(value));
    }
    items.extend(direct_k_limbs(fixed).into_iter().rev().map(scriptnum_item));
    for quotient in [hints.quotients[2], hints.quotients[1], hints.quotients[0]] {
        items.push(scriptnum_item(quotient));
    }
    for value in [y, x] {
        items.extend(field_digits(value).into_iter().rev().map(scriptnum_item));
    }
    assert_eq!(items.len(), EXPANDED_CURRENT_DIRECT_K_INPUT_ITEM_COUNT);
    items
}

/// Host boundary for the chained wrappers whose selected table entry emits
/// direct K limbs and direct C-/C+ digit vectors.
///
/// The returned 244 items are ordered
/// `x'_packed | y'_packed | C-[50..0] | C+[50..0] | tau_packed |
/// K[12..0] | q- | q+ | q0 | y[50..0] | x[50..0]`.
/// Exactly the three q items are auxiliary hints; the other 241 items are
/// authenticated/certified data.
pub fn chained_direct_constants_witness_items(
    x: &BigUint,
    y: &BigUint,
    tau: &BigUint,
    x_next: &BigUint,
    y_next: &BigUint,
    fixed: &FixedPointConstants,
    hints: &TransitionHints,
) -> Vec<Vec<u8>> {
    let mut items = Vec::with_capacity(EXPANDED_CURRENT_DIRECT_CONSTANTS_INPUT_ITEM_COUNT);
    for value in [x_next, y_next] {
        items.extend(u5_packed::packed_value_witness_items(value));
    }
    for value in [&fixed.cm, &fixed.cp] {
        items.extend(field_digits(value).into_iter().rev().map(scriptnum_item));
    }
    items.extend(u5_packed::packed_value_witness_items(tau));
    items.extend(direct_k_limbs(fixed).into_iter().rev().map(scriptnum_item));
    for quotient in [hints.quotients[2], hints.quotients[1], hints.quotients[0]] {
        items.push(scriptnum_item(quotient));
    }
    for value in [y, x] {
        items.extend(field_digits(value).into_iter().rev().map(scriptnum_item));
    }
    assert_eq!(
        items.len(),
        EXPANDED_CURRENT_DIRECT_CONSTANTS_INPUT_ITEM_COUNT
    );
    items
}

fn controlled_transition_witness_items(
    x: &BigUint,
    y: &BigUint,
    tau_magnitude: &BigUint,
    x_next: &BigUint,
    y_next: &BigUint,
    k_magnitude: &BigUint,
    selected_cp: &BigUint,
    selected_cm: &BigUint,
    negative: bool,
    nonzero: bool,
    hints: &TransitionHints,
    current_is_expanded: bool,
    constants_are_direct_digits: bool,
) -> Vec<Vec<u8>> {
    assert!(
        nonzero || !negative,
        "identity cannot carry a negative sign"
    );
    let p = modulus();
    for value in [
        x,
        y,
        tau_magnitude,
        x_next,
        y_next,
        k_magnitude,
        selected_cp,
        selected_cm,
    ] {
        assert!(value < &p, "controlled transition field must be canonical");
    }

    let expected = if current_is_expanded {
        if constants_are_direct_digits {
            EXPANDED_CURRENT_SIGNED_DIRECT_CONSTANTS_INPUT_ITEM_COUNT
        } else {
            EXPANDED_CURRENT_SIGNED_DIRECT_K_INPUT_ITEM_COUNT
        }
    } else {
        assert!(!constants_are_direct_digits);
        PACKED_SIGNED_DIRECT_K_INPUT_ITEM_COUNT
    };
    let mut items = Vec::with_capacity(expected);
    for value in [x_next, y_next] {
        items.extend(u5_packed::packed_value_witness_items(value));
    }
    if constants_are_direct_digits {
        for value in [selected_cm, selected_cp] {
            items.extend(field_digits(value).into_iter().rev().map(scriptnum_item));
        }
    } else {
        for value in [selected_cm, selected_cp] {
            items.extend(u5_packed::packed_value_witness_items(value));
        }
    }
    items.extend(u5_packed::packed_value_witness_items(tau_magnitude));
    items.extend(
        direct_four_digit_limbs(k_magnitude)
            .into_iter()
            .rev()
            .map(scriptnum_item),
    );
    for quotient in [hints.quotients[2], hints.quotients[1], hints.quotients[0]] {
        items.push(scriptnum_item(quotient));
    }
    for value in [y, x] {
        if current_is_expanded {
            items.extend(field_digits(value).into_iter().rev().map(scriptnum_item));
        } else {
            items.extend(u5_packed::packed_value_witness_items(value));
        }
    }
    items.push(scriptnum_item(i32::from(nonzero)));
    items.push(scriptnum_item(i32::from(negative)));
    assert_eq!(items.len(), expected);
    items
}

/// Host boundary for the signed/identity first-transition packed-C+/C-
/// wrapper. Exactly three of its 74 items are quotient hints.
pub fn packed_signed_transition_direct_k_witness_items(
    x: &BigUint,
    y: &BigUint,
    tau_magnitude: &BigUint,
    x_next: &BigUint,
    y_next: &BigUint,
    k_magnitude: &BigUint,
    selected_cp: &BigUint,
    selected_cm: &BigUint,
    negative: bool,
    nonzero: bool,
    hints: &TransitionHints,
) -> Vec<Vec<u8>> {
    controlled_transition_witness_items(
        x,
        y,
        tau_magnitude,
        x_next,
        y_next,
        k_magnitude,
        selected_cp,
        selected_cm,
        negative,
        nonzero,
        hints,
        false,
        false,
    )
}

/// Host boundary for the signed/identity chained packed-C+/C- wrapper.
/// Exactly three of its 160 items are quotient hints.
pub fn chained_signed_transition_direct_k_witness_items(
    x: &BigUint,
    y: &BigUint,
    tau_magnitude: &BigUint,
    x_next: &BigUint,
    y_next: &BigUint,
    k_magnitude: &BigUint,
    selected_cp: &BigUint,
    selected_cm: &BigUint,
    negative: bool,
    nonzero: bool,
    hints: &TransitionHints,
) -> Vec<Vec<u8>> {
    controlled_transition_witness_items(
        x,
        y,
        tau_magnitude,
        x_next,
        y_next,
        k_magnitude,
        selected_cp,
        selected_cm,
        negative,
        nonzero,
        hints,
        true,
        false,
    )
}

/// Host boundary for the signed/identity chained direct-C+/C- wrapper.
/// Exactly three of its 246 items are quotient hints.
pub fn chained_signed_transition_direct_constants_witness_items(
    x: &BigUint,
    y: &BigUint,
    tau_magnitude: &BigUint,
    x_next: &BigUint,
    y_next: &BigUint,
    k_magnitude: &BigUint,
    selected_cp: &BigUint,
    selected_cm: &BigUint,
    negative: bool,
    nonzero: bool,
    hints: &TransitionHints,
) -> Vec<Vec<u8>> {
    controlled_transition_witness_items(
        x,
        y,
        tau_magnitude,
        x_next,
        y_next,
        k_magnitude,
        selected_cp,
        selected_cm,
        negative,
        nonzero,
        hints,
        true,
        true,
    )
}

// Repeating a fragment forces the repository policy's intentionally raw path
// without calling an upstream compile entry point directly. All fragments
// measured here are well above 256 bytes, so 128 copies exceed 32 KiB.
fn raw_fragment_len(fragment: Script) -> usize {
    const COPIES: usize = 128;
    let repeated = script! {
        for _ in 0..COPIES { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % COPIES, 0);
    repeated.len() / COPIES
}

/// Exact raw byte attribution for [`verify_packed_positive_transition`].
///
/// The whole wrapper is over the 32 KiB optimizer cutoff, so the repository
/// policy emits these bytes unoptimized. `routing_and_cleanup` is the exact
/// residual after independently measuring every semantic fragment.
pub fn packed_positive_transition_cost_breakdown() -> PackedPositiveTransitionCostBreakdown {
    let total = verify_packed_positive_transition(0)
        .compile_with_policy()
        .len();
    let six_products = raw_fragment_len(accumulate_streamed_product_preserving_grouping(
        false,
        Grouping::Three,
        false,
    )) + raw_fragment_len(accumulate_streamed_limb_product_grouping(
        Grouping::Four,
        true,
        true,
    )) + 2 * raw_fragment_len(accumulate_streamed_limb_product_grouping(
        Grouping::Three,
        true,
        false,
    )) + 2 * raw_fragment_len(accumulate_streamed_product_preserving_grouping(
        true,
        Grouping::Three,
        false,
    ));
    let coordinate_derivation =
        raw_fragment_len(derive_current_sum_difference_limbs(Grouping::Three))
            + raw_fragment_len(centered_digits_to_limbs(Grouping::Four, true))
            + raw_fragment_len(transform_coordinate_with_raw_y(
                CoordinateFormula::Difference,
            ))
            + raw_fragment_len(transform_coordinate_with_raw_y(
                CoordinateFormula::SumWithTwiceRawYCentered,
            ))
            + raw_fragment_len(transform_coordinate_with_raw_y(
                CoordinateFormula::RestoreRawFromCenteredSum,
            ))
            + raw_fragment_len(add_next_linear_to_accumulator(
                NextLinearFormula::SumFromDifference,
            ))
            + raw_fragment_len(add_next_linear_to_accumulator(
                NextLinearFormula::DifferenceFromSum,
            ));
    let mut cost = PackedPositiveTransitionCostBreakdown {
        decoding: PACKED_POSITIVE_CLAIMED_FIELD_COUNT * raw_fragment_len(u5_packed::decode_fast(0)),
        encoding: 2 * raw_fragment_len(u5_packed::encode_certified(0)),
        six_products,
        relation_closes: raw_fragment_len(verify_streamed_relation(false))
            + 2 * raw_fragment_len(verify_streamed_relation_absorbed()),
        accumulator_setup: RELATION_COUNT * ACCUMULATOR_COUNT,
        coordinate_derivation,
        routing_and_cleanup: 0,
    };
    let attributed = cost.total();
    cost.routing_and_cleanup = total
        .checked_sub(attributed)
        .expect("packed transition byte attribution exceeds whole script");
    debug_assert_eq!(cost.total(), total);
    cost
}

/// Raw byte attribution for the monolithic runtime-constant transition.
pub fn runtime_transition_cost_breakdown() -> TransitionCostBreakdown {
    let cost = TransitionCostBreakdown {
        r0: raw_fragment_len(runtime_r0()),
        r_plus: raw_fragment_len(runtime_r_plus()),
        r_minus: raw_fragment_len(runtime_r_minus()),
        cleanup: raw_fragment_len(retain_next_point(true)),
    };
    debug_assert_eq!(
        cost.total(),
        verify_affine_transition_runtime_constants()
            .compile_with_policy()
            .len()
    );
    cost
}

pub fn conservative_runtime_transition_cost_breakdown() -> TransitionCostBreakdown {
    let cost = TransitionCostBreakdown {
        r0: raw_fragment_len(runtime_r0_grouped(Grouping::Three)),
        r_plus: raw_fragment_len(runtime_r_plus()),
        r_minus: raw_fragment_len(runtime_r_minus()),
        cleanup: raw_fragment_len(retain_next_point(true)),
    };
    debug_assert_eq!(
        cost.total(),
        verify_affine_transition_runtime_constants_conservative()
            .compile_with_policy()
            .len()
    );
    cost
}

/// Raw bytes for the six-product scheduling boundary, excluding packed-field
/// decode/derive/repack code.
pub fn streamed_kernel_cost_breakdown() -> StreamedKernelCostBreakdown {
    let four_positive = raw_fragment_len(accumulate_streamed_product(false, true, false));
    let four_negative = raw_fragment_len(accumulate_streamed_product(false, true, true));
    let three_positive = raw_fragment_len(accumulate_streamed_product(true, false, false));
    let three_negative = raw_fragment_len(accumulate_streamed_product(true, false, true));
    StreamedKernelCostBreakdown {
        accumulator_initialization: RELATION_COUNT * ACCUMULATOR_COUNT,
        r0_products: four_positive + four_negative,
        r_plus_products: three_negative + three_positive,
        r_minus_products: three_negative + three_positive,
        relation_closes: raw_fragment_len(verify_streamed_relation(false))
            + 2 * raw_fragment_len(verify_streamed_relation(true)),
    }
}

/// Raw arithmetic bytes for the cached-limb packed-trace schedule documented
/// in the module README. Decode, digit-to-limb conversion, table selection,
/// and final repacking remain outside this boundary.
pub fn packed_schedule_kernel_cost_breakdown() -> PackedScheduleKernelCostBreakdown {
    packed_schedule_kernel_cost(false)
}

/// Conservative all-three-digit R0 counterpart to
/// [`packed_schedule_kernel_cost_breakdown`].
pub fn conservative_packed_schedule_kernel_cost_breakdown() -> PackedScheduleKernelCostBreakdown {
    packed_schedule_kernel_cost(true)
}

fn packed_schedule_kernel_cost(conservative_r0: bool) -> PackedScheduleKernelCostBreakdown {
    let close = raw_fragment_len(verify_streamed_relation(false));
    PackedScheduleKernelCostBreakdown {
        xy_product: raw_fragment_len(accumulate_streamed_product(false, !conservative_r0, false)),
        k_tau_product: raw_fragment_len(accumulate_streamed_limb_product(!conservative_r0, true)),
        a_cp_product: raw_fragment_len(accumulate_streamed_limb_product(false, true)),
        b_next_tau_product: raw_fragment_len(accumulate_streamed_limb_product(false, false)),
        b_cm_product: raw_fragment_len(accumulate_streamed_limb_product(false, true)),
        a_next_tau_product: raw_fragment_len(accumulate_streamed_limb_product(false, false)),
        // R0 and R+ start from zero. R- reuses B' directly as its initial
        // accumulator, which is a zero-byte representation change.
        accumulator_setup: 2 * ACCUMULATOR_COUNT,
        linear_add: raw_fragment_len(add_linear_to_relation_accumulator()),
        relation_closes: RELATION_COUNT * close,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{
        execution::execute_raw_script_with_inputs_strict, script::ScriptCompilation,
    };
    use num_bigint::RandBigInt;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn push_stored_digits(digits: &FieldDigits) -> Script {
        script! {
            for digit in digits.iter().rev() { { *digit } }
        }
    }

    #[test]
    fn affine_relations_have_exact_three_quotients() {
        let fixed = basepoint_constants();
        let (x_next, y_next, tau) = affine_add(&fixed.a, &fixed.b, &fixed);
        let hints = transition_hints(&fixed.a, &fixed.b, &tau, &x_next, &y_next, &fixed);
        assert_eq!(hints.witness_items().len(), HINT_ITEM_COUNT);
        assert!(hints
            .quotients
            .iter()
            .all(|q| i64::from(*q).abs() * 32 <= i64::from(i32::MAX)));
    }

    #[test]
    fn asymmetric_r0_quotient_binds_operand_orientation() {
        let fixed = basepoint_constants();
        let (x_next, y_next, tau_value) = affine_add(&fixed.a, &fixed.b, &fixed);
        let x = arithmetic_digits(&fixed.a);
        let y = arithmetic_digits(&fixed.b);
        let tau = arithmetic_digits(&tau_value);
        let k = arithmetic_digits(&fixed.k);

        let mut correct = [0i64; FIELD_DIGIT_COUNT];
        add_folded_product(&mut correct, &x, &y, 1, Grouping::Three);
        add_folded_product(&mut correct, &k, &tau, -1, Grouping::Four);
        let mut swapped = [0i64; FIELD_DIGIT_COUNT];
        add_folded_product(&mut swapped, &x, &y, 1, Grouping::Three);
        add_folded_product(&mut swapped, &tau, &k, -1, Grouping::Four);

        let p = BigInt::from_biguint(Sign::Plus, modulus());
        let correct_integer = reconstruct(&correct);
        let swapped_integer = reconstruct(&swapped);
        assert_eq!(&correct_integer % &p, BigInt::zero());
        assert_eq!(&swapped_integer % &p, BigInt::zero());
        assert_eq!((&correct_integer / &p).to_i32(), Some(114_549));
        assert_eq!((&swapped_integer / &p).to_i32(), Some(76_359));
        assert_eq!((&correct_integer - &swapped_integer) / &p, 38_190.into());

        let hints = asymmetric_r0_transition_hints(
            &fixed.a, &fixed.b, &tau_value, &x_next, &y_next, &fixed,
        );
        assert_eq!(hints.quotients[0], 114_549);
    }

    #[test]
    fn controlled_hints_cover_positive_negative_and_identity() {
        let fixed = basepoint_constants();
        let x = &fixed.a;
        let y = &fixed.b;
        let (x_positive, y_positive, tau_positive) = affine_add(x, y, &fixed);
        let positive = controlled_shared_tau_mixed_transition_hints(
            x,
            y,
            &tau_positive,
            &x_positive,
            &y_positive,
            &fixed.k,
            &fixed.cp,
            &fixed.cm,
            false,
            true,
        );
        assert_eq!(
            positive,
            shared_tau_mixed_transition_hints(
                x,
                y,
                &tau_positive,
                &x_positive,
                &y_positive,
                &fixed,
            )
        );

        let p = modulus();
        let negative_fixed = FixedPointConstants::new(&p - &fixed.a, fixed.b.clone());
        let (x_negative, y_negative, tau_negative_field) = affine_add(x, y, &negative_fixed);
        let tau_negative_magnitude = if tau_negative_field.is_zero() {
            BigUint::zero()
        } else {
            &p - tau_negative_field
        };
        let negative = controlled_shared_tau_mixed_transition_hints(
            x,
            y,
            &tau_negative_magnitude,
            &x_negative,
            &y_negative,
            &fixed.k,
            &fixed.cm,
            &fixed.cp,
            true,
            true,
        );
        assert!(negative
            .quotients
            .iter()
            .all(|quotient| i64::from(*quotient).abs() < (1 << 22)));

        let one = BigUint::one();
        let zero = BigUint::zero();
        let identity = controlled_shared_tau_mixed_transition_hints(
            x, y, &zero, x, y, &one, &one, &one, false, false,
        );
        assert_eq!(identity.quotients, [0, 0, 0]);
    }

    #[test]
    fn sampled_valid_r0_four_digit_coefficients_fit_scriptnum() {
        let fixed = basepoint_constants();
        let dab = invert(&fixed.k);
        let p = modulus();
        let mut rng = ChaCha20Rng::seed_from_u64(0xa551_4f30_4234_0001);
        let mut maximum = 0i64;
        for _ in 0..4_096 {
            let x_value = rng.gen_biguint_below(&p);
            let y_value = rng.gen_biguint_below(&p);
            let tau_value = mul_mod(&dab, &mul_mod(&x_value, &y_value));
            let x = arithmetic_digits(&x_value);
            let y = arithmetic_digits(&y_value);
            let tau = arithmetic_digits(&tau_value);
            let k = arithmetic_digits(&fixed.k);
            let mut r0 = [0i64; FIELD_DIGIT_COUNT];
            add_folded_product(&mut r0, &x, &y, 1, Grouping::Four);
            add_folded_product(&mut r0, &tau, &k, -1, Grouping::Four);
            maximum = maximum.max(r0.iter().map(|value| value.abs()).max().unwrap());
            assert!(r0.iter().all(|value| value.abs() <= i64::from(i32::MAX)));
        }
        eprintln!("sampled_r0_max_abs_coefficient={maximum}");
    }

    #[test]
    #[ignore = "generated Ed25519 Script execution is opt-in; use the focused benchmark examples"]
    fn affine_transition_script_accepts_and_rejects() {
        let fixed = basepoint_constants();
        let (x_next, y_next, tau) = affine_add(&fixed.a, &fixed.b, &fixed);
        let hints = transition_hints(&fixed.a, &fixed.b, &tau, &x_next, &y_next, &fixed);
        let witness = transition_witness_items(&fixed.a, &fixed.b, &tau, &x_next, &y_next, &hints);
        assert_eq!(witness.len(), COMPLETE_INPUT_ITEM_COUNT);
        let compiled = verify_affine_transition(&fixed).compile_with_policy();
        let execution = execute_raw_script_with_inputs_strict(compiled.to_bytes(), witness.clone());
        assert!(
            execution.error.is_none(),
            "honest transition failed: {execution}"
        );
        assert_eq!(execution.final_stack.len(), 2 * FIELD_DIGIT_COUNT);

        let wrong_x = add_mod(&x_next, &BigUint::one());
        let mut wrong_witness = witness;
        let start = 3 * FIELD_DIGIT_COUNT;
        for (slot, digit) in wrong_witness[start..start + FIELD_DIGIT_COUNT]
            .iter_mut()
            .zip(field_digits(&wrong_x).iter().rev())
        {
            *slot = scriptnum_item(*digit);
        }
        let rejected = execute_raw_script_with_inputs_strict(compiled.to_bytes(), wrong_witness);
        assert!(rejected.error.is_some(), "wrong transition was accepted");

        let runtime_witness = runtime_transition_witness_items(
            &fixed.a, &fixed.b, &tau, &x_next, &y_next, &fixed, &hints,
        );
        assert_eq!(runtime_witness.len(), RUNTIME_COMPLETE_INPUT_ITEM_COUNT);
        let runtime = verify_affine_transition_runtime_constants().compile_with_policy();
        let runtime_execution =
            execute_raw_script_with_inputs_strict(runtime.to_bytes(), runtime_witness);
        assert!(
            runtime_execution.error.is_none(),
            "honest runtime-constant transition failed: {runtime_execution}"
        );
        assert_eq!(runtime_execution.final_stack.len(), 2 * FIELD_DIGIT_COUNT);

        let conservative_hints =
            conservative_transition_hints(&fixed.a, &fixed.b, &tau, &x_next, &y_next, &fixed);
        let conservative_witness = runtime_transition_witness_items(
            &fixed.a,
            &fixed.b,
            &tau,
            &x_next,
            &y_next,
            &fixed,
            &conservative_hints,
        );
        let conservative_script =
            verify_affine_transition_runtime_constants_conservative().compile_with_policy();
        let conservative_execution = execute_raw_script_with_inputs_strict(
            conservative_script.to_bytes(),
            conservative_witness,
        );
        assert!(
            conservative_execution.error.is_none(),
            "honest conservative transition failed: {conservative_execution}"
        );
    }

    #[test]
    #[ignore = "generated Ed25519 Script execution is opt-in; use ed25519_packed_affine_transition_benchmark"]
    fn packed_positive_transition_accepts_honest_witness() {
        let fixed = basepoint_constants();
        let (x_next, y_next, tau) = affine_add(&fixed.a, &fixed.b, &fixed);
        let hints =
            asymmetric_r0_transition_hints(&fixed.a, &fixed.b, &tau, &x_next, &y_next, &fixed);
        let witness = packed_positive_transition_witness_items(
            &fixed.a, &fixed.b, &tau, &x_next, &y_next, &fixed, &hints,
        );
        assert_eq!(witness.len(), PACKED_POSITIVE_COMPLETE_INPUT_ITEM_COUNT);
        let compiled = verify_packed_positive_transition(0).compile_with_policy();
        let execution = execute_raw_script_with_inputs_strict(compiled.to_bytes(), witness);
        assert!(
            execution.error.is_none(),
            "honest packed transition failed: {execution}"
        );
        let expected = u5_packed::packed_value_witness_items(&x_next)
            .into_iter()
            .chain(u5_packed::packed_value_witness_items(&y_next))
            .collect::<Vec<_>>();
        assert_eq!(execution.final_stack.len(), expected.len());
        for (index, item) in expected.iter().enumerate() {
            assert_eq!(execution.final_stack.get(index), *item);
        }
    }

    #[test]
    #[ignore = "generated Ed25519 Script execution is opt-in; use the focused benchmark examples"]
    fn streamed_product_matches_host_coefficients() {
        let fixed = basepoint_constants();
        let lhs = field_digits(&fixed.a);
        let rhs = field_digits(&fixed.b);
        let product = convolution(
            &lhs.map(|digit| digit - DIGIT_BIAS),
            &rhs.map(|digit| digit - DIGIT_BIAS),
            Grouping::Four,
        );
        let mut expected = [0i64; FIELD_DIGIT_COUNT];
        for (index, coefficient) in product.into_iter().enumerate() {
            if index < FIELD_DIGIT_COUNT {
                expected[index] += coefficient;
            } else {
                expected[index - FIELD_DIGIT_COUNT] += 19 * coefficient;
            }
        }
        let script = script! {
            // Keep this focused test on the policy's raw path. Optimizing the
            // isolated generated product is much slower than executing it.
            for _ in 0..MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
            { push_stored_digits(&lhs) }
            { push_stored_digits(&rhs) }
            { push_relation_accumulator() }
            { accumulate_streamed_product(false, true, false) }
            for coefficient in expected {
                { coefficient } OP_NUMEQUALVERIFY
            }
            1
        }
        .compile_with_policy();
        let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), vec![]);
        assert!(
            execution.error.is_none(),
            "streamed product failed: {execution}"
        );
        assert_eq!(execution.stats.max_nb_stack_items, 187);
    }

    #[test]
    #[ignore = "generated Ed25519 Script execution is opt-in; use the focused benchmark examples"]
    fn streamed_limb_product_and_linear_add_match_host() {
        let fixed = basepoint_constants();
        let lhs = field_digits(&fixed.a);
        let rhs = field_digits(&fixed.b);
        let lhs_centered = lhs.map(|digit| digit - DIGIT_BIAS);
        let grouping = Grouping::Four;
        let limbs = (0..grouping.limb_count())
            .map(|limb_index| {
                let start = grouping.limb_start(limb_index);
                (0..grouping.limb_digits(limb_index))
                    .rev()
                    .fold(0, |value, digit| {
                        value * RADIX + lhs_centered[start + digit]
                    })
            })
            .collect::<Vec<_>>();
        let product = convolution(&lhs_centered, &arithmetic_digits(&fixed.b), grouping);
        let mut expected = [0i64; FIELD_DIGIT_COUNT];
        for (index, coefficient) in product.into_iter().enumerate() {
            if index < FIELD_DIGIT_COUNT {
                expected[index] += coefficient;
            } else {
                expected[index - FIELD_DIGIT_COUNT] += 19 * coefficient;
            }
        }
        let limb_script = script! {
            for _ in 0..MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
            for limb in limbs.iter().rev() { { *limb } }
            { push_stored_digits(&rhs) }
            { push_relation_accumulator() }
            { accumulate_streamed_limb_product(true, false) }
            for coefficient in expected { { coefficient } OP_NUMEQUALVERIFY }
            1
        }
        .compile_with_policy();
        let limb_execution = execute_raw_script_with_inputs_strict(limb_script.to_bytes(), vec![]);
        assert!(
            limb_execution.error.is_none(),
            "streamed limb product failed: {limb_execution}"
        );
        assert_eq!(limb_execution.stats.max_nb_stack_items, 148);

        let linear = arithmetic_digits(&fixed.a);
        let accumulator = arithmetic_digits(&fixed.b);
        let linear_script = script! {
            for digit in linear.iter().rev() { { *digit } }
            for digit in accumulator.iter().rev() { { *digit } }
            { add_linear_to_relation_accumulator() }
            for index in 0..FIELD_DIGIT_COUNT {
                { linear[index] + accumulator[index] } OP_NUMEQUALVERIFY
            }
            1
        }
        .compile_with_policy();
        let linear_execution =
            execute_raw_script_with_inputs_strict(linear_script.to_bytes(), vec![]);
        assert!(
            linear_execution.error.is_none(),
            "linear accumulator add failed: {linear_execution}"
        );
        assert_eq!(linear_execution.stats.max_nb_stack_items, 103);
    }

    #[test]
    #[ignore = "generated Ed25519 Script execution is opt-in; mixed-layout diagnostic"]
    fn mixed_layout_limb_conversion_matches_host() {
        let fixed = basepoint_constants();
        let digits = field_digits(&fixed.k);
        let centered = digits.map(|digit| digit - DIGIT_BIAS);
        let grouping = Grouping::MixedRZero;
        let limbs = (0..grouping.limb_count())
            .map(|limb_index| {
                let start = grouping.limb_start(limb_index);
                (0..grouping.limb_digits(limb_index))
                    .rev()
                    .fold(0, |value, digit| value * RADIX + centered[start + digit])
            })
            .collect::<Vec<_>>();
        let conversion = script! {
            { push_stored_digits(&digits) }
            { centered_digits_to_limbs(grouping, true) }
            for limb in limbs { { limb } OP_NUMEQUALVERIFY }
            1
        }
        .compile_with_policy();
        let execution = execute_raw_script_with_inputs_strict(conversion.to_bytes(), vec![]);
        assert!(
            execution.error.is_none(),
            "mixed conversion failed: {execution}"
        );
    }

    #[test]
    #[ignore = "generated Ed25519 Script execution is opt-in; asymmetric R0 diagnostic"]
    fn asymmetric_r0_fragments_match_host() {
        let fixed = basepoint_constants();
        let (x_next, y_next, tau) = affine_add(&fixed.a, &fixed.b, &fixed);
        let hints =
            asymmetric_r0_transition_hints(&fixed.a, &fixed.b, &tau, &x_next, &y_next, &fixed);
        let x = field_digits(&fixed.a);
        let y = field_digits(&fixed.b);
        let tau_digits = field_digits(&tau);
        let k = arithmetic_digits(&fixed.k);
        let grouping = Grouping::Four;
        let k_limbs = (0..grouping.limb_count())
            .map(|limb_index| {
                let start = grouping.limb_start(limb_index);
                (0..grouping.limb_digits(limb_index))
                    .rev()
                    .fold(0, |value, digit| value * RADIX + k[start + digit])
            })
            .collect::<Vec<_>>();
        let script = script! {
            for _ in 0..MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
            for limb in k_limbs.iter().rev() { { *limb } }
            { push_stored_digits(&tau_digits) }
            { push_stored_digits(&x) }
            { push_stored_digits(&y) }
            { push_relation_accumulator() }
            { accumulate_streamed_product_inner(false, Grouping::Three, false) }
            { cleanup_streamed_product_operands() }
            { accumulate_streamed_limb_product_inner(Grouping::Four, true) }
            { cleanup_streamed_limb_product_rhs() }
            { hints.quotients[0] }
            { move_block_to_top(FIELD_DIGIT_COUNT, 1) }
            { verify_streamed_relation(false) }
            1
        }
        .compile_with_policy();
        let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), vec![]);
        assert!(
            execution.error.is_none(),
            "asymmetric R0 failed: {execution}"
        );
    }

    #[test]
    #[ignore = "generated Ed25519 Script execution is opt-in; shared-tau diagnostic"]
    fn shared_tau_fragment_matches_host_coefficients() {
        let fixed = basepoint_constants();
        let (x_next, y_next, tau_value) = affine_add(&fixed.a, &fixed.b, &fixed);
        let tau = arithmetic_digits(&tau_value);
        let x = arithmetic_digits(&x_next);
        let y = arithmetic_digits(&y_next);
        let grouping = Grouping::Three;
        let tau_limbs = (0..grouping.limb_count())
            .map(|limb_index| {
                let start = grouping.limb_start(limb_index);
                (0..grouping.limb_digits(limb_index))
                    .rev()
                    .fold(0, |value, digit| value * RADIX + tau[start + digit])
            })
            .collect::<Vec<_>>();
        let mut plus = [0i64; FIELD_DIGIT_COUNT];
        let mut minus = [0i64; FIELD_DIGIT_COUNT];
        add_folded_product(&mut plus, &tau, &x, 1, grouping);
        add_folded_product(&mut plus, &tau, &y, -1, grouping);
        add_folded_product(&mut minus, &tau, &x, 1, grouping);
        add_folded_product(&mut minus, &tau, &y, 1, grouping);
        let x_raw = field_digits(&x_next);
        let y_raw = field_digits(&y_next);
        let check_pair = (0..FIELD_DIGIT_COUNT)
            .map(|coefficient| {
                script! {
                    { plus[coefficient] } OP_NUMEQUALVERIFY
                    { minus[coefficient] } OP_NUMEQUALVERIFY
                }
            })
            .collect::<Vec<_>>();
        let script = script! {
            for _ in 0..MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
            for limb in tau_limbs.iter().rev() { { *limb } }
            { push_stored_digits(&x_raw) }
            { push_stored_digits(&y_raw) }
            for _ in 0..2 * ACCUMULATOR_COUNT { 0 }
            { accumulate_shared_tau_relations() }
            for check in check_pair { { check } }
            for _ in 0..FIELD_DIGIT_COUNT { OP_2DROP }
            1
        }
        .compile_with_policy();
        let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), vec![]);
        assert!(
            execution.error.is_none(),
            "shared tau fragment failed: {execution}"
        );
        assert_eq!(execution.stats.max_nb_stack_items, 257);
    }
}
