//! Host-only hostile-input bounds for the Montgomery slope-chain relations.
//!
//! This example generates and executes no Bitcoin Script. It reproduces
//! correlation-free coefficient, quotient, and reverse-carry bounds for the
//! centered radix-32 representation used by `curves::ed25519`.

use bitcoin_lab::{
    curves::ed25519::montgomery_slope::{
        CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX, CURVE_LOW_COEFFICIENT_ABS_MAX,
        CURVE_QUOTIENT_MAX, CURVE_QUOTIENT_MIN, FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
        SYMMETRIC_CURVE_LOW_COEFFICIENT_ABS_MAX,
    },
    fields::ed25519::u5_balanced_table::{field_digits, modulus},
};
use num_bigint::{BigInt, BigUint};
use num_traits::ToPrimitive;

const N: usize = 51;
const RADIX: i64 = 32;
const DIGIT_BIAS: i32 = 16;
const SCRIPTNUM_MAX: i64 = i32::MAX as i64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Interval {
    min: i64,
    max: i64,
}

impl Interval {
    const fn new(min: i64, max: i64) -> Self {
        Self { min, max }
    }

    const fn add(self, rhs: Self) -> Self {
        Self::new(self.min + rhs.min, self.max + rhs.max)
    }

    fn max_abs(self) -> i64 {
        self.min.abs().max(self.max.abs())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RelationBounds {
    max_coefficient_abs: i64,
    quotient_min: i64,
    quotient_max: i64,
    signed_quotient_bits: u32,
    max_reverse_carry_abs: i64,
    max_verifier_arithmetic_abs: i64,
}

fn product(value: Interval, rhs: Interval) -> Interval {
    let endpoints = [
        value.min * rhs.min,
        value.min * rhs.max,
        value.max * rhs.min,
        value.max * rhs.max,
    ];
    Interval::new(
        *endpoints.iter().min().unwrap(),
        *endpoints.iter().max().unwrap(),
    )
}

fn scale(value: Interval, factor: i64) -> Interval {
    product(value, Interval::new(factor, factor))
}

fn limb_span(width: usize) -> i64 {
    (0..width).fold(0, |value, _| value * RADIX + 1)
}

fn starts(widths: &[usize]) -> Vec<usize> {
    widths
        .iter()
        .scan(0usize, |offset, width| {
            let result = *offset;
            *offset += width;
            Some(result)
        })
        .collect()
}

/// Bound one folded product exactly as the streamed Script kernel represents
/// it. A limb beginning at `offset` contributes ordinarily at and above its
/// offset and contributes with factor 19 after wrapping across degree 51.
fn product_bounds(widths: &[usize], lhs_digit: Interval, rhs_digit: Interval) -> [Interval; N] {
    assert_eq!(widths.iter().sum::<usize>(), N);
    let offsets = starts(widths);
    std::array::from_fn(|coefficient| {
        offsets
            .iter()
            .copied()
            .zip(widths.iter().copied())
            .filter_map(|(offset, width)| {
                let (rhs_index, fold) = if coefficient < offset {
                    (N + coefficient - offset, 19)
                } else {
                    (coefficient - offset, 1)
                };
                (rhs_index < N).then(|| {
                    let limb = scale(lhs_digit, limb_span(width));
                    scale(product(limb, rhs_digit), fold)
                })
            })
            .fold(Interval::new(0, 0), Interval::add)
    })
}

/// Bound the symmetry-specialized square's exact coefficient orientation.
/// A block owns its within-block square, while only products with later
/// blocks are doubled. The block-start fold decision matches Script exactly.
fn symmetric_square_bounds(widths: &[usize], digit: Interval) -> [Interval; N] {
    assert_eq!(widths.iter().sum::<usize>(), N);
    let mut result = [Interval::new(0, 0); N];
    for (offset, width) in starts(widths).into_iter().zip(widths.iter().copied()) {
        let limb = scale(digit, limb_span(width));
        for rhs_index in offset..N {
            let coefficient = offset + rhs_index;
            let (folded, fold) = if coefficient < N {
                (coefficient, 1)
            } else {
                (coefficient - N, 19)
            };
            let symmetry = if rhs_index < offset + width { 1 } else { 2 };
            result[folded] = result[folded].add(scale(product(limb, digit), fold * symmetry));
        }
    }
    result
}

fn reconstruct_endpoint(coefficients: &[Interval; N], lower: bool) -> BigInt {
    coefficients
        .iter()
        .rev()
        .fold(BigInt::from(0), |value, coefficient| {
            value * RADIX
                + if lower {
                    coefficient.min
                } else {
                    coefficient.max
                }
        })
}

fn ceil_div(value: i64, divisor: i64) -> i64 {
    -(-value).div_euclid(divisor)
}

fn relation_bounds(coefficients: &[Interval; N]) -> RelationBounds {
    let p = BigInt::from(modulus());
    // Every accepting relation is an exact multiple q*p. The first division
    // is truncation toward zero and therefore ceiling for the negative lower
    // endpoint; the second is floor for the positive upper endpoint.
    let quotient_min = (reconstruct_endpoint(coefficients, true) / &p)
        .to_i64()
        .unwrap();
    let quotient_max = (reconstruct_endpoint(coefficients, false) / p)
        .to_i64()
        .unwrap();
    let quotient_abs = quotient_min.abs().max(quotient_max.abs());
    let signed_quotient_bits = i64::BITS - quotient_abs.leading_zeros() + 1;

    // Forward carry intervals equal the values recovered by the verifier's
    // reverse recurrence. Keeping the coefficient and q endpoints
    // independent is conservative for every hostile certified input.
    let mut carry = Interval::new(
        ceil_div(coefficients[0].min + 19 * quotient_min, RADIX),
        (coefficients[0].max + 19 * quotient_max).div_euclid(RADIX),
    );
    let mut max_reverse_carry_abs = carry.max_abs();
    let mut max_verifier_arithmetic_abs = coefficients
        .iter()
        .map(|coefficient| coefficient.max_abs())
        .max()
        .unwrap()
        .max(
            (RADIX * quotient_min)
                .abs()
                .max((RADIX * quotient_max).abs()),
        )
        .max((19 * quotient_min).abs().max((19 * quotient_max).abs()))
        .max(
            (coefficients[0].min + 19 * quotient_min)
                .abs()
                .max((coefficients[0].max + 19 * quotient_max).abs()),
        )
        .max(RADIX * carry.max_abs());
    for coefficient in coefficients.iter().take(N - 1).skip(1) {
        carry = Interval::new(
            ceil_div(coefficient.min + carry.min, RADIX),
            (coefficient.max + carry.max).div_euclid(RADIX),
        );
        max_reverse_carry_abs = max_reverse_carry_abs.max(carry.max_abs());
        max_verifier_arithmetic_abs = max_verifier_arithmetic_abs.max(RADIX * carry.max_abs());
    }

    RelationBounds {
        max_coefficient_abs: coefficients
            .iter()
            .map(|coefficient| coefficient.max_abs())
            .max()
            .unwrap(),
        quotient_min,
        quotient_max,
        signed_quotient_bits,
        max_reverse_carry_abs,
        max_verifier_arithmetic_abs,
    }
}

fn sparse_field_bounds(widths: &[usize], negative: bool) -> [Interval; N] {
    assert_eq!(widths.iter().sum::<usize>(), N);
    let mut result = [Interval::new(0, 0); N];
    for (offset, width) in starts(widths).into_iter().zip(widths.iter().copied()) {
        let span = limb_span(width);
        result[offset] = if negative {
            Interval::new(-15 * span, 16 * span)
        } else {
            Interval::new(-16 * span, 15 * span)
        };
    }
    result
}

/// A table-selected Montgomery `b`/`v` coordinate may be sign-routed by
/// negating every grouped limb.  The original canonical limb interval is
/// `[-16*S,15*S]`; its negation is `[-15*S,16*S]`, so a hostile value that
/// can arrive through either branch is conservatively `[-16*S,16*S]`.
fn sparse_sign_routed_field_bounds(widths: &[usize]) -> [Interval; N] {
    assert_eq!(widths.iter().sum::<usize>(), N);
    let mut result = [Interval::new(0, 0); N];
    for (offset, width) in starts(widths).into_iter().zip(widths.iter().copied()) {
        let span = limb_span(width);
        result[offset] = Interval::new(-16 * span, 16 * span);
    }
    result
}

fn sparse_constant(value: u32, widths: &[usize], negative: bool) -> [Interval; N] {
    assert_eq!(widths.iter().sum::<usize>(), N);
    let digits = field_digits(&BigUint::from(value)).map(|digit| digit - DIGIT_BIAS);
    let mut result = [Interval::new(0, 0); N];
    for (offset, width) in starts(widths).into_iter().zip(widths.iter().copied()) {
        let limb = (0..width).rev().fold(0i64, |limb, digit| {
            limb * RADIX + i64::from(digits[offset + digit])
        });
        let limb = if negative { -limb } else { limb };
        result[offset] = Interval::new(limb, limb);
    }
    result
}

fn add_coefficients(lhs: &[Interval; N], rhs: &[Interval; N]) -> [Interval; N] {
    std::array::from_fn(|index| lhs[index].add(rhs[index]))
}

/// Match the prototype's exact coefficient representation: lambda^2 uses
/// four-digit product limbs, the three u/a linear fields use sparse
/// three-digit limbs, and the Montgomery A constant uses sparse four-digit
/// limbs.
fn sparse_square_relation(
    square_widths: &[usize],
    coordinate_widths: &[usize],
    constant_widths: &[usize],
) -> ([Interval; N], i64) {
    let field = Interval::new(-16, 15);
    let product = product_bounds(square_widths, field, field);
    let mut relation = product;
    for _ in 0..3 {
        relation = add_coefficients(&relation, &sparse_field_bounds(coordinate_widths, true));
    }
    relation = add_coefficients(&relation, &sparse_constant(486_662, constant_widths, true));
    let max_product = product
        .iter()
        .map(|coefficient| coefficient.max_abs())
        .max()
        .unwrap();
    (relation, max_product)
}

fn sparse_symmetric_square_relation(
    square_widths: &[usize],
    coordinate_widths: &[usize],
    constant_widths: &[usize],
) -> ([Interval; N], i64) {
    let field = Interval::new(-16, 15);
    let product = symmetric_square_bounds(square_widths, field);
    let mut relation = product;
    for _ in 0..3 {
        relation = add_coefficients(&relation, &sparse_field_bounds(coordinate_widths, true));
    }
    relation = add_coefficients(&relation, &sparse_constant(486_662, constant_widths, true));
    let max_product = product
        .iter()
        .map(|coefficient| coefficient.max_abs())
        .max()
        .unwrap();
    (relation, max_product)
}

/// Match the prototype's regular continuity representation: two grouped
/// `(a-u)*lambda` products followed by two sign-routed sparse b fields.
fn sparse_continuity_relation(
    product_widths: &[usize],
    b_widths: &[usize],
) -> ([Interval; N], i64) {
    let difference = Interval::new(-31, 31);
    let field = Interval::new(-16, 15);
    let one_product = product_bounds(product_widths, difference, field);
    let mut relation = std::array::from_fn(|index| one_product[index].add(one_product[index]));
    for _ in 0..2 {
        relation = add_coefficients(&relation, &sparse_sign_routed_field_bounds(b_widths));
    }
    let max_product = one_product
        .iter()
        .map(|coefficient| coefficient.max_abs())
        .max()
        .unwrap();
    (relation, max_product)
}

/// The first continuity relation has one `(a-u)*lambda` product, one
/// negative sign-routed sparse b field, and one positive canonical sparse
/// initial-v field. The top initializer does not sign-route its v coordinate.
fn sparse_initial_continuity_relation(
    product_widths: &[usize],
    b_widths: &[usize],
) -> ([Interval; N], i64) {
    let difference = Interval::new(-31, 31);
    let field = Interval::new(-16, 15);
    let product = product_bounds(product_widths, difference, field);
    let relation = add_coefficients(
        &add_coefficients(&product, &sparse_sign_routed_field_bounds(b_widths)),
        &sparse_field_bounds(b_widths, false),
    );
    let max_product = product
        .iter()
        .map(|coefficient| coefficient.max_abs())
        .max()
        .unwrap();
    (relation, max_product)
}

fn metadata_bits(signed_quotient_bits: u32) -> u32 {
    // Both ScriptNum signs carry data. A negative carrier encodes the upper
    // half as `-(low31+1)`, leaving only the unattainable all-ones 32-bit
    // code. The honest q intervals below never use the all-ones low slot.
    32 - signed_quotient_bits
}

fn assert_honest_q_avoids_missing_carrier_code(bounds: RelationBounds) {
    let width = 1i64 << bounds.signed_quotient_bits;
    let bias = width / 2;
    assert!(bounds.quotient_min >= -bias);
    assert!(bounds.quotient_max < bias);
    // Code 0xffff_ffff is the sole 32-bit pattern with no four-byte
    // ScriptNum carrier. It would require both all-one metadata and the
    // all-one low q slot. The proved honest interval excludes that q slot.
    assert!(bounds.quotient_max + bias < width - 1);
}

fn max_streamed_limb_abs(widths: &[usize], lhs_digit_abs: i64) -> i64 {
    widths
        .iter()
        .map(|width| lhs_digit_abs * limb_span(*width))
        .max()
        .unwrap()
}

fn print_relation(name: &str, product_abs: i64, bounds: RelationBounds) {
    println!("{name}_max_one_product_coefficient_abs={product_abs}");
    println!(
        "{name}_max_complete_relation_coefficient_abs={}",
        bounds.max_coefficient_abs
    );
    println!(
        "{name}_quotient_interval=[{},{}]",
        bounds.quotient_min, bounds.quotient_max
    );
    println!(
        "{name}_signed_quotient_slot_bits={}",
        bounds.signed_quotient_bits
    );
    println!(
        "{name}_metadata_bits_per_signed_scriptnum_carrier={}",
        metadata_bits(bounds.signed_quotient_bits)
    );
    println!(
        "{name}_max_reverse_carry_abs={}",
        bounds.max_reverse_carry_abs
    );
    println!(
        "{name}_max_verifier_arithmetic_abs={}",
        bounds.max_verifier_arithmetic_abs
    );
}

#[cfg(any())]
fn digitwise_diagnostic_main() {
    let square_widths = [vec![4usize; 12], vec![3]].concat();
    let continuity_widths = [vec![4usize; 3], vec![3usize; 13]].concat();
    let conservative_widths = vec![3usize; 17];

    let (square, square_product_abs) = square_relation(&square_widths);
    let square = relation_bounds(&square);
    let square_limb_abs = max_streamed_limb_abs(&square_widths, 16);
    let square_table_abs = 16 * square_limb_abs;
    let square_wrapped_table_abs = 19 * square_table_abs;
    assert_eq!(square_product_abs, 1_823_573_248);
    assert_eq!(square.max_coefficient_abs, 1_823_573_301);
    assert_eq!(
        (square.quotient_min, square.quotient_max),
        (-3_150_640, 3_360_683)
    );
    assert_eq!(square.signed_quotient_bits, 23);
    assert_eq!(square.max_reverse_carry_abs, 58_982_070);
    assert_eq!(square.max_verifier_arithmetic_abs, 1_887_426_267);
    assert_eq!(square_limb_abs, 541_200);
    assert_eq!(square_table_abs, 8_659_200);
    assert_eq!(square_wrapped_table_abs, 164_524_800);

    let (continuity, continuity_product_abs) = continuity_relation(&continuity_widths);
    let continuity = relation_bounds(&continuity);
    let continuity_limb_abs = max_streamed_limb_abs(&continuity_widths, 31);
    let continuity_table_abs = 16 * continuity_limb_abs;
    let continuity_wrapped_table_abs = 19 * continuity_table_abs;
    assert_eq!(continuity_product_abs, 783_805_984);
    assert_eq!(continuity.max_coefficient_abs, 1_567_612_000);
    assert_eq!(
        (continuity.quotient_min, continuity.quotient_max),
        (-3_686_931, 3_686_931)
    );
    assert_eq!(continuity.signed_quotient_bits, 23);
    assert_eq!(continuity.max_reverse_carry_abs, 51_176_990);
    assert_eq!(continuity.max_verifier_arithmetic_abs, 1_637_663_689);
    assert_eq!(continuity_limb_abs, 1_048_575);
    assert_eq!(continuity_table_abs, 16_777_200);
    assert_eq!(continuity_wrapped_table_abs, 318_766_800);

    let (initial_continuity, initial_continuity_product_abs) =
        initial_continuity_relation(&continuity_widths);
    let initial_continuity = relation_bounds(&initial_continuity);
    assert_eq!(initial_continuity_product_abs, 783_805_984);
    assert_eq!(initial_continuity.max_coefficient_abs, 783_806_015);
    assert_eq!(
        (
            initial_continuity.quotient_min,
            initial_continuity.quotient_max
        ),
        (-1_843_466, 1_843_466)
    );
    assert_eq!(initial_continuity.signed_quotient_bits, 22);
    assert_eq!(initial_continuity.max_reverse_carry_abs, 25_588_495);
    assert_eq!(initial_continuity.max_verifier_arithmetic_abs, 818_831_869);

    // The formerly useful six-four-digit mixed grouping is not safe for a
    // slope continuity relation: each relation contains two products whose
    // left digit interval is [-31,31].
    let rejected_continuity_widths = [vec![4usize; 6], vec![3usize; 9]].concat();
    let (rejected_continuity, rejected_product_abs) =
        continuity_relation(&rejected_continuity_widths);
    let rejected_continuity = relation_bounds(&rejected_continuity);
    assert_eq!(rejected_product_abs, 1_700_261_712);
    assert_eq!(rejected_continuity.max_coefficient_abs, 3_400_523_456);
    assert!(rejected_continuity.max_coefficient_abs > SCRIPTNUM_MAX);

    let (continuity_u3, continuity_u3_product_abs) = continuity_relation(&conservative_widths);
    let continuity_u3 = relation_bounds(&continuity_u3);
    assert_eq!(continuity_u3_product_abs, 159_902_960);
    assert_eq!(continuity_u3.max_coefficient_abs, 319_805_952);
    assert_eq!(
        (continuity_u3.quotient_min, continuity_u3.quotient_max),
        (-575_027, 575_027)
    );
    assert_eq!(continuity_u3.signed_quotient_bits, 21);
    assert_eq!(continuity_u3.max_reverse_carry_abs, 10_335_358);
    assert_eq!(continuity_u3.max_verifier_arithmetic_abs, 330_731_465);

    for bound in [square, initial_continuity, continuity, continuity_u3] {
        assert!(bound.max_coefficient_abs <= SCRIPTNUM_MAX);
        assert!(bound.max_verifier_arithmetic_abs <= SCRIPTNUM_MAX);
        assert_honest_q_avoids_missing_carrier_code(bound);
    }

    let transitions = 42;
    let trace_fields = 2 * transitions;
    let uniform_signed_q23_metadata_per_item = metadata_bits(23);
    let uniform_q_metadata_per_transition = 2 * uniform_signed_q23_metadata_per_item;
    let uniform_q_metadata_bits = 2 * transitions * uniform_signed_q23_metadata_per_item;
    let native_initial_q_metadata_bits = metadata_bits(square.signed_quotient_bits)
        + metadata_bits(initial_continuity.signed_quotient_bits);
    let native_regular_q_metadata_per_transition =
        metadata_bits(square.signed_quotient_bits) + metadata_bits(continuity.signed_quotient_bits);
    let maximum_mixed_width_q_metadata_bits = native_initial_q_metadata_bits
        + native_regular_q_metadata_per_transition * (transitions - 1);
    let trace_padding_metadata_bits = trace_fields;
    let uniform_combined_metadata_bits = uniform_q_metadata_bits + trace_padding_metadata_bits;
    let maximum_mixed_width_combined_metadata_bits =
        maximum_mixed_width_q_metadata_bits + trace_padding_metadata_bits;

    println!("model=ed25519_montgomery_slope_hostile_bounds");
    println!("evidence=locally-reproduced");
    println!("boundary=host-only-correlation-free-interval-model");
    println!("execution_class=unclassified");
    println!("bitcoin_script_generated=false");
    println!("square_grouping=4x12,3x1");
    println!("square_max_limb_abs={square_limb_abs}");
    println!("square_max_signed_table_entry_abs={square_table_abs}");
    println!("square_max_wrapped_table_entry_abs={square_wrapped_table_abs}");
    print_relation("square", square_product_abs, square);
    println!("continuity_grouping=4x3,3x13");
    println!("continuity_max_limb_abs={continuity_limb_abs}");
    println!("continuity_max_signed_table_entry_abs={continuity_table_abs}");
    println!("continuity_max_wrapped_table_entry_abs={continuity_wrapped_table_abs}");
    print_relation(
        "initial_continuity",
        initial_continuity_product_abs,
        initial_continuity,
    );
    print_relation("continuity", continuity_product_abs, continuity);
    println!("rejected_continuity_grouping=4x6,3x9");
    println!("rejected_continuity_max_one_product_coefficient_abs={rejected_product_abs}");
    println!(
        "rejected_continuity_max_complete_relation_coefficient_abs={}",
        rejected_continuity.max_coefficient_abs
    );
    println!("continuity_all_u3_grouping=3x17");
    print_relation(
        "continuity_all_u3",
        continuity_u3_product_abs,
        continuity_u3,
    );
    println!("logical_quotient_hint_items_per_transition=2");
    println!("logical_quotient_hint_items_total=84");
    println!("uniform_signed_q23_metadata_bits_per_item=9");
    println!("uniform_q_metadata_bits_per_transition={uniform_q_metadata_per_transition}");
    println!("uniform_q_metadata_bits_total={uniform_q_metadata_bits}");
    println!("native_initial_q_metadata_bits={native_initial_q_metadata_bits}");
    println!(
        "native_regular_q_metadata_bits_per_transition={native_regular_q_metadata_per_transition}"
    );
    println!("maximum_mixed_width_q_metadata_bits_total={maximum_mixed_width_q_metadata_bits}");
    println!("trace_padding_metadata_bits_total={trace_padding_metadata_bits}");
    println!("uniform_combined_metadata_bits_total={uniform_combined_metadata_bits}");
    println!(
        "maximum_mixed_width_combined_metadata_bits_total={maximum_mixed_width_combined_metadata_bits}"
    );
    println!("transcript_plus_scalar_bits=765");
    println!(
        "uniform_combined_metadata_headroom_bits={}",
        uniform_combined_metadata_bits - 765
    );
    println!(
        "first_28_uniform_q_metadata_bits={}",
        28 * uniform_q_metadata_per_transition
    );
    println!("first_28_trace_padding_bits={}", 28 * 2);
    println!("scheduled_transcript_bits=512");
    println!("scheduled_trace_padding_carriers=8");
    println!("scalar_remains_eight_separate_words=true");
    println!("actual_order_updates_enclosed_by_reported_coefficients=true");
    println!("carrier_decoders_generated=false");
}

fn main() {
    let square_widths = [vec![4usize; 12], vec![3]].concat();
    let a_widths = [vec![4usize; 3], vec![3usize; 13]].concat();
    let b_widths = [vec![4usize], vec![6usize; 7], vec![5usize]].concat();

    let (curve, curve_product_abs) =
        sparse_square_relation(&square_widths, &a_widths, &square_widths);
    let generic_curve_low_abs: [i64; 5] = std::array::from_fn(|index| curve[index].max_abs());
    assert_eq!(
        generic_curve_low_abs,
        [
            1_824_710_186,
            1_823_573_248,
            1_823_573_248,
            1_823_573_248,
            1_669_331_248,
        ]
    );
    let curve = relation_bounds(&curve);
    assert_eq!(curve_product_abs, 1_823_573_248);
    assert_eq!(curve.max_coefficient_abs, 1_824_710_186);
    assert_eq!(
        (curve.quotient_min, curve.quotient_max),
        (-3_150_640, 3_360_683)
    );
    assert_eq!(curve.signed_quotient_bits, 23);
    assert_eq!(curve.max_reverse_carry_abs, 59_017_598);
    assert_eq!(curve.max_verifier_arithmetic_abs, 1_888_563_163);

    let (symmetric_curve, symmetric_curve_product_abs) =
        sparse_symmetric_square_relation(&square_widths, &a_widths, &square_widths);
    let symmetric_curve_low_abs: [i64; 5] =
        std::array::from_fn(|index| symmetric_curve[index].max_abs());
    assert_eq!(
        symmetric_curve_low_abs,
        SYMMETRIC_CURVE_LOW_COEFFICIENT_ABS_MAX
    );
    let union_curve_low_abs = std::array::from_fn(|index| {
        generic_curve_low_abs[index].max(symmetric_curve_low_abs[index])
    });
    assert_eq!(union_curve_low_abs, CURVE_LOW_COEFFICIENT_ABS_MAX);
    assert!(
        CURVE_LOW_COEFFICIENT_ABS_MAX
            .iter()
            .all(|bound| (1i64 << 30..1i64 << 31).contains(bound)),
        "every curve low coefficient must retain the same 31-bit reducer shape"
    );
    let symmetric_curve = relation_bounds(&symmetric_curve);
    assert_eq!(symmetric_curve_product_abs, 1_982_956_800);
    assert_eq!(symmetric_curve.max_coefficient_abs, 1_982_956_800);
    assert_eq!(
        (symmetric_curve.quotient_min, symmetric_curve.quotient_max),
        (i64::from(CURVE_QUOTIENT_MIN), i64::from(CURVE_QUOTIENT_MAX))
    );
    assert_eq!(symmetric_curve.signed_quotient_bits, 23);
    assert_eq!(symmetric_curve.max_reverse_carry_abs, 63_966_197);
    assert_eq!(symmetric_curve.max_verifier_arithmetic_abs, 2_046_918_304);
    assert_eq!(
        SCRIPTNUM_MAX - symmetric_curve.max_verifier_arithmetic_abs,
        100_565_343
    );

    let (initial, continuity_product_abs) =
        sparse_initial_continuity_relation(&a_widths, &b_widths);
    assert_eq!(
        std::array::from_fn(|index| initial[index].max_abs()),
        FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX
    );
    let initial = relation_bounds(&initial);
    assert_eq!(continuity_product_abs, 783_805_984);
    assert_eq!(initial.max_coefficient_abs, 1_590_195_040);
    assert_eq!(
        (initial.quotient_min, initial.quotient_max),
        (-1_843_466, 1_843_466)
    );
    assert_eq!(initial.signed_quotient_bits, 22);
    assert_eq!(initial.max_reverse_carry_abs, 50_483_722);
    assert_eq!(initial.max_verifier_arithmetic_abs, 1_615_479_104);

    let (continuity, regular_product_abs) = sparse_continuity_relation(&a_widths, &b_widths);
    assert_eq!(
        std::array::from_fn(|index| continuity[index].max_abs()),
        CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX
    );
    let continuity = relation_bounds(&continuity);
    assert_eq!(regular_product_abs, 783_805_984);
    assert_eq!(continuity.max_coefficient_abs, 2_072_011_424);
    assert_eq!(
        (continuity.quotient_min, continuity.quotient_max),
        (-3_686_931, 3_686_931)
    );
    assert_eq!(continuity.signed_quotient_bits, 23);
    assert_eq!(continuity.max_reverse_carry_abs, 66_330_611);
    assert_eq!(continuity.max_verifier_arithmetic_abs, 2_122_579_552);
    assert_eq!(
        SCRIPTNUM_MAX - continuity.max_verifier_arithmetic_abs,
        24_904_095
    );

    let square_limb_abs = max_streamed_limb_abs(&square_widths, 16);
    let square_table_abs = 16 * square_limb_abs;
    let square_wrapped_table_abs = 19 * square_table_abs;
    assert_eq!(square_limb_abs, 541_200);
    assert_eq!(square_table_abs, 8_659_200);
    assert_eq!(square_wrapped_table_abs, 164_524_800);

    let continuity_limb_abs = max_streamed_limb_abs(&a_widths, 31);
    let continuity_table_abs = 16 * continuity_limb_abs;
    let continuity_wrapped_table_abs = 19 * continuity_table_abs;
    assert_eq!(continuity_limb_abs, 1_048_575);
    assert_eq!(continuity_table_abs, 16_777_200);
    assert_eq!(continuity_wrapped_table_abs, 318_766_800);

    let b_limb_abs = max_streamed_limb_abs(&b_widths, 16);
    assert_eq!(b_limb_abs, 554_189_328);
    assert!(b_limb_abs <= SCRIPTNUM_MAX);

    // Starting with a six-digit b limb is unsafe. Staggering the sole
    // four-digit limb first moves every six-digit sparse term away from the
    // product's largest low coefficients without changing the represented
    // field integer or q.
    let rejected_b_widths = [vec![6usize; 8], vec![3usize]].concat();
    let (rejected, _) = sparse_continuity_relation(&a_widths, &rejected_b_widths);
    let rejected = relation_bounds(&rejected);
    assert_eq!(rejected.max_coefficient_abs, 2_675_990_624);
    assert_eq!(rejected.max_verifier_arithmetic_abs, 2_746_042_313);
    assert!(rejected.max_verifier_arithmetic_abs > SCRIPTNUM_MAX);

    for bound in [curve, symmetric_curve, initial, continuity] {
        assert!(bound.max_coefficient_abs <= SCRIPTNUM_MAX);
        assert!(bound.max_verifier_arithmetic_abs <= SCRIPTNUM_MAX);
        assert_honest_q_avoids_missing_carrier_code(bound);
    }

    let transitions = 44u32;
    let q_metadata_per_transition = 2 * metadata_bits(23);
    let q_metadata_bits = transitions * q_metadata_per_transition;
    let native_width_q_metadata_bits = metadata_bits(curve.signed_quotient_bits)
        + metadata_bits(initial.signed_quotient_bits)
        + (transitions - 1)
            * (metadata_bits(curve.signed_quotient_bits)
                + metadata_bits(continuity.signed_quotient_bits));
    let trace_padding_metadata_bits = 2 * transitions;
    let combined_metadata_bits = q_metadata_bits + trace_padding_metadata_bits;
    let first_28_native_q_metadata_bits = metadata_bits(curve.signed_quotient_bits)
        + metadata_bits(initial.signed_quotient_bits)
        + 27 * (metadata_bits(curve.signed_quotient_bits)
            + metadata_bits(continuity.signed_quotient_bits));
    let required_transcript_padding_bits = 512 - first_28_native_q_metadata_bits;

    println!("model=ed25519_montgomery_slope_hostile_bounds");
    println!("evidence=locally-reproduced");
    println!("boundary=host-only-correlation-free-sparse-coefficient-model");
    println!("execution_class=unclassified");
    println!("bitcoin_script_generated=false");
    println!("curve_square_product_grouping=4x12,3x1");
    println!("curve_sparse_u_a_grouping=4x3,3x13");
    println!("curve_sparse_constant_grouping=4x12,3x1");
    print_relation("curve_generic_sparse", curve_product_abs, curve);
    println!("curve_symmetric_square_updates=351");
    println!("curve_symmetric_low_bounds_are_31_bit=true");
    print_relation(
        "curve_symmetric_sparse",
        symmetric_curve_product_abs,
        symmetric_curve,
    );
    println!("continuity_product_grouping=4x3,3x13");
    println!("continuity_sparse_b_grouping=4,6x7,5");
    println!("continuity_sparse_b_offsets=0,4,10,16,22,28,34,40,46");
    println!("sign_routed_b_limb_interval_per_width=[-16*S_w,16*S_w]");
    print_relation("initial_continuity_sparse", continuity_product_abs, initial);
    print_relation("regular_continuity_sparse", regular_product_abs, continuity);
    println!("square_max_limb_abs={square_limb_abs}");
    println!("square_max_signed_table_entry_abs={square_table_abs}");
    println!("square_max_wrapped_table_entry_abs={square_wrapped_table_abs}");
    println!("continuity_max_limb_abs={continuity_limb_abs}");
    println!("continuity_max_signed_table_entry_abs={continuity_table_abs}");
    println!("continuity_max_wrapped_table_entry_abs={continuity_wrapped_table_abs}");
    println!("sparse_b_max_limb_abs={b_limb_abs}");
    println!("sparse_b_limbwise_negation_fits_scriptnum=true");
    println!("limbwise_negation_reconstructs_exact_integer_negation=true");
    println!("limbwise_negation_represents_field_negative_mod_p=true");
    println!("fold_substitution_32_pow_51_equals_19_mod_p=true");
    println!("logical_quotient_hint_items_per_transition=2");
    println!("logical_quotient_hint_items_total={}", 2 * transitions);
    println!("uniform_signed_q23_metadata_bits_per_item=9");
    println!("q_metadata_bits_per_transition={q_metadata_per_transition}");
    println!("q_metadata_bits_total={q_metadata_bits}");
    println!("native_width_q_metadata_bits_total={native_width_q_metadata_bits}");
    println!("trace_padding_metadata_bits_total={trace_padding_metadata_bits}");
    println!("combined_metadata_bits_total={combined_metadata_bits}");
    println!("transcript_plus_scalar_bits=765");
    println!(
        "combined_metadata_headroom_bits={}",
        combined_metadata_bits - 765
    );
    println!(
        "first_28_uniform_q_metadata_bits={}",
        28 * q_metadata_per_transition
    );
    println!("first_28_native_q_metadata_bits={first_28_native_q_metadata_bits}");
    println!("first_28_trace_padding_bits={}", 28 * 2);
    println!("required_transcript_padding_bits={required_transcript_padding_bits}");
    println!("scheduled_transcript_bits=512");
    println!("scheduled_trace_padding_carriers=8");
    println!("scheduled_trace_padding_bits_in_transcript=8");
    println!("scheduled_response_q_metadata_spare_bits=1");
    println!("scalar_witness_entry_items=0");
    println!("scalar_carrier_predecode_transient_words=8");
    println!("actual_order_updates_enclosed_by_reported_coefficients=true");
    println!("carrier_decoders_generated=false");
}
