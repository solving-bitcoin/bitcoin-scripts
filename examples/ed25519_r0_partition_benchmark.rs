//! Raw-byte and arithmetic-bound comparison of safe Ed25519 affine-relation
//! limb partitions.
//!
//! This reproduces only the streamed product/cache fragments and deliberately
//! forces the repository compilation policy's unoptimized path. It executes
//! no long-running Script test.

use bitcoin_lab::{
    arithmetic::scriptint,
    support::script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
};
use num_bigint::BigInt;
use num_traits::{One, ToPrimitive};

const N: usize = 51;
const TABLE: usize = 32;
const RADIX: u32 = 32;
const BIAS: i32 = 16;

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

    fn subtract(self, rhs: Self) -> Self {
        Self {
            min: self.min - rhs.max,
            max: self.max - rhs.min,
        }
    }

    fn max_abs(self) -> i64 {
        self.min.abs().max(self.max.abs())
    }
}

fn starts(widths: &[usize]) -> Vec<usize> {
    widths
        .iter()
        .scan(0usize, |offset, width| {
            let start = *offset;
            *offset += width;
            Some(start)
        })
        .collect()
}

fn raw_len(fragment: Script) -> usize {
    const COPIES: usize = 512;
    let repeated = script! { for _ in 0..COPIES { { fragment.clone() } } }.compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % COPIES, 0);
    repeated.len() / COPIES
}

fn term_bound(width: usize, offset: usize, coefficient: usize) -> Option<Interval> {
    term_bound_for(
        width,
        offset,
        coefficient,
        Interval { min: -16, max: 15 },
        Interval { min: -16, max: 15 },
    )
}

fn term_bound_for(
    width: usize,
    offset: usize,
    coefficient: usize,
    lhs_digit: Interval,
    rhs_digit: Interval,
) -> Option<Interval> {
    let (rhs_index, scale) = if coefficient < offset {
        (N + coefficient - offset, 19)
    } else {
        (coefficient - offset, 1)
    };
    if rhs_index >= N {
        return None;
    }
    let span = (0..width).fold(0i64, |value, _| value * i64::from(RADIX) + 1);
    let limb = Interval {
        min: lhs_digit.min * span,
        max: lhs_digit.max * span,
    };
    let values = [
        scale * limb.min * rhs_digit.min,
        scale * limb.min * rhs_digit.max,
        scale * limb.max * rhs_digit.min,
        scale * limb.max * rhs_digit.max,
    ];
    Some(Interval {
        min: *values.iter().min().unwrap(),
        max: *values.iter().max().unwrap(),
    })
}

fn product_bounds_for(widths: &[usize], lhs_digit: Interval, rhs_digit: Interval) -> [Interval; N] {
    let offsets = starts(widths);
    std::array::from_fn(|coefficient| {
        offsets
            .iter()
            .copied()
            .zip(widths.iter().copied())
            .filter_map(|(offset, width)| {
                term_bound_for(width, offset, coefficient, lhs_digit, rhs_digit)
            })
            .fold(Interval { min: 0, max: 0 }, Interval::add)
    })
}

fn product_bounds(widths: &[usize]) -> [Interval; N] {
    product_bounds_for(
        widths,
        Interval { min: -16, max: 15 },
        Interval { min: -16, max: 15 },
    )
}

fn ceil_div(value: i64, divisor: i64) -> i64 {
    -(-value).div_euclid(divisor)
}

fn bound_report(first: &[usize], second: &[usize]) -> (i64, i64, i64, i64, i64) {
    let first_bounds = product_bounds(first);
    let second_bounds = product_bounds(second);
    let relation: [Interval; N] =
        std::array::from_fn(|index| first_bounds[index].subtract(second_bounds[index]));

    // Match the Script schedule exactly: the complete first product is live,
    // then wrapped and ordinary updates of each second-product limb occur.
    let mut live = first_bounds;
    let mut maximum_update = live.iter().map(|bound| bound.max_abs()).max().unwrap();
    for (offset, width) in starts(second).into_iter().zip(second.iter().copied()) {
        for coefficient in (0..offset).chain(offset..N) {
            if let Some(term) = term_bound(width, offset, coefficient) {
                live[coefficient] = live[coefficient].subtract(term);
                maximum_update = maximum_update.max(live[coefficient].max_abs());
            }
        }
    }
    assert!(live
        .iter()
        .zip(relation.iter())
        .all(|(lhs, rhs)| lhs.min == rhs.min && lhs.max == rhs.max));

    let reconstruct = |select_min: bool| {
        relation.iter().rev().fold(BigInt::from(0), |value, bound| {
            value * RADIX + if select_min { bound.min } else { bound.max }
        })
    };
    let modulus = (BigInt::one() << 255usize) - BigInt::from(19);
    // The lower endpoint is negative and truncation toward zero is ceil;
    // the positive upper endpoint truncates to floor.
    let quotient_min = (reconstruct(true) / &modulus).to_i64().unwrap();
    let quotient_max = (reconstruct(false) / &modulus).to_i64().unwrap();

    let mut carry = Interval {
        min: ceil_div(relation[0].min + 19 * quotient_min, i64::from(RADIX)),
        max: (relation[0].max + 19 * quotient_max).div_euclid(i64::from(RADIX)),
    };
    let mut maximum_carry = carry.max_abs();
    let mut maximum_verifier = relation
        .iter()
        .map(|bound| bound.max_abs())
        .max()
        .unwrap()
        .max((19 * quotient_min).abs().max((19 * quotient_max).abs()))
        .max(
            (relation[0].min + 19 * quotient_min)
                .abs()
                .max((relation[0].max + 19 * quotient_max).abs()),
        )
        .max(32 * carry.max_abs());
    for bound in relation.iter().take(N - 1).skip(1) {
        carry = Interval {
            min: ceil_div(bound.min + carry.min, i64::from(RADIX)),
            max: (bound.max + carry.max).div_euclid(i64::from(RADIX)),
        };
        maximum_carry = maximum_carry.max(carry.max_abs());
        maximum_verifier = maximum_verifier.max(32 * carry.max_abs());
    }
    (
        maximum_update,
        quotient_min,
        quotient_max,
        maximum_carry,
        maximum_verifier,
    )
}

fn signed_table() -> Script {
    script! {
        OP_DUP
        for _ in 0..4 { OP_DUP OP_ADD }
        OP_OVER OP_SUB OP_SWAP
        for _ in 0..31 { OP_2DUP OP_SUB OP_SWAP }
        OP_DROP
    }
}

fn drop_table() -> Script {
    script! { for _ in 0..TABLE / 2 { OP_2DROP } }
}

fn pick_lhs_digit(digit: usize, live_accumulators: usize, transient: usize) -> Script {
    script! { { (live_accumulators + N + digit + transient) as u32 } OP_PICK }
}

fn build_lhs_limb(
    start: usize,
    width: usize,
    live_accumulators: usize,
    scaled_by_19: bool,
) -> Script {
    let span = (0..width).fold(0, |value, _| value * RADIX as i32 + 1);
    let bias = BIAS * span;
    script! {
        { pick_lhs_digit(start + width - 1, live_accumulators, 0) }
        for digit in (0..width - 1).rev() {
            { scriptint::mul_by_constant(RADIX) }
            { pick_lhs_digit(start + digit, live_accumulators, 1) }
            OP_ADD
        }
        { bias } OP_SUB
        if scaled_by_19 { { scriptint::mul_by_constant(19) } }
    }
}

fn update(rhs_digit: usize, unprocessed_accumulators: usize) -> Script {
    script! {
        { (TABLE + unprocessed_accumulators + rhs_digit) as u32 } OP_PICK
        OP_PICK
        { (TABLE + 1) as u32 } OP_ROLL
        OP_ADD OP_TOALTSTACK
    }
}

fn streamed_xy_inner(widths: &[usize]) -> Script {
    let limbs = starts(widths)
        .into_iter()
        .zip(widths.iter().copied())
        .map(|(offset, width)| {
            let wrapped = if offset == 0 {
                Script::new("no wrapped coefficients")
            } else {
                script! {
                    { build_lhs_limb(offset, width, N, true) }
                    { signed_table() }
                    for coefficient in 0..offset {
                        { update(N + coefficient - offset, N - coefficient) }
                    }
                    { drop_table() }
                }
            };
            script! {
                { wrapped }
                { build_lhs_limb(offset, width, N - offset, false) }
                { signed_table() }
                for coefficient in offset..N {
                    { update(coefficient - offset, N - coefficient) }
                }
                { drop_table() }
                for _ in 0..N { OP_FROMALTSTACK }
            }
        })
        .collect::<Vec<_>>();
    script! { for limb in limbs { { limb } } }
}

fn cleanup_two_fields() -> Script {
    script! {
        for _ in 0..N { OP_TOALTSTACK }
        for _ in 0..N { OP_2DROP }
        for _ in 0..N { OP_FROMALTSTACK }
    }
}

fn streamed_xy(widths: &[usize]) -> Script {
    script! { { streamed_xy_inner(widths) } { cleanup_two_fields() } }
}

fn take_limb(live_accumulators: usize, scaled_by_19: bool, copy: bool) -> Script {
    let depth = N + live_accumulators;
    let select = if copy {
        script! { { depth as u32 } OP_PICK }
    } else {
        script! { { depth as u32 } OP_ROLL }
    };
    script! {
        { select }
        OP_NEGATE
        if scaled_by_19 { { scriptint::mul_by_constant(19) } }
    }
}

fn cached_k_tau_inner(widths: &[usize]) -> Script {
    let limbs = starts(widths)
        .into_iter()
        .map(|offset| {
            let wrapped = if offset == 0 {
                Script::new("no wrapped coefficients")
            } else {
                script! {
                    { take_limb(N, true, true) }
                    { signed_table() }
                    for coefficient in 0..offset {
                        { update(N + coefficient - offset, N - coefficient) }
                    }
                    { drop_table() }
                }
            };
            script! {
                { wrapped }
                { take_limb(N - offset, false, false) }
                { signed_table() }
                for coefficient in offset..N {
                    { update(coefficient - offset, N - coefficient) }
                }
                { drop_table() }
                for _ in 0..N { OP_FROMALTSTACK }
            }
        })
        .collect::<Vec<_>>();
    script! { for limb in limbs { { limb } } }
}

fn cleanup_rhs() -> Script {
    script! {
        for _ in 0..N { OP_TOALTSTACK }
        for _ in 0..N / 2 { OP_2DROP }
        if N % 2 != 0 { OP_DROP }
        for _ in 0..N { OP_FROMALTSTACK }
    }
}

fn cached_k_tau(widths: &[usize]) -> Script {
    script! { { cached_k_tau_inner(widths) } { cleanup_rhs() } }
}

fn digits_to_limbs(widths: &[usize]) -> Script {
    let limbs = widths
        .iter()
        .copied()
        .map(|width| {
            let bias = BIAS * (0..width).fold(0, |value, _| value * RADIX as i32 + 1);
            script! {
                { (width - 1) as u32 } OP_ROLL
                for digit in (0..width - 1).rev() {
                    { scriptint::mul_by_constant(RADIX) }
                    { (digit + 1) as u32 } OP_ROLL OP_ADD
                }
                { bias } OP_SUB OP_TOALTSTACK
            }
        })
        .collect::<Vec<_>>();
    script! {
        for limb in limbs { { limb } }
        for _ in 0..widths.len() { OP_FROMALTSTACK }
    }
}

fn report(name: &str, xy: &[usize], k_tau: &[usize]) {
    assert_eq!(xy.iter().sum::<usize>(), N);
    assert_eq!(k_tau.iter().sum::<usize>(), N);
    let xy_bytes = raw_len(streamed_xy(xy));
    let kt_bytes = raw_len(cached_k_tau(k_tau));
    println!("{name}_xy_product_bytes={xy_bytes}");
    println!("{name}_k_tau_product_bytes={kt_bytes}");
    println!("{name}_r0_products_bytes={}", xy_bytes + kt_bytes);
    println!("{name}_k_cache_bytes={}", raw_len(digits_to_limbs(k_tau)));
    println!("{name}_limbs={}", xy.len() + k_tau.len());
    let (update, q_min, q_max, carry, verifier) = bound_report(xy, k_tau);
    println!("{name}_max_accumulator_abs={update}");
    println!("{name}_quotient_interval=[{q_min},{q_max}]");
    let quotient_magnitude = q_min.abs().max(q_max.abs());
    let magnitude_bits = i64::BITS - quotient_magnitude.leading_zeros();
    println!("{name}_quotient_magnitude_bits={magnitude_bits}");
    println!("{name}_quotient_signed_slot_bits={}", magnitude_bits + 1);
    println!("{name}_max_carry_abs={carry}");
    println!("{name}_max_verifier_arithmetic_abs={verifier}");
    if name != "all_four" {
        assert!(update <= i64::from(i32::MAX));
        assert!(verifier <= i64::from(i32::MAX));
    }
}

fn report_mixed_relation(name: &str, negative_widths: &[usize], plus: bool) {
    let direct = Interval { min: -16, max: 15 };
    let sum = Interval { min: -32, max: 30 };
    let difference = Interval { min: -31, max: 31 };
    let three = [3; 17];
    let (negative_lhs, positive_rhs, linear) = if plus {
        (sum, difference, sum)
    } else {
        (difference, sum, difference)
    };
    let negative = product_bounds_for(negative_widths, negative_lhs, direct);
    let positive = product_bounds_for(&three, direct, positive_rhs);
    let relation: [Interval; N] =
        std::array::from_fn(|index| linear.add(positive[index]).subtract(negative[index]));
    // Every multiplicative term and both linear ranges contain zero, so these
    // final intervals enclose every earlier actual-order accumulator update.
    let coefficient = relation.iter().map(|bound| bound.max_abs()).max().unwrap();
    let reconstruct = |select_min: bool| {
        relation.iter().rev().fold(BigInt::from(0), |value, bound| {
            value * RADIX + if select_min { bound.min } else { bound.max }
        })
    };
    let modulus = (BigInt::one() << 255usize) - BigInt::from(19);
    let q_min = (reconstruct(true) / &modulus).to_i64().unwrap();
    let q_max = (reconstruct(false) / &modulus).to_i64().unwrap();
    let mut carry = Interval {
        min: ceil_div(relation[0].min + 19 * q_min, i64::from(RADIX)),
        max: (relation[0].max + 19 * q_max).div_euclid(i64::from(RADIX)),
    };
    let mut maximum_carry = carry.max_abs();
    let mut verifier = coefficient
        .max((relation[0].min + 19 * q_min).abs())
        .max((relation[0].max + 19 * q_max).abs())
        .max(32 * carry.max_abs());
    for bound in relation.iter().take(N - 1).skip(1) {
        carry = Interval {
            min: ceil_div(bound.min + carry.min, i64::from(RADIX)),
            max: (bound.max + carry.max).div_euclid(i64::from(RADIX)),
        };
        maximum_carry = maximum_carry.max(carry.max_abs());
        verifier = verifier.max(32 * carry.max_abs());
    }
    let quotient_magnitude = q_min.abs().max(q_max.abs());
    let magnitude_bits = i64::BITS - quotient_magnitude.leading_zeros();
    println!("{name}_max_accumulator_abs={coefficient}");
    println!("{name}_quotient_interval=[{q_min},{q_max}]");
    println!("{name}_quotient_magnitude_bits={magnitude_bits}");
    println!("{name}_quotient_signed_slot_bits={}", magnitude_bits + 1);
    println!("{name}_max_carry_abs={maximum_carry}");
    println!("{name}_max_verifier_arithmetic_abs={verifier}");
    assert!(coefficient <= i64::from(i32::MAX));
    assert!(verifier <= i64::from(i32::MAX));
}

fn report_shared_tau_kernel() {
    // tau u3 limbs | raw x' | raw y' | R- | R+
    let local_inputs = 17 + 2 * N + 2 * N;
    // In the wrapped pass the source limb is copied. Replacing that copy by
    // the 32-entry table gives 253 items. Two selected products plus OP_2DUP
    // transiently add four more. The table builder itself peaks two over its
    // final size and therefore reaches only 255.
    let local_peak = local_inputs + TABLE + 4;
    let tau_limb_abs = 16 * ((1i64 << 15) - 1) / 31;
    let table_entry_abs = tau_limb_abs * 16;
    let folded_table_entry_abs = 19 * table_entry_abs;
    let folded_sum_or_difference_abs = 2 * folded_table_entry_abs;
    println!("shared_tau_hint_items=0");
    println!("shared_tau_local_input_items={local_inputs}");
    println!("shared_tau_local_peak_items={local_peak}");
    println!("shared_tau_table_entry_abs={table_entry_abs}");
    println!("shared_tau_folded_table_entry_abs={folded_table_entry_abs}");
    println!("shared_tau_folded_pair_abs={folded_sum_or_difference_abs}");
    assert_eq!(local_inputs, 221);
    assert_eq!(local_peak, 257);
    assert_eq!(table_entry_abs, 270_592);
    assert_eq!(folded_table_entry_abs, 5_141_248);
    assert_eq!(folded_sum_or_difference_abs, 10_282_496);
}

fn main() {
    let four = [4; 12].into_iter().chain([3]).collect::<Vec<_>>();
    let three = [3; 17].to_vec();
    let fifteen = [4; 6].into_iter().chain([3; 9]).collect::<Vec<_>>();
    let mixed_r0 = [4]
        .into_iter()
        .chain([3; 9])
        .chain([4; 5])
        .collect::<Vec<_>>();
    report("all_four", &four, &four);
    report("all_three", &three, &three);
    report("asymmetric_four_three", &four, &three);
    report("direct_k_asymmetric_three_four", &three, &four);
    report("symmetric_fifteen", &fifteen, &fifteen);
    report("agent_mixed_r0", &mixed_r0, &mixed_r0);
    report_mixed_relation("mixed_fifteen_r_plus", &fifteen, true);
    report_mixed_relation("mixed_fifteen_r_minus", &fifteen, false);
    report_shared_tau_kernel();
}
