//! Zero-free redundant scalar recoding and canonical-domain validator for the
//! G31 Ed25519 fixed-base schedule.
//!
//! For a lower radix `R` with `B=R/2`, the usual centered code `e=B` would
//! select digit zero.  Here it instead selects `d=-R`, and the encoder adds one
//! to the next quotient.  The lower digit set is therefore
//! `{-R, -B..=-1, 1..=B-1}`: exactly `R` codes, no identity digit, and the same
//! compressed eight-u32 witness shape.
//!
//! This redundancy destroys the standard affine payload identity `P=C+s`.
//! Canonicality is instead checked by two finite radix-carry machines, one for
//! `s-0` and one for `s-l`.  Digits arrive high-to-low, so the verifier stores
//! each carry machine as a small transition map and prepends each newly seen
//! lower digit.  The maps have three and four entries respectively.  They are
//! entirely verifier-derived: this primitive has zero hint items.
//!
//! Run this focused benchmark with:
//! `cargo run --locked --release --example ed25519_g31_zero_free_scalar_validator`.

use bitcoin::{consensus::encode::serialize, Witness};
use bitcoin_lab::{
    fields::ed25519::{u5_balanced_table, u5_packed},
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
    },
};
use num_bigint::{BigInt, BigUint};
use num_traits::{One, ToPrimitive, Zero};

const PACKED_WORDS: usize = 8;
const PAYLOAD_BITS: usize = 253;
const TOP_WORD_BITS: usize = PAYLOAD_BITS - 7 * 32;
const TRACE_ITEMS: usize = 720;
const QUOTIENT_HINT_ITEMS: usize = 61;
const PRESERVED_NON_SCALAR_ITEMS: usize = TRACE_ITEMS + QUOTIENT_HINT_ITEMS;
const COMPLETE_ENTRY_ITEMS: usize = PRESERVED_NON_SCALAR_ITEMS + PACKED_WORDS;

// top | lower-bound map[-2,-1,0] | upper-bound map[-3,-2,-1,0]
const COMPARATOR_STATE_ITEMS: usize = 8;

const STANDARD_G31_CONTROL_BYTES: usize = 41_452;
const STANDARD_G31_PACKED_TABLE_BYTES: usize = 583_813;
const STANDARD_G31_DIRECT_K_TABLE_BYTES: usize = 628_529;
const STANDARD_G31_DIRECT_K_W8_COORDINATE_TABLE_BYTES: usize = 861_360;
const STANDARD_G31_WORD_VALIDATOR_POLICY_BYTES: usize = 774;
const STANDARD_G31_WORD_VALIDATOR_STRICT_PEAK: usize = 796;

#[derive(Clone)]
struct ExtendedPoint {
    x: BigUint,
    y: BigUint,
    z: BigUint,
    t: BigUint,
}

#[derive(Clone)]
struct AffinePoint {
    x: BigUint,
    y: BigUint,
}

fn scalar_order() -> BigUint {
    (BigUint::one() << 252usize)
        + BigUint::parse_bytes(b"27742317777372353535851937790883648493", 10)
            .expect("Ed25519 order offset parses")
}

fn field_modulus() -> BigUint {
    (BigUint::one() << 255usize) - BigUint::from(19u32)
}

fn add_mod(lhs: &BigUint, rhs: &BigUint, modulus: &BigUint) -> BigUint {
    (lhs + rhs) % modulus
}

fn sub_mod(lhs: &BigUint, rhs: &BigUint, modulus: &BigUint) -> BigUint {
    if lhs >= rhs {
        lhs - rhs
    } else {
        modulus - (rhs - lhs)
    }
}

fn mul_mod(lhs: &BigUint, rhs: &BigUint, modulus: &BigUint) -> BigUint {
    (lhs * rhs) % modulus
}

fn invert(value: &BigUint, modulus: &BigUint) -> BigUint {
    assert!(!value.is_zero());
    value.modpow(&(modulus - BigUint::from(2u32)), modulus)
}

fn edwards_d(modulus: &BigUint) -> BigUint {
    mul_mod(
        &(modulus - BigUint::from(121_665u32)),
        &invert(&BigUint::from(121_666u32), modulus),
        modulus,
    )
}

fn identity() -> ExtendedPoint {
    ExtendedPoint {
        x: BigUint::zero(),
        y: BigUint::one(),
        z: BigUint::one(),
        t: BigUint::zero(),
    }
}

fn basepoint(modulus: &BigUint) -> ExtendedPoint {
    let x = BigUint::parse_bytes(
        b"15112221349535400772501151409588531511454012693041857206046113283949847762202",
        10,
    )
    .expect("basepoint x parses");
    let y = BigUint::parse_bytes(
        b"46316835694926478169428394003475163141307993866256225615783033603165251855960",
        10,
    )
    .expect("basepoint y parses");
    ExtendedPoint {
        t: mul_mod(&x, &y, modulus),
        x,
        y,
        z: BigUint::one(),
    }
}

fn add_extended(
    lhs: &ExtendedPoint,
    rhs: &ExtendedPoint,
    d: &BigUint,
    modulus: &BigUint,
) -> ExtendedPoint {
    let a = mul_mod(
        &sub_mod(&lhs.y, &lhs.x, modulus),
        &sub_mod(&rhs.y, &rhs.x, modulus),
        modulus,
    );
    let b = mul_mod(
        &add_mod(&lhs.y, &lhs.x, modulus),
        &add_mod(&rhs.y, &rhs.x, modulus),
        modulus,
    );
    let c = mul_mod(
        &BigUint::from(2u32),
        &mul_mod(d, &mul_mod(&lhs.t, &rhs.t, modulus), modulus),
        modulus,
    );
    let two_z = mul_mod(
        &BigUint::from(2u32),
        &mul_mod(&lhs.z, &rhs.z, modulus),
        modulus,
    );
    let e = sub_mod(&b, &a, modulus);
    let f = sub_mod(&two_z, &c, modulus);
    let g = add_mod(&two_z, &c, modulus);
    let h = add_mod(&b, &a, modulus);
    ExtendedPoint {
        x: mul_mod(&e, &f, modulus),
        y: mul_mod(&g, &h, modulus),
        t: mul_mod(&e, &h, modulus),
        z: mul_mod(&f, &g, modulus),
    }
}

fn batch_invert(values: &[BigUint], modulus: &BigUint) -> Vec<BigUint> {
    let mut prefixes = Vec::with_capacity(values.len());
    let mut product = BigUint::one();
    for value in values {
        assert!(!value.is_zero());
        prefixes.push(product.clone());
        product = mul_mod(&product, value, modulus);
    }
    let mut inverse = invert(&product, modulus);
    let mut result = vec![BigUint::zero(); values.len()];
    for index in (0..values.len()).rev() {
        result[index] = mul_mod(&inverse, &prefixes[index], modulus);
        inverse = mul_mod(&inverse, &values[index], modulus);
    }
    result
}

fn normalize_batch(points: &[ExtendedPoint], modulus: &BigUint) -> Vec<AffinePoint> {
    let inverses = batch_invert(
        &points
            .iter()
            .map(|point| point.z.clone())
            .collect::<Vec<_>>(),
        modulus,
    );
    points
        .iter()
        .zip(inverses)
        .map(|(point, inverse)| AffinePoint {
            x: mul_mod(&point.x, &inverse, modulus),
            y: mul_mod(&point.y, &inverse, modulus),
        })
        .collect()
}

fn scalar_mul_small(
    point: &ExtendedPoint,
    mut scalar: u32,
    d: &BigUint,
    modulus: &BigUint,
) -> ExtendedPoint {
    let mut result = identity();
    let mut addend = point.clone();
    while scalar != 0 {
        if scalar & 1 != 0 {
            result = add_extended(&result, &addend, d, modulus);
        }
        scalar >>= 1;
        if scalar != 0 {
            addend = add_extended(&addend, &addend, d, modulus);
        }
    }
    result
}

fn widths_low_to_high() -> Vec<usize> {
    let mut widths = vec![8; 26];
    widths.extend(std::iter::repeat_n(9, 4));
    widths.push(9);
    assert_eq!(widths.iter().sum::<usize>(), PAYLOAD_BITS);
    widths
}

/// Deterministic zero-free recoding, low digit through unsigned top digit.
fn zero_free_digits(scalar: &BigUint) -> Vec<i32> {
    let widths = widths_low_to_high();
    let mut remaining = scalar.clone();
    let mut digits = Vec::with_capacity(widths.len());
    for width in &widths[..widths.len() - 1] {
        let radix = 1u32 << width;
        let bias = radix / 2;
        let residue = (&remaining & BigUint::from(radix - 1))
            .to_u32()
            .expect("window residue fits u32");
        let digit = if residue == 0 {
            remaining += BigUint::from(radix);
            -(radix as i32)
        } else if residue >= bias {
            remaining += BigUint::from(radix - residue);
            residue as i32 - radix as i32
        } else {
            remaining -= BigUint::from(residue);
            residue as i32
        };
        remaining >>= width;
        assert_ne!(digit, 0);
        assert!(
            digit == -(radix as i32)
                || (-(bias as i32)..=-1).contains(&digit)
                || (1..bias as i32).contains(&digit)
        );
        digits.push(digit);
    }
    digits.push(remaining.to_i32().expect("top digit fits i32"));

    let reconstructed = digits[..digits.len() - 1]
        .iter()
        .zip(&widths[..widths.len() - 1])
        .rev()
        .fold(
            BigInt::from(*digits.last().expect("top digit exists")),
            |accumulator, (digit, width)| {
                accumulator * BigInt::from(1u32 << width) + BigInt::from(*digit)
            },
        );
    assert_eq!(reconstructed, BigInt::from(scalar.clone()));
    digits
}

fn payload_from_digits(digits: &[i32]) -> BigUint {
    let widths = widths_low_to_high();
    assert_eq!(digits.len(), widths.len());
    let mut payload = BigUint::zero();
    let mut bit_position = 0usize;
    for (digit, width) in digits[..digits.len() - 1]
        .iter()
        .zip(&widths[..widths.len() - 1])
    {
        let radix = 1i32 << width;
        let bias = radix / 2;
        let code = if *digit == -radix {
            bias
        } else {
            *digit + bias
        };
        assert!((0..radix).contains(&code));
        payload |= BigUint::from(code as u32) << bit_position;
        bit_position += width;
    }
    let top = *digits.last().expect("top digit exists");
    assert!((0..(1i32 << 9)).contains(&top));
    payload |= BigUint::from(top as u32) << bit_position;
    assert!((&payload >> PAYLOAD_BITS).is_zero());
    payload
}

fn words_from_payload(payload: &BigUint) -> [u32; PACKED_WORDS] {
    assert!((payload >> 256usize).is_zero());
    std::array::from_fn(|index| {
        ((payload >> (32 * index)) & BigUint::from(u32::MAX))
            .to_u32()
            .expect("masked word fits u32")
    })
}

fn words_for_scalar(scalar: &BigUint) -> [u32; PACKED_WORDS] {
    words_from_payload(&payload_from_digits(&zero_free_digits(scalar)))
}

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn scriptnum_push_bytes(value: i64) -> usize {
    if value == -1 || (0..=16).contains(&value) {
        1
    } else {
        1 + scriptnum_item(value).len()
    }
}

fn packed_field_push_bytes(value: &BigUint) -> usize {
    u5_packed::packed_words_from_digits(&u5_balanced_table::field_digits(value))
        .into_iter()
        .map(|word| scriptnum_push_bytes(i64::from(word as i32)))
        .sum()
}

fn direct_field_digit_push_bytes(value: &BigUint) -> usize {
    u5_balanced_table::field_digits(value)
        .into_iter()
        .map(|digit| scriptnum_push_bytes(i64::from(digit)))
        .sum()
}

fn direct_k_limb_push_bytes(value: &BigUint) -> usize {
    const LIMB_DIGITS: [usize; 13] = [4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 3];
    let digits = u5_balanced_table::field_digits(value);
    let mut cursor = 0usize;
    LIMB_DIGITS
        .into_iter()
        .map(|digit_count| {
            let start = cursor;
            cursor += digit_count;
            let limb = digits[start..cursor]
                .iter()
                .rev()
                .fold(0i64, |limb, digit| limb * 32 + i64::from(*digit - 16));
            scriptnum_push_bytes(limb)
        })
        .sum()
}

fn decision_tree_control_bytes(low: usize, high: usize, leaf_bytes: usize) -> usize {
    assert!(low < high);
    if high - low == 1 {
        leaf_bytes
    } else {
        let middle = low + (high - low) / 2;
        5 + scriptnum_push_bytes(middle as i64)
            + decision_tree_control_bytes(low, middle, leaf_bytes)
            + decision_tree_control_bytes(middle, high, leaf_bytes)
    }
}

#[derive(Clone, Copy)]
struct TableDelta {
    control: i64,
    packed_payload: usize,
    direct_k_payload: usize,
    direct_k_w8_coordinate_payload: usize,
    packed_total: i64,
    direct_k_total: i64,
    direct_k_w8_coordinate_total: i64,
    lower_leaf_markers_removed: usize,
    top_extra_payload: usize,
}

/// Exact G31 table delta from replacing each lower identity payload with the
/// point `R * 2^offset * B` and extending the top table from 256 through 257.
fn zero_free_table_delta() -> TableDelta {
    let modulus = field_modulus();
    let d = edwards_d(&modulus);
    let widths = widths_low_to_high();
    let mut position_base = basepoint(&modulus);
    let mut special_points = Vec::with_capacity(widths.len() - 1);
    for width in &widths[..widths.len() - 1] {
        for _ in 0..*width {
            position_base = add_extended(&position_base, &position_base, &d, &modulus);
        }
        special_points.push(position_base.clone());
    }
    let top_257 = scalar_mul_small(&position_base, 257, &d, &modulus);
    let mut all_points = special_points;
    all_points.push(top_257);
    let affine = normalize_batch(&all_points, &modulus);

    let denominators = affine[..affine.len() - 1]
        .iter()
        .map(|point| mul_mod(&d, &mul_mod(&point.x, &point.y, &modulus), &modulus))
        .collect::<Vec<_>>();
    let inverse_denominators = batch_invert(&denominators, &modulus);

    let mut packed_special_payload = 0usize;
    let mut direct_k_special_payload = 0usize;
    let mut direct_k_w8_special_payload = 0usize;
    for ((point, k), width) in affine[..affine.len() - 1]
        .iter()
        .zip(inverse_denominators)
        .zip(&widths[..widths.len() - 1])
    {
        let cp = add_mod(&point.x, &point.y, &modulus);
        let cm = sub_mod(&point.y, &point.x, &modulus);
        let packed_cp = packed_field_push_bytes(&cp);
        let packed_cm = packed_field_push_bytes(&cm);
        let packed_k = packed_field_push_bytes(&k);
        let direct_k = direct_k_limb_push_bytes(&k);
        packed_special_payload += packed_cp + packed_cm + packed_k;
        direct_k_special_payload += packed_cp + packed_cm + direct_k;
        direct_k_w8_special_payload += if *width == 8 {
            direct_field_digit_push_bytes(&cp) + direct_field_digit_push_bytes(&cm) + direct_k
        } else {
            packed_cp + packed_cm + direct_k
        };
    }

    let top = affine.last().expect("top 257 point exists");
    let top_extra_payload = packed_field_push_bytes(&top.x) + packed_field_push_bytes(&top.y);
    let packed_payload = packed_special_payload + top_extra_payload;
    let direct_k_payload = direct_k_special_payload + top_extra_payload;
    let direct_k_w8_coordinate_payload = direct_k_w8_special_payload + top_extra_payload;

    let lower_leaf_markers_removed = 26 * 129 + 4 * 257;
    let old_lower_control =
        26 * decision_tree_control_bytes(0, 129, 2) + 4 * decision_tree_control_bytes(0, 257, 2);
    let new_lower_control =
        26 * decision_tree_control_bytes(0, 129, 1) + 4 * decision_tree_control_bytes(0, 257, 1);
    let old_top_control = decision_tree_control_bytes(0, 257, 1);
    let new_top_control = decision_tree_control_bytes(0, 258, 1);
    assert_eq!(
        old_lower_control + old_top_control,
        STANDARD_G31_CONTROL_BYTES
    );
    let control = (new_lower_control + new_top_control) as i64 - STANDARD_G31_CONTROL_BYTES as i64;

    TableDelta {
        control,
        packed_payload,
        direct_k_payload,
        direct_k_w8_coordinate_payload,
        packed_total: control + packed_payload as i64,
        direct_k_total: control + direct_k_payload as i64,
        direct_k_w8_coordinate_total: control + direct_k_w8_coordinate_payload as i64,
        lower_leaf_markers_removed,
        top_extra_payload,
    }
}

fn complete_witness(words: &[u32; PACKED_WORDS]) -> Vec<Vec<u8>> {
    let mut witness = vec![Vec::new(); PRESERVED_NON_SCALAR_ITEMS];
    witness.extend(
        words
            .iter()
            .map(|word| scriptnum_item(i64::from(*word as i32))),
    );
    assert_eq!(witness.len(), COMPLETE_ENTRY_ITEMS);
    witness
}

/// Consume one picked hostile word and return `low31 | sign_bit` after proving
/// its unique ScriptNum encoding.  Exact -2^31 is handled only by byte equality.
fn exact_word_to_low31_and_sign() -> Script {
    script! {
        OP_DUP { -2_147_483_648i64 } OP_EQUAL
        OP_IF
            OP_DROP 0 1
        OP_ELSE
            OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
            OP_DUP 0 OP_LESSTHAN
            OP_IF { i32::MAX } OP_ADD OP_1ADD 1
            OP_ELSE 0
            OP_ENDIF
        OP_ENDIF
    }
}

fn bits_from_altstack_to_number(width: usize) -> Script {
    assert!(width > 0);
    script! {
        OP_FROMALTSTACK
        for _ in 1..width {
            OP_DUP OP_ADD OP_FROMALTSTACK OP_ADD
        }
    }
}

/// Split an at-most-31-bit nonnegative number into `high | low` without
/// decomposing or retaining all of its bits.
fn split_high(total_bits: usize, high_bits: usize) -> Script {
    assert!(high_bits > 0 && high_bits < total_bits && total_bits <= 31);
    let low_bits = total_bits - high_bits;
    script! {
        for bit in (low_bits..total_bits).rev() {
            OP_DUP { (1u32 << bit) - 1 } OP_GREATERTHAN
            OP_SWAP OP_OVER
            OP_IF { 1u32 << bit } OP_SUB OP_ENDIF
        }
        OP_TOALTSTACK
        for _ in 0..high_bits { OP_TOALTSTACK }
        { bits_from_altstack_to_number(high_bits) }
        OP_FROMALTSTACK
    }
}

fn finish_partial(total_bits: usize, partial_bits: usize, take: usize) -> Script {
    assert!(partial_bits > 0 && take > 0 && take < total_bits);
    script! {
        OP_SWAP
        { split_high(total_bits, take) }
        OP_TOALTSTACK OP_SWAP
        for _ in 0..take { OP_DUP OP_ADD }
        OP_ADD
        OP_FROMALTSTACK OP_SWAP
    }
}

fn park_comparator_state() -> Script {
    script! { for _ in 0..COMPARATOR_STATE_ITEMS { OP_TOALTSTACK } }
}

/// With comparator state parked, route a completed digit above that state.
fn restore_comparator_state_around_digit() -> Script {
    script! {
        for _ in 0..COMPARATOR_STATE_ITEMS { OP_FROMALTSTACK }
        { COMPARATOR_STATE_ITEMS as u32 } OP_ROLL
    }
}

fn decode_zero_free_digit(width: usize) -> Script {
    let radix = 1i32 << width;
    let bias = radix / 2;
    script! {
        OP_DUP { bias } OP_NUMEQUAL
        OP_IF OP_DROP { -radix }
        OP_ELSE { bias } OP_SUB
        OP_ENDIF
    }
}

/// Compute `floor((digit - bound_digit + carry) / radix)` for the lower-bound
/// carry domain {-2,-1,0}.
fn lower_carry_transition(radix: i32, carry: i32) -> Script {
    assert!((-2..=0).contains(&carry));
    script! {
        if carry != 0 { { carry } OP_ADD }
        OP_DUP { -radix } OP_LESSTHAN
        OP_IF OP_DROP -2
        OP_ELSE
            0 OP_LESSTHAN
            OP_IF -1 OP_ELSE 0 OP_ENDIF
        OP_ENDIF
    }
}

/// Compute `floor((digit - bound_digit + carry) / radix)` for the upper-bound
/// carry domain {-3,-2,-1,0}.
fn upper_carry_transition(radix: i32, bound_digit: i32, carry: i32) -> Script {
    assert!((-3..=0).contains(&carry));
    let shift = carry - bound_digit;
    script! {
        if shift != 0 { { shift } OP_ADD }
        OP_DUP { -2 * radix } OP_LESSTHAN
        OP_IF OP_DROP -3
        OP_ELSE
            OP_DUP { -radix } OP_LESSTHAN
            OP_IF OP_DROP -2
            OP_ELSE
                0 OP_LESSTHAN
                OP_IF -1 OP_ELSE 0 OP_ENDIF
            OP_ENDIF
        OP_ENDIF
    }
}

/// Append one value of a newly prepended lower-bound transition map.
fn append_lower_map_value(radix: i32, carry: i32, outputs_above_digit: usize) -> Script {
    // OP_PICK first consumes its dynamic depth, after which old map[f] is at
    // depth base-f.
    let base_depth = outputs_above_digit + 5;
    script! {
        { outputs_above_digit as u32 } OP_PICK
        { lower_carry_transition(radix, carry) }
        { base_depth as u32 } OP_SWAP OP_SUB OP_PICK
    }
}

/// Append one value of a newly prepended upper-bound transition map.
fn append_upper_map_value(
    radix: i32,
    bound_digit: i32,
    carry: i32,
    outputs_above_digit: usize,
) -> Script {
    let base_depth = outputs_above_digit + 1;
    script! {
        { outputs_above_digit as u32 } OP_PICK
        { upper_carry_transition(radix, bound_digit, carry) }
        { base_depth as u32 } OP_SWAP OP_SUB OP_PICK
    }
}

/// Prepend one lower digit to both high-to-low transition maps.
///
/// Before: `top | old_lower[3] | old_upper[4] | encoded_digit`.
/// After:  `top | new_lower[3] | new_upper[4]`.
fn prepend_digit_to_comparators(width: usize, upper_bound_digit: i32) -> Script {
    let radix = 1i32 << width;
    script! {
        { decode_zero_free_digit(width) }

        { append_lower_map_value(radix, -2, 0) }
        { append_lower_map_value(radix, -1, 1) }
        { append_lower_map_value(radix,  0, 2) }

        { append_upper_map_value(radix, upper_bound_digit, -3, 3) }
        { append_upper_map_value(radix, upper_bound_digit, -2, 4) }
        { append_upper_map_value(radix, upper_bound_digit, -1, 5) }
        { append_upper_map_value(radix, upper_bound_digit,  0, 6) }

        // Park new maps, discard digit and both old maps, then restore the new
        // maps in their original order.  The unsigned top digit stays below.
        for _ in 0..7 { OP_TOALTSTACK }
        for _ in 0..4 { OP_2DROP }
        for _ in 0..7 { OP_FROMALTSTACK }
    }
}

fn ordinary_bound_digits(bound: &BigUint) -> (Vec<i32>, i32) {
    let widths = widths_low_to_high();
    let mut remaining = bound.clone();
    let mut lower = Vec::with_capacity(widths.len() - 1);
    for width in &widths[..widths.len() - 1] {
        let radix = 1u32 << width;
        lower.push(
            (&remaining & BigUint::from(radix - 1))
                .to_i32()
                .expect("ordinary bound digit fits i32"),
        );
        remaining >>= width;
    }
    (lower, remaining.to_i32().expect("ordinary top fits i32"))
}

/// Preserve the eight exact compressed words while validating `0 <= s < l`.
fn validate_zero_free_words_preserving(preserved_items: usize) -> Script {
    let widths = widths_low_to_high();
    let target_widths = widths.iter().rev().copied().collect::<Vec<_>>();
    let (upper_digits, upper_top) = ordinary_bound_digits(&scalar_order());
    assert_eq!(upper_top, 256);
    assert!(preserved_items + PACKED_WORDS + 32 <= 1_000);

    let mut steps = Vec::new();
    // Pick and exactly certify word seven.  Its sign and three padding bits
    // must be zero before it is treated as a 29-bit nonnegative remainder.
    steps.push(script! {
        0 OP_PICK
        { exact_word_to_low31_and_sign() }
        OP_NOT OP_VERIFY
        OP_DUP { 1u32 << TOP_WORD_BITS } OP_LESSTHAN OP_VERIFY
    });

    let mut target = 0usize;
    let first_width = target_widths[target];
    steps.push(script! {
        { split_high(TOP_WORD_BITS, first_width) }
        OP_SWAP
        // top; identity transition maps for carry inputs in ascending order.
        -2 -1 0
        -3 -2 -1 0
    });
    target += 1;
    let mut remainder_bits = TOP_WORD_BITS - first_width;

    while remainder_bits >= target_widths[target] {
        let width = target_widths[target];
        let position = widths.len() - 1 - target;
        steps.push(park_comparator_state());
        if remainder_bits == width {
            steps.push(script! {
                { restore_comparator_state_around_digit() }
                { prepend_digit_to_comparators(width, upper_digits[position]) }
            });
            remainder_bits = 0;
        } else {
            steps.push(script! {
                { split_high(remainder_bits, width) }
                OP_SWAP
                { restore_comparator_state_around_digit() }
                { prepend_digit_to_comparators(width, upper_digits[position]) }
            });
            remainder_bits -= width;
        }
        target += 1;
    }
    let mut partial_bits = remainder_bits;

    for word_index in (0..PACKED_WORDS - 1).rev() {
        steps.push(park_comparator_state());
        let depth = PACKED_WORDS - 1 - word_index + usize::from(partial_bits != 0);
        steps.push(script! {
            { depth as u32 } OP_PICK
            { exact_word_to_low31_and_sign() }
        });

        if partial_bits == 0 {
            partial_bits = 1;
        } else {
            steps.push(script! {
                OP_TOALTSTACK OP_SWAP
                OP_DUP OP_ADD OP_FROMALTSTACK OP_ADD
            });
            partial_bits += 1;
        }

        let width = target_widths[target];
        let needed = width - partial_bits;
        let position = widths.len() - 1 - target;
        if needed == 0 {
            steps.push(script! {
                { restore_comparator_state_around_digit() }
                { prepend_digit_to_comparators(width, upper_digits[position]) }
            });
        } else {
            steps.push(script! {
                { finish_partial(31, partial_bits, needed) }
                { restore_comparator_state_around_digit() }
                { prepend_digit_to_comparators(width, upper_digits[position]) }
            });
        }
        target += 1;
        remainder_bits = 31 - needed;

        while target < target_widths.len() && remainder_bits >= target_widths[target] {
            let width = target_widths[target];
            let position = widths.len() - 1 - target;
            steps.push(park_comparator_state());
            if remainder_bits == width {
                steps.push(script! {
                    { restore_comparator_state_around_digit() }
                    { prepend_digit_to_comparators(width, upper_digits[position]) }
                });
                remainder_bits = 0;
            } else {
                steps.push(script! {
                    { split_high(remainder_bits, width) }
                    OP_SWAP
                    { restore_comparator_state_around_digit() }
                    { prepend_digit_to_comparators(width, upper_digits[position]) }
                });
                remainder_bits -= width;
            }
            target += 1;
        }
        partial_bits = remainder_bits;
    }

    assert_eq!(target, target_widths.len());
    assert_eq!(partial_bits, 0);
    steps.push(script! {
        // lower final coefficient: top + lower_map(0) >= 0.
        7 OP_PICK 5 OP_PICK OP_ADD
        0 OP_GREATERTHANOREQUAL OP_VERIFY

        // upper final coefficient: top - 256 + upper_map(0) < 0.
        7 OP_PICK 1 OP_PICK OP_ADD { upper_top } OP_SUB
        0 OP_LESSTHAN OP_VERIFY

        for _ in 0..4 { OP_2DROP }
    });

    script! { for step in steps { { step } } }
}

fn maximum_zero_free_top(upper: &BigUint) -> BigUint {
    let widths = widths_low_to_high();
    let mut maximum = upper.clone();
    for width in &widths[..widths.len() - 1] {
        maximum = (maximum >> width) + BigUint::one();
    }
    maximum
}

fn minimal_preimage_for_top(top: u32) -> BigUint {
    let widths = widths_low_to_high();
    let mut value = BigUint::from(top);
    for width in widths[..widths.len() - 1].iter().rev() {
        value = (value - BigUint::one()) << width;
    }
    value
}

/// Exhaust every legal digit, bound digit, and incoming carry for both G31
/// radices.  This proves the finite domains used by the Script classifiers;
/// it is exhaustive over transition inputs rather than a random scalar sample.
fn exhaustive_carry_domain_proof() {
    for radix in [256i32, 512] {
        let bias = radix / 2;
        let digits = std::iter::once(-radix)
            .chain(-bias..=-1)
            .chain(1..bias)
            .collect::<Vec<_>>();
        assert_eq!(digits.len(), radix as usize);

        for digit in digits {
            for carry in -2..=0 {
                let next = (digit + carry).div_euclid(radix);
                assert!((-2..=0).contains(&next));
            }
            for bound_digit in 0..radix {
                for carry in -3..=0 {
                    let total = digit - bound_digit + carry;
                    let next = total.div_euclid(radix);
                    let threshold_result = if total < -2 * radix {
                        -3
                    } else if total < -radix {
                        -2
                    } else if total < 0 {
                        -1
                    } else {
                        0
                    };
                    assert_eq!(next, threshold_result);
                    assert!((-3..=0).contains(&next));
                }
            }
        }
    }
}

fn execute_accept(validator: &[u8], scalar: &BigUint, description: &str) -> usize {
    let words = words_for_scalar(scalar);
    let witness = complete_witness(&words);
    let execution = execute_raw_script_with_inputs_strict(validator.to_vec(), witness.clone());
    assert!(
        execution.error.is_none(),
        "valid scalar rejected ({description}): {execution}"
    );
    assert!(!execution.success, "preserving fragment is not cleanstack");
    assert_eq!(execution.final_stack.len(), COMPLETE_ENTRY_ITEMS);
    for (index, item) in witness.iter().enumerate() {
        assert_eq!(execution.final_stack.get(index), *item);
    }
    execution.stats.max_nb_stack_items
}

fn execute_reject(validator: &[u8], words: &[u32; PACKED_WORDS], description: &str) {
    execute_reject_witness(validator, complete_witness(words), description);
}

fn execute_reject_witness(validator: &[u8], witness: Vec<Vec<u8>>, description: &str) {
    let execution = execute_raw_script_with_inputs_strict(validator.to_vec(), witness);
    assert!(
        execution.error.is_some(),
        "invalid scalar accepted ({description})"
    );
}

fn raw_fragment_len(fragment: Script) -> usize {
    const COPIES: usize = 16;
    let repeated = script! { for _ in 0..COPIES { { fragment.clone() } } }.compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % COPIES, 0);
    repeated.len() / COPIES
}

fn main() {
    exhaustive_carry_domain_proof();
    let order = scalar_order();
    let upper = &order - BigUint::one();
    let top_max = maximum_zero_free_top(&upper);
    assert_eq!(top_max, BigUint::from(257u32));
    let top_257_preimage = minimal_preimage_for_top(257);
    assert!(top_257_preimage < order);
    assert_eq!(
        *zero_free_digits(&top_257_preimage)
            .last()
            .expect("top exists"),
        257
    );

    let order_digits = zero_free_digits(&order);
    let (order_bound_digits, _) = ordinary_bound_digits(&order);
    let widths = widths_low_to_high();
    let order_codes = order_digits[..30]
        .iter()
        .zip(&widths[..30])
        .map(|(digit, width)| {
            let radix = 1i32 << width;
            let bias = radix / 2;
            if *digit == -radix {
                bias
            } else {
                *digit + bias
            }
        })
        .collect::<Vec<_>>();
    let map_probe = script! {
        { order_digits[30] }
        -2 -1 0 -3 -2 -1 0
        for position in (0..30).rev() {
            { order_codes[position] }
            { prepend_digit_to_comparators(widths[position], order_bound_digits[position]) }
        }
    }
    .compile_with_policy();
    let map_probe_execution = execute_raw_script_with_inputs_strict(map_probe.to_bytes(), vec![]);
    assert!(
        map_probe_execution.error.is_none(),
        "map probe failed: {map_probe_execution}"
    );
    let expected_order_maps = [256, 0, 0, 0, -1, -1, -1, 0];
    assert_eq!(
        map_probe_execution.final_stack.len(),
        expected_order_maps.len()
    );
    for (index, expected) in expected_order_maps.into_iter().enumerate() {
        assert_eq!(
            map_probe_execution.final_stack.get(index),
            scriptnum_item(expected)
        );
    }

    let fragment = validate_zero_free_words_preserving(PRESERVED_NON_SCALAR_ITEMS);
    let raw_bytes = raw_fragment_len(fragment.clone());
    let policy = fragment.compile_with_policy();
    let policy_bytes = policy.len();
    let validator = policy.to_bytes();

    let mut strict_peak = execute_accept(&validator, &BigUint::zero(), "zero");
    strict_peak = strict_peak.max(execute_accept(&validator, &upper, "l - 1"));
    strict_peak = strict_peak.max(execute_accept(
        &validator,
        &top_257_preimage,
        "reachable top 257",
    ));
    let exact_min_word_scalar = BigUint::from(0xff7f_7f80u32);
    let exact_min_words = words_for_scalar(&exact_min_word_scalar);
    assert_eq!(exact_min_words[0], 0x8000_0000);
    strict_peak = strict_peak.max(execute_accept(
        &validator,
        &exact_min_word_scalar,
        "exact -2^31 compressed word",
    ));
    execute_reject(&validator, &words_for_scalar(&order), "s = l");

    // Unique zero-free digits representing -1: -1 at position zero, then
    // alternating special -R and +1, with unsigned top one.
    let widths = widths_low_to_high();
    let mut minus_one_digits = Vec::with_capacity(widths.len());
    minus_one_digits.push(-1);
    for (index, width) in widths[1..widths.len() - 1].iter().enumerate() {
        minus_one_digits.push(if index % 2 == 0 { -(1i32 << width) } else { 1 });
    }
    minus_one_digits.push(1);
    let minus_one_words = words_from_payload(&payload_from_digits(&minus_one_digits));
    execute_reject(&validator, &minus_one_words, "represented scalar -1");

    let mut invalid_padding = words_for_scalar(&BigUint::zero());
    invalid_padding[7] |= 1u32 << TOP_WORD_BITS;
    execute_reject(&validator, &invalid_padding, "bit 253 padding set");

    let mut redundant_sign = complete_witness(&words_for_scalar(&BigUint::zero()));
    redundant_sign[PRESERVED_NON_SCALAR_ITEMS + 7].push(0);
    execute_reject_witness(&validator, redundant_sign, "redundant ScriptNum sign byte");

    let witness_bytes = serialize(&Witness::from_slice(&complete_witness(&words_for_scalar(
        &upper,
    ))))
    .len();
    let table_delta = zero_free_table_delta();
    let one = BigUint::one();
    let identity_packed_field = packed_field_push_bytes(&one);
    let identity_direct_field = direct_field_digit_push_bytes(&one);
    let identity_direct_k = direct_k_limb_push_bytes(&one);
    let unified_identity_early_leaf_payload = 2 * identity_packed_field + identity_direct_k;
    let unified_identity_late_leaf_payload = 2 * identity_direct_field + identity_direct_k;
    let unified_identity_table_payload_delta =
        4 * unified_identity_early_leaf_payload + 26 * unified_identity_late_leaf_payload;
    const ZERO_FREE_DECODE_ADDED_BYTES_PER_TRANSITION: usize = 12;
    const SCHEDULER_MARKER_CONSUMER_BYTES_PER_TRANSITION: usize = 2;
    let validator_policy_delta =
        policy_bytes as i64 - STANDARD_G31_WORD_VALIDATOR_POLICY_BYTES as i64;
    let known_non_table_delta = validator_policy_delta
        + (30 * ZERO_FREE_DECODE_ADDED_BYTES_PER_TRANSITION) as i64
        - (30 * SCHEDULER_MARKER_CONSUMER_BYTES_PER_TRANSITION) as i64;
    println!("model=ed25519_g31_zero_free_scalar_validator");
    println!("scalar_domain=0..l-1");
    println!("lower_digit_zero_replaced_by_negative_radix=true");
    println!("zero_free_top_max={top_max}");
    println!("top_257_is_reachable=true");
    println!("physical_scalar_items={PACKED_WORDS}");
    println!("validator_incremental_hint_items=0");
    println!(
        "finite_comparator_state_items={}",
        COMPARATOR_STATE_ITEMS - 1
    );
    println!("preserved_trace_items={TRACE_ITEMS}");
    println!("preserved_quotient_hint_items={QUOTIENT_HINT_ITEMS}");
    println!("preserved_non_scalar_items={PRESERVED_NON_SCALAR_ITEMS}");
    println!("complete_entry_items={COMPLETE_ENTRY_ITEMS}");
    println!("validator_raw_script_bytes={raw_bytes}");
    println!("validator_policy_script_bytes={policy_bytes}");
    println!("validator_policy_byte_delta_vs_standard={validator_policy_delta}");
    println!("representative_complete_witness_bytes={witness_bytes}");
    println!("strict_max_combined_stack_items={strict_peak}");
    println!(
        "validator_peak_delta_items={}",
        strict_peak - COMPLETE_ENTRY_ITEMS
    );
    println!(
        "strict_peak_delta_vs_standard={}",
        strict_peak as i64 - STANDARD_G31_WORD_VALIDATOR_STRICT_PEAK as i64
    );
    println!("rejects_s_equal_l=true");
    println!("rejects_represented_minus_one=true");
    println!("rejects_invalid_top_padding=true");
    println!("rejects_nonminimal_scriptnums=true");
    println!("exact_minus_2_pow_31_word_accepted=true");
    println!("fragment_preserves_all_entry_items=true");
    println!("terminal_cleanstack_predicate=required_from_caller");
    println!(
        "lower_table_leaf_markers_removed={}",
        table_delta.lower_leaf_markers_removed
    );
    println!("table_control_byte_delta={}", table_delta.control);
    println!(
        "top_257_extra_packed_payload_bytes={}",
        table_delta.top_extra_payload
    );
    println!(
        "packed_table_payload_byte_delta={}",
        table_delta.packed_payload
    );
    println!("packed_table_total_byte_delta={}", table_delta.packed_total);
    println!(
        "zero_free_packed_table_bytes={}",
        STANDARD_G31_PACKED_TABLE_BYTES as i64 + table_delta.packed_total
    );
    println!(
        "direct_k_table_payload_byte_delta={}",
        table_delta.direct_k_payload
    );
    println!(
        "direct_k_table_total_byte_delta={}",
        table_delta.direct_k_total
    );
    println!(
        "zero_free_direct_k_table_bytes={}",
        STANDARD_G31_DIRECT_K_TABLE_BYTES as i64 + table_delta.direct_k_total
    );
    println!(
        "direct_k_w8_coordinate_table_payload_byte_delta={}",
        table_delta.direct_k_w8_coordinate_payload
    );
    println!(
        "direct_k_w8_coordinate_table_total_byte_delta={}",
        table_delta.direct_k_w8_coordinate_total
    );
    println!(
        "zero_free_direct_k_w8_coordinate_table_bytes={}",
        STANDARD_G31_DIRECT_K_W8_COORDINATE_TABLE_BYTES as i64
            + table_delta.direct_k_w8_coordinate_total
    );
    println!(
        "zero_free_decode_added_bytes_per_transition={ZERO_FREE_DECODE_ADDED_BYTES_PER_TRANSITION}"
    );
    println!(
        "zero_free_decode_added_bytes_all_transitions={}",
        30 * ZERO_FREE_DECODE_ADDED_BYTES_PER_TRANSITION
    );
    println!(
        "scheduler_marker_consumer_removed_bytes_per_transition={SCHEDULER_MARKER_CONSUMER_BYTES_PER_TRANSITION}"
    );
    println!(
        "known_packed_table_plus_validator_route_byte_delta={}",
        table_delta.packed_total + known_non_table_delta
    );
    println!(
        "known_direct_k_table_plus_validator_route_byte_delta={}",
        table_delta.direct_k_total + known_non_table_delta
    );
    println!(
        "known_direct_k_w8_table_plus_validator_route_byte_delta={}",
        table_delta.direct_k_w8_coordinate_total + known_non_table_delta
    );
    println!("known_combined_delta_excludes_unimplemented_zero_branch_body=true");
    println!("selected_table_branch_marker_item_delta=-1");
    println!("sign_marker_item_delta=0");
    println!(
        "unified_identity_early_zero_leaf_payload_bytes={unified_identity_early_leaf_payload}"
    );
    println!("unified_identity_late_zero_leaf_payload_bytes={unified_identity_late_leaf_payload}");
    println!("unified_identity_table_payload_byte_delta={unified_identity_table_payload_delta}");
    println!("execution_class=unclassified");
}
