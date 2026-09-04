//! Exact fixed-base table-size model for width-8, -9, -10, and a mixed
//! width-8/9 Ed25519 table schedule.
//!
//! The model computes actual affine multiples of the RFC 8032 base point using
//! complete extended-coordinate addition and two batch inversions per width.
//! Lower-position nonzero leaves push packed `C+ = a+b`, `C- = b-a`, and
//! `K = (d*a*b)^-1`. A zero leaf pushes only a false branch marker. The top
//! position initializes the accumulator and therefore pushes packed affine
//! `x,y`, including for its identity entry.
//!
//! This is a table-only boundary. Scalar recoding, sign handling, the body of
//! the zero/nonzero branch, point-transition relations, and witness data are
//! excluded. The generated scripts exceed the repository optimizer cutoff and
//! are therefore policy-produced raw scripts.
//!
//! H16 key-specialized consumers have a production-oriented host boundary:
//! they accept a canonical external RFC 8032 public-key encoding, validate its
//! curve and prime-subgroup membership, and derive both the `-A` tables and
//! returned transcript key from that point. No secret scalar enters that path.
//! The no-argument H16 helpers retain the disclosed `[987654321]B` fixture only
//! to keep the benchmark leaf stable.
//!
//! Run with:
//! `cargo run --locked --release --example ed25519_fixed_table_actual_model`.

use bitcoin_lab::{
    fields::ed25519::{u5_balanced_table, u5_packed},
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
    },
};
use num_bigint::{BigInt, BigUint};
use num_traits::{One, ToPrimitive, Zero};
use std::fmt;

const SCALAR_BITS: usize = 253;
const PACKED_WORDS_PER_FIELD: usize = 8;

#[derive(Clone, Debug)]
struct ExtendedPoint {
    x: BigUint,
    y: BigUint,
    z: BigUint,
    t: BigUint,
}

#[derive(Clone, Debug)]
struct AffinePoint {
    x: BigUint,
    y: BigUint,
}

#[derive(Clone, Debug)]
enum TableEntry {
    Identity,
    Packed(Vec<i64>),
}

#[derive(Clone, Copy, Debug)]
enum TableKind {
    Top,
    Addition,
}

#[derive(Clone, Copy, Debug)]
enum AdditionEncoding {
    DirectKLimbs,
    DirectKAndWidth8Coordinates,
}

#[derive(Clone, Copy, Debug, Default)]
struct TableCost {
    control: usize,
    payload: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct HybridPayloadCost {
    packed: usize,
    direct_k_limbs: usize,
    direct_cp_and_k_limbs: usize,
    direct_cm_and_k_limbs: usize,
    direct_cp_cm_and_k_limbs: usize,
    direct_k_and_w8_cp: usize,
    direct_k_and_w8_cp_cm: usize,
}

impl TableCost {
    fn total(self) -> usize {
        self.control + self.payload
    }
}

fn modulus() -> BigUint {
    (BigUint::one() << 255usize) - BigUint::from(19u32)
}

fn scalar_order() -> BigUint {
    (BigUint::one() << 252usize)
        + BigUint::parse_bytes(b"27742317777372353535851937790883648493", 10)
            .expect("Ed25519 order offset parses")
}

fn reachable_top_max(group_widths_low_to_high: &[usize], upper: &BigUint) -> usize {
    let mut remaining = upper.clone();
    for width in &group_widths_low_to_high[..group_widths_low_to_high.len() - 1] {
        let radix = 1u32 << *width;
        let bias = radix / 2;
        let residue = (&remaining & BigUint::from(radix - 1))
            .to_u32()
            .expect("window residue fits u32");
        if residue >= bias {
            remaining += BigUint::from(radix - residue);
        } else {
            remaining -= BigUint::from(residue);
        }
        remaining >>= *width;
    }
    remaining.to_usize().expect("top digit fits usize")
}

fn add_mod(lhs: &BigUint, rhs: &BigUint, p: &BigUint) -> BigUint {
    (lhs + rhs) % p
}

fn sub_mod(lhs: &BigUint, rhs: &BigUint, p: &BigUint) -> BigUint {
    if lhs >= rhs {
        lhs - rhs
    } else {
        p - (rhs - lhs)
    }
}

fn mul_mod(lhs: &BigUint, rhs: &BigUint, p: &BigUint) -> BigUint {
    (lhs * rhs) % p
}

fn invert(value: &BigUint, p: &BigUint) -> BigUint {
    assert!(!value.is_zero());
    value.modpow(&(p - BigUint::from(2u32)), p)
}

fn edwards_d(p: &BigUint) -> BigUint {
    let numerator = p - BigUint::from(121_665u32);
    mul_mod(&numerator, &invert(&BigUint::from(121_666u32), p), p)
}

fn identity() -> ExtendedPoint {
    ExtendedPoint {
        x: BigUint::zero(),
        y: BigUint::one(),
        z: BigUint::one(),
        t: BigUint::zero(),
    }
}

fn basepoint(p: &BigUint) -> ExtendedPoint {
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
        t: mul_mod(&x, &y, p),
        x,
        y,
        z: BigUint::one(),
    }
}

// Complete a=-1 twisted-Edwards addition in extended coordinates.
fn add_extended(
    lhs: &ExtendedPoint,
    rhs: &ExtendedPoint,
    d: &BigUint,
    p: &BigUint,
) -> ExtendedPoint {
    let y1_minus_x1 = sub_mod(&lhs.y, &lhs.x, p);
    let y2_minus_x2 = sub_mod(&rhs.y, &rhs.x, p);
    let y1_plus_x1 = add_mod(&lhs.y, &lhs.x, p);
    let y2_plus_x2 = add_mod(&rhs.y, &rhs.x, p);
    let a = mul_mod(&y1_minus_x1, &y2_minus_x2, p);
    let b = mul_mod(&y1_plus_x1, &y2_plus_x2, p);
    let c = mul_mod(
        &BigUint::from(2u32),
        &mul_mod(d, &mul_mod(&lhs.t, &rhs.t, p), p),
        p,
    );
    let d2 = mul_mod(&BigUint::from(2u32), &mul_mod(&lhs.z, &rhs.z, p), p);
    let e = sub_mod(&b, &a, p);
    let f = sub_mod(&d2, &c, p);
    let g = add_mod(&d2, &c, p);
    let h = add_mod(&b, &a, p);
    ExtendedPoint {
        x: mul_mod(&e, &f, p),
        y: mul_mod(&g, &h, p),
        t: mul_mod(&e, &h, p),
        z: mul_mod(&f, &g, p),
    }
}

fn batch_invert(values: &[BigUint], p: &BigUint) -> Vec<BigUint> {
    assert!(values.iter().all(|value| !value.is_zero()));
    let mut prefixes = Vec::with_capacity(values.len());
    let mut product = BigUint::one();
    for value in values {
        prefixes.push(product.clone());
        product = mul_mod(&product, value, p);
    }

    let mut inverse = invert(&product, p);
    let mut result = vec![BigUint::zero(); values.len()];
    for index in (0..values.len()).rev() {
        result[index] = mul_mod(&inverse, &prefixes[index], p);
        inverse = mul_mod(&inverse, &values[index], p);
    }
    result
}

fn normalize_batch(points: &[ExtendedPoint], p: &BigUint) -> Vec<AffinePoint> {
    let z_inverses = batch_invert(
        &points
            .iter()
            .map(|point| point.z.clone())
            .collect::<Vec<_>>(),
        p,
    );
    points
        .iter()
        .zip(z_inverses)
        .map(|(point, z_inverse)| AffinePoint {
            x: mul_mod(&point.x, &z_inverse, p),
            y: mul_mod(&point.y, &z_inverse, p),
        })
        .collect()
}

fn compressed_words(value: &BigUint) -> Vec<i64> {
    u5_packed::packed_words_from_digits(&u5_balanced_table::field_digits(value))
        .iter()
        .rev()
        .map(|word| i64::from(*word as i32))
        .collect()
}

// The asymmetric sound R0 schedule groups x*y in 17 three-digit limbs and
// K*tau in the field backend's compact 13-limb layout.  Its complete
// two-product update and reverse-carry bounds are checked by the affine
// kernel; emitting K in this exact form removes its packed decoder entirely.
const R0_K_LIMB_DIGITS: [usize; 13] = [4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 3];

fn stored_digits_from_compressed_words(words_high_to_low: &[i64]) -> Vec<i32> {
    assert_eq!(words_high_to_low.len(), PACKED_WORDS_PER_FIELD);
    let mut words = words_high_to_low
        .iter()
        .rev()
        .map(|word| *word as i32 as u32)
        .collect::<Vec<_>>();
    let words: [u32; PACKED_WORDS_PER_FIELD] = words
        .drain(..)
        .collect::<Vec<_>>()
        .try_into()
        .expect("field has eight packed words");
    u5_packed::digits_from_packed_words(&words)
        .expect("generated table field is canonical")
        .to_vec()
}

fn r0_k_limbs(stored_digits: &[i32]) -> Vec<i64> {
    assert_eq!(stored_digits.len(), u5_balanced_table::FIELD_DIGIT_COUNT);
    let mut cursor = 0usize;
    R0_K_LIMB_DIGITS
        .iter()
        .map(|digit_count| {
            let start = cursor;
            cursor += digit_count;
            stored_digits[start..cursor]
                .iter()
                .rev()
                .fold(0i64, |limb, digit| limb * 32 + i64::from(*digit - 16))
        })
        .collect()
}

fn hybrid_payload_cost(entries: &[Vec<TableEntry>], lower_widths: &[usize]) -> HybridPayloadCost {
    assert_eq!(entries.len(), lower_widths.len());
    let mut result = HybridPayloadCost::default();
    for (table, width) in entries.iter().zip(lower_widths) {
        for entry in table {
            let TableEntry::Packed(words) = entry else {
                continue;
            };
            assert_eq!(words.len(), 3 * PACKED_WORDS_PER_FIELD);
            let cp_words = &words[..PACKED_WORDS_PER_FIELD];
            let cm_words = &words[PACKED_WORDS_PER_FIELD..2 * PACKED_WORDS_PER_FIELD];
            let k_words = &words[2 * PACKED_WORDS_PER_FIELD..];
            let packed_cp = cp_words
                .iter()
                .copied()
                .map(scriptnum_push_bytes)
                .sum::<usize>();
            let packed_cm = cm_words
                .iter()
                .copied()
                .map(scriptnum_push_bytes)
                .sum::<usize>();
            let packed_k = k_words
                .iter()
                .copied()
                .map(scriptnum_push_bytes)
                .sum::<usize>();
            let direct_cp = stored_digits_from_compressed_words(cp_words)
                .into_iter()
                .map(|digit| scriptnum_push_bytes(i64::from(digit)))
                .sum::<usize>();
            let direct_cm = stored_digits_from_compressed_words(cm_words)
                .into_iter()
                .map(|digit| scriptnum_push_bytes(i64::from(digit)))
                .sum::<usize>();
            let direct_k = r0_k_limbs(&stored_digits_from_compressed_words(k_words))
                .into_iter()
                .map(scriptnum_push_bytes)
                .sum::<usize>();

            result.packed += packed_cp + packed_cm + packed_k;
            result.direct_k_limbs += packed_cp + packed_cm + direct_k;
            result.direct_cp_and_k_limbs += direct_cp + packed_cm + direct_k;
            result.direct_cm_and_k_limbs += packed_cp + direct_cm + direct_k;
            result.direct_cp_cm_and_k_limbs += direct_cp + direct_cm + direct_k;
            result.direct_k_and_w8_cp += if *width == 8 {
                direct_cp + packed_cm + direct_k
            } else {
                packed_cp + packed_cm + direct_k
            };
            result.direct_k_and_w8_cp_cm += if *width == 8 {
                direct_cp + direct_cm + direct_k
            } else {
                packed_cp + packed_cm + direct_k
            };
        }
    }
    result
}

fn packed_fields(values: &[&BigUint]) -> Vec<i64> {
    let mut result = Vec::with_capacity(values.len() * PACKED_WORDS_PER_FIELD);
    for value in values {
        result.extend(compressed_words(value));
    }
    result
}

// Direct limb shapes consumed by the Montgomery slope verifier.  Values are
// pushed high limb first, leaving limb zero nearest the top, exactly like the
// verifier's witness constructors.
const SLOPE_MIXED_LIMB_STARTS: [usize; 16] =
    [0, 4, 8, 12, 15, 18, 21, 24, 27, 30, 33, 36, 39, 42, 45, 48];
const SLOPE_MIXED_LIMB_DIGITS: [usize; 16] = [4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3];
const SLOPE_LINEAR_LIMB_STARTS: [usize; 9] = [0, 4, 10, 16, 22, 28, 34, 40, 46];
const SLOPE_LINEAR_LIMB_DIGITS: [usize; 9] = [4, 6, 6, 6, 6, 6, 6, 6, 5];

fn direct_centered_limbs(value: &BigUint, starts: &[usize], digit_counts: &[usize]) -> Vec<i64> {
    assert_eq!(starts.len(), digit_counts.len());
    let digits = u5_balanced_table::field_digits(value);
    starts
        .iter()
        .copied()
        .zip(digit_counts.iter().copied())
        .map(|(start, digit_count)| {
            (0..digit_count).rev().fold(0i64, |limb, digit_index| {
                limb * 32 + i64::from(digits[start + digit_index] - 16)
            })
        })
        .rev()
        .collect()
}

fn direct_slope_coordinates(u: &BigUint, v: &BigUint) -> Vec<i64> {
    let mut result = direct_centered_limbs(u, &SLOPE_MIXED_LIMB_STARTS, &SLOPE_MIXED_LIMB_DIGITS);
    result.extend(direct_centered_limbs(
        v,
        &SLOPE_LINEAR_LIMB_STARTS,
        &SLOPE_LINEAR_LIMB_DIGITS,
    ));
    assert_eq!(result.len(), 25);
    result
}

fn scriptnum_push_bytes(value: i64) -> usize {
    if value == -1 || (0..=16).contains(&value) {
        1
    } else {
        let mut bytes = [0u8; 8];
        let payload = bitcoin::script::write_scriptint(&mut bytes, value);
        1 + payload
    }
}

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn selector_push_bytes(value: usize) -> usize {
    scriptnum_push_bytes(i64::try_from(value).expect("selector fits i64"))
}

fn leaf_cost(entry: &TableEntry, kind: TableKind) -> TableCost {
    match (kind, entry) {
        (TableKind::Top, TableEntry::Packed(words)) => TableCost {
            control: 1, // OP_DROP
            payload: words.iter().copied().map(scriptnum_push_bytes).sum(),
        },
        (TableKind::Addition, TableEntry::Identity) => TableCost {
            control: 2, // OP_DROP OP_0: selector plus false branch marker
            payload: 0,
        },
        (TableKind::Addition, TableEntry::Packed(words)) => TableCost {
            control: 2, // OP_DROP OP_1: selector plus true branch marker
            payload: words.iter().copied().map(scriptnum_push_bytes).sum(),
        },
        (TableKind::Top, TableEntry::Identity) => {
            panic!("top identity must carry its affine x,y coordinates")
        }
    }
}

fn decision_tree_cost(
    entries: &[TableEntry],
    low: usize,
    high: usize,
    kind: TableKind,
) -> TableCost {
    assert!(low < high);
    if high - low == 1 {
        leaf_cost(&entries[low], kind)
    } else {
        let middle = low + (high - low) / 2;
        let lhs = decision_tree_cost(entries, low, middle, kind);
        let rhs = decision_tree_cost(entries, middle, high, kind);
        TableCost {
            // OP_DUP, pivot, OP_LESSTHAN, OP_IF, OP_ELSE, OP_ENDIF.
            control: 5 + selector_push_bytes(middle) + lhs.control + rhs.control,
            payload: lhs.payload + rhs.payload,
        }
    }
}

fn push_words(words: &[i64]) -> Script {
    script! {
        for word in words { { *word } }
    }
}

fn hybrid_addition_values(words: &[i64], width: usize, encoding: AdditionEncoding) -> Vec<i64> {
    assert_eq!(words.len(), 3 * PACKED_WORDS_PER_FIELD);
    let cp_words = &words[..PACKED_WORDS_PER_FIELD];
    let cm_words = &words[PACKED_WORDS_PER_FIELD..2 * PACKED_WORDS_PER_FIELD];
    let k_words = &words[2 * PACKED_WORDS_PER_FIELD..];
    let mut values = Vec::new();
    match encoding {
        AdditionEncoding::DirectKLimbs => {
            values.extend_from_slice(cp_words);
            values.extend_from_slice(cm_words);
        }
        AdditionEncoding::DirectKAndWidth8Coordinates if width == 8 => {
            values.extend(
                stored_digits_from_compressed_words(cp_words)
                    .into_iter()
                    .map(i64::from),
            );
            values.extend(
                stored_digits_from_compressed_words(cm_words)
                    .into_iter()
                    .map(i64::from),
            );
        }
        AdditionEncoding::DirectKAndWidth8Coordinates => {
            values.extend_from_slice(cp_words);
            values.extend_from_slice(cm_words);
        }
    }
    values.extend(r0_k_limbs(&stored_digits_from_compressed_words(k_words)));
    values
}

fn hybrid_addition_tree(
    entries: &[TableEntry],
    low: usize,
    high: usize,
    width: usize,
    encoding: AdditionEncoding,
) -> Script {
    assert!(low < high);
    if high - low == 1 {
        match &entries[low] {
            TableEntry::Identity => script! { OP_DROP OP_0 },
            TableEntry::Packed(words) => {
                let values = hybrid_addition_values(words, width, encoding);
                script! {
                    OP_DROP
                    { push_words(&values) }
                    OP_1
                }
            }
        }
    } else {
        let middle = low + (high - low) / 2;
        script! {
            OP_DUP { middle as u32 } OP_LESSTHAN
            OP_IF
                { hybrid_addition_tree(entries, low, middle, width, encoding) }
            OP_ELSE
                { hybrid_addition_tree(entries, middle, high, width, encoding) }
            OP_ENDIF
        }
    }
}

fn decision_tree(entries: &[TableEntry], low: usize, high: usize, kind: TableKind) -> Script {
    assert!(low < high);
    if high - low == 1 {
        match (kind, &entries[low]) {
            (TableKind::Top, TableEntry::Packed(words)) => script! {
                OP_DROP
                { push_words(words) }
            },
            (TableKind::Addition, TableEntry::Identity) => script! {
                OP_DROP OP_0
            },
            (TableKind::Addition, TableEntry::Packed(words)) => script! {
                OP_DROP
                { push_words(words) }
                OP_1
            },
            (TableKind::Top, TableEntry::Identity) => {
                panic!("top identity must carry its affine x,y coordinates")
            }
        }
    } else {
        let middle = low + (high - low) / 2;
        script! {
            OP_DUP { middle as u32 } OP_LESSTHAN
            OP_IF
                { decision_tree(entries, low, middle, kind) }
            OP_ELSE
                { decision_tree(entries, middle, high, kind) }
            OP_ENDIF
        }
    }
}

/// Decompose a nonnegative selector into boolean bits with the most
/// significant bit on top.
///
/// The decision tree below consumes the bits directly.  This pays the numeric
/// decomposition once per selected table instead of serializing a comparison
/// and a copy of the selector at every internal tree node.  A residue left
/// above `width` bits rejects an out-of-range hostile selector.
fn selector_to_msb_first_bits(width: usize) -> Script {
    assert!((1..=30).contains(&width));
    script! {
        for bit in (0..width).rev() {
            OP_DUP { (1u32 << bit) - 1 } OP_GREATERTHAN
            OP_SWAP OP_OVER
            OP_IF { 1u32 << bit } OP_SUB OP_ENDIF
        }
        OP_NOT OP_VERIFY
        // Extraction leaves bit zero nearest the top. Reverse the short bit
        // block so the range-pruned trie can branch on its MSB first.
        for depth in 1..width { { depth as u32 } OP_ROLL }
    }
}

fn bit_tree_leaf(entry: &TableEntry, kind: TableKind) -> Script {
    match (kind, entry) {
        (TableKind::Top, TableEntry::Packed(words)) => script! { { push_words(words) } },
        (TableKind::Addition, TableEntry::Identity) => script! { OP_0 },
        (TableKind::Addition, TableEntry::Packed(words)) => script! {
            { push_words(words) }
            OP_1
        },
        (TableKind::Top, TableEntry::Identity) => {
            panic!("top identity must carry its affine x,y coordinates")
        }
    }
}

/// Select a leaf by consuming already-decomposed selector bits high-to-low.
/// One-sided nodes become VERIFYs, so invalid bit patterns are rejected
/// without materializing otherwise-dead branches.
fn bit_decision_tree_inner(
    entries: &[TableEntry],
    candidates: &[usize],
    remaining_bits: usize,
    width: usize,
    kind: TableKind,
) -> Script {
    assert!(!candidates.is_empty());
    if remaining_bits == 0 {
        assert_eq!(candidates.len(), 1);
        return bit_tree_leaf(&entries[candidates[0]], kind);
    }

    let bit = remaining_bits - 1;

    let (one, zero): (Vec<_>, Vec<_>) = candidates
        .iter()
        .copied()
        .partition(|index| ((index >> bit) & 1) != 0);
    match (zero.is_empty(), one.is_empty()) {
        (false, false) => {
            let zero_tree =
                bit_decision_tree_inner(entries, &zero, remaining_bits - 1, width, kind);
            let one_tree = bit_decision_tree_inner(entries, &one, remaining_bits - 1, width, kind);
            script! {
                OP_IF { one_tree } OP_ELSE { zero_tree } OP_ENDIF
            }
        }
        (false, true) => {
            let zero_tree =
                bit_decision_tree_inner(entries, &zero, remaining_bits - 1, width, kind);
            script! { OP_NOT OP_VERIFY { zero_tree } }
        }
        (true, false) => {
            let one_tree = bit_decision_tree_inner(entries, &one, remaining_bits - 1, width, kind);
            script! { OP_VERIFY { one_tree } }
        }
        (true, true) => unreachable!("a populated node has a child"),
    }
}

fn bit_decision_tree(entries: &[TableEntry], width: usize, kind: TableKind) -> Script {
    assert!(!entries.is_empty());
    assert!(entries.len() <= 1usize << width);
    let candidates = (0..entries.len()).collect::<Vec<_>>();
    script! {
        { selector_to_msb_first_bits(width) }
        { bit_decision_tree_inner(entries, &candidates, width, width, kind) }
    }
}

fn hybrid_bit_tree_leaf(entry: &TableEntry, width: usize, encoding: AdditionEncoding) -> Script {
    match entry {
        TableEntry::Identity => {
            // Uniform identity tuple for the signed/zero-safe affine kernel:
            // C+=C-=K=1 and z=0. R0 binds tau=0; R+/R- bind next=current.
            let one = BigUint::one();
            let packed = packed_fields(&[&one, &one, &one]);
            let values = hybrid_addition_values(&packed, width, encoding);
            script! {
                { push_words(&values) }
                OP_0
            }
        }
        TableEntry::Packed(words) => {
            let values = hybrid_addition_values(words, width, encoding);
            script! {
                { push_words(&values) }
                OP_1
            }
        }
    }
}

fn hybrid_addition_bit_tree_inner(
    entries: &[TableEntry],
    candidates: &[usize],
    remaining_bits: usize,
    width: usize,
    encoding: AdditionEncoding,
) -> Script {
    assert!(!candidates.is_empty());
    if remaining_bits == 0 {
        assert_eq!(candidates.len(), 1);
        return hybrid_bit_tree_leaf(&entries[candidates[0]], width, encoding);
    }

    let bit = remaining_bits - 1;

    let (one, zero): (Vec<_>, Vec<_>) = candidates
        .iter()
        .copied()
        .partition(|index| ((index >> bit) & 1) != 0);
    match (zero.is_empty(), one.is_empty()) {
        (false, false) => {
            let zero_tree =
                hybrid_addition_bit_tree_inner(entries, &zero, remaining_bits - 1, width, encoding);
            let one_tree =
                hybrid_addition_bit_tree_inner(entries, &one, remaining_bits - 1, width, encoding);
            script! { OP_IF { one_tree } OP_ELSE { zero_tree } OP_ENDIF }
        }
        (false, true) => {
            let zero_tree =
                hybrid_addition_bit_tree_inner(entries, &zero, remaining_bits - 1, width, encoding);
            script! { OP_NOT OP_VERIFY { zero_tree } }
        }
        (true, false) => {
            let one_tree =
                hybrid_addition_bit_tree_inner(entries, &one, remaining_bits - 1, width, encoding);
            script! { OP_VERIFY { one_tree } }
        }
        (true, true) => unreachable!("a populated node has a child"),
    }
}

fn hybrid_addition_bit_tree(
    entries: &[TableEntry],
    width: usize,
    encoding: AdditionEncoding,
) -> Script {
    assert!(!entries.is_empty());
    assert!(entries.len() <= 1usize << width);
    let candidates = (0..entries.len()).collect::<Vec<_>>();
    script! {
        { selector_to_msb_first_bits(width) }
        { hybrid_addition_bit_tree_inner(entries, &candidates, width, width, encoding) }
    }
}

fn verify_bit_selected_addition(
    entries: &[TableEntry],
    width: usize,
    encoding: AdditionEncoding,
    index: usize,
) {
    let compiled = hybrid_addition_bit_tree(entries, width, encoding).compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(
        compiled.to_bytes(),
        vec![scriptnum_item(index as i64)],
    );
    assert!(
        execution.error.is_none(),
        "bit-selected addition leaf {index} failed: {execution}"
    );
    let expected_values = match &entries[index] {
        TableEntry::Identity => {
            let one = BigUint::one();
            let packed = packed_fields(&[&one, &one, &one]);
            let mut values = hybrid_addition_values(&packed, width, encoding);
            values.push(0);
            values
        }
        TableEntry::Packed(words) => {
            let mut values = hybrid_addition_values(words, width, encoding);
            values.push(1);
            values
        }
    };
    let expected = expected_values
        .into_iter()
        .map(scriptnum_item)
        .collect::<Vec<_>>();
    assert_eq!(execution.final_stack.len(), expected.len());
    for (item_index, item) in expected.into_iter().enumerate() {
        assert_eq!(execution.final_stack.get(item_index), item);
    }
}

fn verify_bit_selected_top(entries: &[TableEntry], width: usize, index: usize) {
    let compiled = bit_decision_tree(entries, width, TableKind::Top).compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(
        compiled.to_bytes(),
        vec![scriptnum_item(index as i64)],
    );
    assert!(
        execution.error.is_none(),
        "bit-selected top leaf {index} failed: {execution}"
    );
    let TableEntry::Packed(words) = &entries[index] else {
        panic!("top entry is affine")
    };
    let expected = words
        .iter()
        .copied()
        .map(scriptnum_item)
        .collect::<Vec<_>>();
    assert_eq!(execution.final_stack.len(), expected.len());
    for (item_index, item) in expected.into_iter().enumerate() {
        assert_eq!(execution.final_stack.get(item_index), item);
    }
}

fn generate_affine_tables(
    group_widths_low_to_high: &[usize],
    top_max: usize,
    p: &BigUint,
    d: &BigUint,
) -> Vec<Vec<AffinePoint>> {
    assert!(!group_widths_low_to_high.is_empty());
    assert_eq!(group_widths_low_to_high.iter().sum::<usize>(), SCALAR_BITS);
    let mut projective_tables = Vec::with_capacity(group_widths_low_to_high.len());
    let mut position_base = basepoint(p);
    for (position, width) in group_widths_low_to_high.iter().copied().enumerate() {
        let maximum = if position + 1 == group_widths_low_to_high.len() {
            top_max
        } else {
            1usize << (width - 1)
        };
        let mut multiples = Vec::with_capacity(maximum + 1);
        let mut current = identity();
        for _ in 0..=maximum {
            multiples.push(current.clone());
            current = add_extended(&current, &position_base, d, p);
        }
        projective_tables.push(multiples);
        for _ in 0..width {
            position_base = add_extended(&position_base, &position_base, d, p);
        }
    }

    let flat = projective_tables
        .iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    let normalized = normalize_batch(&flat, p);
    let mut cursor = 0usize;
    projective_tables
        .into_iter()
        .map(|table| {
            let end = cursor + table.len();
            let result = normalized[cursor..end].to_vec();
            cursor = end;
            result
        })
        .collect()
}

fn make_entries(
    affine_tables: &[Vec<AffinePoint>],
    p: &BigUint,
    d: &BigUint,
) -> (Vec<Vec<TableEntry>>, Vec<TableEntry>) {
    let lower_points = affine_tables[..affine_tables.len() - 1]
        .iter()
        .flat_map(|table| table.iter().skip(1))
        .collect::<Vec<_>>();
    let denominators = lower_points
        .iter()
        .map(|point| mul_mod(d, &mul_mod(&point.x, &point.y, p), p))
        .collect::<Vec<_>>();
    let inverses = batch_invert(&denominators, p);
    let mut inverse_cursor = 0usize;

    let lower = affine_tables[..affine_tables.len() - 1]
        .iter()
        .map(|table| {
            let mut entries = Vec::with_capacity(table.len());
            entries.push(TableEntry::Identity);
            for point in table.iter().skip(1) {
                let cp = add_mod(&point.x, &point.y, p);
                let cm = sub_mod(&point.y, &point.x, p);
                let k_inverse = &inverses[inverse_cursor];
                inverse_cursor += 1;
                entries.push(TableEntry::Packed(packed_fields(&[&cp, &cm, k_inverse])));
            }
            entries
        })
        .collect::<Vec<_>>();
    assert_eq!(inverse_cursor, inverses.len());

    let top = affine_tables
        .last()
        .expect("there is a top table")
        .iter()
        .map(|point| TableEntry::Packed(packed_fields(&[&point.x, &point.y])))
        .collect::<Vec<_>>();
    (lower, top)
}

fn report_schedule(
    name: &str,
    group_widths_low_to_high: &[usize],
    top_max: usize,
    p: &BigUint,
    d: &BigUint,
) {
    let affine = generate_affine_tables(group_widths_low_to_high, top_max, p, d);
    let (lower, top) = make_entries(&affine, p, d);
    let hybrid_payload = hybrid_payload_cost(
        &lower,
        &group_widths_low_to_high[..group_widths_low_to_high.len() - 1],
    );
    let mut scripts = Vec::with_capacity(lower.len() + 1);
    let mut cost = TableCost::default();

    for entries in &lower {
        let table_cost = decision_tree_cost(entries, 0, entries.len(), TableKind::Addition);
        cost.control += table_cost.control;
        cost.payload += table_cost.payload;
        scripts.push(decision_tree(
            entries,
            0,
            entries.len(),
            TableKind::Addition,
        ));
    }
    let top_cost = decision_tree_cost(&top, 0, top.len(), TableKind::Top);
    cost.control += top_cost.control;
    cost.payload += top_cost.payload;
    scripts.push(decision_tree(&top, 0, top.len(), TableKind::Top));

    let whole = script! {
        for table in scripts { { table } }
    }
    .compile_with_policy();
    assert!(whole.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(whole.len(), cost.total());

    let compile_hybrid = |encoding| {
        let mut hybrid_scripts = lower
            .iter()
            .zip(&group_widths_low_to_high[..group_widths_low_to_high.len() - 1])
            .map(|(entries, width)| {
                hybrid_addition_tree(entries, 0, entries.len(), *width, encoding)
            })
            .collect::<Vec<_>>();
        hybrid_scripts.push(decision_tree(&top, 0, top.len(), TableKind::Top));
        script! { for table in hybrid_scripts { { table } } }
            .compile_with_policy()
            .len()
    };
    let compile_bit_selected = |encoding| {
        let mut bit_scripts = lower
            .iter()
            .zip(&group_widths_low_to_high[..group_widths_low_to_high.len() - 1])
            .map(|(entries, width)| hybrid_addition_bit_tree(entries, *width, encoding))
            .collect::<Vec<_>>();
        let top_width = *group_widths_low_to_high
            .last()
            .expect("schedule has a top group");
        bit_scripts.push(bit_decision_tree(&top, top_width, TableKind::Top));
        script! { for table in bit_scripts { { table } } }
            .compile_with_policy()
            .len()
    };
    let direct_k_compiled = compile_hybrid(AdditionEncoding::DirectKLimbs);
    let direct_k_w8_coordinates_compiled =
        compile_hybrid(AdditionEncoding::DirectKAndWidth8Coordinates);
    let bit_direct_k_compiled = compile_bit_selected(AdditionEncoding::DirectKLimbs);
    let bit_direct_k_w8_coordinates_compiled =
        compile_bit_selected(AdditionEncoding::DirectKAndWidth8Coordinates);

    // Execute the identity, first nonzero, and maximum leaves at each distinct
    // boundary.  This catches bit order, one-sided range pruning, and leaf
    // payload routing without executing any affine arithmetic kernel.
    let mut verified_widths = Vec::new();
    for (entries, width) in lower
        .iter()
        .zip(&group_widths_low_to_high[..group_widths_low_to_high.len() - 1])
    {
        if verified_widths.contains(width) {
            continue;
        }
        verified_widths.push(*width);
        for index in [0, 1, entries.len() - 1] {
            verify_bit_selected_addition(
                entries,
                *width,
                AdditionEncoding::DirectKAndWidth8Coordinates,
                index,
            );
        }
    }
    let top_width = *group_widths_low_to_high
        .last()
        .expect("schedule has a top group");
    for index in [0, 1, top.len() - 1] {
        verify_bit_selected_top(&top, top_width, index);
    }

    let lower_entries = lower.iter().map(Vec::len).sum::<usize>();
    let nonzero_lower_entries = lower_entries - lower.len();
    println!("schedule={name}");
    println!(
        "group_widths_low_to_high={}",
        group_widths_low_to_high
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("position_groups={}", affine.len());
    println!("addition_groups={}", lower.len());
    println!("top_entries={}", top.len());
    println!("lower_entries_including_zero={lower_entries}");
    println!("lower_nonzero_entries={nonzero_lower_entries}");
    println!("control_bytes={}", cost.control);
    println!("payload_bytes={}", cost.payload);
    println!("locking_script_bytes={}", whole.len());
    let top_payload = top
        .iter()
        .map(|entry| leaf_cost(entry, TableKind::Top).payload)
        .sum::<usize>();
    assert_eq!(hybrid_payload.packed + top_payload, cost.payload);
    println!(
        "locking_script_bytes_direct_k_limbs={}",
        cost.control + top_payload + hybrid_payload.direct_k_limbs
    );
    assert_eq!(
        direct_k_compiled,
        cost.control + top_payload + hybrid_payload.direct_k_limbs
    );
    println!(
        "locking_script_bytes_direct_cp_k_limbs={}",
        cost.control + top_payload + hybrid_payload.direct_cp_and_k_limbs
    );
    println!(
        "locking_script_bytes_direct_cm_k_limbs={}",
        cost.control + top_payload + hybrid_payload.direct_cm_and_k_limbs
    );
    println!(
        "locking_script_bytes_direct_cp_cm_k_limbs={}",
        cost.control + top_payload + hybrid_payload.direct_cp_cm_and_k_limbs
    );
    println!(
        "locking_script_bytes_direct_k_and_w8_cp={}",
        cost.control + top_payload + hybrid_payload.direct_k_and_w8_cp
    );
    println!(
        "locking_script_bytes_direct_k_and_w8_cp_cm={}",
        cost.control + top_payload + hybrid_payload.direct_k_and_w8_cp_cm
    );
    assert_eq!(
        direct_k_w8_coordinates_compiled,
        cost.control + top_payload + hybrid_payload.direct_k_and_w8_cp_cm
    );
    println!("locking_script_bytes_bit_selector_direct_k={bit_direct_k_compiled}");
    println!(
        "locking_script_bytes_bit_selector_direct_k_and_w8_cp_cm={bit_direct_k_w8_coordinates_compiled}"
    );
    println!("bit_selector_identity_tuple=Cp=1,Cm=1,K=1,z=0");
    println!("top_selected_runtime_items={}", 2 * PACKED_WORDS_PER_FIELD);
    println!("zero_add_selected_runtime_items=1");
    println!(
        "nonzero_add_selected_runtime_items={}",
        1 + 3 * PACKED_WORDS_PER_FIELD
    );
    println!("nonzero_add_selected_runtime_items_direct_k_limbs=30");
    println!("nonzero_add_selected_runtime_items_direct_cp_k_limbs=73");
    println!("nonzero_add_selected_runtime_items_direct_cm_k_limbs=73");
    println!("nonzero_add_selected_runtime_items_direct_cp_cm_k_limbs=116");
    println!("hint_items=0");
    println!();
}

fn report_uniform_width(width: usize, p: &BigUint, d: &BigUint) {
    let groups = SCALAR_BITS.div_ceil(width);
    let top_source_bits = SCALAR_BITS - width * (groups - 1);
    let mut group_widths = vec![width; groups - 1];
    group_widths.push(top_source_bits);
    // One possible carry from the lower centered digits is included. This is
    // deliberately the full 253-bit recoding domain rather than an l-specific
    // top-table pruning argument.
    report_schedule(
        &format!("uniform_w{width}"),
        &group_widths,
        1usize << top_source_bits,
        p,
        d,
    );
}

fn report_mixed_width_8_9(p: &BigUint, d: &BigUint) {
    // Seven low width-8 groups, then 21 width-9 groups, then the top width-8
    // source group. Lower centered carries make the top digit range 0..=256.
    let mut group_widths = vec![8; 7];
    group_widths.extend([9; 21]);
    group_widths.push(8);
    report_schedule("mixed_top8_lower21w9_7w8", &group_widths, 256, p, d);
}

fn report_canonical_mixed_schedules(p: &BigUint, d: &BigUint) {
    let upper = scalar_order() - BigUint::one();

    let mut top8 = vec![8; 7];
    top8.extend([9; 21]);
    top8.push(8);
    let top8_max = reachable_top_max(&top8, &upper);
    assert_eq!(top8_max, 128);
    report_schedule("canonical_l_top8_lower21w9_7w8", &top8, top8_max, p, d);

    let mut top9 = vec![8; 8];
    top9.extend([9; 20]);
    top9.push(9);
    let top9_max = reachable_top_max(&top9, &upper);
    // Exact lexicographic scalar validation proves digit 257 unreachable for
    // s < l, so the top table needs entries 0..=256 rather than 0..=257.
    assert_eq!(top9_max, 256);
    report_schedule("canonical_l_top9_lower20w9_8w8", &top9, top9_max, p, d);

    // Neighboring group counts trade one affine transition against roughly
    // 896 width-8-equivalent table leaves.  Measuring these exact constants
    // is necessary because that trade is close at the current ~100--120 kB
    // transition cost; optimizing the table in isolation can choose the wrong
    // scalar schedule.
    let neighboring = [
        ("canonical_l_g28_lower27w9_top10", vec![9; 27], 10usize),
        (
            "canonical_l_g30_lower12w9_17w8_top9",
            [vec![8; 17], vec![9; 12]].concat(),
            9usize,
        ),
        (
            "canonical_l_g31_lower4w9_26w8_top9",
            [vec![8; 26], vec![9; 4]].concat(),
            9usize,
        ),
        ("canonical_l_g32_lower31w8_top5", vec![8; 31], 5usize),
    ];
    for (name, mut lower, top_width) in neighboring {
        lower.push(top_width);
        assert_eq!(lower.iter().sum::<usize>(), SCALAR_BITS);
        let top_max = reachable_top_max(&lower, &upper);
        report_schedule(name, &lower, top_max, p, d);
    }
}

/// Build the exact G29 MSB-first table fragments used by the integrated
/// fixed-base scalar-multiplication model.  Fragments are returned in
/// low-to-high position order: the first 28 entries are addition tables and
/// the final entry is the top accumulator-initialization table.
///
/// This is `pub(crate)` so another focused example can compose the real table
/// bytecode without duplicating the expensive point/table generator.  It is
/// not a public library API.
#[allow(dead_code)]
pub(crate) fn g29_hybrid_bit_table_fragments() -> Vec<Script> {
    let p = modulus();
    let d = edwards_d(&p);
    let upper = scalar_order() - BigUint::one();
    let mut widths = vec![8; 8];
    widths.extend(std::iter::repeat_n(9, 20));
    widths.push(9);
    let top_max = reachable_top_max(&widths, &upper);
    assert_eq!(top_max, 256);

    let affine = generate_affine_tables(&widths, top_max, &p, &d);
    let (lower, top) = make_entries(&affine, &p, &d);
    let mut result = lower
        .iter()
        .zip(&widths[..widths.len() - 1])
        .map(|(entries, width)| {
            hybrid_addition_bit_tree(
                entries,
                *width,
                AdditionEncoding::DirectKAndWidth8Coordinates,
            )
        })
        .collect::<Vec<_>>();
    result.push(bit_decision_tree(&top, 9, TableKind::Top));
    assert_eq!(result.len(), 29);
    result
}

fn sqrt_mod_checked(value: &BigUint, p: &BigUint, sqrt_minus_one: &BigUint) -> Option<BigUint> {
    let mut root = value.modpow(&((p + BigUint::from(3u8)) >> 3usize), p);
    if mul_mod(&root, &root, p) != *value {
        root = mul_mod(&root, sqrt_minus_one, p);
    }
    (mul_mod(&root, &root, p) == *value).then_some(root)
}

fn sqrt_mod(value: &BigUint, p: &BigUint, sqrt_minus_one: &BigUint) -> BigUint {
    sqrt_mod_checked(value, p, sqrt_minus_one).expect("field element has a square root")
}

fn negate_extended(point: &ExtendedPoint, p: &BigUint) -> ExtendedPoint {
    ExtendedPoint {
        x: if point.x.is_zero() {
            BigUint::zero()
        } else {
            p - &point.x
        },
        y: point.y.clone(),
        z: point.z.clone(),
        t: if point.t.is_zero() {
            BigUint::zero()
        } else {
            p - &point.t
        },
    }
}

fn scalar_mul_extended(
    mut scalar: BigUint,
    point: &ExtendedPoint,
    d: &BigUint,
    p: &BigUint,
) -> ExtendedPoint {
    let mut accumulator = identity();
    let mut power = point.clone();
    while !scalar.is_zero() {
        if (&scalar & BigUint::one()) == BigUint::one() {
            accumulator = add_extended(&accumulator, &power, d, p);
        }
        power = add_extended(&power, &power, d, p);
        scalar >>= 1usize;
    }
    accumulator
}

fn torsion_t(p: &BigUint) -> ExtendedPoint {
    ExtendedPoint {
        x: BigUint::zero(),
        y: p - BigUint::one(),
        z: BigUint::one(),
        t: BigUint::zero(),
    }
}

fn torsion_u(sqrt_minus_one: &BigUint) -> ExtendedPoint {
    ExtendedPoint {
        x: sqrt_minus_one.clone(),
        y: BigUint::zero(),
        z: BigUint::one(),
        t: BigUint::zero(),
    }
}

fn montgomery_coordinates(
    point: &AffinePoint,
    p: &BigUint,
    v_scale: &BigUint,
) -> (BigUint, BigUint) {
    let one = BigUint::one();
    // The birational formula is exceptional at the Edwards order-two point,
    // but T itself is the ordinary Montgomery point (0,0).
    if point.x.is_zero() && point.y == p - &one {
        return (BigUint::zero(), BigUint::zero());
    }
    assert!(!point.x.is_zero());
    let one_minus_y = sub_mod(&one, &point.y, p);
    assert!(!one_minus_y.is_zero());
    let u = mul_mod(&add_mod(&one, &point.y, p), &invert(&one_minus_y, p), p);
    let v = mul_mod(&mul_mod(v_scale, &u, p), &invert(&point.x, p), p);
    let u_squared = mul_mod(&u, &u, p);
    let curve_rhs = add_mod(
        &add_mod(
            &mul_mod(&u_squared, &u, p),
            &mul_mod(&BigUint::from(486_662u32), &u_squared, p),
            p,
        ),
        &u,
        p,
    );
    assert_eq!(mul_mod(&v, &v, p), curve_rhs);
    (u, v)
}

/// Build uniform two-coordinate Montgomery tables for a centered-digit
/// schedule. Every leaf is translated by T, so magnitude zero emits the real
/// point T=(0,0) rather than a short identity branch. When
/// `initialize_top_with_u` is true, the final table folds in the conceptual U
/// initializer and emits P0=U+(T+Qtop)=-U+Qtop.
fn montgomery_torsion_coset_entries(
    widths_low_to_high: &[usize],
    top_max: usize,
    base: &ExtendedPoint,
    initialize_top_with_u: bool,
    p: &BigUint,
    d: &BigUint,
    sqrt_minus_one: &BigUint,
    v_scale: &BigUint,
) -> Vec<Vec<TableEntry>> {
    let t = torsion_t(p);
    let u_plus_t = add_extended(&torsion_u(sqrt_minus_one), &t, d, p);
    let mut position_base = base.clone();
    let mut result = Vec::with_capacity(widths_low_to_high.len());

    for (position, width) in widths_low_to_high.iter().copied().enumerate() {
        let is_top = position + 1 == widths_low_to_high.len();
        let maximum = if is_top {
            top_max
        } else {
            1usize << (width - 1)
        };
        let offset = if is_top && initialize_top_with_u {
            &u_plus_t
        } else {
            &t
        };
        let mut multiple = identity();
        let mut translated = Vec::with_capacity(maximum + 1);
        for _ in 0..=maximum {
            translated.push(add_extended(offset, &multiple, d, p));
            multiple = add_extended(&multiple, &position_base, d, p);
        }
        let affine = normalize_batch(&translated, p);
        result.push(
            affine
                .iter()
                .map(|point| {
                    let (u, v) = montgomery_coordinates(point, p, v_scale);
                    TableEntry::Packed(packed_fields(&[&u, &v]))
                })
                .collect(),
        );
        for _ in 0..width {
            position_base = add_extended(&position_base, &position_base, d, p);
        }
    }
    result
}

/// Direct-limb counterpart of [`montgomery_torsion_coset_entries`]. Each leaf
/// emits 16 `u`/`a` limbs in `[4x3,3x13]`, followed by nine `v`/`b` limbs in
/// the staggered `[4,6x7,5]` layout. The latter's starts are deliberately
/// `0,4,10,...,46`; those sparse positions are part of the relation bound.
/// A response top can initialize at either `U` or `U+T=-U`; its choice must
/// account for the parity of the remaining T-translated selections.
fn montgomery_direct_torsion_coset_entries(
    widths_low_to_high: &[usize],
    top_max: usize,
    base: &ExtendedPoint,
    initialize_top_with_u: bool,
    initialize_top_with_t: bool,
    top_initializer_shift: Option<&ExtendedPoint>,
    p: &BigUint,
    d: &BigUint,
    sqrt_minus_one: &BigUint,
    v_scale: &BigUint,
) -> Vec<Vec<TableEntry>> {
    let t = torsion_t(p);
    let u = torsion_u(sqrt_minus_one);
    let u_plus_t = add_extended(&u, &t, d, p);
    let mut position_base = base.clone();
    let mut result = Vec::with_capacity(widths_low_to_high.len());

    for (position, width) in widths_low_to_high.iter().copied().enumerate() {
        let is_top = position + 1 == widths_low_to_high.len();
        let maximum = if is_top {
            top_max
        } else {
            1usize << (width - 1)
        };
        let offset = if is_top && initialize_top_with_u {
            let torsion_initializer = if initialize_top_with_t { &u_plus_t } else { &u };
            if let Some(shift) = top_initializer_shift {
                add_extended(torsion_initializer, shift, d, p)
            } else {
                torsion_initializer.clone()
            }
        } else {
            t.clone()
        };
        result.push(montgomery_direct_torsion_coset_table(
            &position_base,
            &offset,
            maximum,
            p,
            d,
            v_scale,
        ));
        for _ in 0..width {
            position_base = add_extended(&position_base, &position_base, d, p);
        }
    }
    result
}

fn montgomery_direct_torsion_coset_table(
    position_base: &ExtendedPoint,
    offset: &ExtendedPoint,
    maximum: usize,
    p: &BigUint,
    d: &BigUint,
    v_scale: &BigUint,
) -> Vec<TableEntry> {
    let mut multiple = identity();
    let mut translated = Vec::with_capacity(maximum + 1);
    for _ in 0..=maximum {
        translated.push(add_extended(offset, &multiple, d, p));
        multiple = add_extended(&multiple, position_base, d, p);
    }
    normalize_batch(&translated, p)
        .iter()
        .map(|point| {
            let (u, v) = montgomery_coordinates(point, p, v_scale);
            TableEntry::Packed(direct_slope_coordinates(&u, &v))
        })
        .collect()
}

fn packed_leaf_payload_bytes(entries: &[TableEntry]) -> usize {
    entries
        .iter()
        .map(|entry| match entry {
            TableEntry::Packed(words) => words
                .iter()
                .copied()
                .map(scriptnum_push_bytes)
                .sum::<usize>(),
            TableEntry::Identity => panic!("Montgomery torsion-coset leaves are uniform"),
        })
        .sum()
}

fn verify_direct_leaf_strict(entries: &[TableEntry], selector_bits: usize, index: usize) -> usize {
    const RAW_COPIES: usize = 4;
    let tree = bit_decision_tree(entries, selector_bits, TableKind::Top);
    // Four serialized copies force policy compilation above the 32-KiB cutoff,
    // avoiding a slow optimizer pass. Only the first copy executes; the other
    // three are unreachable test padding and are not part of table metrics.
    let executable = script! {
        { tree.clone() }
        OP_0 OP_IF
            for _ in 1..RAW_COPIES { { tree.clone() } }
        OP_ENDIF
        // The selected tuple is a fragment result, not a terminal predicate.
        // Add a test-only truthy item so T=(0,0) is executable too.
        OP_1
    }
    .compile_with_policy();
    assert!(executable.len() > MAX_OPTIMIZER_INPUT_BYTES);
    let execution = execute_raw_script_with_inputs_strict(
        executable.to_bytes(),
        vec![scriptnum_item(index as i64)],
    );
    assert!(
        execution.error.is_none(),
        "direct table leaf {index} failed: {execution}"
    );
    let TableEntry::Packed(expected) = &entries[index] else {
        panic!("torsion-coset table leaf is uniform")
    };
    assert_eq!(expected.len(), 25);
    assert_eq!(execution.final_stack.len(), expected.len() + 1);
    for (item_index, value) in expected.iter().copied().enumerate() {
        assert_eq!(execution.final_stack.get(item_index), scriptnum_item(value));
    }
    assert_eq!(execution.final_stack.get(expected.len()), scriptnum_item(1));
    execution.stats.max_nb_stack_items
}

/// Recover a fragment's exact unoptimized length without bypassing the
/// repository compilation policy. Four copies force even the response-top
/// table over the 32-KiB threshold; the raw concatenation is exactly additive.
fn repeated_raw_fragment_len(fragment: Script) -> usize {
    const COPIES: usize = 4;
    let repeated = script! {
        for _ in 0..COPIES { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % COPIES, 0);
    repeated.len() / COPIES
}

/// Exact direct-limb table fragments for the 29-response/16-challenge H16
/// Montgomery slope candidate. The vectors are in low-to-high scalar-window
/// order; consumers stream them in reverse. `public_key_compressed` is the
/// RFC 8032 compressed Edwards encoding of the same fixed point whose
/// negation backs every challenge table.
///
/// This focused helper is intentionally crate-local to examples. It lets the
/// whole-candidate linker bind the key-specialized BLAKE3 prefix to the table
/// key without duplicating or approximating either constant.
#[allow(dead_code)]
pub(crate) struct MontgomeryDirectH16TableFragments {
    pub(crate) response_low_to_high: Vec<Script>,
    pub(crate) challenge_low_to_high: Vec<Script>,
    pub(crate) public_key_compressed: [u8; 32],
}

/// Exact direct-coordinate leaf values backing the H16 Script tables.
///
/// Each leaf is in the same bottom-to-top order emitted by its decision tree:
/// sixteen high-to-low `u/a` limbs followed by nine high-to-low `v/b` limbs.
/// This host-only view lets witness generators derive relation quotients from
/// the authenticated table representatives instead of regenerating them with
/// a subtly different sign or limb convention.
#[allow(dead_code)]
pub(crate) struct MontgomeryDirectH16HostTables {
    pub(crate) response_low_to_high: Vec<Vec<[i32; 25]>>,
    pub(crate) challenge_low_to_high: Vec<Vec<[i32; 25]>>,
    pub(crate) public_key_compressed: [u8; 32],
}

/// Errors rejected by the production H16 table generator's public-key
/// boundary. The decoder accepts only a canonical RFC 8032 encoding of a
/// non-identity point in the prime-order subgroup.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Ed25519PublicKeyError {
    NonCanonicalY,
    NotOnCurve,
    InvalidSignOfZero,
    Identity,
    SmallOrder,
    NotPrimeSubgroup,
}

impl fmt::Display for Ed25519PublicKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NonCanonicalY => "non-canonical Ed25519 y coordinate",
            Self::NotOnCurve => "compressed Ed25519 key does not encode a curve point",
            Self::InvalidSignOfZero => "compressed Ed25519 key sets the sign bit for x=0",
            Self::Identity => "Ed25519 identity is not a public key",
            Self::SmallOrder => "small-order Ed25519 point is not a public key",
            Self::NotPrimeSubgroup => "Ed25519 point is not in the prime-order subgroup",
        })
    }
}

impl std::error::Error for Ed25519PublicKeyError {}

/// Host-validated key used internally while building the key-specialized
/// challenge tables. Its point is deliberately private so table generation
/// cannot bypass the encoding/subgroup boundary.
#[allow(dead_code)]
pub(crate) struct ValidatedEd25519PublicKey {
    compressed: [u8; 32],
    point: ExtendedPoint,
}

#[allow(dead_code)]
impl ValidatedEd25519PublicKey {
    pub(crate) fn compressed(&self) -> [u8; 32] {
        self.compressed
    }
}

/// Disclosed benchmark key `[987654321]B`, retained only so the existing
/// no-argument measurement helpers remain byte-for-byte stable. Production
/// generation takes an external compressed public key through the validated
/// APIs below; it never takes or derives from a secret scalar.
pub(crate) const H16_BENCHMARK_PUBLIC_KEY_COMPRESSED: [u8; 32] = [
    0x7d, 0xb0, 0xdc, 0x92, 0x22, 0xf3, 0xc1, 0x83, 0x45, 0x7d, 0xdd, 0xe4, 0xc7, 0x08, 0xde, 0x8e,
    0x5e, 0xa6, 0xbf, 0x3d, 0x5c, 0x44, 0x04, 0xcc, 0xa1, 0x4b, 0x32, 0x72, 0x9a, 0x05, 0xc3, 0x2a,
];

/// Per-byte challenge bias for the compact independent signed-byte schedule.
/// For each little-endian challenge byte `b_i`, the selected signed digit is
/// `e_i=b_i-127` in `[-127,128]`.
pub(crate) const H16_INDEPENDENT_CHALLENGE_BYTE_BIAS: u8 = 127;

/// `K_127 = 0x7f7f...7f = sum(127 * 2^(8i), i=0..15)`.
/// The independent-byte identity is `h=sum(e_i*2^(8i))+K_127`.
#[allow(dead_code)]
pub(crate) fn h16_independent_challenge_bias_scalar() -> BigUint {
    BigUint::from_bytes_le(&[H16_INDEPENDENT_CHALLENGE_BYTE_BIAS; 16])
}

/// Regression-only derivation proving the constant above preserves the old
/// disclosed benchmark fixture. Production table generation does not call
/// this helper and has no scalar parameter.
#[allow(dead_code)]
pub(crate) fn h16_benchmark_key_matches_disclosed_scalar() -> bool {
    const DISCLOSED_BENCHMARK_SCALAR: u64 = 987_654_321;
    let p = modulus();
    let d = edwards_d(&p);
    let derived = scalar_mul_extended(
        BigUint::from(DISCLOSED_BENCHMARK_SCALAR),
        &basepoint(&p),
        &d,
        &p,
    );
    let affine = normalize_batch(std::slice::from_ref(&derived), &p)
        .pop()
        .expect("one normalized benchmark point");
    rfc8032_compress_affine(&affine) == H16_BENCHMARK_PUBLIC_KEY_COMPRESSED
}

fn rfc8032_compress_affine(point: &AffinePoint) -> [u8; 32] {
    let mut encoded = point.y.to_bytes_le();
    assert!(encoded.len() <= 32);
    encoded.resize(32, 0);
    assert_eq!(encoded[31] & 0x80, 0, "Edwards y occupies 255 bits");
    if (&point.x & BigUint::one()) == BigUint::one() {
        encoded[31] |= 0x80;
    }
    encoded
        .try_into()
        .expect("an RFC 8032 compressed point has 32 bytes")
}

fn is_extended_identity(point: &ExtendedPoint) -> bool {
    !point.z.is_zero() && point.x.is_zero() && point.t.is_zero() && point.y == point.z
}

/// Decode and validate the exact external public key used by the H16
/// challenge-table generator.
///
/// This is a host-only compile-time boundary, not Script bytecode. It checks
/// canonical `y`, recovers the signed `x` root, rejects the forbidden negative
/// encoding of zero, checks the Edwards equation, rejects identity and
/// small-order points, and finally proves prime-subgroup membership with
/// `[l]A = identity`.
#[allow(dead_code)]
pub(crate) fn validate_ed25519_public_key(
    compressed: [u8; 32],
) -> Result<ValidatedEd25519PublicKey, Ed25519PublicKeyError> {
    let p = modulus();
    let d = edwards_d(&p);
    let sqrt_minus_one = BigUint::parse_bytes(
        b"19681161376707505956807079304988542015446066515923890162744021073123829784752",
        10,
    )
    .expect("sqrt(-1) parses");

    let x_sign = (compressed[31] >> 7) != 0;
    let mut y_bytes = compressed;
    y_bytes[31] &= 0x7f;
    let y = BigUint::from_bytes_le(&y_bytes);
    if y >= p {
        return Err(Ed25519PublicKeyError::NonCanonicalY);
    }

    // -x^2 + y^2 = 1 + d*x^2*y^2, hence
    // x^2 = (y^2 - 1) / (d*y^2 + 1).
    let y_squared = mul_mod(&y, &y, &p);
    let numerator = sub_mod(&y_squared, &BigUint::one(), &p);
    let denominator = add_mod(&mul_mod(&d, &y_squared, &p), &BigUint::one(), &p);
    if denominator.is_zero() {
        return Err(Ed25519PublicKeyError::NotOnCurve);
    }
    let x_squared = mul_mod(&numerator, &invert(&denominator, &p), &p);
    let mut x = sqrt_mod_checked(&x_squared, &p, &sqrt_minus_one)
        .ok_or(Ed25519PublicKeyError::NotOnCurve)?;
    if x.is_zero() && x_sign {
        return Err(Ed25519PublicKeyError::InvalidSignOfZero);
    }
    if ((&x & BigUint::one()) == BigUint::one()) != x_sign {
        x = &p - &x;
    }

    // Keep the explicit equation check at this trust boundary even though a
    // correct square-root recovery algebraically implies it.
    let x_squared = mul_mod(&x, &x, &p);
    let equation_lhs = sub_mod(&y_squared, &x_squared, &p);
    let equation_rhs = add_mod(
        &BigUint::one(),
        &mul_mod(&d, &mul_mod(&x_squared, &y_squared, &p), &p),
        &p,
    );
    if equation_lhs != equation_rhs {
        return Err(Ed25519PublicKeyError::NotOnCurve);
    }

    let point = ExtendedPoint {
        t: mul_mod(&x, &y, &p),
        x: x.clone(),
        y: y.clone(),
        z: BigUint::one(),
    };
    if is_extended_identity(&point) {
        return Err(Ed25519PublicKeyError::Identity);
    }
    if is_extended_identity(&scalar_mul_extended(BigUint::from(8u8), &point, &d, &p)) {
        return Err(Ed25519PublicKeyError::SmallOrder);
    }
    if !is_extended_identity(&scalar_mul_extended(scalar_order(), &point, &d, &p)) {
        return Err(Ed25519PublicKeyError::NotPrimeSubgroup);
    }

    let affine = AffinePoint { x, y };
    debug_assert_eq!(rfc8032_compress_affine(&affine), compressed);
    Ok(ValidatedEd25519PublicKey { compressed, point })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H16ChallengeDigitSchedule {
    CarryCentered,
    IndependentByte127,
}

fn montgomery_direct_h16_g29_response_widths() -> Vec<usize> {
    let mut widths = vec![8usize; 8];
    widths.extend(std::iter::repeat_n(9usize, 21));
    assert_eq!(widths.iter().sum::<usize>(), SCALAR_BITS);
    widths
}

/// Exact low-to-high response schedule selected by the exhaustive zero-hint
/// G31 table/routing search. The five width-9 lower groups are positions
/// 20,21,22,23,26; all other lower groups and the unsigned top group are width
/// eight.
#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_qfree_g31_response_widths() -> Vec<usize> {
    let mut widths = vec![8usize; 31];
    for position in [20usize, 21, 22, 23, 26] {
        widths[position] = 9;
    }
    assert_eq!(widths.iter().sum::<usize>(), SCALAR_BITS);
    widths
}

/// Exact low-to-high response schedule selected by the exhaustive zero-hint
/// G32 search. Lower positions 21,25,29 are width seven; every other lower
/// group and the unsigned top group are width eight.
#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_qfree_g32_response_widths() -> Vec<usize> {
    let mut widths = vec![8usize; 32];
    for position in [21usize, 25, 29] {
        widths[position] = 7;
    }
    assert_eq!(widths.iter().sum::<usize>(), SCALAR_BITS);
    widths
}

fn montgomery_direct_h16_entries_for_validated_public_key_with_schedule(
    public_key: &ValidatedEd25519PublicKey,
    challenge_schedule: H16ChallengeDigitSchedule,
    response_widths: &[usize],
    response_top_with_t: bool,
) -> (Vec<Vec<TableEntry>>, Vec<Vec<TableEntry>>, [u8; 32]) {
    const CHALLENGE_GROUPS: usize = 16;

    let p = modulus();
    let d = edwards_d(&p);
    let sqrt_minus_one = BigUint::parse_bytes(
        b"19681161376707505956807079304988542015446066515923890162744021073123829784752",
        10,
    )
    .expect("sqrt(-1) parses");
    assert_eq!(
        mul_mod(&sqrt_minus_one, &sqrt_minus_one, &p),
        &p - BigUint::one()
    );
    let v_scale = sqrt_mod(&(&p - BigUint::from(486_664u32)), &p, &sqrt_minus_one);

    assert!(response_widths.len() >= 2);
    assert_eq!(response_widths.iter().sum::<usize>(), SCALAR_BITS);
    let response_top_max = reachable_top_max(response_widths, &(scalar_order() - BigUint::one()));

    let challenge_widths = vec![8usize; CHALLENGE_GROUPS];
    let challenge_top_max = match challenge_schedule {
        H16ChallengeDigitSchedule::CarryCentered => {
            let maximum = reachable_top_max(
                &challenge_widths,
                &((BigUint::one() << 128usize) - BigUint::one()),
            );
            assert_eq!(maximum, 256);
            maximum
        }
        H16ChallengeDigitSchedule::IndependentByte127 => 128,
    };

    let base = basepoint(&p);
    let public_key_compressed = public_key.compressed;
    let negative_public_key = negate_extended(&public_key.point, &p);
    let response_initializer_shift =
        (challenge_schedule == H16ChallengeDigitSchedule::IndependentByte127).then(|| {
            negate_extended(
                &scalar_mul_extended(
                    h16_independent_challenge_bias_scalar(),
                    &public_key.point,
                    &d,
                    &p,
                ),
                &p,
            )
        });

    let response_entries = montgomery_direct_torsion_coset_entries(
        response_widths,
        response_top_max,
        &base,
        true,
        response_top_with_t,
        response_initializer_shift.as_ref(),
        &p,
        &d,
        &sqrt_minus_one,
        &v_scale,
    );
    let challenge_entries = montgomery_direct_torsion_coset_entries(
        &challenge_widths,
        challenge_top_max,
        &negative_public_key,
        false,
        false,
        None,
        &p,
        &d,
        &sqrt_minus_one,
        &v_scale,
    );

    (response_entries, challenge_entries, public_key_compressed)
}

fn montgomery_direct_h16_entries_for_validated_public_key(
    public_key: &ValidatedEd25519PublicKey,
) -> (Vec<Vec<TableEntry>>, Vec<Vec<TableEntry>>, [u8; 32]) {
    montgomery_direct_h16_entries_for_validated_public_key_with_schedule(
        public_key,
        H16ChallengeDigitSchedule::CarryCentered,
        &montgomery_direct_h16_g29_response_widths(),
        true,
    )
}

fn montgomery_direct_h16_independent_byte_entries_for_validated_public_key(
    public_key: &ValidatedEd25519PublicKey,
) -> (Vec<Vec<TableEntry>>, Vec<Vec<TableEntry>>, [u8; 32]) {
    montgomery_direct_h16_entries_for_validated_public_key_with_schedule(
        public_key,
        H16ChallengeDigitSchedule::IndependentByte127,
        &montgomery_direct_h16_g29_response_widths(),
        true,
    )
}

fn montgomery_direct_h16_qfree_g31_entries_for_validated_public_key(
    public_key: &ValidatedEd25519PublicKey,
) -> (Vec<Vec<TableEntry>>, Vec<Vec<TableEntry>>, [u8; 32]) {
    montgomery_direct_h16_entries_for_validated_public_key_with_schedule(
        public_key,
        H16ChallengeDigitSchedule::IndependentByte127,
        &montgomery_direct_h16_qfree_g31_response_widths(),
        true,
    )
}

fn montgomery_direct_h16_qfree_g32_entries_for_validated_public_key(
    public_key: &ValidatedEd25519PublicKey,
) -> (Vec<Vec<TableEntry>>, Vec<Vec<TableEntry>>, [u8; 32]) {
    montgomery_direct_h16_entries_for_validated_public_key_with_schedule(
        public_key,
        H16ChallengeDigitSchedule::IndependentByte127,
        &montgomery_direct_h16_qfree_g32_response_widths(),
        false,
    )
}

fn montgomery_direct_h16_entries_for_public_key(
    public_key_compressed: [u8; 32],
) -> Result<(Vec<Vec<TableEntry>>, Vec<Vec<TableEntry>>, [u8; 32]), Ed25519PublicKeyError> {
    let public_key = validate_ed25519_public_key(public_key_compressed)?;
    Ok(montgomery_direct_h16_entries_for_validated_public_key(
        &public_key,
    ))
}

fn montgomery_direct_h16_independent_byte_entries_for_public_key(
    public_key_compressed: [u8; 32],
) -> Result<(Vec<Vec<TableEntry>>, Vec<Vec<TableEntry>>, [u8; 32]), Ed25519PublicKeyError> {
    let public_key = validate_ed25519_public_key(public_key_compressed)?;
    Ok(montgomery_direct_h16_independent_byte_entries_for_validated_public_key(&public_key))
}

fn montgomery_direct_h16_qfree_g31_entries_for_public_key(
    public_key_compressed: [u8; 32],
) -> Result<(Vec<Vec<TableEntry>>, Vec<Vec<TableEntry>>, [u8; 32]), Ed25519PublicKeyError> {
    let public_key = validate_ed25519_public_key(public_key_compressed)?;
    Ok(montgomery_direct_h16_qfree_g31_entries_for_validated_public_key(&public_key))
}

fn montgomery_direct_h16_qfree_g32_entries_for_public_key(
    public_key_compressed: [u8; 32],
) -> Result<(Vec<Vec<TableEntry>>, Vec<Vec<TableEntry>>, [u8; 32]), Ed25519PublicKeyError> {
    let public_key = validate_ed25519_public_key(public_key_compressed)?;
    Ok(montgomery_direct_h16_qfree_g32_entries_for_validated_public_key(&public_key))
}

fn montgomery_direct_h16_fragments_from_entries(
    response_entries: Vec<Vec<TableEntry>>,
    challenge_entries: Vec<Vec<TableEntry>>,
    public_key_compressed: [u8; 32],
    response_widths: &[usize],
    challenge_top_selector_bits: usize,
) -> MontgomeryDirectH16TableFragments {
    const CHALLENGE_GROUPS: usize = 16;

    let response_low_to_high = response_entries
        .iter()
        .zip(response_widths)
        .map(|(entries, width)| bit_decision_tree(entries, *width, TableKind::Top))
        .collect::<Vec<_>>();
    let challenge_low_to_high = challenge_entries
        .iter()
        .enumerate()
        .map(|(index, entries)| {
            let selector_bits = if index + 1 == CHALLENGE_GROUPS {
                challenge_top_selector_bits
            } else {
                8
            };
            bit_decision_tree(entries, selector_bits, TableKind::Top)
        })
        .collect::<Vec<_>>();
    assert_eq!(response_low_to_high.len(), response_widths.len());
    assert_eq!(challenge_low_to_high.len(), CHALLENGE_GROUPS);

    MontgomeryDirectH16TableFragments {
        response_low_to_high,
        challenge_low_to_high,
        public_key_compressed,
    }
}

#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_table_fragments() -> MontgomeryDirectH16TableFragments {
    montgomery_direct_h16_table_fragments_for_public_key(H16_BENCHMARK_PUBLIC_KEY_COMPRESSED)
        .expect("the disclosed benchmark public key is valid")
}

/// Build the exact H16 table fragments for an externally supplied public key.
///
/// The only key material accepted here is the canonical 32-byte RFC 8032
/// public encoding. Validation happens before any tables are built, and the
/// returned `public_key_compressed` plus every `-A` challenge-table leaf derive
/// from the same validated point. No private scalar is accepted, embedded, or
/// derived by this production-oriented path.
#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_table_fragments_for_public_key(
    public_key_compressed: [u8; 32],
) -> Result<MontgomeryDirectH16TableFragments, Ed25519PublicKeyError> {
    let (response_entries, challenge_entries, public_key_compressed) =
        montgomery_direct_h16_entries_for_public_key(public_key_compressed)?;
    Ok(montgomery_direct_h16_fragments_from_entries(
        response_entries,
        challenge_entries,
        public_key_compressed,
        &montgomery_direct_h16_g29_response_widths(),
        9,
    ))
}

/// H16 tables for independent signed challenge bytes `e_i=b_i-127`.
/// All sixteen challenge selectors are magnitudes in `0..=128`; the fixed
/// `-K_127*A` contribution is folded into every response initializer leaf.
/// This retains 45 tables and 44 transitions while removing 128 challenge-top
/// leaves. The old carry-centered API above remains available for exact
/// before/after comparison.
#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_independent_byte_table_fragments(
) -> MontgomeryDirectH16TableFragments {
    montgomery_direct_h16_independent_byte_table_fragments_for_public_key(
        H16_BENCHMARK_PUBLIC_KEY_COMPRESSED,
    )
    .expect("the disclosed benchmark public key is valid")
}

#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_independent_byte_table_fragments_for_public_key(
    public_key_compressed: [u8; 32],
) -> Result<MontgomeryDirectH16TableFragments, Ed25519PublicKeyError> {
    let (response_entries, challenge_entries, public_key_compressed) =
        montgomery_direct_h16_independent_byte_entries_for_public_key(public_key_compressed)?;
    Ok(montgomery_direct_h16_fragments_from_entries(
        response_entries,
        challenge_entries,
        public_key_compressed,
        &montgomery_direct_h16_g29_response_widths(),
        8,
    ))
}

/// Optimized G31 response tables paired directly with the existing sixteen
/// independent-byte challenge tables. This path generates no legacy G29
/// response tables.
#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_qfree_g31_table_fragments() -> MontgomeryDirectH16TableFragments
{
    montgomery_direct_h16_qfree_g31_table_fragments_for_public_key(
        H16_BENCHMARK_PUBLIC_KEY_COMPRESSED,
    )
    .expect("the disclosed benchmark public key is valid")
}

#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_qfree_g31_table_fragments_for_public_key(
    public_key_compressed: [u8; 32],
) -> Result<MontgomeryDirectH16TableFragments, Ed25519PublicKeyError> {
    let (response_entries, challenge_entries, public_key_compressed) =
        montgomery_direct_h16_qfree_g31_entries_for_public_key(public_key_compressed)?;
    Ok(montgomery_direct_h16_fragments_from_entries(
        response_entries,
        challenge_entries,
        public_key_compressed,
        &montgomery_direct_h16_qfree_g31_response_widths(),
        8,
    ))
}

/// Parity-correct G32 response tables paired directly with the sixteen
/// independent-byte challenge tables. With 47 post-initializer selections,
/// the response top uses `U-[K_127]A` without an initial torsion offset.
#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_qfree_g32_table_fragments() -> MontgomeryDirectH16TableFragments
{
    montgomery_direct_h16_qfree_g32_table_fragments_for_public_key(
        H16_BENCHMARK_PUBLIC_KEY_COMPRESSED,
    )
    .expect("the disclosed benchmark public key is valid")
}

#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_qfree_g32_table_fragments_for_public_key(
    public_key_compressed: [u8; 32],
) -> Result<MontgomeryDirectH16TableFragments, Ed25519PublicKeyError> {
    let (response_entries, challenge_entries, public_key_compressed) =
        montgomery_direct_h16_qfree_g32_entries_for_public_key(public_key_compressed)?;
    Ok(montgomery_direct_h16_fragments_from_entries(
        response_entries,
        challenge_entries,
        public_key_compressed,
        &montgomery_direct_h16_qfree_g32_response_widths(),
        8,
    ))
}

/// Exact response-table result for an alternate canonical centered-window
/// schedule. The independent-byte challenge remains fixed; every top leaf
/// includes the same `-K_127*A` initializer shift as the H16 production path.
#[allow(dead_code)]
pub(crate) struct MontgomeryDirectResponseTableVariant {
    pub(crate) response_low_to_high: Vec<Script>,
    /// Host leaves derived from the exact same in-memory entries as the Script
    /// decision trees above.
    pub(crate) host_low_to_high: Vec<Vec<[i32; 25]>>,
    pub(crate) widths_low_to_high: Vec<usize>,
    pub(crate) top_max: usize,
    pub(crate) per_table_raw_bytes: Vec<usize>,
    pub(crate) total_raw_bytes: usize,
}

/// Build exact direct-limb response tables for a caller-selected partition of
/// the 253-bit canonical scalar payload. Lower groups are centered and the top
/// group is unsigned. This host-only cost-model helper accepts no secret key;
/// it retains the disclosed benchmark public key solely to compare schedules
/// against the existing deterministic H16 fixture.
#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_independent_response_table_variant(
    widths_low_to_high: &[usize],
) -> MontgomeryDirectResponseTableVariant {
    assert!(widths_low_to_high.len() >= 2);
    assert_eq!(widths_low_to_high.iter().sum::<usize>(), SCALAR_BITS);
    assert!(widths_low_to_high
        .iter()
        .all(|width| (2..=16).contains(width)));

    let public_key = validate_ed25519_public_key(H16_BENCHMARK_PUBLIC_KEY_COMPRESSED)
        .expect("the disclosed benchmark public key is valid");
    let p = modulus();
    let d = edwards_d(&p);
    let sqrt_minus_one = BigUint::parse_bytes(
        b"19681161376707505956807079304988542015446066515923890162744021073123829784752",
        10,
    )
    .expect("sqrt(-1) parses");
    let v_scale = sqrt_mod(&(&p - BigUint::from(486_664u32)), &p, &sqrt_minus_one);
    let top_max = reachable_top_max(widths_low_to_high, &(scalar_order() - BigUint::one()));
    let top_width = *widths_low_to_high.last().expect("at least two groups");
    assert!(top_max < 1usize << top_width);
    // Every lower response and challenge selection contributes T. Choose the
    // top torsion representative so the final endpoint is always R-U.
    let response_top_with_t = ((widths_low_to_high.len() - 1 + 16) % 2) == 0;

    let response_initializer_shift = negate_extended(
        &scalar_mul_extended(
            h16_independent_challenge_bias_scalar(),
            &public_key.point,
            &d,
            &p,
        ),
        &p,
    );
    let entries = montgomery_direct_torsion_coset_entries(
        widths_low_to_high,
        top_max,
        &basepoint(&p),
        true,
        response_top_with_t,
        Some(&response_initializer_shift),
        &p,
        &d,
        &sqrt_minus_one,
        &v_scale,
    );
    let host_low_to_high = direct_host_leaves(entries.clone());
    let response_low_to_high = entries
        .iter()
        .zip(widths_low_to_high)
        .map(|(table, width)| bit_decision_tree(table, *width, TableKind::Top))
        .collect::<Vec<_>>();
    let per_table_raw_bytes = response_low_to_high
        .iter()
        .map(Script::len)
        .collect::<Vec<_>>();
    let raw = script! {
        for table in &response_low_to_high { { table.clone() } }
    }
    .compile_with_policy();
    assert!(raw.len() > MAX_OPTIMIZER_INPUT_BYTES);
    let total_raw_bytes = per_table_raw_bytes.iter().sum::<usize>();
    assert_eq!(raw.len(), total_raw_bytes);

    MontgomeryDirectResponseTableVariant {
        response_low_to_high,
        host_low_to_high,
        widths_low_to_high: widths_low_to_high.to_vec(),
        top_max,
        per_table_raw_bytes,
        total_raw_bytes,
    }
}

/// Exact table-cost result for an independent variable-width low-128
/// challenge schedule.
///
/// A width-`w` unsigned chunk is represented as
/// `e = chunk - (2^(w-1)-1)`, with magnitude at most `2^(w-1)`. The returned
/// response-top cost includes the corresponding exact
/// `-sum((2^(w-1)-1)*2^offset)*A` initializer shift and the parity-correct U/T
/// representative. Lower response tables do not depend on this bias.
#[allow(dead_code)]
pub(crate) struct MontgomeryDirectIndependentChallengeTableVariant {
    pub(crate) widths_low_to_high: Vec<usize>,
    pub(crate) bias_scalar: BigUint,
    pub(crate) response_top_with_t: bool,
    pub(crate) response_top_raw_bytes: usize,
    pub(crate) challenge_per_table_raw_bytes: Vec<usize>,
    pub(crate) challenge_total_raw_bytes: usize,
}

/// Build only the exact direct-coordinate challenge tables and the shifted
/// response-top table needed to compare an independent variable-width
/// challenge partition. This host-only cost helper does not concatenate a
/// scalar schedule or a complete leaf.
#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_independent_challenge_table_variant(
    challenge_widths_low_to_high: &[usize],
) -> MontgomeryDirectIndependentChallengeTableVariant {
    const CHALLENGE_BITS: usize = 128;

    assert!(!challenge_widths_low_to_high.is_empty());
    assert_eq!(
        challenge_widths_low_to_high.iter().sum::<usize>(),
        CHALLENGE_BITS
    );
    assert!(challenge_widths_low_to_high
        .iter()
        .all(|width| (2..=16).contains(width)));

    let public_key = validate_ed25519_public_key(H16_BENCHMARK_PUBLIC_KEY_COMPRESSED)
        .expect("the disclosed benchmark public key is valid");
    let p = modulus();
    let d = edwards_d(&p);
    let sqrt_minus_one = BigUint::parse_bytes(
        b"19681161376707505956807079304988542015446066515923890162744021073123829784752",
        10,
    )
    .expect("sqrt(-1) parses");
    let v_scale = sqrt_mod(&(&p - BigUint::from(486_664u32)), &p, &sqrt_minus_one);

    let mut bias_scalar = BigUint::zero();
    let mut bit_offset = 0usize;
    for width in challenge_widths_low_to_high.iter().copied() {
        let local_bias = (1u32 << (width - 1)) - 1;
        bias_scalar += BigUint::from(local_bias) << bit_offset;
        bit_offset += width;
    }
    assert_eq!(bit_offset, CHALLENGE_BITS);

    let negative_public_key = negate_extended(&public_key.point, &p);
    let challenge_top_width = *challenge_widths_low_to_high
        .last()
        .expect("nonempty challenge schedule");
    let challenge_entries = montgomery_direct_torsion_coset_entries(
        challenge_widths_low_to_high,
        1usize << (challenge_top_width - 1),
        &negative_public_key,
        false,
        false,
        None,
        &p,
        &d,
        &sqrt_minus_one,
        &v_scale,
    );
    let challenge_scripts = challenge_entries
        .iter()
        .zip(challenge_widths_low_to_high)
        .map(|(entries, width)| bit_decision_tree(entries, *width, TableKind::Top))
        .collect::<Vec<_>>();
    let challenge_per_table_raw_bytes = challenge_scripts
        .iter()
        .map(Script::len)
        .collect::<Vec<_>>();
    let challenge_total_raw_bytes = challenge_per_table_raw_bytes.iter().sum::<usize>();
    let challenge_raw = script! {
        for table in &challenge_scripts { { table.clone() } }
    }
    .compile_with_policy();
    assert!(challenge_raw.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(challenge_raw.len(), challenge_total_raw_bytes);

    let response_widths = montgomery_direct_h16_qfree_g32_response_widths();
    let response_top_width = *response_widths.last().expect("G32 response top");
    let response_top_max = reachable_top_max(&response_widths, &(scalar_order() - BigUint::one()));
    let response_top_with_t =
        ((response_widths.len() - 1 + challenge_widths_low_to_high.len()) % 2) == 0;
    let response_initializer_shift = negate_extended(
        &scalar_mul_extended(bias_scalar.clone(), &public_key.point, &d, &p),
        &p,
    );
    let torsion_initializer = if response_top_with_t {
        add_extended(&torsion_u(&sqrt_minus_one), &torsion_t(&p), &d, &p)
    } else {
        torsion_u(&sqrt_minus_one)
    };
    let response_top_offset =
        add_extended(&torsion_initializer, &response_initializer_shift, &d, &p);
    let response_top_base = schedule_position_bases(&response_widths, &basepoint(&p), &d, &p)
        .pop()
        .expect("G32 response top base");
    let response_top_entries = montgomery_direct_torsion_coset_table(
        &response_top_base,
        &response_top_offset,
        response_top_max,
        &p,
        &d,
        &v_scale,
    );
    let response_top = bit_decision_tree(&response_top_entries, response_top_width, TableKind::Top);
    let response_top_raw_bytes = repeated_raw_fragment_len(response_top);

    MontgomeryDirectIndependentChallengeTableVariant {
        widths_low_to_high: challenge_widths_low_to_high.to_vec(),
        bias_scalar,
        response_top_with_t,
        response_top_raw_bytes,
        challenge_per_table_raw_bytes,
        challenge_total_raw_bytes,
    }
}

/// Return exact raw direct-tree bytes for lower response groups at caller-
/// selected scalar bit offsets. Unlike the top group, these tables always use
/// the torsion-T offset and therefore do not depend on the public-key bias.
/// This is a host-only placement-search helper; `(offset, width)` must remain
/// strictly below the 253-bit top boundary.
#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_response_lower_table_raw_bytes_at(
    queries: &[(usize, usize)],
) -> Vec<usize> {
    let p = modulus();
    let d = edwards_d(&p);
    let sqrt_minus_one = BigUint::parse_bytes(
        b"19681161376707505956807079304988542015446066515923890162744021073123829784752",
        10,
    )
    .expect("sqrt(-1) parses");
    let v_scale = sqrt_mod(&(&p - BigUint::from(486_664u32)), &p, &sqrt_minus_one);
    let offset = torsion_t(&p);

    let mut position_bases = Vec::with_capacity(SCALAR_BITS);
    let mut position_base = basepoint(&p);
    for _ in 0..SCALAR_BITS {
        position_bases.push(position_base.clone());
        position_base = add_extended(&position_base, &position_base, &d, &p);
    }

    queries
        .iter()
        .copied()
        .map(|(bit_offset, width)| {
            assert!((2..=16).contains(&width));
            assert!(bit_offset + width < SCALAR_BITS);
            let entries = montgomery_direct_torsion_coset_table(
                &position_bases[bit_offset],
                &offset,
                1usize << (width - 1),
                &p,
                &d,
                &v_scale,
            );
            bit_decision_tree(&entries, width, TableKind::Top).len()
        })
        .collect()
}

fn direct_host_leaves(entries: Vec<Vec<TableEntry>>) -> Vec<Vec<[i32; 25]>> {
    entries
        .into_iter()
        .map(|table| {
            table
                .into_iter()
                .map(|entry| {
                    let TableEntry::Packed(values) = entry else {
                        panic!("Montgomery torsion-coset leaves are uniform")
                    };
                    assert_eq!(values.len(), 25);
                    values
                        .into_iter()
                        .map(|value| i32::try_from(value).expect("direct limb fits i32"))
                        .collect::<Vec<_>>()
                        .try_into()
                        .expect("direct Montgomery leaf has 25 limbs")
                })
                .collect()
        })
        .collect()
}

/// Host-only leaf data produced by the exact same generator as
/// [`montgomery_direct_h16_table_fragments`].
#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_host_tables() -> MontgomeryDirectH16HostTables {
    montgomery_direct_h16_host_tables_for_public_key(H16_BENCHMARK_PUBLIC_KEY_COMPRESSED)
        .expect("the disclosed benchmark public key is valid")
}

/// Host leaf view for the same externally validated key path as
/// [`montgomery_direct_h16_table_fragments_for_public_key`]. Witness builders
/// can therefore consume exact leaves without learning or receiving the
/// corresponding secret scalar.
#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_host_tables_for_public_key(
    public_key_compressed: [u8; 32],
) -> Result<MontgomeryDirectH16HostTables, Ed25519PublicKeyError> {
    let (response_entries, challenge_entries, public_key_compressed) =
        montgomery_direct_h16_entries_for_public_key(public_key_compressed)?;
    Ok(MontgomeryDirectH16HostTables {
        response_low_to_high: direct_host_leaves(response_entries),
        challenge_low_to_high: direct_host_leaves(challenge_entries),
        public_key_compressed,
    })
}

/// Exact host leaves matching
/// [`montgomery_direct_h16_independent_byte_table_fragments_for_public_key`].
#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_independent_byte_host_tables() -> MontgomeryDirectH16HostTables
{
    montgomery_direct_h16_independent_byte_host_tables_for_public_key(
        H16_BENCHMARK_PUBLIC_KEY_COMPRESSED,
    )
    .expect("the disclosed benchmark public key is valid")
}

#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_independent_byte_host_tables_for_public_key(
    public_key_compressed: [u8; 32],
) -> Result<MontgomeryDirectH16HostTables, Ed25519PublicKeyError> {
    let (response_entries, challenge_entries, public_key_compressed) =
        montgomery_direct_h16_independent_byte_entries_for_public_key(public_key_compressed)?;
    Ok(MontgomeryDirectH16HostTables {
        response_low_to_high: direct_host_leaves(response_entries),
        challenge_low_to_high: direct_host_leaves(challenge_entries),
        public_key_compressed,
    })
}

/// Exact host leaves matching
/// [`montgomery_direct_h16_qfree_g31_table_fragments_for_public_key`].
#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_qfree_g31_host_tables() -> MontgomeryDirectH16HostTables {
    montgomery_direct_h16_qfree_g31_host_tables_for_public_key(H16_BENCHMARK_PUBLIC_KEY_COMPRESSED)
        .expect("the disclosed benchmark public key is valid")
}

#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_qfree_g31_host_tables_for_public_key(
    public_key_compressed: [u8; 32],
) -> Result<MontgomeryDirectH16HostTables, Ed25519PublicKeyError> {
    let (response_entries, challenge_entries, public_key_compressed) =
        montgomery_direct_h16_qfree_g31_entries_for_public_key(public_key_compressed)?;
    Ok(MontgomeryDirectH16HostTables {
        response_low_to_high: direct_host_leaves(response_entries),
        challenge_low_to_high: direct_host_leaves(challenge_entries),
        public_key_compressed,
    })
}

/// Exact host leaves for the G32 zero-hint candidate. This is intentionally a
/// host-only witness-builder boundary; no G32 Script table is constructed.
#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_qfree_g32_host_tables() -> MontgomeryDirectH16HostTables {
    montgomery_direct_h16_qfree_g32_host_tables_for_public_key(H16_BENCHMARK_PUBLIC_KEY_COMPRESSED)
        .expect("the disclosed benchmark public key is valid")
}

#[allow(dead_code)]
pub(crate) fn montgomery_direct_h16_qfree_g32_host_tables_for_public_key(
    public_key_compressed: [u8; 32],
) -> Result<MontgomeryDirectH16HostTables, Ed25519PublicKeyError> {
    let (response_entries, challenge_entries, public_key_compressed) =
        montgomery_direct_h16_qfree_g32_entries_for_public_key(public_key_compressed)?;
    Ok(MontgomeryDirectH16HostTables {
        response_low_to_high: direct_host_leaves(response_entries),
        challenge_low_to_high: direct_host_leaves(challenge_entries),
        public_key_compressed,
    })
}

/// Sign/magnitude control for one independent low-128 challenge byte.
/// The zero digit (`byte=127`) always has a false sign.
#[allow(dead_code)]
pub(crate) fn h16_independent_challenge_control(byte: u8) -> (bool, usize) {
    let digit = i16::from(byte) - i16::from(H16_INDEPENDENT_CHALLENGE_BYTE_BIAS);
    (digit < 0, usize::from(digit.unsigned_abs()))
}

fn extended_points_equal(lhs: &ExtendedPoint, rhs: &ExtendedPoint, p: &BigUint) -> bool {
    mul_mod(&lhs.x, &rhs.z, p) == mul_mod(&rhs.x, &lhs.z, p)
        && mul_mod(&lhs.y, &rhs.z, p) == mul_mod(&rhs.y, &lhs.z, p)
}

fn centered_scalar_digits(mut scalar: BigUint, widths: &[usize]) -> Vec<i32> {
    let mut digits = Vec::with_capacity(widths.len());
    for width in &widths[..widths.len() - 1] {
        let radix = 1u32 << width;
        let residue = (&scalar & BigUint::from(radix - 1))
            .to_u32()
            .expect("window residue fits u32");
        scalar >>= width;
        if residue >= radix / 2 {
            digits.push(residue as i32 - radix as i32);
            scalar += BigUint::one();
        } else {
            digits.push(residue as i32);
        }
    }
    digits.push(scalar.to_i32().expect("top response digit fits i32"));
    digits
}

fn schedule_position_bases(
    widths: &[usize],
    base: &ExtendedPoint,
    d: &BigUint,
    p: &BigUint,
) -> Vec<ExtendedPoint> {
    let mut position_base = base.clone();
    widths
        .iter()
        .map(|width| {
            let result = position_base.clone();
            for _ in 0..*width {
                position_base = add_extended(&position_base, &position_base, d, p);
            }
            result
        })
        .collect()
}

fn signed_t_translated_multiple(
    digit: i32,
    position_base: &ExtendedPoint,
    t: &ExtendedPoint,
    d: &BigUint,
    p: &BigUint,
) -> ExtendedPoint {
    let magnitude = scalar_mul_extended(BigUint::from(digit.unsigned_abs()), position_base, d, p);
    let translated = add_extended(t, &magnitude, d, p);
    if digit < 0 {
        // This is the exact group action implemented by negating the selected
        // Montgomery v limbs. Since -T=T, it equals T-[m]Q.
        negate_extended(&translated, p)
    } else {
        translated
    }
}

/// Fast host algebra audit for the independent signed-byte schedule.
///
/// It checks the unchanged response recoding at `s=0,1,l-1`, the exact
/// `h=sum(e_i*2^(8i))+K_127` identity and endpoint for uniform boundary bytes
/// `00,7f,80,ff`, and the cancellation of all 44 explicit order-two table
/// translations. It builds no Script tables and uses no witness hints.
#[allow(dead_code)]
pub(crate) fn verify_h16_independent_byte_host_algebra() {
    let p = modulus();
    let d = edwards_d(&p);
    let sqrt_minus_one = BigUint::parse_bytes(
        b"19681161376707505956807079304988542015446066515923890162744021073123829784752",
        10,
    )
    .expect("sqrt(-1) parses");
    let b = basepoint(&p);
    let public_key = scalar_mul_extended(BigUint::from(987_654_321u64), &b, &d, &p);
    let negative_public_key = negate_extended(&public_key, &p);
    let t = torsion_t(&p);
    let u_plus_t = add_extended(&torsion_u(&sqrt_minus_one), &t, &d, &p);
    let response_shift = negate_extended(
        &scalar_mul_extended(h16_independent_challenge_bias_scalar(), &public_key, &d, &p),
        &p,
    );

    let response_widths = [vec![8usize; 8], vec![9usize; 21]].concat();
    let response_bases = schedule_position_bases(&response_widths, &b, &d, &p);
    let mut shifted_response_one = None;
    for scalar in [
        BigUint::zero(),
        BigUint::one(),
        scalar_order() - BigUint::one(),
    ] {
        let digits = centered_scalar_digits(scalar.clone(), &response_widths);
        assert!(digits[..digits.len() - 1]
            .iter()
            .zip(&response_widths[..response_widths.len() - 1])
            .all(|(digit, width)| digit.unsigned_abs() <= 1u32 << (width - 1)));
        let top = digits.len() - 1;
        assert!((0..=256).contains(&digits[top]));

        let top_multiple = scalar_mul_extended(
            BigUint::from(digits[top] as u32),
            &response_bases[top],
            &d,
            &p,
        );
        let mut old_response = add_extended(&u_plus_t, &top_multiple, &d, &p);
        let mut shifted_response = add_extended(
            &add_extended(&u_plus_t, &response_shift, &d, &p),
            &top_multiple,
            &d,
            &p,
        );
        for (digit, position_base) in digits[..top].iter().zip(&response_bases[..top]) {
            let selected = signed_t_translated_multiple(*digit, position_base, &t, &d, &p);
            old_response = add_extended(&old_response, &selected, &d, &p);
            shifted_response = add_extended(&shifted_response, &selected, &d, &p);
        }

        let expected_old = add_extended(
            &u_plus_t,
            &scalar_mul_extended(scalar.clone(), &b, &d, &p),
            &d,
            &p,
        );
        assert!(extended_points_equal(&old_response, &expected_old, &p));
        assert!(extended_points_equal(
            &shifted_response,
            &add_extended(&expected_old, &response_shift, &d, &p),
            &p,
        ));
        if scalar == BigUint::one() {
            shifted_response_one = Some(shifted_response);
        }
    }

    let challenge_widths = vec![8usize; 16];
    let challenge_bases = schedule_position_bases(&challenge_widths, &negative_public_key, &d, &p);
    let shifted_response_one = shifted_response_one.expect("s=1 response was checked");
    let bias = BigInt::from(h16_independent_challenge_bias_scalar());
    for byte in [0x00u8, 0x7f, 0x80, 0xff] {
        let bytes = [byte; 16];
        let h = BigUint::from_bytes_le(&bytes);
        let digits =
            bytes.map(|value| i32::from(value) - i32::from(H16_INDEPENDENT_CHALLENGE_BYTE_BIAS));
        let reconstructed = digits
            .iter()
            .enumerate()
            .fold(BigInt::from(0), |sum, (position, digit)| {
                sum + (BigInt::from(*digit) << (8 * position))
            });
        assert_eq!(reconstructed + &bias, BigInt::from(h.clone()));

        let mut endpoint = shifted_response_one.clone();
        for (digit, position_base) in digits.iter().zip(&challenge_bases) {
            let selected = signed_t_translated_multiple(*digit, position_base, &t, &d, &p);
            endpoint = add_extended(&endpoint, &selected, &d, &p);
        }
        let expected = add_extended(
            &add_extended(&u_plus_t, &b, &d, &p),
            &negate_extended(&scalar_mul_extended(h, &public_key, &d, &p), &p),
            &d,
            &p,
        );
        assert!(extended_points_equal(&endpoint, &expected, &p));
    }

    assert_eq!(h16_independent_challenge_control(0x00), (true, 127));
    assert_eq!(h16_independent_challenge_control(0x7f), (false, 0));
    assert_eq!(h16_independent_challenge_control(0x80), (false, 1));
    assert_eq!(h16_independent_challenge_control(0xff), (false, 128));
}

/// Exact table-only byte probe for the 43-group Montgomery slope-chain
/// proposal. This is intentionally a focused example helper rather than a
/// public library API.
#[allow(dead_code)]
pub(crate) fn report_montgomery_torsion_coset_tables() {
    const RESPONSE_GROUPS: usize = 29;
    const CHALLENGE_GROUPS: usize = 14;
    const PUBLIC_KEY_SCALAR: u64 = 987_654_321;

    let p = modulus();
    let d = edwards_d(&p);
    let sqrt_minus_one = BigUint::parse_bytes(
        b"19681161376707505956807079304988542015446066515923890162744021073123829784752",
        10,
    )
    .expect("sqrt(-1) parses");
    assert_eq!(
        mul_mod(&sqrt_minus_one, &sqrt_minus_one, &p),
        &p - BigUint::one()
    );
    let v_scale = sqrt_mod(&(&p - BigUint::from(486_664u32)), &p, &sqrt_minus_one);

    let mut response_widths = vec![8usize; 8];
    response_widths.extend(std::iter::repeat_n(9usize, 21));
    assert_eq!(response_widths.len(), RESPONSE_GROUPS);
    assert_eq!(response_widths.iter().sum::<usize>(), 253);
    let response_top_max = reachable_top_max(&response_widths, &(scalar_order() - BigUint::one()));
    assert_eq!(response_top_max, 256);

    let mut challenge_widths = vec![10usize; 2];
    challenge_widths.extend(std::iter::repeat_n(9usize, 12));
    assert_eq!(challenge_widths.len(), CHALLENGE_GROUPS);
    assert_eq!(challenge_widths.iter().sum::<usize>(), 128);
    let challenge_top_max = reachable_top_max(
        &challenge_widths,
        &((BigUint::one() << 128usize) - BigUint::one()),
    );
    assert_eq!(challenge_top_max, 512);

    let base = basepoint(&p);
    let public_key = scalar_mul_extended(BigUint::from(PUBLIC_KEY_SCALAR), &base, &d, &p);
    // Positive table magnitudes implement -m*A. The centered-digit sign bit
    // still negates v for a negative digit, yielding +m*A as required.
    let negative_public_key = negate_extended(&public_key, &p);
    let response_tables = montgomery_torsion_coset_entries(
        &response_widths,
        response_top_max,
        &base,
        true,
        &p,
        &d,
        &sqrt_minus_one,
        &v_scale,
    );
    let challenge_tables = montgomery_torsion_coset_entries(
        &challenge_widths,
        challenge_top_max,
        &negative_public_key,
        false,
        &p,
        &d,
        &sqrt_minus_one,
        &v_scale,
    );

    let response_lower_entries = response_tables[..RESPONSE_GROUPS - 1]
        .iter()
        .map(Vec::len)
        .sum::<usize>();
    let response_top_entries = response_tables[RESPONSE_GROUPS - 1].len();
    let challenge_entries = challenge_tables.iter().map(Vec::len).sum::<usize>();
    assert_eq!(response_lower_entries, 6_172);
    assert_eq!(response_top_entries, 257);
    assert_eq!(challenge_entries, 4_366);

    let response_lower_scripts = response_tables[..RESPONSE_GROUPS - 1]
        .iter()
        .zip(&response_widths[..RESPONSE_GROUPS - 1])
        .map(|(entries, width)| bit_decision_tree(entries, *width, TableKind::Top))
        .collect::<Vec<_>>();
    let response_top_script =
        bit_decision_tree(&response_tables[RESPONSE_GROUPS - 1], 9, TableKind::Top);
    let challenge_selector_widths = [vec![10usize; 2], vec![9usize; 11], vec![10usize]].concat();
    let challenge_scripts = challenge_tables
        .iter()
        .zip(&challenge_selector_widths)
        .map(|(entries, width)| bit_decision_tree(entries, *width, TableKind::Top))
        .collect::<Vec<_>>();

    let response_lower_script = script! {
        for table in &response_lower_scripts { { table.clone() } }
    };
    let challenge_script = script! {
        for table in &challenge_scripts { { table.clone() } }
    };
    let response_lower_bytes = repeated_raw_fragment_len(response_lower_script.clone());
    let response_top_bytes = repeated_raw_fragment_len(response_top_script.clone());
    let challenge_bytes = repeated_raw_fragment_len(challenge_script.clone());
    let whole = script! {
        { response_top_script }
        { response_lower_script }
        { challenge_script }
    }
    .compile_with_policy();
    assert!(whole.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(
        whole.len(),
        response_top_bytes + response_lower_bytes + challenge_bytes
    );

    let response_lower_payload = response_tables[..RESPONSE_GROUPS - 1]
        .iter()
        .map(|entries| packed_leaf_payload_bytes(entries))
        .sum::<usize>();
    let response_top_payload = packed_leaf_payload_bytes(&response_tables[RESPONSE_GROUPS - 1]);
    let challenge_payload = challenge_tables
        .iter()
        .map(|entries| packed_leaf_payload_bytes(entries))
        .sum::<usize>();
    let payload_bytes = response_lower_payload + response_top_payload + challenge_payload;
    let control_bytes = whole.len() - payload_bytes;

    println!("model=ed25519_montgomery_torsion_coset_fixed_tables");
    println!("comparison=43_group_slope_chain_table_only");
    println!("evidence=locally-reproduced");
    println!("execution_class=unclassified");
    println!("compilation=policy-produced-unoptimized");
    println!("public_key_fixture=[{PUBLIC_KEY_SCALAR}]B");
    println!("response_groups={RESPONSE_GROUPS}");
    println!("challenge_groups={CHALLENGE_GROUPS}");
    println!("addition_tables={}", RESPONSE_GROUPS - 1 + CHALLENGE_GROUPS);
    println!(
        "zero_addition_leaves={}",
        RESPONSE_GROUPS - 1 + CHALLENGE_GROUPS
    );
    println!("response_initializer_tables=1");
    println!("response_lower_candidate_leaves={response_lower_entries}");
    println!("response_top_candidate_leaves={response_top_entries}");
    println!("challenge_candidate_leaves={challenge_entries}");
    println!(
        "candidate_leaves_total={}",
        response_lower_entries + response_top_entries + challenge_entries
    );
    println!("response_top_max_magnitude={response_top_max}");
    println!("response_top_selector_bits=9");
    println!("challenge_top_max_magnitude={challenge_top_max}");
    println!("challenge_top_source_bits=9");
    println!("challenge_top_selector_bits=10");
    println!(
        "response_lower_control_bytes={}",
        response_lower_bytes - response_lower_payload
    );
    println!("response_lower_payload_bytes={response_lower_payload}");
    println!("response_lower_table_bytes={response_lower_bytes}");
    println!(
        "response_top_control_bytes={}",
        response_top_bytes - response_top_payload
    );
    println!("response_top_payload_bytes={response_top_payload}");
    println!("response_top_table_bytes={response_top_bytes}");
    println!(
        "challenge_control_bytes={}",
        challenge_bytes - challenge_payload
    );
    println!("challenge_payload_bytes={challenge_payload}");
    println!("challenge_table_bytes={challenge_bytes}");
    println!("control_bytes={control_bytes}");
    println!("payload_bytes={payload_bytes}");
    println!("locking_script_bytes={}", whole.len());
    println!("table_selector_input_items_per_invocation=1");
    println!("selected_output_items_per_invocation=16");
    println!("selected_output_shape=packed_u_8_words,packed_v_8_words");
    println!("zero_addition_leaf=packed_T_(0,0)");
    println!("response_top_leaf=packed_P0_equals_U_plus_T_plus_Qtop_equals_minus_U_plus_Qtop");
    println!("lower_sign_action=negate_selected_v_only");
    println!("challenge_table_base=-A");
    println!("hint_items_per_table_invocation=0");
    println!("hint_items_all_43_tables=0");
    println!("hint_coexistence=not_applicable_zero_hints");
    println!("arithmetic_kernel_included=false");
    println!("scalar_recoding_and_sign_routing_included=false");
    println!("combined_stack_peak=unmeasured");
}

/// Exact table-only byte probe for the direct-limb 45-group Montgomery
/// slope-chain proposal. This schedule keeps the 29-group response table and
/// uses sixteen byte-aligned challenge groups, halving the challenge leaf
/// population relative to the earlier 14-group 9/10-bit schedule.
#[allow(dead_code)]
pub(crate) fn report_montgomery_direct_torsion_coset_tables() {
    const RESPONSE_GROUPS: usize = 29;
    const CHALLENGE_GROUPS: usize = 16;
    const PUBLIC_KEY_SCALAR: u64 = 987_654_321;

    let p = modulus();
    let d = edwards_d(&p);
    let sqrt_minus_one = BigUint::parse_bytes(
        b"19681161376707505956807079304988542015446066515923890162744021073123829784752",
        10,
    )
    .expect("sqrt(-1) parses");
    assert_eq!(
        mul_mod(&sqrt_minus_one, &sqrt_minus_one, &p),
        &p - BigUint::one()
    );
    let v_scale = sqrt_mod(&(&p - BigUint::from(486_664u32)), &p, &sqrt_minus_one);

    let mut response_widths = vec![8usize; 8];
    response_widths.extend(std::iter::repeat_n(9usize, 21));
    assert_eq!(response_widths.len(), RESPONSE_GROUPS);
    assert_eq!(response_widths.iter().sum::<usize>(), 253);
    let response_top_max = reachable_top_max(&response_widths, &(scalar_order() - BigUint::one()));
    assert_eq!(response_top_max, 256);

    let challenge_widths = vec![8usize; CHALLENGE_GROUPS];
    assert_eq!(challenge_widths.iter().sum::<usize>(), 128);
    let challenge_top_max = reachable_top_max(
        &challenge_widths,
        &((BigUint::one() << 128usize) - BigUint::one()),
    );
    assert_eq!(challenge_top_max, 256);

    let base = basepoint(&p);
    let public_key = scalar_mul_extended(BigUint::from(PUBLIC_KEY_SCALAR), &base, &d, &p);
    // Positive table magnitudes implement -m*A. A negative centered digit
    // negates only the selected Montgomery v coordinate, yielding +m*A.
    let negative_public_key = negate_extended(&public_key, &p);
    let response_tables = montgomery_direct_torsion_coset_entries(
        &response_widths,
        response_top_max,
        &base,
        true,
        true,
        None,
        &p,
        &d,
        &sqrt_minus_one,
        &v_scale,
    );
    let challenge_tables = montgomery_direct_torsion_coset_entries(
        &challenge_widths,
        challenge_top_max,
        &negative_public_key,
        false,
        false,
        None,
        &p,
        &d,
        &sqrt_minus_one,
        &v_scale,
    );

    let response_lower_entries = response_tables[..RESPONSE_GROUPS - 1]
        .iter()
        .map(Vec::len)
        .sum::<usize>();
    let response_top_entries = response_tables[RESPONSE_GROUPS - 1].len();
    let challenge_lower_entries = challenge_tables[..CHALLENGE_GROUPS - 1]
        .iter()
        .map(Vec::len)
        .sum::<usize>();
    let challenge_top_entries = challenge_tables[CHALLENGE_GROUPS - 1].len();
    assert_eq!(response_lower_entries, 6_172);
    assert_eq!(response_top_entries, 257);
    assert_eq!(challenge_lower_entries, 1_935);
    assert_eq!(challenge_top_entries, 257);

    let response_lower_scripts = response_tables[..RESPONSE_GROUPS - 1]
        .iter()
        .zip(&response_widths[..RESPONSE_GROUPS - 1])
        .map(|(entries, width)| bit_decision_tree(entries, *width, TableKind::Top))
        .collect::<Vec<_>>();
    let response_top_script =
        bit_decision_tree(&response_tables[RESPONSE_GROUPS - 1], 9, TableKind::Top);
    let challenge_lower_scripts = challenge_tables[..CHALLENGE_GROUPS - 1]
        .iter()
        .map(|entries| bit_decision_tree(entries, 8, TableKind::Top))
        .collect::<Vec<_>>();
    let challenge_top_script =
        bit_decision_tree(&challenge_tables[CHALLENGE_GROUPS - 1], 9, TableKind::Top);

    let response_lower_script = script! {
        for table in &response_lower_scripts { { table.clone() } }
    };
    let challenge_lower_script = script! {
        for table in &challenge_lower_scripts { { table.clone() } }
    };
    let response_lower_compiled = response_lower_script.clone().compile_with_policy();
    let challenge_lower_compiled = challenge_lower_script.clone().compile_with_policy();
    assert!(response_lower_compiled.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert!(challenge_lower_compiled.len() > MAX_OPTIMIZER_INPUT_BYTES);
    let response_lower_bytes = response_lower_compiled.len();
    let response_top_bytes = repeated_raw_fragment_len(response_top_script.clone());
    let challenge_lower_bytes = challenge_lower_compiled.len();
    let challenge_top_bytes = repeated_raw_fragment_len(challenge_top_script.clone());
    let whole = script! {
        { response_top_script }
        { response_lower_script }
        { challenge_lower_script }
        { challenge_top_script }
    }
    .compile_with_policy();
    assert!(whole.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(
        whole.len(),
        response_top_bytes + response_lower_bytes + challenge_lower_bytes + challenge_top_bytes
    );

    let response_lower_payload = response_tables[..RESPONSE_GROUPS - 1]
        .iter()
        .map(|entries| packed_leaf_payload_bytes(entries))
        .sum::<usize>();
    let response_top_payload = packed_leaf_payload_bytes(&response_tables[RESPONSE_GROUPS - 1]);
    let challenge_lower_payload = challenge_tables[..CHALLENGE_GROUPS - 1]
        .iter()
        .map(|entries| packed_leaf_payload_bytes(entries))
        .sum::<usize>();
    let challenge_top_payload = packed_leaf_payload_bytes(&challenge_tables[CHALLENGE_GROUPS - 1]);
    let payload_bytes = response_lower_payload
        + response_top_payload
        + challenge_lower_payload
        + challenge_top_payload;
    let control_bytes = whole.len() - payload_bytes;

    // Sample one uniform T leaf and both largest top leaves. The wrapper keeps
    // compilation raw and adds only a test terminal predicate; it is excluded
    // from all byte metrics above.
    let sample_peaks = [
        verify_direct_leaf_strict(&response_tables[0], 8, 0),
        verify_direct_leaf_strict(&response_tables[RESPONSE_GROUPS - 1], 9, 256),
        verify_direct_leaf_strict(&challenge_tables[CHALLENGE_GROUPS - 1], 9, 256),
    ];
    let strict_sample_peak = sample_peaks.into_iter().max().expect("three samples");

    println!("model=ed25519_montgomery_direct_torsion_coset_fixed_tables");
    println!("comparison=45_group_slope_chain_direct_table_only");
    println!("evidence=locally-reproduced");
    println!("execution_class=unclassified");
    println!("compilation=policy-produced-unoptimized");
    println!("optimizer_cutoff_bytes={MAX_OPTIMIZER_INPUT_BYTES}");
    println!("public_key_fixture=[{PUBLIC_KEY_SCALAR}]B");
    println!("response_groups={RESPONSE_GROUPS}");
    println!("response_widths_low_to_high=8x8,9x21");
    println!("challenge_groups={CHALLENGE_GROUPS}");
    println!("challenge_widths_low_to_high=8x16");
    println!("addition_tables={}", RESPONSE_GROUPS - 1 + CHALLENGE_GROUPS);
    println!("response_initializer_tables=1");
    println!(
        "uniform_torsion_zero_addition_leaves={}",
        RESPONSE_GROUPS - 1 + CHALLENGE_GROUPS
    );
    println!("response_lower_candidate_leaves={response_lower_entries}");
    println!("response_top_candidate_leaves={response_top_entries}");
    println!("challenge_lower_candidate_leaves={challenge_lower_entries}");
    println!("challenge_top_candidate_leaves={challenge_top_entries}");
    println!(
        "candidate_leaves_total={}",
        response_lower_entries
            + response_top_entries
            + challenge_lower_entries
            + challenge_top_entries
    );
    println!("response_top_max_magnitude={response_top_max}");
    println!("response_top_source_bits=9");
    println!("response_top_selector_bits=9");
    println!("challenge_lower_max_magnitude=128");
    println!("challenge_lower_selector_bits=8");
    println!("challenge_top_max_magnitude={challenge_top_max}");
    println!("challenge_top_source_bits=8");
    println!("challenge_top_selector_bits=9");
    println!(
        "response_lower_control_bytes={}",
        response_lower_bytes - response_lower_payload
    );
    println!("response_lower_payload_bytes={response_lower_payload}");
    println!("response_lower_table_bytes={response_lower_bytes}");
    println!(
        "response_top_control_bytes={}",
        response_top_bytes - response_top_payload
    );
    println!("response_top_payload_bytes={response_top_payload}");
    println!("response_top_table_bytes={response_top_bytes}");
    println!(
        "challenge_lower_control_bytes={}",
        challenge_lower_bytes - challenge_lower_payload
    );
    println!("challenge_lower_payload_bytes={challenge_lower_payload}");
    println!("challenge_lower_table_bytes={challenge_lower_bytes}");
    println!(
        "challenge_top_control_bytes={}",
        challenge_top_bytes - challenge_top_payload
    );
    println!("challenge_top_payload_bytes={challenge_top_payload}");
    println!("challenge_top_table_bytes={challenge_top_bytes}");
    println!("control_bytes={control_bytes}");
    println!("payload_bytes={payload_bytes}");
    println!("locking_script_bytes={}", whole.len());
    println!("table_selector_input_items_per_invocation=1");
    println!("selected_output_items_per_invocation=25");
    println!("selected_output_shape=direct_u_or_a_16_limbs,direct_v_or_b_9_limbs");
    println!("u_or_a_grouping=4x3,3x13");
    println!("u_or_a_limb_starts=0,4,8,12,15,18,21,24,27,30,33,36,39,42,45,48");
    println!("v_or_b_grouping=4,6x7,5");
    println!("v_or_b_limb_starts=0,4,10,16,22,28,34,40,46");
    println!("zero_addition_leaf=direct_T_(0,0)_uniform_25_items");
    println!("response_top_leaf=direct_P0_equals_U_plus_T_plus_Qtop_equals_minus_U_plus_Qtop");
    println!("lower_sign_action=negate_selected_v_or_b_limbs_only");
    println!("challenge_table_base=-A");
    println!("hint_items_per_table_invocation=0");
    println!("hint_items_all_45_tables=0");
    println!("hint_coexistence=not_applicable_zero_hints");
    println!("strict_executed_leaf_samples=3");
    println!("strict_sample_includes_zero_T_leaf=true");
    println!("strict_sample_execution_context=bitcoin-scriptexec_tapscript_stack_limit_enabled");
    println!("strict_sample_boundary=table_fragment_plus_test_only_truthy_item_not_cleanstack");
    println!("strict_sample_combined_stack_peak_with_test_predicate={strict_sample_peak}");
    println!("locking_script_boundary=all_table_selectors_and_constant_payload_only");
    println!("full_45_table_sequence_executed=false");
    println!("arithmetic_kernel_included=false");
    println!("scalar_recoding_and_sign_routing_included=false");
    println!("full_scalar_combined_stack_peak=unmeasured");
}

fn main() {
    let p = modulus();
    let d = edwards_d(&p);
    println!("model=ed25519_actual_fixed_base_tables");
    println!("compilation=policy-produced-unoptimized");
    println!("scalar_bits={SCALAR_BITS}");
    println!("zero_entry=minimal_branch_marker");
    println!("evidence=locally-reproduced");
    println!("execution_class=unclassified");
    println!();
    let focused_schedule = std::env::args().find_map(|argument| match argument.as_str() {
        "--g29-hybrid-only" => Some(29usize),
        "--g31-hybrid-only" => Some(31usize),
        _ => None,
    });
    if let Some(groups) = focused_schedule {
        let upper = scalar_order() - BigUint::one();
        let (low_width8, lower_width9, name) = match groups {
            29 => (8, 20, "canonical_l_top9_lower20w9_8w8"),
            31 => (26, 4, "canonical_l_g31_lower4w9_26w8_top9"),
            _ => unreachable!("focused schedule is known"),
        };
        let mut widths = vec![8; low_width8];
        widths.extend(std::iter::repeat_n(9, lower_width9));
        widths.push(9);
        let top_max = reachable_top_max(&widths, &upper);
        assert_eq!(top_max, 256);
        report_schedule(name, &widths, top_max, &p, &d);
        return;
    }
    for width in [8, 9, 10] {
        report_uniform_width(width, &p, &d);
    }
    report_mixed_width_8_9(&p, &d);
    report_canonical_mixed_schedules(&p, &d);
}
