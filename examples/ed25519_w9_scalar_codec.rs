//! Two-phase packed centered-window scalar codec for fixed-base Ed25519.
//!
//! Phase one validates eight hostile compressed-u32 words while retaining the
//! exact words. It checks unique ScriptNum encodings, padding, per-window
//! ranges, and the canonical scalar interval `0 <= s < l`, where
//! `l = 2^252 + 27742317777372353535851937790883648493`.
//!
//! Phase two assumes those same words are certified and consumes them one at a
//! time, high word first. Each signed digit is passed immediately to a caller
//! supplied Script fragment before the next complete digit is constructed.
//! Only one cross-word partial digit may remain on the main stack. This avoids
//! permanently expanding the eight scalar items into 29 items on top of the
//! affine trace.
//!
//! Three 29-group layouts are measured: uniform width 9, the earlier mixed
//! top-8 layout, and the canonical-order candidate with eight lower width-8
//! groups, twenty lower width-9 groups, and a top width-9 source group.
//!
//! Run only this lightweight model with:
//! `cargo run --locked --release --example ed25519_w9_scalar_codec`.

use bitcoin::{consensus::encode::serialize, Witness};
use bitcoin_lab::{
    arithmetic::{u31::u31_to_bits_with_width, u32::stack::u32_uncompress},
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation},
    },
};
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};

const LOWER_DIGITS: usize = 28;
const DIGIT_COUNT: usize = LOWER_DIGITS + 1;
const PACKED_WORDS: usize = 8;
const PACKED_CAPACITY_BITS: usize = PACKED_WORDS * 32;
const SOURCE_SCALAR_BITS: usize = 253;
const HINT_ITEMS: usize = 0;
const VALIDATION_LOCAL_STACK_ITEMS: usize = 46;
const STREAM_DROP_LOCAL_STACK_ITEMS: usize = 40;
const FULL_AFFINE_TRACE_ITEMS: usize = 756;

#[derive(Clone, Debug)]
struct Layout {
    name: &'static str,
    /// Widths from the least-significant lower group to the highest lower group.
    lower_widths: Vec<usize>,
    /// Physical encoding width of the unsigned, carry-bearing top digit.
    top_bits: usize,
    /// Structural range checked before the tighter canonical-order comparison.
    top_max: i32,
    /// Number of source scalar bits covered by the top group before carry.
    top_source_width: usize,
}

impl Layout {
    fn uniform_w9() -> Self {
        Self {
            name: "uniform_w9",
            lower_widths: vec![9; LOWER_DIGITS],
            top_bits: 2,
            top_max: 2,
            top_source_width: 1,
        }
    }

    /// Earlier full-253-bit optimum: seven low width-8 groups, then 21 lower
    /// width-9 groups, and a top width-8 source group.
    fn mixed_top8() -> Self {
        let mut lower_widths = vec![8; 7];
        lower_widths.extend([9; 21]);
        Self {
            name: "mixed_top8_lower21w9_7w8",
            lower_widths,
            top_bits: 9,
            top_max: 256,
            top_source_width: 8,
        }
    }

    /// Candidate specialized to `s < l`: eight low width-8 groups, then 20
    /// lower width-9 groups, and a top width-9 source group. Canonical scalars
    /// need top digits only through 257, so nine physical bits suffice.
    fn mixed_top9_order_l() -> Self {
        let mut lower_widths = vec![8; 8];
        lower_widths.extend([9; 20]);
        Self {
            name: "mixed_top9_lower20w9_8w8_order_l",
            lower_widths,
            top_bits: 9,
            top_max: 257,
            top_source_width: 9,
        }
    }

    fn payload_bits(&self) -> usize {
        self.lower_widths.iter().sum::<usize>() + self.top_bits
    }

    fn validate(&self) {
        assert_eq!(self.lower_widths.len(), LOWER_DIGITS);
        assert!(self
            .lower_widths
            .iter()
            .all(|width| *width == 8 || *width == 9));
        assert_eq!(
            self.lower_widths.iter().sum::<usize>() + self.top_source_width,
            SOURCE_SCALAR_BITS
        );
        assert!(self.payload_bits() <= PACKED_CAPACITY_BITS);
        assert!(self.top_max < (1i32 << self.top_bits));
    }
}

type CenteredDigits = Vec<i32>;

fn scalar_capacity() -> BigUint {
    BigUint::from(1u32) << SOURCE_SCALAR_BITS
}

fn scalar_order() -> BigUint {
    (BigUint::from(1u32) << 252usize)
        + BigUint::parse_bytes(b"27742317777372353535851937790883648493", 10)
            .expect("Ed25519 order offset parses")
}

fn centered_digits_unbounded(value: &BigUint, layout: &Layout) -> CenteredDigits {
    layout.validate();
    let mut remaining = value.clone();
    let mut digits = Vec::with_capacity(DIGIT_COUNT);
    for width in layout.lower_widths.iter().copied() {
        let radix = 1u32 << width;
        let bias = radix / 2;
        let residue = (&remaining & BigUint::from(radix - 1))
            .to_u32()
            .expect("window residue fits u32");
        if residue >= bias {
            digits.push(residue as i32 - radix as i32);
            remaining += BigUint::from(radix - residue);
        } else {
            digits.push(residue as i32);
            remaining -= BigUint::from(residue);
        }
        remaining >>= width;
    }
    digits.push(remaining.to_i32().expect("top digit fits i32"));
    digits
}

fn centered_digits_canonical(value: &BigUint, layout: &Layout) -> CenteredDigits {
    assert!(value < &scalar_order(), "scalar must be canonical modulo l");
    let digits = centered_digits_unbounded(value, layout);
    assert!((0..=layout.top_max).contains(&digits[LOWER_DIGITS]));
    digits
}

fn packed_words_from_digits(digits: &[i32], layout: &Layout) -> [u32; PACKED_WORDS] {
    assert_eq!(digits.len(), DIGIT_COUNT);
    let mut payload = BigUint::zero();
    let mut bit_offset = 0usize;
    for (digit, width) in digits[..LOWER_DIGITS]
        .iter()
        .copied()
        .zip(layout.lower_widths.iter().copied())
    {
        let bias = 1i32 << (width - 1);
        let encoded = digit + bias;
        assert!((0..(1i32 << width)).contains(&encoded));
        payload |= BigUint::from(encoded as u32) << bit_offset;
        bit_offset += width;
    }
    assert!((0..(1i32 << layout.top_bits)).contains(&digits[LOWER_DIGITS]));
    payload |= BigUint::from(digits[LOWER_DIGITS] as u32) << bit_offset;
    bit_offset += layout.top_bits;
    assert_eq!(bit_offset, layout.payload_bits());
    assert!((&payload >> layout.payload_bits()).is_zero());

    std::array::from_fn(|index| {
        ((&payload >> (index * 32)) & BigUint::from(u32::MAX))
            .to_u32()
            .expect("masked packed word fits u32")
    })
}

fn packed_words_unbounded(value: &BigUint, layout: &Layout) -> [u32; PACKED_WORDS] {
    let digits = centered_digits_unbounded(value, layout);
    assert!((0..=layout.top_max).contains(&digits[LOWER_DIGITS]));
    packed_words_from_digits(&digits, layout)
}

fn packed_words_canonical(value: &BigUint, layout: &Layout) -> [u32; PACKED_WORDS] {
    packed_words_from_digits(&centered_digits_canonical(value, layout), layout)
}

fn compressed_word_scriptnum(word: u32) -> i64 {
    i64::from(word as i32)
}

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

/// Witness order is word zero through word seven, so word seven is initially
/// on top and can be decoded first without moving the other packed words.
fn witness_items_from_words(words: &[u32; PACKED_WORDS]) -> Vec<Vec<u8>> {
    words
        .iter()
        .map(|word| scriptnum_item(compressed_word_scriptnum(*word)))
        .collect()
}

fn witness_items_canonical(value: &BigUint, layout: &Layout) -> Vec<Vec<u8>> {
    witness_items_from_words(&packed_words_canonical(value, layout))
}

// Reject non-minimal, negative-zero, and redundant-sign encodings even when
// the surrounding interpreter does not enforce MINIMALDATA. The only exact
// five-byte compressed word is the signed representation of 0x80000000.
fn certify_exact_compressed_word() -> Script {
    script! {
        OP_SIZE 5 OP_NUMEQUAL
        OP_IF
            OP_DUP { -2_147_483_648i64 } OP_EQUALVERIFY
        OP_ELSE
            OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
        OP_ENDIF
    }
}

// Consume one already-certified compressed word and park its 32 bits on
// altstack with bit 31 nearest the top.
fn certified_word_to_alt_bits() -> Script {
    script! {
        { u32_uncompress() }
        for _ in 0..4 {
            { u31_to_bits_with_width(8) }
            for _ in 0..8 { OP_TOALTSTACK }
        }
    }
}

fn exact_word_to_alt_bits() -> Script {
    script! {
        { certify_exact_compressed_word() }
        { certified_word_to_alt_bits() }
    }
}

fn append_next_bit(first: bool) -> Script {
    if first {
        script! { OP_FROMALTSTACK }
    } else {
        script! { OP_DUP OP_ADD OP_FROMALTSTACK OP_ADD }
    }
}

/// Update a three-way lexicographic relation.
///
/// Before: `digit | state`; after: `new_state`, with state/new_state in
/// `{-1,0,1}`. Once nonzero, the first unequal digit remains decisive.
fn update_relation(constant: i32) -> Script {
    script! {
        OP_DUP OP_NOT
        OP_IF
            OP_DROP
            { constant } OP_SUB
            OP_DUP 0 OP_LESSTHAN
            OP_IF OP_DROP -1 OP_ELSE OP_0NOTEQUAL OP_ENDIF
        OP_ELSE
            OP_SWAP OP_DROP
        OP_ENDIF
    }
}

/// Consume one digit into lower- and upper-bound comparison states.
///
/// Before: `low_state | high_state | digit`; after:
/// `new_low_state | new_high_state`.
fn consume_digit_for_bounds(low: i32, high: i32) -> Script {
    script! {
        // Compute the new high relation from copies.
        OP_DUP
        2 OP_PICK
        { update_relation(high) }

        // Compute the new low relation from copies.
        1 OP_PICK
        4 OP_PICK
        { update_relation(low) }

        // Discard old digit/high/low, retaining the two new states.
        2 OP_ROLL OP_DROP
        2 OP_ROLL OP_DROP
        2 OP_ROLL OP_DROP
        OP_SWAP
    }
}

fn target_widths_high_to_low(layout: &Layout) -> Vec<usize> {
    let mut widths = Vec::with_capacity(DIGIT_COUNT);
    widths.push(layout.top_bits);
    widths.extend(layout.lower_widths.iter().rev().copied());
    widths
}

/// Validate hostile packed words and retain the exact eight original items.
///
/// Before and after: `preserved | word[0] .. word[7]`, with word seven on top.
/// `upper_inclusive` is encoded into the Script; the Ed25519 boundary uses
/// `l-1`. No auxiliary hints are required.
fn validate_packed_preserving(
    layout: &Layout,
    upper_inclusive: &BigUint,
    preserved_items: usize,
) -> Script {
    layout.validate();
    let low = centered_digits_unbounded(&BigUint::zero(), layout)
        .into_iter()
        .rev()
        .collect::<Vec<_>>();
    let high = centered_digits_unbounded(upper_inclusive, layout)
        .into_iter()
        .rev()
        .collect::<Vec<_>>();
    assert!((0..=layout.top_max).contains(&high[0]));
    let target_widths = target_widths_high_to_low(layout);

    let mut fragments = vec![script! { 0 0 }];
    let mut target_index = 0usize;
    let mut bits_in_digit = 0usize;

    for word_index in (0..PACKED_WORDS).rev() {
        // Originals never move. Pick a copy above the two comparison states
        // and the optional cross-word partial digit.
        let processed_higher_words = PACKED_WORDS - 1 - word_index;
        let depth = processed_higher_words + 2 + usize::from(bits_in_digit != 0);
        fragments.push(script! {
            { depth as u32 } OP_PICK
            { exact_word_to_alt_bits() }
        });

        for global_bit in (word_index * 32..word_index * 32 + 32).rev() {
            if global_bit >= layout.payload_bits() {
                fragments.push(script! { OP_FROMALTSTACK OP_NOT OP_VERIFY });
                continue;
            }

            fragments.push(append_next_bit(bits_in_digit == 0));
            bits_in_digit += 1;
            if bits_in_digit == target_widths[target_index] {
                let finish = if target_index == 0 {
                    script! {
                        OP_DUP 0 { layout.top_max + 1 } OP_WITHIN OP_VERIFY
                    }
                } else {
                    let width = target_widths[target_index];
                    script! { { 1i32 << (width - 1) } OP_SUB }
                };
                fragments.push(script! {
                    { finish }
                    { consume_digit_for_bounds(low[target_index], high[target_index]) }
                });
                target_index += 1;
                bits_in_digit = 0;
            }
        }
    }

    assert_eq!(target_index, DIGIT_COUNT);
    assert_eq!(bits_in_digit, 0);
    fragments.push(script! {
        // high_state <= 0 and low_state >= 0.
        0 OP_LESSTHANOREQUAL OP_VERIFY
        0 OP_GREATERTHANOREQUAL OP_VERIFY
    });

    // The assertion documents composability; the generator's depths are
    // relative to the scalar block and preserve everything below it.
    assert!(preserved_items + VALIDATION_LOCAL_STACK_ITEMS <= 1_000);
    script! {
        for fragment in fragments { { fragment } }
    }
}

/// Consume certified packed words and invoke `consume_digit` high-to-low.
///
/// Before: `preserved | word[0] .. word[7]`; after: `preserved`, provided each
/// callback consumes its one signed digit and restores the caller's unrelated
/// stack shape. This decoder deliberately does not repeat phase-one checks.
fn stream_certified_digits<F>(
    layout: &Layout,
    preserved_items: usize,
    mut consume_digit: F,
) -> Script
where
    F: FnMut(usize) -> Script,
{
    layout.validate();
    // This covers the decoder with a one-item-consuming callback. A real
    // callback must separately account for its own selected-table/kernel peak.
    assert!(preserved_items + STREAM_DROP_LOCAL_STACK_ITEMS <= 1_000);
    let target_widths = target_widths_high_to_low(layout);
    let mut fragments = Vec::new();
    let mut target_index = 0usize;
    let mut bits_in_digit = 0usize;

    for word_index in (0..PACKED_WORDS).rev() {
        let bring_word_above_partial = if bits_in_digit == 0 {
            Script::new("next certified word already on top")
        } else {
            script! { 1 OP_ROLL }
        };
        fragments.push(script! {
            { bring_word_above_partial }
            { certified_word_to_alt_bits() }
        });

        for global_bit in (word_index * 32..word_index * 32 + 32).rev() {
            if global_bit >= layout.payload_bits() {
                // Padding was checked in phase one and is no longer data.
                fragments.push(script! { OP_FROMALTSTACK OP_DROP });
                continue;
            }

            fragments.push(append_next_bit(bits_in_digit == 0));
            bits_in_digit += 1;
            if bits_in_digit == target_widths[target_index] {
                let center = if target_index == 0 {
                    Script::new("top digit is unsigned")
                } else {
                    let width = target_widths[target_index];
                    script! { { 1i32 << (width - 1) } OP_SUB }
                };
                fragments.push(script! {
                    { center }
                    { consume_digit(target_index) }
                });
                target_index += 1;
                bits_in_digit = 0;
            }
        }
    }

    assert_eq!(target_index, DIGIT_COUNT);
    assert_eq!(bits_in_digit, 0);
    script! {
        for fragment in fragments { { fragment } }
    }
}

fn drop_items_and_succeed(items: usize) -> Script {
    script! {
        for _ in 0..items { OP_DROP }
        OP_1
    }
}

fn execute_success(script: Script, witness: Vec<Vec<u8>>, description: &str) -> usize {
    let compiled = script.compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(compiled.to_bytes(), witness);
    assert!(
        execution.error.is_none(),
        "honest execution failed ({description}): {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);
    execution.stats.max_nb_stack_items
}

fn execute_rejection(script: Script, witness: Vec<Vec<u8>>, description: &str) {
    let compiled = script.compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(compiled.to_bytes(), witness);
    assert!(
        execution.error.is_some(),
        "hostile input accepted ({description})"
    );
}

fn report_layout(layout: &Layout) {
    let order = scalar_order();
    let upper = &order - BigUint::from(1u32);
    let validator = validate_packed_preserving(layout, &upper, 0).compile_with_policy();
    let iterator =
        stream_certified_digits(layout, 0, |_| script! { OP_DROP }).compile_with_policy();
    let combined = script! {
        { validate_packed_preserving(layout, &upper, 0) }
        { stream_certified_digits(layout, 0, |_| script! { OP_DROP }) }
    }
    .compile_with_policy();

    let fixtures = [BigUint::zero(), BigUint::from(1u32), upper.clone()];
    let mut validation_peak = 0usize;
    let mut iteration_peak = 0usize;
    let mut combined_peak = 0usize;
    let mut representative_witness_bytes = 0usize;
    for (fixture_index, value) in fixtures.iter().enumerate() {
        let witness = witness_items_canonical(value, layout);
        if fixture_index + 1 == fixtures.len() {
            representative_witness_bytes = serialize(&Witness::from_slice(&witness)).len();
        }
        validation_peak = validation_peak.max(execute_success(
            script! {
                { validate_packed_preserving(layout, &upper, 0) }
                { drop_items_and_succeed(PACKED_WORDS) }
            },
            witness.clone(),
            "canonical preserving validation",
        ));

        let expected = centered_digits_canonical(value, layout)
            .into_iter()
            .rev()
            .collect::<Vec<_>>();
        iteration_peak = iteration_peak.max(execute_success(
            script! {
                { stream_certified_digits(layout, 0, |index| script! {
                    { expected[index] } OP_NUMEQUALVERIFY
                }) }
                OP_1
            },
            witness.clone(),
            "certified high-to-low iteration",
        ));
        combined_peak = combined_peak.max(execute_success(
            script! {
                { validate_packed_preserving(layout, &upper, 0) }
                { stream_certified_digits(layout, 0, |index| script! {
                    { expected[index] } OP_NUMEQUALVERIFY
                }) }
                OP_1
            },
            witness,
            "combined validation and iteration",
        ));
    }

    assert_eq!(validation_peak, VALIDATION_LOCAL_STACK_ITEMS);
    assert_eq!(iteration_peak, STREAM_DROP_LOCAL_STACK_ITEMS);

    // Directly reproduce the phase peaks when the full 84-field/84-quotient
    // packed affine trace remains below the scalar wire.
    let mut full_entry_witness = vec![Vec::new(); FULL_AFFINE_TRACE_ITEMS];
    full_entry_witness.extend(witness_items_canonical(&upper, layout));
    let full_trace_validation_peak = execute_success(
        script! {
            { validate_packed_preserving(layout, &upper, FULL_AFFINE_TRACE_ITEMS) }
            { drop_items_and_succeed(FULL_AFFINE_TRACE_ITEMS + PACKED_WORDS) }
        },
        full_entry_witness.clone(),
        "preserving validation above full affine trace",
    );
    let full_trace_iteration_peak = execute_success(
        script! {
            { stream_certified_digits(layout, FULL_AFFINE_TRACE_ITEMS, |_| script! { OP_DROP }) }
            { drop_items_and_succeed(FULL_AFFINE_TRACE_ITEMS) }
        },
        full_entry_witness.clone(),
        "stream iteration above full affine trace",
    );
    let full_trace_combined_peak = execute_success(
        script! {
            { validate_packed_preserving(layout, &upper, FULL_AFFINE_TRACE_ITEMS) }
            { stream_certified_digits(layout, FULL_AFFINE_TRACE_ITEMS, |_| script! { OP_DROP }) }
            { drop_items_and_succeed(FULL_AFFINE_TRACE_ITEMS) }
        },
        full_entry_witness,
        "two-phase scalar codec above full affine trace",
    );
    assert_eq!(
        full_trace_validation_peak,
        FULL_AFFINE_TRACE_ITEMS + VALIDATION_LOCAL_STACK_ITEMS
    );
    assert_eq!(
        full_trace_iteration_peak,
        FULL_AFFINE_TRACE_ITEMS + STREAM_DROP_LOCAL_STACK_ITEMS
    );

    // l-1 is accepted above. l itself has a structurally legal encoding but
    // must fail the canonical-order comparison.
    let order_words = packed_words_unbounded(&order, layout);
    execute_rejection(
        script! {
            { validate_packed_preserving(layout, &upper, 0) }
            { drop_items_and_succeed(PACKED_WORDS) }
        },
        witness_items_from_words(&order_words),
        "scalar equal to Ed25519 order l",
    );

    // Exercise physical padding and exact raw ScriptNum certification.
    let mut padding_words = packed_words_canonical(&BigUint::zero(), layout);
    padding_words[7] |= 1 << 31;
    execute_rejection(
        script! {
            { validate_packed_preserving(layout, &upper, 0) }
            { drop_items_and_succeed(PACKED_WORDS) }
        },
        witness_items_from_words(&padding_words),
        "nonzero bit-255 padding",
    );
    let mut nonminimal = witness_items_canonical(&BigUint::zero(), layout);
    nonminimal[PACKED_WORDS - 1] = vec![0];
    execute_rejection(
        script! {
            { validate_packed_preserving(layout, &upper, 0) }
            { drop_items_and_succeed(PACKED_WORDS) }
        },
        nonminimal,
        "nonminimal compressed word",
    );

    let canonical_top_max = centered_digits_unbounded(&upper, layout)[LOWER_DIGITS];
    println!("model=ed25519_two_phase_centered_scalar_codec");
    println!("schedule={}", layout.name);
    println!("scalar_domain=0..l-1");
    println!("centered_digits={DIGIT_COUNT}");
    println!(
        "lower_widths_low_to_high={}",
        layout
            .lower_widths
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("top_source_width={}", layout.top_source_width);
    println!("top_structural_range=0..={}", layout.top_max);
    println!("top_canonical_range=0..={canonical_top_max}");
    println!("packed_payload_bits={}", layout.payload_bits());
    println!("physical_input_items={PACKED_WORDS}");
    println!("incremental_hint_items={HINT_ITEMS}");
    println!("validation_preserves_input_words=true");
    println!("validation_script_bytes={}", validator.len());
    println!("validation_strict_peak_items={validation_peak}");
    println!("stream_iteration_script_bytes={}", iterator.len());
    println!("stream_iteration_strict_peak_scalar_items={iteration_peak}");
    println!("stream_iteration_max_persistent_main_items=8");
    println!("combined_script_bytes={}", combined.len());
    println!("combined_strict_peak_items={combined_peak}");
    println!("preserved_full_affine_trace_items={FULL_AFFINE_TRACE_ITEMS}");
    println!("full_trace_validation_peak_items={full_trace_validation_peak}");
    println!("full_trace_iteration_peak_items={full_trace_iteration_peak}");
    println!("full_trace_combined_peak_items={full_trace_combined_peak}");
    println!("representative_complete_witness_bytes={representative_witness_bytes}");
    println!("iteration_order=high_digit_to_low_digit");
    println!("evidence=locally-reproduced");
    println!("execution_class=unclassified");
    println!();
}

fn report_order_check_increment() {
    let layout = Layout::uniform_w9();
    let capacity_upper = scalar_capacity() - BigUint::from(1u32);
    let canonical_upper = scalar_order() - BigUint::from(1u32);
    let capacity = validate_packed_preserving(&layout, &capacity_upper, 0).compile_with_policy();
    let canonical = validate_packed_preserving(&layout, &canonical_upper, 0).compile_with_policy();
    let capacity_peak = execute_success(
        script! {
            { validate_packed_preserving(&layout, &capacity_upper, 0) }
            { drop_items_and_succeed(PACKED_WORDS) }
        },
        witness_items_from_words(&packed_words_unbounded(&capacity_upper, &layout)),
        "full-capacity validation baseline",
    );
    let canonical_peak = execute_success(
        script! {
            { validate_packed_preserving(&layout, &canonical_upper, 0) }
            { drop_items_and_succeed(PACKED_WORDS) }
        },
        witness_items_canonical(&canonical_upper, &layout),
        "canonical-order validation",
    );

    println!("comparison=uniform_w9_order_check_increment");
    println!("capacity_upper_bound=2^253-1");
    println!("canonical_upper_bound=l-1");
    println!("capacity_validation_bytes={}", capacity.len());
    println!("canonical_validation_bytes={}", canonical.len());
    println!(
        "canonical_incremental_bytes={}",
        canonical.len() as isize - capacity.len() as isize
    );
    println!("capacity_validation_peak_items={capacity_peak}");
    println!("canonical_validation_peak_items={canonical_peak}");
    println!(
        "canonical_incremental_peak_items={}",
        canonical_peak as isize - capacity_peak as isize
    );
    println!();
}

fn main() {
    println!("ed25519_order={}", scalar_order());
    println!();
    report_order_check_increment();
    report_layout(&Layout::uniform_w9());
    report_layout(&Layout::mixed_top8());
    report_layout(&Layout::mixed_top9_order_l());
}
