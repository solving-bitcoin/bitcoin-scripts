//! Direct high-to-low scalar streaming for Ed25519 fixed-base schedules.
//!
//! This is the stack-composable alternative to expanding a compressed u32
//! into 32 individual bits on altstack.  The already-certified scalar words
//! remain numeric.  Each word is represented by one low remainder plus, only
//! at a word boundary, one partial digit.  At every digit callback altstack is
//! empty, so an affine relation kernel may use it freely.
//!
//! The example measures both the 29-group stack frontier and the 31-group
//! table-size candidate. The scalar validator is intentionally outside this
//! fragment; it must first bind the same eight hostile words to `0 <= s < l`.
//!
//! Run with:
//! `cargo run --locked --release --example ed25519_direct_scalar_splitter`.

use bitcoin_lab::support::{
    execution::execute_raw_script_with_inputs_strict,
    script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
};
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};

const PACKED_WORDS: usize = 8;
const PAYLOAD_BITS: usize = 253;
const TOP_WORD_BITS: usize = PAYLOAD_BITS - 7 * 32;
const STATE_ITEMS: usize = 16;
const EXPANDED_STATE_ITEMS: usize = 102;

#[derive(Clone, Copy)]
struct Layout {
    name: &'static str,
    transitions: usize,
    low_width8_groups: usize,
    lower_width9_groups: usize,
    quotient_hint_items: usize,
    first_selected_constant_items: usize,
    first_kernel_transient_growth: usize,
}

impl Layout {
    fn g29() -> Self {
        Self {
            name: "canonical_l_top9_lower20w9_8w8",
            transitions: 28,
            low_width8_groups: 8,
            lower_width9_groups: 20,
            quotient_hint_items: 61,
            first_selected_constant_items: 29,
            first_kernel_transient_growth: 184,
        }
    }

    fn g31() -> Self {
        Self {
            name: "canonical_l_g31_lower4w9_26w8_top9",
            transitions: 30,
            low_width8_groups: 26,
            lower_width9_groups: 4,
            quotient_hint_items: 61,
            first_selected_constant_items: 29,
            first_kernel_transient_growth: 165,
        }
    }

    fn widths_low_to_high(self) -> Vec<usize> {
        let mut widths = vec![8; self.low_width8_groups];
        widths.extend(std::iter::repeat_n(9, self.lower_width9_groups));
        widths.push(9);
        assert_eq!(widths.len(), self.transitions + 1);
        assert_eq!(widths.iter().sum::<usize>(), PAYLOAD_BITS);
        widths
    }

    fn trace_items(self) -> usize {
        self.transitions * 3 * 8
    }

    fn preserved_below_scalar(self) -> usize {
        self.trace_items() + self.quotient_hint_items
    }

    fn complete_entry_items(self) -> usize {
        self.preserved_below_scalar() + PACKED_WORDS
    }
}

/// Recover the raw fragment size through the central policy. Eight copies of
/// either scalar stream exceed 32 KiB, disabling optimization exactly as it is
/// disabled for the eventual multi-megabyte Tapleaf.
fn raw_fragment_len(fragment: Script) -> usize {
    const COPIES: usize = 8;
    let repeated = script! {
        for _ in 0..COPIES { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % COPIES, 0);
    repeated.len() / COPIES
}

fn raw_small_fragment_len(fragment: Script) -> usize {
    const COPIES: usize = 512;
    let repeated = script! {
        for _ in 0..COPIES { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % COPIES, 0);
    repeated.len() / COPIES
}

/// Raw serialization of a state park/restore pair and its depth-selecting
/// roll. In a >32-KiB leaf these bytes are additive and unoptimized.
fn state_roundtrip_raw_bytes(items: usize) -> usize {
    let depth_push_bytes = match items {
        0 => 1,
        1..=16 => 1,
        17..=127 => 2,
        _ => panic!("model only covers small current-point states"),
    };
    2 * items + depth_push_bytes + 1
}

fn scalar_order() -> BigUint {
    (BigUint::one() << 252usize)
        + BigUint::parse_bytes(b"27742317777372353535851937790883648493", 10)
            .expect("Ed25519 order offset parses")
}

fn centered_digits(value: &BigUint, layout: Layout) -> Vec<i32> {
    assert!(value < &scalar_order());
    let widths = layout.widths_low_to_high();
    let mut remaining = value.clone();
    let mut digits = Vec::with_capacity(widths.len());
    for width in &widths[..widths.len() - 1] {
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
    let top = remaining.to_i32().expect("top digit fits i32");
    assert!((0..=256).contains(&top));
    digits.push(top);
    digits
}

fn packed_words(digits: &[i32], layout: Layout) -> [u32; PACKED_WORDS] {
    let widths = layout.widths_low_to_high();
    assert_eq!(digits.len(), widths.len());
    let mut payload = BigUint::zero();
    let mut offset = 0usize;
    for (index, (digit, width)) in digits.iter().zip(widths).enumerate() {
        let encoded = if index + 1 == digits.len() {
            assert!((0..(1i32 << width)).contains(digit));
            *digit as u32
        } else {
            let biased = *digit + (1i32 << (width - 1));
            assert!((0..(1i32 << width)).contains(&biased));
            biased as u32
        };
        payload |= BigUint::from(encoded) << offset;
        offset += width;
    }
    assert_eq!(offset, PAYLOAD_BITS);
    std::array::from_fn(|index| {
        ((&payload >> (32 * index)) & BigUint::from(u32::MAX))
            .to_u32()
            .expect("masked word fits u32")
    })
}

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn scalar_items(digits: &[i32], layout: Layout) -> Vec<Vec<u8>> {
    packed_words(digits, layout)
        .into_iter()
        .map(|word| scriptnum_item(i64::from(word as i32)))
        .collect()
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

/// Split an at-most-31-bit nonnegative number into `high | low`.
///
/// Only the requested high quotient bits are materialized, never all bits of
/// the source word. Any caller-owned altstack suffix is preserved, and this
/// fragment has no net altstack effect.
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

fn park_state() -> Script {
    script! { for _ in 0..STATE_ITEMS { OP_TOALTSTACK } }
}

/// Input `remainder | digit` with the state parked on altstack. Output is
/// `remainder | state | digit`, with altstack empty at the callback boundary.
fn restore_state_around_digit(has_remainder: bool) -> Script {
    script! {
        for _ in 0..STATE_ITEMS { OP_FROMALTSTACK }
        if has_remainder { { STATE_ITEMS as u32 } OP_ROLL }
        else { { STATE_ITEMS as u32 } OP_ROLL }
    }
}

fn verify_digit(expected: i32, width: usize, top: bool) -> Script {
    script! {
        if !top { { 1u32 << (width - 1) } OP_SUB }
        { expected } OP_NUMEQUALVERIFY
        if top {
            // Stand in for the top-table-selected packed affine x and y.
            for _ in 0..STATE_ITEMS { 0 }
        }
    }
}

/// Convert a certified compressed-u32 ScriptNum to `low31 | sign_bit`.
///
/// A negative compressed word represents `2^31 + low31`. The two safe adds
/// avoid ever presenting positive 2^31 to a four-byte arithmetic opcode.
fn compressed_word_to_low31_and_sign() -> Script {
    script! {
        OP_DUP 0 OP_LESSTHAN
        OP_IF
            { i32::MAX } OP_ADD OP_1ADD 1
        OP_ELSE
            0
        OP_ENDIF
    }
}

/// Append `take` high bits from `word_remainder` to an existing partial digit.
///
/// Input with state parked is `partial | word_remainder`; output is
/// `new_remainder | completed_digit`. The parked state is untouched.
fn finish_partial(total_bits: usize, partial_bits: usize, take: usize) -> Script {
    assert!(partial_bits > 0 && take > 0);
    assert!(take < total_bits);
    script! {
        OP_SWAP
        { split_high(total_bits, take) }
        OP_TOALTSTACK
        OP_SWAP
        for _ in 0..take { OP_DUP OP_ADD }
        OP_ADD
        OP_FROMALTSTACK OP_SWAP
    }
}

/// Stream every digit. The first callback creates a 16-item current-point
/// state; each later callback consumes its digit and preserves that state.
fn direct_stream(expected_high_to_low: &[i32], layout: Layout) -> Script {
    let widths = layout.widths_low_to_high();
    let target_widths = widths.into_iter().rev().collect::<Vec<_>>();
    assert_eq!(expected_high_to_low.len(), target_widths.len());

    let mut steps = Vec::new();
    let mut target = 0usize;

    // Word seven is nonnegative because phase one checked its three padding
    // bits. Extract the top group before a persistent current point exists.
    let first_width = target_widths[target];
    steps.push(script! {
        { split_high(TOP_WORD_BITS, first_width) }
        OP_SWAP
        { verify_digit(expected_high_to_low[target], first_width, true) }
    });
    target += 1;
    let mut remainder_bits = TOP_WORD_BITS - first_width;

    // Finish every complete digit still present in the top word. A single
    // numeric low remainder stays below the persistent point state.
    while remainder_bits >= target_widths[target] {
        let width = target_widths[target];
        steps.push(park_state());
        if remainder_bits == width {
            steps.push(script! {
                { restore_state_around_digit(false) }
                { verify_digit(expected_high_to_low[target], width, false) }
            });
            remainder_bits = 0;
        } else {
            steps.push(script! {
                { split_high(remainder_bits, width) }
                OP_SWAP
                { restore_state_around_digit(true) }
                { verify_digit(expected_high_to_low[target], width, false) }
            });
            remainder_bits -= width;
        }
        target += 1;
    }
    let mut partial_bits = remainder_bits;

    // Every lower physical word contributes its sign bit followed by a
    // nonnegative 31-bit remainder. At a boundary there is at most one
    // partial numeric digit from the prior word.
    for _word in (0..PACKED_WORDS - 1).rev() {
        steps.push(park_state());
        if partial_bits != 0 {
            // Bring the next physical word above the partial item.
            steps.push(script! { 1 OP_ROLL });
        }
        steps.push(compressed_word_to_low31_and_sign());

        if partial_bits == 0 {
            // `sign_bit` itself starts the next digit.
            partial_bits = 1;
        } else {
            // Stack is `partial | low31 | sign`; append the sign bit while
            // leaving low31 available as the current word remainder.
            steps.push(script! {
                OP_TOALTSTACK OP_SWAP
                OP_DUP OP_ADD OP_FROMALTSTACK OP_ADD
            });
            partial_bits += 1;
        }

        let width = target_widths[target];
        let needed = width - partial_bits;
        assert!(needed < 31);
        if needed == 0 {
            // The new word's sign bit itself completed the cross-word digit;
            // low31 is already the retained numeric remainder.
            steps.push(script! {
                { restore_state_around_digit(true) }
                { verify_digit(expected_high_to_low[target], width, false) }
            });
        } else {
            steps.push(script! {
                { finish_partial(31, partial_bits, needed) }
                { restore_state_around_digit(true) }
                { verify_digit(expected_high_to_low[target], width, false) }
            });
        }
        target += 1;
        remainder_bits = 31 - needed;

        while target < target_widths.len() && remainder_bits >= target_widths[target] {
            let width = target_widths[target];
            steps.push(park_state());
            if remainder_bits == width {
                steps.push(script! {
                    { restore_state_around_digit(false) }
                    { verify_digit(expected_high_to_low[target], width, false) }
                });
                remainder_bits = 0;
            } else {
                steps.push(script! {
                    { split_high(remainder_bits, width) }
                    OP_SWAP
                    { restore_state_around_digit(true) }
                    { verify_digit(expected_high_to_low[target], width, false) }
                });
                remainder_bits -= width;
            }
            target += 1;
        }
        partial_bits = remainder_bits;
    }

    assert_eq!(target, target_widths.len());
    assert_eq!(partial_bits, 0);
    script! { for step in steps { { step } } }
}

fn report_layout(layout: Layout) {
    let scalar = scalar_order() - BigUint::one();
    let digits = centered_digits(&scalar, layout);
    let expected_high_to_low = digits.iter().rev().copied().collect::<Vec<_>>();
    let words = packed_words(&digits, layout);

    // Focused prefix check: top, first lower, second lower, then the retained
    // two-bit word remainder. This catches state-routing errors independently
    // of later cross-word handling.
    let prefix = script! {
        { i64::from(words[7] as i32) }
        { split_high(29, 9) } OP_SWAP
        { verify_digit(expected_high_to_low[0], 9, true) }
        { park_state() }
        { split_high(20, 9) } OP_SWAP
        { restore_state_around_digit(true) }
        { verify_digit(expected_high_to_low[1], 9, false) }
        { park_state() }
        { split_high(11, 9) } OP_SWAP
        { restore_state_around_digit(true) }
        { verify_digit(expected_high_to_low[2], 9, false) }
        for _ in 0..STATE_ITEMS { OP_DROP }
        2 OP_NUMEQUALVERIFY OP_1
    }
    .compile_with_policy();
    let prefix_execution = execute_raw_script_with_inputs_strict(prefix.to_bytes(), vec![]);
    assert!(
        prefix_execution.error.is_none(),
        "direct scalar prefix failed: {prefix_execution}"
    );

    let decoder_fragment = direct_stream(&expected_high_to_low, layout);
    let decoder_raw_bytes = raw_fragment_len(decoder_fragment.clone());
    let decoder = decoder_fragment.compile_with_policy();

    let preserved_below_scalar = layout.preserved_below_scalar();
    let complete_entry_items = layout.complete_entry_items();
    let mut witness = vec![Vec::new(); preserved_below_scalar];
    witness.extend(scalar_items(&digits, layout));
    assert_eq!(witness.len(), complete_entry_items);

    let executable = script! {
        { direct_stream(&expected_high_to_low, layout) }
        for _ in 0..STATE_ITEMS { OP_DROP }
        for _ in 0..preserved_below_scalar { OP_DROP }
        OP_1
    }
    .compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(executable.to_bytes(), witness);
    assert!(
        execution.error.is_none(),
        "direct scalar stream failed: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);

    // The first transition retains one numeric remainder for the rest of the
    // top word. It replaces the current compressed word, so this boundary is
    // exactly the complete entry plus the selected current point and constants.
    // Quotients remain physically packed here.
    let first_transition_opaque_q_entry =
        complete_entry_items + STATE_ITEMS + layout.first_selected_constant_items;
    // Decoding two physical quotient words to three logical values adds one
    // item immediately before the relation kernel.
    let first_transition_decoded_q_entry = first_transition_opaque_q_entry + 1;
    let projected_first_transition_peak =
        first_transition_decoded_q_entry + layout.first_kernel_transient_growth;
    let fixed_state_roundtrip_bytes = state_roundtrip_raw_bytes(STATE_ITEMS);
    let expanded_state_roundtrip_bytes = state_roundtrip_raw_bytes(EXPANDED_STATE_ITEMS);
    let dynamic_state_raw_adjustment =
        (layout.transitions - 1) * (expanded_state_roundtrip_bytes - fixed_state_roundtrip_bytes);
    let dynamic_state_model_raw_bytes = decoder_raw_bytes + dynamic_state_raw_adjustment;
    let test_only_callbacks = script! {
        for (index, expected) in expected_high_to_low.iter().copied().enumerate() {
            { expected } OP_NUMEQUALVERIFY
            if index == 0 {
                for _ in 0..STATE_ITEMS { 0 }
            }
        }
    };
    let test_callback_raw_bytes = raw_small_fragment_len(test_only_callbacks);
    let production_scalar_scaffolding_raw_bytes =
        dynamic_state_model_raw_bytes - test_callback_raw_bytes;

    println!("model=ed25519_direct_scalar_splitter");
    println!("schedule={}", layout.name);
    println!("scalar_domain=0..l-1");
    println!("position_groups={}", layout.transitions + 1);
    println!("transitions={}", layout.transitions);
    println!("low_width8_groups={}", layout.low_width8_groups);
    println!("lower_width9_groups={}", layout.lower_width9_groups);
    println!("top_width=9");
    println!("physical_scalar_items={PACKED_WORDS}");
    println!("incremental_hint_items=0");
    println!("trace_items={}", layout.trace_items());
    println!("quotient_hint_items={}", layout.quotient_hint_items);
    println!("complete_trace_and_hint_items={preserved_below_scalar}");
    println!("complete_entry_items={complete_entry_items}");
    println!("decoder_policy_script_bytes={}", decoder.len());
    println!("decoder_raw_script_bytes={decoder_raw_bytes}");
    println!(
        "decoder_whole_leaf_optimizer_delta_bytes={}",
        decoder_raw_bytes - decoder.len()
    );
    println!("fixed16_state_roundtrip_raw_bytes={fixed_state_roundtrip_bytes}");
    println!("expanded102_state_roundtrip_raw_bytes={expanded_state_roundtrip_bytes}");
    println!("expanded_state_callbacks={}", layout.transitions - 1);
    println!("dynamic_state_raw_adjustment_bytes={dynamic_state_raw_adjustment}");
    println!("dynamic_state_test_model_raw_bytes={dynamic_state_model_raw_bytes}");
    println!("test_only_digit_callback_raw_bytes={test_callback_raw_bytes}");
    println!("production_scalar_scaffolding_raw_bytes={production_scalar_scaffolding_raw_bytes}");
    println!("production_scalar_scaffolding_excludes_table_callbacks=true");
    println!(
        "strict_max_combined_stack_items={}",
        execution.stats.max_nb_stack_items
    );
    println!("maximum_numeric_word_remainders=1");
    println!("maximum_cross_word_partial_items=1");
    println!("callback_altstack_items=0");
    println!("first_transition_opaque_q_entry_items={first_transition_opaque_q_entry}");
    println!("first_transition_decoded_q_entry_items={first_transition_decoded_q_entry}");
    println!(
        "first_kernel_transient_growth_items={}",
        layout.first_kernel_transient_growth
    );
    println!("projected_first_transition_combined_peak={projected_first_transition_peak}");
    println!(
        "projected_stack_excess_items={}",
        projected_first_transition_peak.saturating_sub(1_000)
    );
    println!("execution_class=unclassified");
    println!();
}

fn main() {
    assert_eq!(TOP_WORD_BITS, 29);
    report_layout(Layout::g29());
    report_layout(Layout::g31());
}
