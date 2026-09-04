//! Whole-schedule item and additive-byte model for the Montgomery H16
//! Ed25519-style verification candidate.
//!
//! This is deliberately not an integrated signature-verification Script. It
//! executes the real G29 scalar interval validator and scalar word streamer,
//! the exact compact-transcript unpacker, the exact independent bias-127
//! width-8 challenge recoder,
//! and population-equivalent stubs for the 44 independently measured
//! transition kernels and BLAKE3 interface.
//! The scalar-carrier deep router is an independently executed exact byte
//! slot. Remaining response-carrier routing and component insertion remain
//! explicit byte-budget slots. No large arithmetic kernel or hash compression
//! is executed here.
//!
//! Run with:
//! `cargo run --locked --release --example ed25519_montgomery_h16_schedule_model`.
//! Use `--response-controls-only` for the short semantic scalar-control probe.

#[allow(dead_code)]
#[path = "ed25519_g31_scalar_word_validator.rs"]
mod scalar_validation;

#[allow(dead_code)]
#[path = "ed25519_h16_midpoint_glue.rs"]
mod midpoint_glue;

use bitcoin_lab::support::{
    execution::execute_raw_script_with_inputs_strict,
    script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
};
use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

const STACK_LIMIT: usize = 1_000;
const RESPONSE_GROUPS: usize = 29;
const RESPONSE_TRANSITIONS: usize = 28;
const CHALLENGE_GROUPS: usize = 16;
const CHALLENGE_TRANSITIONS: usize = 16;
const TRANSITIONS: usize = RESPONSE_TRANSITIONS + CHALLENGE_TRANSITIONS;

const TRACE_FIELDS_PER_TRANSITION: usize = 2;
const PACKED_WORDS_PER_FIELD: usize = 8;
const TRACE_ITEMS_PER_TRANSITION: usize = TRACE_FIELDS_PER_TRANSITION * PACKED_WORDS_PER_FIELD;
const Q_HINT_ITEMS_PER_TRANSITION: usize = 2;
const PACKET_ITEMS: usize = TRACE_ITEMS_PER_TRANSITION + Q_HINT_ITEMS_PER_TRANSITION;
const TRACE_DATA_ITEMS: usize = TRANSITIONS * TRACE_ITEMS_PER_TRANSITION;
const QUOTIENT_HINT_ITEMS: usize = TRANSITIONS * Q_HINT_ITEMS_PER_TRANSITION;
const RAW_ENTRY_ITEMS: usize = TRACE_DATA_ITEMS + QUOTIENT_HINT_ITEMS;

const RESPONSE_SCALAR_BITS: usize = 253;
const RESPONSE_SCALAR_WORDS: usize = 8;
const SCALAR_CARRIER_ITEMS: usize = 29;
const SCALAR_CARRIER_CAPACITY_BITS: usize = SCALAR_CARRIER_ITEMS * 9;
const ENTRY_AFTER_SCALAR_REPACK: usize = RAW_ENTRY_ITEMS + RESPONSE_SCALAR_WORDS;
const SCALAR_PREDECODE_TRANSIENT_PEAK: usize = 813;

const TRANSCRIPT_BITS: usize = 512;
const RESPONSE_Q_METADATA_BITS: usize = 505;
const TRANSCRIPT_PADDING_BITS: usize = TRANSCRIPT_BITS - RESPONSE_Q_METADATA_BITS;
const TRANSCRIPT_CHUNKS: usize = RESPONSE_TRANSITIONS;
const TRANSCRIPT_U4_ITEMS: usize = TRANSCRIPT_BITS / 4;
const RETAINED_R_WORDS: usize = 8;

const TOP_STATE_ITEMS: usize = 25;
const CURRENT_STATE_ITEMS: usize = 41;
const SELECTED_POINT_ITEMS: usize = 25;
const FIRST_KERNEL_INPUT_ITEMS: usize = 68;
const CHAINED_KERNEL_INPUT_ITEMS: usize = 84;
const FIRST_KERNEL_LOCAL_PEAK: usize = 216;
const CHAINED_KERNEL_LOCAL_PEAK: usize = 232;
const PAIR_DECODER_TRANSIENT_GROWTH: usize = 8;

const FIXED_MESSAGE_U4_ITEMS: usize = 64;
const BLAKE_INPUT_ITEMS: usize = 64;
const BLAKE_OUTPUT_ITEMS: usize = 32;
const BLAKE_LOCAL_PEAK_UPPER_BOUND: usize = 527;
const CHALLENGE_CONTROL_ITEMS: usize = 2 * CHALLENGE_GROUPS;

// Exact policy-produced unoptimized component measurements. These are
// additive in a whole script above the repository's 32-KiB optimizer cutoff.
const TABLE_BYTES: usize = 826_072;
const FIRST_KERNEL_BYTES: usize = 42_754;
const CHAINED_KERNEL_BYTES: usize = 65_568;
// Policy-only fixed-message compressor at the 337-item legacy H16 frontier.
// The separate 128-byte hostile-message binder below makes the complete
// fixed-M boundary 64,118 bytes.
const BLAKE_BYTES: usize = 63_990;
const FIXED_MESSAGE_BINDING_BYTES: usize = 128;
const FIXED_MESSAGE_BLAKE_BOUNDARY_BYTES: usize = 64_118;
const COMPACT_SIGNED23_DECODER_BYTES: usize = 185;
const SCALAR_CARRIER_ROUTER_BYTES: usize = 25_231;
const CHALLENGE_Q_CARRIERS_OUTSIDE_SCALAR: usize =
    CHALLENGE_TRANSITIONS * Q_HINT_ITEMS_PER_TRANSITION - SCALAR_CARRIER_ITEMS;
const FIRST_PAIR_TWO_PADDING_BYTES: usize = 438;
const REGULAR_PAIR_TWO_PADDING_BYTES: usize = 418;
const REGULAR_PAIR_NO_PADDING_BYTES: usize = 392;
const PADDING_WORD_DECODER_BYTES: usize = 37;

#[derive(Clone, Copy, Debug)]
struct Kernel {
    name: &'static str,
    input: usize,
    local_peak: usize,
    bytes: usize,
}

const FIRST_KERNEL: Kernel = Kernel {
    name: "first_montgomery_slope",
    input: FIRST_KERNEL_INPUT_ITEMS,
    local_peak: FIRST_KERNEL_LOCAL_PEAK,
    bytes: FIRST_KERNEL_BYTES,
};

const CHAINED_KERNEL: Kernel = Kernel {
    name: "chained_montgomery_slope",
    input: CHAINED_KERNEL_INPUT_ITEMS,
    local_peak: CHAINED_KERNEL_LOCAL_PEAK,
    bytes: CHAINED_KERNEL_BYTES,
};

#[derive(Clone, Debug)]
struct TransitionRow {
    transition: usize,
    phase: &'static str,
    scalar_items: usize,
    retained_chunks: usize,
    remaining_challenge_digits: usize,
    future_packets: usize,
    preserved: usize,
    kernel: Kernel,
    kernel_entry: usize,
    carrier_transient_peak: Option<usize>,
    combined_peak: usize,
}

fn response_widths_low_to_high() -> Vec<usize> {
    let mut widths = vec![8usize; 8];
    widths.extend(std::iter::repeat_n(9usize, 21));
    assert_eq!(widths.len(), RESPONSE_GROUPS);
    assert_eq!(widths.iter().sum::<usize>(), RESPONSE_SCALAR_BITS);
    widths
}

/// Physical scalar word/remainder items left after each lower-window callback.
fn scalar_items_after_response_transitions() -> Vec<usize> {
    let mut chunks = vec![29usize];
    chunks.extend(std::iter::repeat_n(32usize, 7));
    let widths_high_to_low = [vec![9usize; 21], vec![8usize; 8]].concat();
    assert_eq!(
        widths_high_to_low.iter().sum::<usize>(),
        RESPONSE_SCALAR_BITS
    );
    let mut chunk = 0usize;
    let mut remainder = chunks[0];
    let mut states = Vec::with_capacity(RESPONSE_GROUPS);
    for width in widths_high_to_low {
        let mut needed = width;
        while needed >= remainder {
            needed -= remainder;
            chunk += 1;
            if needed == 0 {
                remainder = chunks.get(chunk).copied().unwrap_or(0);
                break;
            }
            remainder = chunks[chunk];
        }
        if needed != 0 {
            remainder -= needed;
        }
        states.push(chunks.len() - chunk);
    }
    assert_eq!(states.len(), RESPONSE_GROUPS);
    assert_eq!(states.remove(0), RESPONSE_SCALAR_WORDS);
    assert_eq!(states.len(), RESPONSE_TRANSITIONS);
    assert_eq!(*states.last().expect("response transitions"), 0);
    states
}

fn drop_top_items(items: usize) -> Script {
    script! {
        for _ in 0..items / 2 { OP_2DROP }
        if items % 2 != 0 { OP_DROP }
    }
}

fn policy_precompiled(fragment: Script, name: &'static str) -> Script {
    Script::new(name).push_script(fragment.compile_with_policy())
}

fn grow_then_change(growth: usize, net_change: isize) -> Script {
    let drops = isize::try_from(growth).expect("small growth") - net_change;
    assert!(drops >= 0);
    script! {
        for _ in 0..growth { 0 }
        { drop_top_items(usize::try_from(drops).expect("nonnegative drops")) }
    }
}

/// Move one contiguous block above a suffix while retaining both orders.
fn move_block_to_top(block_items: usize, items_above: usize) -> Script {
    if block_items == 0 || items_above == 0 {
        return Script::new("no-op block move");
    }
    let depth = block_items + items_above - 1;
    script! {
        for _ in 0..block_items { { depth as u32 } OP_ROLL }
    }
}

fn kernel_stub(kernel: Kernel) -> Script {
    assert!(kernel.local_peak >= kernel.input);
    let growth = kernel.local_peak - kernel.input;
    script! {
        for _ in 0..growth { 0 }
        { drop_top_items(growth + kernel.input) }
        for _ in 0..CURRENT_STATE_ITEMS { 0 }
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

fn compressed_word_to_low31_and_sign() -> Script {
    script! {
        OP_DUP 0 OP_LESSTHAN
        OP_IF { i32::MAX } OP_ADD OP_1ADD 1 OP_ELSE 0 OP_ENDIF
    }
}

fn finish_partial(total_bits: usize, partial_bits: usize, take: usize) -> Script {
    assert!(partial_bits > 0 && take > 0 && take < total_bits);
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

/// Convert one biased lower-window code from the canonical `C+s` payload to
/// the fixed-table selector and sign control.
///
/// Before: `code`. After: `magnitude | negative`. The top response window is
/// not biased and must bypass this fragment.
fn decode_lower_code(width: usize) -> Script {
    assert!(width == 8 || width == 9);
    script! {
        { 1u32 << (width - 1) } OP_SUB
        OP_DUP 0 OP_LESSTHAN
        OP_IF OP_NEGATE 1 OP_ELSE 0 OP_ENDIF
    }
}

fn park_current(items: usize) -> Script {
    script! { for _ in 0..items { OP_TOALTSTACK } }
}

/// Stream the certified G29 response scalar high-to-low. The top callback
/// returns 25 current-state items; each lower callback receives that state on
/// altstack and must return the 41-item chained state with altstack empty.
fn response_scalar_stream(top_callback: Script, lower_callbacks: &[Script]) -> Script {
    assert_eq!(lower_callbacks.len(), RESPONSE_TRANSITIONS);
    let target_widths = response_widths_low_to_high()
        .into_iter()
        .rev()
        .collect::<Vec<_>>();
    let mut steps = Vec::new();
    let mut target = 0usize;

    let first_width = target_widths[target];
    steps.push(script! {
        { split_high(29, first_width) }
        OP_SWAP
        { top_callback }
    });
    target += 1;
    let mut remainder_bits = 29 - first_width;

    while remainder_bits >= target_widths[target] {
        let width = target_widths[target];
        let current_items = if target == 1 {
            TOP_STATE_ITEMS
        } else {
            CURRENT_STATE_ITEMS
        };
        steps.push(park_current(current_items));
        if remainder_bits != width {
            steps.push(script! { { split_high(remainder_bits, width) } OP_SWAP });
            remainder_bits -= width;
        } else {
            remainder_bits = 0;
        }
        steps.push(lower_callbacks[target - 1].clone());
        target += 1;
    }
    let mut partial_bits = remainder_bits;

    for _word in (0..RESPONSE_SCALAR_WORDS - 1).rev() {
        steps.push(park_current(CURRENT_STATE_ITEMS));
        if partial_bits != 0 {
            steps.push(script! { 1 OP_ROLL });
        }
        steps.push(compressed_word_to_low31_and_sign());

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
        if needed != 0 {
            steps.push(finish_partial(31, partial_bits, needed));
        }
        steps.push(lower_callbacks[target - 1].clone());
        target += 1;
        remainder_bits = 31 - needed;

        while target < target_widths.len() && remainder_bits >= target_widths[target] {
            let width = target_widths[target];
            steps.push(park_current(CURRENT_STATE_ITEMS));
            if remainder_bits != width {
                steps.push(script! { { split_high(remainder_bits, width) } OP_SWAP });
                remainder_bits -= width;
            } else {
                remainder_bits = 0;
            }
            steps.push(lower_callbacks[target - 1].clone());
            target += 1;
        }
        partial_bits = remainder_bits;
    }

    assert_eq!(target, target_widths.len());
    assert_eq!(partial_bits, 0);
    script! { for step in steps { { step } } }
}

fn response_callback_stub(transition: usize, scalar_items: usize) -> Script {
    let chunks_before = transition;
    let current_items = if transition == 0 {
        TOP_STATE_ITEMS
    } else {
        CURRENT_STATE_ITEMS
    };
    let kernel = if transition == 0 {
        FIRST_KERNEL
    } else {
        CHAINED_KERNEL
    };
    let local_input = PACKET_ITEMS + SELECTED_POINT_ITEMS + current_items;
    assert_eq!(local_input, kernel.input);
    let width = if transition < 20 { 9 } else { 8 };

    script! {
        // Scalar streaming exposes a biased lower-window code. Convert it to
        // the table magnitude and sign, retaining the sign across selection.
        { decode_lower_code(width) }
        OP_TOALTSTACK

        // Population-equivalent table: consume one magnitude and emit the
        // measured table's 25 direct coordinate limbs.
        OP_DROP
        for _ in 0..SELECTED_POINT_ITEMS { 0 }
        OP_FROMALTSTACK
        OP_IF
            for _ in 0..9 { OP_NEGATE OP_TOALTSTACK }
            for _ in 0..9 { OP_FROMALTSTACK }
        OP_ENDIF

        // Packets are ordered for top-down consumption below retained chunks
        // and the live scalar block.
        { move_block_to_top(
            PACKET_ITEMS,
            chunks_before + scalar_items + SELECTED_POINT_ITEMS,
        ) }
        for _ in 0..current_items { OP_FROMALTSTACK }

        // Compact q-pair decoding retains exactly one transcript chunk. Eight
        // transient items conservatively cover padding extraction plus the
        // measured compact decoder peak.
        { grow_then_change(PAIR_DECODER_TRANSIENT_GROWTH, 1) }
        // Rotate scalar+kernel-local data over the new chunk, leaving that
        // chunk in the preserved prefix consumed by the hash midpoint.
        { move_block_to_top(scalar_items + local_input, 1) }
        { kernel_stub(kernel) }
    }
}

fn response_callbacks() -> Vec<Script> {
    scalar_items_after_response_transitions()
        .into_iter()
        .enumerate()
        .map(|(transition, scalar_items)| response_callback_stub(transition, scalar_items))
        .collect()
}

fn top_table_stub() -> Script {
    script! {
        OP_DROP
        for _ in 0..TOP_STATE_ITEMS { 0 }
    }
}

/// Execute the real response-frontier route and compact transcript unpacker.
/// The short component is policy-compiled independently before insertion, so
/// its 546-byte optimizer delta remains available in the >32-KiB whole model.
fn transcript_expansion() -> Script {
    policy_precompiled(
        midpoint_glue::route_and_unpack_h16_midpoint(),
        "policy-precompiled routed H16 transcript unpacker",
    )
}

fn blake_interface_stub() -> Script {
    assert!(BLAKE_LOCAL_PEAK_UPPER_BOUND >= BLAKE_INPUT_ITEMS);
    let growth = BLAKE_LOCAL_PEAK_UPPER_BOUND - BLAKE_INPUT_ITEMS;
    script! {
        for _ in 0..growth { 0 }
        { drop_top_items(growth + BLAKE_INPUT_ITEMS) }
        for _ in 0..BLAKE_OUTPUT_ITEMS { 0 }
    }
}

fn fixed_message_binding_stub() -> Script {
    drop_top_items(FIXED_MESSAGE_U4_ITEMS)
}

fn h16_recode_certified_u4() -> Script {
    policy_precompiled(
        midpoint_glue::recode_h16_blake3_low128_independent_byte127(),
        "policy-precompiled exact H16 challenge recoder",
    )
}

fn challenge_callback_stub(transition: usize) -> Script {
    let remaining_digits = CHALLENGE_TRANSITIONS - transition - 1;
    let remaining_controls = 2 * remaining_digits;
    script! {
        // Current state lies immediately below Rtilde and all sign/selector
        // pairs. The current magnitude is on top of its sign bit.
        { move_block_to_top(
            CURRENT_STATE_ITEMS,
            RETAINED_R_WORDS + remaining_controls + 2,
        ) }
        { park_current(CURRENT_STATE_ITEMS) }

        // Population-equivalent table selection consumes magnitude. Its sign
        // remains immediately below the 25 selected direct limbs.
        OP_DROP
        for _ in 0..SELECTED_POINT_ITEMS { 0 }
        { SELECTED_POINT_ITEMS as u32 } OP_ROLL
        OP_IF
            for _ in 0..9 { OP_NEGATE OP_TOALTSTACK }
            for _ in 0..9 { OP_FROMALTSTACK }
        OP_ENDIF
        { move_block_to_top(
            PACKET_ITEMS,
            RETAINED_R_WORDS + remaining_controls + SELECTED_POINT_ITEMS,
        ) }
        for _ in 0..CURRENT_STATE_ITEMS { OP_FROMALTSTACK }
        { kernel_stub(CHAINED_KERNEL) }
    }
}

fn challenge_schedule_stub() -> Script {
    script! {
        for transition in 0..CHALLENGE_TRANSITIONS {
            { challenge_callback_stub(transition) }
        }
    }
}

fn scalar_words(scalar: &BigUint) -> Vec<i64> {
    let payload = scalar_validation::centered_payload_for_scalar_with_widths(
        scalar,
        &response_widths_low_to_high(),
    );
    scalar_validation::words_from_payload(&payload)
        .into_iter()
        .map(|word| i64::from(word as i32))
        .collect()
}

fn centered_response_digits(scalar: &BigUint) -> Vec<i32> {
    let widths = response_widths_low_to_high();
    let original = scalar.clone();
    let mut remaining = scalar.clone();
    let mut digits = Vec::with_capacity(widths.len());
    let mut position = 0usize;
    for width in &widths[..widths.len() - 1] {
        let radix = 1i32 << width;
        let mask = (BigUint::one() << width) - BigUint::one();
        let residue: i32 = (&remaining & mask)
            .try_into()
            .expect("window residue fits i32");
        remaining >>= width;
        if residue >= radix / 2 {
            digits.push(residue - radix);
            remaining += BigUint::one();
        } else {
            digits.push(residue);
        }
        position += width;
    }
    digits.push(remaining.try_into().expect("top response digit fits i32"));

    let reconstructed = digits
        .iter()
        .zip(&widths)
        .scan(0usize, |shift, (digit, width)| {
            let term = (BigInt::from(*digit), *shift);
            *shift += width;
            Some(term)
        })
        .fold(BigInt::zero(), |sum, (digit, shift)| sum + (digit << shift));
    assert_eq!(reconstructed, BigInt::from(original));
    assert_eq!(position + widths[widths.len() - 1], RESPONSE_SCALAR_BITS);
    digits
}

/// Strictly verify every response table control emitted by the real scalar
/// streamer for one canonical scalar. The compared magnitude is the exact
/// fixed-table leaf index; negative zero is therefore observable here.
fn execute_response_control_fixture(scalar: &BigUint) -> usize {
    let words = scalar_words(scalar);
    let digits = centered_response_digits(scalar);
    let top_digit = *digits.last().expect("29 response digits");
    assert!((0..=256).contains(&top_digit));
    let lower_high_to_low = digits[..digits.len() - 1]
        .iter()
        .rev()
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(lower_high_to_low.len(), RESPONSE_TRANSITIONS);

    let top = script! {
        { top_digit } OP_NUMEQUALVERIFY
        for _ in 0..TOP_STATE_ITEMS { 0 }
    };
    let callbacks = lower_high_to_low
        .into_iter()
        .enumerate()
        .map(|(transition, digit)| {
            let width = if transition < 20 { 9 } else { 8 };
            let current_items = if transition == 0 {
                TOP_STATE_ITEMS
            } else {
                CURRENT_STATE_ITEMS
            };
            let magnitude = digit.unsigned_abs();
            let negative = u32::from(digit < 0);
            assert!(magnitude <= 1u32 << (width - 1));
            script! {
                { decode_lower_code(width) }
                { negative } OP_NUMEQUALVERIFY
                { magnitude } OP_NUMEQUALVERIFY
                for _ in 0..current_items { OP_FROMALTSTACK OP_DROP }
                for _ in 0..CURRENT_STATE_ITEMS { 0 }
            }
        })
        .collect::<Vec<_>>();
    let body = script! {
        { scalar_validation::validate_scalar_words_for_widths_preserving(
            &response_widths_low_to_high(),
            0,
        ) }
        { response_scalar_stream(top, &callbacks) }
        { drop_top_items(CURRENT_STATE_ITEMS) }
        OP_1
    };
    // Keep the focused control probe quick: unreachable padding takes the
    // centralized policy's >32-KiB no-optimizer path without changing the
    // executed scalar/control semantics.
    let executable = script! {
        { body }
        OP_0 OP_IF
            for _ in 0..17_000 { OP_0 OP_DROP }
        OP_ENDIF
    }
    .compile_with_policy();
    assert!(executable.len() > MAX_OPTIMIZER_INPUT_BYTES);
    let witness = words
        .iter()
        .map(|word| scalar_validation::scriptnum_item(*word))
        .collect();
    let execution = execute_raw_script_with_inputs_strict(executable.to_bytes(), witness);
    assert!(
        execution.error.is_none(),
        "response scalar controls for {scalar}: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);
    execution.stats.max_nb_stack_items
}

fn execute_lower_code_bias_boundaries() -> usize {
    let mut peak = 0usize;
    for width in [8usize, 9usize] {
        let bias = 1i64 << (width - 1);
        for (code, magnitude, negative) in [(bias - 1, 1i64, 1i64), (bias, 0, 0), (bias + 1, 1, 0)]
        {
            let executable = script! {
                { decode_lower_code(width) }
                { negative } OP_NUMEQUALVERIFY
                { magnitude } OP_NUMEQUALVERIFY
                OP_1
            }
            .compile_with_policy();
            let execution = execute_raw_script_with_inputs_strict(
                executable.to_bytes(),
                vec![scalar_validation::scriptnum_item(code)],
            );
            assert!(
                execution.error.is_none(),
                "width-{width} lower code {code}: {execution}"
            );
            assert_eq!(execution.final_stack.len(), 1);
            peak = peak.max(execution.stats.max_nb_stack_items);
        }
    }
    peak
}

fn execute_all_response_control_fixtures() -> (usize, usize) {
    let scalar_order = scalar_validation::scalar_order();
    let upper = &scalar_order - BigUint::one();
    let response_control_peak = [BigUint::zero(), BigUint::one(), upper]
        .iter()
        .map(execute_response_control_fixture)
        .max()
        .expect("three response-control fixtures");
    (response_control_peak, execute_lower_code_bias_boundaries())
}

fn scalar_validator() -> Script {
    scalar_validation::validate_scalar_words_for_widths_preserving(
        &response_widths_low_to_high(),
        RAW_ENTRY_ITEMS,
    )
}

fn scalar_predecode_stub(words: &[i64]) -> Script {
    assert_eq!(words.len(), RESPONSE_SCALAR_WORDS);
    assert_eq!(SCALAR_PREDECODE_TRANSIENT_PEAK - RAW_ENTRY_ITEMS, 21);
    script! {
        // Population-equivalent interface to the separately executed full
        // deep router. Its real strict peak is 813 and its output is the 792
        // restored packet items plus eight scalar words.
        for _ in 0..21 { 0 }
        { drop_top_items(21) }
        for word in words { { *word } }
    }
}

fn build_rows() -> Vec<TransitionRow> {
    let scalar_states = scalar_items_after_response_transitions();
    let mut rows = Vec::with_capacity(TRANSITIONS);
    for (transition, scalar_items) in scalar_states.into_iter().enumerate() {
        let future_packets = (TRANSITIONS - transition - 1) * PACKET_ITEMS;
        let retained_chunks = transition + 1;
        let kernel = if transition == 0 {
            FIRST_KERNEL
        } else {
            CHAINED_KERNEL
        };
        let preserved = future_packets + scalar_items + retained_chunks;
        let kernel_entry = preserved + kernel.input;
        let raw_before_chunk = kernel_entry - 1;
        let carrier_transient_peak = raw_before_chunk + PAIR_DECODER_TRANSIENT_GROWTH;
        let combined_peak = preserved + kernel.local_peak;
        assert!(carrier_transient_peak <= STACK_LIMIT);
        assert!(combined_peak <= STACK_LIMIT);
        rows.push(TransitionRow {
            transition,
            phase: "response",
            scalar_items,
            retained_chunks,
            remaining_challenge_digits: 0,
            future_packets,
            preserved,
            kernel,
            kernel_entry,
            carrier_transient_peak: Some(carrier_transient_peak),
            combined_peak,
        });
    }

    for challenge_transition in 0..CHALLENGE_TRANSITIONS {
        let transition = RESPONSE_TRANSITIONS + challenge_transition;
        let future_packets = (CHALLENGE_TRANSITIONS - challenge_transition - 1) * PACKET_ITEMS;
        let remaining_challenge_digits = CHALLENGE_TRANSITIONS - challenge_transition - 1;
        let preserved = future_packets + RETAINED_R_WORDS + 2 * remaining_challenge_digits;
        let kernel = CHAINED_KERNEL;
        let kernel_entry = preserved + kernel.input;
        let combined_peak = preserved + kernel.local_peak;
        assert!(combined_peak <= STACK_LIMIT);
        rows.push(TransitionRow {
            transition,
            phase: "challenge",
            scalar_items: 0,
            retained_chunks: 0,
            remaining_challenge_digits,
            future_packets,
            preserved,
            kernel,
            kernel_entry,
            carrier_transient_peak: None,
            combined_peak,
        });
    }
    assert_eq!(rows.len(), TRANSITIONS);
    rows
}

fn raw_fragment_len(fragment: Script) -> usize {
    const COPIES: usize = 256;
    let repeated = script! {
        for _ in 0..COPIES { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % COPIES, 0);
    repeated.len() / COPIES
}

fn raw_small_fragment_len(fragment: Script) -> usize {
    const COPIES: usize = 2_048;
    let repeated = script! {
        for _ in 0..COPIES { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % COPIES, 0);
    repeated.len() / COPIES
}

fn execute_validator_fixture(words: &[i64]) -> usize {
    let witness = [
        vec![Vec::<u8>::new(); RAW_ENTRY_ITEMS],
        words
            .iter()
            .map(|word| scalar_validation::scriptnum_item(*word))
            .collect(),
    ]
    .concat();
    let compiled = scalar_validator().compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(compiled.to_bytes(), witness);
    assert!(
        execution.error.is_none(),
        "G29 scalar validator: {execution}"
    );
    assert_eq!(execution.final_stack.len(), ENTRY_AFTER_SCALAR_REPACK);
    execution.stats.max_nb_stack_items
}

fn independent_h16_controls(bytes: &[u8; 16]) -> [(i32, i32); 16] {
    bytes.map(|byte| {
        let digit = i32::from(byte) - 127;
        ((digit < 0) as i32, digit.unsigned_abs() as i32)
    })
}

fn h16_witness(bytes: &[u8; 16], preserved: usize) -> Vec<Vec<u8>> {
    let mut result = vec![Vec::new(); preserved];
    for byte in bytes.iter().copied() {
        result.push(scalar_validation::scriptnum_item(i64::from(byte >> 4)));
        result.push(scalar_validation::scriptnum_item(i64::from(byte & 15)));
    }
    result
}

fn execute_h16_fixture(bytes: &[u8; 16], preserved: usize) -> usize {
    let controls = independent_h16_controls(bytes);
    let executable = script! {
        { h16_recode_certified_u4() }
        for (negative, magnitude) in controls.iter().rev() {
            { *magnitude } OP_NUMEQUALVERIFY
            { *negative } OP_NUMEQUALVERIFY
        }
        { drop_top_items(preserved) }
        OP_1
    }
    .compile_with_policy();
    let execution =
        execute_raw_script_with_inputs_strict(executable.to_bytes(), h16_witness(bytes, preserved));
    assert!(execution.error.is_none(), "H16 recoder: {execution}");
    assert_eq!(execution.final_stack.len(), 1);
    execution.stats.max_nb_stack_items
}

fn execute_endpoint_fixture() -> usize {
    let r_words = (0..RETAINED_R_WORDS)
        .map(|index| 10_000i64 + index as i64)
        .collect::<Vec<_>>();
    let mut witness = r_words
        .iter()
        .copied()
        .map(scalar_validation::scriptnum_item)
        .collect::<Vec<_>>();
    witness.extend(
        r_words
            .iter()
            .copied()
            .map(scalar_validation::scriptnum_item),
    );
    witness.extend(
        (0..CURRENT_STATE_ITEMS - RETAINED_R_WORDS)
            .map(|index| scalar_validation::scriptnum_item(20_000 + index as i64)),
    );
    assert_eq!(witness.len(), RETAINED_R_WORDS + CURRENT_STATE_ITEMS);
    let compiled = endpoint_comparison().compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(compiled.to_bytes(), witness.clone());
    assert!(execution.error.is_none(), "endpoint equality: {execution}");
    assert_eq!(execution.final_stack.len(), 1);

    witness[RETAINED_R_WORDS + 3] = scalar_validation::scriptnum_item(-1);
    let rejected = execute_raw_script_with_inputs_strict(compiled.to_bytes(), witness);
    assert!(rejected.error.is_some(), "unequal endpoint was accepted");
    execution.stats.max_nb_stack_items
}

fn execute_schedule_stub(words: &[i64]) -> usize {
    let callbacks = response_callbacks();
    let body = script! {
        { scalar_predecode_stub(words) }
        { scalar_validator() }
        { response_scalar_stream(top_table_stub(), &callbacks) }
        { transcript_expansion() }
        { fixed_message_binding_stub() }
        { blake_interface_stub() }
        { h16_recode_certified_u4() }
        { challenge_schedule_stub() }
        { endpoint_comparison() }
    };
    // Keep this item-schedule execution quick. The unreachable branch moves
    // the probe above the repository cutoff, so the centralized policy takes
    // its no-optimizer path just as the eventual multi-megabyte leaf does.
    let executable = script! {
        { body }
        OP_0 OP_IF
            for _ in 0..17_000 { OP_0 OP_DROP }
        OP_ENDIF
    }
    .compile_with_policy();
    assert!(executable.len() > MAX_OPTIMIZER_INPUT_BYTES);
    let execution = execute_raw_script_with_inputs_strict(
        executable.to_bytes(),
        vec![Vec::new(); RAW_ENTRY_ITEMS],
    );
    assert!(execution.error.is_none(), "H16 schedule stub: {execution}");
    assert_eq!(execution.final_stack.len(), 1);
    execution.stats.max_nb_stack_items
}

fn response_scalar_stream_scaffolding() -> Script {
    let callbacks = vec![Script::new("unpriced callback insertion"); RESPONSE_TRANSITIONS];
    response_scalar_stream(Script::new("unpriced top-table insertion"), &callbacks)
}

// Input is one biased lower-window code. The negative marker is parked across
// a virtual fixed-table insertion; the postlude negates exactly the nine
// direct b/v limbs when required. These two fragments are byte-attribution
// boundaries and are not executable without the measured table between them.
fn biased_table_pre_routing(width: usize) -> Script {
    script! {
        { decode_lower_code(width) }
        OP_TOALTSTACK
    }
}

fn signed_table_post_routing() -> Script {
    script! {
        OP_FROMALTSTACK
        OP_IF
            for _ in 0..9 { OP_NEGATE OP_TOALTSTACK }
            for _ in 0..9 { OP_FROMALTSTACK }
        OP_ENDIF
    }
}

/// Raw glue around the response table, compact q-pair decoder, and transition
/// kernel insertion points. Scalar extraction's current-state parking is
/// already counted by [`response_scalar_stream_scaffolding`].
fn response_component_routing_scaffolding() -> Script {
    let scalar_states = scalar_items_after_response_transitions();
    let steps = scalar_states
        .into_iter()
        .enumerate()
        .map(|(transition, scalar_items)| {
            let current_items = if transition == 0 {
                TOP_STATE_ITEMS
            } else {
                CURRENT_STATE_ITEMS
            };
            let width = if transition < 20 { 9 } else { 8 };
            script! {
            { biased_table_pre_routing(width) }
            // Virtual table insertion: magnitude -> selected[25].
            { signed_table_post_routing() }
            { move_block_to_top(
                PACKET_ITEMS,
                transition + scalar_items + SELECTED_POINT_ITEMS,
            ) }
            for _ in 0..current_items { OP_FROMALTSTACK }
            // Virtual compact pair decoder insertion: q carriers (+ optional
            // padding bits) -> q_curve | q_continuity | chunk.
            { move_block_to_top(
                scalar_items + PACKET_ITEMS + SELECTED_POINT_ITEMS + current_items,
                1,
            ) }
            // Virtual transition-kernel insertion.
            }
        })
        .collect::<Vec<_>>();
    script! { for step in steps { { step } } }
}

/// Raw current/digit/table/packet routing around the sixteen challenge
/// transition insertion points. Challenge q values are assumed restored in
/// their packet slots by the scalar router or a remaining isolated decoder.
fn challenge_component_routing_scaffolding() -> Script {
    let steps = (0..CHALLENGE_TRANSITIONS)
        .map(|transition| {
            let remaining_digits = CHALLENGE_TRANSITIONS - transition - 1;
            let remaining_controls = 2 * remaining_digits;
            script! {
            { move_block_to_top(
                CURRENT_STATE_ITEMS,
                RETAINED_R_WORDS + remaining_controls + 2,
            ) }
            { park_current(CURRENT_STATE_ITEMS) }
            // Virtual table consumes magnitude, leaving its explicit sign
            // below the 25 selected limbs.
            { SELECTED_POINT_ITEMS as u32 } OP_ROLL
            OP_IF
                for _ in 0..9 { OP_NEGATE OP_TOALTSTACK }
                for _ in 0..9 { OP_FROMALTSTACK }
            OP_ENDIF
            { move_block_to_top(
                PACKET_ITEMS,
                RETAINED_R_WORDS + remaining_controls + SELECTED_POINT_ITEMS,
            ) }
            for _ in 0..CURRENT_STATE_ITEMS { OP_FROMALTSTACK }
            // Virtual chained-kernel insertion.
            }
        })
        .collect::<Vec<_>>();
    script! { for step in steps { { step } } }
}

/// Consume the final direct state and compare its packed u coordinate with the
/// retained native eight-word Rtilde representation. This is a complete
/// clean-stack predicate for the modeled endpoint layout `R[8] | state[41]`.
fn endpoint_comparison() -> Script {
    const NON_U_STATE_ITEMS: usize = CURRENT_STATE_ITEMS - RETAINED_R_WORDS;
    script! {
        { drop_top_items(NON_U_STATE_ITEMS) }
        for depth in (1..=RETAINED_R_WORDS).rev() {
            { depth as u32 } OP_ROLL OP_EQUALVERIFY
        }
        OP_1
    }
}

fn main() {
    assert_eq!(
        BLAKE_BYTES + FIXED_MESSAGE_BINDING_BYTES,
        FIXED_MESSAGE_BLAKE_BOUNDARY_BYTES
    );
    assert_eq!(TRANSITIONS, 44);
    assert_eq!(TRACE_DATA_ITEMS, 704);
    assert_eq!(QUOTIENT_HINT_ITEMS, 88);
    assert_eq!(RAW_ENTRY_ITEMS, 792);
    assert_eq!(SCALAR_CARRIER_CAPACITY_BITS, 261);
    assert_eq!(ENTRY_AFTER_SCALAR_REPACK, 800);
    assert_eq!(RESPONSE_Q_METADATA_BITS, 505);
    assert_eq!(TRANSCRIPT_PADDING_BITS, 7);
    assert_eq!(TRANSCRIPT_U4_ITEMS, 128);

    match std::env::args().nth(1).as_deref() {
        Some("--response-controls-only") => {
            let (response_control_peak, lower_code_bias_peak) =
                execute_all_response_control_fixtures();
            println!("model=ed25519_montgomery_h16_response_controls");
            println!("evidence=locally-reproduced");
            println!("execution_class=unclassified");
            println!("context=tapscript,strict_1000_item_stack,bitcoin-scriptexec");
            println!("response_control_strict_fixtures=scalar_0,scalar_1,scalar_l_minus_1");
            println!("response_control_table_indices_and_signs_verified=true");
            println!("response_control_strict_peak={response_control_peak}");
            println!("lower_code_bias_boundaries_checked_per_width=3");
            println!("lower_code_bias_boundary_widths=8,9");
            println!("lower_code_bias_boundary_strict_peak={lower_code_bias_peak}");
            println!("long_schedule_arithmetic_hash_or_table_execution=false");
            return;
        }
        Some("--stack-only") => {
            let scalar = scalar_validation::scalar_order() - BigUint::one();
            let words = scalar_words(&scalar);
            let strict_schedule_peak = execute_schedule_stub(&words);
            println!("model=ed25519_montgomery_h16_stack_only");
            println!("evidence=locally-reproduced");
            println!("evidence_boundary=item-schedule");
            println!("execution_class=unclassified");
            println!("response_lower_codes_centered_before_table_selection=true");
            println!("strict_stubbed_whole_schedule_peak={strict_schedule_peak}");
            println!(
                "whole_schedule_peak_below_1000={}",
                strict_schedule_peak <= STACK_LIMIT
            );
            println!("long_arithmetic_hash_or_table_execution=false");
            return;
        }
        Some("--response-routing-bytes-only") => {
            let scalar_stream = raw_fragment_len(response_scalar_stream_scaffolding());
            let component_routing = raw_fragment_len(response_component_routing_scaffolding());
            println!("model=ed25519_montgomery_h16_response_routing_bytes");
            println!("evidence=locally-reproduced");
            println!("evidence_boundary=generation");
            println!("execution_class=unclassified");
            println!("response_lower_codes_centered_before_table_selection=true");
            println!("response_scalar_stream_scaffolding_raw_bytes={scalar_stream}");
            println!("response_component_routing_scaffolding_raw_bytes={component_routing}");
            println!("long_arithmetic_hash_or_table_execution=false");
            return;
        }
        None => {}
        Some(argument) => panic!(
            "unknown mode {argument}; use --response-controls-only, --stack-only, or --response-routing-bytes-only"
        ),
    }

    let rows = build_rows();
    assert_eq!(rows[0].preserved, 783);
    assert_eq!(rows[0].kernel_entry, 851);
    assert_eq!(rows[0].combined_peak, 999);
    assert_eq!(rows[1].preserved, 766);
    assert_eq!(rows[1].kernel_entry, 850);
    assert_eq!(rows[1].combined_peak, 998);

    let scalar_order = scalar_validation::scalar_order();
    let scalar = &scalar_order - BigUint::from(1u8);
    let words = scalar_words(&scalar);
    let (response_control_peak, lower_code_bias_peak) = execute_all_response_control_fixtures();
    let scalar_validator_peak = execute_validator_fixture(&words);
    let h16_zero_peak = execute_h16_fixture(&[0u8; 16], 337);
    let h16_ff_peak = execute_h16_fixture(&[0xffu8; 16], 337);
    let h16_peak = h16_zero_peak.max(h16_ff_peak);
    let endpoint_peak = execute_endpoint_fixture();
    let strict_schedule_peak = execute_schedule_stub(&words);
    assert_eq!(strict_schedule_peak, 999);

    let scalar_validator_raw_bytes = raw_fragment_len(scalar_validator());
    let response_scalar_stream_raw_bytes = raw_fragment_len(response_scalar_stream_scaffolding());
    let response_component_routing_raw_bytes =
        raw_fragment_len(response_component_routing_scaffolding());
    let challenge_component_routing_raw_bytes =
        raw_fragment_len(challenge_component_routing_scaffolding());
    let transcript_unpack_raw_bytes =
        raw_fragment_len(midpoint_glue::route_and_unpack_h16_midpoint());
    let transcript_unpack_policy_bytes = midpoint_glue::route_and_unpack_h16_midpoint()
        .compile_with_policy()
        .len();
    let h16_recode_raw_bytes =
        raw_fragment_len(midpoint_glue::recode_h16_blake3_low128_independent_byte127());
    let h16_recode_policy_bytes = midpoint_glue::recode_h16_blake3_low128_independent_byte127()
        .compile_with_policy()
        .len();
    let endpoint_comparison_raw_bytes = raw_small_fragment_len(endpoint_comparison());
    let all_kernel_bytes = FIRST_KERNEL.bytes + (TRANSITIONS - 1) * CHAINED_KERNEL.bytes;
    let response_pair_decoder_bytes = FIRST_PAIR_TWO_PADDING_BYTES
        + 3 * REGULAR_PAIR_TWO_PADDING_BYTES
        + 24 * REGULAR_PAIR_NO_PADDING_BYTES;
    let remaining_challenge_carrier_decoder_bytes =
        CHALLENGE_Q_CARRIERS_OUTSIDE_SCALAR * COMPACT_SIGNED23_DECODER_BYTES;
    let padding_word_decoder_bytes = 8 * PADDING_WORD_DECODER_BYTES;
    let priced_subtotal = TABLE_BYTES
        + all_kernel_bytes
        + BLAKE_BYTES
        + FIXED_MESSAGE_BINDING_BYTES
        + scalar_validator_raw_bytes
        + response_scalar_stream_raw_bytes
        + response_component_routing_raw_bytes
        + challenge_component_routing_raw_bytes
        + transcript_unpack_policy_bytes
        + h16_recode_policy_bytes
        + endpoint_comparison_raw_bytes
        + response_pair_decoder_bytes
        + SCALAR_CARRIER_ROUTER_BYTES
        + remaining_challenge_carrier_decoder_bytes
        + padding_word_decoder_bytes;
    let remaining_unpriced_budget = 4_000_000usize.saturating_sub(priced_subtotal);

    println!("model=ed25519_montgomery_h16_whole_schedule");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=item-schedule");
    println!("execution_class=unclassified");
    println!("candidate_protocol=custom_BLAKE3_128_Ed25519_style_not_RFC8032");
    println!("complete_integrated_script=false");
    println!("arithmetic_and_hash_execution=measured_interface_stubs");
    println!("response_scalar_validator_and_stream=real");
    println!("challenge_h16_recoder=real");
    println!("response_groups={RESPONSE_GROUPS}");
    println!("challenge_groups={CHALLENGE_GROUPS}");
    println!("transitions={TRANSITIONS}");
    println!("trace_data_items_per_transition={TRACE_ITEMS_PER_TRANSITION}");
    println!("trace_data_items_total={TRACE_DATA_ITEMS}");
    println!("quotient_hint_items_per_transition={Q_HINT_ITEMS_PER_TRANSITION}");
    println!("quotient_hint_items_total={QUOTIENT_HINT_ITEMS}");
    println!("all_trace_and_quotient_hint_items_coexist_at_entry=true");
    println!("raw_entry_items_without_separate_scalar={RAW_ENTRY_ITEMS}");
    println!("scalar_bits_embedded_in_final_challenge_q_carriers=253");
    println!("scalar_carrier_items={SCALAR_CARRIER_ITEMS}");
    println!("scalar_carrier_capacity_bits={SCALAR_CARRIER_CAPACITY_BITS}");
    println!(
        "scalar_carrier_spare_bits={}",
        SCALAR_CARRIER_CAPACITY_BITS - 253
    );
    println!("scalar_repacked_word_items={RESPONSE_SCALAR_WORDS}");
    println!("entry_items_after_scalar_repack={ENTRY_AFTER_SCALAR_REPACK}");
    println!("scalar_predecode_transient_upper_bound={SCALAR_PREDECODE_TRANSIENT_PEAK}");
    println!("scalar_predecode_routing_separately_implemented=true");
    println!("scalar_predecode_integrated_in_this_scheduler=false");
    println!("scalar_validator_strict_combined_peak={scalar_validator_peak}");
    println!("response_control_strict_fixtures=scalar_0,scalar_1,scalar_l_minus_1");
    println!("response_control_table_indices_and_signs_verified=true");
    println!("response_control_strict_peak={response_control_peak}");
    println!("lower_code_bias_boundaries_checked_per_width=3");
    println!("lower_code_bias_boundary_widths=8,9");
    println!("lower_code_bias_boundary_strict_peak={lower_code_bias_peak}");
    println!("response_q_metadata_bits_first_28_pairs={RESPONSE_Q_METADATA_BITS}");
    println!("packed_trace_padding_bits_used={TRANSCRIPT_PADDING_BITS}");
    println!("packed_trace_padding_bits_decoded=8");
    println!("discarded_authenticated_padding_bits=1");
    println!("transcript_bits={TRANSCRIPT_BITS}");
    println!("transcript_chunks={TRANSCRIPT_CHUNKS}");
    println!("transcript_chunk_widths=21,20,20,20,18x24");
    println!("transcript_unpack_hint_items=0");
    println!("transcript_chunk_items_at_response_midpoint={TRANSCRIPT_CHUNKS}");
    println!(
        "response_midpoint_future_packet_items={}",
        CHALLENGE_TRANSITIONS * PACKET_ITEMS
    );
    println!("response_midpoint_current_state_items={CURRENT_STATE_ITEMS}");
    println!(
        "response_midpoint_live_items={}",
        CHALLENGE_TRANSITIONS * PACKET_ITEMS + TRANSCRIPT_CHUNKS + CURRENT_STATE_ITEMS
    );
    println!("hash_retained_r_packed_words={RETAINED_R_WORDS}");
    println!("hash_certified_transcript_u4_items={TRANSCRIPT_U4_ITEMS}");
    println!(
        "pre_message_binding_frontier_items={}",
        CHALLENGE_TRANSITIONS * PACKET_ITEMS
            + CURRENT_STATE_ITEMS
            + RETAINED_R_WORDS
            + TRANSCRIPT_U4_ITEMS
    );
    println!("fixed_message_binding_consumed_u4_items={FIXED_MESSAGE_U4_ITEMS}");
    println!(
        "hash_input_frontier_items={}",
        CHALLENGE_TRANSITIONS * PACKET_ITEMS
            + CURRENT_STATE_ITEMS
            + RETAINED_R_WORDS
            + BLAKE_INPUT_ITEMS
    );
    println!(
        "hash_preserved_prefix_items={}",
        CHALLENGE_TRANSITIONS * PACKET_ITEMS + CURRENT_STATE_ITEMS + RETAINED_R_WORDS
    );
    println!("blake_local_peak_upper_bound={BLAKE_LOCAL_PEAK_UPPER_BOUND}");
    println!(
        "blake_combined_peak_upper_bound={}",
        CHALLENGE_TRANSITIONS * PACKET_ITEMS
            + CURRENT_STATE_ITEMS
            + RETAINED_R_WORDS
            + BLAKE_LOCAL_PEAK_UPPER_BOUND
    );
    println!(
        "post_hash_frontier_items={}",
        CHALLENGE_TRANSITIONS * PACKET_ITEMS
            + CURRENT_STATE_ITEMS
            + RETAINED_R_WORDS
            + BLAKE_OUTPUT_ITEMS
    );
    println!("h16_recode_output_control_items={CHALLENGE_CONTROL_ITEMS}");
    println!("h16_recode_control_shape=16_pairs_of_negative_then_magnitude");
    println!("h16_recode_schedule=independent_signed_bytes_bias127");
    println!("h16_recode_digit_interval=-127..128");
    println!("h16_response_initializer_shift=-K_127_times_A");
    println!("h16_recode_hint_items=0");
    println!("h16_recode_strict_combined_peak={h16_peak}");
    println!("endpoint_comparison_strict_peak={endpoint_peak}");
    println!("endpoint_mismatch_rejected=true");
    println!(
        "post_h16_recode_frontier_items={}",
        CHALLENGE_TRANSITIONS * PACKET_ITEMS
            + CURRENT_STATE_ITEMS
            + RETAINED_R_WORDS
            + CHALLENGE_CONTROL_ITEMS
    );
    println!("strict_stubbed_whole_schedule_peak={strict_schedule_peak}");
    println!(
        "whole_schedule_peak_below_1000={}",
        strict_schedule_peak <= STACK_LIMIT
    );
    for row in &rows {
        println!(
            "transition={:02},phase={},future_packets={},scalar_items={},retained_chunks={},remaining_h_digits={},kernel={},kernel_input={},kernel_entry={},preserved={},local_peak={},carrier_transient_peak={},combined_peak={},fits={}",
            row.transition,
            row.phase,
            row.future_packets,
            row.scalar_items,
            row.retained_chunks,
            row.remaining_challenge_digits,
            row.kernel.name,
            row.kernel.input,
            row.kernel_entry,
            row.preserved,
            row.kernel.local_peak,
            row.carrier_transient_peak.map(|peak| peak.to_string()).unwrap_or_else(|| "predecoded".to_owned()),
            row.combined_peak,
            row.combined_peak <= STACK_LIMIT,
        );
    }

    println!("table_raw_bytes={TABLE_BYTES}");
    println!("first_transition_raw_bytes={FIRST_KERNEL_BYTES}");
    println!("chained_transition_raw_bytes={CHAINED_KERNEL_BYTES}");
    println!("all_44_transition_raw_bytes={all_kernel_bytes}");
    println!("blake3_fixed_message_policy_bytes={BLAKE_BYTES}");
    println!(
        "blake3_fixed_message_with_binding_policy_bytes={}",
        FIXED_MESSAGE_BLAKE_BOUNDARY_BYTES
    );
    println!("blake3_manual_post_policy_optimizer=false");
    println!("fixed_message_binding_bytes={FIXED_MESSAGE_BINDING_BYTES}");
    println!("scalar_validator_raw_bytes={scalar_validator_raw_bytes}");
    println!("response_scalar_stream_scaffolding_raw_bytes={response_scalar_stream_raw_bytes}");
    println!(
        "response_component_routing_scaffolding_raw_bytes={response_component_routing_raw_bytes}"
    );
    println!(
        "challenge_component_routing_scaffolding_raw_bytes={challenge_component_routing_raw_bytes}"
    );
    println!("transcript_unpack_raw_bytes={transcript_unpack_raw_bytes}");
    println!("transcript_unpack_policy_precompiled_bytes={transcript_unpack_policy_bytes}");
    println!(
        "transcript_unpack_policy_delta_bytes={}",
        transcript_unpack_raw_bytes - transcript_unpack_policy_bytes
    );
    println!("h16_recode_raw_bytes={h16_recode_raw_bytes}");
    println!("h16_recode_policy_precompiled_bytes={h16_recode_policy_bytes}");
    println!("endpoint_comparison_raw_bytes={endpoint_comparison_raw_bytes}");
    println!("response_pair_decoder_raw_bytes={response_pair_decoder_bytes}");
    println!("scalar_carrier_full_router_raw_bytes={SCALAR_CARRIER_ROUTER_BYTES}");
    println!("remaining_challenge_q_carriers={CHALLENGE_Q_CARRIERS_OUTSIDE_SCALAR}");
    println!(
        "remaining_challenge_carrier_decoder_raw_bytes={remaining_challenge_carrier_decoder_bytes}"
    );
    println!("padding_word_decoder_raw_bytes={padding_word_decoder_bytes}");
    println!("priced_additive_subtotal_bytes={priced_subtotal}");
    println!("priced_subtotal_uses_policy_precompiled_midpoint_glue=true");
    println!("remaining_below_4_000_000_for_unpriced_integration={remaining_unpriced_budget}");
    println!("unpriced_scalar_carrier_deep_routing_and_repack=false");
    println!("unpriced_remaining_three_challenge_q_decoder_routing=true");
    println!("unpriced_response_table_sign_packet_and_component_routing=false");
    println!("response_component_routing_scaffolding_priced=true");
    println!("response_component_routing_integrated=false");
    println!("unpriced_transcript_chunk_to_u4_and_R_word_router=false");
    println!("transcript_router_policy_precompiled_and_priced=true");
    println!("unpriced_challenge_table_sign_packet_and_component_routing=false");
    println!("challenge_component_routing_scaffolding_priced=true");
    println!("challenge_component_routing_integrated=false");
    println!("unpriced_final_endpoint_comparison_and_cleanstack=false");
    println!("unpriced_witness_and_transaction_envelope=true");
    println!("full_44_transition_arithmetic_executed=false");
    println!("full_blake3_script_executed=false");
    println!("routing_assumption=packet_order_allows_top_down_18_item_consumption_and_q_restoration_in_place");
    println!("binding_assumption=carrier_metadata_order_is_consumed_exactly_once_by_scalar_or_transcript_consumer");
    println!("includes=modeled-whole-schedule: exact entry coexistence and per-frontier item arithmetic; independently measured table, transition, carrier-decoder, scalar-validator, scalar-stream, routing-scaffolding, exact transcript unpacker, exact H16 sign-selector recoder, endpoint, and BLAKE byte slots; remaining-q placement, cross-component reconciliation, and transaction envelope excluded");
}
