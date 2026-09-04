//! Trace-only scheduler and routing probe for the quotient-derived H16 leaf.
//!
//! Entry is exactly `challenge_trace[16] | response_trace[28] | scalar[8]`:
//! 704 trace items plus eight canonical compressed-u32 scalar words. Response
//! packets execute top-down (`p27..p0`), followed by challenge packets
//! (`p43..p28`). There are no quotient carriers, transcript chunks, scalar
//! router, or packet transpose.
//!
//! The focused strict probe uses distinguishable synthetic tables, states,
//! and packets to check the complete ordering. It never executes a field
//! relation, fixed table, BLAKE3, scalar multiplication, or multi-megabyte
//! leaf. Real derived kernels are generated one at a time only to obtain exact
//! additive byte counts and analytical combined-stack peaks.

#[allow(dead_code)]
#[path = "ed25519_fixed_table_actual_model.rs"]
mod fixed_tables;

#[allow(dead_code)]
#[path = "ed25519_g31_scalar_word_validator.rs"]
mod scalar_validation;

use bitcoin_lab::{
    curves::ed25519::montgomery_slope::{
        verify_chained_transition_derived, verify_chained_transition_derived_legacy_naf,
        verify_first_transition_derived, verify_first_transition_derived_legacy_naf,
        CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT, FIRST_DERIVED_COMPLETE_INPUT_ITEM_COUNT,
    },
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
    },
};
use num_bigint::{BigInt, BigUint};
use num_traits::ToPrimitive;

const RESPONSE_GROUPS: usize = 29;
const RESPONSE_TRANSITIONS: usize = RESPONSE_GROUPS - 1;
const CHALLENGE_GROUPS: usize = 16;
const CHALLENGE_TRANSITIONS: usize = CHALLENGE_GROUPS;
const TRANSITIONS: usize = RESPONSE_TRANSITIONS + CHALLENGE_TRANSITIONS;

const PACKED_WORDS: usize = 8;
const TRACE_ITEMS_PER_PACKET: usize = 2 * PACKED_WORDS;
const TRACE_ITEMS: usize = TRANSITIONS * TRACE_ITEMS_PER_PACKET;
const SCALAR_WORDS: usize = 8;
const ENTRY_ITEMS: usize = TRACE_ITEMS + SCALAR_WORDS;
const SELECTED_ITEMS: usize = 25;
const TOP_STATE_ITEMS: usize = 25;
const STATE_ITEMS: usize = 41;
pub(crate) const QFREE_ENTRY_ITEMS: usize = ENTRY_ITEMS;
pub(crate) const QFREE_HASH_PRESERVED_ITEMS: usize =
    CHALLENGE_GROUPS * TRACE_ITEMS_PER_PACKET + STATE_ITEMS;
pub(crate) const QFREE_HASH_R_WORD0_DEPTH: usize =
    PACKED_WORDS + (CHALLENGE_GROUPS - 1) * TRACE_ITEMS_PER_PACKET + STATE_ITEMS;

// Exact strict local peaks measured by the focused no-hint transition probe.
const FIRST_DERIVED_LOCAL_PEAK: usize = 214;
const CHAINED_DERIVED_LOCAL_PEAK: usize = 232;
// Policy output is unoptimized because each kernel exceeds 32 KiB. Focused
// `--kernel-size` probes cover response preserved endpoints 680/256 and every
// challenge preserved depth 270,252,...,0; serialized size is invariant.
const FIRST_DERIVED_KERNEL_BYTES: usize = 45_455;
const CHAINED_DERIVED_KERNEL_BYTES: usize = 68_295;

/// Quotient-derivation implementation embedded in a generated schedule.
/// Legacy NAF is retained only for byte-exact reproduction of the G29 leaf;
/// new schedules use the smaller mixed-multiplier default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DerivedKernelStyle {
    OptimizedMixed,
    LegacyNaf,
}

fn response_widths_low_to_high() -> Vec<usize> {
    let mut widths = vec![8usize; 8];
    widths.extend(std::iter::repeat_n(9usize, 21));
    assert_eq!(widths.len(), RESPONSE_GROUPS);
    assert_eq!(widths.iter().sum::<usize>(), 253);
    widths
}

/// Physical scalar word/remainder items live at each lower response callback.
fn scalar_items_after_response_transitions_for_widths(widths_low_to_high: &[usize]) -> Vec<usize> {
    assert!(widths_low_to_high.len() >= 2);
    assert_eq!(widths_low_to_high.iter().sum::<usize>(), 253);
    let mut chunks = vec![29usize];
    chunks.extend(std::iter::repeat_n(32usize, 7));
    let widths_high_to_low = widths_low_to_high.iter().copied().rev().collect::<Vec<_>>();
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
    assert_eq!(states.remove(0), SCALAR_WORDS);
    assert_eq!(states.len(), widths_low_to_high.len() - 1);
    assert_eq!(*states.last().expect("response transitions"), 0);
    states
}

fn scalar_items_after_response_transitions() -> Vec<usize> {
    scalar_items_after_response_transitions_for_widths(&response_widths_low_to_high())
}

fn move_block_to_top(block_items: usize, items_above: usize) -> Script {
    if block_items == 0 || items_above == 0 {
        return Script::new("no-op block move");
    }
    let depth = block_items + items_above - 1;
    script! {
        for _ in 0..block_items { { depth as u32 } OP_ROLL }
    }
}

fn park_current(items: usize) -> Script {
    script! { for _ in 0..items { OP_TOALTSTACK } }
}

fn restore_current(items: usize) -> Script {
    script! { for _ in 0..items { OP_FROMALTSTACK } }
}

fn bits_from_altstack_to_number(width: usize) -> Script {
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

/// Stream an already-validated 253-bit payload high-to-low. Every lower callback
/// receives the current state parked on altstack and returns the next state on
/// main stack, with altstack empty.
fn response_scalar_stream_for_widths(
    widths_low_to_high: &[usize],
    top_callback: Script,
    lower_callbacks: &[Script],
) -> Script {
    assert_eq!(lower_callbacks.len(), widths_low_to_high.len() - 1);
    let target_widths = widths_low_to_high.iter().copied().rev().collect::<Vec<_>>();
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
            STATE_ITEMS
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

    for _word in (0..SCALAR_WORDS - 1).rev() {
        steps.push(park_current(STATE_ITEMS));
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
            steps.push(park_current(STATE_ITEMS));
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

fn response_scalar_stream(top_callback: Script, lower_callbacks: &[Script]) -> Script {
    response_scalar_stream_for_widths(
        &response_widths_low_to_high(),
        top_callback,
        lower_callbacks,
    )
}

/// Input is a biased lower-window code; output is `magnitude | negative`.
fn decode_lower_code(width: usize) -> Script {
    assert!((7..=10).contains(&width));
    script! {
        { 1u32 << (width - 1) } OP_SUB
        OP_DUP 0 OP_LESSTHAN
        OP_IF OP_NEGATE 1 OP_ELSE 0 OP_ENDIF
    }
}

/// Negate the selected point's nine literal b limbs when the independent sign
/// control is true. The sixteen a limbs are unchanged.
fn apply_selected_sign() -> Script {
    script! {
        OP_IF
            for _ in 0..9 { OP_NEGATE OP_TOALTSTACK }
            for _ in 0..9 { OP_FROMALTSTACK }
        OP_ENDIF
    }
}

fn orient_initial_state() -> Script {
    move_block_to_top(16, 9)
}

fn reverse_chained_state_blocks() -> Script {
    script! {
        { move_block_to_top(16, 9) }
        { move_block_to_top(8, 9 + 16) }
        { move_block_to_top(8, 9 + 16 + 8) }
    }
}

/// Route one trace-only response packet into a derived kernel.
fn response_transition_callback(
    transition: usize,
    scalar_items: usize,
    width: usize,
    table: Script,
    kernel: Script,
) -> Script {
    let current_items = if transition == 0 {
        TOP_STATE_ITEMS
    } else {
        STATE_ITEMS
    };
    script! {
        { decode_lower_code(width) }
        OP_TOALTSTACK
        { table }
        OP_FROMALTSTACK
        { apply_selected_sign() }

        // No retained chunks exist. The topmost remaining response trace is
        // immediately below the scalar remainder and selected point.
        { move_block_to_top(
            TRACE_ITEMS_PER_PACKET,
            scalar_items + SELECTED_ITEMS,
        ) }
        { move_block_to_top(SELECTED_ITEMS, TRACE_ITEMS_PER_PACKET) }

        { restore_current(current_items) }
        if transition != 0 { { reverse_chained_state_blocks() } }
        { kernel }
    }
}

/// Route one trace-only challenge packet. At transition zero, current is below
/// all 32 independent-byte controls; later it is already above the remaining
/// controls. No R copy survives: the hash consumes a temporary copy and the
/// final packet later authenticates the original `u_next` words themselves.
fn challenge_transition_callback(transition: usize, table: Script, kernel: Script) -> Script {
    let remaining_groups = CHALLENGE_TRANSITIONS - transition - 1;
    let remaining_controls = 2 * remaining_groups;
    script! {
        if transition == 0 {
            { move_block_to_top(STATE_ITEMS, 2 * CHALLENGE_GROUPS) }
        }
        { park_current(STATE_ITEMS) }

        // Current control is `negative | magnitude`, magnitude on top.
        { table }
        { move_block_to_top(1, SELECTED_ITEMS) }
        { apply_selected_sign() }

        { move_block_to_top(
            TRACE_ITEMS_PER_PACKET,
            remaining_controls + SELECTED_ITEMS,
        ) }
        { move_block_to_top(SELECTED_ITEMS, TRACE_ITEMS_PER_PACKET) }

        { restore_current(STATE_ITEMS) }
        { reverse_chained_state_blocks() }
        { kernel }
    }
}

/// Canonical eight-word scalar validator for the exact 712-item q-free entry.
/// It requires zero hint items and preserves every entry item byte-for-byte.
pub(crate) fn qfree_scalar_validator() -> Script {
    qfree_scalar_validator_for_widths(&response_widths_low_to_high())
}

pub(crate) fn qfree_entry_items_for_widths(widths_low_to_high: &[usize]) -> usize {
    assert!(widths_low_to_high.len() >= 2);
    assert_eq!(widths_low_to_high.iter().sum::<usize>(), 253);
    (widths_low_to_high.len() - 1 + CHALLENGE_TRANSITIONS) * TRACE_ITEMS_PER_PACKET + SCALAR_WORDS
}

/// Canonical eight-word scalar validator for an arbitrary 253-bit response
/// partition. It preserves every trace packet and requires zero hint items.
pub(crate) fn qfree_scalar_validator_for_widths(widths_low_to_high: &[usize]) -> Script {
    let trace_items =
        (widths_low_to_high.len() - 1 + CHALLENGE_TRANSITIONS) * TRACE_ITEMS_PER_PACKET;
    scalar_validation::validate_scalar_words_for_widths_preserving(widths_low_to_high, trace_items)
}

fn first_derived_kernel(style: DerivedKernelStyle, preserved_items: u32) -> Script {
    match style {
        DerivedKernelStyle::OptimizedMixed => verify_first_transition_derived(preserved_items),
        DerivedKernelStyle::LegacyNaf => {
            verify_first_transition_derived_legacy_naf(preserved_items)
        }
    }
}

fn chained_derived_kernel(style: DerivedKernelStyle, preserved_items: u32) -> Script {
    match style {
        DerivedKernelStyle::OptimizedMixed => verify_chained_transition_derived(preserved_items),
        DerivedKernelStyle::LegacyNaf => {
            verify_chained_transition_derived_legacy_naf(preserved_items)
        }
    }
}

/// Compose the production response scheduler from 29 low-to-high H16 table
/// fragments. This builder contains no quotient decoding, transcript retention,
/// scalar routing, or packet transpose. It does not compile the returned
/// multi-megabyte fragment.
#[allow(dead_code)]
pub(crate) fn build_qfree_response_stream(response_tables_low_to_high: Vec<Script>) -> Script {
    build_qfree_response_stream_for_widths(
        response_tables_low_to_high,
        &response_widths_low_to_high(),
        DerivedKernelStyle::LegacyNaf,
    )
}

/// Compose a trace-only response schedule for a caller-selected canonical
/// partition and derived-kernel implementation. Tables and widths are both in
/// low-to-high scalar order. This only builds the fragment; it does not compile
/// or execute a multi-megabyte leaf.
pub(crate) fn build_qfree_response_stream_for_widths(
    response_tables_low_to_high: Vec<Script>,
    widths_low_to_high: &[usize],
    kernel_style: DerivedKernelStyle,
) -> Script {
    let response_groups = widths_low_to_high.len();
    let response_transitions = response_groups - 1;
    assert_eq!(response_tables_low_to_high.len(), response_groups);
    assert_eq!(widths_low_to_high.iter().sum::<usize>(), 253);
    let scalar_states = scalar_items_after_response_transitions_for_widths(widths_low_to_high);
    let top = script! {
        { response_tables_low_to_high[response_groups - 1].clone() }
        { orient_initial_state() }
    };
    let mut callbacks = Vec::with_capacity(response_transitions);
    for (transition, scalar_items) in scalar_states.into_iter().enumerate() {
        let preserved = response_preserved_items_for_transitions(
            response_transitions,
            transition,
            scalar_items,
        );
        let kernel = if transition == 0 {
            first_derived_kernel(kernel_style, preserved as u32)
        } else {
            chained_derived_kernel(kernel_style, preserved as u32)
        };
        let table_position = response_groups - transition - 2;
        callbacks.push(response_transition_callback(
            transition,
            scalar_items,
            widths_low_to_high[table_position],
            response_tables_low_to_high[table_position].clone(),
            kernel,
        ));
    }
    response_scalar_stream_for_widths(widths_low_to_high, top, &callbacks)
}

/// Exact raw routing/scalar-stream fragment for a selected response schedule,
/// excluding authenticated tables and transition kernels. This is small
/// enough for focused shape and byte checks without materializing a leaf.
pub(crate) fn qfree_response_scaffolding_for_widths(widths_low_to_high: &[usize]) -> Script {
    let response_groups = widths_low_to_high.len();
    let scalar_states = scalar_items_after_response_transitions_for_widths(widths_low_to_high);
    let callbacks = scalar_states
        .into_iter()
        .enumerate()
        .map(|(transition, scalar_items)| {
            let group = response_groups - transition - 2;
            response_transition_callback(
                transition,
                scalar_items,
                widths_low_to_high[group],
                Script::new("table excluded"),
                Script::new("kernel excluded"),
            )
        })
        .collect::<Vec<_>>();
    response_scalar_stream_for_widths(widths_low_to_high, orient_initial_state(), &callbacks)
}

/// Compose the production challenge scheduler from 16 low-to-high independent
/// bias-127 table fragments. Input after the packed-R hash boundary is
/// `challenge_trace[16] | current[41] | (negative,magnitude)[16]`.
#[allow(dead_code)]
pub(crate) fn build_qfree_challenge_schedule(challenge_tables_low_to_high: Vec<Script>) -> Script {
    build_qfree_challenge_schedule_with_style(
        challenge_tables_low_to_high,
        DerivedKernelStyle::LegacyNaf,
    )
}

/// Compose the fixed independent-byte challenge schedule with an explicitly
/// selected quotient-derivation implementation.
pub(crate) fn build_qfree_challenge_schedule_with_style(
    challenge_tables_low_to_high: Vec<Script>,
    kernel_style: DerivedKernelStyle,
) -> Script {
    assert_eq!(challenge_tables_low_to_high.len(), CHALLENGE_GROUPS);
    script! {
        for transition in 0..CHALLENGE_TRANSITIONS {
            { challenge_transition_callback(
                transition,
                challenge_tables_low_to_high[CHALLENGE_GROUPS - transition - 1].clone(),
                chained_derived_kernel(
                    kernel_style,
                    challenge_preserved_items(transition) as u32,
                )
            ) }
        }
    }
}

fn raw_fragment_len(fragment: &Script) -> usize {
    if fragment.len() > MAX_OPTIMIZER_INPUT_BYTES {
        let compiled = fragment.clone().compile_with_policy();
        assert_eq!(compiled.len(), fragment.len());
        return compiled.len();
    }
    let copies = MAX_OPTIMIZER_INPUT_BYTES.div_ceil(fragment.len().max(1)) + 1;
    let repeated = script! {
        for _ in 0..copies { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % copies, 0);
    repeated.len() / copies
}

fn response_preserved_items(transition: usize, scalar_items: usize) -> usize {
    response_preserved_items_for_transitions(RESPONSE_TRANSITIONS, transition, scalar_items)
}

fn response_preserved_items_for_transitions(
    response_transitions: usize,
    transition: usize,
    scalar_items: usize,
) -> usize {
    let future_packets = response_transitions + CHALLENGE_TRANSITIONS - transition - 1;
    future_packets * TRACE_ITEMS_PER_PACKET + scalar_items
}

fn challenge_preserved_items(transition: usize) -> usize {
    let remaining_groups = CHALLENGE_TRANSITIONS - transition - 1;
    remaining_groups * TRACE_ITEMS_PER_PACKET + 2 * remaining_groups
}

#[derive(Debug)]
struct KernelAccounting {
    first_bytes: usize,
    response_chained_bytes: usize,
    challenge_chained_bytes: usize,
    total_bytes: usize,
    max_combined_peak: usize,
    max_peak_phase: &'static str,
    max_peak_transition: usize,
}

/// Add exact independently measured kernel sizes without materializing their
/// multi-megabyte concatenation. `--kernel-size PHASE TRANSITION` regenerates
/// any row through the centralized compilation policy.
fn account_derived_kernels() -> KernelAccounting {
    let scalar_states = scalar_items_after_response_transitions();
    let mut max_combined_peak = ENTRY_ITEMS + 16; // scalar validator transient
    let mut max_peak_phase = "scalar-validator";
    let mut max_peak_transition = 0usize;

    for (transition, scalar_items) in scalar_states.iter().copied().enumerate() {
        let preserved = response_preserved_items(transition, scalar_items);
        let peak = preserved
            + if transition == 0 {
                FIRST_DERIVED_LOCAL_PEAK
            } else {
                CHAINED_DERIVED_LOCAL_PEAK
            };
        if peak > max_combined_peak {
            max_combined_peak = peak;
            max_peak_phase = "response";
            max_peak_transition = transition;
        }
    }

    for transition in 0..CHALLENGE_TRANSITIONS {
        let preserved = challenge_preserved_items(transition);
        let peak = preserved + CHAINED_DERIVED_LOCAL_PEAK;
        if peak > max_combined_peak {
            max_combined_peak = peak;
            max_peak_phase = "challenge";
            max_peak_transition = transition;
        }
    }

    let first_bytes = FIRST_DERIVED_KERNEL_BYTES;
    let response_chained_bytes = CHAINED_DERIVED_KERNEL_BYTES * (RESPONSE_TRANSITIONS - 1);
    let challenge_chained_bytes = CHAINED_DERIVED_KERNEL_BYTES * CHALLENGE_TRANSITIONS;

    KernelAccounting {
        first_bytes,
        response_chained_bytes,
        challenge_chained_bytes,
        total_bytes: first_bytes + response_chained_bytes + challenge_chained_bytes,
        max_combined_peak,
        max_peak_phase,
        max_peak_transition,
    }
}

fn scalar_order() -> BigUint {
    scalar_validation::scalar_order()
}

fn response_controls_low_to_high(scalar: &BigUint) -> Vec<(usize, bool)> {
    let widths = response_widths_low_to_high();
    let payload = scalar_validation::centered_payload_for_scalar_with_widths(scalar, &widths);
    let mut bit = 0usize;
    let mut recovered = BigInt::from(0);
    let mut controls = Vec::with_capacity(widths.len());
    for (group, width) in widths.iter().copied().enumerate() {
        let code = ((&payload >> bit) & BigUint::from((1u32 << width) - 1))
            .to_usize()
            .expect("window code fits usize");
        if group + 1 == widths.len() {
            assert!(code <= 256);
            recovered += BigInt::from(code) << bit;
            controls.push((code, false));
        } else {
            let centered = code as isize - (1isize << (width - 1));
            recovered += BigInt::from(centered) << bit;
            controls.push((centered.unsigned_abs(), centered < 0));
        }
        bit += width;
    }
    assert_eq!(bit, 253);
    assert_eq!(recovered, BigInt::from(scalar.clone()));
    controls
}

fn scriptnum_item(value: i64) -> Vec<u8> {
    scalar_validation::scriptnum_item(value)
}

fn trace_packet(global_packet: usize) -> Vec<i64> {
    assert!(global_packet < TRANSITIONS);
    let base = 10_000 + (global_packet * 100) as i64;
    (0..TRACE_ITEMS_PER_PACKET)
        .map(|word| base + word as i64)
        .collect()
}

fn selected_point(group: usize, negative: bool) -> Vec<i64> {
    let a = (0..16)
        .map(|limb| 30_000 + (group * 100 + limb) as i64)
        .collect::<Vec<_>>();
    let b = (0..9)
        .map(|limb| 40_000 + (group * 100 + limb) as i64)
        .map(|limb| if negative { -limb } else { limb });
    a.into_iter().chain(b).collect()
}

fn natural_state(step: usize) -> Vec<i64> {
    let base = 60_000 + (step * 100) as i64;
    (0..STATE_ITEMS).map(|item| base + item as i64).collect()
}

fn initial_state_parts() -> (Vec<i64>, Vec<i64>) {
    let u = (0..16).map(|item| 50_000 + item).collect::<Vec<_>>();
    let v = (0..9).map(|item| 50_100 + item).collect::<Vec<_>>();
    (u, v)
}

fn reverse_state_blocks(state: &[i64]) -> Vec<i64> {
    assert_eq!(state.len(), STATE_ITEMS);
    let u = &state[0..8];
    let lambda = &state[8..16];
    let a = &state[16..32];
    let b = &state[32..41];
    [b, a, lambda, u].concat()
}

fn push_values(values: &[i64]) -> Script {
    script! { for value in values { { *value } } }
}

fn verify_values(values_bottom_to_top: &[i64]) -> Script {
    script! {
        for value in values_bottom_to_top.iter().rev() {
            { *value } OP_NUMEQUALVERIFY
        }
    }
}

fn table_stub(group: usize, magnitude: usize) -> Script {
    let positive_selected = selected_point(group, false);
    script! {
        { magnitude as u32 } OP_NUMEQUALVERIFY
        { push_values(&positive_selected) }
    }
}

fn kernel_stub(expected_input: Vec<i64>, output: Vec<i64>) -> Script {
    script! {
        { verify_values(&expected_input) }
        { push_values(&output) }
    }
}

fn synthetic_response_stream(
    scalar_controls: &[(usize, bool)],
    final_state: &mut Vec<i64>,
) -> Script {
    assert_eq!(scalar_controls.len(), RESPONSE_GROUPS);
    let widths = response_widths_low_to_high();
    let (initial_u, initial_v) = initial_state_parts();
    let top_magnitude = scalar_controls[RESPONSE_GROUPS - 1].0;
    assert!(!scalar_controls[RESPONSE_GROUPS - 1].1);
    let top = script! {
        { top_magnitude as u32 } OP_NUMEQUALVERIFY
        { push_values(&initial_u) }
        { push_values(&initial_v) }
        { orient_initial_state() }
    };

    let scalar_states = scalar_items_after_response_transitions();
    let mut callbacks = Vec::with_capacity(RESPONSE_TRANSITIONS);
    let mut current = [initial_v, initial_u].concat();
    for (transition, scalar_items) in scalar_states.into_iter().enumerate() {
        let group = RESPONSE_GROUPS - transition - 2;
        let (magnitude, negative) = scalar_controls[group];
        let packet = trace_packet(RESPONSE_TRANSITIONS - transition - 1);
        let selected = selected_point(group, negative);
        let oriented_current = if transition == 0 {
            current.clone()
        } else {
            reverse_state_blocks(&current)
        };
        let expected_input = [packet, selected, oriented_current].concat();
        let output = natural_state(transition);
        callbacks.push(response_transition_callback(
            transition,
            scalar_items,
            widths[group],
            table_stub(group, magnitude),
            kernel_stub(expected_input, output.clone()),
        ));
        current = output;
    }
    *final_state = current;
    response_scalar_stream(top, &callbacks)
}

fn challenge_controls_low_to_high(bytes: &[u8; CHALLENGE_GROUPS]) -> Vec<(bool, usize)> {
    bytes
        .iter()
        .copied()
        .map(fixed_tables::h16_independent_challenge_control)
        .collect()
}

fn push_challenge_controls(controls: &[(bool, usize)]) -> Script {
    script! {
        for (negative, magnitude) in controls {
            { i64::from(*negative) } { *magnitude as u32 }
        }
    }
}

fn synthetic_challenge_schedule(
    controls: &[(bool, usize)],
    starting_state: &[i64],
    final_state: &mut Vec<i64>,
) -> Script {
    assert_eq!(controls.len(), CHALLENGE_GROUPS);
    let mut steps = Vec::with_capacity(CHALLENGE_TRANSITIONS);
    let mut current = starting_state.to_vec();
    for transition in 0..CHALLENGE_TRANSITIONS {
        let group = CHALLENGE_GROUPS - transition - 1;
        let (negative, magnitude) = controls[group];
        let packet = trace_packet(RESPONSE_TRANSITIONS + group);
        let selected = selected_point(RESPONSE_GROUPS + group, negative);
        let expected_input = [packet, selected, reverse_state_blocks(&current)].concat();
        let output = natural_state(RESPONSE_TRANSITIONS + transition);
        steps.push(challenge_transition_callback(
            transition,
            table_stub(RESPONSE_GROUPS + group, magnitude),
            kernel_stub(expected_input, output.clone()),
        ));
        current = output;
    }
    *final_state = current;
    script! { for step in steps { { step } } }
}

fn entry_witness(scalar: &BigUint) -> Vec<Vec<u8>> {
    let mut witness = Vec::with_capacity(ENTRY_ITEMS);
    // Bottom-to-top: challenge p28..p43, then response p0..p27.
    for packet in RESPONSE_TRANSITIONS..TRANSITIONS {
        witness.extend(trace_packet(packet).into_iter().map(scriptnum_item));
    }
    for packet in 0..RESPONSE_TRANSITIONS {
        witness.extend(trace_packet(packet).into_iter().map(scriptnum_item));
    }
    let payload = scalar_validation::centered_payload_for_scalar_with_widths(
        scalar,
        &response_widths_low_to_high(),
    );
    witness.extend(
        scalar_validation::words_from_payload(&payload)
            .into_iter()
            .map(|word| scriptnum_item(i64::from(word as i32))),
    );
    assert_eq!(witness.len(), ENTRY_ITEMS);
    witness
}

fn scheduler_scaffolding() -> (Script, Script) {
    let response = qfree_response_scaffolding_for_widths(&response_widths_low_to_high());
    let challenge = script! {
        for transition in 0..CHALLENGE_TRANSITIONS {
            { challenge_transition_callback(
                transition,
                Script::new("table excluded"),
                Script::new("kernel excluded"),
            ) }
        }
    };
    (response, challenge)
}

fn print_single_kernel_size(phase: &str, transition: usize) {
    let (preserved, local_peak, fragment) = match phase {
        "response" => {
            assert!(transition < RESPONSE_TRANSITIONS);
            let scalar_items = scalar_items_after_response_transitions()[transition];
            let preserved = response_preserved_items(transition, scalar_items);
            if transition == 0 {
                (
                    preserved,
                    FIRST_DERIVED_LOCAL_PEAK,
                    verify_first_transition_derived_legacy_naf(preserved as u32),
                )
            } else {
                (
                    preserved,
                    CHAINED_DERIVED_LOCAL_PEAK,
                    verify_chained_transition_derived_legacy_naf(preserved as u32),
                )
            }
        }
        "challenge" => {
            assert!(transition < CHALLENGE_TRANSITIONS);
            let preserved = challenge_preserved_items(transition);
            (
                preserved,
                CHAINED_DERIVED_LOCAL_PEAK,
                verify_chained_transition_derived_legacy_naf(preserved as u32),
            )
        }
        _ => panic!("kernel phase must be response or challenge"),
    };
    let bytes = fragment.compile_with_policy().len();
    assert!(bytes > MAX_OPTIMIZER_INPUT_BYTES);
    println!(
        "phase={phase} transition={transition} preserved={preserved} bytes={bytes} combined_peak={}",
        preserved + local_peak
    );
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if args.get(1).map(String::as_str) == Some("--kernel-size") {
        assert_eq!(args.len(), 4);
        let transition = args[3].parse::<usize>().expect("numeric transition");
        print_single_kernel_size(&args[2], transition);
        return;
    }
    let mode = args.get(1).cloned();
    assert!(matches!(
        mode.as_deref(),
        None | Some("--routing-only") | Some("--measure-only")
    ));
    assert_eq!(TRACE_ITEMS, 704);
    assert_eq!(QFREE_ENTRY_ITEMS, 712);
    assert_eq!(FIRST_DERIVED_COMPLETE_INPUT_ITEM_COUNT, 66);
    assert_eq!(CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT, 82);

    let scalar = BigUint::from(987_654_321u64);
    assert!(scalar < scalar_order());
    let scalar_controls = response_controls_low_to_high(&scalar);
    let challenge_bytes: [u8; CHALLENGE_GROUPS] =
        std::array::from_fn(|index| [0x00, 0x7f, 0x80, 0xff][index % 4]);
    let challenge_controls = challenge_controls_low_to_high(&challenge_bytes);
    assert_eq!(challenge_controls[0], (true, 127));
    assert_eq!(challenge_controls[1], (false, 0));
    assert_eq!(challenge_controls[2], (false, 1));
    assert_eq!(challenge_controls[3], (false, 128));

    let validator = qfree_scalar_validator();
    let strict_peak = if mode.as_deref() == Some("--measure-only") {
        None
    } else {
        let mut post_response_state = Vec::new();
        let response = synthetic_response_stream(&scalar_controls, &mut post_response_state);
        let mut final_state = Vec::new();
        let challenge = synthetic_challenge_schedule(
            &challenge_controls,
            &post_response_state,
            &mut final_state,
        );
        let strict_fragment = script! {
            { validator.clone() }
            { response }
            { push_challenge_controls(&challenge_controls) }
            { challenge }
            { verify_values(&final_state) }
            OP_1
        };
        println!("strict_synthetic_raw_ast_bytes={}", strict_fragment.len());
        let strict_script = strict_fragment.compile_with_policy();
        let witness = entry_witness(&scalar);
        let execution =
            execute_raw_script_with_inputs_strict(strict_script.to_bytes(), witness.clone());
        assert!(
            execution.error.is_none(),
            "q-free synthetic schedule: {execution}"
        );
        assert_eq!(execution.final_stack.len(), 1);

        if mode.as_deref() != Some("--routing-only") {
            let mut bad_response = witness.clone();
            let response_p27_word0 = CHALLENGE_GROUPS * TRACE_ITEMS_PER_PACKET
                + (RESPONSE_TRANSITIONS - 1) * TRACE_ITEMS_PER_PACKET;
            bad_response[response_p27_word0] = scriptnum_item(-77);
            let rejected_response =
                execute_raw_script_with_inputs_strict(strict_script.to_bytes(), bad_response);
            assert!(rejected_response.error.is_some());

            let mut bad_challenge = witness;
            let challenge_p43_word15 =
                (CHALLENGE_GROUPS - 1) * TRACE_ITEMS_PER_PACKET + TRACE_ITEMS_PER_PACKET - 1;
            bad_challenge[challenge_p43_word15] = scriptnum_item(-88);
            let rejected_challenge =
                execute_raw_script_with_inputs_strict(strict_script.to_bytes(), bad_challenge);
            assert!(rejected_challenge.error.is_some());
        }
        Some(execution.stats.max_nb_stack_items)
    };

    if mode.as_deref() == Some("--routing-only") {
        println!(
            "strict_synthetic_combined_stack_peak={}",
            strict_peak.expect("routing probe executed")
        );
        return;
    }

    let validator_raw = raw_fragment_len(&validator);
    let validator_policy = validator.compile_with_policy().len();
    let (response_scaffolding, challenge_scaffolding) = scheduler_scaffolding();
    let response_scaffolding_raw = raw_fragment_len(&response_scaffolding);
    let response_scaffolding_policy = response_scaffolding.compile_with_policy().len();
    let challenge_scaffolding_raw = raw_fragment_len(&challenge_scaffolding);
    let challenge_scaffolding_policy = challenge_scaffolding.compile_with_policy().len();
    let kernel_accounting = account_derived_kernels();
    let non_table_raw = validator_raw
        + response_scaffolding_raw
        + challenge_scaffolding_raw
        + kernel_accounting.total_bytes;

    println!("model=ed25519_montgomery_h16_qfree_scheduler");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=item-order");
    println!("execution_class=unclassified");
    println!("entry_layout=challenge16_trace|response28_trace|scalar8");
    println!("trace_items={TRACE_ITEMS}");
    println!("quotient_hint_items=0");
    println!("scalar_items={SCALAR_WORDS}");
    println!("complete_entry_items={QFREE_ENTRY_ITEMS}");
    println!("all_entry_items_coexist=true");
    println!("response_execution_order=p27_to_p0");
    println!("challenge_execution_order=p43_to_p28");
    println!("scalar_router_bytes=0");
    println!("packet_transpose_bytes=0");
    println!("q_decoder_bytes=0");
    println!("retained_transcript_chunk_items=0");
    println!("scalar_validator_raw_bytes={validator_raw}");
    println!("scalar_validator_policy_bytes={validator_policy}");
    println!("response_scaffolding_raw_bytes={response_scaffolding_raw}");
    println!("response_scaffolding_policy_bytes={response_scaffolding_policy}");
    println!("challenge_scaffolding_raw_bytes={challenge_scaffolding_raw}");
    println!("challenge_scaffolding_policy_bytes={challenge_scaffolding_policy}");
    println!("hash_boundary_preserved_items={QFREE_HASH_PRESERVED_ITEMS}");
    println!("hash_boundary_r_word0_depth={QFREE_HASH_R_WORD0_DEPTH}");
    println!("hash_packed_r_helper_bytes_excluded_from_scheduler_total=true");
    println!(
        "derived_first_kernel_bytes={}",
        kernel_accounting.first_bytes
    );
    println!(
        "derived_response_chained_kernel_bytes={}",
        kernel_accounting.response_chained_bytes
    );
    println!(
        "derived_challenge_chained_kernel_bytes={}",
        kernel_accounting.challenge_chained_bytes
    );
    println!("derived_44_kernel_bytes={}", kernel_accounting.total_bytes);
    println!("qfree_non_table_raw_bytes={non_table_raw}");
    println!(
        "analytical_max_combined_stack_items={}",
        kernel_accounting.max_combined_peak
    );
    println!("analytical_peak_phase={}", kernel_accounting.max_peak_phase);
    println!(
        "analytical_peak_transition={}",
        kernel_accounting.max_peak_transition
    );
    if let Some(strict_peak) = strict_peak {
        println!("strict_synthetic_combined_stack_peak={strict_peak}");
        println!("response_packet_order_mutation_rejected=true");
        println!("challenge_packet_order_mutation_rejected=true");
    } else {
        println!("strict_synthetic_probe_executed=false");
    }
    println!("independent_byte_boundaries_tested=00,7f,80,ff");
    println!("retained_r_copy_items_through_challenge=0");
    println!("hash_r_binding_reason=hash_helper_copies_original_p28_u_words_and_final_derived_kernel_later_authenticates_those_same_untouched_items");
    println!("large_table_hash_field_or_full_leaf_executed=false");
}
