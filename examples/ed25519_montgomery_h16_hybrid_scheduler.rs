//! Focused scheduler/cost scaffold for the experimental persistent hybrid
//! Montgomery-slope state.
//!
//! This probe never builds authenticated fixed tables, BLAKE3, a field
//! relation, or a complete multi-megabyte leaf. It strictly executes only
//! distinguishable table/kernel stubs to prove packet, scalar, control, and
//! 92-item state routing for both candidate response partitions.
//!
//! Entry remains trace-only: `challenge_trace[16] | response_trace[G-1] |
//! scalar[8]`. A successful first transition expands the 25-item initializer
//! directly to the next verifier's suffix order
//! `b_selected_limbs[9] | a_selected_limbs[16] |
//! lambda_next_biased_digits[51] | u_next_limbs[16]`. No callback spends
//! bytes reversing a persistent state.

#[allow(dead_code)]
#[path = "ed25519_g31_scalar_word_validator.rs"]
mod scalar_validation;

use bitcoin_lab::{
    curves::ed25519::montgomery_slope::{
        initialize_hybrid_persistent_shared_power_pool,
        verify_chained_transition_derived_hybrid_state_certified_u_next_u5_terminal_finalize_persistent_shared_power_pool,
        verify_chained_transition_derived_hybrid_state_finalize_persistent_shared_power_pool,
        verify_chained_transition_derived_hybrid_state_initialize_persistent_shared_power_pool,
        verify_chained_transition_derived_hybrid_state_persistent_shared_power_pool,
        verify_first_transition_derived_hybrid_state_shared_power_pool,
        FIRST_DERIVED_COMPLETE_INPUT_ITEM_COUNT, HYBRID_CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT,
        HYBRID_FIRST_SHARED_POWER_ITEM_COUNT, HYBRID_LATER_SHARED_POWER_BITS,
        HYBRID_LATER_SHARED_POWER_ITEM_COUNT, HYBRID_STATE_ITEM_COUNT,
    },
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
    },
};
use num_bigint::{BigInt, BigUint};
use num_traits::ToPrimitive;

const CHALLENGE_GROUPS: usize = 16;
const PACKED_WORDS: usize = 8;
const TRACE_ITEMS_PER_PACKET: usize = 2 * PACKED_WORDS;
const SCALAR_WORDS: usize = 8;
const SELECTED_ITEMS: usize = 25;
const TOP_STATE_ITEMS: usize = 25;
const U5_FINAL_R_ITEMS: usize = 51;
const U5_FINAL_PACKET_ITEMS: usize = U5_FINAL_R_ITEMS + PACKED_WORDS;
const U5_FINAL_PACKET_EXTRA_ITEMS: usize = U5_FINAL_R_ITEMS - PACKED_WORDS;

pub(crate) const HYBRID_STATE_ITEMS: usize = 16 + 51 + 16 + 9;
pub(crate) const HYBRID_HASH_PRESERVED_ITEMS: usize =
    CHALLENGE_GROUPS * TRACE_ITEMS_PER_PACKET + HYBRID_STATE_ITEMS;
pub(crate) const HYBRID_HASH_R_WORD0_DEPTH: usize =
    PACKED_WORDS + (CHALLENGE_GROUPS - 1) * TRACE_ITEMS_PER_PACKET + HYBRID_STATE_ITEMS;

// Exact policy-produced sizes and strict local peaks reproduced by
// `ed25519_montgomery_slope_shared_constants_probe`. Each kernel first policy-
// compiles its sub-32-KiB semantic steps; its assembled wrapper is then larger
// than 32 KiB, so policy applies no second optimizer pass to that wrapper.
const HYBRID_FIRST_KERNEL_BYTES: usize = 37_109;
const HYBRID_INITIALIZE_PERSISTENT_KERNEL_BYTES: usize = 49_921;
const HYBRID_PERSISTENT_KERNEL_BYTES: usize = 49_888;
const HYBRID_FINALIZE_PERSISTENT_KERNEL_BYTES: usize = 49_880;
const HYBRID_FIRST_LOCAL_PEAK: usize = 212;
const HYBRID_INITIALIZE_PERSISTENT_LOCAL_PEAK: usize = 224;
const HYBRID_PERSISTENT_LOCAL_PEAK: usize = 240;
const HYBRID_FINALIZE_PERSISTENT_LOCAL_PEAK: usize = 240;

// Independently focused component measurements. They are summed here without
// constructing any authenticated table, hash fragment, or complete leaf.
const G31_RESPONSE_TABLE_BYTES: usize = 451_272;
const G32_PARITY_CORRECT_RESPONSE_TABLE_BYTES: usize = 383_004;
const CHALLENGE_TABLE_BYTES: usize = 200_843;
const PACKED_R_HASH_BYTES_AT_HYBRID_BOUNDARY: usize = 67_806;
const INDEPENDENT_BYTE_RECODER_BYTES: usize = 389;
const HYBRID_TERMINAL_BYTES: usize = HYBRID_STATE_ITEMS / 2 + 1;
const EXPECTED_G31_PACKED_R_HYBRID_LEAF_BYTES: usize = 3_023_362;
const EXPECTED_G32_PACKED_R_HYBRID_LEAF_BYTES: usize = 3_005_271;
pub(crate) const HYBRID_U5_HASH_PRESERVED_ITEMS: usize =
    HYBRID_HASH_PRESERVED_ITEMS + U5_FINAL_PACKET_EXTRA_ITEMS;
pub(crate) const HYBRID_U5_HASH_R_DIGIT0_DEPTH: usize = HYBRID_HASH_R_WORD0_DEPTH;
const HYBRID_U5_HASH_BYTES: usize = 67_137;
const HYBRID_U5_FINAL_TERMINAL_KERNEL_BYTES: usize = 45_179;
const HYBRID_U5_FINAL_LOCAL_PEAK: usize = 283;
const EXPECTED_G32_U5_HYBRID_LEAF_BYTES: usize = 2_999_983;

/// Exact exhaustive-placement winner for 31 response groups.
pub(crate) fn g31_widths_low_to_high() -> Vec<usize> {
    let mut widths = vec![8usize; 31];
    for position in [20usize, 21, 22, 23, 26] {
        widths[position] = 9;
    }
    assert_eq!(widths.iter().sum::<usize>(), 253);
    assert_eq!(*widths.last().expect("top width"), 8);
    widths
}

/// Exact exhaustive-placement winner for 32 response groups.
pub(crate) fn g32_widths_low_to_high() -> Vec<usize> {
    let mut widths = vec![8usize; 32];
    for position in [21usize, 25, 29] {
        widths[position] = 7;
    }
    assert_eq!(widths.iter().sum::<usize>(), 253);
    assert_eq!(*widths.last().expect("top width"), 8);
    widths
}

pub(crate) fn hybrid_entry_items_for_widths(widths_low_to_high: &[usize]) -> usize {
    assert!(widths_low_to_high.len() >= 2);
    assert_eq!(widths_low_to_high.iter().sum::<usize>(), 253);
    (widths_low_to_high.len() - 1 + CHALLENGE_GROUPS) * TRACE_ITEMS_PER_PACKET + SCALAR_WORDS
}

pub(crate) fn hybrid_u5_entry_items_for_widths(widths_low_to_high: &[usize]) -> usize {
    hybrid_entry_items_for_widths(widths_low_to_high) + U5_FINAL_PACKET_EXTRA_ITEMS
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

/// Physical scalar word/remainder items below each lower response callback.
fn scalar_items_after_response_transitions(widths_low_to_high: &[usize]) -> Vec<usize> {
    assert!(widths_low_to_high.len() >= 2);
    assert_eq!(widths_low_to_high.iter().sum::<usize>(), 253);
    let mut chunks = vec![29usize];
    chunks.extend(std::iter::repeat_n(32usize, 7));
    let widths_high_to_low = widths_low_to_high.iter().copied().rev().collect::<Vec<_>>();
    let mut chunk = 0usize;
    let mut remainder = chunks[0];
    let mut states = Vec::with_capacity(widths_low_to_high.len());
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
    assert_eq!(*states.last().expect("response transition"), 0);
    states
}

/// Stream a validated 253-bit response payload high-to-low. The first lower
/// callback consumes a 25-item initializer and returns hybrid state; every
/// later callback consumes and returns 92 hybrid items.
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
            HYBRID_STATE_ITEMS
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
        steps.push(park_current(HYBRID_STATE_ITEMS));
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
            steps.push(park_current(HYBRID_STATE_ITEMS));
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

/// Input is a biased lower-window code; output is `magnitude | negative`.
fn decode_lower_code(width: usize) -> Script {
    assert!((7..=10).contains(&width));
    script! {
        { 1u32 << (width - 1) } OP_SUB
        OP_DUP 0 OP_LESSTHAN
        OP_IF OP_NEGATE 1 OP_ELSE 0 OP_ENDIF
    }
}

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
        HYBRID_STATE_ITEMS
    };
    script! {
        { decode_lower_code(width) }
        OP_TOALTSTACK
        { table }
        OP_FROMALTSTACK
        { apply_selected_sign() }

        { move_block_to_top(
            TRACE_ITEMS_PER_PACKET,
            scalar_items + SELECTED_ITEMS,
        ) }
        { move_block_to_top(SELECTED_ITEMS, TRACE_ITEMS_PER_PACKET) }

        { restore_current(current_items) }
        { kernel }
    }
}

/// Input at transition zero is `challenge_trace256 | current92 | controls32`.
/// Later callbacks already leave current above the remaining controls.
fn challenge_transition_callback(transition: usize, table: Script, kernel: Script) -> Script {
    challenge_transition_callback_with_packet_items(
        transition,
        TRACE_ITEMS_PER_PACKET,
        table,
        kernel,
    )
}

fn challenge_transition_callback_with_packet_items(
    transition: usize,
    packet_items: usize,
    table: Script,
    kernel: Script,
) -> Script {
    let remaining_groups = CHALLENGE_GROUPS - transition - 1;
    let remaining_controls = 2 * remaining_groups;
    script! {
        if transition == 0 {
            { move_block_to_top(HYBRID_STATE_ITEMS, 2 * CHALLENGE_GROUPS) }
        }
        { park_current(HYBRID_STATE_ITEMS) }

        { table }
        { move_block_to_top(1, SELECTED_ITEMS) }
        { apply_selected_sign() }

        { move_block_to_top(
            packet_items,
            remaining_controls + SELECTED_ITEMS,
        ) }
        { move_block_to_top(SELECTED_ITEMS, packet_items) }

        { restore_current(HYBRID_STATE_ITEMS) }
        { kernel }
    }
}

pub(crate) fn hybrid_scalar_validator_for_widths(widths_low_to_high: &[usize]) -> Script {
    let trace_items = (widths_low_to_high.len() - 1 + CHALLENGE_GROUPS) * TRACE_ITEMS_PER_PACKET;
    scalar_validation::validate_scalar_words_for_widths_preserving(widths_low_to_high, trace_items)
}

pub(crate) fn hybrid_u5_scalar_validator_for_widths(widths_low_to_high: &[usize]) -> Script {
    let trace_items = (widths_low_to_high.len() - 1 + CHALLENGE_GROUPS) * TRACE_ITEMS_PER_PACKET
        + U5_FINAL_PACKET_EXTRA_ITEMS;
    scalar_validation::validate_scalar_words_for_widths_preserving(widths_low_to_high, trace_items)
}

pub(crate) fn hybrid_response_scaffolding_for_widths(widths_low_to_high: &[usize]) -> Script {
    let response_groups = widths_low_to_high.len();
    let callbacks = scalar_items_after_response_transitions(widths_low_to_high)
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

pub(crate) fn hybrid_challenge_scaffolding() -> Script {
    script! {
        for transition in 0..CHALLENGE_GROUPS {
            { challenge_transition_callback(
                transition,
                Script::new("table excluded"),
                Script::new("kernel excluded"),
            ) }
        }
    }
}

pub(crate) fn hybrid_u5_challenge_scaffolding() -> Script {
    script! {
        for transition in 0..CHALLENGE_GROUPS {
            { challenge_transition_callback_with_packet_items(
                transition,
                if transition + 1 == CHALLENGE_GROUPS {
                    U5_FINAL_PACKET_ITEMS
                } else {
                    TRACE_ITEMS_PER_PACKET
                },
                Script::new("table excluded"),
                Script::new("kernel excluded"),
            ) }
        }
    }
}

/// Compose a production-shaped response scheduler without materializing it in
/// this probe. The caller supplies authenticated tables and the exact
/// preserved-depth-aware hybrid kernels. Each kernel returns the 92-item state
/// already in next-input order.
#[allow(dead_code)]
pub(crate) fn build_hybrid_response_stream_for_widths(
    response_tables_low_to_high: Vec<Script>,
    widths_low_to_high: &[usize],
) -> Script {
    build_hybrid_response_stream_for_widths_with_preserved_extra(
        response_tables_low_to_high,
        widths_low_to_high,
        0,
    )
}

/// Response counterpart for a final/lowest challenge packet whose packed
/// eight-word u coordinate is replaced by 51 canonical u5 digits.
#[allow(dead_code)]
pub(crate) fn build_hybrid_u5_response_stream_for_widths(
    response_tables_low_to_high: Vec<Script>,
    widths_low_to_high: &[usize],
) -> Script {
    build_hybrid_response_stream_for_widths_with_preserved_extra(
        response_tables_low_to_high,
        widths_low_to_high,
        U5_FINAL_PACKET_EXTRA_ITEMS,
    )
}

fn build_hybrid_response_stream_for_widths_with_preserved_extra(
    response_tables_low_to_high: Vec<Script>,
    widths_low_to_high: &[usize],
    future_trace_extra: usize,
) -> Script {
    let response_groups = widths_low_to_high.len();
    assert!(response_groups >= 4);
    let response_transitions = response_groups - 1;
    assert_eq!(response_tables_low_to_high.len(), response_groups);
    assert_eq!(widths_low_to_high.iter().sum::<usize>(), 253);
    let scalar_states = scalar_items_after_response_transitions(widths_low_to_high);
    let top = script! {
        { response_tables_low_to_high[response_groups - 1].clone() }
        { orient_initial_state() }
    };
    let callbacks = scalar_states
        .into_iter()
        .enumerate()
        .map(|(transition, scalar_items)| {
            let group = response_groups - transition - 2;
            let preserved = response_preserved_items_with_extra(
                response_transitions,
                transition,
                scalar_items,
                future_trace_extra,
            );
            let kernel = if transition == 0 {
                verify_first_transition_derived_hybrid_state_shared_power_pool(preserved as u32)
            } else if transition == 1 {
                verify_chained_transition_derived_hybrid_state_initialize_persistent_shared_power_pool(
                    preserved as u32,
                )
            } else if transition + 1 == response_transitions {
                verify_chained_transition_derived_hybrid_state_finalize_persistent_shared_power_pool(
                    preserved as u32,
                )
            } else {
                verify_chained_transition_derived_hybrid_state_persistent_shared_power_pool(
                    preserved as u32,
                )
            };
            response_transition_callback(
                transition,
                scalar_items,
                widths_low_to_high[group],
                response_tables_low_to_high[group].clone(),
                kernel,
            )
        })
        .collect::<Vec<_>>();
    response_scalar_stream_for_widths(widths_low_to_high, top, &callbacks)
}

/// Compose the fixed independent-byte challenge scheduler. The packed-R hash
/// has already copied from the still-untouched final/lowest trace packet and
/// left `challenge_trace256 | current92 | controls32`.
#[allow(dead_code)]
pub(crate) fn build_hybrid_challenge_schedule(challenge_tables_low_to_high: Vec<Script>) -> Script {
    assert_eq!(challenge_tables_low_to_high.len(), CHALLENGE_GROUPS);
    script! {
        for transition in 0..CHALLENGE_GROUPS {
            { challenge_transition_callback(
                transition,
                challenge_tables_low_to_high[CHALLENGE_GROUPS - transition - 1].clone(),
                if transition == 0 {
                    verify_chained_transition_derived_hybrid_state_initialize_persistent_shared_power_pool(
                        challenge_preserved_items(transition) as u32,
                    )
                } else if transition + 1 == CHALLENGE_GROUPS {
                    verify_chained_transition_derived_hybrid_state_finalize_persistent_shared_power_pool(
                        challenge_preserved_items(transition) as u32,
                    )
                } else {
                    verify_chained_transition_derived_hybrid_state_persistent_shared_power_pool(
                        challenge_preserved_items(transition) as u32,
                    )
                },
            ) }
        }
    }
}

/// Challenge schedule for the canonical-u5 final R packet. The first fifteen
/// callbacks return next-input-order hybrid state. The last 59-item callback
/// consumes certified R digits with the specialized kernel and fuses the
/// clean-stack terminal predicate.
#[allow(dead_code)]
pub(crate) fn build_hybrid_u5_challenge_schedule(
    challenge_tables_low_to_high: Vec<Script>,
) -> Script {
    assert_eq!(challenge_tables_low_to_high.len(), CHALLENGE_GROUPS);
    script! {
        for transition in 0..CHALLENGE_GROUPS {
            { challenge_transition_callback_with_packet_items(
                transition,
                if transition + 1 == CHALLENGE_GROUPS {
                    U5_FINAL_PACKET_ITEMS
                } else {
                    TRACE_ITEMS_PER_PACKET
                },
                challenge_tables_low_to_high[CHALLENGE_GROUPS - transition - 1].clone(),
                if transition + 1 == CHALLENGE_GROUPS {
                    verify_chained_transition_derived_hybrid_state_certified_u_next_u5_terminal_finalize_persistent_shared_power_pool(
                        0,
                    )
                } else if transition == 0 {
                    verify_chained_transition_derived_hybrid_state_initialize_persistent_shared_power_pool(
                        challenge_u5_preserved_items(transition) as u32,
                    )
                } else {
                    verify_chained_transition_derived_hybrid_state_persistent_shared_power_pool(
                        challenge_u5_preserved_items(transition) as u32,
                    )
                },
            ) }
        }
    }
}

fn response_preserved_items(
    response_transitions: usize,
    transition: usize,
    scalar_items: usize,
) -> usize {
    response_preserved_items_with_extra(response_transitions, transition, scalar_items, 0)
}

fn response_preserved_items_with_extra(
    response_transitions: usize,
    transition: usize,
    scalar_items: usize,
    future_trace_extra: usize,
) -> usize {
    let future_packets = response_transitions + CHALLENGE_GROUPS - transition - 1;
    future_packets * TRACE_ITEMS_PER_PACKET + scalar_items + future_trace_extra
}

fn challenge_preserved_items(transition: usize) -> usize {
    let remaining_groups = CHALLENGE_GROUPS - transition - 1;
    remaining_groups * TRACE_ITEMS_PER_PACKET + 2 * remaining_groups
}

fn challenge_u5_preserved_items(transition: usize) -> usize {
    let remaining_groups = CHALLENGE_GROUPS - transition - 1;
    challenge_preserved_items(transition)
        + usize::from(remaining_groups != 0) * U5_FINAL_PACKET_EXTRA_ITEMS
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

fn response_kernel_bytes(response_groups: usize) -> usize {
    assert!(response_groups >= 4);
    HYBRID_FIRST_KERNEL_BYTES
        + HYBRID_INITIALIZE_PERSISTENT_KERNEL_BYTES
        + (response_groups - 4) * HYBRID_PERSISTENT_KERNEL_BYTES
        + HYBRID_FINALIZE_PERSISTENT_KERNEL_BYTES
}

fn challenge_kernel_bytes() -> usize {
    HYBRID_INITIALIZE_PERSISTENT_KERNEL_BYTES
        + (CHALLENGE_GROUPS - 2) * HYBRID_PERSISTENT_KERNEL_BYTES
        + HYBRID_FINALIZE_PERSISTENT_KERNEL_BYTES
}

fn u5_challenge_kernel_bytes() -> usize {
    HYBRID_INITIALIZE_PERSISTENT_KERNEL_BYTES
        + (CHALLENGE_GROUPS - 2) * HYBRID_PERSISTENT_KERNEL_BYTES
        + HYBRID_U5_FINAL_TERMINAL_KERNEL_BYTES
}

fn scalar_order() -> BigUint {
    scalar_validation::scalar_order()
}

fn response_controls_low_to_high(
    scalar: &BigUint,
    widths_low_to_high: &[usize],
) -> Vec<(usize, bool)> {
    let payload =
        scalar_validation::centered_payload_for_scalar_with_widths(scalar, widths_low_to_high);
    let mut bit = 0usize;
    let mut recovered = BigInt::from(0);
    let mut controls = Vec::with_capacity(widths_low_to_high.len());
    for (group, width) in widths_low_to_high.iter().copied().enumerate() {
        let code = ((&payload >> bit) & BigUint::from((1u32 << width) - 1))
            .to_usize()
            .expect("window code fits usize");
        if group + 1 == widths_low_to_high.len() {
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

fn challenge_controls_low_to_high(bytes: &[u8; CHALLENGE_GROUPS]) -> Vec<(bool, usize)> {
    bytes
        .iter()
        .copied()
        .map(|byte| {
            if byte < 127 {
                (true, usize::from(127 - byte))
            } else {
                (false, usize::from(byte - 127))
            }
        })
        .collect()
}

fn scriptnum_item(value: i64) -> Vec<u8> {
    scalar_validation::scriptnum_item(value)
}

fn trace_packet(global_packet: usize) -> Vec<i64> {
    trace_packet_with_items(global_packet, TRACE_ITEMS_PER_PACKET)
}

fn trace_packet_with_items(global_packet: usize, items: usize) -> Vec<i64> {
    let base = 10_000 + (global_packet * 100) as i64;
    (0..items).map(|word| base + word as i64).collect()
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

fn next_input_order_hybrid_state(step: usize) -> Vec<i64> {
    let base = 60_000 + (step * 1_000) as i64;
    (0..HYBRID_STATE_ITEMS)
        .map(|item| base + item as i64)
        .collect()
}

fn initial_state_parts() -> (Vec<i64>, Vec<i64>) {
    let u = (0..16).map(|item| 50_000 + item).collect::<Vec<_>>();
    let v = (0..9).map(|item| 50_100 + item).collect::<Vec<_>>();
    (u, v)
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

const RESPONSE_POOL_SENTINEL: i64 = 7_654_321;
const CHALLENGE_POOL_SENTINEL: i64 = 7_654_322;

#[derive(Clone, Copy)]
enum PoolProbeBoundary {
    None,
    Initialize,
    VerifyAndRepark,
    VerifyAndFinalize,
}

fn verify_probe_pool_values() -> Script {
    script! {
        // Parking the ascending main-stack pool makes bit 15 the first item
        // restored from alt. Consuming all 16 reveals the phase sentinel.
        for bit in HYBRID_LATER_SHARED_POWER_BITS {
            OP_FROMALTSTACK
            { 1u32 << bit } OP_NUMEQUALVERIFY
        }
    }
}

fn kernel_stub_with_pool_boundary(
    expected_input: Vec<i64>,
    output: Vec<i64>,
    boundary: PoolProbeBoundary,
) -> Script {
    script! {
        { verify_values(&expected_input) }
        if matches!(boundary, PoolProbeBoundary::Initialize) {
            { initialize_hybrid_persistent_shared_power_pool() }
        } else if matches!(boundary, PoolProbeBoundary::VerifyAndRepark) {
            { verify_probe_pool_values() }
            { initialize_hybrid_persistent_shared_power_pool() }
        } else if matches!(boundary, PoolProbeBoundary::VerifyAndFinalize) {
            { verify_probe_pool_values() }
        }
        { push_values(&output) }
    }
}

fn synthetic_response_stream(
    scalar_controls: &[(usize, bool)],
    widths_low_to_high: &[usize],
    final_state: &mut Vec<i64>,
) -> Script {
    let response_groups = widths_low_to_high.len();
    let response_transitions = response_groups - 1;
    assert_eq!(scalar_controls.len(), response_groups);
    let (initial_u, initial_v) = initial_state_parts();
    let top_magnitude = scalar_controls[response_groups - 1].0;
    assert!(!scalar_controls[response_groups - 1].1);
    let top = script! {
        { top_magnitude as u32 } OP_NUMEQUALVERIFY
        { push_values(&initial_u) }
        { push_values(&initial_v) }
        { orient_initial_state() }
    };

    let scalar_states = scalar_items_after_response_transitions(widths_low_to_high);
    let mut callbacks = Vec::with_capacity(response_transitions);
    let mut current = [initial_v, initial_u].concat();
    for (transition, scalar_items) in scalar_states.into_iter().enumerate() {
        let group = response_groups - transition - 2;
        let (magnitude, negative) = scalar_controls[group];
        let packet = trace_packet(response_transitions - transition - 1);
        let selected = selected_point(group, negative);
        let expected_input = [packet, selected, current.clone()].concat();
        let output = next_input_order_hybrid_state(transition);
        let pool_boundary = if transition == 0 {
            PoolProbeBoundary::None
        } else if transition == 1 {
            PoolProbeBoundary::Initialize
        } else if transition + 1 == response_transitions {
            PoolProbeBoundary::VerifyAndFinalize
        } else {
            PoolProbeBoundary::VerifyAndRepark
        };
        callbacks.push(response_transition_callback(
            transition,
            scalar_items,
            widths_low_to_high[group],
            table_stub(group, magnitude),
            kernel_stub_with_pool_boundary(expected_input, output.clone(), pool_boundary),
        ));
        current = output;
    }
    *final_state = current;
    response_scalar_stream_for_widths(widths_low_to_high, top, &callbacks)
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
    response_transitions: usize,
    starting_state: &[i64],
    final_state: &mut Vec<i64>,
) -> Script {
    assert_eq!(controls.len(), CHALLENGE_GROUPS);
    let mut steps = Vec::with_capacity(CHALLENGE_GROUPS);
    let mut current = starting_state.to_vec();
    for transition in 0..CHALLENGE_GROUPS {
        let group = CHALLENGE_GROUPS - transition - 1;
        let (negative, magnitude) = controls[group];
        let packet = trace_packet(response_transitions + group);
        let selected = selected_point(response_transitions + 1 + group, negative);
        let expected_input = [packet, selected, current.clone()].concat();
        let output = next_input_order_hybrid_state(response_transitions + transition);
        let pool_boundary = if transition == 0 {
            PoolProbeBoundary::Initialize
        } else if transition + 1 == CHALLENGE_GROUPS {
            PoolProbeBoundary::VerifyAndFinalize
        } else {
            PoolProbeBoundary::VerifyAndRepark
        };
        steps.push(challenge_transition_callback(
            transition,
            table_stub(response_transitions + 1 + group, magnitude),
            kernel_stub_with_pool_boundary(expected_input, output.clone(), pool_boundary),
        ));
        current = output;
    }
    *final_state = current;
    script! { for step in steps { { step } } }
}

fn synthetic_u5_challenge_schedule(
    controls: &[(bool, usize)],
    response_transitions: usize,
    starting_state: &[i64],
) -> Script {
    assert_eq!(controls.len(), CHALLENGE_GROUPS);
    let mut steps = Vec::with_capacity(CHALLENGE_GROUPS);
    let mut current = starting_state.to_vec();
    for transition in 0..CHALLENGE_GROUPS {
        let group = CHALLENGE_GROUPS - transition - 1;
        let (negative, magnitude) = controls[group];
        let packet_items = if transition + 1 == CHALLENGE_GROUPS {
            U5_FINAL_PACKET_ITEMS
        } else {
            TRACE_ITEMS_PER_PACKET
        };
        let packet = trace_packet_with_items(response_transitions + group, packet_items);
        let selected = selected_point(response_transitions + 1 + group, negative);
        let expected_input = [packet, selected, current.clone()].concat();
        let output = if transition + 1 == CHALLENGE_GROUPS {
            vec![1]
        } else {
            next_input_order_hybrid_state(response_transitions + transition)
        };
        let pool_boundary = if transition == 0 {
            PoolProbeBoundary::Initialize
        } else if transition + 1 == CHALLENGE_GROUPS {
            PoolProbeBoundary::VerifyAndFinalize
        } else {
            PoolProbeBoundary::VerifyAndRepark
        };
        steps.push(challenge_transition_callback_with_packet_items(
            transition,
            packet_items,
            table_stub(response_transitions + 1 + group, magnitude),
            kernel_stub_with_pool_boundary(expected_input, output.clone(), pool_boundary),
        ));
        current = output;
    }
    script! { for step in steps { { step } } }
}

fn entry_witness(scalar: &BigUint, widths_low_to_high: &[usize]) -> Vec<Vec<u8>> {
    let response_transitions = widths_low_to_high.len() - 1;
    let entry_items = hybrid_entry_items_for_widths(widths_low_to_high);
    let mut witness = Vec::with_capacity(entry_items);
    for packet in response_transitions..response_transitions + CHALLENGE_GROUPS {
        witness.extend(trace_packet(packet).into_iter().map(scriptnum_item));
    }
    for packet in 0..response_transitions {
        witness.extend(trace_packet(packet).into_iter().map(scriptnum_item));
    }
    let payload =
        scalar_validation::centered_payload_for_scalar_with_widths(scalar, widths_low_to_high);
    witness.extend(
        scalar_validation::words_from_payload(&payload)
            .into_iter()
            .map(|word| scriptnum_item(i64::from(word as i32))),
    );
    assert_eq!(witness.len(), entry_items);
    witness
}

fn u5_entry_witness(scalar: &BigUint, widths_low_to_high: &[usize]) -> Vec<Vec<u8>> {
    let response_transitions = widths_low_to_high.len() - 1;
    let entry_items = hybrid_u5_entry_items_for_widths(widths_low_to_high);
    let mut witness = Vec::with_capacity(entry_items);
    // The final/lowest challenge packet is `u5[51] | lambda_packed[8]`.
    witness.extend(
        trace_packet_with_items(response_transitions, U5_FINAL_PACKET_ITEMS)
            .into_iter()
            .map(scriptnum_item),
    );
    for packet in response_transitions + 1..response_transitions + CHALLENGE_GROUPS {
        witness.extend(trace_packet(packet).into_iter().map(scriptnum_item));
    }
    for packet in 0..response_transitions {
        witness.extend(trace_packet(packet).into_iter().map(scriptnum_item));
    }
    let payload =
        scalar_validation::centered_payload_for_scalar_with_widths(scalar, widths_low_to_high);
    witness.extend(
        scalar_validation::words_from_payload(&payload)
            .into_iter()
            .map(|word| scriptnum_item(i64::from(word as i32))),
    );
    assert_eq!(witness.len(), entry_items);
    witness
}

#[derive(Debug)]
struct ScheduleReport {
    name: &'static str,
    response_groups: usize,
    entry_items: usize,
    validator_raw: usize,
    validator_policy: usize,
    response_scaffolding_raw: usize,
    response_scaffolding_policy: usize,
    challenge_scaffolding_raw: usize,
    challenge_scaffolding_policy: usize,
    strict_synthetic_raw: usize,
    strict_synthetic_policy: usize,
    strict_synthetic_peak: usize,
    first_preserved: usize,
    max_chained_preserved: usize,
    max_chained_preserved_phase: &'static str,
    max_chained_preserved_transition: usize,
    chained_kernel_count: usize,
    kernel_bytes: usize,
    non_table_scheduler_and_kernel_raw: usize,
    analytical_combined_peak: usize,
    analytical_peak_phase: &'static str,
    analytical_peak_transition: usize,
    response_table_bytes: usize,
    response_schedule_bytes: usize,
    challenge_schedule_bytes: usize,
    projected_packed_r_leaf_bytes: usize,
}

fn run_schedule(name: &'static str, widths_low_to_high: &[usize]) -> ScheduleReport {
    let response_groups = widths_low_to_high.len();
    let response_transitions = response_groups - 1;
    let entry_items = hybrid_entry_items_for_widths(widths_low_to_high);
    let scalar = BigUint::from(987_654_321u64);
    assert!(scalar < scalar_order());
    let scalar_controls = response_controls_low_to_high(&scalar, widths_low_to_high);
    let challenge_bytes: [u8; CHALLENGE_GROUPS] =
        std::array::from_fn(|index| [0x00, 0x7f, 0x80, 0xff][index % 4]);
    let challenge_controls = challenge_controls_low_to_high(&challenge_bytes);
    assert_eq!(challenge_controls[0], (true, 127));
    assert_eq!(challenge_controls[1], (false, 0));
    assert_eq!(challenge_controls[2], (false, 1));
    assert_eq!(challenge_controls[3], (false, 128));

    let validator = hybrid_scalar_validator_for_widths(widths_low_to_high);
    let mut post_response_state = Vec::new();
    let response = synthetic_response_stream(
        &scalar_controls,
        widths_low_to_high,
        &mut post_response_state,
    );
    let mut final_state = Vec::new();
    let challenge = synthetic_challenge_schedule(
        &challenge_controls,
        response_transitions,
        &post_response_state,
        &mut final_state,
    );
    let strict_fragment = script! {
        { validator.clone() }
        { RESPONSE_POOL_SENTINEL } OP_TOALTSTACK
        { response }
        OP_FROMALTSTACK { RESPONSE_POOL_SENTINEL } OP_NUMEQUALVERIFY
        { push_challenge_controls(&challenge_controls) }
        { CHALLENGE_POOL_SENTINEL } OP_TOALTSTACK
        { challenge }
        OP_FROMALTSTACK { CHALLENGE_POOL_SENTINEL } OP_NUMEQUALVERIFY
        { verify_values(&final_state) }
        OP_1
    };
    let strict_synthetic_raw = strict_fragment.len();
    let strict_script = strict_fragment.compile_with_policy();
    let strict_synthetic_policy = strict_script.len();
    let witness = entry_witness(&scalar, widths_low_to_high);
    let execution =
        execute_raw_script_with_inputs_strict(strict_script.to_bytes(), witness.clone());
    assert!(
        execution.error.is_none(),
        "{name} hybrid scheduler: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);

    let mut bad_response = witness.clone();
    let top_response_word0 = CHALLENGE_GROUPS * TRACE_ITEMS_PER_PACKET
        + (response_transitions - 1) * TRACE_ITEMS_PER_PACKET;
    bad_response[top_response_word0] = scriptnum_item(-77);
    let rejected_response =
        execute_raw_script_with_inputs_strict(strict_script.to_bytes(), bad_response);
    assert!(rejected_response.error.is_some());

    let mut bad_challenge = witness;
    let top_challenge_word15 =
        (CHALLENGE_GROUPS - 1) * TRACE_ITEMS_PER_PACKET + TRACE_ITEMS_PER_PACKET - 1;
    bad_challenge[top_challenge_word15] = scriptnum_item(-88);
    let rejected_challenge =
        execute_raw_script_with_inputs_strict(strict_script.to_bytes(), bad_challenge);
    assert!(rejected_challenge.error.is_some());

    let response_scaffolding = hybrid_response_scaffolding_for_widths(widths_low_to_high);
    let challenge_scaffolding = hybrid_challenge_scaffolding();
    let scalar_states = scalar_items_after_response_transitions(widths_low_to_high);
    let first_preserved = response_preserved_items(response_transitions, 0, scalar_states[0]);
    let mut max_chained_preserved = 0usize;
    let mut max_chained_combined_peak = 0usize;
    let mut max_chained_preserved_phase = "response";
    let mut max_chained_preserved_transition = 1usize;
    for (transition, scalar_items) in scalar_states.iter().copied().enumerate().skip(1) {
        let preserved = response_preserved_items(response_transitions, transition, scalar_items);
        let local_peak = if transition == 1 {
            HYBRID_INITIALIZE_PERSISTENT_LOCAL_PEAK
        } else {
            HYBRID_PERSISTENT_LOCAL_PEAK
        };
        let combined_peak = preserved + local_peak;
        if combined_peak > max_chained_combined_peak {
            max_chained_preserved = preserved;
            max_chained_combined_peak = combined_peak;
            max_chained_preserved_phase = "response";
            max_chained_preserved_transition = transition;
        }
    }
    for transition in 0..CHALLENGE_GROUPS {
        let preserved = challenge_preserved_items(transition);
        let local_peak = if transition == 0 {
            HYBRID_INITIALIZE_PERSISTENT_LOCAL_PEAK
        } else {
            HYBRID_PERSISTENT_LOCAL_PEAK
        };
        let combined_peak = preserved + local_peak;
        if combined_peak > max_chained_combined_peak {
            max_chained_preserved = preserved;
            max_chained_combined_peak = combined_peak;
            max_chained_preserved_phase = "challenge";
            max_chained_preserved_transition = transition;
        }
    }

    let first_combined_peak = first_preserved + HYBRID_FIRST_LOCAL_PEAK;
    let chained_combined_peak = max_chained_combined_peak;
    let validator_combined_peak = entry_items + 16;
    let (analytical_combined_peak, analytical_peak_phase, analytical_peak_transition) =
        if first_combined_peak >= chained_combined_peak
            && first_combined_peak >= validator_combined_peak
            && first_combined_peak >= execution.stats.max_nb_stack_items
        {
            (first_combined_peak, "response-first-kernel", 0)
        } else if chained_combined_peak >= validator_combined_peak
            && chained_combined_peak >= execution.stats.max_nb_stack_items
        {
            (
                chained_combined_peak,
                max_chained_preserved_phase,
                max_chained_preserved_transition,
            )
        } else if validator_combined_peak >= execution.stats.max_nb_stack_items {
            (validator_combined_peak, "scalar-validator", 0)
        } else {
            (execution.stats.max_nb_stack_items, "synthetic-routing", 0)
        };
    let chained_kernel_count = response_transitions - 1 + CHALLENGE_GROUPS;
    let kernel_bytes = response_kernel_bytes(response_groups) + challenge_kernel_bytes();
    let validator_raw = raw_fragment_len(&validator);
    let validator_policy = validator.clone().compile_with_policy().len();
    let response_scaffolding_raw = raw_fragment_len(&response_scaffolding);
    let challenge_scaffolding_raw = raw_fragment_len(&challenge_scaffolding);
    let response_table_bytes = match name {
        "g31" => G31_RESPONSE_TABLE_BYTES,
        "g32" => G32_PARITY_CORRECT_RESPONSE_TABLE_BYTES,
        _ => panic!("unaccounted response schedule"),
    };
    let response_schedule_bytes =
        response_table_bytes + response_scaffolding_raw + response_kernel_bytes(response_groups);
    let challenge_schedule_bytes =
        CHALLENGE_TABLE_BYTES + challenge_scaffolding_raw + challenge_kernel_bytes();
    let projected_packed_r_leaf_bytes = validator_policy
        + response_schedule_bytes
        + PACKED_R_HASH_BYTES_AT_HYBRID_BOUNDARY
        + INDEPENDENT_BYTE_RECODER_BYTES
        + challenge_schedule_bytes
        + HYBRID_TERMINAL_BYTES;

    ScheduleReport {
        name,
        response_groups,
        entry_items,
        validator_raw,
        validator_policy,
        response_scaffolding_raw,
        response_scaffolding_policy: response_scaffolding.compile_with_policy().len(),
        challenge_scaffolding_raw,
        challenge_scaffolding_policy: challenge_scaffolding.compile_with_policy().len(),
        strict_synthetic_raw,
        strict_synthetic_policy,
        strict_synthetic_peak: execution.stats.max_nb_stack_items,
        first_preserved,
        max_chained_preserved,
        max_chained_preserved_phase,
        max_chained_preserved_transition,
        chained_kernel_count,
        kernel_bytes,
        non_table_scheduler_and_kernel_raw: validator_raw
            + response_scaffolding_raw
            + challenge_scaffolding_raw
            + kernel_bytes,
        analytical_combined_peak,
        analytical_peak_phase,
        analytical_peak_transition,
        response_table_bytes,
        response_schedule_bytes,
        challenge_schedule_bytes,
        projected_packed_r_leaf_bytes,
    }
}

fn print_report(report: &ScheduleReport) {
    println!("schedule={}", report.name);
    println!("response_groups={}", report.response_groups);
    println!("response_transitions={}", report.response_groups - 1);
    println!("challenge_transitions={CHALLENGE_GROUPS}");
    println!("trace_packet_items={TRACE_ITEMS_PER_PACKET}");
    println!("quotient_hint_items=0");
    println!("shared_power_pool_items_first={HYBRID_FIRST_SHARED_POWER_ITEM_COUNT}");
    println!("shared_power_pool_items_later={HYBRID_LATER_SHARED_POWER_ITEM_COUNT}");
    println!("shared_power_pool_is_script_authored=true");
    println!("shared_power_pool_added_hint_items=0");
    println!("scalar_items={SCALAR_WORDS}");
    println!("complete_entry_items={}", report.entry_items);
    println!("all_entry_items_coexist=true");
    println!("hybrid_state_items={HYBRID_STATE_ITEMS}");
    println!("hybrid_state_layout=b9|a16|lambda_biased_digits51|u16");
    println!("hybrid_state_is_already_in_next_input_order=true");
    println!("hash_boundary_preserved_items={HYBRID_HASH_PRESERVED_ITEMS}");
    println!("hash_boundary_r_word0_depth={HYBRID_HASH_R_WORD0_DEPTH}");
    println!("retained_r_copy_items_through_challenge=0");
    println!("scalar_validator_raw_bytes={}", report.validator_raw);
    println!("scalar_validator_policy_bytes={}", report.validator_policy);
    println!(
        "response_scaffolding_raw_bytes={}",
        report.response_scaffolding_raw
    );
    println!(
        "response_scaffolding_policy_bytes={}",
        report.response_scaffolding_policy
    );
    println!(
        "challenge_scaffolding_raw_bytes={}",
        report.challenge_scaffolding_raw
    );
    println!(
        "challenge_scaffolding_policy_bytes={}",
        report.challenge_scaffolding_policy
    );
    println!(
        "scheduler_scaffolding_raw_bytes={}",
        report.response_scaffolding_raw + report.challenge_scaffolding_raw
    );
    println!("strict_synthetic_raw_bytes={}", report.strict_synthetic_raw);
    println!(
        "strict_synthetic_policy_bytes={}",
        report.strict_synthetic_policy
    );
    println!(
        "strict_synthetic_combined_stack_peak={}",
        report.strict_synthetic_peak
    );
    println!("first_kernel_preserved_items={}", report.first_preserved);
    println!(
        "max_chained_kernel_preserved_items={}",
        report.max_chained_preserved
    );
    println!(
        "max_chained_kernel_preserved_phase={}",
        report.max_chained_preserved_phase
    );
    println!(
        "max_chained_kernel_preserved_transition={}",
        report.max_chained_preserved_transition
    );
    println!("hybrid_first_kernel_bytes={HYBRID_FIRST_KERNEL_BYTES}");
    println!("hybrid_first_kernel_local_peak={HYBRID_FIRST_LOCAL_PEAK}");
    println!(
        "hybrid_initialize_persistent_kernel_bytes={HYBRID_INITIALIZE_PERSISTENT_KERNEL_BYTES}"
    );
    println!(
        "hybrid_initialize_persistent_kernel_local_peak={HYBRID_INITIALIZE_PERSISTENT_LOCAL_PEAK}"
    );
    println!("hybrid_persistent_kernel_bytes={HYBRID_PERSISTENT_KERNEL_BYTES}");
    println!("hybrid_persistent_kernel_local_peak={HYBRID_PERSISTENT_LOCAL_PEAK}");
    println!("hybrid_finalize_persistent_kernel_bytes={HYBRID_FINALIZE_PERSISTENT_KERNEL_BYTES}");
    println!(
        "hybrid_finalize_persistent_kernel_local_peak={HYBRID_FINALIZE_PERSISTENT_LOCAL_PEAK}"
    );
    println!(
        "hybrid_chained_kernel_count={}",
        report.chained_kernel_count
    );
    println!("hybrid_all_kernel_bytes={}", report.kernel_bytes);
    println!(
        "non_table_scheduler_and_kernel_raw_bytes={}",
        report.non_table_scheduler_and_kernel_raw
    );
    println!(
        "analytical_max_combined_stack_items={}",
        report.analytical_combined_peak
    );
    println!("analytical_peak_phase={}", report.analytical_peak_phase);
    println!(
        "analytical_peak_transition={}",
        report.analytical_peak_transition
    );
    println!("response_table_bytes={}", report.response_table_bytes);
    println!(
        "response_schedule_projected_bytes={}",
        report.response_schedule_bytes
    );
    println!("challenge_table_bytes={CHALLENGE_TABLE_BYTES}");
    println!(
        "challenge_schedule_projected_bytes={}",
        report.challenge_schedule_bytes
    );
    println!("packed_r_hash_bytes_at_hybrid_boundary={PACKED_R_HASH_BYTES_AT_HYBRID_BOUNDARY}");
    println!("independent_byte_recoder_bytes={INDEPENDENT_BYTE_RECODER_BYTES}");
    println!("hybrid_terminal_bytes={HYBRID_TERMINAL_BYTES}");
    println!(
        "projected_packed_r_hybrid_leaf_bytes={}",
        report.projected_packed_r_leaf_bytes
    );
    println!("response_packet_order_mutation_rejected=true");
    println!("challenge_packet_order_mutation_rejected=true");
    println!("response_pool_survived_all_callbacks=true");
    println!("challenge_pool_survived_all_callbacks=true");
    println!("response_hash_boundary_alt_pool_items=0");
    println!("terminal_alt_pool_items=0");
    println!("independent_byte_boundaries_tested=00,7f,80,ff");
    println!("authenticated_tables_built=false");
    println!("blake3_built_or_executed=false");
    println!("field_relation_built_or_executed=false");
    println!("full_leaf_built_or_executed=false");
    if report.name == "g32" {
        println!("parity_correct_top_initializer=U_minus_K127A_without_initial_T");
        println!("pre_parity_fix_g32_table_cost_reused=false");
    }
}

fn run_g32_u5_final_shape() {
    let widths = g32_widths_low_to_high();
    let response_transitions = widths.len() - 1;
    let entry_items = hybrid_u5_entry_items_for_widths(&widths);
    assert_eq!(entry_items, 803);
    assert_eq!(HYBRID_U5_HASH_PRESERVED_ITEMS, 391);
    assert_eq!(HYBRID_U5_HASH_R_DIGIT0_DEPTH, 340);

    let scalar = BigUint::from(987_654_321u64);
    let scalar_controls = response_controls_low_to_high(&scalar, &widths);
    let challenge_bytes: [u8; CHALLENGE_GROUPS] =
        std::array::from_fn(|index| [0x00, 0x7f, 0x80, 0xff][index % 4]);
    let challenge_controls = challenge_controls_low_to_high(&challenge_bytes);
    let validator = hybrid_u5_scalar_validator_for_widths(&widths);
    let mut post_response_state = Vec::new();
    let response = synthetic_response_stream(&scalar_controls, &widths, &mut post_response_state);
    let challenge = synthetic_u5_challenge_schedule(
        &challenge_controls,
        response_transitions,
        &post_response_state,
    );
    let strict_fragment = script! {
        { validator.clone() }
        { RESPONSE_POOL_SENTINEL } OP_TOALTSTACK
        { response }
        OP_FROMALTSTACK { RESPONSE_POOL_SENTINEL } OP_NUMEQUALVERIFY
        { push_challenge_controls(&challenge_controls) }
        { CHALLENGE_POOL_SENTINEL } OP_TOALTSTACK
        { challenge }
        OP_FROMALTSTACK { CHALLENGE_POOL_SENTINEL } OP_NUMEQUALVERIFY
    };
    let strict_raw = strict_fragment.len();
    let strict_script = strict_fragment.compile_with_policy();
    let witness = u5_entry_witness(&scalar, &widths);
    let execution =
        execute_raw_script_with_inputs_strict(strict_script.to_bytes(), witness.clone());
    assert!(
        execution.error.is_none(),
        "G32 hybrid-u5 synthetic schedule: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);

    let mut bad_final_r = witness.clone();
    bad_final_r[0] = scriptnum_item(-77);
    let rejected_final_r =
        execute_raw_script_with_inputs_strict(strict_script.to_bytes(), bad_final_r);
    assert!(rejected_final_r.error.is_some());

    let challenge_trace_items =
        CHALLENGE_GROUPS * TRACE_ITEMS_PER_PACKET + U5_FINAL_PACKET_EXTRA_ITEMS;
    let mut bad_response = witness;
    let top_response_word0 =
        challenge_trace_items + (response_transitions - 1) * TRACE_ITEMS_PER_PACKET;
    bad_response[top_response_word0] = scriptnum_item(-88);
    let rejected_response =
        execute_raw_script_with_inputs_strict(strict_script.to_bytes(), bad_response);
    assert!(rejected_response.error.is_some());

    let validator_raw = raw_fragment_len(&validator);
    let validator_policy = validator.compile_with_policy().len();
    let response_scaffolding_raw =
        raw_fragment_len(&hybrid_response_scaffolding_for_widths(&widths));
    let challenge_scaffolding = hybrid_u5_challenge_scaffolding();
    let challenge_scaffolding_raw = raw_fragment_len(&challenge_scaffolding);
    let challenge_scaffolding_policy = challenge_scaffolding.compile_with_policy().len();
    assert_eq!(validator_raw, 791);
    assert_eq!(validator_policy, 774);
    assert_eq!(response_scaffolding_raw, 14_701);
    assert_eq!(challenge_scaffolding_raw, 5_829);

    let response_schedule_bytes = G32_PARITY_CORRECT_RESPONSE_TABLE_BYTES
        + response_scaffolding_raw
        + response_kernel_bytes(widths.len());
    let challenge_schedule_bytes =
        CHALLENGE_TABLE_BYTES + challenge_scaffolding_raw + u5_challenge_kernel_bytes();
    let projected_leaf_bytes = validator_policy
        + response_schedule_bytes
        + HYBRID_U5_HASH_BYTES
        + INDEPENDENT_BYTE_RECODER_BYTES
        + challenge_schedule_bytes;
    assert_eq!(response_schedule_bytes, 1_931_479);
    assert_eq!(challenge_schedule_bytes, 1_000_204);
    assert_eq!(projected_leaf_bytes, EXPECTED_G32_U5_HYBRID_LEAF_BYTES);
    assert_eq!(
        EXPECTED_G32_PACKED_R_HYBRID_LEAF_BYTES - projected_leaf_bytes,
        5_288
    );

    let scalar_states = scalar_items_after_response_transitions(&widths);
    let first_preserved = response_preserved_items_with_extra(
        response_transitions,
        0,
        scalar_states[0],
        U5_FINAL_PACKET_EXTRA_ITEMS,
    );
    let first_combined_peak = first_preserved + HYBRID_FIRST_LOCAL_PEAK;
    let chained_preserved = response_preserved_items_with_extra(
        response_transitions,
        1,
        scalar_states[1],
        U5_FINAL_PACKET_EXTRA_ITEMS,
    );
    let chained_combined_peak = chained_preserved + HYBRID_INITIALIZE_PERSISTENT_LOCAL_PEAK;
    let persistent_preserved = response_preserved_items_with_extra(
        response_transitions,
        2,
        scalar_states[2],
        U5_FINAL_PACKET_EXTRA_ITEMS,
    );
    let persistent_combined_peak = persistent_preserved + HYBRID_PERSISTENT_LOCAL_PEAK;
    assert_eq!(first_preserved, 787);
    assert_eq!(chained_preserved, 771);
    assert_eq!(persistent_preserved, 754);
    assert_eq!(first_combined_peak, 999);
    assert_eq!(chained_combined_peak, 995);
    assert_eq!(persistent_combined_peak, 994);
    assert_eq!(HYBRID_U5_FINAL_LOCAL_PEAK, 283);

    println!("schedule=g32-u5-final");
    println!("complete_entry_items={entry_items}");
    println!("quotient_hint_items=0");
    println!("final_r_u5_items={U5_FINAL_R_ITEMS}");
    println!("final_packet_items={U5_FINAL_PACKET_ITEMS}");
    println!("entry_item_delta_vs_packed_r={U5_FINAL_PACKET_EXTRA_ITEMS}");
    println!("fixture_witness_byte_delta_vs_packed_r=62");
    println!("hash_boundary_preserved_items={HYBRID_U5_HASH_PRESERVED_ITEMS}");
    println!("hash_boundary_r_digit0_depth={HYBRID_U5_HASH_R_DIGIT0_DEPTH}");
    println!("scalar_validator_raw_bytes={validator_raw}");
    println!("scalar_validator_policy_bytes={validator_policy}");
    println!("response_scaffolding_raw_bytes={response_scaffolding_raw}");
    println!("challenge_scaffolding_raw_bytes={challenge_scaffolding_raw}");
    println!("challenge_scaffolding_policy_bytes={challenge_scaffolding_policy}");
    println!("final_packet_routing_raw_increment_bytes=129");
    println!("u5_hash_policy_bytes={HYBRID_U5_HASH_BYTES}");
    println!("u5_final_terminal_kernel_bytes={HYBRID_U5_FINAL_TERMINAL_KERNEL_BYTES}");
    println!("u5_final_terminal_kernel_local_peak={HYBRID_U5_FINAL_LOCAL_PEAK}");
    println!("response_schedule_projected_bytes={response_schedule_bytes}");
    println!("challenge_schedule_projected_bytes={challenge_schedule_bytes}");
    println!("projected_u5_hybrid_leaf_bytes={projected_leaf_bytes}");
    println!("script_saving_vs_packed_r_hybrid_bytes=5288");
    println!("shared_power_pool_items_first={HYBRID_FIRST_SHARED_POWER_ITEM_COUNT}");
    println!("shared_power_pool_items_later={HYBRID_LATER_SHARED_POWER_ITEM_COUNT}");
    println!("shared_power_pool_is_script_authored=true");
    println!("shared_power_pool_added_hint_items=0");
    println!("response_hash_boundary_alt_pool_items=0");
    println!("terminal_alt_pool_items=0");
    println!("analytical_max_combined_stack_items={first_combined_peak}");
    println!("analytical_peak_locations=response_transition_0");
    println!("response_transition_0_preserved_items={first_preserved}");
    println!("response_transition_1_preserved_items={chained_preserved}");
    println!("response_transition_2_preserved_items={persistent_preserved}");
    println!("response_transition_2_combined_peak={persistent_combined_peak}");
    println!("strict_synthetic_raw_bytes={strict_raw}");
    println!("strict_synthetic_policy_bytes={}", strict_script.len());
    println!(
        "strict_synthetic_combined_stack_peak={}",
        execution.stats.max_nb_stack_items
    );
    println!("final_r_packet_mutation_rejected=true");
    println!("response_packet_mutation_rejected=true");
    println!("full_leaf_built_or_executed=false");
}

fn main() {
    assert_eq!(HYBRID_STATE_ITEMS, 92);
    assert_eq!(HYBRID_STATE_ITEM_COUNT, HYBRID_STATE_ITEMS);
    assert_eq!(FIRST_DERIVED_COMPLETE_INPUT_ITEM_COUNT, 66);
    assert_eq!(HYBRID_CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT, 133);
    assert_eq!(HYBRID_HASH_PRESERVED_ITEMS, 348);
    assert_eq!(HYBRID_HASH_R_WORD0_DEPTH, 340);
    let reports = [
        run_schedule("g31", &g31_widths_low_to_high()),
        run_schedule("g32", &g32_widths_low_to_high()),
    ];
    assert_eq!(
        reports[0].projected_packed_r_leaf_bytes,
        EXPECTED_G31_PACKED_R_HYBRID_LEAF_BYTES
    );
    assert_eq!(
        reports[1].projected_packed_r_leaf_bytes,
        EXPECTED_G32_PACKED_R_HYBRID_LEAF_BYTES
    );
    assert_eq!(
        reports[0].projected_packed_r_leaf_bytes - reports[1].projected_packed_r_leaf_bytes,
        18_091
    );
    println!("model=ed25519_montgomery_h16_hybrid_scheduler");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=item-order");
    println!("execution_class=unclassified");
    println!("kernel_internal_order=previous_lambda_product_then_drop_old_state_then_decode_next_lambda_then_continuity_then_curve");
    for report in &reports {
        print_report(report);
    }
    run_g32_u5_final_shape();
}
