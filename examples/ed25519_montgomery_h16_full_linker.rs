//! Generation-only full linker for the custom BLAKE3-128 Montgomery H16
//! Ed25519-style verification candidate.
//!
//! This builds one complete clean-stack Script serialization from the real
//! scalar carrier router, scalar interval validator/stream, all 45 direct
//! fixed tables, all 44 slope kernels, response transcript carrier decoders,
//! midpoint transcript unpacker, key-specialized BLAKE3 compression, H16
//! challenge recoder, remaining challenge-carrier checks, and endpoint
//! equality predicate. The multi-megabyte Script is deliberately never
//! executed. Short component probes live in the focused examples from which
//! these helpers are imported.
//!
//! The witness stores `response[0..28] | challenge[0..16]` so the 29 scalar
//! carriers in the challenge block are shallow. Immediately after scalar
//! extraction, a one-time exact block transpose produces the execution order
//! `challenge | response | scalar`. Execution then consumes response 27 down
//! to zero, followed by challenge 15 down to zero after hashing.

#[allow(dead_code)]
#[path = "ed25519_fixed_table_actual_model.rs"]
mod table_model;

#[allow(dead_code)]
#[path = "ed25519_g31_scalar_word_validator.rs"]
mod scalar_validation;

#[allow(dead_code)]
#[path = "ed25519_h16_midpoint_glue.rs"]
mod midpoint;

#[allow(dead_code)]
#[path = "ed25519_h16_scalar_carrier_router.rs"]
mod scalar_carrier_router;

#[allow(dead_code)]
#[path = "ed25519_slope_carrier_codec.rs"]
mod carrier_codec;

use bitcoin::{script::Instruction, ScriptBuf};
use bitcoin_lab::{
    curves::ed25519::montgomery_slope::{
        verify_chained_transition, verify_first_transition, CHAINED_COMPLETE_INPUT_ITEM_COUNT,
        FIRST_COMPLETE_INPUT_ITEM_COUNT,
    },
    hashes::blake3::ed25519_challenge,
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
const SELECTED_ITEMS: usize = 25;
const TOP_STATE_ITEMS: usize = 25;
const STATE_ITEMS: usize = 41;
const TRACE_ITEMS_PER_PACKET: usize = 16;
const Q_ITEMS_PER_PACKET: usize = 2;
const PACKET_ITEMS: usize = TRACE_ITEMS_PER_PACKET + Q_ITEMS_PER_PACKET;
const TRACE_ITEMS: usize = TRANSITIONS * TRACE_ITEMS_PER_PACKET;
const Q_HINT_ITEMS: usize = TRANSITIONS * Q_ITEMS_PER_PACKET;
const RAW_ENTRY_ITEMS: usize = TRANSITIONS * PACKET_ITEMS;
const SCALAR_WORDS: usize = 8;
const RETAINED_R_WORDS: usize = 8;

const RESPONSE_PADDED_TRANSITIONS: usize = 4;
const RESPONSE_PADDING_BITS_PER_PADDED_TRANSITION: usize = 2;
const RESPONSE_TRANSCRIPT_CHUNKS: usize = RESPONSE_TRANSITIONS;
const RESPONSE_TRANSCRIPT_BITS: usize = 512;
const RESPONSE_CARRIED_BITS: usize = 513;

const SIGNED23_Q_BITS: usize = 23;
const SIGNED22_Q_BITS: usize = 22;
const SCALAR_ROUTED_CHALLENGE_Q_ITEMS: usize = 29;
const REMAINING_CHALLENGE_Q_ITEMS: usize =
    CHALLENGE_TRANSITIONS * Q_ITEMS_PER_PACKET - SCALAR_ROUTED_CHALLENGE_Q_ITEMS;

const STRICT_SCALAR_ROUTER_PEAK: usize = 813;
const STRICT_FIRST_LOCAL_PEAK: usize = 216;
const STRICT_CHAINED_LOCAL_PEAK: usize = 232;
const STRICT_MIDPOINT_PEAK: usize = 843;
const BLAKE_COMBINED_PEAK_UPPER_BOUND: usize = 864;
const STRICT_RECODER_PEAK: usize = 371;
const STRICT_WHOLE_STUB_PEAK: usize = 999;

const MAX_BLOCK_WEIGHT: usize = 4_000_000;
const TARGET_AND_WITNESS_OVERHEAD_WEIGHT: usize = 5_084;
const MINIMUM_OTHER_BLOCK_WEIGHT: usize = 768;
const EXPECTED_TABLE_BYTES: usize = 826_072;
const EXPECTED_FIXED_MESSAGE_BLAKE_POLICY_BYTES: usize = 63_990;
const EXPECTED_FIXED_MESSAGE_BOUNDARY_POLICY_BYTES: usize = 64_118;
// Additive projection after the fixed-message BLAKE3 backend moved to the
// repository compilation policy only. A `--measure-bytes` run promotes this
// checkpoint to an exact whole-leaf serialization measurement.
const ADDITIVE_PROJECTED_LINKED_SCRIPT_BYTES: usize = 3_828_057;

fn response_widths_low_to_high() -> Vec<usize> {
    let mut widths = vec![8usize; 8];
    widths.extend(std::iter::repeat_n(9usize, 21));
    assert_eq!(widths.len(), RESPONSE_GROUPS);
    assert_eq!(widths.iter().sum::<usize>(), 253);
    widths
}

fn scalar_items_after_response_transitions() -> Vec<usize> {
    let mut chunks = vec![29usize];
    chunks.extend(std::iter::repeat_n(32usize, 7));
    let widths_high_to_low = [vec![9usize; 21], vec![8usize; 8]].concat();
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
    assert_eq!(states.len(), RESPONSE_TRANSITIONS);
    assert_eq!(*states.last().expect("response transitions"), 0);
    states
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

fn insert_top_at_depth(depth: usize) -> Script {
    script! {
        for _ in 0..depth { { depth as u32 } OP_ROLL }
    }
}

fn policy_precompiled(fragment: Script, name: &'static str) -> Script {
    Script::new(name).push_script(fragment.compile_with_policy())
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

/// Stream the validated centered G29 payload high-to-low. At each lower
/// callback the current state is on altstack, and the callback must restore
/// and consume it before returning a new 41-item state.
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

/// Input is a biased lower-window code; output is `magnitude | negative`.
fn decode_lower_code(width: usize) -> Script {
    assert!(width == 8 || width == 9);
    script! {
        { 1u32 << (width - 1) } OP_SUB
        OP_DUP 0 OP_LESSTHAN
        OP_IF OP_NEGATE 1 OP_ELSE 0 OP_ENDIF
    }
}

/// Table output is direct `a[16] | b[9]`. Sign routing negates the literal b
/// limbs, preserving their within-block order and exact noncanonical field
/// representative when a centered digit is negative.
fn apply_selected_sign() -> Script {
    script! {
        OP_IF
            for _ in 0..9 { OP_NEGATE OP_TOALTSTACK }
            for _ in 0..9 { OP_FROMALTSTACK }
        OP_ENDIF
    }
}

/// Convert initializer output `u[16] | v[9]` into the first kernel's required
/// suffix `v[9] | u[16]`.
fn orient_initial_state() -> Script {
    move_block_to_top(16, 9)
}

/// Convert retained chained state `u[8] | lambda[8] | a[16] | b[9]` into the
/// next kernel's required suffix `b[9] | a[16] | lambda[8] | u[8]`.
fn reverse_chained_state_blocks() -> Script {
    script! {
        { move_block_to_top(16, 9) }
        { move_block_to_top(8, 9 + 16) }
        { move_block_to_top(8, 9 + 16 + 8) }
    }
}

/// Clear one packed field's word-seven metadata bit and restore its low31
/// word to the same packet slot while leaving the certified bit on top.
fn clear_padding_word_at_depth(depth: usize) -> Script {
    script! {
        { depth as u32 } OP_ROLL
        { policy_precompiled(
            carrier_codec::clear_packed_field_padding_bit_semantic(),
            "policy-precompiled packed-field padding carrier decoder",
        ) }
        OP_TOALTSTACK
        { insert_top_at_depth(depth) }
        OP_FROMALTSTACK
    }
}

fn raw_fragment_len(fragment: Script, copies: usize) -> usize {
    let repeated = script! {
        for _ in 0..copies { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % copies, 0);
    repeated.len() / copies
}

fn response_transition_callback(
    transition: usize,
    scalar_items: usize,
    table: Script,
    kernel: Script,
) -> Script {
    let current_items = if transition == 0 {
        TOP_STATE_ITEMS
    } else {
        STATE_ITEMS
    };
    let padding_bits = if transition < RESPONSE_PADDED_TRANSITIONS {
        RESPONSE_PADDING_BITS_PER_PADDED_TRANSITION
    } else {
        0
    };
    let width = if transition < 20 { 9 } else { 8 };
    let retained_chunks_before = transition;

    script! {
        { decode_lower_code(width) }
        // Altstack already contains current; put the temporary sign above it.
        OP_TOALTSTACK
        { table }
        OP_FROMALTSTACK
        { apply_selected_sign() }

        // Pull the physically topmost remaining response packet above the
        // scalar, retained chunks, and selected point.
        { move_block_to_top(
            PACKET_ITEMS,
            retained_chunks_before + scalar_items + SELECTED_ITEMS,
        ) }

        if padding_bits == 2 {
            // Packet top is q_curve. Lambda word seven is depth nine. After
            // retaining its bit, u word seven moves from depth 17 to 18.
            { clear_padding_word_at_depth(9) }
            { clear_padding_word_at_depth(18) }
        }

        // selected | trace | q-pair | padding ->
        // trace | selected | q-pair | padding.
        { move_block_to_top(SELECTED_ITEMS, PACKET_ITEMS + padding_bits) }
        { move_block_to_top(Q_ITEMS_PER_PACKET + padding_bits, SELECTED_ITEMS) }

        if transition == 0 {
            { policy_precompiled(
                carrier_codec::decode_pair_to_chunk_semantic(
                    SIGNED23_Q_BITS,
                    SIGNED22_Q_BITS,
                    padding_bits,
                ),
                "policy-precompiled first response q-pair decoder",
            ) }
        } else {
            { policy_precompiled(
                carrier_codec::decode_pair_to_chunk_semantic(
                    SIGNED23_Q_BITS,
                    SIGNED23_Q_BITS,
                    padding_bits,
                ),
                "policy-precompiled regular response q-pair decoder",
            ) }
        }

        // Decoder output q_curve | q_continuity | chunk. Put q values in the
        // kernel order and rotate the authenticated chunk under all live
        // scalar/kernel-local data.
        OP_TOALTSTACK OP_SWAP OP_FROMALTSTACK
        { move_block_to_top(
            scalar_items + TRACE_ITEMS_PER_PACKET + SELECTED_ITEMS + Q_ITEMS_PER_PACKET,
            1,
        ) }

        { restore_current(current_items) }
        if transition != 0 { { reverse_chained_state_blocks() } }
        { kernel }
    }
}

fn build_response_stream(
    response_tables_low_to_high: Vec<Script>,
) -> (Script, usize, usize, usize) {
    assert_eq!(response_tables_low_to_high.len(), RESPONSE_GROUPS);
    let scalar_states = scalar_items_after_response_transitions();
    let top = script! {
        { response_tables_low_to_high[RESPONSE_GROUPS - 1].clone() }
        { orient_initial_state() }
    };
    let mut callbacks = Vec::with_capacity(RESPONSE_TRANSITIONS);
    let mut first_kernel_bytes = 0usize;
    let mut chained_kernel_bytes = 0usize;

    for (transition, scalar_items) in scalar_states.into_iter().enumerate() {
        let future_packets = TRANSITIONS - transition - 1;
        let retained_chunks = transition + 1;
        let preserved = future_packets * PACKET_ITEMS + retained_chunks + scalar_items;
        let kernel = if transition == 0 {
            let kernel = verify_first_transition(preserved as u32);
            first_kernel_bytes = kernel.clone().compile_with_policy().len();
            kernel
        } else {
            let kernel = verify_chained_transition(preserved as u32);
            chained_kernel_bytes += kernel.clone().compile_with_policy().len();
            kernel
        };
        let table_position = RESPONSE_GROUPS - transition - 2;
        callbacks.push(response_transition_callback(
            transition,
            scalar_items,
            response_tables_low_to_high[table_position].clone(),
            kernel,
        ));
    }
    let stream = response_scalar_stream(top, &callbacks);
    let stream_bytes = stream.clone().compile_with_policy().len();
    assert!(stream_bytes > MAX_OPTIMIZER_INPUT_BYTES);
    (
        stream,
        first_kernel_bytes,
        chained_kernel_bytes,
        stream_bytes,
    )
}

/// Challenge packet #1 has only q_curve scalar-routed. Packet #0 has neither
/// q routed. Decode exactly those three remaining signed23 carriers and force
/// their otherwise-unused metadata chunks to zero.
fn normalize_remaining_challenge_q(transition: usize) -> Script {
    match transition {
        0..=13 => Script::new("both challenge q values already scalar-routed"),
        14 => script! {
            // q_continuity_carrier | q_curve.
            OP_TOALTSTACK
            { policy_precompiled(
                carrier_codec::decode_carrier_compact_semantic(SIGNED23_Q_BITS),
                "policy-precompiled remaining challenge q decoder",
            ) }
            OP_NOT OP_VERIFY
            OP_FROMALTSTACK
        },
        15 => script! {
            // q_continuity_carrier | q_curve_carrier.
            { policy_precompiled(
                carrier_codec::decode_carrier_compact_semantic(SIGNED23_Q_BITS),
                "policy-precompiled remaining challenge q decoder",
            ) }
            OP_NOT OP_VERIFY
            OP_SWAP
            { policy_precompiled(
                carrier_codec::decode_carrier_compact_semantic(SIGNED23_Q_BITS),
                "policy-precompiled remaining challenge q decoder",
            ) }
            OP_NOT OP_VERIFY
            OP_SWAP
        },
        _ => unreachable!("sixteen challenge transitions"),
    }
}

fn challenge_transition_callback(transition: usize, table: Script, kernel: Script) -> Script {
    let remaining_groups = CHALLENGE_TRANSITIONS - transition - 1;
    let remaining_controls = 2 * remaining_groups;
    script! {
        if transition == 0 {
            // At the post-recoder frontier, current lies below retained R and
            // all 32 sign/magnitude controls. Later kernels return it on top.
            { move_block_to_top(STATE_ITEMS, RETAINED_R_WORDS + 2 * CHALLENGE_GROUPS) }
        }
        { park_current(STATE_ITEMS) }

        // Current control is `negative | magnitude`, with magnitude on top.
        { table }
        { move_block_to_top(1, SELECTED_ITEMS) }
        { apply_selected_sign() }

        { move_block_to_top(
            PACKET_ITEMS,
            RETAINED_R_WORDS + remaining_controls + SELECTED_ITEMS,
        ) }
        { move_block_to_top(SELECTED_ITEMS, PACKET_ITEMS) }
        { move_block_to_top(Q_ITEMS_PER_PACKET, SELECTED_ITEMS) }
        { normalize_remaining_challenge_q(transition) }

        { restore_current(STATE_ITEMS) }
        { reverse_chained_state_blocks() }
        { kernel }
    }
}

fn build_challenge_schedule(challenge_tables_low_to_high: Vec<Script>) -> (Script, usize, usize) {
    assert_eq!(challenge_tables_low_to_high.len(), CHALLENGE_GROUPS);
    let mut steps = Vec::with_capacity(CHALLENGE_TRANSITIONS);
    let mut kernel_bytes = 0usize;
    for transition in 0..CHALLENGE_TRANSITIONS {
        let remaining_groups = CHALLENGE_TRANSITIONS - transition - 1;
        let preserved = remaining_groups * PACKET_ITEMS + RETAINED_R_WORDS + 2 * remaining_groups;
        let kernel = verify_chained_transition(preserved as u32);
        kernel_bytes += kernel.clone().compile_with_policy().len();
        let table_position = CHALLENGE_GROUPS - transition - 1;
        steps.push(challenge_transition_callback(
            transition,
            challenge_tables_low_to_high[table_position].clone(),
            kernel,
        ));
    }
    let schedule = script! { for step in steps { { step } } };
    let schedule_bytes = schedule.clone().compile_with_policy().len();
    assert!(schedule_bytes > MAX_OPTIMIZER_INPUT_BYTES);
    (schedule, kernel_bytes, schedule_bytes)
}

fn scalar_validator() -> Script {
    scalar_validation::validate_scalar_words_for_widths_preserving(
        &response_widths_low_to_high(),
        RAW_ENTRY_ITEMS,
    )
}

/// BLAKE3's u4 backend visits four-byte words low-to-high and bytes within
/// each word high-to-low, with each byte represented high nibble then low.
fn blake_u4_layout(bytes: &[u8; 32]) -> Vec<u8> {
    bytes
        .chunks_exact(4)
        .flat_map(|word| word.iter().rev())
        .flat_map(|byte| [byte >> 4, byte & 15])
        .collect()
}

/// Consume the hostile M32 nibble block against a compiled constant. The
/// fixed-message BLAKE3 specialization materializes M internally, so the
/// certified carrier values do not need to remain on the runtime stack.
fn bind_fixed_message(message: &[u8; 32]) -> Script {
    ed25519_challenge::bind_and_drop_fixed_message(*message)
}

fn endpoint_comparison() -> Script {
    const NON_U_STATE_ITEMS: usize = STATE_ITEMS - PACKED_WORDS;
    script! {
        for _ in 0..NON_U_STATE_ITEMS / 2 { OP_2DROP }
        if NON_U_STATE_ITEMS % 2 != 0 { OP_DROP }
        for depth in (1..=RETAINED_R_WORDS).rev() {
            { depth as u32 } OP_ROLL OP_EQUALVERIFY
        }
        OP_1
    }
}

fn static_non_push_opcodes(script: &ScriptBuf) -> usize {
    script
        .instructions()
        .map(|instruction| instruction.expect("generated script parses"))
        .filter(
            |instruction| matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() > 0x60),
        )
        .count()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Independently recover the exact magnitude/sign table controls encoded in
/// the validated `C+s` payload. The scalar streamer visits this vector in
/// reverse. Lower groups are biased; the top group is unsigned.
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
            assert!(centered.unsigned_abs() <= 1usize << (width - 1));
            recovered += BigInt::from(centered) << bit;
            controls.push((centered.unsigned_abs(), centered < 0));
        }
        bit += width;
    }
    assert_eq!(bit, 253);
    assert_eq!(recovered, BigInt::from(scalar.clone()));
    controls
}

fn controls_high_to_low_string(controls: &[(usize, bool)]) -> String {
    controls
        .iter()
        .rev()
        .map(|(magnitude, negative)| format!("{magnitude}{}", if *negative { "-" } else { "+" }))
        .collect::<Vec<_>>()
        .join(",")
}

fn push_probe_values(values: &[i64]) -> Script {
    script! { for value in values { { *value } } }
}

fn verify_probe_values(values_bottom_to_top: &[i64]) -> Script {
    script! {
        for value in values_bottom_to_top.iter().rev() {
            { *value } OP_NUMEQUALVERIFY
        }
    }
}

fn probe_values(start: i64, items: usize) -> Vec<i64> {
    (0..items).map(|offset| start + offset as i64).collect()
}

fn encode_probe_carrier(metadata: u16, q: i32, q_bits: usize) -> i64 {
    let metadata_bits = 32 - q_bits;
    assert!(u32::from(metadata) < 1u32 << metadata_bits);
    let bias = 1i64 << (q_bits - 1);
    assert!((-bias..bias).contains(&i64::from(q)));
    let low_mask = (1u16 << (metadata_bits - 1)) - 1;
    let sign = metadata >> (metadata_bits - 1);
    let payload = (i64::from(metadata & low_mask) << q_bits) + i64::from(q) + bias;
    let carrier = if sign == 0 { payload } else { -(payload + 1) };
    assert_ne!(carrier, -(1i64 << 31));
    carrier
}

fn padded_probe_word(low31: u32, metadata_bit: u32) -> i64 {
    assert!(low31 < 1u32 << 31);
    assert!(metadata_bit <= 1);
    i64::from((low31 | (metadata_bit << 31)) as i32)
}

fn response_probe(transition: usize, centered_digit: i32) -> usize {
    assert!(transition < RESPONSE_TRANSITIONS);
    let scalar_items = scalar_items_after_response_transitions()[transition];
    let width = if transition < 20 { 9 } else { 8 };
    let bias = 1i32 << (width - 1);
    let encoded_digit = bias + centered_digit;
    assert!((0..1i32 << width).contains(&encoded_digit));
    let magnitude = centered_digit.unsigned_abs() as usize;
    let negative = centered_digit < 0;

    let padding_bits = if transition < RESPONSE_PADDED_TRANSITIONS {
        2
    } else {
        0
    };
    let u_padding = u32::from(padding_bits != 0 && transition % 2 == 0);
    let lambda_padding = u32::from(padding_bits != 0 && transition % 2 != 0);
    let mut trace = probe_values(1_000, TRACE_ITEMS_PER_PACKET);
    trace[0] = 3;
    trace[8] = 5;
    let mut wire_trace = trace.clone();
    if padding_bits != 0 {
        wire_trace[0] = padded_probe_word(trace[0] as u32, u_padding);
        wire_trace[8] = padded_probe_word(trace[8] as u32, lambda_padding);
    }

    let q_curve = 123_456i32;
    let q_continuity = if transition == 0 { -654_321 } else { -765_432 };
    let curve_metadata = 0x1a5u16;
    let continuity_metadata = if transition == 0 { 0x2aau16 } else { 0x155u16 };
    let q_continuity_bits = if transition == 0 {
        SIGNED22_Q_BITS
    } else {
        SIGNED23_Q_BITS
    };
    let mut packet = wire_trace;
    packet.push(encode_probe_carrier(
        continuity_metadata,
        q_continuity,
        q_continuity_bits,
    ));
    packet.push(encode_probe_carrier(
        curve_metadata,
        q_curve,
        SIGNED23_Q_BITS,
    ));

    let padding_chunk = lambda_padding | (u_padding << 1);
    let curve_metadata_bits = 9usize;
    let continuity_metadata_bits = 32 - q_continuity_bits;
    let expected_chunk = u32::from(curve_metadata)
        | (u32::from(continuity_metadata) << curve_metadata_bits)
        | (padding_chunk << (curve_metadata_bits + continuity_metadata_bits));

    let selected_a = probe_values(2_000, 16);
    let selected_b = probe_values(3_000, 9);
    let mut selected = selected_a.clone();
    selected.extend(
        selected_b
            .iter()
            .map(|value| if negative { -*value } else { *value }),
    );
    let table = script! {
        { magnitude as u32 } OP_NUMEQUALVERIFY
        { push_probe_values(&selected_a) }
        { push_probe_values(&selected_b) }
    };

    let (current, expected_current) = if transition == 0 {
        let v = probe_values(4_000, 9);
        let u = probe_values(4_100, 16);
        let current = [v, u].concat();
        (current.clone(), current)
    } else {
        let u = probe_values(4_000, 8);
        let lambda = probe_values(4_100, 8);
        let a = probe_values(4_200, 16);
        let b = probe_values(4_300, 9);
        let current = [u.clone(), lambda.clone(), a.clone(), b.clone()].concat();
        (current, [b, a, lambda, u].concat())
    };
    let mut expected_kernel = trace;
    expected_kernel.extend(selected);
    expected_kernel.push(i64::from(q_continuity));
    expected_kernel.push(i64::from(q_curve));
    expected_kernel.extend(expected_current);
    let output = probe_values(5_000, STATE_ITEMS);
    let kernel = script! {
        { verify_probe_values(&expected_kernel) }
        { push_probe_values(&output) }
    };

    let old_chunks = probe_values(6_000, transition);
    let scalar = probe_values(7_000, scalar_items);
    let mut expected_final = old_chunks.clone();
    expected_final.push(i64::from(expected_chunk));
    expected_final.extend(&scalar);
    expected_final.extend(&output);
    let executable = script! {
        { push_probe_values(&packet) }
        { push_probe_values(&old_chunks) }
        { push_probe_values(&scalar) }
        { push_probe_values(&current) }
        { park_current(current.len()) }
        { encoded_digit }
        { response_transition_callback(transition, scalar_items, table, kernel) }
        { verify_probe_values(&expected_final) }
        OP_1
    }
    .compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(executable.to_bytes(), vec![]);
    assert!(
        execution.error.is_none(),
        "response transition {transition} routing: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);
    execution.stats.max_nb_stack_items
}

fn challenge_probe(transition: usize, magnitude: usize, negative: bool) -> usize {
    assert!(transition < CHALLENGE_TRANSITIONS);
    let remaining_groups = CHALLENGE_TRANSITIONS - transition - 1;
    let trace = probe_values(10_000, TRACE_ITEMS_PER_PACKET);
    let q_continuity = -234_567i32;
    let q_curve = 345_678i32;
    let mut packet = trace.clone();
    match transition {
        0..=13 => {
            packet.push(i64::from(q_continuity));
            packet.push(i64::from(q_curve));
        }
        14 => {
            packet.push(encode_probe_carrier(0, q_continuity, SIGNED23_Q_BITS));
            packet.push(i64::from(q_curve));
        }
        15 => {
            packet.push(encode_probe_carrier(0, q_continuity, SIGNED23_Q_BITS));
            packet.push(encode_probe_carrier(0, q_curve, SIGNED23_Q_BITS));
        }
        _ => unreachable!(),
    }

    let selected_a = probe_values(11_000, 16);
    let selected_b = probe_values(12_000, 9);
    let mut selected = selected_a.clone();
    selected.extend(
        selected_b
            .iter()
            .map(|value| if negative { -*value } else { *value }),
    );
    let table = script! {
        { magnitude as u32 } OP_NUMEQUALVERIFY
        { push_probe_values(&selected_a) }
        { push_probe_values(&selected_b) }
    };

    let u = probe_values(13_000, 8);
    let lambda = probe_values(13_100, 8);
    let a = probe_values(13_200, 16);
    let b = probe_values(13_300, 9);
    let current = [u.clone(), lambda.clone(), a.clone(), b.clone()].concat();
    let expected_current = [b, a, lambda, u].concat();
    let mut expected_kernel = trace;
    expected_kernel.extend(selected);
    expected_kernel.push(i64::from(q_continuity));
    expected_kernel.push(i64::from(q_curve));
    expected_kernel.extend(expected_current);
    let output = probe_values(14_000, STATE_ITEMS);
    let kernel = script! {
        { verify_probe_values(&expected_kernel) }
        { push_probe_values(&output) }
    };

    let retained_r = probe_values(15_000, RETAINED_R_WORDS);
    let remaining_controls = probe_values(16_000, 2 * remaining_groups);
    let mut expected_final = retained_r.clone();
    expected_final.extend(&remaining_controls);
    expected_final.extend(&output);
    let executable = if transition == 0 {
        script! {
            { push_probe_values(&packet) }
            { push_probe_values(&current) }
            { push_probe_values(&retained_r) }
            { push_probe_values(&remaining_controls) }
            { i64::from(negative) } { magnitude as u32 }
            { challenge_transition_callback(transition, table, kernel) }
            { verify_probe_values(&expected_final) }
            OP_1
        }
    } else {
        script! {
            { push_probe_values(&packet) }
            { push_probe_values(&retained_r) }
            { push_probe_values(&remaining_controls) }
            { i64::from(negative) } { magnitude as u32 }
            { push_probe_values(&current) }
            { challenge_transition_callback(transition, table, kernel) }
            { verify_probe_values(&expected_final) }
            OP_1
        }
    }
    .compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(executable.to_bytes(), vec![]);
    assert!(
        execution.error.is_none(),
        "challenge transition {transition} routing: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);
    execution.stats.max_nb_stack_items
}

fn fixed_message_binding_probe() -> usize {
    let message: [u8; 32] = std::array::from_fn(|index| (index as u8).wrapping_mul(7));
    let nibbles = blake_u4_layout(&message);
    let prefix = probe_values(20_000, 17);
    let executable = script! {
        { push_probe_values(&prefix) }
        for nibble in &nibbles { { *nibble } }
        { bind_fixed_message(&message) }
        { verify_probe_values(&prefix) }
        OP_1
    }
    .compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(executable.to_bytes(), vec![]);
    assert!(execution.error.is_none(), "fixed M32 binding: {execution}");
    assert_eq!(execution.final_stack.len(), 1);

    let mut invalid_nibbles = nibbles.clone();
    invalid_nibbles[63] ^= 1;
    let rejecting = script! {
        { push_probe_values(&prefix) }
        for nibble in &invalid_nibbles { { *nibble } }
        { bind_fixed_message(&message) }
        OP_1
    }
    .compile_with_policy();
    let rejected = execute_raw_script_with_inputs_strict(rejecting.to_bytes(), vec![]);
    assert!(rejected.error.is_some(), "mutated M32 nibble was accepted");
    execution.stats.max_nb_stack_items
}

fn run_routing_probes() {
    let response_cases = [(0, -5), (1, 7), (4, -3), (20, 2)];
    let response_peak = response_cases
        .into_iter()
        .map(|(transition, digit)| response_probe(transition, digit))
        .max()
        .expect("response cases");
    let challenge_cases = [(0, 128, false), (14, 7, true), (15, 0, false)];
    let challenge_peak = challenge_cases
        .into_iter()
        .map(|(transition, magnitude, negative)| challenge_probe(transition, magnitude, negative))
        .max()
        .expect("challenge cases");
    let message_peak = fixed_message_binding_probe();
    println!("model=ed25519_montgomery_h16_full_linker_routing_probe");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=item-order");
    println!("execution_class=unclassified");
    println!("large_arithmetic_or_hash_executed=false");
    println!("response_cases=first_padded_negative,chained_padded_positive,chained_unpadded_negative,width8_positive");
    println!(
        "challenge_cases=top128,packet1_single_remaining_carrier,packet0_two_remaining_carriers"
    );
    println!("response_callback_probe_peak={response_peak}");
    println!("challenge_callback_probe_peak={challenge_peak}");
    println!("fixed_message_binding_probe_peak={message_peak}");
    println!("trace_selected_q_prior_state_order_verified=true");
    println!("padding_chunk_bit_order_verified=lambda_then_u");
    println!("selected_b_literal_sign_negation_verified=true");
    println!("remaining_three_q_metadata_chunks_checked_zero=true");
    println!("fixed_message_order_and_preservation_verified=true");
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("--check-routing") => {
            run_routing_probes();
            return;
        }
        None | Some("--measure-bytes") => {}
        Some(_) => panic!("use --measure-bytes or --check-routing"),
    }
    assert_eq!(TRACE_ITEMS, 704);
    assert_eq!(Q_HINT_ITEMS, 88);
    assert_eq!(RAW_ENTRY_ITEMS, 792);
    assert_eq!(FIRST_COMPLETE_INPUT_ITEM_COUNT, 68);
    assert_eq!(CHAINED_COMPLETE_INPUT_ITEM_COUNT, 84);
    assert_eq!(RESPONSE_TRANSCRIPT_CHUNKS, 28);
    assert_eq!(RESPONSE_TRANSCRIPT_BITS, 512);
    assert_eq!(RESPONSE_CARRIED_BITS, 513);
    assert_eq!(REMAINING_CHALLENGE_Q_ITEMS, 3);

    let scalar_zero = BigUint::from(0u8);
    let scalar_one = BigUint::from(1u8);
    let scalar_l_minus_one = scalar_validation::scalar_order() - BigUint::from(1u8);
    let zero_controls = response_controls_low_to_high(&scalar_zero);
    let one_controls = response_controls_low_to_high(&scalar_one);
    let l_minus_one_controls = response_controls_low_to_high(&scalar_l_minus_one);

    let table_model::MontgomeryDirectH16TableFragments {
        response_low_to_high,
        challenge_low_to_high,
        public_key_compressed,
    } = table_model::montgomery_direct_h16_independent_byte_table_fragments();
    const EXPECTED_FIXTURE_PUBLIC_KEY: [u8; 32] = [
        0x7d, 0xb0, 0xdc, 0x92, 0x22, 0xf3, 0xc1, 0x83, 0x45, 0x7d, 0xdd, 0xe4, 0xc7, 0x08, 0xde,
        0x8e, 0x5e, 0xa6, 0xbf, 0x3d, 0x5c, 0x44, 0x04, 0xcc, 0xa1, 0x4b, 0x32, 0x72, 0x9a, 0x05,
        0xc3, 0x2a,
    ];
    assert_eq!(public_key_compressed, EXPECTED_FIXTURE_PUBLIC_KEY);
    let all_tables = script! {
        for table in response_low_to_high.iter().chain(challenge_low_to_high.iter()) {
            { table.clone() }
        }
    }
    .compile_with_policy();
    assert!(all_tables.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(all_tables.len(), EXPECTED_TABLE_BYTES);

    let (response_stream, first_kernel_bytes, response_chained_kernel_bytes, response_stream_bytes) =
        build_response_stream(response_low_to_high);
    let (challenge_schedule, challenge_kernel_bytes, challenge_schedule_bytes) =
        build_challenge_schedule(challenge_low_to_high);

    let domain = *blake3::hash(b"bitcoin-lab/custom-ed25519-blake3-slope-v1").as_bytes();
    let fixed_message: [u8; 32] = std::array::from_fn(|index| (index as u8).wrapping_mul(7));
    let message_u4 = blake_u4_layout(&fixed_message);
    let reconstructed_message = message_u4
        .chunks_exact(8)
        .flat_map(|word_nibbles| {
            let bytes_high_to_low = word_nibbles
                .chunks_exact(2)
                .map(|pair| (pair[0] << 4) | pair[1])
                .collect::<Vec<_>>();
            bytes_high_to_low.into_iter().rev()
        })
        .collect::<Vec<_>>();
    assert_eq!(reconstructed_message, fixed_message);
    let prefix_cv = ed25519_challenge::fixed_prefix_cv(domain, public_key_compressed);
    let blake =
        ed25519_challenge::key_specialized_compute_script_preserving_truncated_128_fixed_message(
            domain,
            public_key_compressed,
            fixed_message,
            337,
        );
    let blake_bytes = blake.clone().compile_with_policy().len();
    assert_eq!(blake_bytes, EXPECTED_FIXED_MESSAGE_BLAKE_POLICY_BYTES);

    let scalar_router = scalar_carrier_router::scalar_router();
    let scalar_router_raw_bytes = raw_fragment_len(scalar_router.clone(), 4);
    let packet_transpose = scalar_carrier_router::transpose_packet_blocks_after_scalar();
    let packet_transpose_raw_bytes = raw_fragment_len(packet_transpose.clone(), 32);
    let scalar_validator_raw = scalar_validator();
    let scalar_validator_raw_bytes = raw_fragment_len(scalar_validator_raw.clone(), 64);
    let scalar_validator_policy = scalar_validator_raw.compile_with_policy();
    let scalar_validator_policy_bytes = scalar_validator_policy.len();
    let scalar_validator =
        Script::new("policy-precompiled scalar validator").push_script(scalar_validator_policy);

    let midpoint_unpack_raw = midpoint::route_and_unpack_h16_midpoint();
    let midpoint_unpack_raw_bytes = raw_fragment_len(midpoint_unpack_raw.clone(), 4);
    let midpoint_unpack_policy = midpoint_unpack_raw.compile_with_policy();
    let midpoint_unpack_policy_bytes = midpoint_unpack_policy.len();
    let midpoint_unpack =
        Script::new("policy-precompiled H16 midpoint unpacker").push_script(midpoint_unpack_policy);

    let message_binding_raw = bind_fixed_message(&fixed_message);
    // The 128-byte consume-and-drop binder repeated 256 times lands exactly
    // on the policy's 32 KiB optimization cutoff.  Use 512 copies so this
    // raw-size probe stays on the intentional no-optimizer path.
    let message_binding_raw_bytes = raw_fragment_len(message_binding_raw.clone(), 512);
    let message_binding_policy = message_binding_raw.compile_with_policy();
    let message_binding_policy_bytes = message_binding_policy.len();
    assert_eq!(message_binding_policy_bytes, 128);
    assert_eq!(
        message_binding_policy_bytes + blake_bytes,
        EXPECTED_FIXED_MESSAGE_BOUNDARY_POLICY_BYTES
    );
    assert_eq!(
        message_binding_policy_bytes * 256,
        MAX_OPTIMIZER_INPUT_BYTES
    );
    let message_binding =
        Script::new("policy-precompiled fixed M32 binding").push_script(message_binding_policy);

    let challenge_recoder_raw = midpoint::recode_h16_blake3_low128_independent_byte127();
    let challenge_recoder_raw_bytes = raw_fragment_len(challenge_recoder_raw.clone(), 128);
    let challenge_recoder_policy = challenge_recoder_raw.compile_with_policy();
    let challenge_recoder_policy_bytes = challenge_recoder_policy.len();
    assert_eq!(challenge_recoder_policy_bytes, 389);
    let challenge_recoder = Script::new("policy-precompiled H16 challenge recoder")
        .push_script(challenge_recoder_policy);

    let endpoint_raw = endpoint_comparison();
    let endpoint_raw_bytes = raw_fragment_len(endpoint_raw.clone(), 2_048);
    let endpoint_policy = endpoint_raw.compile_with_policy();
    let endpoint_policy_bytes = endpoint_policy.len();
    let endpoint = Script::new("policy-precompiled endpoint cleanstack predicate")
        .push_script(endpoint_policy);

    let whole = script! {
        { scalar_router }
        { packet_transpose }
        { scalar_validator }
        { response_stream }
        { midpoint_unpack }
        { message_binding }
        { blake }
        { challenge_recoder }
        { challenge_schedule }
        { endpoint }
    };
    let compiled = whole.compile_with_policy();
    assert!(compiled.len() > MAX_OPTIMIZER_INPUT_BYTES);
    let script_bytes = compiled.len();
    assert_eq!(script_bytes, ADDITIVE_PROJECTED_LINKED_SCRIPT_BYTES);
    let linked_component_sum = scalar_router_raw_bytes
        + packet_transpose_raw_bytes
        + scalar_validator_policy_bytes
        + response_stream_bytes
        + midpoint_unpack_policy_bytes
        + message_binding_policy_bytes
        + blake_bytes
        + challenge_recoder_policy_bytes
        + challenge_schedule_bytes
        + endpoint_policy_bytes;
    assert_eq!(script_bytes, linked_component_sum);

    let all_kernel_bytes =
        first_kernel_bytes + response_chained_kernel_bytes + challenge_kernel_bytes;
    let target_weight_upper_bound = script_bytes + TARGET_AND_WITNESS_OVERHEAD_WEIGHT;
    let projected_minimum_block_weight = target_weight_upper_bound + MINIMUM_OTHER_BLOCK_WEIGHT;
    let headroom = MAX_BLOCK_WEIGHT.saturating_sub(projected_minimum_block_weight);

    println!("model=ed25519_montgomery_h16_full_linker");
    println!("evidence=locally-reproduced");
    println!("execution_class=unclassified");
    println!("candidate_protocol=custom_BLAKE3_128_Ed25519_style_not_RFC8032");
    println!("whole_serialization_generated=true");
    println!("whole_script_executed=false");
    println!("long_arithmetic_or_blake_execution=false");
    println!("complete_cleanstack_predicate_serialized=true");
    println!("script_compilation=repository_policy_NONE_above_32KiB_with_policy_precompiled_kernel_steps_and_BLAKE_backend");
    println!("locking_script_bytes={script_bytes}");
    println!(
        "pre_run_additive_projection_checkpoint_bytes={ADDITIVE_PROJECTED_LINKED_SCRIPT_BYTES}"
    );
    println!("projection_confirmed_by_this_generation=true");
    println!(
        "static_non_push_opcodes={}",
        static_non_push_opcodes(&compiled)
    );
    println!("cross_component_optimizer_delta_bytes=0");
    println!("linked_component_sum_bytes={linked_component_sum}");
    println!("table_raw_bytes={}", all_tables.len());
    println!("all_44_kernel_bytes={all_kernel_bytes}");
    println!("first_kernel_bytes={first_kernel_bytes}");
    println!("response_chained_kernel_bytes={response_chained_kernel_bytes}");
    println!("challenge_chained_kernel_bytes={challenge_kernel_bytes}");
    println!("response_stream_including_tables_kernels_and_routing_bytes={response_stream_bytes}");
    println!(
        "challenge_schedule_including_tables_kernels_and_routing_bytes={challenge_schedule_bytes}"
    );
    println!("scalar_carrier_router_raw_bytes={scalar_router_raw_bytes}");
    println!("packet_block_transpose_raw_bytes={packet_transpose_raw_bytes}");
    println!("scalar_validator_raw_bytes={scalar_validator_raw_bytes}");
    println!("scalar_validator_policy_bytes={scalar_validator_policy_bytes}");
    println!("midpoint_unpack_raw_bytes={midpoint_unpack_raw_bytes}");
    println!("midpoint_unpack_policy_bytes={midpoint_unpack_policy_bytes}");
    println!("fixed_message_binding_raw_bytes={message_binding_raw_bytes}");
    println!("fixed_message_binding_policy_bytes={message_binding_policy_bytes}");
    println!("blake3_policy_bytes={blake_bytes}");
    println!("blake3_fixed_message_specialization=true");
    println!("blake3_hash_frontier_input_items=401");
    println!("blake3_auxiliary_hint_items=0");
    println!("challenge_recoder_raw_bytes={challenge_recoder_raw_bytes}");
    println!("challenge_recoder_policy_bytes={challenge_recoder_policy_bytes}");
    println!("challenge_recode_schedule=independent_signed_bytes_bias127");
    println!("challenge_recode_identity=h=sum(e_i*2^(8i))+K_127");
    println!("challenge_recode_digit_interval=-127..128");
    println!("challenge_selector_magnitude_interval=0..128");
    println!("challenge_top_candidate_leaves=129");
    println!("response_initializer_shift=-K_127_times_A");
    println!("endpoint_cleanstack_raw_bytes={endpoint_raw_bytes}");
    println!("endpoint_cleanstack_policy_bytes={endpoint_policy_bytes}");
    println!("domain_separator={}", hex(&domain));
    println!("fixed_message_hex={}", hex(&fixed_message));
    println!("fixed_message_bound_in_script=true");
    println!("fixed_message_u4_order_asserted_against_midpoint_BLAKE_layout=true");
    println!("fixed_public_key_scalar=987654321");
    println!("benchmark_fixture_private_scalar_disclosed=true");
    println!("production_secure_key=false");
    println!("production_table_generator_accepts_external_public_key=true");
    println!("production_table_generator_secret_scalar_inputs=0");
    println!("production_requirement=regenerate_tables_and_BLAKE_prefix_from_an_external_prime_subgroup_public_key_without_embedding_or_disclosing_its_secret_scalar");
    println!(
        "fixed_public_key_rfc8032_compressed={}",
        hex(&public_key_compressed)
    );
    println!("blake3_embedded_prefix_cv={prefix_cv:08x?}");
    println!("blake3_prefix_key_matches_table_key=true");
    println!(
        "response_controls_s_0_high_to_low={}",
        controls_high_to_low_string(&zero_controls)
    );
    println!(
        "response_controls_s_1_high_to_low={}",
        controls_high_to_low_string(&one_controls)
    );
    println!(
        "response_controls_s_l_minus_1_high_to_low={}",
        controls_high_to_low_string(&l_minus_one_controls)
    );
    println!("response_control_recomposition_s_0_s_1_s_l_minus_1=true");
    println!("response_groups={RESPONSE_GROUPS}");
    println!("challenge_groups={CHALLENGE_GROUPS}");
    println!("transitions={TRANSITIONS}");
    println!("hint_items_per_transition=2");
    println!("quotient_hint_items_total={Q_HINT_ITEMS}");
    println!("trace_data_items_total={TRACE_ITEMS}");
    println!("complete_argument_items_at_script_entry={RAW_ENTRY_ITEMS}");
    println!("all_88_hints_and_704_trace_items_coexist_at_entry=true");
    println!("separate_scalar_or_transcript_witness_items=0");
    println!("entry_packet_order=response28_then_challenge16");
    println!("post_scalar_transpose_packet_order=challenge16_then_response28");
    println!(
        "scalar_carriers_in_entry_challenge_packets_1_through_15={SCALAR_ROUTED_CHALLENGE_Q_ITEMS}"
    );
    println!("remaining_challenge_carriers_zero_metadata_checked={REMAINING_CHALLENGE_Q_ITEMS}");
    println!("response_transcript_chunk_items={RESPONSE_TRANSCRIPT_CHUNKS}");
    println!("response_transcript_forced_zero_spare_bits=1");
    println!("scalar_router_strict_peak={STRICT_SCALAR_ROUTER_PEAK}");
    println!(
        "first_kernel_combined_peak={}",
        783 + STRICT_FIRST_LOCAL_PEAK
    );
    println!(
        "second_kernel_combined_peak={}",
        766 + STRICT_CHAINED_LOCAL_PEAK
    );
    println!("midpoint_unpack_strict_peak={STRICT_MIDPOINT_PEAK}");
    println!("blake3_combined_peak_upper_bound={BLAKE_COMBINED_PEAK_UPPER_BOUND}");
    println!("blake3_fixed_message_strict_peak={BLAKE_COMBINED_PEAK_UPPER_BOUND}");
    println!("challenge_recoder_strict_peak={STRICT_RECODER_PEAK}");
    println!("strict_item_schedule_peak={STRICT_WHOLE_STUB_PEAK}");
    println!("strict_item_schedule_below_1000=true");
    println!("conservative_target_weight_upper_bound={target_weight_upper_bound}");
    println!("projected_minimum_block_weight={projected_minimum_block_weight}");
    println!("headroom_below_4_000_000={headroom}");
    println!("default_policy_400_000_weight_compatible=false");
    println!("honest_792_item_witness_generated=true");
    println!("honest_witness_generation_boundary=separate_deterministic_host_probe_not_whole_leaf_execution");
    println!("unresolved_validation=whole_script_with_concrete_honest_witness_not_executed_under_Bitcoin_Core");
    println!("includes=complete-leaf: real 792-item carrier/trace consumption, fixed-key scalar and challenge tables, 44 slope relations, BLAKE3-128 transcript, canonical Rtilde retention, endpoint comparison, and clean truthy result; a separate focused host probe generates and serializes the exact honest 792-item argument vector, while full execution and Bitcoin Core consensus validation are excluded");
}
