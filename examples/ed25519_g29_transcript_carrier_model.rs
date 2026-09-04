//! Focused model for transporting a 64-byte BLAKE3 transcript inside G29's
//! 84 direct signed-23-bit quotient items.
//!
//! This deliberately does not build or execute the multi-megabyte affine
//! kernels and does not execute BLAKE3. It executes the exact carrier decoder
//! and q/current/altstack routing against peak-equivalent transition and hash
//! stubs, then reports additive byte composition against the independently
//! reproduced 3,881,402-byte G29 fragment.

use bitcoin_lab::support::{
    execution::execute_raw_script_with_inputs_strict,
    script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
};

const BASE_G29_BYTES: usize = 3_881_402;
const TRANSITIONS: usize = 28;
const PACKET_ITEMS: usize = 27;
const QUOTIENT_ITEMS: usize = 3;
const SCALAR_ITEMS: usize = 8;
const POINT_ITEMS: usize = 102;
const TRANSCRIPT_BYTES: usize = 64;
const DIRECT_Q_ITEMS: usize = 20;
const BLAKE_INPUT_NIBBLES: usize = 128;
const BLAKE_OUTPUT_NIBBLES: usize = 64;
const BLAKE_LOCAL_PEAK_UPPER_BOUND: usize = 591;
const BLAKE_UNPRESERVED_BYTES: usize = 65_208;
// The preserving generator differs only by encoding OP_DEPTH's expected
// value as 102 rather than zero; that constant adds one serialized byte.
const BLAKE_PRESERVING_POINT_BYTES: usize = BLAKE_UNPRESERVED_BYTES + 1;
const COMPLETE_ENTRY_ITEMS: usize = 764;
const BASE_G29_STRICT_STUB_PEAK: usize = 993;

#[derive(Clone, Copy, Debug)]
struct KernelShape {
    name: &'static str,
    current_items: usize,
    input_items: usize,
    local_peak: usize,
}

const FIRST_PACKED: KernelShape = KernelShape {
    name: "first-packed",
    current_items: 16,
    input_items: 74,
    local_peak: 256,
};

const CHAINED_PACKED: KernelShape = KernelShape {
    name: "chained-packed",
    current_items: POINT_ITEMS,
    input_items: 160,
    local_peak: 256,
};

const CHAINED_DIRECT: KernelShape = KernelShape {
    name: "chained-direct",
    current_items: POINT_ITEMS,
    input_items: 246,
    local_peak: 330,
};

fn shape_for_transition(transition: usize) -> KernelShape {
    match transition {
        0 => FIRST_PACKED,
        1..20 => CHAINED_PACKED,
        _ => CHAINED_DIRECT,
    }
}

fn drop_top_items(items: usize) -> Script {
    script! {
        for _ in 0..items / 2 { OP_2DROP }
        if items % 2 != 0 { OP_DROP }
    }
}

/// Move a contiguous block across `items_above` while retaining its order.
fn move_block_to_top(block_items: usize, items_above: usize) -> Script {
    if block_items == 0 || items_above == 0 {
        return Script::new("no-op block move");
    }
    let depth = block_items + items_above - 1;
    script! {
        for _ in 0..block_items { { depth as u32 } OP_ROLL }
    }
}

/// `packed=(byte<<23)+(q+2^22)` -> `high_nibble | low_nibble | q`.
///
/// The raw-byte equality against OP_ABS both rejects negative values and
/// canonicalizes the at-most-four-byte ScriptNum carrier. Each threshold
/// branch emits its final nibble weight directly, avoiding a second byte
/// expansion pass.
fn decode_carrier_semantic() -> Script {
    script! {
        OP_DUP OP_DUP OP_ABS OP_EQUALVERIFY
        for bit in (23usize..31).rev() {
            { 1u32 << bit }
            OP_2DUP OP_GREATERTHANOREQUAL
            OP_IF
                OP_SUB
                { 1u32 << ((bit - 23) % 4) }
            OP_ELSE
                OP_DROP
                OP_0
            OP_ENDIF
            OP_SWAP
        }
        { 1u32 << 22 } OP_SUB
        OP_TOALTSTACK
        OP_ADD OP_ADD OP_ADD
        OP_TOALTSTACK
        OP_ADD OP_ADD OP_ADD
        OP_FROMALTSTACK
        OP_FROMALTSTACK
    }
}

/// Raw length under the repository's no-optimizer path without directly
/// invoking an upstream compilation API.
fn raw_fragment_len(fragment: Script) -> usize {
    // Every fragment measured here is at least the 102-item chained tail.
    // Repeating 512 times therefore forces the centralized policy's raw path
    // instead of accidentally measuring an optimizer rewrite of the fragment.
    const COPIES: usize = 512;
    let repeated = script! {
        for _ in 0..COPIES { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % COPIES, 0);
    repeated.len() / COPIES
}

/// Mask indexed by bottom-to-top q position (`q0,q1,q2`). Quotients are
/// visited top-down (`q2,q1,q0`), and the first 20 visited slots remain direct.
fn carrier_mask(transition: usize) -> [bool; QUOTIENT_ITEMS] {
    let mut mask = [false; QUOTIENT_ITEMS];
    for q_index in 0..QUOTIENT_ITEMS {
        let top_down_rank = transition * QUOTIENT_ITEMS + (QUOTIENT_ITEMS - 1 - q_index);
        mask[q_index] = top_down_rank >= DIRECT_Q_ITEMS;
    }
    mask
}

fn carrier_count(mask: [bool; QUOTIENT_ITEMS]) -> usize {
    mask.into_iter().filter(|carrier| *carrier).count()
}

/// State before this fragment:
///
/// main: `preserved | kernel-prefix-ending-in-controls | q0 | q1 | q2`
/// alt:  `retained-nibbles | current`
///
/// State after:
///
/// main: `preserved | kernel-prefix-without-controls | q0 | q1 | q2 |
///        current | nonzero | negative`
/// alt:  `retained-nibbles | newly-decoded-nibbles`
fn carrier_tail_semantic(shape: KernelShape, mask: [bool; QUOTIENT_ITEMS]) -> Script {
    let mut steps = Vec::new();
    let mut decoded_nibbles = 0usize;

    // Park every q above the current point. Carrier decoding leaves its two
    // nibbles on main, so the next q is rolled across only the digits already
    // decoded.
    for q_index in (0..QUOTIENT_ITEMS).rev() {
        if decoded_nibbles != 0 {
            steps.push(script! { { decoded_nibbles as u32 } OP_ROLL });
        }
        if mask[q_index] {
            steps.push(decode_carrier_semantic());
            decoded_nibbles += 2;
        }
        steps.push(script! { OP_TOALTSTACK });
    }
    assert_eq!(decoded_nibbles, 2 * carrier_count(mask));

    steps.push(script! {
        // q0, q1, q2 are restored in their original order, exposing current.
        for _ in 0..QUOTIENT_ITEMS { OP_FROMALTSTACK }
        for _ in 0..shape.current_items { OP_FROMALTSTACK }
    });

    if decoded_nibbles != 0 {
        // The digits sit below q/current. Move only this tiny block to the
        // top, then retain it on altstack beneath all later balanced kernel
        // use.
        steps.push(move_block_to_top(
            decoded_nibbles,
            QUOTIENT_ITEMS + shape.current_items,
        ));
        steps.push(script! {
            for _ in 0..decoded_nibbles { OP_TOALTSTACK }
        });
    }

    // Match the signed-kernel suffix: nonzero | negative at the top.
    steps.push(move_block_to_top(2, QUOTIENT_ITEMS + shape.current_items));
    script! { for step in steps { { step } } }
}

fn base_tail_semantic(shape: KernelShape) -> Script {
    script! {
        for _ in 0..shape.current_items { OP_FROMALTSTACK }
        { move_block_to_top(2, QUOTIENT_ITEMS + shape.current_items) }
    }
}

fn policy_precompiled(fragment: Script, name: &'static str) -> Script {
    Script::new(name).push_script(fragment.compile_with_policy())
}

fn carrier_tail(shape: KernelShape, mask: [bool; QUOTIENT_ITEMS]) -> Script {
    policy_precompiled(
        carrier_tail_semantic(shape, mask),
        "policy-precompiled transcript carrier tail",
    )
}

fn kernel_stub(shape: KernelShape) -> Script {
    assert!(shape.local_peak >= shape.input_items);
    let growth = shape.local_peak - shape.input_items;
    script! {
        for _ in 0..growth { 0 }
        { drop_top_items(growth + shape.input_items) }
        for _ in 0..POINT_ITEMS { 0 }
    }
}

fn scalar_items_after_transitions() -> Vec<usize> {
    let chunks = [29usize, 32, 32, 32, 32, 32, 32, 32];
    let widths = [vec![9; 21], vec![8; 8]].concat();
    let mut chunk = 0usize;
    let mut remainder = chunks[0];
    let mut states = Vec::with_capacity(widths.len());
    for width in widths {
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
    assert_eq!(states.remove(0), SCALAR_ITEMS);
    assert_eq!(states.len(), TRANSITIONS);
    states
}

fn packed_carrier(byte: u8, q: i32) -> i64 {
    assert!((-(1 << 22)..(1 << 22)).contains(&q));
    (i64::from(byte) << 23) + i64::from(q + (1 << 22))
}

fn push_number(value: i64) -> Script {
    script! { { value } }
}

fn run_decoder_boundaries() {
    let cases = [
        (0_u8, -(1 << 22)),
        (0, (1 << 22) - 1),
        (255, -(1 << 22)),
        (255, (1 << 22) - 1),
        (0xa5, -17),
    ];
    let decoder = policy_precompiled(decode_carrier_semantic(), "carrier decoder");
    let executable = script! {
        for (byte, q) in cases {
            { packed_carrier(byte, q) }
            { decoder.clone() }
            { q } OP_NUMEQUALVERIFY
            { byte & 0x0f } OP_NUMEQUALVERIFY
            { byte >> 4 } OP_NUMEQUALVERIFY
        }
        OP_1
    }
    .compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(executable.to_bytes(), vec![]);
    assert!(
        execution.error.is_none(),
        "decoder boundary probe: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);
}

fn run_routing_probe(shape: KernelShape, mask: [bool; QUOTIENT_ITEMS]) {
    let prefix_items = shape.input_items - QUOTIENT_ITEMS - shape.current_items;
    assert!(prefix_items >= 2);
    let prefix = (0..prefix_items)
        .map(|index| 1_000_i64 + index as i64)
        .collect::<Vec<_>>();
    let current = (0..shape.current_items)
        .map(|index| 2_000_i64 + index as i64)
        .collect::<Vec<_>>();
    let q = [-31_i32, 47, -63];
    let bytes = [0x12_u8, 0x80, 0xfe];

    let mut expected_main = prefix[..prefix_items - 2].to_vec();
    expected_main.extend(q.into_iter().map(i64::from));
    expected_main.extend_from_slice(&current);
    expected_main.extend_from_slice(&prefix[prefix_items - 2..]);

    let executable = script! {
        for value in prefix.iter().copied() { { push_number(value) } }
        for q_index in 0..QUOTIENT_ITEMS {
            if mask[q_index] {
                { packed_carrier(bytes[q_index], q[q_index]) }
            } else {
                { q[q_index] }
            }
        }
        for value in current.iter().copied() { { push_number(value) } }
        for _ in 0..shape.current_items { OP_TOALTSTACK }
        { carrier_tail(shape, mask) }
        for value in expected_main.iter().rev().copied() {
            { value } OP_NUMEQUALVERIFY
        }
        for q_index in (0..QUOTIENT_ITEMS).rev() {
            if mask[q_index] {
                OP_FROMALTSTACK { bytes[q_index] >> 4 } OP_NUMEQUALVERIFY
                OP_FROMALTSTACK { bytes[q_index] & 0x0f } OP_NUMEQUALVERIFY
            }
        }
        OP_1
    }
    .compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(executable.to_bytes(), vec![]);
    assert!(
        execution.error.is_none(),
        "{} routing probe: {execution}",
        shape.name
    );
    assert_eq!(execution.final_stack.len(), 1);
}

fn run_transition_peak_probe(
    transition: usize,
    scalar_items: usize,
    retained_before: usize,
) -> usize {
    let shape = shape_for_transition(transition);
    let mask = carrier_mask(transition);
    let new_nibbles = 2 * carrier_count(mask);
    let preserved = (TRANSITIONS - transition - 1) * PACKET_ITEMS + scalar_items;
    let prefix_items = shape.input_items - QUOTIENT_ITEMS - shape.current_items;
    let q = [0_i32; QUOTIENT_ITEMS];

    let body = script! {
        for _ in 0..retained_before { 7 OP_TOALTSTACK }
        for _ in 0..preserved { 0 }
        for _ in 0..prefix_items { 0 }
        for q_index in 0..QUOTIENT_ITEMS {
            if mask[q_index] {
                { packed_carrier((transition * 3 + q_index) as u8, q[q_index]) }
            } else {
                { q[q_index] }
            }
        }
        for _ in 0..shape.current_items { 0 }
        for _ in 0..shape.current_items { OP_TOALTSTACK }
        { carrier_tail(shape, mask) }
        { kernel_stub(shape) }
        { drop_top_items(POINT_ITEMS) }
        { drop_top_items(preserved) }
        for _ in 0..retained_before + new_nibbles { OP_FROMALTSTACK OP_DROP }
        OP_1
    };
    let executable = compile_probe_without_optimizer(body);
    let execution = execute_raw_script_with_inputs_strict(executable.to_bytes(), vec![]);
    assert!(
        execution.error.is_none(),
        "transition {transition} peak probe: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);
    execution.stats.max_nb_stack_items
}

fn transcript_handoff() -> Script {
    script! { for _ in 0..BLAKE_INPUT_NIBBLES { OP_FROMALTSTACK } }
}

fn blake_stub() -> Script {
    let growth = BLAKE_LOCAL_PEAK_UPPER_BOUND - BLAKE_INPUT_NIBBLES;
    script! {
        for _ in 0..growth { 0 }
        { drop_top_items(growth + BLAKE_INPUT_NIBBLES) }
        for _ in 0..BLAKE_OUTPUT_NIBBLES { 0 }
    }
}

fn run_post_g29_peak_probe() -> usize {
    let body = script! {
        for _ in 0..POINT_ITEMS { 0 }
        // Carrier restoration is deliberately reverse chronological. The
        // witness maps transcript digits to carrier slots in reverse so this
        // handoff produces the BLAKE backend's R32 | M32 layout.
        for nibble in (0..BLAKE_INPUT_NIBBLES).rev() {
            { (nibble % 16) as u8 } OP_TOALTSTACK
        }
        { transcript_handoff() }
        { blake_stub() }
        { drop_top_items(BLAKE_OUTPUT_NIBBLES + POINT_ITEMS) }
        OP_1
    };
    let executable = compile_probe_without_optimizer(body);
    let execution = execute_raw_script_with_inputs_strict(executable.to_bytes(), vec![]);
    assert!(
        execution.error.is_none(),
        "post-G29 peak probe: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);
    execution.stats.max_nb_stack_items
}

/// Keep peak-equivalent constant scaffolds out of the optimizer. The false
/// branch is never executed; it only moves the complete probe above the
/// repository's 32 KiB cutoff so compilation uses the raw policy path.
fn compile_probe_without_optimizer(body: Script) -> bitcoin::ScriptBuf {
    let probe = script! {
        { body }
        OP_0 OP_IF
            for _ in 0..17_000 { OP_0 OP_DROP }
        OP_ENDIF
    };
    let compiled = probe.compile_with_policy();
    assert!(compiled.len() > MAX_OPTIMIZER_INPUT_BYTES);
    compiled
}

fn main() {
    assert_eq!(
        DIRECT_Q_ITEMS + TRANSCRIPT_BYTES,
        TRANSITIONS * QUOTIENT_ITEMS
    );
    assert_eq!(COMPLETE_ENTRY_ITEMS, 672 + 84 + SCALAR_ITEMS);
    run_decoder_boundaries();
    run_routing_probe(CHAINED_PACKED, [true, false, false]);
    run_routing_probe(CHAINED_PACKED, [true; QUOTIENT_ITEMS]);
    run_routing_probe(CHAINED_DIRECT, [true; QUOTIENT_ITEMS]);

    let check_stub_peaks = std::env::args().any(|argument| argument == "--check-stub-peaks");
    let (transition_peak, post_g29_peak, strict_stub_peak) = if check_stub_peaks {
        let scalar_states = scalar_items_after_transitions();
        let mut retained = 0usize;
        let mut transition_peak = 0usize;
        for (transition, scalar_items) in scalar_states.into_iter().enumerate() {
            let peak = run_transition_peak_probe(transition, scalar_items, retained);
            transition_peak = transition_peak.max(peak);
            retained += 2 * carrier_count(carrier_mask(transition));
        }
        assert_eq!(retained, BLAKE_INPUT_NIBBLES);
        let post_g29_peak = run_post_g29_peak_probe();
        (
            transition_peak,
            post_g29_peak,
            transition_peak.max(post_g29_peak),
        )
    } else {
        (0, 0, BASE_G29_STRICT_STUB_PEAK)
    };

    let decoder_raw_bytes = raw_fragment_len(decode_carrier_semantic());
    let decoder_policy_bytes = decode_carrier_semantic().compile_with_policy().len();
    let handoff_bytes = transcript_handoff().compile_with_policy().len();

    let variants = [
        (CHAINED_PACKED, carrier_mask(6), 1usize),
        (CHAINED_PACKED, [true; QUOTIENT_ITEMS], 13usize),
        (CHAINED_DIRECT, [true; QUOTIENT_ITEMS], 8usize),
    ];
    assert_eq!(carrier_count(variants[0].1), 1);
    assert_eq!(variants.iter().map(|(_, _, uses)| uses).sum::<usize>(), 22);
    let mut carrier_tail_incremental_bytes = 0usize;
    let mut carrier_tail_policy_bytes = 0usize;
    let mut replaced_base_tail_raw_bytes = 0usize;
    for (shape, mask, uses) in variants {
        let carrier_bytes = carrier_tail_semantic(shape, mask)
            .compile_with_policy()
            .len();
        let base_bytes = raw_fragment_len(base_tail_semantic(shape));
        carrier_tail_policy_bytes += uses * carrier_bytes;
        replaced_base_tail_raw_bytes += uses * base_bytes;
        carrier_tail_incremental_bytes += uses * (carrier_bytes - base_bytes);
    }

    let carrier_and_handoff_bytes = carrier_tail_incremental_bytes + handoff_bytes;
    let composed_script_bytes =
        BASE_G29_BYTES + carrier_and_handoff_bytes + BLAKE_PRESERVING_POINT_BYTES;

    // The 64 nonnegative 31-bit carriers need at most four payload bytes rather
    // than the old q-only bound of three, adding 64 witness bytes. Item count
    // is unchanged. Existing G29 projection was script + 4,836 WU.
    let composed_transaction_weight = composed_script_bytes + 4_836 + TRANSCRIPT_BYTES;

    println!("model=ed25519_g29_transcript_carrier");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=decoder-routing");
    println!("composition_evidence=inspected");
    println!("execution_class=unclassified");
    println!("full_arithmetic_and_blake_execution=false");
    println!("carrier_formula=(byte<<23)+(q+2^22)");
    println!("direct_q_items={DIRECT_Q_ITEMS}");
    println!("carrier_q_items={TRANSCRIPT_BYTES}");
    println!("quotient_hint_items_total=84");
    println!("incremental_witness_items=0");
    println!("complete_entry_items={COMPLETE_ENTRY_ITEMS}");
    println!("decoder_raw_bytes_per_carrier={decoder_raw_bytes}");
    println!("decoder_policy_bytes_per_carrier={decoder_policy_bytes}");
    println!("carrier_tail_policy_bytes_total={carrier_tail_policy_bytes}");
    println!("replaced_base_tail_raw_bytes_total={replaced_base_tail_raw_bytes}");
    println!("carrier_tail_incremental_bytes={carrier_tail_incremental_bytes}");
    println!("transcript_handoff_bytes={handoff_bytes}");
    println!("carrier_and_handoff_incremental_bytes={carrier_and_handoff_bytes}");
    println!("base_g29_raw_script_bytes={BASE_G29_BYTES}");
    println!("key_blake_unpreserved_bytes={BLAKE_UNPRESERVED_BYTES}");
    println!("key_blake_preserving_102_bytes={BLAKE_PRESERVING_POINT_BYTES}");
    println!("key_blake_bytes_source=standalone_generation_plus_one_byte_depth_constant_delta");
    println!("composed_raw_script_bytes={composed_script_bytes}");
    println!(
        "remaining_below_4_000_000_script_bytes={}",
        4_000_000usize.saturating_sub(composed_script_bytes)
    );
    println!("transition_strict_stub_peak={transition_peak}");
    println!("post_g29_blake_stub_peak={post_g29_peak}");
    println!("strict_combined_main_alt_stack_peak={strict_stub_peak}");
    println!("stub_peak_check_executed={check_stub_peaks}");
    if !check_stub_peaks {
        println!("strict_peak_source=projected_from_independently_reproduced_g29_baseline");
    }
    println!("projected_transaction_weight={composed_transaction_weight}");
    println!(
        "remaining_below_4_000_000_block_weight={}",
        4_000_000usize.saturating_sub(composed_transaction_weight)
    );
    println!("terminal_equation_consumer_and_block_overhead_excluded=true");
}
