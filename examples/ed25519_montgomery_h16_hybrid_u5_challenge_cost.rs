//! Bounded variable-width challenge search for the zero-hint hybrid-u5 leaf.
//!
//! The response partition remains the parity-correct G32 winner. For challenge
//! group counts 14 through 19, this probes balanced independent chunks whose
//! widths sum to 128. A width-`w` chunk is encoded as
//! `e=chunk-(2^(w-1)-1)`, so every group has a canonical sign/magnitude pair
//! and no carry. Each measured row builds only its exact challenge tables and
//! bias-shifted response-top table, plus small recoder/scaffold fragments. It
//! never builds or executes a complete leaf or BLAKE3 compression.
//! The relation-kernel checkpoints predate the later symmetric-square and
//! shared-power-pool reductions, so these rows are retained as a superseded
//! comparison model rather than the current G32 whole-leaf result.
//! Frozen provenance: commit f7bb0c2. Reproduce these exact historical table
//! assertions from that snapshot; current table generators may have changed.

#[allow(dead_code)]
#[path = "ed25519_fixed_table_actual_model.rs"]
mod fixed_tables;

#[allow(dead_code)]
#[path = "ed25519_g31_scalar_word_validator.rs"]
mod scalar_validation;

use bitcoin_lab::{
    arithmetic::u31::u31_to_bits_with_width,
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
    },
};
use std::collections::BTreeSet;

const RESPONSE_GROUPS: usize = 32;
const RESPONSE_TRANSITIONS: usize = RESPONSE_GROUPS - 1;
const TRACE_ITEMS_PER_PACKET: usize = 16;
const SCALAR_ITEMS: usize = 8;
const HYBRID_STATE_ITEMS: usize = 92;
const SELECTED_ITEMS: usize = 25;
const PACKED_PACKET_ITEMS: usize = 16;
const FINAL_R_U5_PACKET_ITEMS: usize = 59;
const FINAL_R_U5_EXTRA_ITEMS: usize = 43;
const DIGEST_NIBBLES: usize = 32;

const RESPONSE_LOWER_TABLE_BYTES: usize = 370_395;
const RESPONSE_SCAFFOLD_BYTES: usize = 14_701;
const HYBRID_FIRST_KERNEL_BYTES: usize = 37_296;
const HYBRID_CHAINED_KERNEL_BYTES: usize = 50_306;
const HYBRID_U5_TERMINAL_KERNEL_BYTES: usize = 45_605;
const HYBRID_FIRST_LOCAL_PEAK: usize = 208;
const HYBRID_CHAINED_LOCAL_PEAK: usize = 224;
const HYBRID_U5_FINAL_LOCAL_PEAK: usize = 267;
const HYBRID_U5_HASH_BYTES: usize = 67_137;
const HASH_OVER_PRESERVED_PEAK: usize = 527;

#[derive(Clone, Debug)]
struct Candidate {
    groups: usize,
    order: &'static str,
    widths: Vec<usize>,
}

#[derive(Debug)]
struct Row {
    candidate: Candidate,
    response_top_with_t: bool,
    response_top_bytes: usize,
    challenge_table_bytes: usize,
    challenge_scaffold_bytes: usize,
    validator_bytes: usize,
    recoder_bytes: usize,
    generic_recoder_bytes: usize,
    projected_leaf_bytes: usize,
    entry_items: usize,
    analytical_peak: usize,
}

fn balanced_widths(groups: usize, order: &str) -> Vec<usize> {
    let narrow = 128 / groups;
    let wide_count = 128 % groups;
    let wide = narrow + usize::from(wide_count != 0);
    let narrow_count = groups - wide_count;
    let widths = match order {
        "lohi" => std::iter::repeat_n(narrow, narrow_count)
            .chain(std::iter::repeat_n(wide, wide_count))
            .collect::<Vec<_>>(),
        "hilo" => std::iter::repeat_n(wide, wide_count)
            .chain(std::iter::repeat_n(narrow, narrow_count))
            .collect::<Vec<_>>(),
        "spread" | "spread-rev" => {
            let mut widths = (0..groups)
                .map(|index| {
                    let before = index * wide_count / groups;
                    let after = (index + 1) * wide_count / groups;
                    narrow + usize::from(after != before)
                })
                .collect::<Vec<_>>();
            if order == "spread-rev" {
                widths.reverse();
            }
            widths
        }
        _ => panic!("unknown balanced order"),
    };
    assert_eq!(widths.len(), groups);
    assert_eq!(widths.iter().sum::<usize>(), 128);
    assert!(widths.iter().all(|width| (6..=10).contains(width)));
    widths
}

fn candidates() -> Vec<Candidate> {
    let mut result = Vec::new();
    for groups in 14usize..=19 {
        let mut seen = BTreeSet::new();
        for order in ["lohi", "hilo", "spread", "spread-rev"] {
            let widths = balanced_widths(groups, order);
            if seen.insert(widths.clone()) {
                result.push(Candidate {
                    groups,
                    order,
                    widths,
                });
            }
        }
    }
    result
}

fn g32_response_widths() -> Vec<usize> {
    let mut widths = vec![8usize; RESPONSE_GROUPS];
    for position in [21usize, 25, 29] {
        widths[position] = 7;
    }
    assert_eq!(widths.iter().sum::<usize>(), 253);
    widths
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

fn apply_selected_sign() -> Script {
    script! {
        OP_IF
            for _ in 0..9 { OP_NEGATE OP_TOALTSTACK }
            for _ in 0..9 { OP_FROMALTSTACK }
        OP_ENDIF
    }
}

fn challenge_callback_scaffold(transition: usize, groups: usize, packet_items: usize) -> Script {
    let remaining_groups = groups - transition - 1;
    let remaining_controls = 2 * remaining_groups;
    script! {
        if transition == 0 {
            { move_block_to_top(HYBRID_STATE_ITEMS, 2 * groups) }
        }
        { park_current(HYBRID_STATE_ITEMS) }

        // The authenticated table consumes magnitude and emits 25 items.
        // It is excluded from this scaffold measurement.
        { move_block_to_top(1, SELECTED_ITEMS) }
        { apply_selected_sign() }

        { move_block_to_top(
            packet_items,
            remaining_controls + SELECTED_ITEMS,
        ) }
        { move_block_to_top(SELECTED_ITEMS, packet_items) }

        { restore_current(HYBRID_STATE_ITEMS) }
        // The derived field-relation kernel is excluded here.
    }
}

fn challenge_scaffold(groups: usize) -> Script {
    script! {
        for transition in 0..groups {
            { challenge_callback_scaffold(
                transition,
                groups,
                if transition + 1 == groups {
                    FINAL_R_U5_PACKET_ITEMS
                } else {
                    PACKED_PACKET_ITEMS
                },
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

/// Expand certified BLAKE3 u4 output to a global low-bit-first stack.
fn digest_u4_to_low_first_bits() -> Script {
    let mut expanded_bits = 0usize;
    let mut steps = Vec::with_capacity(DIGEST_NIBBLES);
    // Physical u4 order is high nibble then low nibble for each byte. Work
    // from byte 15 down so the final top item is global bit zero.
    for _byte in (0..16).rev() {
        steps.push(script! {
            { (expanded_bits + 1) as u32 } OP_ROLL
            { u31_to_bits_with_width(4) }
        });
        steps.push(script! {
            { (expanded_bits + 4) as u32 } OP_ROLL
            { u31_to_bits_with_width(4) }
        });
        expanded_bits += 8;
    }
    assert_eq!(expanded_bits, 128);
    script! { for step in steps { { step } } }
}

fn bits_from_altstack_to_number(width: usize) -> Script {
    script! {
        OP_FROMALTSTACK
        for _ in 1..width {
            OP_DUP OP_ADD OP_FROMALTSTACK OP_ADD
        }
    }
}

/// Generic independent-width recoder used only for bounded cost comparison.
/// Its inputs are already hash-certified u4 values.
fn variable_width_recoder(widths_low_to_high: &[usize], preserved_items: usize) -> Script {
    assert_eq!(widths_low_to_high.iter().sum::<usize>(), 128);
    script! {
        OP_DEPTH { (preserved_items + DIGEST_NIBBLES) as u32 } OP_NUMEQUALVERIFY
        { digest_u4_to_low_first_bits() }
        for (group, width) in widths_low_to_high.iter().copied().enumerate() {
            for _ in 0..width {
                if group != 0 { { (2 * group) as u32 } OP_ROLL }
                OP_TOALTSTACK
            }
            { bits_from_altstack_to_number(width) }
            { (1u32 << (width - 1)) - 1 } OP_SUB
            OP_DUP 0 OP_LESSTHAN
            OP_SWAP OP_ABS
        }
    }
}

fn byte127_recoder(preserved_items: usize) -> Script {
    script! {
        OP_DEPTH { (preserved_items + DIGEST_NIBBLES) as u32 } OP_NUMEQUALVERIFY
        for _ in 0..16 {
            31 OP_ROLL
            31 OP_ROLL
            OP_SWAP
            for _ in 0..4 { OP_DUP OP_ADD }
            OP_ADD
            127 OP_SUB
            OP_DUP 0 OP_LESSTHAN
            OP_SWAP OP_ABS
        }
    }
}

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn digest_fixture() -> [u8; 16] {
    std::array::from_fn(|index| [0x00, 0x7f, 0x80, 0xff][index % 4])
}

fn expected_controls(bytes: &[u8; 16], widths: &[usize]) -> Vec<(bool, u32)> {
    let value = u128::from_le_bytes(*bytes);
    let mut bit_offset = 0usize;
    widths
        .iter()
        .copied()
        .map(|width| {
            let chunk = ((value >> bit_offset) & ((1u128 << width) - 1)) as i32;
            bit_offset += width;
            let digit = chunk - ((1i32 << (width - 1)) - 1);
            (digit < 0, digit.unsigned_abs())
        })
        .collect()
}

fn strict_recoder_probe(widths: &[usize], specialized_byte_path: bool) -> usize {
    const PREFIX_ITEMS: usize = 5;
    let bytes = digest_fixture();
    let expected = expected_controls(&bytes, widths);
    let recoder = if specialized_byte_path {
        byte127_recoder(PREFIX_ITEMS)
    } else {
        variable_width_recoder(widths, PREFIX_ITEMS)
    };
    let checker = script! {
        { recoder }
        for (negative, magnitude) in expected.iter().rev() {
            { *magnitude } OP_NUMEQUALVERIFY
            { u32::from(*negative) } OP_NUMEQUALVERIFY
        }
        for _ in 0..PREFIX_ITEMS { 11 OP_NUMEQUALVERIFY }
        OP_1
    }
    .compile_with_policy();
    let mut witness = vec![scriptnum_item(11); PREFIX_ITEMS];
    for byte in bytes {
        witness.push(scriptnum_item(i64::from(byte >> 4)));
        witness.push(scriptnum_item(i64::from(byte & 0x0f)));
    }
    let execution = execute_raw_script_with_inputs_strict(checker.to_bytes(), witness);
    assert!(execution.error.is_none(), "variable recoder: {execution}");
    assert_eq!(execution.final_stack.len(), 1);
    execution.stats.max_nb_stack_items
}

fn widths_string(widths: &[usize]) -> String {
    widths
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join("/")
}

fn measure(candidate: Candidate) -> Row {
    let groups = candidate.groups;
    let table =
        fixed_tables::montgomery_direct_h16_independent_challenge_table_variant(&candidate.widths);
    assert_eq!(table.widths_low_to_high, candidate.widths);
    let challenge_scaffold_bytes = raw_fragment_len(&challenge_scaffold(groups));
    let preserved_trace_items =
        (RESPONSE_TRANSITIONS + groups) * TRACE_ITEMS_PER_PACKET + FINAL_R_U5_EXTRA_ITEMS;
    let validator = scalar_validation::validate_scalar_words_for_widths_preserving(
        &g32_response_widths(),
        preserved_trace_items,
    )
    .compile_with_policy();
    let validator_bytes = validator.len();

    let hash_preserved_items =
        groups * TRACE_ITEMS_PER_PACKET + FINAL_R_U5_EXTRA_ITEMS + HYBRID_STATE_ITEMS;
    let generic_recoder =
        variable_width_recoder(&candidate.widths, hash_preserved_items).compile_with_policy();
    let generic_recoder_bytes = generic_recoder.len();
    let is_byte16 = groups == 16 && candidate.widths.iter().all(|width| *width == 8);
    if is_byte16 {
        assert_eq!(table.bias_scalar.to_bytes_le(), vec![0x7f; 16]);
    }
    let recoder_bytes = if is_byte16 {
        byte127_recoder(hash_preserved_items)
            .compile_with_policy()
            .len()
    } else {
        generic_recoder_bytes
    };

    let response_kernel_bytes =
        HYBRID_FIRST_KERNEL_BYTES + (RESPONSE_GROUPS - 2) * HYBRID_CHAINED_KERNEL_BYTES;
    let challenge_kernel_bytes =
        (groups - 1) * HYBRID_CHAINED_KERNEL_BYTES + HYBRID_U5_TERMINAL_KERNEL_BYTES;
    let projected_leaf_bytes = RESPONSE_LOWER_TABLE_BYTES
        + table.response_top_raw_bytes
        + RESPONSE_SCAFFOLD_BYTES
        + response_kernel_bytes
        + table.challenge_total_raw_bytes
        + challenge_scaffold_bytes
        + challenge_kernel_bytes
        + HYBRID_U5_HASH_BYTES
        + recoder_bytes
        + validator_bytes;

    let entry_items = (RESPONSE_TRANSITIONS + groups) * TRACE_ITEMS_PER_PACKET
        + SCALAR_ITEMS
        + FINAL_R_U5_EXTRA_ITEMS;
    let response_first_peak = entry_items - TRACE_ITEMS_PER_PACKET + HYBRID_FIRST_LOCAL_PEAK;
    let response_second_peak = entry_items - 2 * TRACE_ITEMS_PER_PACKET + HYBRID_CHAINED_LOCAL_PEAK;
    assert_eq!(response_first_peak, response_second_peak);
    let hash_peak = hash_preserved_items + HASH_OVER_PRESERVED_PEAK;
    let generic_recoder_peak = hash_preserved_items + 128;
    let challenge_first_peak =
        18 * (groups - 1) + FINAL_R_U5_EXTRA_ITEMS + HYBRID_CHAINED_LOCAL_PEAK;
    let analytical_peak = response_first_peak
        .max(hash_peak)
        .max(generic_recoder_peak)
        .max(challenge_first_peak)
        .max(HYBRID_U5_FINAL_LOCAL_PEAK)
        .max(entry_items + 16);

    Row {
        candidate,
        response_top_with_t: table.response_top_with_t,
        response_top_bytes: table.response_top_raw_bytes,
        challenge_table_bytes: table.challenge_total_raw_bytes,
        challenge_scaffold_bytes,
        validator_bytes,
        recoder_bytes,
        generic_recoder_bytes,
        projected_leaf_bytes,
        entry_items,
        analytical_peak,
    }
}

fn main() {
    println!("metric_status=historical-projection");
    println!("historical_source_commit=f7bb0c29235b5a2fddefb6748888394ff5c1186a");
    let candidates = candidates();
    println!("model=ed25519_montgomery_h16_hybrid_u5_challenge_cost");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=generation-only");
    println!("execution_class=unclassified");
    println!("projection_status=superseded_pre_symmetric_square_and_shared_power_pool");
    println!("candidate_scope=bounded_balanced_G14_through_G19_four_placements");
    println!("digit_rule=chunk_minus_2pow_width_minus_1");
    println!("carry_items=0");
    println!("quotient_hint_items=0");
    println!("complete_hint_items=0");
    println!("hybrid_first_kernel_bytes={HYBRID_FIRST_KERNEL_BYTES}");
    println!("hybrid_chained_kernel_bytes={HYBRID_CHAINED_KERNEL_BYTES}");
    println!("hybrid_u5_terminal_kernel_bytes={HYBRID_U5_TERMINAL_KERNEL_BYTES}");
    println!("fixed_u5_hash_policy_bytes={HYBRID_U5_HASH_BYTES}");
    println!("fixed_u5_hash_manual_post_policy_optimizer=false");
    println!("full_leaf_built_or_executed=false");
    println!("blake3_built_or_executed=false");

    let mut rows = candidates.into_iter().map(measure).collect::<Vec<_>>();
    rows.sort_by_key(|row| (row.candidate.groups, row.projected_leaf_bytes));

    let mut best_by_group = Vec::new();
    for groups in 14usize..=19 {
        let group_rows = rows
            .iter()
            .filter(|row| row.candidate.groups == groups)
            .collect::<Vec<_>>();
        let best = group_rows[0];
        best_by_group.push(best);
        for row in group_rows {
            println!(
                "variant=g{}_{} widths={} response_top_with_t={} response_top_bytes={} challenge_table_bytes={} challenge_scaffold_bytes={} scalar_validator_policy_bytes={} recoder_policy_bytes={} generic_recoder_policy_bytes={} projected_leaf_bytes={} complete_entry_items={} hint_items=0 analytical_peak={} accepted_under_1000={}",
                groups,
                row.candidate.order,
                widths_string(&row.candidate.widths),
                row.response_top_with_t,
                row.response_top_bytes,
                row.challenge_table_bytes,
                row.challenge_scaffold_bytes,
                row.validator_bytes,
                row.recoder_bytes,
                row.generic_recoder_bytes,
                row.projected_leaf_bytes,
                row.entry_items,
                row.analytical_peak,
                row.analytical_peak <= 1_000,
            );
        }
    }

    let expected_group_bests = [
        (14usize, "lohi", 3_118_212usize, 963usize),
        (15, "spread-rev", 3_057_062, 979),
        (16, "lohi", 3_019_348, 995),
        (17, "spread-rev", 3_034_178, 1_011),
        (18, "hilo", 3_047_559, 1_027),
        (19, "lohi", 3_076_641, 1_043),
    ];
    for (row, (groups, order, bytes, peak)) in best_by_group.iter().zip(expected_group_bests) {
        assert_eq!(row.candidate.groups, groups);
        assert_eq!(row.candidate.order, order);
        assert_eq!(row.projected_leaf_bytes, bytes);
        assert_eq!(row.analytical_peak, peak);
    }

    let best = best_by_group
        .iter()
        .copied()
        .filter(|row| row.analytical_peak <= 1_000)
        .min_by_key(|row| row.projected_leaf_bytes)
        .expect("at least one stack-feasible candidate");
    assert_eq!(best.candidate.groups, 16);
    assert!(best.candidate.widths.iter().all(|width| *width == 8));
    assert_eq!(best.response_top_bytes, 12_609);
    assert_eq!(best.challenge_table_bytes, 200_843);
    assert_eq!(best.validator_bytes, 774);
    assert_eq!(best.recoder_bytes, 389);
    assert_eq!(best.entry_items, 803);
    assert_eq!(best.analytical_peak, 995);

    let best_g14 = best_by_group[0];
    let best_g15 = best_by_group[1];
    let best_g17 = best_by_group[3];
    assert_eq!(
        best_g14.projected_leaf_bytes - best.projected_leaf_bytes,
        98_864
    );
    assert_eq!(
        best_g15.projected_leaf_bytes - best.projected_leaf_bytes,
        37_714
    );
    assert_eq!(
        best_g17.projected_leaf_bytes - best.projected_leaf_bytes,
        14_830
    );
    // Even granting the G15 alternative a zero-byte recoder leaves a margin
    // over the specialized 389-byte C16 path. Any future reduction in the
    // per-transition kernel cost makes the lower-count C14/C15 rows worse
    // relative to C16 because they save fewer now-cheaper kernels.
    let g15_free_recoder_margin =
        best_g15.projected_leaf_bytes - best_g15.recoder_bytes - best.projected_leaf_bytes;
    assert_eq!(g15_free_recoder_margin, 35_881);

    let generic_peaks = best_by_group
        .iter()
        .map(|row| strict_recoder_probe(&row.candidate.widths, row.candidate.groups == 16))
        .collect::<Vec<_>>();

    println!(
        "best_stack_feasible_challenge_groups={}",
        best.candidate.groups
    );
    println!(
        "best_stack_feasible_widths={}",
        widths_string(&best.candidate.widths)
    );
    println!(
        "best_stack_feasible_leaf_bytes={}",
        best.projected_leaf_bytes
    );
    println!("best_stack_feasible_entry_items={}", best.entry_items);
    println!("best_stack_feasible_peak={}", best.analytical_peak);
    println!("best_recoder_strict_peak={}", generic_peaks[2]);
    println!(
        "g16_margin_over_g15_current_bytes={}",
        best_g15.projected_leaf_bytes - best.projected_leaf_bytes
    );
    println!("g16_margin_over_g15_if_g15_recoder_free_bytes={g15_free_recoder_margin}");
    println!(
        "g16_margin_over_g14_current_bytes={}",
        best_g14.projected_leaf_bytes - best.projected_leaf_bytes
    );
    println!(
        "g17_script_delta_vs_g16_before_stack_rejection={}",
        best_g17.projected_leaf_bytes - best.projected_leaf_bytes
    );
    println!("g17_through_g19_rejected_by_response_peak=true");
    println!("lower_future_pooled_kernel_cost_reinforces_g16_over_g14_g15=true");
    println!("winner=16x8_independent_byte127");
}
