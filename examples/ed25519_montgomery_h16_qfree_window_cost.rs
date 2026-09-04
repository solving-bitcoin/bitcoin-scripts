//! Host-only response-window search for the zero-hint Montgomery H16 leaf.
//!
//! This enumerates balanced G28..G34 partitions of the 253-bit canonical
//! response scalar. Lower widths are restricted to 7..=10 and placed in both
//! narrow-low and wide-low order; top widths 5..=10 are considered whenever
//! the remaining lower partition is balanced. Each row builds only its exact
//! response fixed tables and small scalar-routing fragments. It never builds
//! or executes a complete multi-megabyte leaf.

#[allow(dead_code)]
#[path = "ed25519_fixed_table_actual_model.rs"]
mod fixed_tables;

#[allow(dead_code)]
#[path = "ed25519_g31_scalar_word_validator.rs"]
mod scalar_validation;

use bitcoin_lab::support::script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES};
use std::{collections::BTreeMap, collections::BTreeSet, sync::Mutex};

const SCALAR_BITS: usize = 253;
const SCALAR_WORDS: usize = 8;
const CHALLENGE_GROUPS: usize = 16;
const TRACE_ITEMS_PER_TRANSITION: usize = 16;
const SELECTED_ITEMS: usize = 25;
const TOP_STATE_ITEMS: usize = 25;
const STATE_ITEMS: usize = 41;

// Optimized mixed-chain quotient derivation. The preserved production G29
// baseline below deliberately remains the exact legacy-NAF serialization.
const FIRST_DERIVED_KERNEL_BYTES: usize = 45_355;
const CHAINED_DERIVED_KERNEL_BYTES: usize = 68_171;
const FIRST_DERIVED_LOCAL_PEAK: usize = 214;
const CHAINED_DERIVED_LOCAL_PEAK: usize = 232;

// Fixed independent-byte challenge/hash side from focused policy-produced
// measurements. Response tables, scalar validation, response routing, and
// response kernels are added per row below.
const CHALLENGE_TABLE_BYTES: usize = 200_843;
const CHALLENGE_SCAFFOLD_RAW_BYTES: usize = 5_451;
const CHALLENGE_DERIVED_KERNEL_BYTES: usize = 16 * CHAINED_DERIVED_KERNEL_BYTES;
const PACKED_R_DIRECT_HASH_POLICY_BYTES: usize = 63_830;
const PACKED_R_CONVERSION_POLICY_BYTES: usize = 3_976;
const PACKED_R_HASH_POLICY_BYTES: usize =
    PACKED_R_DIRECT_HASH_POLICY_BYTES + PACKED_R_CONVERSION_POLICY_BYTES;
const INDEPENDENT_BYTE_RECODER_POLICY_BYTES: usize = 389;
const TERMINAL_POLICY_BYTES: usize = 22;
const FIXED_NON_RESPONSE_BYTES: usize = CHALLENGE_TABLE_BYTES
    + CHALLENGE_SCAFFOLD_RAW_BYTES
    + CHALLENGE_DERIVED_KERNEL_BYTES
    + PACKED_R_HASH_POLICY_BYTES
    + INDEPENDENT_BYTE_RECODER_POLICY_BYTES
    + TERMINAL_POLICY_BYTES;
const HASH_STRICT_COMBINED_PEAK: usize = 824;

const BASELINE_GROUPS: usize = 29;
const BASELINE_ENTRY_ITEMS: usize = 712;
const BASELINE_EXACT_ARGUMENT_WITNESS_BYTES: isize = 3_561;
const BASELINE_ADDITIVE_PROJECTED_BYTES: usize = 3_896_335;
const BASELINE_OPTIMIZED_PROJECTED_BYTES: usize = 3_890_903;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LowerOrder {
    NarrowLow,
    WideLow,
    SpreadA,
    SpreadB,
    ScaffoldA,
    ScaffoldB,
    ScaffoldC,
    ExactBest,
}

impl LowerOrder {
    fn label(self) -> &'static str {
        match self {
            Self::NarrowLow => "lohi",
            Self::WideLow => "hilo",
            Self::SpreadA => "spread-a",
            Self::SpreadB => "spread-b",
            Self::ScaffoldA => "scaffold-a",
            Self::ScaffoldB => "scaffold-b",
            Self::ScaffoldC => "scaffold-c",
            Self::ExactBest => "exact-best",
        }
    }
}

#[derive(Clone, Debug)]
struct Variant {
    name: String,
    groups: usize,
    top_width: usize,
    order: LowerOrder,
    widths: Vec<usize>,
}

#[derive(Debug)]
struct Row {
    variant: Variant,
    top_max: usize,
    lower_table_bytes: usize,
    top_table_bytes: usize,
    response_table_bytes: usize,
    scalar_validator_policy_bytes: usize,
    response_scaffold_raw_bytes: usize,
    response_kernel_bytes: usize,
    projected_leaf_bytes: usize,
    entry_items: usize,
    analytical_peak: usize,
    estimated_fixture_witness_bytes: isize,
    conservative_witness_bytes: usize,
}

fn balanced_variants() -> Vec<Variant> {
    let mut variants = Vec::new();
    for groups in 28usize..=34 {
        let lower_groups = groups - 1;
        for top_width in 5usize..=10 {
            let lower_bits = SCALAR_BITS - top_width;
            let narrow_width = lower_bits / lower_groups;
            let wide_count = lower_bits % lower_groups;
            let wide_width = narrow_width + usize::from(wide_count != 0);
            if narrow_width < 7 || wide_width > 10 {
                continue;
            }
            let narrow_count = lower_groups - wide_count;
            let orders: &[LowerOrder] = if wide_count == 0 || narrow_count == 0 {
                &[LowerOrder::NarrowLow]
            } else {
                &[LowerOrder::NarrowLow, LowerOrder::WideLow]
            };
            for order in orders {
                let mut widths = Vec::with_capacity(groups);
                match order {
                    LowerOrder::NarrowLow => {
                        widths.extend(std::iter::repeat_n(narrow_width, narrow_count));
                        widths.extend(std::iter::repeat_n(wide_width, wide_count));
                    }
                    LowerOrder::WideLow => {
                        widths.extend(std::iter::repeat_n(wide_width, wide_count));
                        widths.extend(std::iter::repeat_n(narrow_width, narrow_count));
                    }
                    LowerOrder::SpreadA
                    | LowerOrder::SpreadB
                    | LowerOrder::ScaffoldA
                    | LowerOrder::ScaffoldB
                    | LowerOrder::ScaffoldC
                    | LowerOrder::ExactBest => {
                        unreachable!("spread variants are appended separately")
                    }
                }
                widths.push(top_width);
                assert_eq!(widths.len(), groups);
                assert_eq!(widths.iter().sum::<usize>(), SCALAR_BITS);
                variants.push(Variant {
                    name: format!("g{groups}_t{top_width}_{}", order.label()),
                    groups,
                    top_width,
                    order: *order,
                    widths,
                });
            }
        }
    }

    // The balanced G32/t8 schedule has only three width-7 lower groups. In
    // addition to clustering them at either end, sample two roughly even
    // placements because exact direct-limb push sizes depend on bit position.
    for (order, positions) in [
        (LowerOrder::SpreadA, [0usize, 10, 20]),
        (LowerOrder::SpreadB, [5usize, 15, 25]),
        (LowerOrder::ScaffoldA, [25usize, 29, 30]),
        (LowerOrder::ScaffoldB, [26usize, 29, 30]),
        (LowerOrder::ScaffoldC, [27usize, 29, 30]),
    ] {
        let mut widths = vec![8usize; 31];
        for position in positions {
            widths[position] = 7;
        }
        widths.push(8);
        assert_eq!(widths.iter().sum::<usize>(), SCALAR_BITS);
        variants.push(Variant {
            name: format!("g32_t8_{}", order.label()),
            groups: 32,
            top_width: 8,
            order,
            widths,
        });
    }

    // G31/t8 has five width-9 lower groups among 25 width-8 groups. The spread
    // placements sample the interior; the scaffold placements are the three
    // cheapest exact routing layouts from the exhaustive lightweight search.
    for (order, positions) in [
        (LowerOrder::SpreadA, [0usize, 6, 12, 18, 24]),
        (LowerOrder::SpreadB, [5usize, 11, 17, 23, 29]),
        (LowerOrder::ScaffoldA, [24usize, 25, 26, 27, 28]),
        (LowerOrder::ScaffoldB, [24usize, 25, 26, 27, 29]),
        (LowerOrder::ScaffoldC, [24usize, 25, 26, 28, 29]),
    ] {
        let mut widths = vec![8usize; 30];
        for position in positions {
            widths[position] = 9;
        }
        widths.push(8);
        assert_eq!(widths.iter().sum::<usize>(), SCALAR_BITS);
        variants.push(Variant {
            name: format!("g31_t8_{}", order.label()),
            groups: 31,
            top_width: 8,
            order,
            widths,
        });
    }
    variants
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

fn scalar_items_after_response_transitions(widths: &[usize]) -> Vec<usize> {
    let mut chunks = vec![SCALAR_BITS - 7 * 32];
    chunks.extend(std::iter::repeat_n(32usize, 7));
    let widths_high_to_low = widths.iter().copied().rev().collect::<Vec<_>>();
    let mut chunk = 0usize;
    let mut remainder = chunks[0];
    let mut states = Vec::with_capacity(widths.len());
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
    assert_eq!(states.len(), widths.len() - 1);
    assert_eq!(*states.last().expect("lower response groups"), 0);
    states
}

fn response_scalar_stream(
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

fn reverse_chained_state_blocks() -> Script {
    script! {
        { move_block_to_top(16, 9) }
        { move_block_to_top(8, 25) }
        { move_block_to_top(8, 33) }
    }
}

fn response_callback_glue(transition: usize, scalar_items: usize, width: usize) -> Script {
    let current_items = if transition == 0 {
        TOP_STATE_ITEMS
    } else {
        STATE_ITEMS
    };
    script! {
        { decode_lower_code(width) }
        OP_TOALTSTACK
        // Exact table and kernel bytes are accounted separately.
        OP_FROMALTSTACK
        { apply_selected_sign() }
        { move_block_to_top(
            TRACE_ITEMS_PER_TRANSITION,
            scalar_items + SELECTED_ITEMS,
        ) }
        { move_block_to_top(SELECTED_ITEMS, TRACE_ITEMS_PER_TRANSITION) }
        for _ in 0..current_items { OP_FROMALTSTACK }
        if transition != 0 { { reverse_chained_state_blocks() } }
    }
}

fn response_scaffold(widths: &[usize]) -> Script {
    let scalar_states = scalar_items_after_response_transitions(widths);
    let callbacks = scalar_states
        .iter()
        .copied()
        .enumerate()
        .map(|(transition, scalar_items)| {
            let group = widths.len() - transition - 2;
            response_callback_glue(transition, scalar_items, widths[group])
        })
        .collect::<Vec<_>>();
    response_scalar_stream(widths, move_block_to_top(16, 9), &callbacks)
}

fn raw_fragment_len(fragment: &Script) -> usize {
    let copies = MAX_OPTIMIZER_INPUT_BYTES.div_ceil(fragment.len().max(1)) + 1;
    let repeated = script! {
        for _ in 0..copies { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % copies, 0);
    repeated.len() / copies
}

fn analytical_peak(groups: usize, widths: &[usize], entry_items: usize) -> usize {
    let scalar_states = scalar_items_after_response_transitions(widths);
    let transitions = groups - 1 + CHALLENGE_GROUPS;
    let mut peak = HASH_STRICT_COMBINED_PEAK
        .max(entry_items + 16) // scalar validator
        .max(entry_items + 51); // table/callback selection frontier
    for (transition, scalar_items) in scalar_states.into_iter().enumerate() {
        let future = transitions - transition - 1;
        let preserved = future * TRACE_ITEMS_PER_TRANSITION + scalar_items;
        let local = if transition == 0 {
            FIRST_DERIVED_LOCAL_PEAK
        } else {
            CHAINED_DERIVED_LOCAL_PEAK
        };
        peak = peak.max(preserved + local);
    }
    // Challenge transition zero: 15 trace packets plus 30 controls survive.
    peak.max(15 * TRACE_ITEMS_PER_TRANSITION + 30 + CHAINED_DERIVED_LOCAL_PEAK)
}

fn measure_variant(variant: Variant) -> Row {
    let table =
        fixed_tables::montgomery_direct_h16_independent_response_table_variant(&variant.widths);
    assert_eq!(table.widths_low_to_high, variant.widths);
    assert_eq!(table.response_low_to_high.len(), variant.groups);
    let top_table_bytes = *table
        .per_table_raw_bytes
        .last()
        .expect("top response table");
    let lower_table_bytes = table.total_raw_bytes - top_table_bytes;
    let response_table_bytes = table.total_raw_bytes;
    let validator = scalar_validation::validate_scalar_words_for_widths_preserving(
        &variant.widths,
        TRACE_ITEMS_PER_TRANSITION * (variant.groups - 1 + CHALLENGE_GROUPS),
    );
    let scalar_validator_policy_bytes = validator.compile_with_policy().len();
    let response_scaffold_raw_bytes = raw_fragment_len(&response_scaffold(&variant.widths));
    let response_kernel_bytes =
        FIRST_DERIVED_KERNEL_BYTES + (variant.groups - 2) * CHAINED_DERIVED_KERNEL_BYTES;
    let projected_leaf_bytes = response_table_bytes
        + scalar_validator_policy_bytes
        + response_scaffold_raw_bytes
        + response_kernel_bytes
        + FIXED_NON_RESPONSE_BYTES;
    let entry_items =
        TRACE_ITEMS_PER_TRANSITION * (variant.groups - 1 + CHALLENGE_GROUPS) + SCALAR_WORDS;
    let analytical_peak = analytical_peak(variant.groups, &variant.widths, entry_items);
    let group_delta = variant.groups as isize - BASELINE_GROUPS as isize;
    let estimated_fixture_witness_bytes = BASELINE_EXACT_ARGUMENT_WITNESS_BYTES + 80 * group_delta;
    let conservative_witness_bytes = 3 + 6 * entry_items;
    Row {
        variant,
        top_max: table.top_max,
        lower_table_bytes,
        top_table_bytes,
        response_table_bytes,
        scalar_validator_policy_bytes,
        response_scaffold_raw_bytes,
        response_kernel_bytes,
        projected_leaf_bytes,
        entry_items,
        analytical_peak,
        estimated_fixture_witness_bytes,
        conservative_witness_bytes,
    }
}

fn widths_string(widths: &[usize]) -> String {
    widths
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join("/")
}

fn print_row(row: &Row) {
    println!(
        "variant={} groups={} top_width={} top_max={} order={} widths={} response_table_bytes={} lower_table_bytes={} top_table_bytes={} scalar_validator_policy_bytes={} response_scaffold_raw_bytes={} response_kernel_bytes={} projected_leaf_bytes={} delta_vs_legacy_g29_additive_projection={} entry_items={} entry_item_delta={} analytical_peak={} estimated_fixture_witness_bytes={} conservative_witness_bytes={} accepted_under_1000={}",
        row.variant.name,
        row.variant.groups,
        row.variant.top_width,
        row.top_max,
        row.variant.order.label(),
        widths_string(&row.variant.widths),
        row.response_table_bytes,
        row.lower_table_bytes,
        row.top_table_bytes,
        row.scalar_validator_policy_bytes,
        row.response_scaffold_raw_bytes,
        row.response_kernel_bytes,
        row.projected_leaf_bytes,
        row.projected_leaf_bytes as isize - BASELINE_ADDITIVE_PROJECTED_BYTES as isize,
        row.entry_items,
        row.entry_items as isize - BASELINE_ENTRY_ITEMS as isize,
        row.analytical_peak,
        row.estimated_fixture_witness_bytes,
        row.conservative_witness_bytes,
        row.analytical_peak <= 1_000,
    );
}

fn search_g32_t8_scaffolds() {
    let costs = ResponseScaffoldCostModel::new();
    let mut best = Vec::<(usize, [usize; 3])>::new();
    for first in 0..29 {
        for second in first + 1..30 {
            for third in second + 1..31 {
                let mut widths = vec![8usize; 31];
                for position in [first, second, third] {
                    widths[position] = 7;
                }
                widths.push(8);
                let bytes = costs.raw_len(&widths);
                best.push((bytes, [first, second, third]));
            }
        }
    }
    best.sort_unstable();
    best.truncate(12);
    for (bytes, positions) in best {
        println!("response_scaffold_raw_bytes={bytes} width7_positions={positions:?}");
    }
}

fn search_g31_t8_scaffolds() {
    let costs = ResponseScaffoldCostModel::new();
    let mut best = Vec::<(usize, [usize; 5])>::new();
    for first in 0..26 {
        for second in first + 1..27 {
            for third in second + 1..28 {
                for fourth in third + 1..29 {
                    for fifth in fourth + 1..30 {
                        let mut widths = vec![8usize; 30];
                        for position in [first, second, third, fourth, fifth] {
                            widths[position] = 9;
                        }
                        widths.push(8);
                        let bytes = costs.raw_len(&widths);
                        best.push((bytes, [first, second, third, fourth, fifth]));
                    }
                }
            }
        }
    }
    best.sort_unstable();
    best.truncate(12);
    for (bytes, positions) in best {
        println!("response_scaffold_raw_bytes={bytes} width9_positions={positions:?}");
    }
}

fn for_each_g31_t8_placement(mut visitor: impl FnMut([usize; 5])) {
    for first in 0..26 {
        for second in first + 1..27 {
            for third in second + 1..28 {
                for fourth in third + 1..29 {
                    for fifth in fourth + 1..30 {
                        visitor([first, second, third, fourth, fifth]);
                    }
                }
            }
        }
    }
}

fn g31_t8_widths(positions: [usize; 5]) -> Vec<usize> {
    let mut widths = vec![8usize; 30];
    for position in positions {
        widths[position] = 9;
    }
    widths.push(8);
    assert_eq!(widths.iter().sum::<usize>(), SCALAR_BITS);
    widths
}

fn search_g31_t8_exact() {
    let costs = ResponseScaffoldCostModel::new();
    let mut queries = BTreeSet::<(usize, usize)>::new();
    for_each_g31_t8_placement(|positions| {
        let widths = g31_t8_widths(positions);
        let mut bit_offset = 0usize;
        for width in widths.iter().copied().take(30) {
            queries.insert((bit_offset, width));
            bit_offset += width;
        }
        assert_eq!(bit_offset, 245);
    });
    let queries = queries.into_iter().collect::<Vec<_>>();
    let query_bytes =
        fixed_tables::montgomery_direct_h16_response_lower_table_raw_bytes_at(&queries);
    let table_bytes = queries
        .iter()
        .copied()
        .zip(query_bytes)
        .collect::<BTreeMap<_, _>>();

    // Cross-check the per-offset oracle and top table against an independently
    // generated complete schedule before using them in the exhaustive sum.
    let seed_widths = g31_t8_widths([25, 26, 27, 28, 29]);
    let seed = fixed_tables::montgomery_direct_h16_independent_response_table_variant(&seed_widths);
    let top_table_bytes = *seed
        .per_table_raw_bytes
        .last()
        .expect("G31 has a top response table");
    assert_eq!(top_table_bytes, 12_625);
    let mut bit_offset = 0usize;
    for (width, expected) in seed_widths
        .iter()
        .copied()
        .zip(seed.per_table_raw_bytes.iter().copied())
        .take(30)
    {
        assert_eq!(table_bytes[&(bit_offset, width)], expected);
        bit_offset += width;
    }

    let mut candidates = Vec::<(usize, usize, usize, [usize; 5])>::new();
    for_each_g31_t8_placement(|positions| {
        let widths = g31_t8_widths(positions);
        let mut bit_offset = 0usize;
        let mut response_table_bytes = top_table_bytes;
        for width in widths.iter().copied().take(30) {
            response_table_bytes += table_bytes[&(bit_offset, width)];
            bit_offset += width;
        }
        let response_scaffold_raw_bytes = costs.raw_len(&widths);
        candidates.push((
            response_table_bytes + response_scaffold_raw_bytes,
            response_table_bytes,
            response_scaffold_raw_bytes,
            positions,
        ));
    });
    candidates.sort_unstable();
    println!("lower_table_query_count={}", queries.len());
    println!("placement_count={}", candidates.len());
    for (combined, table, scaffold, positions) in candidates.iter().take(12) {
        println!(
            "response_table_plus_scaffold_bytes={combined} response_table_bytes={table} response_scaffold_raw_bytes={scaffold} width9_positions={positions:?}"
        );
    }

    let (_, expected_table, expected_scaffold, best_positions) = candidates[0];
    let best = Variant {
        name: "g31_t8_exact-best".to_owned(),
        groups: 31,
        top_width: 8,
        order: LowerOrder::ExactBest,
        widths: g31_t8_widths(best_positions),
    };
    let row = measure_variant(best);
    assert_eq!(row.response_table_bytes, expected_table);
    assert_eq!(row.response_scaffold_raw_bytes, expected_scaffold);
    print_row(&row);
}

fn for_each_g32_t8_placement(mut visitor: impl FnMut([usize; 3])) {
    for first in 0..29 {
        for second in first + 1..30 {
            for third in second + 1..31 {
                visitor([first, second, third]);
            }
        }
    }
}

fn g32_t8_widths(positions: [usize; 3]) -> Vec<usize> {
    let mut widths = vec![8usize; 31];
    for position in positions {
        widths[position] = 7;
    }
    widths.push(8);
    assert_eq!(widths.iter().sum::<usize>(), SCALAR_BITS);
    widths
}

fn search_g32_t8_exact() {
    let costs = ResponseScaffoldCostModel::new();
    let mut queries = BTreeSet::<(usize, usize)>::new();
    for_each_g32_t8_placement(|positions| {
        let widths = g32_t8_widths(positions);
        let mut bit_offset = 0usize;
        for width in widths.iter().copied().take(31) {
            queries.insert((bit_offset, width));
            bit_offset += width;
        }
        assert_eq!(bit_offset, 245);
    });
    let queries = queries.into_iter().collect::<Vec<_>>();
    let query_bytes =
        fixed_tables::montgomery_direct_h16_response_lower_table_raw_bytes_at(&queries);
    let table_bytes = queries
        .iter()
        .copied()
        .zip(query_bytes)
        .collect::<BTreeMap<_, _>>();

    let seed_widths = g32_t8_widths([0, 1, 2]);
    let seed = fixed_tables::montgomery_direct_h16_independent_response_table_variant(&seed_widths);
    let top_table_bytes = *seed
        .per_table_raw_bytes
        .last()
        .expect("G32 has a top response table");
    // G32 has 47 post-initializer T additions, so its top representative is
    // U-[K_127]A rather than the stale T-offset representative U+T-[K_127]A.
    assert_eq!(top_table_bytes, 12_609);
    let mut bit_offset = 0usize;
    for (width, expected) in seed_widths
        .iter()
        .copied()
        .zip(seed.per_table_raw_bytes.iter().copied())
        .take(31)
    {
        assert_eq!(table_bytes[&(bit_offset, width)], expected);
        bit_offset += width;
    }

    let mut candidates = Vec::<(usize, usize, usize, [usize; 3])>::new();
    for_each_g32_t8_placement(|positions| {
        let widths = g32_t8_widths(positions);
        let mut bit_offset = 0usize;
        let mut response_table_bytes = top_table_bytes;
        for width in widths.iter().copied().take(31) {
            response_table_bytes += table_bytes[&(bit_offset, width)];
            bit_offset += width;
        }
        let response_scaffold_raw_bytes = costs.raw_len(&widths);
        candidates.push((
            response_table_bytes + response_scaffold_raw_bytes,
            response_table_bytes,
            response_scaffold_raw_bytes,
            positions,
        ));
    });
    candidates.sort_unstable();
    println!("lower_table_query_count={}", queries.len());
    println!("placement_count={}", candidates.len());
    for (combined, table, scaffold, positions) in candidates.iter().take(12) {
        println!(
            "response_table_plus_scaffold_bytes={combined} response_table_bytes={table} response_scaffold_raw_bytes={scaffold} width7_positions={positions:?}"
        );
    }

    let (_, expected_table, expected_scaffold, best_positions) = candidates[0];
    let best = Variant {
        name: "g32_t8_exact-best".to_owned(),
        groups: 32,
        top_width: 8,
        order: LowerOrder::ExactBest,
        widths: g32_t8_widths(best_positions),
    };
    let row = measure_variant(best);
    assert_eq!(row.response_table_bytes, expected_table);
    assert_eq!(row.response_scaffold_raw_bytes, expected_scaffold);
    print_row(&row);
}

struct ResponseScaffoldCostModel {
    initial: [usize; 11],
    split: [[usize; 11]; 32],
    finish: [[usize; 11]; 32],
    callback_first: [[usize; 11]; SCALAR_WORDS + 1],
    callback_chained: [[usize; 11]; SCALAR_WORDS + 1],
    park_top: usize,
    park_state: usize,
    roll_partial: usize,
    compressed_word: usize,
    append_sign_bit: usize,
}

impl ResponseScaffoldCostModel {
    fn new() -> Self {
        let mut initial = [0usize; 11];
        let mut split = [[0usize; 11]; 32];
        let mut finish = [[0usize; 11]; 32];
        let mut callback_first = [[0usize; 11]; SCALAR_WORDS + 1];
        let mut callback_chained = [[0usize; 11]; SCALAR_WORDS + 1];
        for width in 5..=10 {
            initial[width] = script! {
                { split_high(29, width) }
                OP_SWAP
                { move_block_to_top(16, 9) }
            }
            .len();
        }
        for total in 2..=31 {
            for width in 1..=10.min(total - 1) {
                split[total][width] = script! {
                    { split_high(total, width) }
                    OP_SWAP
                }
                .len();
            }
        }
        for partial in 1..=10 {
            for take in 1..=(10 - partial) {
                finish[partial][take] = finish_partial(31, partial, take).len();
            }
        }
        for scalar_items in 0..=SCALAR_WORDS {
            for width in 7..=10 {
                callback_first[scalar_items][width] =
                    response_callback_glue(0, scalar_items, width).len();
                callback_chained[scalar_items][width] =
                    response_callback_glue(1, scalar_items, width).len();
            }
        }
        Self {
            initial,
            split,
            finish,
            callback_first,
            callback_chained,
            park_top: park_current(TOP_STATE_ITEMS).len(),
            park_state: park_current(STATE_ITEMS).len(),
            roll_partial: script! { 1 OP_ROLL }.len(),
            compressed_word: compressed_word_to_low31_and_sign().len(),
            append_sign_bit: script! {
                OP_TOALTSTACK OP_SWAP
                OP_DUP OP_ADD OP_FROMALTSTACK OP_ADD
            }
            .len(),
        }
    }

    fn callback_len(&self, transition: usize, scalar_items: usize, width: usize) -> usize {
        if transition == 0 {
            self.callback_first[scalar_items][width]
        } else {
            self.callback_chained[scalar_items][width]
        }
    }

    fn raw_len(&self, widths_low_to_high: &[usize]) -> usize {
        let scalar_states = scalar_items_after_response_transitions(widths_low_to_high);
        let target_widths = widths_low_to_high.iter().copied().rev().collect::<Vec<_>>();
        let mut target = 0usize;
        let first_width = target_widths[target];
        let mut bytes = self.initial[first_width];
        target += 1;
        let mut remainder_bits = 29 - first_width;

        while remainder_bits >= target_widths[target] {
            let width = target_widths[target];
            bytes += if target == 1 {
                self.park_top
            } else {
                self.park_state
            };
            if remainder_bits != width {
                bytes += self.split[remainder_bits][width];
                remainder_bits -= width;
            } else {
                remainder_bits = 0;
            }
            bytes += self.callback_len(target - 1, scalar_states[target - 1], width);
            target += 1;
        }
        let mut partial_bits = remainder_bits;

        for _word in (0..SCALAR_WORDS - 1).rev() {
            bytes += self.park_state;
            if partial_bits != 0 {
                bytes += self.roll_partial;
            }
            bytes += self.compressed_word;
            if partial_bits == 0 {
                partial_bits = 1;
            } else {
                bytes += self.append_sign_bit;
                partial_bits += 1;
            }
            let width = target_widths[target];
            let needed = width - partial_bits;
            if needed != 0 {
                bytes += self.finish[partial_bits][needed];
            }
            bytes += self.callback_len(target - 1, scalar_states[target - 1], width);
            target += 1;
            remainder_bits = 31 - needed;

            while target < target_widths.len() && remainder_bits >= target_widths[target] {
                let width = target_widths[target];
                bytes += self.park_state;
                if remainder_bits != width {
                    bytes += self.split[remainder_bits][width];
                    remainder_bits -= width;
                } else {
                    remainder_bits = 0;
                }
                bytes += self.callback_len(target - 1, scalar_states[target - 1], width);
                target += 1;
            }
            partial_bits = remainder_bits;
        }
        assert_eq!(target, target_widths.len());
        assert_eq!(partial_bits, 0);
        bytes
    }
}

fn main() {
    let variants = balanced_variants();
    assert!(variants.iter().any(|variant| {
        variant.groups == 29 && variant.top_width == 9 && variant.order == LowerOrder::NarrowLow
    }));

    let mode = std::env::args().nth(1);
    if mode.as_deref() == Some("--search-g32-scaffold") {
        search_g32_t8_scaffolds();
        return;
    }
    if mode.as_deref() == Some("--search-g31-scaffold") {
        search_g31_t8_scaffolds();
        return;
    }
    if mode.as_deref() == Some("--search-g31-exact") {
        search_g31_t8_exact();
        return;
    }
    if mode.as_deref() == Some("--search-g32-exact") {
        search_g32_t8_exact();
        return;
    }
    if let Some(name) = mode.as_deref().filter(|name| *name != "--measure-all") {
        let variant = variants
            .into_iter()
            .find(|variant| variant.name == *name)
            .unwrap_or_else(|| panic!("unknown variant {name}"));
        print_row(&measure_variant(variant));
        return;
    }

    if mode.is_none() {
        println!("model=ed25519_montgomery_h16_qfree_response_window_cost");
        println!("mode=plan-only");
        println!("candidate_count={}", variants.len());
        println!("candidate_groups=28..34");
        println!("candidate_top_widths=5..10");
        println!("full_leaf_built_or_executed=false");
        println!("run_explicitly=--measure-all_or_one_variant_name");
        return;
    }

    // Table generation is host-only and independent per row. Four bounded
    // workers avoid a long serial benchmark without ever concatenating rows.
    let rows = Mutex::new(Vec::with_capacity(variants.len()));
    let workers = 4usize.min(variants.len());
    std::thread::scope(|scope| {
        for worker in 0..workers {
            let rows = &rows;
            let variants = &variants;
            scope.spawn(move || {
                for index in (worker..variants.len()).step_by(workers) {
                    rows.lock()
                        .expect("row lock")
                        .push(measure_variant(variants[index].clone()));
                }
            });
        }
    });
    let mut rows = rows.into_inner().expect("row lock");
    rows.sort_by_key(|row| row.projected_leaf_bytes);

    let baseline = rows
        .iter()
        .find(|row| row.variant.name == "g29_t9_lohi")
        .expect("G29 baseline row");
    assert_eq!(baseline.response_table_bytes, 625_229);
    assert_eq!(baseline.scalar_validator_policy_bytes, 774);
    assert_eq!(baseline.response_scaffold_raw_bytes, 13_681);
    assert_eq!(
        baseline.projected_leaf_bytes,
        BASELINE_OPTIMIZED_PROJECTED_BYTES
    );

    println!("model=ed25519_montgomery_h16_qfree_response_window_cost");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=generation-only");
    println!("execution_class=unclassified");
    println!("candidate_groups=28..34");
    println!("candidate_lower_widths=balanced_7_through_10");
    println!("candidate_top_widths=5..10");
    println!("candidate_orders=narrow-low,wide-low");
    println!("candidate_count={}", rows.len());
    println!("fixed_non_response_bytes={FIXED_NON_RESPONSE_BYTES}");
    println!("fixed_challenge_table_bytes={CHALLENGE_TABLE_BYTES}");
    println!("fixed_challenge_scaffold_raw_bytes={CHALLENGE_SCAFFOLD_RAW_BYTES}");
    println!("fixed_challenge_kernel_bytes={CHALLENGE_DERIVED_KERNEL_BYTES}");
    println!("fixed_packed_r_direct_hash_policy_bytes={PACKED_R_DIRECT_HASH_POLICY_BYTES}");
    println!("fixed_packed_r_conversion_policy_bytes={PACKED_R_CONVERSION_POLICY_BYTES}");
    println!("fixed_packed_r_hash_policy_bytes={PACKED_R_HASH_POLICY_BYTES}");
    println!("fixed_packed_r_hash_manual_post_policy_optimizer=false");
    println!("legacy_g29_additive_projected_leaf_bytes={BASELINE_ADDITIVE_PROJECTED_BYTES}");
    println!("fixed_independent_recoder_policy_bytes={INDEPENDENT_BYTE_RECODER_POLICY_BYTES}");
    println!("fixed_terminal_policy_bytes={TERMINAL_POLICY_BYTES}");
    println!("witness_byte_delta_model=estimated_80_and_conservative_96_per_added_response_group");
    println!("full_leaf_built_or_executed=false");
    for row in &rows {
        print_row(row);
    }
    let best = rows.first().expect("at least one candidate");
    println!("best_variant={}", best.variant.name);
    println!("best_projected_leaf_bytes={}", best.projected_leaf_bytes);
    println!(
        "best_delta_vs_legacy_g29_additive_projection={}",
        best.projected_leaf_bytes as isize - BASELINE_ADDITIVE_PROJECTED_BYTES as isize
    );
    println!("best_entry_items={}", best.entry_items);
    println!("best_analytical_peak={}", best.analytical_peak);
}
