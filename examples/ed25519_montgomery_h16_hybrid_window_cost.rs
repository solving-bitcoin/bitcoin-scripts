//! Exact bounded response-window cost search for the persistent hybrid state.
//!
//! This enumerates all `C(31,3) = 4,495` balanced G32/t8 placements. It uses
//! the per-offset authenticated-table byte oracle and the exact next-input-
//! order hybrid scheduler scaffold. It does not concatenate or execute a
//! scalar schedule, BLAKE3 fragment, or complete leaf.

#[allow(dead_code)]
#[path = "ed25519_fixed_table_actual_model.rs"]
mod fixed_tables;

#[allow(dead_code)]
#[path = "ed25519_montgomery_h16_hybrid_scheduler.rs"]
mod hybrid_scheduler;

use std::collections::{BTreeMap, BTreeSet};

const SCALAR_BITS: usize = 253;
const LOWER_GROUPS: usize = 31;
const TOP_WIDTH: usize = 8;
const EXPECTED_PLACEMENTS: usize = 4_495;
const EXPECTED_TOP_TABLE_BYTES: usize = 12_609;
const EXPECTED_BEST_POSITIONS: [usize; 3] = [21, 25, 29];
const EXPECTED_BEST_TABLE_BYTES: usize = 383_004;
const EXPECTED_BEST_SCAFFOLD_BYTES: usize = 14_701;

fn widths(positions: [usize; 3]) -> Vec<usize> {
    let mut widths = vec![8usize; LOWER_GROUPS];
    for position in positions {
        widths[position] = 7;
    }
    widths.push(TOP_WIDTH);
    assert_eq!(widths.iter().sum::<usize>(), SCALAR_BITS);
    widths
}

fn for_each_placement(mut visitor: impl FnMut([usize; 3])) {
    for first in 0..LOWER_GROUPS - 2 {
        for second in first + 1..LOWER_GROUPS - 1 {
            for third in second + 1..LOWER_GROUPS {
                visitor([first, second, third]);
            }
        }
    }
}

fn main() {
    let mut queries = BTreeSet::<(usize, usize)>::new();
    for_each_placement(|positions| {
        let widths = widths(positions);
        let mut bit_offset = 0usize;
        for width in widths.iter().copied().take(LOWER_GROUPS) {
            queries.insert((bit_offset, width));
            bit_offset += width;
        }
        assert_eq!(bit_offset, SCALAR_BITS - TOP_WIDTH);
    });
    let queries = queries.into_iter().collect::<Vec<_>>();
    let query_bytes =
        fixed_tables::montgomery_direct_h16_response_lower_table_raw_bytes_at(&queries);
    let table_bytes = queries
        .iter()
        .copied()
        .zip(query_bytes)
        .collect::<BTreeMap<_, _>>();

    // The seed is used only to cross-check the oracle and obtain the corrected
    // odd-transition top table. G32 has no initial torsion offset.
    let seed_widths = widths([0, 1, 2]);
    let seed = fixed_tables::montgomery_direct_h16_independent_response_table_variant(&seed_widths);
    let top_table_bytes = *seed
        .per_table_raw_bytes
        .last()
        .expect("G32 top response table");
    assert_eq!(top_table_bytes, EXPECTED_TOP_TABLE_BYTES);
    let mut bit_offset = 0usize;
    for (width, expected) in seed_widths
        .iter()
        .copied()
        .zip(seed.per_table_raw_bytes.iter().copied())
        .take(LOWER_GROUPS)
    {
        assert_eq!(table_bytes[&(bit_offset, width)], expected);
        bit_offset += width;
    }

    let mut candidates = Vec::<(usize, usize, usize, [usize; 3])>::new();
    for_each_placement(|positions| {
        let widths = widths(positions);
        let mut bit_offset = 0usize;
        let mut response_table_bytes = top_table_bytes;
        for width in widths.iter().copied().take(LOWER_GROUPS) {
            response_table_bytes += table_bytes[&(bit_offset, width)];
            bit_offset += width;
        }
        let response_scaffold_bytes =
            hybrid_scheduler::hybrid_response_scaffolding_for_widths(&widths).len();
        candidates.push((
            response_table_bytes + response_scaffold_bytes,
            response_table_bytes,
            response_scaffold_bytes,
            positions,
        ));
    });
    assert_eq!(candidates.len(), EXPECTED_PLACEMENTS);
    candidates.sort_unstable();

    let (best_combined, best_table, best_scaffold, best_positions) = candidates[0];
    assert_eq!(best_positions, EXPECTED_BEST_POSITIONS);
    assert_eq!(best_table, EXPECTED_BEST_TABLE_BYTES);
    assert_eq!(best_scaffold, EXPECTED_BEST_SCAFFOLD_BYTES);
    assert_eq!(
        hybrid_scheduler::g32_widths_low_to_high(),
        widths(best_positions)
    );

    println!("model=ed25519_montgomery_h16_hybrid_window_cost");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=generation-only");
    println!("execution_class=unclassified");
    println!("response_groups=32");
    println!("top_width={TOP_WIDTH}");
    println!("width7_count=3");
    println!("placement_count={}", candidates.len());
    println!("lower_table_query_count={}", queries.len());
    println!("top_initializer=U_minus_K127A_without_initial_T");
    println!("top_table_bytes={top_table_bytes}");
    println!("best_width7_positions={best_positions:?}");
    println!("best_response_table_bytes={best_table}");
    println!("best_response_scaffold_raw_bytes={best_scaffold}");
    println!("best_table_plus_scaffold_bytes={best_combined}");
    let (second_combined, second_table, second_scaffold, second_positions) = candidates[1];
    println!("second_width7_positions={second_positions:?}");
    println!("second_response_table_bytes={second_table}");
    println!("second_response_scaffold_raw_bytes={second_scaffold}");
    println!("second_table_plus_scaffold_bytes={second_combined}");
    println!(
        "best_margin_over_second_bytes={}",
        second_combined - best_combined
    );
    println!("hybrid_state_is_next_input_order=true");
    println!("pre_parity_fix_table_cost_reused=false");
    println!("authenticated_table_fragments_concatenated=false");
    println!("blake3_built_or_executed=false");
    println!("full_leaf_built_or_executed=false");
}
