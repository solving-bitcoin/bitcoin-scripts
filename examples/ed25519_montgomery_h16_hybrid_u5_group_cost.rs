//! Bounded G28..G34 cost comparison for the zero-hint hybrid-u5 leaf.
//!
//! Each row constructs only one exact response-table family plus the small
//! response scheduler and scalar validator. The fixed challenge, BLAKE3, and
//! relation-kernel costs are imported from focused measurements; this program
//! never concatenates or executes a complete multi-megabyte leaf.
//! The relation-kernel checkpoints predate the later symmetric-square and
//! shared-power-pool reductions, so these rows are retained as a superseded
//! comparison model rather than the current G32 whole-leaf result.

#[allow(dead_code)]
#[path = "ed25519_fixed_table_actual_model.rs"]
mod fixed_tables;

#[allow(dead_code)]
#[path = "ed25519_montgomery_h16_hybrid_scheduler.rs"]
mod hybrid_scheduler;

use bitcoin_lab::support::script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES};

const SCALAR_BITS: usize = 253;
const CHALLENGE_GROUPS: usize = 16;
const TRACE_ITEMS_PER_PACKET: usize = 16;
const SCALAR_ITEMS: usize = 8;
const FINAL_R_U5_EXTRA_ITEMS: usize = 43;

const HYBRID_FIRST_KERNEL_BYTES: usize = 40_183;
const HYBRID_CHAINED_KERNEL_BYTES: usize = 53_193;
const HYBRID_FIRST_LOCAL_PEAK: usize = 208;
const HYBRID_CHAINED_LOCAL_PEAK: usize = 224;
const HYBRID_U5_FINAL_LOCAL_PEAK: usize = 267;

const CHALLENGE_TABLE_BYTES: usize = 200_843;
const CHALLENGE_SCAFFOLD_BYTES: usize = 5_829;
const CHALLENGE_NORMAL_KERNELS: usize = 15;
const CHALLENGE_FINAL_TERMINAL_KERNEL_BYTES: usize = 48_492;
const CHALLENGE_SCHEDULE_BYTES: usize = CHALLENGE_TABLE_BYTES
    + CHALLENGE_SCAFFOLD_BYTES
    + CHALLENGE_NORMAL_KERNELS * HYBRID_CHAINED_KERNEL_BYTES
    + CHALLENGE_FINAL_TERMINAL_KERNEL_BYTES;
const HYBRID_U5_HASH_BYTES: usize = 67_137;
const INDEPENDENT_BYTE_RECODER_BYTES: usize = 389;
const FIXED_NON_RESPONSE_BYTES: usize =
    CHALLENGE_SCHEDULE_BYTES + HYBRID_U5_HASH_BYTES + INDEPENDENT_BYTE_RECODER_BYTES;

const G32_EXACT_ARGUMENT_WITNESS_BYTES: isize = 3_801;
const FINAL_R_U5_FIXTURE_WITNESS_DELTA: isize = 62;
const ESTIMATED_WITNESS_BYTES_PER_RESPONSE_GROUP: isize = 80;
const PACKED_R_SCRIPT_PENALTY_BYTES: usize = 5_288;

#[derive(Clone)]
struct Candidate {
    name: &'static str,
    widths: Vec<usize>,
    expected_table_bytes: usize,
    expected_scaffold_bytes: usize,
    expected_validator_bytes: usize,
    expected_leaf_bytes: usize,
}

fn repeated(width: usize, count: usize) -> impl Iterator<Item = usize> {
    std::iter::repeat_n(width, count)
}

fn widths_with_top(lower: impl IntoIterator<Item = usize>, top: usize) -> Vec<usize> {
    let mut widths = lower.into_iter().collect::<Vec<_>>();
    widths.push(top);
    assert_eq!(widths.iter().sum::<usize>(), SCALAR_BITS);
    widths
}

fn candidates() -> Vec<Candidate> {
    let g28 = widths_with_top(std::iter::once(10).chain(repeated(9, 26)), 9);
    let g29 = widths_with_top(repeated(8, 8).chain(repeated(9, 20)), 9);
    let g30 = widths_with_top(repeated(8, 16).chain(repeated(9, 13)), 8);
    let g31 = hybrid_scheduler::g31_widths_low_to_high();
    let g32 = hybrid_scheduler::g32_widths_low_to_high();
    let g33 = widths_with_top(repeated(8, 21).chain(repeated(7, 11)), 8);
    let g34 = widths_with_top(repeated(8, 14).chain(repeated(7, 19)), 8);

    vec![
        Candidate {
            name: "g28_t9_hilo",
            widths: g28,
            expected_table_bytes: 724_534,
            expected_scaffold_bytes: 13_507,
            expected_validator_bytes: 773,
            expected_leaf_bytes: 3_282_600,
        },
        Candidate {
            name: "g29_t9_lohi",
            widths: g29,
            expected_table_bytes: 625_229,
            expected_scaffold_bytes: 13_843,
            expected_validator_bytes: 774,
            expected_leaf_bytes: 3_236_825,
        },
        Candidate {
            name: "g30_t8_lohi",
            widths: g30,
            expected_table_bytes: 538_254,
            expected_scaffold_bytes: 14_084,
            expected_validator_bytes: 774,
            expected_leaf_bytes: 3_203_284,
        },
        Candidate {
            name: "g31_t8_exact_best",
            widths: g31,
            expected_table_bytes: 451_272,
            expected_scaffold_bytes: 14_412,
            expected_validator_bytes: 774,
            expected_leaf_bytes: 3_169_823,
        },
        Candidate {
            name: "g32_t8_exact_best",
            widths: g32,
            expected_table_bytes: 383_004,
            expected_scaffold_bytes: 14_701,
            expected_validator_bytes: 774,
            expected_leaf_bytes: 3_155_037,
        },
        Candidate {
            name: "g33_t8_hilo",
            widths: g33,
            expected_table_bytes: 345_801,
            expected_scaffold_bytes: 15_085,
            expected_validator_bytes: 774,
            expected_leaf_bytes: 3_171_411,
        },
        Candidate {
            name: "g34_t8_hilo",
            widths: g34,
            expected_table_bytes: 308_544,
            expected_scaffold_bytes: 15_582,
            expected_validator_bytes: 774,
            expected_leaf_bytes: 3_187_844,
        },
    ]
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

fn widths_string(widths: &[usize]) -> String {
    widths
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join("/")
}

fn main() {
    assert_eq!(CHALLENGE_SCHEDULE_BYTES, 1_053_059);
    assert_eq!(FIXED_NON_RESPONSE_BYTES, 1_120_585);

    println!("model=ed25519_montgomery_h16_hybrid_u5_group_cost");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=generation-only");
    println!("execution_class=unclassified");
    println!("projection_status=superseded_pre_symmetric_square_and_shared_power_pool");
    println!("candidate_scope=bounded_balanced_G28_through_G34");
    println!("quotient_hint_items=0");
    println!("complete_hint_items=0");
    println!("fixed_challenge_schedule_bytes={CHALLENGE_SCHEDULE_BYTES}");
    println!("fixed_u5_hash_bytes={HYBRID_U5_HASH_BYTES}");
    println!("fixed_u5_hash_manual_post_policy_optimizer=false");
    println!("fixed_independent_byte_recoder_bytes={INDEPENDENT_BYTE_RECODER_BYTES}");
    println!("full_leaf_built_or_executed=false");

    let mut measured = Vec::new();
    for candidate in candidates() {
        let groups = candidate.widths.len();
        assert!((28..=34).contains(&groups));
        let response_transitions = groups - 1;
        let top_with_t = (response_transitions + CHALLENGE_GROUPS) % 2 == 0;

        let tables = fixed_tables::montgomery_direct_h16_independent_response_table_variant(
            &candidate.widths,
        );
        assert_eq!(tables.widths_low_to_high, candidate.widths);
        assert_eq!(tables.response_low_to_high.len(), groups);
        assert_eq!(tables.total_raw_bytes, candidate.expected_table_bytes);
        let top_table_bytes = *tables
            .per_table_raw_bytes
            .last()
            .expect("every candidate has a top table");
        let lower_table_bytes = tables.total_raw_bytes - top_table_bytes;

        let scaffold = hybrid_scheduler::hybrid_response_scaffolding_for_widths(&candidate.widths);
        let scaffold_bytes = raw_fragment_len(&scaffold);
        assert_eq!(scaffold_bytes, candidate.expected_scaffold_bytes);
        let validator = hybrid_scheduler::hybrid_u5_scalar_validator_for_widths(&candidate.widths)
            .compile_with_policy();
        let validator_bytes = validator.len();
        assert_eq!(validator_bytes, candidate.expected_validator_bytes);

        let response_kernel_bytes =
            HYBRID_FIRST_KERNEL_BYTES + (groups - 2) * HYBRID_CHAINED_KERNEL_BYTES;
        let response_schedule_bytes =
            tables.total_raw_bytes + scaffold_bytes + response_kernel_bytes;
        let leaf_bytes = response_schedule_bytes + validator_bytes + FIXED_NON_RESPONSE_BYTES;
        assert_eq!(leaf_bytes, candidate.expected_leaf_bytes);

        let entry_items = TRACE_ITEMS_PER_PACKET * (response_transitions + CHALLENGE_GROUPS)
            + SCALAR_ITEMS
            + FINAL_R_U5_EXTRA_ITEMS;
        assert_eq!(entry_items, 16 * groups + 291);
        let response_first_preserved = entry_items - 16;
        let response_chained_preserved = entry_items - 32;
        let response_first_peak = response_first_preserved + HYBRID_FIRST_LOCAL_PEAK;
        let response_chained_peak = response_chained_preserved + HYBRID_CHAINED_LOCAL_PEAK;
        assert_eq!(response_first_peak, response_chained_peak);
        let analytical_peak = response_first_peak;
        assert_eq!(analytical_peak, 16 * groups + 483);
        assert!(analytical_peak > HYBRID_U5_FINAL_LOCAL_PEAK);

        let group_delta = groups as isize - 32;
        let estimated_argument_witness_bytes = G32_EXACT_ARGUMENT_WITNESS_BYTES
            + FINAL_R_U5_FIXTURE_WITNESS_DELTA
            + group_delta * ESTIMATED_WITNESS_BYTES_PER_RESPONSE_GROUP;
        let conservative_argument_witness_bytes = 3 + 6 * entry_items;
        let objective = leaf_bytes as isize + estimated_argument_witness_bytes;
        let accepted = analytical_peak <= 1_000;

        println!(
            "variant={} groups={} widths={} top_max={} top_initializer={} response_table_bytes={} lower_table_bytes={} top_table_bytes={} response_scaffold_bytes={} scalar_validator_policy_bytes={} response_kernel_bytes={} projected_leaf_bytes={} complete_entry_items={} hint_items=0 response_t0_preserved={} response_t1_preserved={} analytical_peak={} peak_locations=response_transition_0,response_transition_1 accepted_under_1000={} estimated_fixture_argument_witness_bytes={} conservative_argument_witness_bytes={} projected_script_plus_estimated_argument_witness={}",
            candidate.name,
            groups,
            widths_string(&candidate.widths),
            tables.top_max,
            if top_with_t {
                "U_plus_T_minus_K127A"
            } else {
                "U_minus_K127A"
            },
            tables.total_raw_bytes,
            lower_table_bytes,
            top_table_bytes,
            scaffold_bytes,
            validator_bytes,
            response_kernel_bytes,
            leaf_bytes,
            entry_items,
            response_first_preserved,
            response_chained_preserved,
            analytical_peak,
            accepted,
            estimated_argument_witness_bytes,
            conservative_argument_witness_bytes,
            objective,
        );
        measured.push((leaf_bytes, objective, groups, accepted));
    }

    measured.sort_unstable();
    let best_script = measured[0];
    assert_eq!(best_script.2, 32);
    assert!(best_script.3);
    let mut feasible_objectives = measured
        .iter()
        .copied()
        .filter(|row| row.3)
        .collect::<Vec<_>>();
    feasible_objectives.sort_unstable_by_key(|row| row.1);
    let best_objective = feasible_objectives[0];
    assert_eq!(best_objective.2, 32);

    let g31 = measured.iter().find(|row| row.2 == 31).unwrap();
    let g32 = measured.iter().find(|row| row.2 == 32).unwrap();
    let g33 = measured.iter().find(|row| row.2 == 33).unwrap();
    let g34 = measured.iter().find(|row| row.2 == 34).unwrap();
    assert_eq!(g31.0 - g32.0, 14_786);
    assert_eq!(g31.1 - g32.1, 14_706);
    assert!(!g33.3 && !g34.3);

    println!("best_feasible_groups={}", best_objective.2);
    println!("best_feasible_leaf_bytes={}", best_objective.0);
    println!(
        "best_feasible_script_plus_estimated_argument_witness={}",
        best_objective.1
    );
    println!("g32_script_margin_over_g31_bytes={}", g31.0 - g32.0);
    println!("g32_objective_margin_over_g31_bytes={}", g31.1 - g32.1);
    println!("g33_direct_u5_rejected_peak={}", 16 * 33 + 483);
    println!("g34_direct_u5_rejected_peak={}", 16 * 34 + 483);
    println!(
        "g33_packed_r_fallback_leaf_bytes={}",
        g33.0 + PACKED_R_SCRIPT_PENALTY_BYTES
    );
    println!("g33_packed_r_fallback_peak={}", 16 * 33 + 440);
    println!(
        "g34_packed_r_fallback_leaf_bytes={}",
        g34.0 + PACKED_R_SCRIPT_PENALTY_BYTES
    );
    println!("g34_packed_r_fallback_peak={}", 16 * 34 + 440);
    println!("winner=g32_t8_exact_best_hybrid_u5");
}
