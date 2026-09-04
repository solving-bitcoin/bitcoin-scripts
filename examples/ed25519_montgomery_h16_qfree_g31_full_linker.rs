//! Generation-only linker for the optimized G31 zero-hint Montgomery H16 leaf.
//!
//! This is deliberately separate from the byte-exact legacy-NAF G29 linker.
//! Its response scalar uses the exhaustively selected low-to-high schedule:
//! width nine at lower positions 20,21,22,23,26; width eight at every other
//! lower position and at the unsigned top. Quotients are derived with the
//! optimized mixed multiplier, so all 46 transitions require zero hint items.
//!
//! Exact entry, bottom-to-top, is
//! `challenge_trace[16] | response_trace[30] | scalar_words[8]`: 736 hostile
//! trace items plus eight canonical compressed-u32 scalar words. Default mode
//! checks only this shape. `--measure-bytes` explicitly opts into assembling
//! (but never executing) the multi-megabyte leaf.

#[allow(dead_code)]
#[path = "ed25519_fixed_table_actual_model.rs"]
mod table_model;

#[allow(dead_code)]
#[path = "ed25519_h16_midpoint_glue.rs"]
mod midpoint;

#[allow(dead_code)]
#[path = "ed25519_montgomery_h16_qfree_scheduler.rs"]
mod qfree_scheduler;

use bitcoin::{script::Instruction, ScriptBuf};
use bitcoin_lab::{
    hashes::blake3::ed25519_challenge,
    support::script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
};

const RESPONSE_GROUPS: usize = 31;
const CHALLENGE_GROUPS: usize = 16;
const FINAL_STATE_ITEMS: usize = 41;
const TRACE_ITEMS: usize = (RESPONSE_GROUPS - 1 + CHALLENGE_GROUPS) * 16;
const SCALAR_ITEMS: usize = 8;
const ENTRY_ITEMS: usize = TRACE_ITEMS + SCALAR_ITEMS;
const AUXILIARY_HINT_ITEMS: usize = 0;

const EXPECTED_RESPONSE_TABLE_BYTES: usize = 451_272;
const EXPECTED_CHALLENGE_TABLE_BYTES: usize = 200_843;
const EXPECTED_TABLE_BYTES: usize = 652_115;
const EXPECTED_SCALAR_VALIDATOR_POLICY_BYTES: usize = 774;
const EXPECTED_RESPONSE_SCAFFOLD_RAW_BYTES: usize = 14_238;
const EXPECTED_CHALLENGE_SCAFFOLD_RAW_BYTES: usize = 5_451;
const EXPECTED_FIRST_DERIVED_KERNEL_BYTES: usize = 45_355;
const EXPECTED_RESPONSE_CHAINED_KERNEL_BYTES: usize = 29 * 68_171;
const EXPECTED_CHALLENGE_CHAINED_KERNEL_BYTES: usize = 16 * 68_171;
const EXPECTED_RESPONSE_SCHEDULE_BYTES: usize = 2_487_824;
const EXPECTED_CHALLENGE_SCHEDULE_BYTES: usize = 1_297_030;
const EXPECTED_PACKED_R_DIRECT_HASH_POLICY_BYTES: usize = 63_830;
const EXPECTED_PACKED_R_CONVERSION_POLICY_BYTES: usize = 3_976;
const EXPECTED_PACKED_R_HASH_BYTES: usize =
    EXPECTED_PACKED_R_DIRECT_HASH_POLICY_BYTES + EXPECTED_PACKED_R_CONVERSION_POLICY_BYTES;
const EXPECTED_INDEPENDENT_RECODER_POLICY_BYTES: usize = 389;
const EXPECTED_TERMINAL_POLICY_BYTES: usize = 22;
// Exact sum of focused policy-produced components. The whole leaf remains a
// projection until `--measure-bytes` explicitly regenerates its serialization.
const ADDITIVE_PROJECTED_LINKED_SCRIPT_BYTES: usize = 3_853_845;
const ANALYTICAL_DERIVED_COMBINED_STACK_PEAK: usize = 944;

const FIXTURE_PUBLIC_KEY: [u8; 32] = [
    0x7d, 0xb0, 0xdc, 0x92, 0x22, 0xf3, 0xc1, 0x83, 0x45, 0x7d, 0xdd, 0xe4, 0xc7, 0x08, 0xde, 0x8e,
    0x5e, 0xa6, 0xbf, 0x3d, 0x5c, 0x44, 0x04, 0xcc, 0xa1, 0x4b, 0x32, 0x72, 0x9a, 0x05, 0xc3, 0x2a,
];

fn challenge_domain() -> [u8; 32] {
    *blake3::hash(b"bitcoin-lab/custom-ed25519-blake3-slope-v1").as_bytes()
}

fn fixed_message() -> [u8; 32] {
    std::array::from_fn(|index| (index as u8).wrapping_mul(7))
}

fn policy_precompile(name: &'static str, fragment: Script) -> Script {
    Script::new(name).push_script(fragment.compile_with_policy())
}

fn terminal_cleanstack_predicate() -> Script {
    script! {
        for _ in 0..FINAL_STATE_ITEMS / 2 { OP_2DROP }
        if FINAL_STATE_ITEMS % 2 != 0 { OP_DROP }
        OP_1
    }
}

fn static_non_push_opcodes(script: &ScriptBuf) -> usize {
    script
        .instructions()
        .map(|instruction| instruction.expect("generated script must parse"))
        .filter(
            |instruction| matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() > 0x60),
        )
        .count()
}

struct LinkedLeaf {
    whole: Script,
    response_table_bytes: usize,
    challenge_table_bytes: usize,
    scalar_validator_bytes: usize,
    response_bytes: usize,
    hash_bytes: usize,
    recoder_bytes: usize,
    challenge_bytes: usize,
    terminal_bytes: usize,
}

fn build_linked_leaf() -> LinkedLeaf {
    let widths = table_model::montgomery_direct_h16_qfree_g31_response_widths();
    let table_model::MontgomeryDirectH16TableFragments {
        response_low_to_high,
        challenge_low_to_high,
        public_key_compressed,
    } = table_model::montgomery_direct_h16_qfree_g31_table_fragments();
    assert_eq!(public_key_compressed, FIXTURE_PUBLIC_KEY);
    assert_eq!(response_low_to_high.len(), RESPONSE_GROUPS);
    assert_eq!(challenge_low_to_high.len(), CHALLENGE_GROUPS);

    let response_table_bytes = response_low_to_high.iter().map(Script::len).sum();
    let challenge_table_bytes = challenge_low_to_high.iter().map(Script::len).sum();
    assert_eq!(response_table_bytes, EXPECTED_RESPONSE_TABLE_BYTES);
    assert_eq!(challenge_table_bytes, EXPECTED_CHALLENGE_TABLE_BYTES);
    assert_eq!(
        response_table_bytes + challenge_table_bytes,
        EXPECTED_TABLE_BYTES
    );

    let scalar_validator = policy_precompile(
        "policy-precompiled G31 q-free scalar validator",
        qfree_scheduler::qfree_scalar_validator_for_widths(&widths),
    );
    let response = qfree_scheduler::build_qfree_response_stream_for_widths(
        response_low_to_high,
        &widths,
        qfree_scheduler::DerivedKernelStyle::OptimizedMixed,
    );
    let hash =
        ed25519_challenge::key_specialized_compute_script_preserving_truncated_128_fixed_message_from_certified_packed_r(
            challenge_domain(),
            public_key_compressed,
            fixed_message(),
            qfree_scheduler::QFREE_HASH_PRESERVED_ITEMS as u32,
            qfree_scheduler::QFREE_HASH_R_WORD0_DEPTH as u32,
        );
    let recoder = policy_precompile(
        "policy-precompiled independent-byte challenge recoder",
        midpoint::recode_blake3_low128_independent_byte127(
            qfree_scheduler::QFREE_HASH_PRESERVED_ITEMS,
        ),
    );
    let challenge = qfree_scheduler::build_qfree_challenge_schedule_with_style(
        challenge_low_to_high,
        qfree_scheduler::DerivedKernelStyle::OptimizedMixed,
    );
    let terminal = policy_precompile(
        "policy-precompiled G31 q-free cleanstack predicate",
        terminal_cleanstack_predicate(),
    );

    let scalar_validator_bytes = scalar_validator.len();
    let response_bytes = response.len();
    let hash_bytes = hash.len();
    let recoder_bytes = recoder.len();
    let challenge_bytes = challenge.len();
    let terminal_bytes = terminal.len();
    assert_eq!(
        scalar_validator_bytes,
        EXPECTED_SCALAR_VALIDATOR_POLICY_BYTES
    );
    assert_eq!(response_bytes, EXPECTED_RESPONSE_SCHEDULE_BYTES);
    assert_eq!(challenge_bytes, EXPECTED_CHALLENGE_SCHEDULE_BYTES);
    assert_eq!(hash_bytes, EXPECTED_PACKED_R_HASH_BYTES);
    assert_eq!(recoder_bytes, EXPECTED_INDEPENDENT_RECODER_POLICY_BYTES);
    assert_eq!(terminal_bytes, EXPECTED_TERMINAL_POLICY_BYTES);
    assert_eq!(
        response_bytes,
        EXPECTED_RESPONSE_TABLE_BYTES
            + EXPECTED_RESPONSE_SCAFFOLD_RAW_BYTES
            + EXPECTED_FIRST_DERIVED_KERNEL_BYTES
            + EXPECTED_RESPONSE_CHAINED_KERNEL_BYTES
    );
    assert_eq!(
        challenge_bytes,
        EXPECTED_CHALLENGE_TABLE_BYTES
            + EXPECTED_CHALLENGE_SCAFFOLD_RAW_BYTES
            + EXPECTED_CHALLENGE_CHAINED_KERNEL_BYTES
    );

    let whole = script! {
        { scalar_validator }
        { response }
        { hash }
        { recoder }
        { challenge }
        { terminal }
    };
    LinkedLeaf {
        whole,
        response_table_bytes,
        challenge_table_bytes,
        scalar_validator_bytes,
        response_bytes,
        hash_bytes,
        recoder_bytes,
        challenge_bytes,
        terminal_bytes,
    }
}

fn check_shape() {
    let widths = table_model::montgomery_direct_h16_qfree_g31_response_widths();
    let width9_positions = widths
        .iter()
        .copied()
        .enumerate()
        .filter_map(|(position, width)| (width == 9).then_some(position))
        .collect::<Vec<_>>();
    assert_eq!(widths.len(), RESPONSE_GROUPS);
    assert_eq!(widths.iter().sum::<usize>(), 253);
    assert_eq!(width9_positions, [20, 21, 22, 23, 26]);
    assert_eq!(*widths.last().expect("top width"), 8);
    assert_eq!(TRACE_ITEMS, 736);
    assert_eq!(ENTRY_ITEMS, 744);
    assert_eq!(
        qfree_scheduler::qfree_entry_items_for_widths(&widths),
        ENTRY_ITEMS
    );
    assert_eq!(
        qfree_scheduler::qfree_response_scaffolding_for_widths(&widths).len(),
        EXPECTED_RESPONSE_SCAFFOLD_RAW_BYTES
    );
    assert_eq!(
        qfree_scheduler::qfree_scalar_validator_for_widths(&widths)
            .compile_with_policy()
            .len(),
        EXPECTED_SCALAR_VALIDATOR_POLICY_BYTES
    );
    assert_eq!(qfree_scheduler::QFREE_HASH_PRESERVED_ITEMS, 297);
    assert_eq!(qfree_scheduler::QFREE_HASH_R_WORD0_DEPTH, 289);
    assert!(ANALYTICAL_DERIVED_COMBINED_STACK_PEAK < 1_000);

    println!("model=ed25519_montgomery_h16_qfree_g31_full_linker");
    println!("mode=shape-only");
    println!("multi_megabyte_generation_performed=false");
    println!("whole_leaf_execution_performed=false");
    println!("entry_layout=challenge16_trace|response30_trace|scalar8");
    println!("response_widths_low_to_high={widths:?}");
    println!("response_width9_positions={width9_positions:?}");
    println!("trace_data_items={TRACE_ITEMS}");
    println!("scalar_data_items={SCALAR_ITEMS}");
    println!("auxiliary_hint_items={AUXILIARY_HINT_ITEMS}");
    println!("complete_argument_items_at_script_entry={ENTRY_ITEMS}");
    println!("all_entry_items_coexist=true");
    println!("transition_auxiliary_hint_items_per_invocation=0");
    println!("transition_invocations=46");
    println!("additive_projected_policy_script_bytes={ADDITIVE_PROJECTED_LINKED_SCRIPT_BYTES}");
    println!("whole_leaf_metric_status=projection_pending_exact_generation");
    println!("analytical_combined_stack_peak={ANALYTICAL_DERIVED_COMBINED_STACK_PEAK}");
    println!("analytical_peak_phase=response");
    println!("analytical_peak_transition=1");
    println!("run_explicit_measurement_with=--measure-bytes");
}

fn account_components() {
    let expected_response_kernel_bytes =
        EXPECTED_FIRST_DERIVED_KERNEL_BYTES + EXPECTED_RESPONSE_CHAINED_KERNEL_BYTES;
    let expected_challenge_kernel_bytes = EXPECTED_CHALLENGE_CHAINED_KERNEL_BYTES;
    assert_eq!(
        EXPECTED_RESPONSE_SCHEDULE_BYTES,
        EXPECTED_RESPONSE_TABLE_BYTES
            + EXPECTED_RESPONSE_SCAFFOLD_RAW_BYTES
            + expected_response_kernel_bytes
    );
    assert_eq!(
        EXPECTED_CHALLENGE_SCHEDULE_BYTES,
        EXPECTED_CHALLENGE_TABLE_BYTES
            + EXPECTED_CHALLENGE_SCAFFOLD_RAW_BYTES
            + expected_challenge_kernel_bytes
    );
    assert_eq!(
        EXPECTED_TABLE_BYTES,
        EXPECTED_RESPONSE_TABLE_BYTES + EXPECTED_CHALLENGE_TABLE_BYTES
    );
    assert_eq!(
        ADDITIVE_PROJECTED_LINKED_SCRIPT_BYTES,
        EXPECTED_SCALAR_VALIDATOR_POLICY_BYTES
            + EXPECTED_RESPONSE_SCHEDULE_BYTES
            + EXPECTED_PACKED_R_HASH_BYTES
            + EXPECTED_INDEPENDENT_RECODER_POLICY_BYTES
            + EXPECTED_CHALLENGE_SCHEDULE_BYTES
            + EXPECTED_TERMINAL_POLICY_BYTES
    );

    println!("model=ed25519_montgomery_h16_qfree_g31_full_linker");
    println!("mode=additive-component-accounting");
    println!("multi_megabyte_generation_performed=false");
    println!("whole_leaf_execution_performed=false");
    println!("response_table_bytes={EXPECTED_RESPONSE_TABLE_BYTES}");
    println!("response_scaffold_raw_bytes={EXPECTED_RESPONSE_SCAFFOLD_RAW_BYTES}");
    println!("response_derived_kernel_bytes={expected_response_kernel_bytes}");
    println!("response_schedule_bytes={EXPECTED_RESPONSE_SCHEDULE_BYTES}");
    println!("challenge_table_bytes={EXPECTED_CHALLENGE_TABLE_BYTES}");
    println!("challenge_scaffold_raw_bytes={EXPECTED_CHALLENGE_SCAFFOLD_RAW_BYTES}");
    println!("challenge_derived_kernel_bytes={expected_challenge_kernel_bytes}");
    println!("challenge_schedule_bytes={EXPECTED_CHALLENGE_SCHEDULE_BYTES}");
    println!("scalar_validator_policy_bytes={EXPECTED_SCALAR_VALIDATOR_POLICY_BYTES}");
    println!("packed_r_direct_hash_policy_bytes={EXPECTED_PACKED_R_DIRECT_HASH_POLICY_BYTES}");
    println!("packed_r_conversion_policy_bytes={EXPECTED_PACKED_R_CONVERSION_POLICY_BYTES}");
    println!("packed_r_fixed_message_blake3_bytes={EXPECTED_PACKED_R_HASH_BYTES}");
    println!("packed_r_blake3_manual_post_policy_optimizer=false");
    println!("independent_byte_recoder_policy_bytes={EXPECTED_INDEPENDENT_RECODER_POLICY_BYTES}");
    println!("terminal_cleanstack_policy_bytes={EXPECTED_TERMINAL_POLICY_BYTES}");
    println!("additive_projected_policy_script_bytes={ADDITIVE_PROJECTED_LINKED_SCRIPT_BYTES}");
    println!("whole_leaf_metric_status=projection_pending_exact_generation");
    println!("auxiliary_hint_items={AUXILIARY_HINT_ITEMS}");
    println!("complete_argument_items_at_script_entry={ENTRY_ITEMS}");
    println!("analytical_combined_stack_peak={ANALYTICAL_DERIVED_COMBINED_STACK_PEAK}");
}

fn measure_bytes() {
    let linked = build_linked_leaf();
    let component_sum = linked.scalar_validator_bytes
        + linked.response_bytes
        + linked.hash_bytes
        + linked.recoder_bytes
        + linked.challenge_bytes
        + linked.terminal_bytes;
    assert_eq!(linked.whole.len(), component_sum);
    let compiled = linked.whole.compile_with_policy();
    assert!(compiled.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(compiled.len(), component_sum);
    assert_eq!(compiled.len(), ADDITIVE_PROJECTED_LINKED_SCRIPT_BYTES);

    println!("model=ed25519_montgomery_h16_qfree_g31_full_linker");
    println!("mode=generation-only-byte-measurement");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=serialization");
    println!("execution_class=unclassified");
    println!("whole_leaf_execution_performed=false");
    println!("compile_options_for_whole_leaf=NONE");
    println!("whole_leaf_policy_bytes={}", compiled.len());
    println!(
        "whole_leaf_static_non_push_opcodes={}",
        static_non_push_opcodes(&compiled)
    );
    println!("linked_component_sum_bytes={component_sum}");
    println!("cross_component_optimizer_delta_bytes=0");
    println!("response_table_bytes={}", linked.response_table_bytes);
    println!("challenge_table_bytes={}", linked.challenge_table_bytes);
    println!("response_schedule_bytes={}", linked.response_bytes);
    println!("challenge_schedule_bytes={}", linked.challenge_bytes);
    println!(
        "scalar_validator_policy_bytes={}",
        linked.scalar_validator_bytes
    );
    println!("packed_r_direct_hash_policy_bytes={EXPECTED_PACKED_R_DIRECT_HASH_POLICY_BYTES}");
    println!("packed_r_conversion_policy_bytes={EXPECTED_PACKED_R_CONVERSION_POLICY_BYTES}");
    println!("packed_r_fixed_message_blake3_bytes={}", linked.hash_bytes);
    println!("packed_r_blake3_manual_post_policy_optimizer=false");
    println!(
        "independent_byte_recoder_policy_bytes={}",
        linked.recoder_bytes
    );
    println!("terminal_cleanstack_policy_bytes={}", linked.terminal_bytes);
    println!("auxiliary_hint_items={AUXILIARY_HINT_ITEMS}");
    println!("complete_argument_items_at_script_entry={ENTRY_ITEMS}");
    println!("analytical_combined_stack_peak={ANALYTICAL_DERIVED_COMBINED_STACK_PEAK}");
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        None | Some("--check-shape") => check_shape(),
        Some("--account-only") => account_components(),
        Some("--measure-bytes") => measure_bytes(),
        Some(_) => panic!("use --check-shape, --account-only, or --measure-bytes"),
    }
}
