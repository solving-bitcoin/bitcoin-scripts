//! Generation-only linker for the parity-correct G32 persistent-hybrid H16
//! leaf with canonical-u5 Rtilde in the final challenge packet.
//!
//! Default and `--account-only` modes perform only bounded shape/arithmetic
//! checks. `--measure-bytes` explicitly opts into assembling, but never
//! executing, the multi-megabyte leaf.

#[allow(dead_code)]
#[path = "ed25519_fixed_table_actual_model.rs"]
mod table_model;

#[allow(dead_code)]
#[path = "ed25519_h16_midpoint_glue.rs"]
mod midpoint;

#[allow(dead_code)]
#[path = "ed25519_montgomery_h16_hybrid_scheduler.rs"]
mod hybrid_scheduler;

use bitcoin::{script::Instruction, ScriptBuf};
use bitcoin_lab::{
    curves::ed25519::montgomery_slope::{
        HYBRID_FIRST_SHARED_POWER_BITS, HYBRID_LATER_SHARED_POWER_ITEM_COUNT,
    },
    hashes::blake3::ed25519_challenge,
    support::script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
};

const RESPONSE_GROUPS: usize = 32;
const RESPONSE_TRANSITIONS: usize = RESPONSE_GROUPS - 1;
const CHALLENGE_GROUPS: usize = 16;
const STANDARD_PACKET_ITEMS: usize = 16;
const FINAL_U5_PACKET_ITEMS: usize = 59;
const TRACE_ITEMS: usize = RESPONSE_TRANSITIONS * STANDARD_PACKET_ITEMS
    + (CHALLENGE_GROUPS - 1) * STANDARD_PACKET_ITEMS
    + FINAL_U5_PACKET_ITEMS;
const SCALAR_ITEMS: usize = 8;
const ENTRY_ITEMS: usize = TRACE_ITEMS + SCALAR_ITEMS;
const AUXILIARY_HINT_ITEMS: usize = 0;

const EXPECTED_RESPONSE_TABLE_BYTES: usize = 383_004;
const EXPECTED_CHALLENGE_TABLE_BYTES: usize = 200_843;
const EXPECTED_TABLE_BYTES: usize = 583_847;
const EXPECTED_SCALAR_VALIDATOR_POLICY_BYTES: usize = 774;
const EXPECTED_RESPONSE_SCAFFOLD_RAW_BYTES: usize = 14_701;
const EXPECTED_CHALLENGE_SCAFFOLD_RAW_BYTES: usize = 5_829;
const EXPECTED_FIRST_HYBRID_KERNEL_BYTES: usize = 37_109;
const EXPECTED_INITIALIZE_PERSISTENT_KERNEL_BYTES: usize = 49_921;
const EXPECTED_PERSISTENT_KERNEL_BYTES: usize = 49_888;
const EXPECTED_FINALIZE_PERSISTENT_KERNEL_BYTES: usize = 49_880;
const EXPECTED_RESPONSE_PERSISTENT_MIDDLE_KERNEL_BYTES: usize =
    28 * EXPECTED_PERSISTENT_KERNEL_BYTES;
const EXPECTED_CHALLENGE_PERSISTENT_MIDDLE_KERNEL_BYTES: usize =
    14 * EXPECTED_PERSISTENT_KERNEL_BYTES;
const EXPECTED_FINAL_U5_TERMINAL_KERNEL_BYTES: usize = 45_179;
const EXPECTED_RESPONSE_SCHEDULE_BYTES: usize = 1_931_479;
const EXPECTED_CHALLENGE_SCHEDULE_BYTES: usize = 1_000_204;
const EXPECTED_U5_R_HASH_BYTES: usize = 67_137;
const EXPECTED_INDEPENDENT_RECODER_POLICY_BYTES: usize = 389;
const EXPECTED_LINKED_SCRIPT_BYTES: usize = 2_999_983;
const EXPECTED_LINKED_STATIC_NON_PUSH_OPCODES: usize = 1_729_242;
const ANALYTICAL_COMBINED_STACK_PEAK: usize = 999;

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
}

fn build_linked_leaf() -> LinkedLeaf {
    let widths = table_model::montgomery_direct_h16_qfree_g32_response_widths();
    let table_model::MontgomeryDirectH16TableFragments {
        response_low_to_high,
        challenge_low_to_high,
        public_key_compressed,
    } = table_model::montgomery_direct_h16_qfree_g32_table_fragments();
    assert_eq!(public_key_compressed, FIXTURE_PUBLIC_KEY);
    assert_eq!(response_low_to_high.len(), RESPONSE_GROUPS);
    assert_eq!(challenge_low_to_high.len(), CHALLENGE_GROUPS);

    let response_table_bytes = response_low_to_high.iter().map(Script::len).sum();
    let challenge_table_bytes = challenge_low_to_high.iter().map(Script::len).sum();
    assert_eq!(response_table_bytes, EXPECTED_RESPONSE_TABLE_BYTES);
    assert_eq!(challenge_table_bytes, EXPECTED_CHALLENGE_TABLE_BYTES);

    let scalar_validator = policy_precompile(
        "policy-precompiled G32 hybrid-u5 scalar validator",
        hybrid_scheduler::hybrid_u5_scalar_validator_for_widths(&widths),
    );
    let response =
        hybrid_scheduler::build_hybrid_u5_response_stream_for_widths(response_low_to_high, &widths);
    let hash = ed25519_challenge::
        key_specialized_compute_script_preserving_truncated_128_fixed_message_from_canonical_u5_r(
            challenge_domain(),
            public_key_compressed,
            fixed_message(),
            hybrid_scheduler::HYBRID_U5_HASH_PRESERVED_ITEMS as u32,
            hybrid_scheduler::HYBRID_U5_HASH_R_DIGIT0_DEPTH as u32,
        );
    let recoder = policy_precompile(
        "policy-precompiled independent-byte challenge recoder",
        midpoint::recode_blake3_low128_independent_byte127(
            hybrid_scheduler::HYBRID_U5_HASH_PRESERVED_ITEMS,
        ),
    );
    let challenge = hybrid_scheduler::build_hybrid_u5_challenge_schedule(challenge_low_to_high);

    let scalar_validator_bytes = scalar_validator.len();
    let response_bytes = response.len();
    let hash_bytes = hash.len();
    let recoder_bytes = recoder.len();
    let challenge_bytes = challenge.len();
    assert_eq!(
        scalar_validator_bytes,
        EXPECTED_SCALAR_VALIDATOR_POLICY_BYTES
    );
    assert_eq!(response_bytes, EXPECTED_RESPONSE_SCHEDULE_BYTES);
    assert_eq!(hash_bytes, EXPECTED_U5_R_HASH_BYTES);
    assert_eq!(recoder_bytes, EXPECTED_INDEPENDENT_RECODER_POLICY_BYTES);
    assert_eq!(challenge_bytes, EXPECTED_CHALLENGE_SCHEDULE_BYTES);
    assert_eq!(
        response_bytes,
        EXPECTED_RESPONSE_TABLE_BYTES
            + EXPECTED_RESPONSE_SCAFFOLD_RAW_BYTES
            + EXPECTED_FIRST_HYBRID_KERNEL_BYTES
            + EXPECTED_INITIALIZE_PERSISTENT_KERNEL_BYTES
            + EXPECTED_RESPONSE_PERSISTENT_MIDDLE_KERNEL_BYTES
            + EXPECTED_FINALIZE_PERSISTENT_KERNEL_BYTES
    );
    assert_eq!(
        challenge_bytes,
        EXPECTED_CHALLENGE_TABLE_BYTES
            + EXPECTED_CHALLENGE_SCAFFOLD_RAW_BYTES
            + EXPECTED_INITIALIZE_PERSISTENT_KERNEL_BYTES
            + EXPECTED_CHALLENGE_PERSISTENT_MIDDLE_KERNEL_BYTES
            + EXPECTED_FINAL_U5_TERMINAL_KERNEL_BYTES
    );

    let whole = script! {
        { scalar_validator }
        { response }
        { hash }
        { recoder }
        { challenge }
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
    }
}

fn check_shape() {
    let widths = table_model::montgomery_direct_h16_qfree_g32_response_widths();
    let width7_positions = widths
        .iter()
        .copied()
        .enumerate()
        .filter_map(|(position, width)| (width == 7).then_some(position))
        .collect::<Vec<_>>();
    assert_eq!(widths.len(), RESPONSE_GROUPS);
    assert_eq!(widths.iter().sum::<usize>(), 253);
    assert_eq!(width7_positions, [21, 25, 29]);
    assert_eq!(*widths.last().expect("top width"), 8);
    assert_eq!(TRACE_ITEMS, 795);
    assert_eq!(ENTRY_ITEMS, 803);
    assert_eq!(
        hybrid_scheduler::hybrid_u5_entry_items_for_widths(&widths),
        ENTRY_ITEMS
    );
    assert_eq!(
        hybrid_scheduler::hybrid_response_scaffolding_for_widths(&widths).len(),
        EXPECTED_RESPONSE_SCAFFOLD_RAW_BYTES
    );
    assert_eq!(
        hybrid_scheduler::hybrid_u5_challenge_scaffolding().len(),
        EXPECTED_CHALLENGE_SCAFFOLD_RAW_BYTES
    );
    assert_eq!(
        hybrid_scheduler::hybrid_u5_scalar_validator_for_widths(&widths)
            .compile_with_policy()
            .len(),
        EXPECTED_SCALAR_VALIDATOR_POLICY_BYTES
    );
    assert_eq!(hybrid_scheduler::HYBRID_U5_HASH_PRESERVED_ITEMS, 391);
    assert_eq!(hybrid_scheduler::HYBRID_U5_HASH_R_DIGIT0_DEPTH, 340);
    assert_eq!(HYBRID_FIRST_SHARED_POWER_BITS, [23, 24, 25, 26]);
    assert_eq!(HYBRID_LATER_SHARED_POWER_ITEM_COUNT, 16);
    assert!(ANALYTICAL_COMBINED_STACK_PEAK <= 1_000);

    println!("model=ed25519_montgomery_h16_hybrid_u5_g32_full_linker");
    println!("mode=shape-only");
    println!("multi_megabyte_generation_performed=false");
    println!("whole_leaf_execution_performed=false");
    println!("entry_layout=challenge_p0_u5_51_lambda8|challenge_p1_to_p15_packed16|response31_packed16|scalar8");
    println!("response_widths_low_to_high={widths:?}");
    println!("response_width7_positions={width7_positions:?}");
    println!("parity_correct_top_initializer=U_minus_K127A_without_initial_T");
    println!("trace_data_items={TRACE_ITEMS}");
    println!("scalar_data_items={SCALAR_ITEMS}");
    println!("auxiliary_hint_items={AUXILIARY_HINT_ITEMS}");
    println!("complete_argument_items_at_script_entry={ENTRY_ITEMS}");
    println!("all_entry_items_coexist=true");
    println!("transition_auxiliary_hint_items_per_invocation=0");
    println!("transition_invocations=47");
    println!(
        "shared_power_pool_first_items={}",
        HYBRID_FIRST_SHARED_POWER_BITS.len()
    );
    println!("shared_power_pool_first_bits=23,24,25,26");
    println!("shared_power_pool_later_items={HYBRID_LATER_SHARED_POWER_ITEM_COUNT}");
    println!("shared_power_pool_is_script_authored=true");
    println!("shared_power_pool_added_witness_items=0");
    println!("persistent_pool_phases=response_t1_to_end,challenge_all16");
    println!("hash_boundary_alt_pool_items=0");
    println!("terminal_alt_pool_items=0");
    println!("hybrid_state_items=92");
    println!("hash_preserved_items=391");
    println!("hash_r_digit0_depth=340");
    println!("expected_policy_script_bytes={EXPECTED_LINKED_SCRIPT_BYTES}");
    println!("expected_static_non_push_opcodes={EXPECTED_LINKED_STATIC_NON_PUSH_OPCODES}");
    println!("analytical_combined_stack_peak={ANALYTICAL_COMBINED_STACK_PEAK}");
    println!("analytical_peak_locations=response_transition_0");
    println!("run_explicit_measurement_with=--measure-bytes");
}

fn account_components() {
    let response_kernel_bytes = EXPECTED_FIRST_HYBRID_KERNEL_BYTES
        + EXPECTED_INITIALIZE_PERSISTENT_KERNEL_BYTES
        + EXPECTED_RESPONSE_PERSISTENT_MIDDLE_KERNEL_BYTES
        + EXPECTED_FINALIZE_PERSISTENT_KERNEL_BYTES;
    let challenge_kernel_bytes = EXPECTED_INITIALIZE_PERSISTENT_KERNEL_BYTES
        + EXPECTED_CHALLENGE_PERSISTENT_MIDDLE_KERNEL_BYTES
        + EXPECTED_FINAL_U5_TERMINAL_KERNEL_BYTES;
    assert_eq!(
        EXPECTED_RESPONSE_SCHEDULE_BYTES,
        EXPECTED_RESPONSE_TABLE_BYTES
            + EXPECTED_RESPONSE_SCAFFOLD_RAW_BYTES
            + response_kernel_bytes
    );
    assert_eq!(
        EXPECTED_CHALLENGE_SCHEDULE_BYTES,
        EXPECTED_CHALLENGE_TABLE_BYTES
            + EXPECTED_CHALLENGE_SCAFFOLD_RAW_BYTES
            + challenge_kernel_bytes
    );
    assert_eq!(
        EXPECTED_TABLE_BYTES,
        EXPECTED_RESPONSE_TABLE_BYTES + EXPECTED_CHALLENGE_TABLE_BYTES
    );
    assert_eq!(
        EXPECTED_LINKED_SCRIPT_BYTES,
        EXPECTED_SCALAR_VALIDATOR_POLICY_BYTES
            + EXPECTED_RESPONSE_SCHEDULE_BYTES
            + EXPECTED_U5_R_HASH_BYTES
            + EXPECTED_INDEPENDENT_RECODER_POLICY_BYTES
            + EXPECTED_CHALLENGE_SCHEDULE_BYTES
    );

    println!("model=ed25519_montgomery_h16_hybrid_u5_g32_full_linker");
    println!("mode=additive-component-accounting");
    println!("multi_megabyte_generation_performed=false");
    println!("whole_leaf_execution_performed=false");
    println!("response_table_bytes={EXPECTED_RESPONSE_TABLE_BYTES}");
    println!("response_scaffold_raw_bytes={EXPECTED_RESPONSE_SCAFFOLD_RAW_BYTES}");
    println!("response_hybrid_kernel_bytes={response_kernel_bytes}");
    println!("response_schedule_bytes={EXPECTED_RESPONSE_SCHEDULE_BYTES}");
    println!("challenge_table_bytes={EXPECTED_CHALLENGE_TABLE_BYTES}");
    println!("challenge_scaffold_raw_bytes={EXPECTED_CHALLENGE_SCAFFOLD_RAW_BYTES}");
    println!("challenge_hybrid_kernel_bytes={challenge_kernel_bytes}");
    println!("challenge_schedule_bytes={EXPECTED_CHALLENGE_SCHEDULE_BYTES}");
    println!("scalar_validator_policy_bytes={EXPECTED_SCALAR_VALIDATOR_POLICY_BYTES}");
    println!("canonical_u5_r_fixed_message_blake3_bytes={EXPECTED_U5_R_HASH_BYTES}");
    println!("independent_byte_recoder_policy_bytes={EXPECTED_INDEPENDENT_RECODER_POLICY_BYTES}");
    println!("terminal_cleanstack_bytes=0");
    println!("terminal_predicate_fused_into_final_u5_kernel=true");
    println!("additive_policy_script_bytes={EXPECTED_LINKED_SCRIPT_BYTES}");
    println!("auxiliary_hint_items={AUXILIARY_HINT_ITEMS}");
    println!(
        "shared_power_pool_first_items={}",
        HYBRID_FIRST_SHARED_POWER_BITS.len()
    );
    println!("shared_power_pool_first_bits=23,24,25,26");
    println!("shared_power_pool_later_items={HYBRID_LATER_SHARED_POWER_ITEM_COUNT}");
    println!("shared_power_pool_added_witness_items=0");
    println!("hash_boundary_alt_pool_items=0");
    println!("terminal_alt_pool_items=0");
    println!("complete_argument_items_at_script_entry={ENTRY_ITEMS}");
    println!("analytical_combined_stack_peak={ANALYTICAL_COMBINED_STACK_PEAK}");
}

fn measure_bytes() {
    let linked = build_linked_leaf();
    let component_sum = linked.scalar_validator_bytes
        + linked.response_bytes
        + linked.hash_bytes
        + linked.recoder_bytes
        + linked.challenge_bytes;
    assert_eq!(linked.whole.len(), component_sum);
    let compiled = linked.whole.compile_with_policy();
    assert!(compiled.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(compiled.len(), component_sum);
    assert_eq!(compiled.len(), EXPECTED_LINKED_SCRIPT_BYTES);
    assert_eq!(
        static_non_push_opcodes(&compiled),
        EXPECTED_LINKED_STATIC_NON_PUSH_OPCODES
    );

    println!("model=ed25519_montgomery_h16_hybrid_u5_g32_full_linker");
    println!("mode=generation-only-byte-measurement");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=serialization");
    println!("execution_class=unclassified");
    println!("whole_leaf_execution_performed=false");
    println!("compile_options_for_whole_leaf=NONE");
    println!("whole_leaf_policy_bytes={}", compiled.len());
    println!(
        "whole_leaf_static_non_push_opcodes={}",
        EXPECTED_LINKED_STATIC_NON_PUSH_OPCODES
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
    println!(
        "canonical_u5_r_fixed_message_blake3_bytes={}",
        linked.hash_bytes
    );
    println!(
        "independent_byte_recoder_policy_bytes={}",
        linked.recoder_bytes
    );
    println!("terminal_cleanstack_bytes=0");
    println!("auxiliary_hint_items={AUXILIARY_HINT_ITEMS}");
    println!("complete_argument_items_at_script_entry={ENTRY_ITEMS}");
    println!("analytical_combined_stack_peak={ANALYTICAL_COMBINED_STACK_PEAK}");
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        None | Some("--check-shape") => check_shape(),
        Some("--account-only") => account_components(),
        Some("--measure-bytes") => measure_bytes(),
        Some(_) => panic!("use --check-shape, --account-only, or --measure-bytes"),
    }
}
