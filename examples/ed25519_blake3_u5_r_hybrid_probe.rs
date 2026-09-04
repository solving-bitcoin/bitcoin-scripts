//! Focused strict probe for the production canonical-u5 Rtilde BLAKE3 boundary
//! at the 92-item hybrid-state layout.
//!
//! It executes one fixed-message BLAKE3 component and malformed canonicality
//! cases. It never builds a fixed table, slope schedule, or complete leaf.

#[allow(dead_code)]
#[path = "ed25519_h16_midpoint_glue.rs"]
mod midpoint;

use bitcoin::{consensus::serialize, script::Instruction, Witness};
use bitcoin_lab::{
    curves::ed25519::montgomery_slope::{
        finalize_hybrid_persistent_shared_power_pool,
        initialize_hybrid_persistent_shared_power_pool, HYBRID_LATER_SHARED_POWER_ITEM_COUNT,
    },
    fields::ed25519::u5_packed,
    hashes::blake3::ed25519_challenge,
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, ScriptCompilation},
    },
};

const U5_R_ITEMS: usize = 51;
const LAMBDA_ITEMS: usize = 8;
const LATER_CHALLENGE_TRACE_ITEMS: usize = 15 * 16;
const HYBRID_STATE_ITEMS: usize = 92;
const R_DIGIT0_DEPTH: usize = LAMBDA_ITEMS + LATER_CHALLENGE_TRACE_ITEMS + HYBRID_STATE_ITEMS;
const PRESERVED_ITEMS: usize = U5_R_ITEMS + R_DIGIT0_DEPTH;
const EXPECTED_CONVERSION_POLICY_BYTES: usize = 2_931;
const EXPECTED_DIRECT_HASH_POLICY_BYTES: usize = 64_206;
const EXPECTED_HELPER_POLICY_BYTES: usize = 67_137;
const EXPECTED_HELPER_STATIC_NON_PUSH_OPCODES: usize = 45_452;
const EXPECTED_STRICT_COMBINED_PEAK: usize = 918;
const ALT_POOL_SENTINEL: i64 = 7_654_323;

const PUBLIC_KEY: [u8; 32] = [
    0x7d, 0xb0, 0xdc, 0x92, 0x22, 0xf3, 0xc1, 0x83, 0x45, 0x7d, 0xdd, 0xe4, 0xc7, 0x08, 0xde, 0x8e,
    0x5e, 0xa6, 0xbf, 0x3d, 0x5c, 0x44, 0x04, 0xcc, 0xa1, 0x4b, 0x32, 0x72, 0x9a, 0x05, 0xc3, 0x2a,
];
const RTILDE: [u8; 32] = [
    0xb3, 0x0d, 0xf2, 0x5e, 0x5f, 0xc1, 0x8a, 0x3c, 0x9b, 0xbe, 0x43, 0xdc, 0x66, 0x88, 0x0f, 0x14,
    0x19, 0xe7, 0xe9, 0x6f, 0x67, 0x8e, 0x75, 0x72, 0xfe, 0xc7, 0x59, 0x48, 0xca, 0xc6, 0x74, 0x3d,
];

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn r_u5_items() -> Vec<Vec<u8>> {
    let words = std::array::from_fn(|index| {
        u32::from_le_bytes(RTILDE[4 * index..4 * index + 4].try_into().unwrap())
    });
    u5_packed::digits_from_packed_words(&words)
        .expect("fixed Rtilde is canonical")
        .into_iter()
        .rev()
        .map(|digit| scriptnum_item(i64::from(digit)))
        .collect()
}

fn prefix_with_r(r: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    assert_eq!(r.len(), U5_R_ITEMS);
    r.into_iter()
        .chain((0..R_DIGIT0_DEPTH).map(|index| scriptnum_item(1 + (index % 97) as i64)))
        .collect()
}

fn verify_low128(digest: &[u8; 32]) -> bitcoin_lab::support::script::Script {
    let nibbles = digest[..16]
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .collect::<Vec<_>>();
    script! {
        for nibble in nibbles.iter().rev() { { *nibble } OP_NUMEQUALVERIFY }
    }
}

fn verify_raw_prefix(prefix: &[Vec<u8>]) -> bitcoin_lab::support::script::Script {
    script! {
        for item in prefix.iter().rev() { { item.clone() } OP_EQUALVERIFY }
    }
}

fn static_non_push_opcodes(script: &bitcoin::Script) -> usize {
    script
        .instructions()
        .map(|instruction| instruction.expect("generated script must parse"))
        .filter(
            |instruction| matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() > 0x60),
        )
        .count()
}

fn main() {
    assert_eq!(R_DIGIT0_DEPTH, 340);
    assert_eq!(PRESERVED_ITEMS, 391);
    let domain = *blake3::hash(b"bitcoin-lab/custom-ed25519-blake3-slope-v1").as_bytes();
    let message: [u8; 32] = std::array::from_fn(|index| (index as u8).wrapping_mul(7));
    let prefix = prefix_with_r(r_u5_items());
    assert_eq!(prefix.len(), PRESERVED_ITEMS);

    let helper = ed25519_challenge::
        key_specialized_compute_script_preserving_truncated_128_fixed_message_from_canonical_u5_r(
            domain,
            PUBLIC_KEY,
            message,
            PRESERVED_ITEMS as u32,
            R_DIGIT0_DEPTH as u32,
        )
        .compile_with_policy();
    let direct_hash =
        ed25519_challenge::key_specialized_compute_script_preserving_truncated_128_fixed_message(
            domain,
            PUBLIC_KEY,
            message,
            PRESERVED_ITEMS as u32,
        )
        .compile_with_policy();
    let conversion = ed25519_challenge::duplicate_canonical_u5_r_as_u4(R_DIGIT0_DEPTH as u32)
        .compile_with_policy();
    assert_eq!(helper.len(), conversion.len() + direct_hash.len());
    assert_eq!(conversion.len(), EXPECTED_CONVERSION_POLICY_BYTES);
    assert_eq!(direct_hash.len(), EXPECTED_DIRECT_HASH_POLICY_BYTES);
    assert_eq!(helper.len(), EXPECTED_HELPER_POLICY_BYTES);
    assert_eq!(
        static_non_push_opcodes(&helper),
        EXPECTED_HELPER_STATIC_NON_PUSH_OPCODES
    );

    let digest = *blake3::hash(&[domain, PUBLIC_KEY, RTILDE, message].concat()).as_bytes();
    let complete = script! {
        { helper.clone() }
        { verify_low128(&digest) }
        { verify_raw_prefix(&prefix) }
        OP_1
    }
    .compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(complete.to_bytes(), prefix.clone());
    assert!(
        execution.error.is_none(),
        "canonical-u5 R BLAKE3 differs from host or changed its prefix: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);
    assert_eq!(
        execution.stats.max_nb_stack_items,
        EXPECTED_STRICT_COMBINED_PEAK
    );

    // Feasibility-only cross-phase audit: a 16-item slope constant pool can
    // sit below every hash/recoder-local alt-stack temporary without changing
    // the transcript or preserved main prefix. The sentinel proves cleanup.
    let recoder =
        midpoint::recode_blake3_low128_independent_byte127(PRESERVED_ITEMS).compile_with_policy();
    let across_hash_and_recoder = script! {
        { ALT_POOL_SENTINEL } OP_TOALTSTACK
        { initialize_hybrid_persistent_shared_power_pool() }
        { helper.clone() }
        { recoder }
        { finalize_hybrid_persistent_shared_power_pool() }
        OP_FROMALTSTACK { ALT_POOL_SENTINEL } OP_NUMEQUALVERIFY
        for _ in 0..16 { OP_2DROP }
        { verify_raw_prefix(&prefix) }
        OP_1
    }
    .compile_with_policy();
    let across_hash_execution =
        execute_raw_script_with_inputs_strict(across_hash_and_recoder.to_bytes(), prefix.clone());
    assert!(
        across_hash_execution.error.is_none(),
        "persistent slope pool did not survive BLAKE3/recoder alt use: {across_hash_execution}"
    );
    assert_eq!(across_hash_execution.final_stack.len(), 1);
    assert_eq!(
        across_hash_execution.stats.max_nb_stack_items,
        EXPECTED_STRICT_COMBINED_PEAK + HYBRID_LATER_SHARED_POWER_ITEM_COUNT + 1,
    );

    let mut out_of_range = prefix.clone();
    out_of_range[17] = scriptnum_item(32);
    let range_execution = execute_raw_script_with_inputs_strict(helper.to_bytes(), out_of_range);
    assert!(range_execution.error.is_some());

    // p itself is the first of the 19 invalid radix-32 encodings below 2^255:
    // d1..d50=31 and d0=13. Public stack order is d50..d0.
    let mut modulus_alias = vec![scriptnum_item(31); U5_R_ITEMS];
    modulus_alias[U5_R_ITEMS - 1] = scriptnum_item(13);
    let gap_prefix = prefix_with_r(modulus_alias);
    let gap_execution = execute_raw_script_with_inputs_strict(helper.to_bytes(), gap_prefix);
    assert!(gap_execution.error.is_some());

    let mut extra = vec![scriptnum_item(42)];
    extra.extend(prefix.clone());
    let extra_execution = execute_raw_script_with_inputs_strict(helper.to_bytes(), extra);
    assert!(extra_execution.error.is_some());

    println!("model=ed25519_blake3_u5_r_hybrid_probe");
    println!("evidence=locally-reproduced");
    println!("execution_class=unclassified");
    println!("context=tapscript,bitcoin-scriptexec,strict_1000_item_stack");
    println!("preserved_input_items={PRESERVED_ITEMS}");
    println!("canonical_u5_r_items={U5_R_ITEMS}");
    println!("r_digit0_initial_depth={R_DIGIT0_DEPTH}");
    println!("hybrid_state_items={HYBRID_STATE_ITEMS}");
    println!("derived_r_u4_items=64");
    println!("output_digest_u4_items=32");
    println!("entry_hint_items=0");
    println!("all_entry_items_coexist=true");
    println!("u5_certify_copy_repack_policy_bytes={}", conversion.len());
    println!("direct_u4_hash_policy_bytes={}", direct_hash.len());
    println!("helper_policy_bytes={}", helper.len());
    println!(
        "helper_static_non_push_opcodes={}",
        static_non_push_opcodes(&helper)
    );
    println!(
        "strict_combined_main_alt_stack_peak={}",
        execution.stats.max_nb_stack_items
    );
    println!("cross_hash_and_recoder_persistent_power_pool_feasible=true");
    println!(
        "cross_hash_and_recoder_persistent_power_pool_items={HYBRID_LATER_SHARED_POWER_ITEM_COUNT}"
    );
    println!("cross_hash_and_recoder_persistent_power_pool_hint_items=0");
    println!(
        "cross_hash_and_recoder_strict_combined_peak_without_probe_sentinel={}",
        across_hash_execution.stats.max_nb_stack_items - 1
    );
    println!(
        "fixture_prefix_witness_bytes={}",
        serialize(&Witness::from_slice(&prefix)).len()
    );
    println!("original_u5_items_preserved_byte_for_byte=true");
    println!("out_of_range_digit_rejected=true");
    println!("nineteen_value_canonical_gap_rejected=true");
    println!("extra_input_rejected=true");
    println!("fixed_table_or_slope_schedule_built=false");
    println!("whole_leaf_built_or_executed=false");
}
