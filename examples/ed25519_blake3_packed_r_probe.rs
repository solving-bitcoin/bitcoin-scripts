//! Focused strict probe for deriving the fixed-message BLAKE3 challenge from
//! packed R words already present in the q-free H16 challenge trace.
//!
//! This executes one BLAKE3 compression only. It does not build or execute the
//! scalar-multiplication linker. The hash helper deliberately relies on the
//! later slope transition to certify the same untouched packed words.

use bitcoin::{consensus::encode::serialize, script::Instruction, Witness};
use bitcoin_lab::{
    fields::ed25519::u5_packed,
    hashes::blake3::ed25519_challenge,
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation},
    },
};

const TRACE_PACKETS: usize = 16;
const TRACE_ITEMS_PER_PACKET: usize = 16;
const CURRENT_STATE_ITEMS: usize = 41;
const PRESERVED_ITEMS: usize = TRACE_PACKETS * TRACE_ITEMS_PER_PACKET + CURRENT_STATE_ITEMS;
const ITEMS_ABOVE_R_WORD0: usize = 8 + 15 * TRACE_ITEMS_PER_PACKET + CURRENT_STATE_ITEMS;
const EXPECTED_HELPER_POLICY_BYTES: usize = 67_806;
const EXPECTED_DIRECT_HASH_POLICY_BYTES: usize = 63_830;
const EXPECTED_CONVERSION_INCREMENTAL_BYTES: usize = 3_976;

const PUBLIC_KEY: [u8; 32] = [
    0x7d, 0xb0, 0xdc, 0x92, 0x22, 0xf3, 0xc1, 0x83, 0x45, 0x7d, 0xdd, 0xe4, 0xc7, 0x08, 0xde, 0x8e,
    0x5e, 0xa6, 0xbf, 0x3d, 0x5c, 0x44, 0x04, 0xcc, 0xa1, 0x4b, 0x32, 0x72, 0x9a, 0x05, 0xc3, 0x2a,
];

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn compressed_word_item(word: u32) -> Vec<u8> {
    scriptnum_item(i64::from(word as i32))
}

fn drop_items(items: usize) -> Script {
    script! {
        for _ in 0..items / 2 { OP_2DROP }
        if items % 2 != 0 { OP_DROP }
    }
}

fn verify_low128(digest: &[u8; 32]) -> Script {
    let nibbles = digest[..16]
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .collect::<Vec<_>>();
    script! {
        for nibble in nibbles.iter().rev() { { *nibble } OP_NUMEQUALVERIFY }
    }
}

fn verify_raw_prefix(prefix: &[Vec<u8>]) -> Script {
    script! {
        for item in prefix.iter().rev() { { item.clone() } OP_EQUALVERIFY }
    }
}

fn static_non_push_opcodes(script: &bitcoin::Script) -> usize {
    script
        .instructions()
        .map(|instruction| instruction.expect("generated script parses"))
        .filter(
            |instruction| matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() > 0x60),
        )
        .count()
}

fn packed_witness(words: &[u32; 8]) -> Vec<Vec<u8>> {
    words
        .iter()
        .rev()
        .map(|word| compressed_word_item(*word))
        .collect()
}

fn exact_external_certifier() -> bitcoin::ScriptBuf {
    script! {
        { Script::new("policy-precompiled exact packed-R certification")
            .push_script(u5_packed::decode_preserving(0).compile_with_policy()) }
        { drop_items(8 + 51) }
        OP_1
    }
    .compile_with_policy()
}

fn main() {
    assert_eq!(PRESERVED_ITEMS, 297);
    assert_eq!(ITEMS_ABOVE_R_WORD0, 289);

    let domain = *blake3::hash(b"bitcoin-lab/custom-ed25519-blake3-slope-v1").as_bytes();
    let message: [u8; 32] = std::array::from_fn(|index| (index as u8).wrapping_mul(7));
    let mut r_bytes: [u8; 32] =
        std::array::from_fn(|index| (index as u8).wrapping_mul(29).wrapping_add(0x13));
    r_bytes[31] &= 0x3f;
    let words: [u32; 8] = std::array::from_fn(|index| {
        u32::from_le_bytes(r_bytes[4 * index..4 * index + 4].try_into().unwrap())
    });

    // Exact q-free boundary: the bottom packet's u block is absolute bottom,
    // followed by its lambda block, fifteen later 16-item trace packets, and
    // the 41-item current state.
    let mut prefix = packed_witness(&words);
    prefix.extend((0..ITEMS_ABOVE_R_WORD0).map(|index| scriptnum_item(1 + (index % 97) as i64)));
    assert_eq!(prefix.len(), PRESERVED_ITEMS);

    let helper = ed25519_challenge::
        key_specialized_compute_script_preserving_truncated_128_fixed_message_from_certified_packed_r(
            domain,
            PUBLIC_KEY,
            message,
            PRESERVED_ITEMS as u32,
            ITEMS_ABOVE_R_WORD0 as u32,
        )
        .compile_with_policy();
    let direct_u4_hash =
        ed25519_challenge::key_specialized_compute_script_preserving_truncated_128_fixed_message(
            domain,
            PUBLIC_KEY,
            message,
            PRESERVED_ITEMS as u32,
        )
        .compile_with_policy();
    assert_eq!(helper.len(), EXPECTED_HELPER_POLICY_BYTES);
    assert_eq!(direct_u4_hash.len(), EXPECTED_DIRECT_HASH_POLICY_BYTES);
    assert_eq!(
        helper.len() - direct_u4_hash.len(),
        EXPECTED_CONVERSION_INCREMENTAL_BYTES
    );
    let digest = *blake3::hash(&[domain, PUBLIC_KEY, r_bytes, message].concat()).as_bytes();
    let complete = script! {
        { Script::new("policy-precompiled packed-R BLAKE3 boundary").push_script(helper.clone()) }
        { verify_low128(&digest) }
        { verify_raw_prefix(&prefix) }
        OP_1
    }
    .compile_with_policy();
    let witness_bytes = serialize(&Witness::from_slice(&prefix)).len();
    let execution = execute_raw_script_with_inputs_strict(complete.to_bytes(), prefix.clone());
    assert!(
        execution.error.is_none(),
        "packed-R BLAKE3 differs from host or changed its prefix: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);
    assert_eq!(execution.stats.max_nb_stack_items, 824);

    // Exact input depth is still enforced after the derived u4 block is made.
    let mut extra_input = vec![scriptnum_item(42)];
    extra_input.extend(prefix.clone());
    let extra = execute_raw_script_with_inputs_strict(
        script! {
            { Script::new("policy-precompiled packed-R BLAKE3 boundary").push_script(helper.clone()) }
            OP_1
        }
        .compile_with_policy()
        .to_bytes(),
        extra_input,
    );
    assert!(
        extra.error.is_some(),
        "packed-R helper accepted extra input"
    );

    // Canonicality intentionally belongs to the later transition. Confirm the
    // exact packed codec that supplies that obligation rejects a raw alias and
    // a nonzero bit-255 padding word.
    let certifier = exact_external_certifier();
    let mut aliased = packed_witness(&[1, 0, 0, 0, 0, 0, 0, 0]);
    *aliased.last_mut().expect("word zero") = vec![1, 0];
    let alias_result = execute_raw_script_with_inputs_strict(certifier.to_bytes(), aliased);
    assert!(
        alias_result.error.is_some(),
        "external exact packed certification accepted a raw alias"
    );
    let mut bad_padding_words = [0u32; 8];
    bad_padding_words[7] = 0x8000_0000;
    let padding_result = execute_raw_script_with_inputs_strict(
        certifier.to_bytes(),
        packed_witness(&bad_padding_words),
    );
    assert!(
        padding_result.error.is_some(),
        "external packed certification accepted bit 255"
    );

    println!("model=ed25519_blake3_packed_r_strict_probe");
    println!("evidence=locally-reproduced");
    println!("execution_class=unclassified");
    println!("context=tapscript,bitcoin-scriptexec,strict_1000_item_stack");
    println!("preserved_input_items={PRESERVED_ITEMS}");
    println!("packed_r_word_items=8");
    println!("packed_r_word0_initial_depth={ITEMS_ABOVE_R_WORD0}");
    println!("derived_r_u4_items=64");
    println!("output_digest_u4_items=32");
    println!("entry_hint_items=0");
    println!("all_entry_items_coexist=true");
    println!("helper_policy_bytes={}", helper.len());
    println!("direct_u4_hash_policy_bytes={}", direct_u4_hash.len());
    println!(
        "packed_copy_conversion_incremental_bytes={}",
        helper.len() - direct_u4_hash.len()
    );
    println!(
        "helper_static_non_push_opcodes={}",
        static_non_push_opcodes(&helper)
    );
    println!("fixture_witness_bytes={witness_bytes}");
    println!(
        "strict_combined_main_alt_stack_peak={}",
        execution.stats.max_nb_stack_items
    );
    println!("host_blake3_low128_match=true");
    println!("entire_297_item_prefix_preserved_byte_for_byte=true");
    println!("extra_input_rejected=true");
    println!("packed_word_certification=external_later_slope_transition");
    println!("raw_alias_rejected_by_external_exact_certifier=true");
    println!("bit255_rejected_by_external_certifier=true");
    println!("helper_auxiliary_hint_items=0");
    println!("long_scalar_leaf_executed=false");
}
