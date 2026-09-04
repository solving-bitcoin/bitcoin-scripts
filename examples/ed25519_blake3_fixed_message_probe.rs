//! Focused strict-stack probe for the fixed-M32 Ed25519 BLAKE3 fragment.
//!
//! This executes one 64-byte final-block compression and several tiny binder
//! rejection/order cases.  It deliberately does not execute the multi-
//! megabyte scalar-multiplication leaf or the long BLAKE3 test suite.

use bitcoin::{consensus::encode::serialize, script::Instruction, Witness};
use bitcoin_lab::{
    hashes::blake3::ed25519_challenge,
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation},
    },
};

const PRESERVED_ITEMS: usize = 288 + 41 + 8;
const EXPECTED_BINDER_POLICY_BYTES: usize = 128;
const EXPECTED_FIXED_MESSAGE_HASH_POLICY_BYTES: usize = 63_990;
const EXPECTED_COMBINED_FRAGMENT_BYTES: usize = 64_118;
const PUBLIC_KEY: [u8; 32] = [
    0x7d, 0xb0, 0xdc, 0x92, 0x22, 0xf3, 0xc1, 0x83, 0x45, 0x7d, 0xdd, 0xe4, 0xc7, 0x08, 0xde, 0x8e,
    0x5e, 0xa6, 0xbf, 0x3d, 0x5c, 0x44, 0x04, 0xcc, 0xa1, 0x4b, 0x32, 0x72, 0x9a, 0x05, 0xc3, 0x2a,
];

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn drop_items(items: usize) -> Script {
    script! {
        for _ in 0..items / 2 { OP_2DROP }
        if items % 2 != 0 { OP_DROP }
    }
}

fn verify_values_bottom_to_top(values: &[u8]) -> Script {
    script! {
        for value in values.iter().rev() { { *value } OP_NUMEQUALVERIFY }
    }
}

fn verify_preserved(values: &[i64]) -> Script {
    script! {
        for value in values.iter().rev() { { *value } OP_NUMEQUALVERIFY }
    }
}

fn verify_low128(digest: &[u8; 32]) -> Script {
    let nibbles = digest[..16]
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .collect::<Vec<_>>();
    verify_values_bottom_to_top(&nibbles)
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

fn witness(preserved: &[i64], r_nibbles: &[u8], message_nibbles: &[u8]) -> Vec<Vec<u8>> {
    preserved
        .iter()
        .copied()
        .map(scriptnum_item)
        .chain(
            r_nibbles
                .iter()
                .map(|value| scriptnum_item(i64::from(*value))),
        )
        .chain(
            message_nibbles
                .iter()
                .map(|value| scriptnum_item(i64::from(*value))),
        )
        .collect()
}

fn main() {
    let domain = *blake3::hash(b"bitcoin-lab/custom-ed25519-blake3-slope-v1").as_bytes();
    let message: [u8; 32] = std::array::from_fn(|index| (index as u8).wrapping_mul(7));
    let mut r: [u8; 32] =
        std::array::from_fn(|index| (index as u8).wrapping_mul(29).wrapping_add(0x13));
    r[31] &= 0x3f;
    let preserved = (0..PRESERVED_ITEMS)
        .map(|index| 1 + (index % 97) as i64)
        .collect::<Vec<_>>();
    let r_nibbles = ed25519_challenge::transcript_half_u4(&r);
    let message_nibbles = ed25519_challenge::transcript_half_u4(&message);
    assert_eq!(r_nibbles.len(), 64);
    assert_eq!(message_nibbles.len(), 64);

    let binder = ed25519_challenge::bind_and_drop_fixed_message(message).compile_with_policy();
    let old_binder = script! {
        { Script::new("precompiled fixed-M binder").push_script(binder.clone()) }
        for nibble in &message_nibbles { { *nibble } }
    }
    .compile_with_policy();
    let old_hash =
        ed25519_challenge::key_specialized_compute_script_preserving_truncated_128_certified_inputs(
            domain,
            PUBLIC_KEY,
            PRESERVED_ITEMS as u32,
        )
        .compile_with_policy();
    let fixed_hash =
        ed25519_challenge::key_specialized_compute_script_preserving_truncated_128_fixed_message(
            domain,
            PUBLIC_KEY,
            message,
            PRESERVED_ITEMS as u32,
        )
        .compile_with_policy();
    assert_eq!(binder.len(), EXPECTED_BINDER_POLICY_BYTES);
    assert_eq!(fixed_hash.len(), EXPECTED_FIXED_MESSAGE_HASH_POLICY_BYTES);
    assert_eq!(
        binder.len() + fixed_hash.len(),
        EXPECTED_COMBINED_FRAGMENT_BYTES
    );

    // The standalone binder must consume M and preserve the exact
    // `preserved | R` order.
    let binder_order_check = script! {
        { Script::new("precompiled fixed-M binder").push_script(binder.clone()) }
        { verify_values_bottom_to_top(&r_nibbles) }
        { verify_preserved(&preserved) }
        OP_1
    }
    .compile_with_policy();
    let binder_order = execute_raw_script_with_inputs_strict(
        binder_order_check.to_bytes(),
        witness(&preserved, &r_nibbles, &message_nibbles),
    );
    assert!(
        binder_order.error.is_none(),
        "fixed-message binder order check failed: {binder_order}"
    );
    assert_eq!(binder_order.final_stack.len(), 1);

    let binder_acceptance = script! {
        { Script::new("precompiled fixed-M binder").push_script(binder.clone()) }
        { drop_items(PRESERVED_ITEMS + 64) }
        OP_1
    }
    .compile_with_policy();
    let mut malformed = message_nibbles.clone();
    malformed[63] = 16;
    let malformed_result = execute_raw_script_with_inputs_strict(
        binder_acceptance.to_bytes(),
        witness(&preserved, &r_nibbles, &malformed),
    );
    assert!(
        malformed_result.error.is_some(),
        "out-of-range fixed-message nibble was accepted"
    );
    let mut wrong_order = message_nibbles.clone();
    let unequal = (0..63)
        .find(|index| wrong_order[*index] != wrong_order[*index + 1])
        .expect("fixture has unequal adjacent nibbles");
    wrong_order.swap(unequal, unequal + 1);
    let wrong_order_result = execute_raw_script_with_inputs_strict(
        binder_acceptance.to_bytes(),
        witness(&preserved, &r_nibbles, &wrong_order),
    );
    assert!(
        wrong_order_result.error.is_some(),
        "wrong fixed-message nibble order was accepted"
    );

    let transcript = [domain, PUBLIC_KEY, r, message].concat();
    let digest = *blake3::hash(&transcript).as_bytes();
    let local_old_hash =
        ed25519_challenge::key_specialized_compute_script_preserving_truncated_128_certified_inputs(
            domain,
            PUBLIC_KEY,
            0,
        )
        .compile_with_policy();
    let local_old_complete = script! {
        { Script::new("precompiled local variable-M BLAKE3").push_script(local_old_hash) }
        { verify_low128(&digest) }
        OP_1
    }
    .compile_with_policy();
    let local_old = execute_raw_script_with_inputs_strict(
        local_old_complete.to_bytes(),
        witness(&[], &r_nibbles, &message_nibbles),
    );
    eprintln!("old local hash probe: {local_old}");
    let old_complete = script! {
        { Script::new("precompiled old fixed-M binder").push_script(old_binder.clone()) }
        { Script::new("precompiled variable-M BLAKE3").push_script(old_hash.clone()) }
        { verify_low128(&digest) }
        { verify_preserved(&preserved) }
        OP_1
    }
    .compile_with_policy();
    let old_execution = execute_raw_script_with_inputs_strict(
        old_complete.to_bytes(),
        witness(&preserved, &r_nibbles, &message_nibbles),
    );
    eprintln!("old preserving hash probe: {old_execution}");
    let complete = script! {
        { Script::new("precompiled fixed-M binder").push_script(binder.clone()) }
        { Script::new("precompiled fixed-M BLAKE3").push_script(fixed_hash.clone()) }
        { verify_low128(&digest) }
        { verify_preserved(&preserved) }
        OP_1
    }
    .compile_with_policy();
    let complete_witness = witness(&preserved, &r_nibbles, &message_nibbles);
    let witness_bytes = serialize(&Witness::from_slice(&complete_witness)).len();
    let execution = execute_raw_script_with_inputs_strict(complete.to_bytes(), complete_witness);
    eprintln!("new preserving hash probe: {execution}");
    assert!(
        old_execution.error.is_none(),
        "old variable-message BLAKE3 differs from host digest: {old_execution}"
    );
    assert!(
        execution.error.is_none(),
        "fixed-message BLAKE3 differs from host digest: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);

    // The specialized hash enforces exactly `preserved | R` after the binder.
    let extra_input = script! {
        OP_0
        { Script::new("precompiled fixed-M BLAKE3").push_script(fixed_hash.clone()) }
        OP_1
    }
    .compile_with_policy();
    let extra = execute_raw_script_with_inputs_strict(
        extra_input.to_bytes(),
        witness(&preserved, &r_nibbles, &[]),
    );
    assert!(
        extra.error.is_some(),
        "specialized hash accepted extra input"
    );

    println!("model=ed25519_blake3_fixed_message_strict_probe");
    println!("evidence=locally-reproduced");
    println!("execution_class=unclassified");
    println!("context=tapscript,bitcoin-scriptexec,strict_1000_item_stack");
    println!("transcript=ordinary_unkeyed_BLAKE3_D32_A32_R32_fixed_M32");
    println!("digest_checked_bits=128");
    println!("entry_hint_items=0");
    println!("entry_data_items={}", PRESERVED_ITEMS + 128);
    println!("all_entry_items_coexist=true");
    println!("hash_frontier_input_items={}", PRESERVED_ITEMS + 64);
    println!("binder_policy_bytes={}", binder.len());
    println!("fixed_message_hash_policy_bytes={}", fixed_hash.len());
    println!(
        "combined_fragment_bytes={}",
        binder.len() + fixed_hash.len()
    );
    println!("manual_post_policy_optimizer=false");
    println!(
        "combined_static_non_push_opcodes={}",
        static_non_push_opcodes(&complete)
    );
    println!("fixture_witness_bytes={witness_bytes}");
    println!(
        "strict_combined_main_alt_stack_peak={}",
        execution.stats.max_nb_stack_items
    );
    println!("host_blake3_low128_match=true");
    println!("binder_preserves_exact_preserved_then_R_order=true");
    println!("malformed_message_rejected=true");
    println!("wrong_message_nibble_order_rejected=true");
    println!("extra_hash_input_rejected=true");
    println!("long_scalar_leaf_executed=false");
    println!("hint_coexistence=not_applicable_zero_hints");
}
