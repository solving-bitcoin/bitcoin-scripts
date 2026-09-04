//! Lightweight generation-only measurements for custom Ed25519-style BLAKE3
//! challenge transcripts. This deliberately does not execute the generated
//! compression scripts or run the long BLAKE3 suite.

use bitcoin::script::Instruction;
use bitcoin_lab::{
    hashes::blake3::ed25519_challenge,
    support::script::{script, ScriptCompilation},
};

fn static_non_push_opcodes(script: &bitcoin::Script) -> usize {
    script
        .instructions()
        .filter(|instruction| matches!(instruction, Ok(Instruction::Op(_))))
        .count()
}

fn measure_key_specialized() {
    let domain = std::array::from_fn(|index| index as u8);
    let public_key = std::array::from_fn(|index| (index as u8).wrapping_mul(3));
    let prefix_cv = ed25519_challenge::fixed_prefix_cv(domain, public_key);
    let script =
        ed25519_challenge::key_specialized_compute_script(domain, public_key).compile_with_policy();
    println!("model=ed25519_blake3_key_specialized_challenge");
    println!("challenge=BLAKE3(D32||A32||R32||M32)");
    println!("transcript_bytes=128");
    println!("fixed_prefix_bytes=64");
    println!("variable_suffix_bytes=64");
    println!("limb_bits=4");
    println!("compute_script_bytes={}", script.len());
    println!(
        "static_non_push_opcodes={}",
        static_non_push_opcodes(&script)
    );
    println!("embedded_prefix_cv={prefix_cv:08x?}");
    println!("declared_input_items=128");
    println!("hint_items=0");
    println!("analytic_local_peak_upper_bound=591");
    println!("maximum_preserved_items=409");
    println!("output_items=64");
    println!("script_compilation=repository_policy_only");
    println!("manual_post_policy_optimizer=false");
    println!("execution_class=unclassified");
    println!("execution_performed=false");
    println!("execution_boundary=generation-only");
    println!("full_signature_verifier=false");
}

fn measure_key_specialized_truncated_128() {
    let domain = std::array::from_fn(|index| index as u8);
    let public_key = std::array::from_fn(|index| (index as u8).wrapping_mul(3));
    let prefix_cv = ed25519_challenge::fixed_prefix_cv(domain, public_key);
    let script = ed25519_challenge::key_specialized_compute_script_preserving_truncated_128(
        domain, public_key, 0,
    )
    .compile_with_policy();
    println!("model=ed25519_blake3_key_specialized_challenge_truncated_128");
    println!("challenge=low128(BLAKE3(D32||A32||R32||M32))");
    println!("transcript_bytes=128");
    println!("fixed_prefix_bytes=64");
    println!("variable_suffix_bytes=64");
    println!("limb_bits=4");
    println!("compute_script_bytes={}", script.len());
    println!(
        "static_non_push_opcodes={}",
        static_non_push_opcodes(&script)
    );
    println!("embedded_prefix_cv={prefix_cv:08x?}");
    println!("declared_input_items=128");
    println!("hint_items=0");
    println!("output_items=32");
    println!("script_compilation=repository_policy_only");
    println!("manual_post_policy_optimizer=false");
    println!("execution_class=unclassified");
    println!("execution_performed=false");
    println!("execution_boundary=generation-only");
    println!("full_signature_verifier=false");
}

fn measure_key_specialized_truncated_128_certified_inputs() {
    let domain = std::array::from_fn(|index| index as u8);
    let public_key = std::array::from_fn(|index| (index as u8).wrapping_mul(3));
    let script =
        ed25519_challenge::key_specialized_compute_script_preserving_truncated_128_certified_inputs(
            domain, public_key, 0,
        )
        .compile_with_policy();
    println!("model=ed25519_blake3_key_specialized_challenge_truncated_128_certified_inputs");
    println!("challenge=low128(BLAKE3(D32||A32||R32||M32))");
    println!("compute_script_bytes={}", script.len());
    println!(
        "static_non_push_opcodes={}",
        static_non_push_opcodes(&script)
    );
    println!("declared_input_items=128");
    println!("input_range_checks=external_required_0_to_15");
    println!("hint_items=0");
    println!("output_items=32");
    println!("script_compilation=repository_policy_only");
    println!("manual_post_policy_optimizer=false");
    println!("execution_class=unclassified");
    println!("execution_performed=false");
    println!("execution_boundary=generation-only");
    println!("full_signature_verifier=false");
}

fn measure_key_specialized_truncated_128_certified_inputs_preserving_337() {
    // At the H16 slope-chain hash frontier, 288 future packets, the 41-item
    // current state, and an eight-word packed copy of R remain below the
    // 128-nibble transcript. Keeping those words permits the final shifted-u
    // comparison without retaining another 64 nibbles through BLAKE3.
    const PRESERVED_ITEMS: u32 = 288 + 41 + 8;
    let domain = std::array::from_fn(|index| index as u8);
    let public_key = std::array::from_fn(|index| (index as u8).wrapping_mul(3));
    let script =
        ed25519_challenge::key_specialized_compute_script_preserving_truncated_128_certified_inputs(
            domain,
            public_key,
            PRESERVED_ITEMS,
        )
        .compile_with_policy();
    println!("model=ed25519_blake3_key_specialized_challenge_truncated_128_certified_inputs_preserving_337");
    println!("challenge=low128(BLAKE3(D32||A32||R32||M32))");
    println!("compute_script_bytes={}", script.len());
    println!(
        "static_non_push_opcodes={}",
        static_non_push_opcodes(&script)
    );
    println!("declared_preserved_items={PRESERVED_ITEMS}");
    println!("declared_transcript_input_items=128");
    println!("complete_fragment_input_items={}", PRESERVED_ITEMS + 128);
    println!("input_range_checks=external_required_0_to_15");
    println!("hint_items=0");
    println!("output_items_above_preserved=32");
    println!("analytic_combined_peak_upper_bound=928");
    println!("script_compilation=repository_policy_only");
    println!("manual_post_policy_optimizer=false");
    println!("execution_class=unclassified");
    println!("execution_performed=false");
    println!("execution_boundary=generation-only");
    println!("full_signature_verifier=false");
}

fn measure_key_specialized_truncated_128_fixed_message_preserving_337() {
    const PRESERVED_ITEMS: u32 = 288 + 41 + 8;
    const PUBLIC_KEY: [u8; 32] = [
        0x7d, 0xb0, 0xdc, 0x92, 0x22, 0xf3, 0xc1, 0x83, 0x45, 0x7d, 0xdd, 0xe4, 0xc7, 0x08, 0xde,
        0x8e, 0x5e, 0xa6, 0xbf, 0x3d, 0x5c, 0x44, 0x04, 0xcc, 0xa1, 0x4b, 0x32, 0x72, 0x9a, 0x05,
        0xc3, 0x2a,
    ];
    let domain = *blake3::hash(b"bitcoin-lab/custom-ed25519-blake3-slope-v1").as_bytes();
    let message = std::array::from_fn(|index| (index as u8).wrapping_mul(7));
    let old_binding = {
        let nibbles = ed25519_challenge::transcript_half_u4(&message);
        script! {
            for nibble in nibbles.iter().rev() { { *nibble } OP_NUMEQUALVERIFY }
            for nibble in &nibbles { { *nibble } }
        }
        .compile_with_policy()
    };
    let old_hash =
        ed25519_challenge::key_specialized_compute_script_preserving_truncated_128_certified_inputs(
            domain,
            PUBLIC_KEY,
            PRESERVED_ITEMS,
        )
        .compile_with_policy();
    let new_binding = ed25519_challenge::bind_and_drop_fixed_message(message).compile_with_policy();
    let new_hash =
        ed25519_challenge::key_specialized_compute_script_preserving_truncated_128_fixed_message(
            domain,
            PUBLIC_KEY,
            message,
            PRESERVED_ITEMS,
        )
        .compile_with_policy();
    let old_total = old_binding.len() + old_hash.len();
    let new_total = new_binding.len() + new_hash.len();

    println!("model=ed25519_blake3_fixed_message_preserving_337");
    println!("challenge=low128(BLAKE3(D32||A32||R32||fixed_M32))");
    println!("old_binding_policy_bytes={}", old_binding.len());
    println!("old_hash_policy_bytes={}", old_hash.len());
    println!("old_combined_policy_bytes={old_total}");
    println!("new_bind_and_drop_policy_bytes={}", new_binding.len());
    println!("new_fixed_message_hash_policy_bytes={}", new_hash.len());
    println!("new_combined_policy_bytes={new_total}");
    println!("combined_savings_bytes={}", old_total - new_total);
    println!("entry_data_items=465");
    println!("old_hash_input_items=465");
    println!("new_hash_input_items=401");
    println!("hint_items=0");
    println!("old_strict_probe_combined_peak=928");
    println!("new_strict_probe_combined_peak=864");
    println!("strict_probe=ed25519_blake3_fixed_message_probe");
    println!("execution_class=unclassified");
    println!("execution_performed=false");
    println!("execution_boundary=generation-only");
}

fn measure_exact_96() {
    let script = ed25519_challenge::compute_script().compile_with_policy();
    println!("model=ed25519_blake3_exact_96_byte_challenge");
    println!("challenge=BLAKE3(R32||A32||M32)");
    println!("transcript_bytes=96");
    println!("fixed_prefix_bytes=0");
    println!("variable_suffix_bytes=96");
    println!("limb_bits=4");
    println!("compute_script_bytes={}", script.len());
    println!(
        "static_non_push_opcodes={}",
        static_non_push_opcodes(&script)
    );
    println!("declared_input_items=192");
    println!("hint_items=0");
    println!("analytic_local_peak_upper_bound=655");
    println!("maximum_preserved_items=345");
    println!("output_items=64");
    println!("script_compilation=repository_policy_only");
    println!("manual_post_policy_optimizer=false");
    println!("execution_class=unclassified");
    println!("execution_performed=false");
    println!("execution_boundary=generation-only");
    println!("full_signature_verifier=false");
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        None | Some("--key-specialized") => measure_key_specialized(),
        Some("--key-specialized-truncated-128") => measure_key_specialized_truncated_128(),
        Some("--key-specialized-truncated-128-certified-inputs") => {
            measure_key_specialized_truncated_128_certified_inputs()
        }
        Some("--key-specialized-truncated-128-certified-inputs-preserving-337") => {
            measure_key_specialized_truncated_128_certified_inputs_preserving_337()
        }
        Some("--key-specialized-truncated-128-fixed-message-preserving-337") => {
            measure_key_specialized_truncated_128_fixed_message_preserving_337()
        }
        Some("--exact-96") => measure_exact_96(),
        Some(_) => panic!("use --key-specialized, --key-specialized-truncated-128, --key-specialized-truncated-128-certified-inputs, --key-specialized-truncated-128-certified-inputs-preserving-337, --key-specialized-truncated-128-fixed-message-preserving-337, or --exact-96"),
    }
}
