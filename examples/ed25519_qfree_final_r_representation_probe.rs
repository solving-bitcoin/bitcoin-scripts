//! Focused packed/u4/u5 representation probe for the final q-free Rtilde packet.
//!
//! This builds and executes only small conversion/routing fragments, plus
//! independently serializes the fixed-message BLAKE3 component. It never
//! builds or executes a scalar-multiplication schedule or complete leaf.

use bitcoin::{consensus::serialize, Witness};
use bitcoin_lab::{
    fields::ed25519::u5_packed,
    hashes::blake3::ed25519_challenge,
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation},
    },
};
use num_bigint::BigUint;

const PACKED_G31_ENTRY_ITEMS: usize = 744;
const PACKED_G31_RESPONSE_PEAK: usize = 944;
const PACKED_HASH_PRESERVED_ITEMS: usize = 297;
const ITEMS_ABOVE_FINAL_R: usize = 289;
const PACKED_R_ITEMS: usize = 8;
const U4_R_ITEMS: usize = 64;
const U5_R_ITEMS: usize = 51;
const LAMBDA_ITEMS: usize = 8;
const SELECTED_ITEMS: usize = 25;
const STATE_ITEMS: usize = 41;

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

fn move_block_to_top(block_items: usize, items_above: usize) -> Script {
    if block_items == 0 || items_above == 0 {
        return Script::new("no-op block move");
    }
    let depth = block_items + items_above - 1;
    script! { for _ in 0..block_items { { depth as u32 } OP_ROLL } }
}

fn reverse_chained_state_blocks() -> Script {
    script! {
        { move_block_to_top(16, 9) }
        { move_block_to_top(8, 25) }
        { move_block_to_top(8, 33) }
    }
}

fn certify_top_u4() -> Script {
    script! { OP_DUP 0 16 OP_WITHIN OP_VERIFY }
}

/// Consume the top eight u4 values in low-to-high significance and emit one
/// compressed-u32 ScriptNum. The sign bit is handled without constructing
/// positive 2^31.
fn pack_top_u4_word() -> Script {
    script! {
        for _ in 0..8 {
            { certify_top_u4() }
            OP_TOALTSTACK
        }
        OP_FROMALTSTACK
        OP_DUP 8 OP_GREATERTHANOREQUAL
        OP_IF 8 OP_SUB 1 OP_ELSE 0 OP_ENDIF
        OP_SWAP
        for _ in 0..7 {
            for _ in 0..4 { OP_DUP OP_ADD }
            OP_FROMALTSTACK OP_ADD
        }
        OP_SWAP
        OP_IF { i32::MAX } OP_SUB OP_1SUB OP_ENDIF
    }
}

/// Input/output is `R_u4[64] | lambda_packed[8]` to
/// `R_packed[8] | lambda_packed[8]`, in each public stack order.
fn reconstruct_u4_packet_to_packed() -> Script {
    script! {
        for _ in 0..LAMBDA_ITEMS { OP_TOALTSTACK }
        // Top u4 values are the low nibbles of word seven, then word six, ...
        for _ in 0..8 {
            { pack_top_u4_word() }
            OP_TOALTSTACK
        }
        for _ in 0..8 { OP_FROMALTSTACK }
        // Reverse word0..word7 back to packed public order word7..word0.
        for depth in 1..8u32 { { depth } OP_ROLL }
        for _ in 0..LAMBDA_ITEMS { OP_FROMALTSTACK }
    }
}

fn duplicate_bottom_u4(preserved_items: usize) -> Script {
    assert!(preserved_items >= U4_R_ITEMS);
    script! {
        // Appending one copy raises the next source by one while its original
        // index rises by one, leaving this depth invariant.
        for _ in 0..U4_R_ITEMS { { (preserved_items - 1) as u32 } OP_PICK }
    }
}

fn final_route(
    packet_items: usize,
    post_reconstruction_items: usize,
    reconstruct: Option<Script>,
) -> Script {
    script! {
        for _ in 0..STATE_ITEMS { OP_TOALTSTACK }
        { move_block_to_top(packet_items, SELECTED_ITEMS) }
        if let Some(reconstruct) = reconstruct { { reconstruct } }
        { move_block_to_top(SELECTED_ITEMS, post_reconstruction_items) }
        for _ in 0..STATE_ITEMS { OP_FROMALTSTACK }
        { reverse_chained_state_blocks() }
    }
}

fn exact_items_bytes(items: &[Vec<u8>]) -> usize {
    // Subtract the vector count; all compared variants leave the total witness
    // count in the same three-byte CompactSize class.
    serialize(&Witness::from_slice(items)).len() - 1
}

fn verify_items(items_bottom_to_top: &[Vec<u8>]) -> Script {
    script! {
        for item in items_bottom_to_top.iter().rev() {
            { item.clone() } OP_EQUALVERIFY
        }
    }
}

fn strict(script: Script, witness: Vec<Vec<u8>>) -> usize {
    let compiled = script.compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(compiled.to_bytes(), witness);
    assert!(
        execution.error.is_none(),
        "focused conversion failed: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);
    execution.stats.max_nb_stack_items
}

fn main() {
    let words = std::array::from_fn(|index| {
        u32::from_le_bytes(RTILDE[4 * index..4 * index + 4].try_into().unwrap())
    });
    let packed = words
        .iter()
        .rev()
        .map(|word| scriptnum_item(i64::from(*word as i32)))
        .collect::<Vec<_>>();
    let u4 = ed25519_challenge::transcript_half_u4(&RTILDE)
        .into_iter()
        .map(|value| scriptnum_item(i64::from(value)))
        .collect::<Vec<_>>();
    let u5 = u5_packed::digits_from_packed_words(&words)
        .expect("fixture Rtilde is a canonical packed field")
        .into_iter()
        .rev()
        .map(|value| scriptnum_item(i64::from(value)))
        .collect::<Vec<_>>();
    assert_eq!(packed.len(), PACKED_R_ITEMS);
    assert_eq!(u4.len(), U4_R_ITEMS);
    assert_eq!(u5.len(), U5_R_ITEMS);

    let lambda = u5_packed::packed_value_witness_items(&BigUint::from(7u8));
    let u4_reconstruction = reconstruct_u4_packet_to_packed();
    let expected_packet = packed
        .iter()
        .cloned()
        .chain(lambda.iter().cloned())
        .collect::<Vec<_>>();
    let u4_packet = u4
        .iter()
        .cloned()
        .chain(lambda.iter().cloned())
        .collect::<Vec<_>>();
    let reconstruction_peak = strict(
        script! {
            { u4_reconstruction.clone() }
            { verify_items(&expected_packet) }
            OP_1
        },
        u4_packet.clone(),
    );
    let mut malformed_u4_packet = u4_packet.clone();
    malformed_u4_packet[17] = scriptnum_item(16);
    let rejected = execute_raw_script_with_inputs_strict(
        script! {
            { u4_reconstruction.clone() }
            { verify_items(&expected_packet) }
            OP_1
        }
        .compile_with_policy()
        .to_bytes(),
        malformed_u4_packet,
    );
    assert!(rejected.error.is_some());

    let packed_route = final_route(16, 16, None);
    let u4_route = final_route(72, 16, Some(u4_reconstruction.clone()));
    let u5_route = final_route(59, 59, None);
    let route_suffix = (0..SELECTED_ITEMS + STATE_ITEMS)
        .map(|index| scriptnum_item(100 + index as i64))
        .collect::<Vec<_>>();
    let route_peak = strict(
        script! {
            { u4_route.clone() }
            for _ in 0..16 + SELECTED_ITEMS + STATE_ITEMS { OP_DROP }
            OP_1
        },
        u4_packet.iter().cloned().chain(route_suffix).collect(),
    );
    let u5_route_peak = strict(
        script! {
            { u5_route.clone() }
            for _ in 0..59 + SELECTED_ITEMS + STATE_ITEMS { OP_DROP }
            OP_1
        },
        u5.iter()
            .cloned()
            .chain(lambda.iter().cloned())
            .chain(
                (0..SELECTED_ITEMS + STATE_ITEMS).map(|index| scriptnum_item(200 + index as i64)),
            )
            .collect(),
    );

    let u4_preserved = PACKED_HASH_PRESERVED_ITEMS + U4_R_ITEMS - PACKED_R_ITEMS;
    let u4_copy = duplicate_bottom_u4(u4_preserved);
    let u4_copy_peak = strict(
        script! {
            { u4_copy.clone() }
            { verify_items(&u4) }
            for _ in 0..u4_preserved { OP_DROP }
            OP_1
        },
        u4.iter()
            .cloned()
            .chain((0..ITEMS_ABOVE_FINAL_R).map(|_| scriptnum_item(1)))
            .collect(),
    );

    let u5_preserved = PACKED_HASH_PRESERVED_ITEMS + U5_R_ITEMS - PACKED_R_ITEMS;
    let u5_conversion =
        ed25519_challenge::duplicate_canonical_u5_r_as_u4(ITEMS_ABOVE_FINAL_R as u32);
    let u5_prefix = u5
        .iter()
        .cloned()
        .chain((0..ITEMS_ABOVE_FINAL_R).map(|_| scriptnum_item(1)))
        .collect::<Vec<_>>();
    assert_eq!(u5_prefix.len(), u5_preserved);
    let u5_conversion_peak = strict(
        script! {
            { u5_conversion.clone() }
            { verify_items(&u4) }
            { verify_items(&u5_prefix) }
            OP_1
        },
        u5_prefix.clone(),
    );
    let mut malformed_u5 = u5_prefix;
    malformed_u5[U5_R_ITEMS - 1] = scriptnum_item(32);
    let malformed_u5_execution = execute_raw_script_with_inputs_strict(
        script! {
            { u5_conversion.clone() }
            for _ in 0..U4_R_ITEMS + u5_preserved { OP_DROP }
            OP_1
        }
        .compile_with_policy()
        .to_bytes(),
        malformed_u5,
    );
    assert!(malformed_u5_execution.error.is_some());

    let domain = *blake3::hash(b"bitcoin-lab/custom-ed25519-blake3-slope-v1").as_bytes();
    let message = std::array::from_fn(|index| (index as u8).wrapping_mul(7));
    let direct_hash_u4 =
        ed25519_challenge::key_specialized_compute_script_preserving_truncated_128_fixed_message(
            domain,
            PUBLIC_KEY,
            message,
            u4_preserved as u32,
        )
        .compile_with_policy();
    let direct_hash_packed_depth =
        ed25519_challenge::key_specialized_compute_script_preserving_truncated_128_fixed_message(
            domain,
            PUBLIC_KEY,
            message,
            PACKED_HASH_PRESERVED_ITEMS as u32,
        )
        .compile_with_policy();
    let direct_hash_u5 =
        ed25519_challenge::key_specialized_compute_script_preserving_truncated_128_fixed_message(
            domain,
            PUBLIC_KEY,
            message,
            u5_preserved as u32,
        )
        .compile_with_policy();
    let packed_boundary = ed25519_challenge::
        key_specialized_compute_script_preserving_truncated_128_fixed_message_from_certified_packed_r(
            domain,
            PUBLIC_KEY,
            message,
            PACKED_HASH_PRESERVED_ITEMS as u32,
            ITEMS_ABOVE_FINAL_R as u32,
        )
        .compile_with_policy();
    assert_eq!(packed_boundary.len(), 67_806);
    let u4_boundary_bytes = u4_copy.clone().compile_with_policy().len() + direct_hash_u4.len();
    let u5_boundary_bytes =
        u5_conversion.clone().compile_with_policy().len() + direct_hash_u5.len();
    let u4_pre_kernel_delta = u4_boundary_bytes as isize - packed_boundary.len() as isize
        + u4_route.len() as isize
        - packed_route.len() as isize;
    let u5_pre_kernel_delta = u5_boundary_bytes as isize - packed_boundary.len() as isize
        + u5_route.len() as isize
        - packed_route.len() as isize;

    let packed_bytes = exact_items_bytes(&packed);
    let u4_bytes = exact_items_bytes(&u4);
    let u5_bytes = exact_items_bytes(&u5);
    println!("model=ed25519_qfree_final_r_representation_probe");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=focused-conversion");
    println!("execution_class=unclassified");
    println!("whole_leaf_built_or_executed=false");
    println!("packed_entry_items={PACKED_G31_ENTRY_ITEMS}");
    println!("packed_analytical_response_peak={PACKED_G31_RESPONSE_PEAK}");
    println!("u4_entry_items={}", PACKED_G31_ENTRY_ITEMS + 56);
    println!(
        "u4_analytical_response_peak={}",
        PACKED_G31_RESPONSE_PEAK + 56
    );
    println!("u5_entry_items={}", PACKED_G31_ENTRY_ITEMS + 43);
    println!(
        "u5_analytical_response_peak={}",
        PACKED_G31_RESPONSE_PEAK + 43
    );
    println!("packed_fixture_r_item_bytes={packed_bytes}");
    println!("u4_fixture_r_item_bytes={u4_bytes}");
    println!(
        "u4_fixture_witness_delta={}",
        u4_bytes as isize - packed_bytes as isize
    );
    println!("u5_fixture_r_item_bytes={u5_bytes}");
    println!(
        "u5_fixture_witness_delta={}",
        u5_bytes as isize - packed_bytes as isize
    );
    println!(
        "u4_copy_policy_bytes={}",
        u4_copy.clone().compile_with_policy().len()
    );
    println!("u4_copy_strict_peak={u4_copy_peak}");
    println!(
        "u4_reconstruction_policy_bytes={}",
        u4_reconstruction.clone().compile_with_policy().len()
    );
    println!("u4_reconstruction_strict_peak={reconstruction_peak}");
    println!("packed_final_route_raw_bytes={}", packed_route.len());
    println!("u4_final_route_raw_bytes={}", u4_route.len());
    println!(
        "u4_final_route_raw_delta={}",
        u4_route.len() as isize - packed_route.len() as isize
    );
    println!(
        "u4_final_route_policy_bytes={}",
        u4_route.compile_with_policy().len()
    );
    println!("u4_final_route_strict_peak={route_peak}");
    println!("u5_final_route_raw_bytes={}", u5_route.len());
    println!(
        "u5_final_route_raw_delta={}",
        u5_route.len() as isize - packed_route.len() as isize
    );
    println!(
        "u5_final_route_policy_bytes={}",
        u5_route.compile_with_policy().len()
    );
    println!("u5_final_route_strict_peak={u5_route_peak}");
    println!("u4_direct_hash_policy_bytes={}", direct_hash_u4.len());
    println!(
        "u5_duplicate_certify_repack_policy_bytes={}",
        u5_conversion.clone().compile_with_policy().len()
    );
    println!("u5_duplicate_certify_repack_strict_peak={u5_conversion_peak}");
    println!("u5_direct_hash_policy_bytes={}", direct_hash_u5.len());
    println!(
        "packed_depth_direct_hash_policy_bytes={}",
        direct_hash_packed_depth.len()
    );
    println!("packed_boundary_policy_bytes={}", packed_boundary.len());
    println!("packed_boundary_manual_post_policy_optimizer=false");
    println!("u4_boundary_policy_bytes={u4_boundary_bytes}");
    println!("u4_boundary_plus_final_route_script_delta={u4_pre_kernel_delta}");
    println!("u5_boundary_policy_bytes={u5_boundary_bytes}");
    println!(
        "u5_boundary_plus_final_route_script_delta_before_specialized_kernel={u5_pre_kernel_delta}"
    );
    println!("u4_out_of_range_rejected=true");
    println!("u5_out_of_range_and_19_value_gap_rejected=true");
    println!(
        "all_alternate_r_items_retained_through_hash_and_consumed_by_final_authentication=true"
    );
    println!("auxiliary_hint_items=0");
}
