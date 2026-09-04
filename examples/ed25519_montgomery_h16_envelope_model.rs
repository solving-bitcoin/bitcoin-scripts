//! Serialization and block-weight envelope for the Montgomery H16 candidate.
//!
//! This is a deterministic arithmetic model, not a constructed transaction and
//! not a Bitcoin Core consensus reproduction.  It uses the BIP-141 weight
//! formula and the BIP-341 depth-zero script-path witness shape.  The default
//! script size is the policy-only additive projection for the legacy linked
//! H16 leaf; pass an exact regenerated value with `--script-bytes N` as
//! integration changes it.
//!
//! Run with:
//! `cargo run --locked --example ed25519_montgomery_h16_envelope_model -- --script-bytes N`.

use bitcoin::{
    absolute, consensus::encode::serialize, transaction, Amount, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness,
};

const DEFAULT_ADDITIVE_PROJECTED_SCRIPT_BYTES: usize = 3_828_057;

const TRACE_DATA_ITEMS: usize = 704;
const TRACE_MAX_PAYLOAD_BYTES: usize = 5;
const QUOTIENT_HINT_ITEMS: usize = 88;
const QUOTIENT_MAX_PAYLOAD_BYTES: usize = 4;
const ARGUMENT_ITEMS: usize = TRACE_DATA_ITEMS + QUOTIENT_HINT_ITEMS;

const DEPTH_ZERO_CONTROL_BLOCK_BYTES: usize = 33;
const TAPROOT_OUTPUT_SCRIPT_BYTES: usize = 34;

const BLOCK_HEADER_BYTES: usize = 80;
const WITNESS_COMMITMENT_SCRIPT_BYTES: usize = 38;
const CURRENT_HEIGHT_COINBASE_SCRIPTSIG_BYTES: usize = 4;
const MAX_BLOCK_WEIGHT: usize = 4_000_000;
const MAX_STANDARD_TX_WEIGHT: usize = 400_000;

fn compact_size_bytes(value: usize) -> usize {
    match value {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn target_base_bytes() -> usize {
    let version = 4;
    let input_count = compact_size_bytes(1);
    // Outpoint, empty-scriptSig CompactSize, and sequence.
    let input = 32 + 4 + compact_size_bytes(0) + 4;
    let output_count = compact_size_bytes(1);
    let output = 8 + compact_size_bytes(TAPROOT_OUTPUT_SCRIPT_BYTES) + TAPROOT_OUTPUT_SCRIPT_BYTES;
    let lock_time = 4;
    version + input_count + input + output_count + output + lock_time
}

fn target_witness_field_bytes(script_bytes: usize) -> usize {
    let witness_item_count = ARGUMENT_ITEMS + 2; // leaf script + control block
    let trace =
        TRACE_DATA_ITEMS * (compact_size_bytes(TRACE_MAX_PAYLOAD_BYTES) + TRACE_MAX_PAYLOAD_BYTES);
    let quotient_hints = QUOTIENT_HINT_ITEMS
        * (compact_size_bytes(QUOTIENT_MAX_PAYLOAD_BYTES) + QUOTIENT_MAX_PAYLOAD_BYTES);
    let leaf = compact_size_bytes(script_bytes) + script_bytes;
    let control =
        compact_size_bytes(DEPTH_ZERO_CONTROL_BLOCK_BYTES) + DEPTH_ZERO_CONTROL_BLOCK_BYTES;
    compact_size_bytes(witness_item_count) + trace + quotient_hints + leaf + control
}

fn target_nonbase_bytes(script_bytes: usize) -> usize {
    2 + target_witness_field_bytes(script_bytes) // marker + flag
}

fn target_weight(script_bytes: usize) -> usize {
    4 * target_base_bytes() + target_nonbase_bytes(script_bytes)
}

/// Minimum current-height coinbase that commits to a witness-bearing block.
///
/// The four-byte scriptSig is the three-byte current block-height ScriptNum
/// plus its one-byte direct-push opcode.  A real miner coinbase normally has
/// extra scriptSig data and may have extra outputs, so this is only a lower
/// bound on the block space outside the candidate transaction.
fn minimum_current_height_coinbase_weight() -> usize {
    let version = 4;
    let input_count = compact_size_bytes(1);
    let input = 32
        + 4
        + compact_size_bytes(CURRENT_HEIGHT_COINBASE_SCRIPTSIG_BYTES)
        + CURRENT_HEIGHT_COINBASE_SCRIPTSIG_BYTES
        + 4;
    let output_count = compact_size_bytes(1);
    let commitment_output =
        8 + compact_size_bytes(WITNESS_COMMITMENT_SCRIPT_BYTES) + WITNESS_COMMITMENT_SCRIPT_BYTES;
    let lock_time = 4;
    let base = version + input_count + input + output_count + commitment_output + lock_time;

    // Segwit marker/flag plus one 32-byte witness-reserved-value stack item.
    let nonbase = 2 + compact_size_bytes(1) + compact_size_bytes(32) + 32;
    4 * base + nonbase
}

fn minimum_other_block_weight() -> usize {
    // Header and the two-transaction CompactSize are non-witness bytes.
    4 * (BLOCK_HEADER_BYTES + compact_size_bytes(2)) + minimum_current_height_coinbase_weight()
}

fn parse_script_bytes() -> (usize, &'static str) {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next(), args.next()) {
        (None, None, None) => (
            DEFAULT_ADDITIVE_PROJECTED_SCRIPT_BYTES,
            "additive_projection_pending_exact_whole_regeneration",
        ),
        (Some("--script-bytes"), Some(value), None) => (
            value
                .parse::<usize>()
                .expect("--script-bytes must be a non-negative integer"),
            "caller_supplied",
        ),
        _ => panic!("usage: ed25519_montgomery_h16_envelope_model [--script-bytes N]"),
    }
}

fn p2tr_script_pubkey() -> ScriptBuf {
    let mut bytes = vec![0x51, 0x20]; // OP_1, direct push of the 32-byte output key
    bytes.extend([0u8; 32]);
    ScriptBuf::from_bytes(bytes)
}

fn serialized_target(script_bytes: usize) -> Transaction {
    let mut witness = Witness::new();
    for _ in 0..TRACE_DATA_ITEMS {
        witness.push([0xff; TRACE_MAX_PAYLOAD_BYTES]);
    }
    for _ in 0..QUOTIENT_HINT_ITEMS {
        witness.push([0xff; QUOTIENT_MAX_PAYLOAD_BYTES]);
    }
    witness.push(vec![0u8; script_bytes]);
    witness.push(vec![0u8; DEPTH_ZERO_CONTROL_BLOCK_BYTES]);

    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: p2tr_script_pubkey(),
        }],
    }
}

fn serialized_minimum_coinbase() -> Transaction {
    let mut witness = Witness::new();
    witness.push([0u8; 32]);

    let mut commitment = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    commitment.extend([0u8; 32]);

    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            // Shape of the BIP-34 direct push for a current three-byte height.
            script_sig: ScriptBuf::from_bytes(vec![0x03, 0x40, 0x42, 0x0f]),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(commitment),
        }],
    }
}

fn main() {
    let (script_bytes, script_bytes_metric_status) = parse_script_bytes();
    assert!((0x1_0000..=0xffff_ffff).contains(&script_bytes));

    assert_eq!(ARGUMENT_ITEMS, 792);
    assert_eq!(compact_size_bytes(ARGUMENT_ITEMS + 2), 3);
    assert_eq!(target_base_bytes(), 94);
    assert_eq!(
        target_witness_field_bytes(script_bytes),
        script_bytes + 4_706
    );
    assert_eq!(target_nonbase_bytes(script_bytes), script_bytes + 4_708);
    assert_eq!(target_weight(script_bytes), script_bytes + 5_084);
    assert_eq!(minimum_current_height_coinbase_weight(), 444);
    assert_eq!(minimum_other_block_weight(), 768);

    // Reproduce the hand-derived CompactSize and weight arithmetic with the
    // pinned rust-bitcoin consensus serializer.  The byte contents are shape
    // fixtures only; neither transaction is submitted for consensus checks.
    let target = serialized_target(script_bytes);
    assert_eq!(target.input[0].witness.len(), ARGUMENT_ITEMS + 2);
    assert_eq!(
        serialize(&target).len(),
        target_base_bytes() + target_nonbase_bytes(script_bytes)
    );
    assert_eq!(
        target.weight().to_wu() as usize,
        target_weight(script_bytes)
    );
    let coinbase = serialized_minimum_coinbase();
    assert_eq!(serialize(&coinbase).len(), 138);
    assert_eq!(
        coinbase.weight().to_wu() as usize,
        minimum_current_height_coinbase_weight()
    );

    let projected_block_weight = target_weight(script_bytes) + minimum_other_block_weight();
    let maximum_script_bytes = MAX_BLOCK_WEIGHT
        - (target_weight(script_bytes) - script_bytes)
        - minimum_other_block_weight();

    println!("model=ed25519_montgomery_h16_tapscript_envelope");
    println!("evidence=locally-reproduced");
    println!("execution_class=unclassified");
    println!("script_bytes={script_bytes}");
    println!("script_bytes_metric_status={script_bytes_metric_status}");
    println!("hint_items_per_transition=2");
    println!("transitions=44");
    println!("quotient_hint_items_total={QUOTIENT_HINT_ITEMS}");
    println!("trace_data_items_total={TRACE_DATA_ITEMS}");
    println!("all_792_argument_items_coexist_at_script_entry=true");
    println!("trace_payload_upper_bound_bytes={TRACE_MAX_PAYLOAD_BYTES}");
    println!("quotient_payload_upper_bound_bytes={QUOTIENT_MAX_PAYLOAD_BYTES}");
    println!(
        "witness_stack_item_count_including_leaf_and_control={}",
        ARGUMENT_ITEMS + 2
    );
    println!("target_stripped_bytes={}", target_base_bytes());
    println!(
        "target_witness_field_bytes={}",
        target_witness_field_bytes(script_bytes)
    );
    println!(
        "target_marker_flag_plus_witness_bytes={}",
        target_nonbase_bytes(script_bytes)
    );
    println!(
        "target_total_serialized_bytes={}",
        target_base_bytes() + target_nonbase_bytes(script_bytes)
    );
    println!("target_weight={}", target_weight(script_bytes));
    println!(
        "minimum_current_height_coinbase_weight={}",
        minimum_current_height_coinbase_weight()
    );
    println!(
        "minimum_header_txcount_coinbase_weight={}",
        minimum_other_block_weight()
    );
    println!("projected_minimum_block_weight={projected_block_weight}");
    println!(
        "headroom_below_4_000_000={}",
        MAX_BLOCK_WEIGHT.saturating_sub(projected_block_weight)
    );
    println!("conservative_maximum_script_bytes_with_only_minimum_current_height_block_overhead={maximum_script_bytes}");
    println!("standard_transaction_weight_limit={MAX_STANDARD_TX_WEIGHT}");
    println!(
        "standard_relay_weight_compatible={}",
        target_weight(script_bytes) <= MAX_STANDARD_TX_WEIGHT
    );
    println!("depth_zero_control_block_assumed=true");
    println!("annex_assumed=false");
    println!("fixed_message_bound_in_linked_leaf=true");
    println!("entry_packet_order=response28_then_challenge16");
    println!("post_scalar_transpose_packet_order=challenge16_then_response28");
    println!("extra_signature_or_message_witness_items_assumed=false");
    println!("signature_and_transcript_payloads_assumed_embedded_in_q_metadata=true");
    println!("coinbase_is_lower_bound_not_miner_template_upper_bound=true");
    println!("rust_bitcoin_consensus_serialization_cross_check=true");
    println!("includes=complete-transaction projection: one input, one 34-byte P2TR output, 792 hostile argument items, revealed leaf, depth-zero control block, witness CompactSizes, marker/flag, and a lower-bound current-height witness-committing block envelope; shape-only serialized fixtures, no consensus-valid signed transaction, funding transaction, fees, annex, extra outputs, real miner coinbase data, or Bitcoin Core validation");
}
