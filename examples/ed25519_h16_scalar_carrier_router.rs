//! Full item-accurate scalar-carrier router for the 44-transition H16 slope
//! schedule.
//!
//! The synthetic entry contains 44 distinguishable packets. Each packet is
//! `trace[0..16] | q_continuity | q_curve`, for 16 packed trace-data items and
//! two logical quotient hints. Twenty-nine challenge-side signed-23 q items
//! carry the 253-bit G29 centered payload `C+s` plus eight checked zero bits.
//! Script rolls each carrier out of its exact packet slot, compact-decodes it,
//! rotates the direct q back into the same slot, and streams the nine metadata
//! bits into eight canonical compressed-u32 scalar words. The entry is laid
//! out response-first and challenge-last so those 29 challenge carriers are
//! physically shallow. A one-time packet-block transpose then changes the
//! execution layout to challenge-first/response-last before scalar streaming.
//!
//! This probe executes real routing and word construction, including a fixture
//! whose first output word is the runtime five-byte `-2^31` sentinel. It does
//! not execute scalar multiplication, field arithmetic, BLAKE3, or the scalar
//! interval validator. The 792-item packet layout is synthetic but exact in
//! item count and packet ordering.

use bitcoin::{consensus::encode::serialize, Witness};
use bitcoin_lab::{
    arithmetic::{u31::u31_to_bits_with_width, u32::stack::u32_compress},
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
    },
};
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};

const TRANSITIONS: usize = 44;
const RESPONSE_TRANSITIONS: usize = 28;
const CHALLENGE_TRANSITIONS: usize = TRANSITIONS - RESPONSE_TRANSITIONS;
const TRACE_ITEMS_PER_PACKET: usize = 16;
const Q_ITEMS_PER_PACKET: usize = 2;
const PACKET_ITEMS: usize = TRACE_ITEMS_PER_PACKET + Q_ITEMS_PER_PACKET;
const TRACE_ITEMS: usize = TRANSITIONS * TRACE_ITEMS_PER_PACKET;
const Q_HINT_ITEMS: usize = TRANSITIONS * Q_ITEMS_PER_PACKET;
const RAW_ENTRY_ITEMS: usize = TRANSITIONS * PACKET_ITEMS;
const SCALAR_CARRIER_ITEMS: usize = 29;
const CARRIER_BITS: usize = 9;
const CARRIED_BITS: usize = SCALAR_CARRIER_ITEMS * CARRIER_BITS;
const SCALAR_BITS: usize = 253;
const SPARE_BITS: usize = CARRIED_BITS - SCALAR_BITS;
const SCALAR_WORDS: usize = 8;
const Q_BITS: usize = 23;

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn encode_carrier(metadata: u16, q: i32) -> i64 {
    assert!(metadata < (1 << CARRIER_BITS));
    assert!((-(1 << 22)..(1 << 22)).contains(&q));
    let low = metadata & 0xff;
    let sign = metadata >> 8;
    let payload = (i64::from(low) << Q_BITS) + i64::from(q) + (1 << 22);
    let carrier = if sign == 0 { payload } else { -(payload + 1) };
    assert_ne!(carrier, -(1i64 << 31));
    carrier
}

/// Before: `carrier`; after: `q | metadata_u9`.
fn decode_carrier_compact() -> Script {
    script! {
        OP_SIZE 5 OP_LESSTHAN OP_VERIFY
        OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
        OP_DUP 0 OP_LESSTHAN
        OP_DUP OP_TOALTSTACK
        OP_IF
            OP_NEGATE OP_1SUB
        OP_ENDIF

        // remainder | metadata prefix, accumulated high bit first.
        0 OP_SWAP
        for bit in (Q_BITS..31).rev() {
            { 1u32 << bit }
            OP_2DUP OP_GREATERTHANOREQUAL
            OP_IF
                OP_SUB 1
            OP_ELSE
                OP_DROP 0
            OP_ENDIF
            OP_ROT OP_DUP OP_ADD OP_ADD OP_SWAP
        }
        { 1u32 << 22 } OP_SUB OP_SWAP
        OP_FROMALTSTACK
        OP_IF 256 OP_ADD OP_ENDIF
    }
}

fn scalar_order() -> BigUint {
    (BigUint::one() << 252usize)
        + BigUint::parse_bytes(b"27742317777372353535851937790883648493", 10)
            .expect("scalar order parses")
}

fn g29_widths() -> Vec<usize> {
    [vec![8usize; 8], vec![9usize; 21]].concat()
}

fn g29_encoding_offset() -> BigUint {
    let widths = g29_widths();
    assert_eq!(widths.iter().sum::<usize>(), SCALAR_BITS);
    let mut offset = BigUint::zero();
    let mut bit_position = 0usize;
    for width in &widths[..widths.len() - 1] {
        offset += BigUint::one() << (bit_position + width - 1);
        bit_position += width;
    }
    assert_eq!(bit_position + widths[widths.len() - 1], SCALAR_BITS);
    offset
}

fn words_from_payload(payload: &BigUint) -> [u32; SCALAR_WORDS] {
    assert!((payload >> 256usize).is_zero());
    std::array::from_fn(|index| {
        ((payload >> (32 * index)) & BigUint::from(u32::MAX))
            .to_u32()
            .expect("masked scalar word fits u32")
    })
}

fn sentinel_scalar_fixture() -> (BigUint, BigUint, [u32; SCALAR_WORDS]) {
    let offset = g29_encoding_offset();
    let offset_low = (&offset & BigUint::from(u32::MAX))
        .to_u64()
        .expect("low offset word fits u64");
    let scalar_low = (0x8000_0000u64 + (1u64 << 32) - offset_low) & 0xffff_ffff;
    let scalar = BigUint::from(scalar_low);
    assert!(scalar < scalar_order());
    let payload = &offset + &scalar;
    assert!(payload.bits() <= SCALAR_BITS as u64);
    let words = words_from_payload(&payload);
    assert_eq!(words[0], 0x8000_0000);
    (scalar, payload, words)
}

fn metadata_chunks(payload: &BigUint) -> [u16; SCALAR_CARRIER_ITEMS] {
    let chunks = std::array::from_fn(|index| {
        ((payload >> (CARRIER_BITS * index)) & BigUint::from(0x1ffu32))
            .to_u16()
            .expect("nine-bit carrier chunk fits u16")
    });
    assert!(chunks[SCALAR_CARRIER_ITEMS - 1] < 2);
    for bit in SCALAR_BITS..CARRIED_BITS {
        assert!(((payload >> bit) & BigUint::one()).is_zero());
    }
    chunks
}

fn packet_value(index: usize) -> i64 {
    let packet = index / PACKET_ITEMS;
    match index % PACKET_ITEMS {
        0..=15 => 100_000 + index as i64,
        16 => -1_000_000 - packet as i64,
        17 => 1_000_000 + packet as i64,
        _ => unreachable!(),
    }
}

/// Selected challenge q positions, in scalar-bit order. The initial witness
/// stores response packets 0..28 below challenge packets 28..44. Taking the
/// globally topmost 29 challenge q items minimizes the deep restoration cost;
/// [`transpose_packet_blocks_after_scalar`] subsequently changes packet order
/// for execution.
fn selected_positions() -> [usize; SCALAR_CARRIER_ITEMS] {
    let mut positions = Vec::with_capacity(SCALAR_CARRIER_ITEMS);
    for packet in (RESPONSE_TRANSITIONS..TRANSITIONS).rev() {
        positions.push(packet * PACKET_ITEMS + 17);
        positions.push(packet * PACKET_ITEMS + 16);
    }
    positions.truncate(SCALAR_CARRIER_ITEMS);
    positions
        .try_into()
        .expect("exactly 29 selected q positions")
}

fn direct_layout() -> Vec<Vec<u8>> {
    (0..RAW_ENTRY_ITEMS)
        .map(|index| scriptnum_item(packet_value(index)))
        .collect()
}

fn carrier_witness(chunks: &[u16; SCALAR_CARRIER_ITEMS]) -> Vec<Vec<u8>> {
    let mut witness = direct_layout();
    for (chunk, position) in chunks.iter().zip(selected_positions()) {
        witness[position] = scriptnum_item(encode_carrier(*chunk, packet_value(position) as i32));
    }
    witness
}

/// Rotate a top item below `depth` existing items. Repeated fixed-depth rolls
/// preserve the intervening block's order.
fn insert_top_at_depth(depth: usize) -> Script {
    script! {
        for _ in 0..depth { { depth as u32 } OP_ROLL }
    }
}

#[derive(Clone, Copy, Debug)]
struct PackerState {
    global_bit: usize,
    byte_bit: usize,
    completed_bytes: usize,
    completed_words: usize,
}

impl PackerState {
    fn new() -> Self {
        Self {
            global_bit: 0,
            byte_bit: 0,
            completed_bytes: 0,
            completed_words: 0,
        }
    }

    /// Consume one u9 chunk. A low31 byte accumulator and up to three complete
    /// bytes live on altstack. A word completed in the middle of this chunk is
    /// rotated below its remaining chunk bits immediately.
    fn consume_chunk(&mut self) -> Script {
        let mut steps = vec![u31_to_bits_with_width(CARRIER_BITS as u32)];

        for chunk_bit in 0..CARRIER_BITS {
            if self.global_bit >= SCALAR_BITS {
                steps.push(script! { OP_NOT OP_VERIFY });
                self.global_bit += 1;
                continue;
            }

            let bit_offset = self.byte_bit;
            steps.push(script! {
                OP_FROMALTSTACK
                if bit_offset == 0 {
                    OP_ADD
                } else {
                    OP_SWAP
                    for _ in 0..bit_offset { OP_DUP OP_ADD }
                    OP_ADD
                }
            });
            self.global_bit += 1;
            self.byte_bit += 1;

            if self.byte_bit == 8 {
                steps.push(script! { OP_TOALTSTACK });
                self.byte_bit = 0;
                self.completed_bytes += 1;

                if self.completed_bytes == 4 {
                    let remaining_chunk_bits = CARRIER_BITS - chunk_bit - 1;
                    steps.push(script! {
                        for _ in 0..4 { OP_FROMALTSTACK }
                        { u32_compress() }
                        { insert_top_at_depth(remaining_chunk_bits) }
                        0 OP_TOALTSTACK
                    });
                    self.completed_bytes = 0;
                    self.completed_words += 1;
                } else {
                    steps.push(script! { 0 OP_TOALTSTACK });
                }
            } else {
                steps.push(script! { OP_TOALTSTACK });
            }
        }

        script! { for step in steps { { step } } }
    }

    fn finalize(mut self) -> Script {
        assert_eq!(self.global_bit, CARRIED_BITS);
        assert_eq!(self.completed_words, SCALAR_WORDS - 1);
        assert_eq!(self.completed_bytes, 3);
        assert_eq!(self.byte_bit, 5);
        self.completed_words += 1;
        script! {
            // The final partial byte already contains bits 248..252. Bits
            // 253..255 were independently required to be zero above.
            for _ in 0..4 { OP_FROMALTSTACK }
            { u32_compress() }
        }
    }
}

/// Restore the 29 selected challenge quotients in place while materializing
/// the certified eight-word G29 scalar payload above all 792 packet items.
/// This focused helper is `pub(crate)` for the whole-candidate linker; it is
/// not a stable library API.
pub(crate) fn scalar_router() -> Script {
    let mut state = PackerState::new();
    let positions = selected_positions();
    let decoder = decode_carrier_compact();
    let mut steps = vec![script! { 0 OP_TOALTSTACK }];

    for position in positions {
        let base_depth = RAW_ENTRY_ITEMS - 1 - position;
        let depth = base_depth + state.completed_words;
        let pack_chunk = state.consume_chunk();
        steps.push(script! {
            if depth != 0 { { depth as u32 } OP_ROLL }
            { decoder.clone() }
            // Park metadata while q is rotated back into its exact slot.
            OP_TOALTSTACK
            { insert_top_at_depth(depth) }
            OP_FROMALTSTACK
            { pack_chunk }
        });
    }
    steps.push(state.finalize());
    script! { for step in steps { { step } } }
}

/// Change `response_packets[504] | challenge_packets[288] | scalar[8]` into
/// `challenge_packets | response_packets | scalar`, preserving every item and
/// each block's internal order. Scalar words are temporarily parked so the
/// 504-item response block crosses only the 288 challenge items.
pub(crate) fn transpose_packet_blocks_after_scalar() -> Script {
    const RESPONSE_PACKET_ITEMS: usize = RESPONSE_TRANSITIONS * PACKET_ITEMS;
    const CHALLENGE_PACKET_ITEMS: usize = CHALLENGE_TRANSITIONS * PACKET_ITEMS;
    let depth = RESPONSE_PACKET_ITEMS + CHALLENGE_PACKET_ITEMS - 1;
    script! {
        for _ in 0..SCALAR_WORDS { OP_TOALTSTACK }
        for _ in 0..RESPONSE_PACKET_ITEMS { { depth as u32 } OP_ROLL }
        for _ in 0..SCALAR_WORDS { OP_FROMALTSTACK }
    }
}

fn raw_fragment_len(fragment: Script) -> usize {
    const COPIES: usize = 32;
    let repeated = script! {
        for _ in 0..COPIES { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % COPIES, 0);
    repeated.len() / COPIES
}

/// Add an unreachable branch so the centralized policy executes the real
/// router without running the optimizer on the large verification scaffold.
fn compile_strict_probe(body: Script) -> bitcoin::ScriptBuf {
    let probe = script! {
        { body }
        OP_0 OP_IF
            for _ in 0..17_000 { OP_0 OP_DROP }
        OP_ENDIF
    };
    let compiled = probe.compile_with_policy();
    assert!(compiled.len() > MAX_OPTIMIZER_INPUT_BYTES);
    compiled
}

fn verification_tail(expected_words: &[u32; SCALAR_WORDS]) -> Script {
    let initial = direct_layout();
    let response_items = RESPONSE_TRANSITIONS * PACKET_ITEMS;
    let expected_layout = [
        initial[response_items..].to_vec(),
        initial[..response_items].to_vec(),
    ]
    .concat();
    script! {
        // Exact byte equality proves canonical compressed-u32 output,
        // including the five-byte -2^31 sentinel.
        for word in expected_words.iter().rev() {
            { scriptnum_item(i64::from(*word as i32)) } OP_EQUALVERIFY
        }
        for item in expected_layout.iter().rev() {
            { item.clone() } OP_EQUALVERIFY
        }
        OP_1
    }
}

fn main() {
    assert_eq!(TRACE_ITEMS, 704);
    assert_eq!(Q_HINT_ITEMS, 88);
    assert_eq!(RAW_ENTRY_ITEMS, 792);
    assert_eq!(CARRIED_BITS, 261);
    assert_eq!(SPARE_BITS, 8);

    let (scalar, payload, expected_words) = sentinel_scalar_fixture();
    let chunks = metadata_chunks(&payload);
    let router = scalar_router();
    let router_raw_bytes = raw_fragment_len(router.clone());
    let transpose = transpose_packet_blocks_after_scalar();
    let transpose_raw_bytes = raw_fragment_len(transpose.clone());
    let router_and_transpose_raw_bytes = raw_fragment_len(script! {
        { router.clone() }
        { transpose.clone() }
    });
    let executable = compile_strict_probe(script! {
        { router.clone() }
        { transpose }
        { verification_tail(&expected_words) }
    });

    let witness = carrier_witness(&chunks);
    let witness_bytes = serialize(&Witness::from_slice(&witness)).len();
    let execution = execute_raw_script_with_inputs_strict(executable.to_bytes(), witness);
    assert!(
        execution.error.is_none(),
        "scalar carrier router: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);

    // Flip carried bit 253, the first of the eight mandatory zero bits.
    let mut invalid_chunks = chunks;
    invalid_chunks[SCALAR_BITS / CARRIER_BITS] |= 1 << (SCALAR_BITS % CARRIER_BITS);
    let invalid = execute_raw_script_with_inputs_strict(
        executable.to_bytes(),
        carrier_witness(&invalid_chunks),
    );
    assert!(invalid.error.is_some(), "nonzero spare bit was accepted");

    println!("model=ed25519_h16_scalar_carrier_router");
    println!("evidence=locally-reproduced");
    println!("execution_class=unclassified");
    println!("context=tapscript,strict_1000_item_stack,bitcoin-scriptexec");
    println!("boundary=full-item-accurate-synthetic-packet-router");
    println!("transitions={TRANSITIONS}");
    println!("trace_data_items={TRACE_ITEMS}");
    println!("logical_quotient_hint_items={Q_HINT_ITEMS}");
    println!("all_hints_coexist_at_entry=true");
    println!("separate_scalar_entry_items=0");
    println!("complete_entry_items={RAW_ENTRY_ITEMS}");
    println!("scalar_carrier_hint_items={SCALAR_CARRIER_ITEMS}");
    println!("scalar_carrier_bits={CARRIED_BITS}");
    println!("scalar_payload_bits={SCALAR_BITS}");
    println!("checked_zero_spare_bits={SPARE_BITS}");
    println!("scalar_output_word_items={SCALAR_WORDS}");
    println!("complete_output_items={}", RAW_ENTRY_ITEMS + SCALAR_WORDS);
    println!("router_raw_script_bytes={router_raw_bytes}");
    println!("packet_block_transpose_raw_script_bytes={transpose_raw_bytes}");
    println!("router_and_transpose_raw_script_bytes={router_and_transpose_raw_bytes}");
    println!("router_policy_optimization_skipped=true");
    println!("complete_synthetic_witness_bytes={witness_bytes}");
    println!(
        "strict_max_combined_stack_items={}",
        execution.stats.max_nb_stack_items
    );
    println!("entry_packet_order=response28_then_challenge16");
    println!("output_packet_order=challenge16_then_response28");
    println!("all_704_trace_items_preserved_in_phase_order=true");
    println!("all_88_q_items_restored_in_exact_slots=true");
    println!("scalar_words_match_exact_G29_C_plus_s_payload=true");
    println!("runtime_negative_2pow31_output_exercised=true");
    println!("nonzero_spare_bit_rejected=true");
    println!("fixture_scalar={scalar}");
    println!("long_scalar_hash_or_field_execution=false");
    println!("includes=fragment-only: full 792-item synthetic packet routing, 29 real signed23 carrier decodes, direct-q slot restoration, u9-to-eight-word scalar packing, eight zero-bit checks, and exact output-order checks; scalar validation, tables, arithmetic kernels, hash, and terminal signature predicate excluded");
}
