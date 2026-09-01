//! SHAKE256 with a fixed 1024-byte output.
//!
//! The implementation uses the byte-oriented u32 logic table already shared
//! by the other hash primitives. Keccak lanes are kept as eight individual
//! bytes in little-endian order, which makes absorbing and squeezing match the
//! FIPS 202 byte convention without a separate endian-conversion pass.

use crate::script::{script, Script};
use crate::u32::{
    u32_rrot::u8_extract_hbit,
    u32_std::u32_push,
    u32_xor::{u8_drop_xor_table, u8_push_xor_table, u8_xor},
};

/// Number of bytes returned by [`shake256`].
pub const OUTPUT_LEN: usize = 1024;

const RATE_BYTES: usize = 136;
const RATE_LANES: usize = RATE_BYTES / 8;
const STATE_LANES: usize = 25;

// Rotation offsets indexed by x + 5*y.
const RHO: [usize; STATE_LANES] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Hashes `num_bytes` byte-valued stack items with SHAKE256 and returns 1024
/// bytes.
///
/// The first message byte must be on top of the stack. The message length is
/// fixed when the script is generated and is limited to 511 bytes, matching
/// the other byte-oriented hash generators in this crate. The script consumes
/// the message and leaves the first output byte on top of the stack.
///
/// A 1024-byte result alone exceeds Bitcoin's 1,000-item combined stack limit.
/// Execute this primitive with [`crate::execute_script_without_stack_limit`]. A
/// consensus-compatible construction would need a specialized variant that
/// consumes squeeze blocks incrementally.
pub fn shake256(num_bytes: usize) -> Script {
    assert!(
        num_bytes < 512,
        "This SHAKE256 implementation supports messages shorter than 512 bytes"
    );

    let block_count = num_bytes / RATE_BYTES + 1;

    script! {
        { push_reverse_bytes_to_alt(num_bytes) }
        { u8_push_xor_table() }

        // State order is A[24] .. A[0], so lane zero and its least-significant
        // byte are at the top of the stack.
        for _ in 0..STATE_LANES {
            { push_u64(0) }
        }

        for block in 0..block_count {
            { absorb_block(num_bytes, block) }
            { keccak_f1600() }
        }

        { squeeze_1024() }
    }
}

fn push_reverse_bytes_to_alt(num_bytes: usize) -> Script {
    script! {
        for i in 1..=num_bytes {
            { num_bytes - i }
            OP_ROLL
            OP_TOALTSTACK
        }
    }
}

fn push_u64(value: u64) -> Script {
    script! {
        { u32_push((value >> 32) as u32) }
        { u32_push(value as u32) }
    }
}

/// Copies a lane while preserving its big-endian stack-item layout. `depth`
/// counts complete u64 lanes from the top.
fn copy_lane(depth: usize) -> Script {
    script! {
        for _ in 0..8 {
            { depth * 8 + 7 }
            OP_PICK
        }
    }
}

fn lane_to_altstack() -> Script {
    script! {
        for _ in 0..8 {
            OP_TOALTSTACK
        }
    }
}

fn lane_from_altstack() -> Script {
    script! {
        for _ in 0..8 {
            OP_FROMALTSTACK
        }
    }
}

fn drop_lane() -> Script {
    script! {
        for _ in 0..4 {
            OP_2DROP
        }
    }
}

/// Replaces `dropped` lanes with the `kept` lanes currently above them.
fn keep_top_lanes(kept: usize, dropped: usize) -> Script {
    script! {
        for _ in 0..kept {
            { lane_to_altstack() }
        }
        for _ in 0..dropped {
            { drop_lane() }
        }
        for _ in 0..kept {
            { lane_from_altstack() }
        }
    }
}

/// XORs the top two lanes, replacing them with their XOR.
///
/// `items_above_table` is the number of byte items above the shared u8 table
/// before the operation begins.
fn xor_top_lanes(items_above_table: usize) -> Script {
    script! {
        // Build the result most-significant byte first so byte zero finishes
        // at the top of the lane.
        for output_index in 0..8 {
            { 15 } OP_PICK
            { 8 } OP_PICK
            { u8_xor((items_above_table + output_index + 2) as u32) }
        }
        { keep_top_bytes(8, 16) }
    }
}

/// ANDs the top two lanes, replacing them with their bitwise AND.
fn and_top_lanes(items_above_table: usize) -> Script {
    script! {
        for output_index in 0..8 {
            { 15 } OP_PICK
            { 8 } OP_PICK
            { crate::u32::u32_and::u8_and(
                (items_above_table + output_index + 2) as u32
            ) }
        }
        { keep_top_bytes(8, 16) }
    }
}

fn keep_top_bytes(kept: usize, dropped: usize) -> Script {
    script! {
        for _ in 0..kept {
            OP_TOALTSTACK
        }
        for _ in 0..(dropped / 2) {
            OP_2DROP
        }
        if dropped % 2 != 0 {
            OP_DROP
        }
        for _ in 0..kept {
            OP_FROMALTSTACK
        }
    }
}

fn not_top_lane() -> Script {
    script! {
        for _ in 0..8 {
            { 7 }
            OP_PICK
            255
            OP_SWAP
            OP_SUB
        }
        { keep_top_bytes(8, 8) }
    }
}

/// Rotates the top lane left. Keccak's lane convention is little endian, while
/// the eight byte items are arranged with the least-significant byte on top.
fn rotate_top_lane_left(rotation: usize) -> Script {
    let rotation = rotation % 64;
    let byte_rotation = rotation / 8;
    let bit_rotation = rotation % 8;

    script! {
        // Produce byte significances 7 down to 0.
        for output_index in 0..8 {
            { ((7 - output_index + 8 - byte_rotation) % 8) + output_index }
            OP_PICK

            if bit_rotation != 0 {
                { u8_extract_hbit(bit_rotation) }
                // Keep (low_source << bit_rotation) mod 256.
                OP_DROP

                { ((7 - output_index + 15 - byte_rotation) % 8) + output_index + 1 }
                OP_PICK
                { u8_extract_hbit(bit_rotation) }
                // Keep high_source >> (8 - bit_rotation).
                OP_SWAP
                OP_DROP
                OP_ADD
            }
        }
        { keep_top_bytes(8, 8) }
    }
}

/// Copies and XORs lanes at the supplied depths. All depths are relative to
/// the stack before this helper starts, and exactly one result lane is added.
fn xor_copied_lanes(depths: &[usize], lanes_before: usize) -> Script {
    assert!(!depths.is_empty());
    script! {
        { copy_lane(depths[0]) }
        for depth in depths.iter().skip(1) {
            { copy_lane(depth + 1) }
            { xor_top_lanes((lanes_before + 2) * 8) }
        }
    }
}

fn absorb_block(num_bytes: usize, block: usize) -> Script {
    let block_start = block * RATE_BYTES;
    let block_end = block_start + RATE_BYTES;

    script! {
        // Append the block as I[0] .. I[16]. The byte reversal after each lane
        // gives every lane the same layout as push_u64.
        for position in block_start..block_end {
            if position < num_bytes {
                OP_FROMALTSTACK
            } else if position == num_bytes && position == block_end - 1 {
                // delimited suffix and final pad bit share the last rate byte
                { 0x9f }
            } else if position == num_bytes {
                { 0x1f }
            } else if position == block_end - 1 {
                { 0x80 }
            } else {
                OP_0
            }

            if position % 8 == 7 {
                for depth in 1..8 {
                    { depth }
                    OP_ROLL
                }
            }
        }

        // Derive a fresh state above the old state and input block. Results are
        // generated in reverse so A[0] is on top when all 25 are present.
        for lane in (0..STATE_LANES).rev() {
            if lane < RATE_LANES {
                {
                    xor_copied_lanes(
                        &[
                            STATE_LANES - 1 - lane + RATE_LANES + lane,
                            STATE_LANES - 1 - lane + RATE_LANES - 1 - lane,
                        ],
                        STATE_LANES + RATE_LANES + STATE_LANES - 1 - lane,
                    )
                }
            } else {
                { copy_lane(STATE_LANES - 1 - lane + RATE_LANES + lane) }
            }
        }
        { keep_top_lanes(STATE_LANES, STATE_LANES + RATE_LANES) }
    }
}

fn keccak_f1600() -> Script {
    script! {
        for round_constant in ROUND_CONSTANTS {
            { theta() }
            { rho_and_pi() }
            { chi() }

            // Iota only changes A[0], already the top lane.
            { push_u64(round_constant) }
            { xor_top_lanes((STATE_LANES + 1) * 8) }
        }
    }
}

fn theta() -> Script {
    script! {
        // C[x] = XOR_y A[x,y], produced as C[4] .. C[0].
        for x in (0..5).rev() {
            {
                xor_copied_lanes(
                    &[
                        4,
                        9,
                        14,
                        19,
                        24,
                    ],
                    STATE_LANES + 4 - x,
                )
            }
        }

        // D[x] = C[x-1] XOR ROTL1(C[x+1]), produced as D[4] .. D[0].
        for x in (0..5).rev() {
            { copy_lane(4 - x + (x + 1) % 5) }
            { rotate_top_lane_left(1) }
            { copy_lane(4 - x + (x + 4) % 5 + 1) }
            { xor_top_lanes((STATE_LANES + 5 + 4 - x + 2) * 8) }
        }

        // A[x,y] ^= D[x].
        for lane in (0..STATE_LANES).rev() {
            {
                xor_copied_lanes(
                    &[
                        STATE_LANES - 1 - lane + 10 + lane,
                        STATE_LANES - 1 - lane + lane % 5,
                    ],
                    STATE_LANES + 10 + STATE_LANES - 1 - lane,
                )
            }
        }

        { keep_top_lanes(STATE_LANES, STATE_LANES + 10) }
    }
}

fn rho_and_pi() -> Script {
    let mut source_for_output = [0usize; STATE_LANES];
    for y in 0..5 {
        for x in 0..5 {
            let source = x + 5 * y;
            let destination = y + 5 * ((2 * x + 3 * y) % 5);
            source_for_output[destination] = source;
        }
    }

    script! {
        for destination in (0..STATE_LANES).rev() {
            { copy_lane(STATE_LANES - 1 - destination + source_for_output[destination]) }
            { rotate_top_lane_left(RHO[source_for_output[destination]]) }
        }
        { keep_top_lanes(STATE_LANES, STATE_LANES) }
    }
}

fn chi() -> Script {
    script! {
        for lane in (0..STATE_LANES).rev() {
            // A[x] XOR ((NOT A[x+1]) AND A[x+2]).
            { copy_lane(STATE_LANES - 1) }
            {
                copy_lane(
                    STATE_LANES - 1 - lane + lane - lane % 5 + (lane % 5 + 1) % 5 + 1
                )
            }
            { not_top_lane() }
            {
                copy_lane(
                    STATE_LANES - 1 - lane + lane - lane % 5 + (lane % 5 + 2) % 5 + 2
                )
            }
            { and_top_lanes((STATE_LANES + STATE_LANES - 1 - lane + 3) * 8) }
            { xor_top_lanes((STATE_LANES + STATE_LANES - 1 - lane + 2) * 8) }
        }
        { keep_top_lanes(STATE_LANES, STATE_LANES) }
    }
}

fn squeeze_1024() -> Script {
    script! {
        for block in 0..OUTPUT_LEN.div_ceil(RATE_BYTES) {
            // Copy in reverse so the first byte of this chunk is on top.
            for _ in 0..(OUTPUT_LEN - block * RATE_BYTES).min(RATE_BYTES) {
                { (OUTPUT_LEN - block * RATE_BYTES).min(RATE_BYTES) - 1 }
                OP_PICK
            }
            for _ in 0..(OUTPUT_LEN - block * RATE_BYTES).min(RATE_BYTES) {
                OP_TOALTSTACK
            }

            if block * RATE_BYTES
                + (OUTPUT_LEN - block * RATE_BYTES).min(RATE_BYTES)
                < OUTPUT_LEN
            {
                { keccak_f1600() }
            }
        }

        for _ in 0..STATE_LANES {
            { drop_lane() }
        }
        { u8_drop_xor_table() }

        for _ in 0..OUTPUT_LEN {
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{execute_script_without_stack_limit, u32::u32_xor::u8_push_xor_table};

    fn push_message(message: &[u8]) -> Script {
        script! {
            for byte in message.iter().rev() {
                { *byte }
            }
        }
    }

    fn reference_keccak_f1600(state: &mut [u64; STATE_LANES]) {
        for round_constant in ROUND_CONSTANTS {
            let mut c = [0u64; 5];
            for x in 0..5 {
                c[x] = (0..5).fold(0, |parity, y| parity ^ state[x + 5 * y]);
            }
            let d =
                std::array::from_fn::<_, 5, _>(|x| c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1));
            for y in 0..5 {
                for x in 0..5 {
                    state[x + 5 * y] ^= d[x];
                }
            }

            let mut b = [0u64; STATE_LANES];
            for y in 0..5 {
                for x in 0..5 {
                    let source = x + 5 * y;
                    b[y + 5 * ((2 * x + 3 * y) % 5)] =
                        state[source].rotate_left(RHO[source] as u32);
                }
            }
            for y in 0..5 {
                for x in 0..5 {
                    state[x + 5 * y] =
                        b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
                }
            }
            state[0] ^= round_constant;
        }
    }

    fn reference_shake256(message: &[u8]) -> [u8; OUTPUT_LEN] {
        let mut state = [0u64; STATE_LANES];
        let mut blocks = message.chunks_exact(RATE_BYTES);

        for block in &mut blocks {
            for (index, byte) in block.iter().enumerate() {
                state[index / 8] ^= (*byte as u64) << (8 * (index % 8));
            }
            reference_keccak_f1600(&mut state);
        }

        let tail = blocks.remainder();
        for (index, byte) in tail.iter().enumerate() {
            state[index / 8] ^= (*byte as u64) << (8 * (index % 8));
        }
        state[tail.len() / 8] ^= 0x1fu64 << (8 * (tail.len() % 8));
        state[(RATE_BYTES - 1) / 8] ^= 0x80u64 << (8 * ((RATE_BYTES - 1) % 8));
        reference_keccak_f1600(&mut state);

        let mut output = [0u8; OUTPUT_LEN];
        let output_blocks = OUTPUT_LEN.div_ceil(RATE_BYTES);
        for (block, chunk) in output.chunks_mut(RATE_BYTES).enumerate() {
            for (index, byte) in chunk.iter_mut().enumerate() {
                *byte = (state[index / 8] >> (8 * (index % 8))) as u8;
            }
            if block + 1 < output_blocks {
                reference_keccak_f1600(&mut state);
            }
        }
        output
    }

    fn scriptnum_byte(byte: u8) -> Vec<u8> {
        let mut encoded = [0u8; 8];
        let len = bitcoin::script::write_scriptint(&mut encoded, byte as i64);
        encoded[..len].to_vec()
    }

    #[test]
    fn lane_rotation_matches_rust() {
        let value = 0x0123_4567_89ab_cdefu64;
        for rotation in RHO {
            let expected = value.rotate_left(rotation as u32).to_le_bytes();
            let result = execute_script_without_stack_limit(script! {
                { push_u64(value) }
                { rotate_top_lane_left(rotation) }
                for byte in expected {
                    { byte }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            });
            assert!(result.success, "rotation {rotation}: {result}");
        }
    }

    #[test]
    fn lane_logic_matches_rust() {
        let a = 0x0123_4567_89ab_cdefu64;
        let b = 0xfedc_ba98_7654_3210u64;
        let expected = (a ^ b).to_le_bytes();
        let result = execute_script_without_stack_limit(script! {
            { u8_push_xor_table() }
            { push_u64(a) }
            { push_u64(b) }
            { xor_top_lanes(16) }
            for byte in expected {
                { byte }
                OP_EQUALVERIFY
            }
            { u8_drop_xor_table() }
            OP_TRUE
        });
        assert!(result.success, "{result}");
    }

    #[test]
    fn hashes_standard_vectors_to_1024_bytes() {
        let messages = [vec![], b"abc".to_vec(), vec![0xa5; RATE_BYTES]];

        for message in messages {
            let expected = reference_shake256(&message);
            // Anchor the independent reference against the published prefix of
            // the FIPS 202 empty-message vector.
            if message.is_empty() {
                assert_eq!(
                    &expected[..8],
                    &[0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13]
                );
            }

            let result = execute_script_without_stack_limit(script! {
                { push_message(&message) }
                { shake256(message.len()) }
            });

            assert!(result.error.is_none(), "len {}: {result}", message.len());
            assert_eq!(result.final_stack.len(), OUTPUT_LEN);
            for (index, expected_byte) in expected.into_iter().enumerate() {
                assert_eq!(
                    result.final_stack.get(OUTPUT_LEN - 1 - index),
                    scriptnum_byte(expected_byte),
                    "message length {}, output byte {index}",
                    message.len(),
                );
            }
        }
    }

    #[test]
    fn rejects_unsupported_message_length() {
        assert!(std::panic::catch_unwind(|| shake256(512)).is_err());
    }
}
