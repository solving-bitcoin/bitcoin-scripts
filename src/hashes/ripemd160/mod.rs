//! RIPEMD-160 implemented over the byte-oriented u32 stack representation.

use crate::pseudo::push_to_stack;
use crate::treepp::{script, Script};
use crate::u32::{
    u32_add::u32_add_drop,
    u32_and::u32_and,
    u32_or::u32_or,
    u32_rrot::u32_rrot,
    u32_std::{u32_drop, u32_fromaltstack, u32_pick, u32_push, u32_roll, u32_toaltstack},
    u32_xor::{u32_xor, u8_drop_xor_table, u8_push_xor_table},
};

const INITIAL_STATE: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

const LEFT_MESSAGE_ORDER: [usize; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5,
    2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4,
    13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];

const RIGHT_MESSAGE_ORDER: [usize; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12,
    4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5,
    12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];

const LEFT_ROTATIONS: [usize; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15,
    9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14,
    15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];

const RIGHT_ROTATIONS: [usize; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12,
    7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14,
    6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

/// Hashes `num_bytes` byte-valued stack items with RIPEMD-160.
///
/// The first message byte must be on top of the stack. The message length is
/// fixed when the script is generated and is limited to 511 bytes, matching
/// the other byte-oriented hash generators. The script consumes the message
/// and leaves the 20 digest bytes on the stack, with the first digest byte on
/// top.
pub fn ripemd160(num_bytes: usize) -> Script {
    assert!(
        num_bytes < 512,
        "This RIPEMD-160 implementation supports messages shorter than 512 bytes"
    );

    let mut block_count = num_bytes / 64 + 1;
    if num_bytes % 64 > 55 {
        block_count += 1;
    }

    script! {
        { push_reverse_bytes_to_alt(num_bytes) }
        { u8_push_xor_table() }
        { padding_add_roll(num_bytes) }
        { ripemd160_init() }

        for block in 0..block_count {
            { ripemd160_transform((block_count - block) * 16) }
        }

        for _ in 0..5 {
            { u32_toaltstack() }
        }
        { u8_drop_xor_table() }
        for _ in 0..5 {
            { u32_fromaltstack() }
        }
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

fn padding_add_roll(num_bytes: usize) -> Script {
    let padding_bytes = if num_bytes % 64 < 56 {
        55 - num_bytes % 64
    } else {
        119 - num_bytes % 64
    };
    let word_count = (num_bytes + padding_bytes + 9) / 4;

    script! {
        for _ in 0..num_bytes {
            OP_FROMALTSTACK
        }
        0x80
        { push_to_stack(0, padding_bytes) }

        // RIPEMD-160 encodes the bit length least-significant word first.
        // The byte swap prepares these values for the per-word reversal below.
        { u32_push(((num_bytes as u32) * 8).swap_bytes()) }
        { u32_push(0) }

        // Interpret every four input bytes as a little-endian u32.
        for _ in 0..word_count {
            OP_SWAP
            OP_2SWAP
            OP_SWAP
            { u32_toaltstack() }
        }
        for _ in 0..word_count {
            { u32_fromaltstack() }
        }

        // Leave the first word of the first unprocessed block on top.
        for i in 1..word_count {
            { u32_roll(i as u32) }
        }
    }
}

fn ripemd160_init() -> Vec<Script> {
    INITIAL_STATE
        .iter()
        .rev()
        .map(|word| u32_push(*word))
        .collect()
}

/// Compresses the top 64-byte block into the five-word RIPEMD-160 state.
fn ripemd160_transform(message_words: usize) -> Script {
    script! {
        // Preserve the chaining state for the crosswise feed-forward step.
        for _ in 0..5 {
            { u32_pick(4) }
        }
        for _ in 0..5 {
            { u32_toaltstack() }
        }

        // Keep a second state on the main stack for the parallel branch.
        for _ in 0..5 {
            { u32_pick(4) }
        }

        // Left branch: five working words plus the untouched right branch.
        for round in 0..80 {
            { ripemd160_round(round, false, message_words + 10) }
        }

        // Save the left result, exposing the right branch state.
        for _ in 0..5 {
            { u32_toaltstack() }
        }

        for round in 0..80 {
            { ripemd160_round(round, true, message_words + 5) }
        }

        // Restore the left result and then the original chaining state.
        for _ in 0..5 {
            { u32_fromaltstack() }
        }
        for _ in 0..5 {
            { u32_fromaltstack() }
        }

        // new h0 = old h1 + left c + right d
        { combine_word(1, 7, 13) }
        // new h1 = old h2 + left d + right e
        { combine_word(2, 8, 14) }
        // new h2 = old h3 + left e + right a
        { combine_word(3, 9, 10) }
        // new h3 = old h4 + left a + right b
        { combine_word(4, 5, 11) }
        // new h4 = old h0 + left b + right c
        { combine_word(0, 6, 12) }

        for _ in 0..15 {
            { u32_drop() }
        }
        for _ in 0..16 {
            { u32_drop() }
        }
        for _ in 0..5 {
            { u32_fromaltstack() }
        }
    }
}

fn combine_word(first: u32, second: u32, third: u32) -> Script {
    script! {
        { u32_pick(first) }
        { u32_pick(second + 1) }
        { u32_add_drop(0, 1) }
        { u32_pick(third + 1) }
        { u32_add_drop(0, 1) }
        { u32_toaltstack() }
    }
}

fn ripemd160_round(round: usize, parallel: bool, words_above_table: usize) -> Script {
    let message_index = if parallel {
        RIGHT_MESSAGE_ORDER[round]
    } else {
        LEFT_MESSAGE_ORDER[round]
    };
    let rotation = if parallel {
        RIGHT_ROTATIONS[round]
    } else {
        LEFT_ROTATIONS[round]
    };
    let message_depth = if parallel { 6 } else { 11 };

    script! {
        { round_function(round, parallel, words_above_table) }

        { u32_pick(1) } // a
        { u32_add_drop(0, 1) }

        { u32_pick((message_depth + message_index) as u32) }
        { u32_add_drop(0, 1) }

        { u32_push(round_constant(round, parallel)) }
        { u32_add_drop(0, 1) }

        { u32_rrot(32 - rotation) }
        { u32_pick(5) } // e
        { u32_add_drop(0, 1) }

        // [temp, a, b, c, d, e] -> [e, temp, b, ROL10(c), d].
        { u32_roll(1) }
        { u32_drop() }
        { u32_roll(2) }
        { u32_rrot(22) }
        { u32_roll(4) }
        { u32_toaltstack() }
        { u32_roll(2) }
        { u32_roll(2) }
        { u32_fromaltstack() }
    }
}

const fn round_constant(round: usize, parallel: bool) -> u32 {
    let phase = round / 16;
    if parallel {
        [
            0x50a2_8be6,
            0x5c4d_d124,
            0x6d70_3ef3,
            0x7a6d_76e9,
            0x0000_0000,
        ][phase]
    } else {
        [
            0x0000_0000,
            0x5a82_7999,
            0x6ed9_eba1,
            0x8f1b_bcdc,
            0xa953_fd4e,
        ][phase]
    }
}

fn round_function(round: usize, parallel: bool, words_above_table: usize) -> Script {
    let phase = round / 16;
    let function = if parallel { 4 - phase } else { phase };
    match function {
        0 => parity(words_above_table),
        1 => choice(words_above_table),
        2 => choose_not_c(words_above_table),
        3 => choose_by_d(words_above_table),
        4 => xor_with_or_not_d(words_above_table),
        _ => unreachable!(),
    }
}

// Each bitwise primitive preserves its first input. These wrappers consume
// that preserved copy so their stack contract is simply (x, y) -> op(x, y).
fn xor_top_drop(words_above_table: usize) -> Script {
    script! {
        { u32_xor(0, 1, words_above_table as u32 + 1) }
        { u32_toaltstack() }
        { u32_drop() }
        { u32_fromaltstack() }
    }
}

fn and_top_drop(words_above_table: usize) -> Script {
    script! {
        { u32_and(0, 1, words_above_table as u32 + 1) }
        { u32_toaltstack() }
        { u32_drop() }
        { u32_fromaltstack() }
    }
}

fn or_top_drop(words_above_table: usize) -> Script {
    script! {
        { u32_or(0, 1, words_above_table as u32 + 1) }
        { u32_toaltstack() }
        { u32_drop() }
        { u32_fromaltstack() }
    }
}

fn not_top() -> Script {
    script! {
        for _ in 0..4 {
            0xff
            4
            OP_ROLL
            OP_SUB
        }
    }
}

// b ^ c ^ d
fn parity(words_above_table: usize) -> Script {
    script! {
        { u32_pick(1) }
        { u32_pick(3) }
        { xor_top_drop(words_above_table + 2) }
        { u32_pick(4) }
        { xor_top_drop(words_above_table + 2) }
    }
}

// (b & c) | (!b & d) = d ^ (b & (c ^ d))
fn choice(words_above_table: usize) -> Script {
    script! {
        { u32_pick(2) }
        { u32_pick(4) }
        { xor_top_drop(words_above_table + 2) }
        { u32_pick(2) }
        { and_top_drop(words_above_table + 2) }
        { u32_pick(4) }
        { xor_top_drop(words_above_table + 2) }
    }
}

// (b | !c) ^ d
fn choose_not_c(words_above_table: usize) -> Script {
    script! {
        { u32_pick(1) }
        { u32_pick(3) }
        { not_top() }
        { or_top_drop(words_above_table + 2) }
        { u32_pick(4) }
        { xor_top_drop(words_above_table + 2) }
    }
}

// (b & d) | (c & !d) = c ^ (d & (b ^ c))
fn choose_by_d(words_above_table: usize) -> Script {
    script! {
        { u32_pick(1) }
        { u32_pick(3) }
        { xor_top_drop(words_above_table + 2) }
        { u32_pick(4) }
        { and_top_drop(words_above_table + 2) }
        { u32_pick(3) }
        { xor_top_drop(words_above_table + 2) }
    }
}

// b ^ (c | !d)
fn xor_with_or_not_d(words_above_table: usize) -> Script {
    script! {
        { u32_pick(2) }
        { u32_pick(4) }
        { not_top() }
        { or_top_drop(words_above_table + 2) }
        { u32_pick(2) }
        { xor_top_drop(words_above_table + 2) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::u32::u32_std::{u32_equal, u32_push};
    use bitcoin::hashes::{ripemd160 as reference_ripemd160, Hash};

    fn push_message(message: &[u8]) -> Script {
        script! {
            for byte in message.iter().rev() {
                { *byte }
            }
        }
    }

    fn verify_digest(message: &[u8]) {
        let expected = reference_ripemd160::Hash::hash(message).to_byte_array();
        let result = crate::execute_script_without_stack_limit(script! {
            { push_message(message) }
            { ripemd160(message.len()) }
            for byte in expected {
                { byte }
                OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(result.success, "{result}");
    }

    #[test]
    fn round_functions_match_reference() {
        let a = 0x0123_4567u32;
        let b = 0x89ab_cdefu32;
        let c = 0xfedc_ba98u32;
        let d = 0x7654_3210u32;
        let e = 0x0f1e_2d3cu32;
        let words = 21usize;

        for (function, expected) in [
            (parity(words), b ^ c ^ d),
            (choice(words), (b & c) | (!b & d)),
            (choose_not_c(words), (b | !c) ^ d),
            (choose_by_d(words), (b & d) | (c & !d)),
            (xor_with_or_not_d(words), b ^ (c | !d)),
        ] {
            let result = crate::execute_script_without_stack_limit(script! {
                { u8_push_xor_table() }
                for _ in 0..16 {
                    { u32_push(0) }
                }
                { u32_push(e) }
                { u32_push(d) }
                { u32_push(c) }
                { u32_push(b) }
                { u32_push(a) }
                { function }
                { u32_push(expected) }
                { u32_equal() }
                OP_TOALTSTACK
                for _ in 0..words {
                    { u32_drop() }
                }
                { u8_drop_xor_table() }
                OP_FROMALTSTACK
            });
            assert!(result.success, "{result}");
        }
    }

    #[test]
    fn hashes_standard_vectors() {
        verify_digest(b"");
        verify_digest(b"abc");
        verify_digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        verify_digest(b"The quick brown fox jumps over the lazy dog");
        verify_digest(&[0xff; 64]);
        verify_digest(&[0x42; 80]);
        verify_digest(&[0x24; 130]);
    }

    #[test]
    fn rejects_unsupported_message_length() {
        let panic = std::panic::catch_unwind(|| ripemd160(512));
        assert!(panic.is_err());
    }

    #[test]
    fn prints_default_script_size() {
        println!("ripemd160(32): {} bytes", ripemd160(32).len());
    }
}
