//! SHA-1 implemented over the byte-oriented u32 stack representation.

use crate::arithmetic::u32::{
    add::u32_add_drop,
    and::u32_and,
    or::u32_or,
    rotate::u32_rrot,
    stack::{u32_drop, u32_fromaltstack, u32_pick, u32_push, u32_roll, u32_toaltstack},
    xor::{u32_xor, u8_drop_xor_table, u8_push_xor_table},
};
use crate::support::script::{script, Script};
use crate::support::script_ops::push_to_stack;

const INITIAL_STATE: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

/// Hashes `num_bytes` byte-valued stack items with SHA-1.
///
/// The first message byte must be on top of the stack. The message length is
/// fixed when the script is generated and is limited to 511 bytes, matching
/// the length encoding used by the existing byte-oriented SHA-256 generator.
/// The script consumes the message and leaves the 20 digest bytes on the
/// stack, with the first digest byte on top.
pub fn sha1(num_bytes: usize) -> Script {
    assert!(
        num_bytes < 512,
        "This SHA-1 implementation supports messages shorter than 512 bytes"
    );

    let mut block_count = num_bytes / 64 + 1;
    if num_bytes % 64 > 55 {
        block_count += 1;
    }

    script! {
        { push_reverse_bytes_to_alt(num_bytes) }
        { u8_push_xor_table() }
        { padding_add_roll(num_bytes) }
        { sha1_init() }

        for block in 0..block_count {
            { sha1_transform((block_count - block) * 16) }
        }

        { sha1_final() }
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
        { u32_push(0) }
        { u32_push((num_bytes as u32) * 8) }

        for i in 1..word_count {
            { u32_roll(i as u32) }
        }
    }
}

fn sha1_init() -> Vec<Script> {
    INITIAL_STATE
        .iter()
        .rev()
        .map(|word| u32_push(*word))
        .collect()
}

fn sha1_final() -> Script {
    script! {
        for _ in 0..5 {
            OP_SWAP
            OP_2SWAP
            OP_SWAP
            { u32_toaltstack() }
        }
        for _ in 0..5 {
            { u32_fromaltstack() }
        }
    }
}

/// Compresses the top 64-byte block into the five-word SHA-1 state.
///
/// `message_words` is the number of padded message words above the lookup
/// table when the transform starts, including the current block.
fn sha1_transform(message_words: usize) -> Script {
    let scheduled_words = message_words + 64;
    let round_words = scheduled_words + 5;

    script! {
        // Preserve the input chaining state while expanding the current block.
        for _ in 0..5 {
            { u32_toaltstack() }
        }

        { extend_schedule(message_words) }

        // Restore the state, then save a second copy for feed-forward.
        for _ in 0..5 {
            { u32_fromaltstack() }
        }
        for _ in 0..5 {
            { u32_pick(4) }
        }
        for _ in 0..5 {
            { u32_toaltstack() }
        }

        // The working state is [e, d, c, b, a], with a on top.
        for t in 0..80 {
            { sha1_round(t, round_words) }
        }

        // Add the working variables back into the chaining state.
        for _ in 0..5 {
            { u32_fromaltstack() }
        }
        for i in 0..5 {
            { u32_roll(5 - i) }
            { u32_add_drop(0, 1) }
            { u32_toaltstack() }
        }

        for _ in 0..80 {
            { u32_drop() }
        }
        for _ in 0..5 {
            { u32_fromaltstack() }
        }
    }
}

fn sha1_round(round: usize, words_above_table: usize) -> Script {
    script! {
        if round < 20 {
            { choice(words_above_table) }
        } else if !(40..60).contains(&round) {
            { parity(words_above_table) }
        } else {
            { majority(words_above_table) }
        }

        { u32_pick(1) }
        { u32_rrot(27) } // ROL5(a)
        { u32_add_drop(0, 1) }

        { u32_push(round_constant(round)) }
        { u32_add_drop(0, 1) }

        // The temporary word above the state shifts W[t] down by one.
        { u32_pick((85 - round) as u32) }
        { u32_add_drop(0, 1) }

        { u32_pick(5) } // e
        { u32_add_drop(0, 1) }

        // [temp, a, b, c, d, e] -> [temp, a, ROL30(b), c, d].
        { u32_roll(2) }
        { u32_rrot(2) } // ROL30(b)
        { u32_roll(5) }
        { u32_drop() }
        { u32_roll(2) }
        { u32_roll(2) }
    }
}

fn extend_schedule(message_words: usize) -> Script {
    script! {
        // Put W[0] at the bottom and W[15] at the top of this block's schedule.
        for i in 1..16 {
            { u32_roll(i) }
        }

        // W[t] = ROL1(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]).
        for t in 16..80 {
            { u32_pick(2) }
            { u32_pick(8) }
            { xor_top_drop(message_words + t - 16 + 2) }

            { u32_pick(14) }
            { xor_top_drop(message_words + t - 16 + 2) }

            { u32_pick(16) }
            { xor_top_drop(message_words + t - 16 + 2) }
            { u32_rrot(31) }
        }
    }
}

const fn round_constant(round: usize) -> u32 {
    match round {
        0..=19 => 0x5a82_7999,
        20..=39 => 0x6ed9_eba1,
        40..=59 => 0x8f1b_bcdc,
        60..=79 => 0xca62_c1d6,
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

// d ^ (b & (c ^ d))
fn choice(words_above_table: usize) -> Script {
    script! {
        { u32_pick(2) } // c
        { u32_pick(4) } // d
        { xor_top_drop(words_above_table + 2) }

        { u32_pick(2) } // b
        { and_top_drop(words_above_table + 2) }

        { u32_pick(4) } // d
        { xor_top_drop(words_above_table + 2) }
    }
}

fn parity(words_above_table: usize) -> Script {
    script! {
        { u32_pick(1) } // b
        { u32_pick(3) } // c
        { xor_top_drop(words_above_table + 2) }

        { u32_pick(4) } // d
        { xor_top_drop(words_above_table + 2) }
    }
}

// (b & c) | (d & (b | c))
fn majority(words_above_table: usize) -> Script {
    script! {
        { u32_pick(1) } // b
        { u32_pick(3) } // c
        { and_top_drop(words_above_table + 2) }

        { u32_pick(2) } // b
        { u32_pick(4) } // c
        { or_top_drop(words_above_table + 3) }

        { u32_pick(5) } // d
        { and_top_drop(words_above_table + 3) }
        { or_top_drop(words_above_table + 2) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::u32::stack::{u32_equal, u32_push};
    use bitcoin::hashes::{sha1 as reference_sha1, Hash};

    fn push_message(message: &[u8]) -> Script {
        script! {
            for byte in message.iter().rev() {
                { *byte }
            }
        }
    }

    fn verify_digest(message: &[u8]) {
        let expected = reference_sha1::Hash::hash(message).to_byte_array();
        let result = crate::support::execution::execute_script_without_stack_limit(script! {
            { push_message(message) }
            { sha1(message.len()) }
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
        let words = 85usize;

        for (function, expected) in [
            (choice(words), d ^ (b & (c ^ d))),
            (parity(words), b ^ c ^ d),
            (majority(words), (b & c) | (d & (b | c))),
        ] {
            let result = crate::support::execution::execute_script_without_stack_limit(script! {
                { u8_push_xor_table() }
                for _ in 0..80 {
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
    fn message_schedule_matches_reference() {
        let mut expected = [0u32; 80];
        expected[0] = 0x8000_0000;
        for t in 16..80 {
            expected[t] = (expected[t - 3] ^ expected[t - 8] ^ expected[t - 14] ^ expected[t - 16])
                .rotate_left(1);
        }

        let result = crate::support::execution::execute_script_without_stack_limit(script! {
            { u8_push_xor_table() }
            for word in expected[..16].iter().rev() {
                { u32_push(*word) }
            }
            { extend_schedule(16) }
            for word in expected.iter().rev() {
                { u32_push(*word) }
                { crate::arithmetic::u32::stack::u32_equalverify() }
            }
            { u8_drop_xor_table() }
            OP_TRUE
        });
        assert!(result.success, "{result}");
    }

    #[test]
    fn single_round_matches_reference() {
        let schedule = [0u32; 80];
        let a = INITIAL_STATE[0];
        let b = INITIAL_STATE[1];
        let c = INITIAL_STATE[2];
        let d = INITIAL_STATE[3];
        let e = INITIAL_STATE[4];
        let next = [
            a.rotate_left(5)
                .wrapping_add(d ^ (b & (c ^ d)))
                .wrapping_add(e)
                .wrapping_add(round_constant(0))
                .wrapping_add(schedule[0]),
            a,
            b.rotate_left(30),
            c,
            d,
        ];

        let result = crate::support::execution::execute_script_without_stack_limit(script! {
            { u8_push_xor_table() }
            for word in schedule {
                { u32_push(word) }
            }
            { u32_push(e) }
            { u32_push(d) }
            { u32_push(c) }
            { u32_push(b) }
            { u32_push(a) }
            { sha1_round(0, 85) }
            for word in next {
                { u32_push(word) }
                { crate::arithmetic::u32::stack::u32_equalverify() }
            }
            for _ in 0..80 {
                { u32_drop() }
            }
            { u8_drop_xor_table() }
            OP_TRUE
        });
        assert!(result.success, "{result}");
    }

    #[test]
    fn hashes_standard_vectors() {
        verify_digest(b"");
        verify_digest(b"abc");
        verify_digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        verify_digest(&[0x42; 80]);
        verify_digest(&[0x24; 130]);
    }

    #[test]
    fn rejects_unsupported_message_length() {
        let panic = std::panic::catch_unwind(|| sha1(512));
        assert!(panic.is_err());
    }

    #[test]
    fn prints_default_script_size() {
        println!("sha1(32): {} bytes", sha1(32).len());
    }
}
