//! Generation-only BLAKE3 transcript experiments for a custom Ed25519-style
//! signature verifier. These are intentionally not part of the stable hash
//! API and do not turn the surrounding construction into RFC 8032 Ed25519.

use std::collections::HashMap;

use bitcoin_script_stack::stack::StackTracker;

use super::Script;
use crate::{
    arithmetic::bigint::U256,
    fields::ed25519::u5_balanced_table,
    hashes::blake3::utils::{
        compress, compress_mixed, get_flags_for_block, CompressionMessageWord, TablesVars,
    },
    support::script::*,
};

const DIGITS_PER_HALF: u32 = 64;
const HOST_IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];
const HOST_MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

fn host_g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(x);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(y);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn host_round(state: &mut [u32; 16], message: &[u32; 16]) {
    host_g(state, 0, 4, 8, 12, message[0], message[1]);
    host_g(state, 1, 5, 9, 13, message[2], message[3]);
    host_g(state, 2, 6, 10, 14, message[4], message[5]);
    host_g(state, 3, 7, 11, 15, message[6], message[7]);
    host_g(state, 0, 5, 10, 15, message[8], message[9]);
    host_g(state, 1, 6, 11, 12, message[10], message[11]);
    host_g(state, 2, 7, 8, 13, message[12], message[13]);
    host_g(state, 3, 4, 9, 14, message[14], message[15]);
}

fn host_compress_cv(cv: [u32; 8], block: &[u8; 64], flags: u32) -> [u32; 8] {
    let mut message = std::array::from_fn(|index| {
        u32::from_le_bytes(block[4 * index..4 * index + 4].try_into().unwrap())
    });
    let mut state = [
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7], HOST_IV[0], HOST_IV[1], HOST_IV[2],
        HOST_IV[3], 0, 0, 64, flags,
    ];
    for round in 0..7 {
        host_round(&mut state, &message);
        if round != 6 {
            message = std::array::from_fn(|index| message[HOST_MSG_PERMUTATION[index]]);
        }
    }
    std::array::from_fn(|index| state[index] ^ state[index + 8])
}

/// Internal BLAKE3 chaining value after the fixed first block `D32 || A32`.
pub fn fixed_prefix_cv(domain: [u8; 32], public_key: [u8; 32]) -> [u32; 8] {
    let mut block = [0_u8; 64];
    block[..32].copy_from_slice(&domain);
    block[32..].copy_from_slice(&public_key);
    host_compress_cv(HOST_IV, &block, 1)
}

fn stage_half(stack: &mut StackTracker, park_on_altstack: bool, certify: bool) {
    stack.custom(
        script! {
            if certify { { U256::verify_bigint_on_stack_with_limb_size(4) } }
            if park_on_altstack {
                for _ in 0..DIGITS_PER_HALF { OP_TOALTSTACK }
            }
        },
        1,
        false,
        0,
        if certify {
            "certify and stage fixed-transcript half"
        } else {
            "stage caller-certified fixed-transcript half"
        },
    );
}

fn certify_half(stack: &mut StackTracker, park_on_altstack: bool) {
    stage_half(stack, park_on_altstack, true);
}

/// The packed XOR backend uses `OP_DEPTH` to address lookup memory and
/// therefore requires its tables to be the bottom of the main stack.  Park a
/// preserved prefix while constructing the tables, then restore it above
/// them.  The prefix remains on the combined main/alt stack throughout.
fn tables_below_preserved(stack: &mut StackTracker, preserved_items: u32) -> TablesVars {
    if preserved_items != 0 {
        stack.to_altstack();
    }
    let tables = TablesVars::new(stack, true);
    if preserved_items != 0 {
        stack.from_altstack();
    }
    tables
}

/// Temporarily park the preserved prefix above the digest already on the alt
/// stack, drop the now-exposed tables, then restore the prefix.  The caller
/// can subsequently restore the digest above it.
fn drop_tables_below_preserved(
    stack: &mut StackTracker,
    tables: &TablesVars,
    preserved_items: u32,
) {
    if preserved_items != 0 {
        stack.to_altstack();
    }
    tables.drop(stack);
    if preserved_items != 0 {
        stack.from_altstack();
    }
}

/// BLAKE3 backend order for one 32-byte transcript half: four-byte words in
/// increasing order, bytes within each word in reverse order, and each byte's
/// high nibble before its low nibble.
pub fn transcript_half_u4(bytes: &[u8; 32]) -> Vec<u8> {
    bytes
        .chunks_exact(4)
        .flat_map(|word| word.iter().rev())
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .collect()
}

/// Bind and consume the 64 hostile u4 items for a fixed 32-byte transcript
/// suffix.  Input is `preserved | fixed_message_u4`, bottom to top; output is
/// only `preserved`.  The surrounding carrier must certify the items as
/// canonical u4 values if raw-byte canonicality matters.  This fragment adds
/// no witness hints.
pub fn bind_and_drop_fixed_message(message: [u8; 32]) -> Script {
    let nibbles = transcript_half_u4(&message);
    Script::new("bind and drop fixed Ed25519 BLAKE3 message").push_script(
        script! {
            for nibble in nibbles.iter().rev() {
                { *nibble } OP_NUMEQUALVERIFY
            }
        }
        .compile_with_policy(),
    )
}

// Split the non-negative remainder at one known bit. The extracted bit is
// left below the reduced remainder so consecutive calls accumulate bits from
// most to least significant.
fn extract_known_bit_immediate(bit: u32) -> Script {
    assert!((4..=30).contains(&bit));
    script! {
        OP_DUP { (1u32 << bit) - 1 } OP_GREATERTHAN
        OP_SWAP OP_OVER
        OP_IF { 1u32 << bit } OP_SUB OP_ENDIF
    }
}

// Reusing the expensive bit-16 through bit-30 thresholds across all eight
// packed words is 96 policy bytes smaller than pushing each threshold at every
// extraction. These are 30 script constants, not witness hints, and are
// removed before the BLAKE3 fragment starts.
const PACKED_R_THRESHOLD_LOW_BIT: u32 = 16;
const PACKED_R_THRESHOLD_TABLE_ITEMS: u32 = 2 * (31 - PACKED_R_THRESHOLD_LOW_BIT);

fn push_packed_r_threshold_table() -> Script {
    script! {
        for bit in (PACKED_R_THRESHOLD_LOW_BIT..=30).rev() {
            { (1u32 << bit) - 1 }
            { 1u32 << bit }
        }
    }
}

// `items_above_table` includes the current non-negative remainder. The table
// lies below all converted nibbles and the current word, so every lookup depth
// is determined at generation time.
fn extract_known_bit_with_threshold_table(bit: u32, items_above_table: u32) -> Script {
    if bit < PACKED_R_THRESHOLD_LOW_BIT {
        return extract_known_bit_immediate(bit);
    }
    assert!(bit <= 30);
    let pair_index_from_bottom = 2 * (30 - bit);
    let minus_one_from_top = PACKED_R_THRESHOLD_TABLE_ITEMS - 1 - pair_index_from_bottom;
    let power_from_top = minus_one_from_top - 1;
    let minus_one_depth = items_above_table + 1 + minus_one_from_top;
    let power_depth = items_above_table + 1 + power_from_top;
    script! {
        OP_DUP { minus_one_depth } OP_PICK OP_GREATERTHAN
        OP_SWAP OP_OVER
        OP_IF { power_depth } OP_PICK OP_SUB OP_ENDIF
    }
}

// Consume high-to-low bits accumulated below a remainder, combine them into
// one nibble, and restore the remainder above it.
fn combine_bits_below_remainder(bit_count: usize) -> Script {
    assert!((3..=4).contains(&bit_count));
    script! {
        OP_TOALTSTACK
        for _ in 0..bit_count { OP_TOALTSTACK }
        OP_FROMALTSTACK
        for _ in 1..bit_count {
            OP_DUP OP_ADD OP_FROMALTSTACK OP_ADD
        }
        OP_FROMALTSTACK
    }
}

/// Duplicate one caller-certified compressed-u32 item into BLAKE3's eight-u4
/// word layout. The original item is not consumed. Five-byte input is assumed
/// to be the unique canonical `-2^31` sentinel; every other certified word is
/// an at-most-four-byte ScriptNum.
fn duplicate_certified_compressed_word_as_u4(word: u32) -> Script {
    let prior_outputs = 8 * word;
    let mut completed_nibbles = 0u32;
    let mut pending_bits = 1u32;
    let mut body = Script::new("table-backed packed-word split").push_script(
        script! {
            // Convert the signed compressed representation to
            // `bit31 | low31` without constructing 2^32 in Script arithmetic.
            OP_SIZE 5 OP_NUMEQUAL
            OP_IF
                OP_DROP 1 0
            OP_ELSE
                OP_DUP 0 OP_LESSTHAN
                OP_IF
                    { 0x7fff_ffffu32 } OP_ADD OP_1ADD
                    1 OP_SWAP
                OP_ELSE
                    0 OP_SWAP
                OP_ENDIF
            OP_ENDIF
        }
        .compile_with_policy(),
    );

    // bit31 plus bits 30..28 form the high nibble. Each following group of
    // four bits forms one nibble; the final remainder is nibble zero.
    for bit in (28..=30u32).rev() {
        let items_above_table = prior_outputs + completed_nibbles + pending_bits + 1;
        body = body.push_script(
            extract_known_bit_with_threshold_table(bit, items_above_table).compile_with_policy(),
        );
        pending_bits += 1;
    }
    body = body.push_script(combine_bits_below_remainder(4).compile_with_policy());
    pending_bits = 0;
    completed_nibbles += 1;

    for high_bit in [27u32, 23, 19, 15, 11, 7] {
        for bit in (high_bit - 3..=high_bit).rev() {
            let items_above_table = prior_outputs + completed_nibbles + pending_bits + 1;
            body = body.push_script(
                extract_known_bit_with_threshold_table(bit, items_above_table)
                    .compile_with_policy(),
            );
            pending_bits += 1;
        }
        body = body.push_script(combine_bits_below_remainder(4).compile_with_policy());
        pending_bits = 0;
        completed_nibbles += 1;
    }
    debug_assert_eq!(completed_nibbles, 7);
    body
}

/// Copy eight caller-certified packed Ed25519 words at a fixed prefix depth
/// into the 64-u4 layout consumed by the BLAKE3 backend.
///
/// `word0_depth` is the initial depth of word zero; words seven through zero
/// are contiguous, with word zero nearest the top of their block. The complete
/// prefix remains byte-for-byte unchanged and `R32_u4[0..64]` is appended.
/// This conversion adds no witness hints.
fn duplicate_certified_packed_r_as_u4(word0_depth: u32) -> Script {
    script! {
        { push_packed_r_threshold_table() }
        for word in 0..8u32 {
            // Each completed word adds eight nibbles above the original block;
            // the lower-index originals also remain above the selected word.
            { word0_depth + PACKED_R_THRESHOLD_TABLE_ITEMS + 9 * word } OP_PICK
            { duplicate_certified_compressed_word_as_u4(word) }
        }

        // Remove the script-resident thresholds before entering BLAKE3. This
        // leaves precisely `preserved | R32_u4` and empties the altstack.
        for _ in 0..64 { OP_TOALTSTACK }
        for _ in 0..PACKED_R_THRESHOLD_TABLE_ITEMS / 2 { OP_2DROP }
        for _ in 0..64 { OP_FROMALTSTACK }
    }
}

fn move_block_to_top(block_items: usize, items_above: usize) -> Script {
    if block_items == 0 || items_above == 0 {
        return Script::new("no-op block move");
    }
    let depth = block_items + items_above - 1;
    script! {
        for _ in 0..block_items { { depth as u32 } OP_ROLL }
    }
}

fn u5_bits_from_altstack_to_number(width: usize) -> Script {
    script! {
        OP_FROMALTSTACK
        for _ in 1..width { OP_DUP OP_ADD OP_FROMALTSTACK OP_ADD }
    }
}

/// Split a certified five-bit digit into `high quotient | low remainder`.
fn split_certified_u5_digit(low_bits: usize) -> Script {
    assert!((1..=4).contains(&low_bits));
    let high_bits = 5 - low_bits;
    script! {
        for bit in (low_bits..5).rev() {
            OP_DUP { (1u32 << bit) - 1 } OP_GREATERTHAN
            OP_SWAP OP_OVER
            OP_IF { 1u32 << bit } OP_SUB OP_ENDIF
        }
        OP_TOALTSTACK
        for _ in 0..high_bits { OP_TOALTSTACK }
        { u5_bits_from_altstack_to_number(high_bits) }
        OP_FROMALTSTACK
    }
}

/// Convert one copied public-order canonical radix-32 block (`d50..d0`, with
/// d0 nearest top) to BLAKE3's 64-u4 order.
fn copied_canonical_u5_r_to_u4() -> Script {
    let mut carry_bits = 0usize;
    let mut steps = Vec::new();
    for _ in 0..u5_balanced_table::FIELD_DIGIT_COUNT {
        if carry_bits != 0 {
            steps.push(script! { OP_SWAP });
        }
        let low_bits = 4 - carry_bits;
        steps.push(split_certified_u5_digit(low_bits));
        steps.push(script! { OP_TOALTSTACK });
        if carry_bits != 0 {
            steps.push(script! { OP_SWAP });
        }
        steps.push(script! {
            OP_FROMALTSTACK
            for _ in 0..carry_bits { OP_DUP OP_ADD }
            if carry_bits != 0 { OP_ADD }
            OP_TOALTSTACK
        });
        carry_bits += 1;
        if carry_bits == 4 {
            steps.push(script! { OP_TOALTSTACK });
            carry_bits = 0;
        }
    }
    assert_eq!(carry_bits, 3);
    steps.push(script! { OP_TOALTSTACK });
    steps.push(script! { for _ in 0..DIGITS_PER_HALF { OP_FROMALTSTACK } });

    // Reverse eight word blocks while retaining high-to-low nibble order
    // within each word, matching `transcript_half_u4` exactly.
    for block_depth in 1..8usize {
        steps.push(move_block_to_top(8, 8 * block_depth));
    }
    script! { for step in steps { { step } } }
}

/// Certify all 51 original biased radix-32 digits, including the 19-value
/// canonical gap below 2^255, and append an exact BLAKE3-ordered u4 copy.
/// Every original digit remains byte-for-byte untouched.
pub fn duplicate_canonical_u5_r_as_u4(r_digit0_depth: u32) -> Script {
    script! {
        { u5_balanced_table::certify_value_at_depth(r_digit0_depth) }
        // Copy d50 first through d0. Each appended copy raises the remaining
        // originals by one, so this source depth stays invariant.
        for _ in 0..u5_balanced_table::FIELD_DIGIT_COUNT {
            { r_digit0_depth + u5_balanced_table::FIELD_DIGIT_COUNT as u32 - 1 } OP_PICK
        }
        { copied_canonical_u5_r_to_u4() }
    }
}

/// Consume exactly three checked u4 half-blocks for `R || A || M32`.
///
/// The bottom-to-top group order is `M32 | R | A`; each group contains 64
/// nibbles in the same semantic order expected by the generic BLAKE3 backend.
/// Unlike the generic 96-byte API, no fourth, ignored padding group exists.
pub fn compute_script() -> Script {
    let mut stack = StackTracker::new();
    stack.define(DIGITS_PER_HALF, "block1-message");
    stack.define(DIGITS_PER_HALF, "block0-low-half");
    stack.define(DIGITS_PER_HALF, "block0-high-half");

    for _ in 0..3 {
        stack.to_altstack();
    }
    stack.custom(
        script! { OP_DEPTH 0 OP_EQUALVERIFY },
        0,
        false,
        0,
        "require exact transcript input",
    );
    let tables = TablesVars::new(&mut stack, true);
    for _ in 0..3 {
        stack.from_altstack();
    }

    // Full first block: R || A.
    certify_half(&mut stack, true);
    certify_half(&mut stack, false);
    stack.custom(
        script! { for _ in 0..DIGITS_PER_HALF { OP_FROMALTSTACK } },
        0,
        false,
        0,
        "restore first-block high half",
    );
    let mut first_message = HashMap::new();
    for index in 0..16_u8 {
        first_message.insert(index, stack.define(8, &format!("block0-word-{index}")));
    }
    compress(
        &mut stack,
        false,
        0,
        64,
        get_flags_for_block(0, 2),
        first_message,
        &tables,
        8,
        false,
        false,
    );
    for _ in 0..8 {
        let top = stack.get_var_from_stack(0);
        stack.drop(top);
    }

    // Sparse final block: only M32's eight words are materialized. Missing
    // words are compile-time zero padding in `compress`.
    certify_half(&mut stack, false);
    let mut second_message = HashMap::new();
    for index in 0..8_u8 {
        second_message.insert(index, stack.define(8, &format!("block1-word-{index}")));
    }
    compress(
        &mut stack,
        true,
        0,
        32,
        get_flags_for_block(1, 2),
        second_message,
        &tables,
        8,
        true,
        false,
    );
    for _ in 0..8 {
        let top = stack.get_var_from_stack(0);
        stack.drop(top);
    }
    tables.drop(&mut stack);
    stack.from_altstack_joined(64, "challenge-digest");

    Script::new("experimental fixed Ed25519 BLAKE3 challenge")
        .push_script(stack.get_script().compile_with_policy())
}

/// One-on-chain-compression custom challenge
/// `BLAKE3(D32 || A32 || R32 || M32)` for fixed `D32,A32`.
///
/// The first block's non-root chaining value is embedded by the generator.
/// Input is exactly 128 checked u4 items, bottom-to-top `R32 | M32`. This is
/// circuit data, not witness hints: the auxiliary hint count is exactly zero.
pub fn key_specialized_compute_script(domain: [u8; 32], public_key: [u8; 32]) -> Script {
    key_specialized_compute_script_preserving(domain, public_key, 0)
}

/// Variant of [`key_specialized_compute_script`] that leaves an unrelated
/// main-stack prefix untouched. The complete input is
/// `preserved | R32 | M32`, bottom to top, and the output is
/// `preserved | challenge_digest`.
///
/// `R32` and `M32` remain circuit data rather than witness hints. This
/// fragment therefore requires exactly zero auxiliary hint items regardless
/// of `preserved_items`.
pub fn key_specialized_compute_script_preserving(
    domain: [u8; 32],
    public_key: [u8; 32],
    preserved_items: u32,
) -> Script {
    let prefix_cv = fixed_prefix_cv(domain, public_key);
    let mut stack = StackTracker::new();
    if preserved_items != 0 {
        stack.define(preserved_items, "preserved");
    }
    stack.define(DIGITS_PER_HALF, "R32");
    stack.define(DIGITS_PER_HALF, "M32");

    stack.to_altstack();
    stack.to_altstack();
    stack.custom(
        script! { OP_DEPTH { preserved_items } OP_EQUALVERIFY },
        0,
        false,
        0,
        "require exact variable transcript plus preserved input",
    );
    let tables = tables_below_preserved(&mut stack, preserved_items);
    stack.from_altstack();
    stack.from_altstack();

    certify_half(&mut stack, true);
    certify_half(&mut stack, false);
    stack.custom(
        script! { for _ in 0..DIGITS_PER_HALF { OP_FROMALTSTACK } },
        0,
        false,
        0,
        "restore M32",
    );
    let mut message = HashMap::new();
    for index in 0..16_u8 {
        message.insert(index, stack.define(8, &format!("variable-word-{index}")));
    }

    // Match the exact altstack layout emitted by a preceding non-final
    // compression: word zero must be popped first by `init_state`.
    for word in prefix_cv.into_iter().rev() {
        let digits = stack.number_u32(word);
        stack.explode(digits);
        for _ in 0..8 {
            stack.to_altstack();
        }
    }
    compress(
        &mut stack, true, 0, 64, 0b1010, message, &tables, 8, true, false,
    );
    for _ in 0..8 {
        let top = stack.get_var_from_stack(0);
        stack.drop(top);
    }
    drop_tables_below_preserved(&mut stack, &tables, preserved_items);
    stack.from_altstack_joined(64, "challenge-digest");

    Script::new("experimental key-specialized Ed25519 BLAKE3 challenge")
        .push_script(stack.get_script().compile_with_policy())
}

/// Four-word variant of [`key_specialized_compute_script_preserving`].
///
/// This computes the same ordinary BLAKE3 transcript but materializes only
/// digest words 0..=3, i.e. the first 128 output bits in BLAKE3's standard
/// little-endian byte encoding. The input remains exactly 128 checked u4
/// items (`preserved | R32 | M32`) and the auxiliary hint count remains zero.
/// It leaves 32 u4 challenge items above the untouched prefix.
pub fn key_specialized_compute_script_preserving_truncated_128(
    domain: [u8; 32],
    public_key: [u8; 32],
    preserved_items: u32,
) -> Script {
    key_specialized_truncated_128_inner(domain, public_key, preserved_items, true)
}

/// Trusted-input counterpart of
/// [`key_specialized_compute_script_preserving_truncated_128`].
///
/// The caller must already have proved that all 128 transcript items are
/// integers in `0..16`, as the quotient/packed-field carrier decoder does.
/// This fragment does not repeat those checks. It still enforces exact input
/// depth and requires exactly zero auxiliary witness hints.
pub fn key_specialized_compute_script_preserving_truncated_128_certified_inputs(
    domain: [u8; 32],
    public_key: [u8; 32],
    preserved_items: u32,
) -> Script {
    key_specialized_truncated_128_inner(domain, public_key, preserved_items, false)
}

/// Fixed-message counterpart of
/// [`key_specialized_compute_script_preserving_truncated_128_certified_inputs`].
///
/// The fixed 32-byte `M` suffix is compiled directly into the BLAKE3 additions
/// instead of being materialized on the Script stack.  Complete input is
/// `preserved | R32_u4` (64 caller-certified u4 items); complete output is
/// `preserved | low128_digest_u4` (32 items), with no M32 witness carrier. If a
/// surrounding protocol separately accepts hostile M32 carrier values, it must
/// bind and consume them with [`bind_and_drop_fixed_message`] (or an equivalent
/// check) before this boundary. Both fragments require exactly zero auxiliary
/// witness hints.
pub fn key_specialized_compute_script_preserving_truncated_128_fixed_message(
    domain: [u8; 32],
    public_key: [u8; 32],
    message: [u8; 32],
    preserved_items: u32,
) -> Script {
    let prefix_cv = fixed_prefix_cv(domain, public_key);
    let mut stack = StackTracker::new();
    if preserved_items != 0 {
        stack.define(preserved_items, "preserved");
    }
    stack.define(DIGITS_PER_HALF, "R32");

    stack.to_altstack();
    stack.custom(
        script! { OP_DEPTH { preserved_items } OP_EQUALVERIFY },
        0,
        false,
        0,
        "require exact R32 plus preserved input",
    );
    let tables = tables_below_preserved(&mut stack, preserved_items);
    stack.from_altstack();

    // R32 has already been certified by the compact transcript unpacker.
    stage_half(&mut stack, false, false);
    let mut compression_message = HashMap::new();
    for index in 0..8_u8 {
        compression_message.insert(
            index,
            CompressionMessageWord::Dynamic(stack.define(8, &format!("R32-word-{index}"))),
        );
    }
    for (index, bytes) in message.chunks_exact(4).enumerate() {
        compression_message.insert(
            8 + index as u8,
            CompressionMessageWord::Constant(u32::from_le_bytes(bytes.try_into().unwrap())),
        );
    }

    // Match the exact altstack layout emitted by the fixed first-block
    // compression: word zero must be restored first by `init_state`.
    for word in prefix_cv.into_iter().rev() {
        let digits = stack.number_u32(word);
        stack.explode(digits);
        for _ in 0..8 {
            stack.to_altstack();
        }
    }
    compress_mixed(
        &mut stack,
        true,
        0,
        64,
        0b1010,
        compression_message,
        &tables,
        4,
        true,
        false,
    );
    for _ in 0..12 {
        let top = stack.get_var_from_stack(0);
        stack.drop(top);
    }
    drop_tables_below_preserved(&mut stack, &tables, preserved_items);
    stack.from_altstack_joined(32, "challenge-low-128");

    Script::new("experimental fixed-message truncated Ed25519 BLAKE3 challenge")
        .push_script(stack.get_script().compile_with_policy())
}

/// Fixed-message low-128 BLAKE3 boundary that deep-copies eight packed words
/// from an untouched future slope-transition packet.
///
/// Complete input is exactly `preserved_items`; complete output is the same
/// prefix followed by `low128_digest_u4`. Within the prefix, `r_word0_depth`
/// gives the initial depth of `Rword[0]`, and `Rword[7] .. Rword[0]` must be a
/// contiguous block. The helper duplicates them into BLAKE3's word-low-to-
/// high, byte-high-to-low, high-nibble-before-low layout and invokes the
/// standard fixed-message compressor above. Every original prefix item,
/// including the eight source words, remains byte-for-byte unchanged.
///
/// This is deliberately a caller-certified interface. It does not check raw
/// compressed-u32 canonicality, the packed field's bit-255 padding, or its
/// 19-value canonical gap. The surrounding slope transition must later
/// certify these same untouched packet items. The helper requires exactly zero
/// auxiliary witness hints.
pub fn key_specialized_compute_script_preserving_truncated_128_fixed_message_from_certified_packed_r(
    domain: [u8; 32],
    public_key: [u8; 32],
    message: [u8; 32],
    preserved_items: u32,
    r_word0_depth: u32,
) -> Script {
    assert!(
        r_word0_depth
            .checked_add(8)
            .is_some_and(|end| end <= preserved_items),
        "packed R block must lie inside the preserved prefix"
    );
    let conversion = Script::new("duplicate certified packed R as BLAKE3 u4")
        .push_script(duplicate_certified_packed_r_as_u4(r_word0_depth).compile_with_policy());
    let hash = key_specialized_compute_script_preserving_truncated_128_fixed_message(
        domain,
        public_key,
        message,
        preserved_items,
    );
    // The combined boundary is larger than the centralized 32 KiB cutoff, so
    // policy compilation is intentionally CompileOptions::NONE. Do not apply a
    // second, out-of-policy fixed-point optimizer pass to this wrapper.
    Script::new("experimental packed-R fixed-message Ed25519 BLAKE3 challenge").push_script(
        script! {
            { conversion }
            { hash }
        }
        .compile_with_policy(),
    )
}

/// Fixed-message low-128 BLAKE3 boundary for a final slope packet whose R
/// coordinate is already represented as 51 biased radix-32 digits.
///
/// Complete input is exactly `preserved_items`; complete output is that same
/// prefix followed by `low128_digest_u4`. `r_digit0_depth` is the initial
/// depth of digit zero, the topmost item of the contiguous public-order
/// `d50..d0` block. The helper enforces every digit in `[0,31]` and the
/// Ed25519 field's 19-value canonical gap, duplicates and repacks the certified
/// originals into BLAKE3 u4 order, and leaves all 51 original items unchanged
/// for the later final slope transition. It requires exactly zero auxiliary
/// witness hints.
pub fn key_specialized_compute_script_preserving_truncated_128_fixed_message_from_canonical_u5_r(
    domain: [u8; 32],
    public_key: [u8; 32],
    message: [u8; 32],
    preserved_items: u32,
    r_digit0_depth: u32,
) -> Script {
    assert!(
        r_digit0_depth
            .checked_add(u5_balanced_table::FIELD_DIGIT_COUNT as u32)
            .is_some_and(|end| end <= preserved_items),
        "canonical u5 R block must lie inside the preserved prefix"
    );
    let conversion = Script::new("certify and duplicate canonical u5 R as BLAKE3 u4")
        .push_script(duplicate_canonical_u5_r_as_u4(r_digit0_depth).compile_with_policy());
    let hash = key_specialized_compute_script_preserving_truncated_128_fixed_message(
        domain,
        public_key,
        message,
        preserved_items,
    );
    // The combined boundary is larger than the centralized 32 KiB cutoff, so
    // policy compilation is intentionally CompileOptions::NONE. Do not apply a
    // second, out-of-policy fixed-point optimizer pass to this wrapper.
    Script::new("experimental canonical-u5-R fixed-message Ed25519 BLAKE3 challenge").push_script(
        script! {
            { conversion }
            { hash }
        }
        .compile_with_policy(),
    )
}

fn key_specialized_truncated_128_inner(
    domain: [u8; 32],
    public_key: [u8; 32],
    preserved_items: u32,
    certify_inputs: bool,
) -> Script {
    let prefix_cv = fixed_prefix_cv(domain, public_key);
    let mut stack = StackTracker::new();
    if preserved_items != 0 {
        stack.define(preserved_items, "preserved");
    }
    stack.define(DIGITS_PER_HALF, "R32");
    stack.define(DIGITS_PER_HALF, "M32");

    stack.to_altstack();
    stack.to_altstack();
    stack.custom(
        script! { OP_DEPTH { preserved_items } OP_EQUALVERIFY },
        0,
        false,
        0,
        "require exact variable transcript plus preserved input",
    );
    let tables = tables_below_preserved(&mut stack, preserved_items);
    stack.from_altstack();
    stack.from_altstack();

    stage_half(&mut stack, true, certify_inputs);
    stage_half(&mut stack, false, certify_inputs);
    stack.custom(
        script! { for _ in 0..DIGITS_PER_HALF { OP_FROMALTSTACK } },
        0,
        false,
        0,
        "restore M32",
    );
    let mut message = HashMap::new();
    for index in 0..16_u8 {
        message.insert(index, stack.define(8, &format!("variable-word-{index}")));
    }

    for word in prefix_cv.into_iter().rev() {
        let digits = stack.number_u32(word);
        stack.explode(digits);
        for _ in 0..8 {
            stack.to_altstack();
        }
    }
    // Only words 0..=3 of the root output are needed by the 128-bit scalar
    // schedule. The other half of the output is never materialized.
    compress(
        &mut stack, true, 0, 64, 0b1010, message, &tables, 4, true, false,
    );
    // Four low state words were consumed while producing the truncated root;
    // discard the twelve unused state words that remain.
    for _ in 0..12 {
        let top = stack.get_var_from_stack(0);
        stack.drop(top);
    }
    drop_tables_below_preserved(&mut stack, &tables, preserved_items);
    stack.from_altstack_joined(32, "challenge-low-128");

    Script::new("experimental key-specialized truncated Ed25519 BLAKE3 challenge")
        .push_script(stack.get_script().compile_with_policy())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_prefix_cv_reconstructs_standard_128_byte_blake3() {
        let domain = std::array::from_fn(|index| index as u8);
        let public_key = std::array::from_fn(|index| (index as u8).wrapping_mul(3));
        let r = std::array::from_fn(|index| (index as u8).wrapping_mul(5));
        let message = std::array::from_fn(|index| (index as u8).wrapping_mul(7));
        let mut second_block = [0_u8; 64];
        second_block[..32].copy_from_slice(&r);
        second_block[32..].copy_from_slice(&message);
        let digest_words = host_compress_cv(fixed_prefix_cv(domain, public_key), &second_block, 10);
        let digest = digest_words.map(u32::to_le_bytes).concat();

        let transcript = [domain, public_key, r, message].concat();
        assert_eq!(digest, blake3::hash(&transcript).as_bytes());
    }
}
