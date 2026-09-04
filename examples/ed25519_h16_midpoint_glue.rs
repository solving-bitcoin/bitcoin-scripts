//! Exact midpoint glue for the 44-transition Ed25519 Montgomery H16 model.
//!
//! This example strictly executes two short, real Script fragments while
//! deliberately avoiding the BLAKE3 compression and multi-megabyte scalar
//! multiplication:
//!
//! 1. Twenty-eight compact carrier chunks hold `Rtilde32 || M32` plus one
//!    forced-zero spare bit.  The chunks have widths
//!    `21,20,20,20,18x24`, low bit first across chunks.  The unpacker rejects
//!    non-canonical, negative, and out-of-range ScriptNums, rejects the spare
//!    bit, enforces the packed-field padding bit and 19-value canonical gap,
//!    preserves `Rtilde` as eight canonical compressed-u32 words, and emits
//!    128 caller-certified u4 items in the exact order consumed by the
//!    key-specialized BLAKE3 fragment.
//! 2. Thirty-two certified u4 items containing BLAKE3's first 128 output bits
//!    are streamed into sixteen independent signed bytes `e_i=byte_i-127`.
//!    Each output pair is `negative | magnitude`, so the high group's selector
//!    is on top, and every selector is in `0..=128`. The older carry-centered
//!    recoder remains below as an exact comparison helper.
//!
//! Both fragments require exactly zero auxiliary witness hints.  The compact
//! chunks and hash nibbles are circuit data recovered from existing quotient
//! carriers/BLAKE3 state, not new hints.  The strict composition probes retain
//! the H16 midpoint prefixes: 288 future packets plus a 41-item current state
//! below the unpacker, and those 329 items plus the eight `Rtilde` words below
//! the hash-output recoder.

use bitcoin::{consensus::encode::serialize, script::Instruction, Witness};
use bitcoin_lab::{
    arithmetic::{u31::u31_to_bits_with_width, u32::stack::u32_compress},
    fields::ed25519::{u5_balanced_table, u5_packed},
    hashes::blake3::blake3_push_message_script_with_limb,
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
    },
};
use num_bigint::BigUint;

const CHUNK_WIDTHS: [usize; 28] = [
    21, 20, 20, 20, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18,
];
const CHUNK_ITEMS: usize = CHUNK_WIDTHS.len();
const TRANSCRIPT_BITS: usize = 512;
const CARRIED_BITS: usize = 513;
const TRANSCRIPT_BYTES: usize = 64;
const TRANSCRIPT_NIBBLES: usize = 128;
const RTILDE_BYTES: usize = 32;
const RTILDE_WORDS: usize = 8;
const DIGEST_BYTES: usize = 16;
const DIGEST_NIBBLES: usize = 32;
const CHALLENGE_GROUPS: usize = 16;
const FUTURE_PACKET_ITEMS: usize = 16 * 18;
const CURRENT_STATE_ITEMS: usize = 41;
const UNPACK_PRESERVED_ITEMS: usize = FUTURE_PACKET_ITEMS + CURRENT_STATE_ITEMS;
const RECODER_PRESERVED_ITEMS: usize = UNPACK_PRESERVED_ITEMS + RTILDE_WORDS;

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

fn policy_precompiled(fragment: Script, name: &'static str) -> Script {
    Script::new(name).push_script(fragment.compile_with_policy())
}

/// Move a contiguous block across `items_above`, preserving both orders.
fn move_block_to_top(block_items: usize, items_above: usize) -> Script {
    if block_items == 0 || items_above == 0 {
        return Script::new("no-op block move");
    }
    let depth = block_items + items_above - 1;
    script! {
        for _ in 0..block_items { { depth as u32 } OP_ROLL }
    }
}

/// Validate one compact unsigned chunk and expand it to literal bits.
///
/// Output order is `bit[width-1] .. bit[0]`, with bit zero on top.  The raw
/// round trip rejects negative zero and redundant sign bytes independently of
/// MINIMALDATA.  A valid value at these widths needs at most three bytes.
fn canonical_chunk_to_bits(width: usize) -> Script {
    assert!((1..=21).contains(&width));
    script! {
        OP_SIZE 4 OP_LESSTHAN OP_VERIFY
        OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
        OP_DUP 0 OP_LESSTHAN OP_NOT OP_VERIFY
        OP_DUP { 1u32 << width } OP_LESSTHAN OP_VERIFY
        { u31_to_bits_with_width(width as u32) }
    }
}

/// Expand all compact chunks to a single low-bit-first stream.
///
/// Input order is `chunk[0] .. chunk[27]`, so the final chunk is initially on
/// top.  Expanding from high to low leaves global bit zero on top without a
/// second permutation.
fn expand_chunks_to_bits() -> Script {
    let mut expanded_bits = 0usize;
    let mut steps = Vec::with_capacity(CHUNK_ITEMS);
    for width in CHUNK_WIDTHS.into_iter().rev() {
        steps.push(script! {
            if expanded_bits != 0 { { expanded_bits as u32 } OP_ROLL }
            { canonical_chunk_to_bits(width) }
        });
        expanded_bits += width;
    }
    assert_eq!(expanded_bits, CARRIED_BITS);
    script! { for step in steps { { step } } }
}

/// Consume four consecutive low-first bits at fixed depth and return one u4.
/// `base_depth` counts lower transcript bits plus persistent main-stack output
/// items.  The partial nibble itself replaces each consumed bit, so every
/// later bit is at `base_depth + 1`.
fn extract_nibble(base_depth: usize) -> Script {
    script! {
        if base_depth != 0 { { base_depth as u32 } OP_ROLL }
        for bit in 1..4usize {
            { (base_depth + 1) as u32 } OP_ROLL
            for _ in 0..bit { OP_DUP OP_ADD }
            OP_ADD
        }
    }
}

/// Reject the 19 packed radix-32 encodings outside the field's canonical
/// image.  Word seven's padding bit has already been checked separately.
///
/// Before/after: `word[7] .. word[0]` (word zero on top).
fn verify_packed_field_gap() -> Script {
    script! {
        // The invalid interval occurs only when words 1..6 are 0xffffffff,
        // word 7 is 0x7fffffff, and unsigned word 0 is 0xffffffed..ffffffff.
        1 OP_PICK { -1i32 } OP_EQUAL
        for original_depth in 2..7u32 {
            { original_depth + 1 } OP_PICK { -1i32 } OP_EQUAL OP_BOOLAND
        }
        8 OP_PICK { 0x7fff_ffffu32 } OP_EQUAL OP_BOOLAND
        OP_IF
            // The canonical five-byte -2^31 word is outside the 19-value gap
            // and cannot be consumed by an arithmetic opcode.
            OP_SIZE 5 OP_NUMEQUAL OP_NOTIF
                OP_DUP { -19i32 } OP_GREATERTHANOREQUAL
                OP_OVER 0 OP_LESSTHAN
                OP_BOOLAND OP_NOT OP_VERIFY
            OP_ENDIF
        OP_ENDIF
    }
}

/// Emit one message-only word's BLAKE3 nibbles to altstack.
///
/// Words are visited high-to-low and each word's bits low-to-high.  This is
/// the reverse of the desired final stack order, so one final altstack restore
/// produces bytes 3,2,1,0 with high nibble before low nibble.
fn stage_message_word(word: usize) -> Script {
    assert!((RTILDE_WORDS..TRANSCRIPT_BYTES / 4).contains(&word));
    let base_depth = word * 32;
    script! {
        for _ in 0..8 {
            { extract_nibble(base_depth) }
            OP_TOALTSTACK
        }
    }
}

/// Emit one Rtilde word's BLAKE3 nibbles while retaining a compressed-u32
/// copy.  `completed_words` compressed words already sit above lower bits.
fn stage_rtilde_word(word: usize, completed_words: usize) -> Script {
    assert!(word < RTILDE_WORDS);
    assert_eq!(completed_words, RTILDE_WORDS - 1 - word);
    let mut steps = Vec::with_capacity(4);
    for byte in 0..4usize {
        let persistent = completed_words + byte;
        let low = extract_nibble(word * 32 + persistent);
        let high = extract_nibble(word * 32 + persistent + 1);
        steps.push(script! {
            { low }
            OP_DUP OP_TOALTSTACK
            { high }
            if word == RTILDE_WORDS - 1 && byte == 3 {
                // Packed field bit 255 is padding, not transcript freedom.
                OP_DUP 8 OP_LESSTHAN OP_VERIFY
            }
            OP_DUP OP_TOALTSTACK

            // low | high -> byte = low + 16*high.
            for _ in 0..4 { OP_DUP OP_ADD }
            OP_ADD
        });
    }
    script! {
        for step in steps { { step } }
        // Natural byte production is b0,b1,b2,b3; u32_compress consumes
        // b3,b2,b1,b0 and emits the unique signed ScriptNum representation.
        OP_SWAP OP_2SWAP OP_SWAP
        { u32_compress() }
    }
}

/// Canonically unpack the compact H16 transcript.
///
/// Before (bottom to top):
/// `preserved | chunk[0] | ... | chunk[27]`.
///
/// After:
/// `preserved | Rword[7] .. Rword[0] | R_u4[0..64] | M_u4[0..64]`.
/// Each BLAKE3 four-byte word appears as byte 3 through byte 0, with each byte
/// represented high nibble then low nibble.  Altstack must be empty at entry
/// and is empty at exit.
pub(crate) fn unpack_transcript(preserved_items: usize) -> Script {
    script! {
        OP_DEPTH { (preserved_items + CHUNK_ITEMS) as u32 } OP_NUMEQUALVERIFY
        { expand_chunks_to_bits() }

        // Global bit 512 is the sole capacity surplus.
        { TRANSCRIPT_BITS as u32 } OP_ROLL OP_NOT OP_VERIFY

        // Push reverse-final-order nibble data onto altstack.
        for word in (RTILDE_WORDS..TRANSCRIPT_BYTES / 4).rev() {
            { stage_message_word(word) }
        }
        for word in (0..RTILDE_WORDS).rev() {
            { stage_rtilde_word(word, RTILDE_WORDS - 1 - word) }
        }

        { verify_packed_field_gap() }
        for _ in 0..TRANSCRIPT_NIBBLES { OP_FROMALTSTACK }
    }
}

/// H16 response-frontier wrapper for the physical scalar-scheduler layout.
///
/// Before: `future_packets[288] | chunk[0..28] | current_state[41]`.
/// After: `future_packets[288] | current_state[41] | Rword[7..0] |
/// R32_u4[64] | M32_u4[64]`.
pub(crate) fn route_and_unpack_h16_midpoint() -> Script {
    script! {
        { move_block_to_top(CHUNK_ITEMS, CURRENT_STATE_ITEMS) }
        { unpack_transcript(UNPACK_PRESERVED_ITEMS) }
    }
}

/// Legacy carry-centered comparison recoder for BLAKE3's low-128 output.
///
/// Input digest order is byte 0 through byte 15, each high nibble then low.
/// Output is `negative[0] | magnitude[0] | ... | negative[15] |
/// magnitude[15]`; the top selector is therefore consumed first.  The caller
/// must already have certified every input item as an integer in `0..16`.
pub(crate) fn recode_blake3_low128(preserved_items: usize) -> Script {
    script! {
        OP_DEPTH { (preserved_items + DIGEST_NIBBLES) as u32 } OP_NUMEQUALVERIFY
        0 // centered carry

        for group in 0..CHALLENGE_GROUPS {
            // The two target nibbles remain at constant depth: each completed
            // group replaces two consumed nibbles, and carry adds one item.
            32 OP_ROLL
            32 OP_ROLL
            // high | low -> byte.
            OP_SWAP
            for _ in 0..4 { OP_DUP OP_ADD }
            OP_ADD
            OP_ADD // byte + incoming carry

            if group + 1 != CHALLENGE_GROUPS {
                OP_DUP 128 OP_GREATERTHANOREQUAL
                OP_IF
                    // digit=t-256.  Emit sign | abs(digit) | carry.  The
                    // t=256 case is canonical zero with a false sign.
                    256 OP_SWAP OP_SUB
                    OP_DUP OP_0NOTEQUAL OP_SWAP
                    1
                OP_ELSE
                    // Nonnegative centered digit, no outgoing carry.
                    0 OP_SWAP
                    0
                OP_ENDIF
            } else {
                // The top digit is not centered again. It includes the last
                // carry and therefore spans 0..=256.
                0 OP_SWAP
            }
        }
    }
}

/// Exact H16 post-hash wrapper. The preserved prefix is 288 future packet
/// items, the 41-item current state, and eight retained Rtilde words.
#[allow(dead_code)]
pub(crate) fn recode_h16_blake3_low128() -> Script {
    recode_blake3_low128(RECODER_PRESERVED_ITEMS)
}

/// Turn BLAKE3's certified low-128 output into sixteen independent signed
/// bytes with no carry chain.
///
/// For little-endian byte `b_i`, this emits the sign/magnitude encoding of
/// `e_i=b_i-127`, so `h=sum(e_i*2^(8i))+K_127` with
/// `K_127=sum(127*2^(8i))=0x7f7f...7f`. The fixed `-K_127*A` term belongs in
/// the response initializer table, not in this recoder. Every magnitude is in
/// `0..=128`; byte 127 maps to canonical `(false, 0)`.
///
/// The caller must already have certified every input item as a u4. This
/// fragment consumes no witness hints and preserves its caller prefix.
pub(crate) fn recode_blake3_low128_independent_byte127(preserved_items: usize) -> Script {
    script! {
        OP_DEPTH { (preserved_items + DIGEST_NIBBLES) as u32 } OP_NUMEQUALVERIFY

        for _ in 0..CHALLENGE_GROUPS {
            // Each completed byte replaces its two input nibbles with exactly
            // two controls, so the next high/low pair remains at depth 31.
            31 OP_ROLL
            31 OP_ROLL
            // high | low -> byte = low + 16*high.
            OP_SWAP
            for _ in 0..4 { OP_DUP OP_ADD }
            OP_ADD
            127 OP_SUB

            // Signed digit -> canonical negative | magnitude. OP_LESSTHAN is
            // false for zero, so the zero digit has no negative-zero form.
            OP_DUP 0 OP_LESSTHAN
            OP_SWAP OP_ABS
        }
    }
}

/// Exact H16 post-hash wrapper for the independent bias-127 schedule.
#[allow(dead_code)]
pub(crate) fn recode_h16_blake3_low128_independent_byte127() -> Script {
    recode_blake3_low128_independent_byte127(RECODER_PRESERVED_ITEMS)
}

fn raw_fragment_len(fragment: Script, copies: usize) -> usize {
    let repeated = script! {
        for _ in 0..copies { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % copies, 0);
    repeated.len() / copies
}

fn static_non_push_opcodes(script: &bitcoin::ScriptBuf) -> usize {
    script
        .instructions()
        .map(|instruction| instruction.expect("generated script must parse"))
        .filter(
            |instruction| matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() > 0x60),
        )
        .count()
}

fn transcript_chunks(transcript: &[u8; TRANSCRIPT_BYTES]) -> [u32; CHUNK_ITEMS] {
    let mut global_bit = 0usize;
    std::array::from_fn(|chunk| {
        let width = CHUNK_WIDTHS[chunk];
        let mut value = 0u32;
        for local_bit in 0..width {
            if global_bit < TRANSCRIPT_BITS {
                value |=
                    u32::from((transcript[global_bit / 8] >> (global_bit % 8)) & 1) << local_bit;
            }
            global_bit += 1;
        }
        value
    })
}

fn set_carried_bit(chunks: &mut [u32; CHUNK_ITEMS], bit: usize) {
    assert!(bit < CARRIED_BITS);
    let mut start = 0usize;
    for (chunk, width) in CHUNK_WIDTHS.into_iter().enumerate() {
        if bit < start + width {
            chunks[chunk] |= 1u32 << (bit - start);
            return;
        }
        start += width;
    }
    unreachable!("carried bit is covered by the chunk layout")
}

fn blake3_u4_layout(transcript: &[u8; TRANSCRIPT_BYTES]) -> Vec<u8> {
    transcript
        .chunks_exact(4)
        .flat_map(|word| word.iter().rev())
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .collect()
}

fn unpack_witness(preserved_items: usize, chunks: &[u32; CHUNK_ITEMS]) -> Vec<Vec<u8>> {
    let mut witness = vec![scriptnum_item(7); preserved_items];
    witness.extend(chunks.iter().map(|value| scriptnum_item(i64::from(*value))));
    witness
}

fn routed_unpack_witness(chunks: &[u32; CHUNK_ITEMS]) -> Vec<Vec<u8>> {
    let mut witness = vec![scriptnum_item(7); FUTURE_PACKET_ITEMS];
    witness.extend(chunks.iter().map(|value| scriptnum_item(i64::from(*value))));
    witness.extend(vec![scriptnum_item(7); CURRENT_STATE_ITEMS]);
    witness
}

fn unpack_checker(
    preserved_items: usize,
    words: &[u32; RTILDE_WORDS],
    expected_nibbles: &[u8],
) -> bitcoin::ScriptBuf {
    assert_eq!(expected_nibbles.len(), TRANSCRIPT_NIBBLES);
    script! {
        { policy_precompiled(
            unpack_transcript(preserved_items),
            "policy-precompiled H16 transcript unpacker",
        ) }
        for nibble in expected_nibbles.iter().rev() {
            { *nibble } OP_NUMEQUALVERIFY
        }
        for word in words {
            { compressed_word_item(*word) } OP_EQUALVERIFY
        }
        for _ in 0..preserved_items { 7 OP_NUMEQUALVERIFY }
        OP_1
    }
    .compile_with_policy()
}

fn unpack_acceptance_probe(preserved_items: usize) -> bitcoin::ScriptBuf {
    script! {
        { policy_precompiled(
            unpack_transcript(preserved_items),
            "policy-precompiled rejecting H16 transcript unpacker",
        ) }
        { drop_items(TRANSCRIPT_NIBBLES + RTILDE_WORDS + preserved_items) }
        OP_1
    }
    .compile_with_policy()
}

fn routed_unpack_checker(
    words: &[u32; RTILDE_WORDS],
    expected_nibbles: &[u8],
) -> bitcoin::ScriptBuf {
    assert_eq!(expected_nibbles.len(), TRANSCRIPT_NIBBLES);
    script! {
        { policy_precompiled(
            route_and_unpack_h16_midpoint(),
            "policy-precompiled routed H16 transcript unpacker",
        ) }
        for nibble in expected_nibbles.iter().rev() {
            { *nibble } OP_NUMEQUALVERIFY
        }
        for word in words {
            { compressed_word_item(*word) } OP_EQUALVERIFY
        }
        for _ in 0..UNPACK_PRESERVED_ITEMS { 7 OP_NUMEQUALVERIFY }
        OP_1
    }
    .compile_with_policy()
}

fn assert_unpack_rejected(script: &bitcoin::ScriptBuf, witness: Vec<Vec<u8>>, description: &str) {
    let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), witness);
    assert!(
        execution.error.is_some(),
        "accepted {description}: {execution}"
    );
}

fn independent_controls(bytes: &[u8; DIGEST_BYTES]) -> Vec<(u32, u32)> {
    bytes
        .iter()
        .map(|byte| {
            let digit = i32::from(*byte) - 127;
            (u32::from(digit < 0), digit.unsigned_abs())
        })
        .collect()
}

fn digest_u4(bytes: &[u8; DIGEST_BYTES]) -> Vec<u8> {
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .collect()
}

fn recoder_witness(preserved_items: usize, bytes: &[u8; DIGEST_BYTES]) -> Vec<Vec<u8>> {
    let mut witness = vec![scriptnum_item(11); preserved_items];
    witness.extend(
        digest_u4(bytes)
            .into_iter()
            .map(|nibble| scriptnum_item(i64::from(nibble))),
    );
    witness
}

fn recoder_checker(preserved_items: usize, expected: &[(u32, u32)]) -> bitcoin::ScriptBuf {
    assert_eq!(expected.len(), CHALLENGE_GROUPS);
    script! {
        { policy_precompiled(
            recode_blake3_low128_independent_byte127(preserved_items),
            "policy-precompiled H16 challenge recoder",
        ) }
        for (negative, magnitude) in expected.iter().rev() {
            { *magnitude } OP_NUMEQUALVERIFY
            { *negative } OP_NUMEQUALVERIFY
        }
        for _ in 0..preserved_items { 11 OP_NUMEQUALVERIFY }
        OP_1
    }
    .compile_with_policy()
}

fn main() {
    assert_eq!(CHUNK_WIDTHS.iter().sum::<usize>(), CARRIED_BITS);
    assert_eq!(FUTURE_PACKET_ITEMS, 288);
    assert_eq!(UNPACK_PRESERVED_ITEMS, 329);
    assert_eq!(RECODER_PRESERVED_ITEMS, 337);

    let p = u5_balanced_table::modulus();
    let rtilde = BigUint::parse_bytes(
        b"123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        16,
    )
    .expect("fixture parses")
        % p;
    let rtilde_words =
        u5_packed::packed_words_from_digits(&u5_balanced_table::field_digits(&rtilde));
    let rtilde_bytes = rtilde_words
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    assert_eq!(rtilde_bytes.len(), RTILDE_BYTES);
    let message: [u8; 32] =
        std::array::from_fn(|index| (index as u8).wrapping_mul(37).wrapping_add(0x5a));
    let transcript: [u8; TRANSCRIPT_BYTES] = rtilde_bytes
        .into_iter()
        .chain(message)
        .collect::<Vec<_>>()
        .try_into()
        .expect("64-byte transcript");
    let chunks = transcript_chunks(&transcript);
    let expected_nibbles = blake3_u4_layout(&transcript);
    let generic_blake_layout_check = script! {
        { blake3_push_message_script_with_limb(&transcript, 4) }
        for nibble in expected_nibbles.iter().rev() {
            { *nibble } OP_NUMEQUALVERIFY
        }
        OP_1
    }
    .compile_with_policy();
    let generic_blake_layout =
        execute_raw_script_with_inputs_strict(generic_blake_layout_check.to_bytes(), vec![]);
    assert!(
        generic_blake_layout.error.is_none(),
        "generic BLAKE3 u4 layout mismatch: {generic_blake_layout}"
    );

    let local_unpack_script = unpack_checker(0, &rtilde_words, &expected_nibbles);
    let local_unpack = execute_raw_script_with_inputs_strict(
        local_unpack_script.to_bytes(),
        unpack_witness(0, &chunks),
    );
    assert!(local_unpack.error.is_none(), "local unpack: {local_unpack}");
    assert_eq!(local_unpack.final_stack.len(), 1);

    let combined_unpack_script =
        unpack_checker(UNPACK_PRESERVED_ITEMS, &rtilde_words, &expected_nibbles);
    let combined_unpack_witness = unpack_witness(UNPACK_PRESERVED_ITEMS, &chunks);
    let combined_unpack_witness_bytes =
        serialize(&Witness::from_slice(&combined_unpack_witness)).len();
    let combined_unpack = execute_raw_script_with_inputs_strict(
        combined_unpack_script.to_bytes(),
        combined_unpack_witness,
    );
    assert!(
        combined_unpack.error.is_none(),
        "H16-preserving unpack: {combined_unpack}"
    );
    assert_eq!(combined_unpack.final_stack.len(), 1);

    let routed_unpack_script = routed_unpack_checker(&rtilde_words, &expected_nibbles);
    let routed_unpack = execute_raw_script_with_inputs_strict(
        routed_unpack_script.to_bytes(),
        routed_unpack_witness(&chunks),
    );
    assert!(
        routed_unpack.error.is_none(),
        "physically routed H16 unpack: {routed_unpack}"
    );
    assert_eq!(routed_unpack.final_stack.len(), 1);

    let rejecting_unpack = unpack_acceptance_probe(UNPACK_PRESERVED_ITEMS);
    let mut out_of_range = chunks;
    out_of_range[0] = 1 << CHUNK_WIDTHS[0];
    assert_unpack_rejected(
        &rejecting_unpack,
        unpack_witness(UNPACK_PRESERVED_ITEMS, &out_of_range),
        "out-of-range 21-bit chunk",
    );
    let mut negative = unpack_witness(UNPACK_PRESERVED_ITEMS, &chunks);
    negative[UNPACK_PRESERVED_ITEMS + 17] = scriptnum_item(-1);
    assert_unpack_rejected(&rejecting_unpack, negative, "negative chunk");
    let mut aliased = unpack_witness(UNPACK_PRESERVED_ITEMS, &chunks);
    aliased[UNPACK_PRESERVED_ITEMS + CHUNK_ITEMS - 1] = vec![1, 0];
    assert_unpack_rejected(&rejecting_unpack, aliased, "non-canonical chunk alias");
    let mut nonzero_spare = chunks;
    set_carried_bit(&mut nonzero_spare, TRANSCRIPT_BITS);
    assert_unpack_rejected(
        &rejecting_unpack,
        unpack_witness(UNPACK_PRESERVED_ITEMS, &nonzero_spare),
        "nonzero capacity-spare bit",
    );
    let mut nonzero_field_padding = chunks;
    set_carried_bit(&mut nonzero_field_padding, 255);
    assert_unpack_rejected(
        &rejecting_unpack,
        unpack_witness(UNPACK_PRESERVED_ITEMS, &nonzero_field_padding),
        "nonzero packed-field padding bit",
    );
    let gap_words = [
        0xffff_ffed,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        0x7fff_ffff,
    ];
    let gap_rtilde = gap_words.into_iter().flat_map(u32::to_le_bytes);
    let gap_transcript: [u8; TRANSCRIPT_BYTES] = gap_rtilde
        .chain(message)
        .collect::<Vec<_>>()
        .try_into()
        .expect("64-byte gap transcript");
    let gap_chunks = transcript_chunks(&gap_transcript);
    assert_unpack_rejected(
        &rejecting_unpack,
        unpack_witness(UNPACK_PRESERVED_ITEMS, &gap_chunks),
        "packed-field 19-value canonical gap",
    );

    let transcript_material = [transcript.as_slice(), b"/blake3-low128-fixture"].concat();
    let digest: [u8; DIGEST_BYTES] = blake3::hash(&transcript_material).as_bytes()[..DIGEST_BYTES]
        .try_into()
        .expect("16-byte digest prefix");
    let recoder_fixtures = [
        digest,
        [0u8; DIGEST_BYTES],
        [0x7fu8; DIGEST_BYTES],
        [0x80u8; DIGEST_BYTES],
        [0xffu8; DIGEST_BYTES],
    ];
    let mut local_recoder_peak = 0usize;
    let mut combined_recoder_peak = 0usize;
    for bytes in recoder_fixtures {
        let expected = independent_controls(&bytes);
        assert!(expected.iter().all(|(_, magnitude)| *magnitude <= 128));

        let local_script = recoder_checker(0, &expected);
        let local = execute_raw_script_with_inputs_strict(
            local_script.to_bytes(),
            recoder_witness(0, &bytes),
        );
        assert!(local.error.is_none(), "local recoder: {local}");
        assert_eq!(local.final_stack.len(), 1);
        local_recoder_peak = local_recoder_peak.max(local.stats.max_nb_stack_items);

        let combined_script = recoder_checker(RECODER_PRESERVED_ITEMS, &expected);
        let combined = execute_raw_script_with_inputs_strict(
            combined_script.to_bytes(),
            recoder_witness(RECODER_PRESERVED_ITEMS, &bytes),
        );
        assert!(
            combined.error.is_none(),
            "H16-preserving recoder: {combined}"
        );
        assert_eq!(combined.final_stack.len(), 1);
        combined_recoder_peak = combined_recoder_peak.max(combined.stats.max_nb_stack_items);
    }
    assert!(independent_controls(&[0x00; DIGEST_BYTES])
        .iter()
        .all(|control| *control == (1, 127)));
    assert!(independent_controls(&[0x7f; DIGEST_BYTES])
        .iter()
        .all(|control| *control == (0, 0)));
    assert!(independent_controls(&[0x80; DIGEST_BYTES])
        .iter()
        .all(|control| *control == (0, 1)));
    assert!(independent_controls(&[0xff; DIGEST_BYTES])
        .iter()
        .all(|control| *control == (0, 128)));

    let unpack_fragment = unpack_transcript(UNPACK_PRESERVED_ITEMS);
    let unpack_policy = unpack_fragment.clone().compile_with_policy();
    let unpack_raw_bytes = raw_fragment_len(unpack_fragment, 16);
    let routed_unpack_fragment = route_and_unpack_h16_midpoint();
    let routed_unpack_policy = routed_unpack_fragment.clone().compile_with_policy();
    let routed_unpack_raw_bytes = raw_fragment_len(routed_unpack_fragment, 16);
    let recoder_fragment = recode_blake3_low128_independent_byte127(RECODER_PRESERVED_ITEMS);
    let recoder_policy = recoder_fragment.clone().compile_with_policy();
    let recoder_raw_bytes = raw_fragment_len(recoder_fragment, 128);

    println!("model=ed25519_h16_midpoint_glue");
    println!("evidence=locally-reproduced");
    println!("execution_class=unclassified");
    println!("context=tapscript,strict_1000_item_stack,bitcoin-scriptexec");
    println!("long_scalar_field_or_blake_execution=false");
    println!("transcript_chunk_widths=21,20,20,20,18x24");
    println!("transcript_chunk_items={CHUNK_ITEMS}");
    println!("transcript_circuit_data_bits={TRANSCRIPT_BITS}");
    println!("transcript_forced_zero_spare_bits=1");
    println!("transcript_unpack_hint_items=0");
    println!("transcript_unpack_incremental_entry_items=0");
    println!("transcript_unpack_input_items={CHUNK_ITEMS}");
    println!(
        "transcript_unpack_output_items={}",
        RTILDE_WORDS + TRANSCRIPT_NIBBLES
    );
    println!("transcript_unpack_preserved_items={UNPACK_PRESERVED_ITEMS}");
    println!(
        "transcript_unpack_complete_fragment_input_items={}",
        UNPACK_PRESERVED_ITEMS + CHUNK_ITEMS
    );
    println!(
        "transcript_unpack_complete_fragment_output_items={}",
        UNPACK_PRESERVED_ITEMS + RTILDE_WORDS + TRANSCRIPT_NIBBLES
    );
    println!("transcript_unpack_raw_bytes={unpack_raw_bytes}");
    println!("transcript_unpack_policy_bytes={}", unpack_policy.len());
    println!(
        "transcript_unpack_policy_static_non_push_opcodes={}",
        static_non_push_opcodes(&unpack_policy)
    );
    println!(
        "transcript_unpack_local_strict_combined_stack_peak={}",
        local_unpack.stats.max_nb_stack_items
    );
    println!(
        "transcript_unpack_h16_strict_combined_stack_peak={}",
        combined_unpack.stats.max_nb_stack_items
    );
    println!("transcript_unpack_fixture_witness_bytes={combined_unpack_witness_bytes}");
    println!("transcript_routed_input_order=future288_then_chunks28_then_state41");
    println!("transcript_routed_output_order=future288_then_state41_then_Rwords8_then_u4_128");
    println!("transcript_routed_raw_bytes={routed_unpack_raw_bytes}");
    println!(
        "transcript_routed_policy_bytes={}",
        routed_unpack_policy.len()
    );
    println!(
        "transcript_routed_policy_delta_bytes={}",
        routed_unpack_raw_bytes - routed_unpack_policy.len()
    );
    println!(
        "transcript_routed_h16_strict_combined_stack_peak={}",
        routed_unpack.stats.max_nb_stack_items
    );
    println!("transcript_unpack_chunk_raw_canonicality_checked=true");
    println!("transcript_unpack_chunk_unsigned_ranges_checked=true");
    println!("transcript_unpack_spare_bit_checked_zero=true");
    println!("transcript_unpack_rtilde_padding_bit_checked_zero=true");
    println!("transcript_unpack_rtilde_field_gap_rejected=true");
    println!("transcript_unpack_altstack_empty_at_entry_required=true");
    println!("transcript_unpack_altstack_empty_at_exit=true");
    println!("transcript_unpack_input_order=chunk0_bottom_through_chunk27_top,low_bits_first");
    println!("transcript_unpack_output_order=Rword7..Rword0_then_R32||M32_u4");
    println!("transcript_u4_word_order=word_low_to_high,byte3_to_byte0,high_nibble_then_low");
    println!("transcript_u4_order_matches_generic_blake3_limb4_pusher=true");
    println!("challenge_recoder_hint_items=0");
    println!("challenge_recoder_incremental_entry_items=0");
    println!("challenge_recoder_input_items={DIGEST_NIBBLES}");
    println!("challenge_recoder_output_items={}", 2 * CHALLENGE_GROUPS);
    println!("challenge_recoder_preserved_items={RECODER_PRESERVED_ITEMS}");
    println!(
        "challenge_recoder_complete_fragment_input_items={}",
        RECODER_PRESERVED_ITEMS + DIGEST_NIBBLES
    );
    println!(
        "challenge_recoder_complete_fragment_output_items={}",
        RECODER_PRESERVED_ITEMS + 2 * CHALLENGE_GROUPS
    );
    println!("challenge_recoder_raw_bytes={recoder_raw_bytes}");
    println!("challenge_recoder_policy_bytes={}", recoder_policy.len());
    println!(
        "challenge_recoder_policy_static_non_push_opcodes={}",
        static_non_push_opcodes(&recoder_policy)
    );
    println!("challenge_recoder_local_strict_combined_stack_peak={local_recoder_peak}");
    println!("challenge_recoder_h16_strict_combined_stack_peak={combined_recoder_peak}");
    println!("challenge_recoder_input_range_checks=external_BLAKE3_certification_required_0_to_15");
    println!("challenge_recoder_input_order=byte0_high_low_through_byte15_high_low");
    println!("challenge_recoder_output_order=low_to_high_groups_as_negative_then_magnitude");
    println!("challenge_recoder_top_selector_on_top=true");
    println!("challenge_recoder_schedule=independent_signed_bytes_bias127");
    println!("challenge_recoder_identity=h=sum(e_i*2^(8i))+K_127");
    println!("challenge_recoder_selector_range=0..128");
    println!("challenge_recoder_boundary_map=00:-127,7f:0,80:1,ff:128");
    println!("hint_coexistence=not_applicable_zero_incremental_hints");
    println!("script_compilation=repository_policy_ALL_below_32KiB");
    println!("includes=fragment-only: exact compact-transcript canonical unpack with Rtilde reconstruction and exact low128 independent bias-127 challenge recoding; carrier extraction, BLAKE3 compression, scalar multiplication, tables, and terminal signature predicate excluded");
}
