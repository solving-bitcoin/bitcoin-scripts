//! Compact witness/data wires for the centered radix-32 Ed25519 backend.
//!
//! A field value's 51 five-bit digits are concatenated least-significant
//! digit first into a 255-bit payload. The payload is split into eight
//! little-endian `u32` words; bit 31 of word seven is fixed to zero. Each word
//! occupies one stack item using [`u32_compress`]. Host witness order is
//! `word[7] .. word[0]`, with word zero nearest the top, matching the field
//! backend's `digit[50] .. digit[0]` order.
//!
//! Both decoders treat every input as hostile. The low-stack decoder rejects
//! alternate raw ScriptNum encodings and expands exact words through
//! [`u32_uncompress`]. The faster decoder maps signed words directly to bits;
//! it allows at-most-four-byte aliases when execution flags do, without
//! changing the decoded value. Both reconstruct all 255 payload bits, reject
//! the padding bit, and reject the centered backend's 19-value canonical gap.
//! The low-stack path streams one byte and one numeric cross-byte carry at a
//! time instead of materializing a 256-item bit vector.
//!
//! These codecs require **zero auxiliary witness hint items**. Packed values
//! are circuit data, not hints. All eight packed items coexist at script entry.

use num_bigint::BigUint;

use crate::{
    arithmetic::{
        u31::{u31_to_bits_with_width, U31_LOOKUP_STACK_LIMIT},
        u32::stack::{u32_compress, u32_uncompress},
    },
    fields::ed25519::u5_balanced_table::{self, FieldDigits, FIELD_DIGIT_COUNT},
    support::script::*,
};

pub const PACKED_WORD_COUNT: usize = 8;
pub const PACKED_PAYLOAD_BITS: usize = 255;
pub const PACKED_PADDING_BITS: usize = 1;
pub const CODEC_HINT_ITEM_COUNT: usize = 0;
pub const MAX_PACKED_WITNESS_BYTES: usize = 48;

pub const DECODE_SCRIPT_BYTES: usize = 6_241;
pub const PRESERVING_DECODE_SCRIPT_BYTES: usize = 6_275;
pub const ENCODE_CERTIFIED_SCRIPT_BYTES: usize = 3_628;
pub const ENCODE_RAW_SCRIPT_BYTES: usize = 4_209;

pub const FAST_DECODE_SCRIPT_BYTES: usize = 4_644;
pub const FAST_PRESERVING_DECODE_SCRIPT_BYTES: usize = 4_678;

// Filled from strict bitcoin-scriptexec measurements. The peak includes all
// main- and alt-stack items, including the eight inputs or 51 outputs.
pub const DECODE_STACK_ITEMS: u32 = 58;
pub const PRESERVING_DECODE_STACK_ITEMS: u32 = 66;
pub const ENCODE_STACK_ITEMS: u32 = 61;
pub const FAST_DECODE_STACK_ITEMS: u32 = 81;
pub const FAST_PRESERVING_DECODE_STACK_ITEMS: u32 = 89;

pub const MAX_DECODE_PRESERVED_ITEMS: u32 = U31_LOOKUP_STACK_LIMIT - DECODE_STACK_ITEMS;
pub const MAX_PRESERVING_DECODE_PRESERVED_ITEMS: u32 =
    U31_LOOKUP_STACK_LIMIT - PRESERVING_DECODE_STACK_ITEMS;
pub const MAX_ENCODE_PRESERVED_ITEMS: u32 = U31_LOOKUP_STACK_LIMIT - ENCODE_STACK_ITEMS;
pub const MAX_FAST_DECODE_PRESERVED_ITEMS: u32 = U31_LOOKUP_STACK_LIMIT - FAST_DECODE_STACK_ITEMS;
pub const MAX_FAST_PRESERVING_DECODE_PRESERVED_ITEMS: u32 =
    U31_LOOKUP_STACK_LIMIT - FAST_PRESERVING_DECODE_STACK_ITEMS;

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn compressed_word_scriptnum(word: u32) -> i64 {
    i64::from(word as i32)
}

/// Pack 51 canonical radix-32 digits into eight little-endian words.
pub fn packed_words_from_digits(digits: &FieldDigits) -> [u32; PACKED_WORD_COUNT] {
    assert!(
        u5_balanced_table::is_canonical_digits(digits),
        "field digits must be canonical"
    );
    let mut words = [0u32; PACKED_WORD_COUNT];
    for (index, digit) in digits.iter().enumerate() {
        let bit_offset = 5 * index;
        let word_index = bit_offset / 32;
        let word_offset = bit_offset % 32;
        let value = *digit as u32;
        words[word_index] |= value << word_offset;
        if word_offset > 27 {
            words[word_index + 1] |= value >> (32 - word_offset);
        }
    }
    debug_assert_eq!(words[PACKED_WORD_COUNT - 1] >> 31, 0);
    words
}

/// Recover and validate the 51 radix-32 digits represented by packed words.
pub fn digits_from_packed_words(words: &[u32; PACKED_WORD_COUNT]) -> Option<FieldDigits> {
    if words[PACKED_WORD_COUNT - 1] >> 31 != 0 {
        return None;
    }
    let digits = std::array::from_fn(|index| {
        let bit_offset = 5 * index;
        let word_index = bit_offset / 32;
        let word_offset = bit_offset % 32;
        let mut value = words[word_index] >> word_offset;
        if word_offset > 27 {
            value |= words[word_index + 1] << (32 - word_offset);
        }
        (value & 31) as i32
    });
    u5_balanced_table::is_canonical_digits(&digits).then_some(digits)
}

/// Eight minimally encoded compressed-word witness items, in stack order.
pub fn packed_value_witness_items(value: &BigUint) -> Vec<Vec<u8>> {
    packed_words_from_digits(&u5_balanced_table::field_digits(value))
        .iter()
        .rev()
        .map(|word| scriptnum_item(compressed_word_scriptnum(*word)))
        .collect()
}

/// Push a packed value as `word[7] .. word[0]`, with word zero nearest top.
pub fn push_packed_value(value: &BigUint) -> Script {
    let words = packed_words_from_digits(&u5_balanced_table::field_digits(value));
    script! {
        for word in words.iter().rev() {
            { compressed_word_scriptnum(*word) }
        }
    }
}

// Pop `width` bits from altstack, most significant first, and combine them.
fn bits_from_altstack_to_number(width: usize) -> Script {
    assert!(width > 0);
    script! {
        OP_FROMALTSTACK
        for _ in 1..width {
            OP_DUP OP_ADD
            OP_FROMALTSTACK OP_ADD
        }
    }
}

// Split an eight-bit value at 2^low_bits. This is a narrowed version of the
// repository's u31 bit decomposition: it extracts only the high quotient bits
// and leaves the low remainder intact. Output is `quotient | remainder`.
fn split_byte(low_bits: usize) -> Script {
    assert!((1..8).contains(&low_bits));
    let high_bits = 8 - low_bits;
    script! {
        for bit in (low_bits..8).rev() {
            OP_DUP
            { (1u32 << bit) - 1 }
            OP_GREATERTHAN
            OP_SWAP OP_OVER
            OP_IF { 1u32 << bit } OP_SUB OP_ENDIF
        }
        // Park the remainder below the extracted quotient bits. They were
        // emitted low bit nearest the top, so moving all of them to altstack
        // makes the quotient's high bit available first.
        OP_TOALTSTACK
        for _ in 0..high_bits { OP_TOALTSTACK }
        { bits_from_altstack_to_number(high_bits) }
        OP_FROMALTSTACK
    }
}

// Input is one certified byte. A numeric cross-byte carry for the next
// radix-32 digit, if any, is already above completed digits on altstack.
// Output leaves completed digits below the next zero-or-one-item carry.
fn byte_to_radix32_stream(carry_bits: usize) -> Script {
    assert!(carry_bits < 5);
    let low_bits = 5 - carry_bits;
    let quotient_bits = 8 - low_bits;
    script! {
        { split_byte(low_bits) }

        // Scale the new low piece above the earlier carry, complete the first
        // digit, and park it while retaining the quotient on main stack.
        for _ in 0..carry_bits { OP_DUP OP_ADD }
        if carry_bits != 0 { OP_FROMALTSTACK OP_ADD }
        OP_TOALTSTACK

        if quotient_bits < 5 {
            // The quotient is the next cross-byte carry.
            OP_TOALTSTACK
        } else if quotient_bits == 5 {
            // Exactly one additional digit and no carry.
            OP_TOALTSTACK
        } else if quotient_bits == 6 {
            // Split q < 64 into q mod 32 and a one-bit carry.
            OP_DUP 32 OP_GREATERTHANOREQUAL
            OP_IF 32 OP_SUB 1 OP_ELSE 0 OP_ENDIF
            OP_SWAP OP_TOALTSTACK OP_TOALTSTACK
        } else {
            // Split q < 128 into q mod 32 and a two-bit carry.
            0 OP_SWAP
            OP_DUP 64 OP_GREATERTHANOREQUAL
            OP_IF 64 OP_SUB OP_SWAP 2 OP_ADD OP_SWAP OP_ENDIF
            OP_DUP 32 OP_GREATERTHANOREQUAL
            OP_IF 32 OP_SUB OP_SWAP OP_1ADD OP_SWAP OP_ENDIF
            OP_TOALTSTACK OP_TOALTSTACK
        }
    }
}

// Keep one word only if its byte string is the unique canonical compressed-u32
// representation. Adding zero cheaply normalizes every at-most-four-byte
// ScriptNum; raw equality then detects negative zero, redundant sign bytes,
// and other aliases even when MINIMALDATA is disabled. The only valid
// five-byte compressed word is canonical -2^31 and is checked directly.
fn certify_exact_compressed_word() -> Script {
    script! {
        OP_SIZE 5 OP_NUMEQUAL
        OP_IF
            OP_DUP { -2_147_483_648i64 } OP_EQUALVERIFY
        OP_ELSE
            OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
        OP_ENDIF
    }
}

// Decode one exact top compressed word to four certified bytes.
fn exact_uncompress_word(keep_original: bool) -> Script {
    script! {
        if keep_original { OP_DUP }
        { certify_exact_compressed_word() }
        { u32_uncompress() }
    }
}

fn verify_packed_canonical_gap() -> Script {
    script! {
        // E >= 2^255-19 iff words 1..6 are 0xffffffff, word 7 is
        // 0x7fffffff, and unsigned word 0 is in 0xffffffed..=0xffffffff.
        // Compressed, those low 19 values are signed -19..=-1.
        1 OP_PICK { -1i32 } OP_EQUAL
        for original_depth in 2..7u32 {
            { original_depth + 1 } OP_PICK { -1i32 } OP_EQUAL OP_BOOLAND
        }
        8 OP_PICK { 0x7fff_ffffu32 } OP_EQUAL OP_BOOLAND
        OP_IF
            // -2^31 is the lone canonical five-byte compressed word and is
            // outside the gap. Any other five-byte item fails exact word
            // certification later.
            OP_SIZE 5 OP_NUMEQUAL OP_NOTIF
                OP_DUP { -19i32 } OP_GREATERTHANOREQUAL
                OP_OVER 0 OP_LESSTHAN
                OP_BOOLAND OP_NOT OP_VERIFY
            OP_ENDIF
        OP_ENDIF
    }
}

fn verify_decoded_canonical_gap() -> Script {
    script! {
        // Every decoded digit is exactly five bits. Reject the remaining
        // semantic gap independently of the packed words' raw encodings.
        1 OP_PICK
        for index in 2..FIELD_DIGIT_COUNT as u32 {
            { index + 1 } OP_PICK OP_MIN
        }
        31 OP_NUMEQUAL
        OP_IF
            OP_DUP 13 OP_LESSTHAN OP_VERIFY
        OP_ENDIF
    }
}

fn decode_inner(keep_original: bool) -> Script {
    let mut carry_bits = 0usize;
    let mut decode_words = Vec::with_capacity(PACKED_WORD_COUNT);
    for word_index in 0..PACKED_WORD_COUNT {
        let mut word = script! {
            if keep_original && word_index != 0 {
                { word_index as u32 } OP_ROLL
            }
            { exact_uncompress_word(keep_original) }
        };
        for _ in 0..4 {
            word = script! {
                { word }
                { byte_to_radix32_stream(carry_bits) }
            };
            carry_bits = (carry_bits + 8) % 5;
        }
        decode_words.push(word);
    }
    assert_eq!(carry_bits, PACKED_PADDING_BITS);

    script! {
        { verify_packed_canonical_gap() }
        for word in decode_words { { word } }

        if keep_original {
            // Processing low words first leaves originals in low-to-high
            // order. Reverse them back to the public packed stack order.
            for depth in 1..PACKED_WORD_COUNT as u32 {
                { depth } OP_ROLL
            }
        }

        // The sole bit above the 255-bit payload is not data.
        OP_FROMALTSTACK OP_NOT OP_VERIFY

        for _ in 0..FIELD_DIGIT_COUNT { OP_FROMALTSTACK }
    }
}

/// Decode eight hostile packed items into 51 certified radix-32 digits.
///
/// Before: `preserved | word[7] .. word[0]` (`word[0]` on top).
/// After: `preserved | digit[50] .. digit[0]` (`digit[0]` on top).
/// The fragment consumes the packed inputs and adds no terminal predicate.
pub fn decode(preserved_items: u32) -> Script {
    assert!(
        u64::from(preserved_items) + u64::from(DECODE_STACK_ITEMS)
            <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "packed Ed25519 decode exceeds the stack limit"
    );
    decode_inner(false)
}

/// Decode while retaining the exact eight packed input items.
///
/// Before: `preserved | word[7] .. word[0]`. After:
/// `preserved | word[7] .. word[0] | digit[50] .. digit[0]`. The original raw
/// word encodings have passed the exact round-trip check and remain unchanged.
pub fn decode_preserving(preserved_items: u32) -> Script {
    assert!(
        u64::from(preserved_items) + u64::from(PRESERVING_DECODE_STACK_ITEMS)
            <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "preserving packed Ed25519 decode exceeds the stack limit"
    );
    decode_inner(true)
}

// Map one signed compressed-u32 item directly to its unsigned bit pattern.
// Output is `bit31 | bit30 .. bit0`, with bit zero nearest the top. At-most-
// four-byte aliases are intentionally accepted as the same signed number; the
// semantic padding/range/gap checks below remain independent of raw encoding.
fn fast_word_to_bits(keep_original: bool) -> Script {
    script! {
        if keep_original { OP_DUP }
        OP_SIZE 5 OP_NUMEQUAL
        OP_IF
            // Arithmetic cannot consume -2^31's canonical five-byte
            // ScriptNum. Check the unique sentinel as raw bytes instead.
            { -2_147_483_648i64 } OP_EQUALVERIFY
            1 0
        OP_ELSE
            OP_DUP 0 OP_LESSTHAN
            OP_IF
                // For signed s < 0, low31 = s + 2^31. Split the constant so
                // every arithmetic operand and intermediate remains legal.
                { 0x7fff_ffffu32 } OP_ADD OP_1ADD
                1 OP_SWAP
            OP_ELSE
                0 OP_SWAP
            OP_ENDIF
        OP_ENDIF
        { u31_to_bits_with_width(31) }
    }
}

// Consume one word's 32 least-significant-first bits and append six or seven
// completed radix-32 digits plus zero-to-four residual bits to altstack.
fn word_bits_to_radix32_stream(carry_bits: usize) -> Script {
    assert!(carry_bits < 5);
    let first_bits = 5 - carry_bits;
    let mut remaining = 32 - first_bits;
    let full_digits = remaining / 5;
    remaining %= 5;
    script! {
        for _ in 0..first_bits { OP_TOALTSTACK }
        { bits_from_altstack_to_number(5) } OP_TOALTSTACK
        for _ in 0..full_digits {
            for _ in 0..5 { OP_TOALTSTACK }
            { bits_from_altstack_to_number(5) } OP_TOALTSTACK
        }
        for _ in 0..remaining { OP_TOALTSTACK }
    }
}

fn decode_fast_inner(keep_original: bool) -> Script {
    let mut carry_bits = 0usize;
    let words = (0..PACKED_WORD_COUNT)
        .map(|word_index| {
            let word = script! {
                if keep_original && word_index != 0 {
                    { word_index as u32 } OP_ROLL
                }
                { fast_word_to_bits(keep_original) }
                { word_bits_to_radix32_stream(carry_bits) }
            };
            carry_bits = (carry_bits + 32) % 5;
            word
        })
        .collect::<Vec<_>>();
    assert_eq!(carry_bits, PACKED_PADDING_BITS);

    script! {
        for word in words { { word } }
        if keep_original {
            for depth in 1..PACKED_WORD_COUNT as u32 {
                { depth } OP_ROLL
            }
        }
        OP_FROMALTSTACK OP_NOT OP_VERIFY
        for _ in 0..FIELD_DIGIT_COUNT { OP_FROMALTSTACK }
        { verify_decoded_canonical_gap() }
    }
}

/// Faster hostile packed-word decoder using direct signed-u32 bit expansion.
///
/// This has the same consuming stack contract and zero-hint cost as [`decode`].
/// It accepts at-most-four-byte nonminimal ScriptNum aliases as the same word
/// when the execution flags permit them, but independently enforces the
/// 255-bit padding and canonical field interval, so aliases cannot certify a
/// false field value. Use [`decode`] when unique raw encoding is required.
pub fn decode_fast(preserved_items: u32) -> Script {
    assert!(
        u64::from(preserved_items) + u64::from(FAST_DECODE_STACK_ITEMS)
            <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "fast packed Ed25519 decode exceeds the stack limit"
    );
    decode_fast_inner(false)
}

/// [`decode_fast`] while retaining the original eight packed items.
///
/// Before: `preserved | word[7] .. word[0]`. After:
/// `preserved | word[7] .. word[0] | digit[50] .. digit[0]`.
pub fn decode_fast_preserving(preserved_items: u32) -> Script {
    assert!(
        u64::from(preserved_items) + u64::from(FAST_PRESERVING_DECODE_STACK_ITEMS)
            <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "fast preserving packed Ed25519 decode exceeds the stack limit"
    );
    decode_fast_inner(true)
}

fn radix32_digit_to_byte_stream(carry_bits: usize) -> Script {
    assert!(carry_bits < 8);
    let completes_byte = carry_bits + 5 >= 8;
    let first_bits = if completes_byte { 8 - carry_bits } else { 5 };
    let remaining_bits = 5 - first_bits;
    script! {
        { u31_to_bits_with_width(5) }
        for _ in 0..first_bits { OP_TOALTSTACK }
        if completes_byte {
            { bits_from_altstack_to_number(8) }
            // Move any unconsumed high digit bits to altstack without moving
            // the completed byte away from the main-stack output block.
            for _ in 0..remaining_bits {
                1 OP_ROLL OP_TOALTSTACK
            }
        }
    }
}

/// Pack an already-certified 51-digit field value into eight compressed words.
///
/// Before: `preserved | digit[50] .. digit[0]`. After:
/// `preserved | word[7] .. word[0]`. The fragment uses no hints and does not
/// append a terminal predicate.
pub fn encode_certified(preserved_items: u32) -> Script {
    assert!(
        u64::from(preserved_items) + u64::from(ENCODE_STACK_ITEMS)
            <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "packed Ed25519 encode exceeds the stack limit"
    );
    let mut carry_bits = 0usize;
    let mut completed_bytes = 0usize;
    let mut encode_digits = Vec::with_capacity(FIELD_DIGIT_COUNT);
    for _ in 0..FIELD_DIGIT_COUNT {
        let completes_byte = carry_bits + 5 >= 8;
        encode_digits.push(script! {
            if completed_bytes != 0 {
                { completed_bytes as u32 } OP_ROLL
            }
            { radix32_digit_to_byte_stream(carry_bits) }
        });
        carry_bits = (carry_bits + 5) % 8;
        completed_bytes += usize::from(completes_byte);
    }
    assert_eq!(carry_bits, 7);
    assert_eq!(completed_bytes, 31);

    script! {
        for digit in encode_digits { { digit } }

        // Complete byte 31 with the required zero padding bit.
        0 OP_TOALTSTACK
        { bits_from_altstack_to_number(8) }

        // Bytes were produced low first. Reverse all 32 so each top group is
        // `b3 b2 b1 b0`, the input convention of u32_compress.
        for depth in 1..32u32 { { depth } OP_ROLL }

        for _ in 0..PACKED_WORD_COUNT {
            { u32_compress() }
            OP_TOALTSTACK
        }
        for _ in 0..PACKED_WORD_COUNT { OP_FROMALTSTACK }
    }
}

/// Certify hostile raw digits, then pack them into eight compressed words.
pub fn encode_from_raw_digits(preserved_items: u32) -> Script {
    script! {
        { u5_balanced_table::certify_value() }
        { encode_certified(preserved_items) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{
        execution::execute_raw_script_with_inputs_strict, script::ScriptCompilation,
    };
    use num_traits::{One, Zero};

    fn digit_items(digits: &FieldDigits) -> Vec<Vec<u8>> {
        digits
            .iter()
            .rev()
            .map(|digit| scriptnum_item(i64::from(*digit)))
            .collect()
    }

    fn assert_stack(execution: &crate::support::execution::ExecuteInfo, expected: &[Vec<u8>]) {
        assert!(execution.error.is_none(), "execution failed: {execution}");
        assert_eq!(execution.final_stack.len(), expected.len());
        for (index, item) in expected.iter().enumerate() {
            assert_eq!(execution.final_stack.get(index), *item);
        }
    }

    #[test]
    fn host_codec_roundtrips_boundaries() {
        let p = u5_balanced_table::modulus();
        for value in [BigUint::zero(), BigUint::one(), &p - BigUint::one()] {
            let digits = u5_balanced_table::field_digits(&value);
            let words = packed_words_from_digits(&digits);
            assert_eq!(words[7] >> 31, 0);
            assert_eq!(digits_from_packed_words(&words), Some(digits));
        }

        let mut maximum_size_words = [0x8000_0000; PACKED_WORD_COUNT];
        maximum_size_words[7] = 0x7fff_fffe;
        assert!(digits_from_packed_words(&maximum_size_words).is_some());
        let serialized_size = 1 + maximum_size_words
            .iter()
            .map(|word| 1 + scriptnum_item(compressed_word_scriptnum(*word)).len())
            .sum::<usize>();
        assert_eq!(serialized_size, MAX_PACKED_WITNESS_BYTES);
    }

    #[test]
    fn strict_script_codec_roundtrips_and_preserves() {
        let p = u5_balanced_table::modulus();
        let decode_script = decode(0).compile_with_policy().to_bytes();
        let fast_decode_script = decode_fast(0).compile_with_policy().to_bytes();
        let preserving_script = decode_preserving(0).compile_with_policy().to_bytes();
        let fast_preserving_script = decode_fast_preserving(0).compile_with_policy().to_bytes();
        let encode_script = encode_from_raw_digits(0).compile_with_policy().to_bytes();
        for value in [BigUint::zero(), BigUint::one(), &p - BigUint::one()] {
            let packed = packed_value_witness_items(&value);
            let digits = u5_balanced_table::field_digits(&value);
            let expected_digits = digit_items(&digits);

            let decoded =
                execute_raw_script_with_inputs_strict(decode_script.clone(), packed.clone());
            assert_stack(&decoded, &expected_digits);

            let fast_decoded =
                execute_raw_script_with_inputs_strict(fast_decode_script.clone(), packed.clone());
            assert_stack(&fast_decoded, &expected_digits);

            let preserving =
                execute_raw_script_with_inputs_strict(preserving_script.clone(), packed.clone());
            let expected_preserving = packed
                .iter()
                .cloned()
                .chain(expected_digits.iter().cloned())
                .collect::<Vec<_>>();
            assert_stack(&preserving, &expected_preserving);

            let fast_preserving = execute_raw_script_with_inputs_strict(
                fast_preserving_script.clone(),
                packed.clone(),
            );
            assert_stack(&fast_preserving, &expected_preserving);

            let encoded =
                execute_raw_script_with_inputs_strict(encode_script.clone(), expected_digits);
            assert_stack(&encoded, &packed);
        }

        // Exercise the unique five-byte compressed-u32 item, -2^31.
        let mut special_words = [0u32; PACKED_WORD_COUNT];
        special_words[0] = 0x8000_0000;
        let special_digits = digits_from_packed_words(&special_words).unwrap();
        let special_witness = special_words
            .iter()
            .rev()
            .map(|word| scriptnum_item(compressed_word_scriptnum(*word)))
            .collect::<Vec<Vec<u8>>>();
        let special = execute_raw_script_with_inputs_strict(decode_script, special_witness.clone());
        assert_stack(&special, &digit_items(&special_digits));
        let fast_special =
            execute_raw_script_with_inputs_strict(fast_decode_script, special_witness);
        assert_stack(&fast_special, &digit_items(&special_digits));
    }

    #[test]
    fn hostile_padding_gap_and_word_alias_are_rejected() {
        let zero = BigUint::zero();
        let decode_script = decode(0).compile_with_policy().to_bytes();
        let fast_decode_script = decode_fast(0).compile_with_policy().to_bytes();
        let encode_script = encode_from_raw_digits(0).compile_with_policy().to_bytes();
        let mut padding_words = packed_words_from_digits(&u5_balanced_table::field_digits(&zero));
        padding_words[7] |= 1 << 31;
        let padding_witness = padding_words
            .iter()
            .rev()
            .map(|word| scriptnum_item(compressed_word_scriptnum(*word)))
            .collect::<Vec<Vec<u8>>>();
        let padding =
            execute_raw_script_with_inputs_strict(decode_script.clone(), padding_witness.clone());
        assert!(
            padding.error.is_some(),
            "padding bit was accepted: {padding}"
        );
        let fast_padding =
            execute_raw_script_with_inputs_strict(fast_decode_script.clone(), padding_witness);
        assert!(
            fast_padding.error.is_some(),
            "fast decoder accepted padding bit: {fast_padding}"
        );

        let mut gap = [31; FIELD_DIGIT_COUNT];
        gap[0] = 13;
        let mut gap_words = [0u32; PACKED_WORD_COUNT];
        for (index, digit) in gap.iter().enumerate() {
            let offset = 5 * index;
            gap_words[offset / 32] |= (*digit as u32) << (offset % 32);
            if offset % 32 > 27 {
                gap_words[offset / 32 + 1] |= (*digit as u32) >> (32 - offset % 32);
            }
        }
        let gap_witness = gap_words
            .iter()
            .rev()
            .map(|word| scriptnum_item(compressed_word_scriptnum(*word)))
            .collect::<Vec<Vec<u8>>>();
        let gap_result =
            execute_raw_script_with_inputs_strict(decode_script.clone(), gap_witness.clone());
        assert!(
            gap_result.error.is_some(),
            "canonical gap was accepted: {gap_result}"
        );
        let fast_gap = execute_raw_script_with_inputs_strict(fast_decode_script, gap_witness);
        assert!(
            fast_gap.error.is_some(),
            "fast decoder accepted canonical gap: {fast_gap}"
        );

        let mut aliased = packed_value_witness_items(&zero);
        aliased[PACKED_WORD_COUNT - 1] = vec![1, 2, 3, 4, 5];
        let alias_result = execute_raw_script_with_inputs_strict(decode_script, aliased);
        assert!(
            alias_result.error.is_some(),
            "word alias was accepted: {alias_result}"
        );

        let gap_encode =
            execute_raw_script_with_inputs_strict(encode_script.clone(), digit_items(&gap));
        assert!(
            gap_encode.error.is_some(),
            "raw encoder accepted the canonical gap: {gap_encode}"
        );

        let mut out_of_range = u5_balanced_table::field_digits(&zero);
        out_of_range[17] = 32;
        let range_encode =
            execute_raw_script_with_inputs_strict(encode_script, digit_items(&out_of_range));
        assert!(
            range_encode.error.is_some(),
            "raw encoder accepted digit 32: {range_encode}"
        );
    }
}
