//! Exact canonical-scalar validation for the eight compressed-u32 words used
//! by the G31 direct Ed25519 scalar splitter.
//!
//! The G31 centered-window payload is order preserving.  If `C` is the
//! concatenation of every lower-window bias (26 width-8 biases followed by
//! four width-9 biases), the packed unsigned integer is exactly `C + s`.
//! Therefore `0 <= s < l` is equivalent to the single unsigned interval
//! `C <= payload < C + l`.  This validator compares the eight hostile words
//! high-to-low against both endpoints without expanding any word into bits.
//!
//! Every original word remains in place.  A picked copy is first proven to be
//! the unique ScriptNum encoding of its u32 bit pattern.  The otherwise
//! arithmetic-inaccessible word 0x80000000 is admitted only as the exact
//! five-byte ScriptNum encoding of -2^31.  Other words become `(low31, sign)`;
//! this pair permits unsigned comparison using only signed-31-bit arithmetic.
//!
//! Run this focused benchmark with:
//! `cargo run --locked --release --example ed25519_g31_scalar_word_validator`.

use bitcoin::{consensus::encode::serialize, Witness};
use bitcoin_lab::support::{
    execution::execute_raw_script_with_inputs_strict,
    script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
};
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};

const PACKED_WORDS: usize = 8;
const PAYLOAD_BITS: usize = 253;
const TRACE_ITEMS: usize = 720;
const QUOTIENT_HINT_ITEMS: usize = 61;
const PRESERVED_NON_SCALAR_ITEMS: usize = TRACE_ITEMS + QUOTIENT_HINT_ITEMS;
const COMPLETE_ENTRY_ITEMS: usize = PRESERVED_NON_SCALAR_ITEMS + PACKED_WORDS;

pub(crate) fn scalar_order() -> BigUint {
    (BigUint::one() << 252usize)
        + BigUint::parse_bytes(b"27742317777372353535851937790883648493", 10)
            .expect("Ed25519 order offset parses")
}

fn g31_widths_low_to_high() -> Vec<usize> {
    let mut widths = vec![8; 26];
    widths.extend(std::iter::repeat_n(9, 4));
    widths.push(9);
    assert_eq!(widths.iter().sum::<usize>(), PAYLOAD_BITS);
    widths
}

/// Fixed offset between a scalar and its biased centered-window payload.
pub(crate) fn encoding_offset_for_widths(widths: &[usize]) -> BigUint {
    assert!(!widths.is_empty());
    assert_eq!(widths.iter().sum::<usize>(), PAYLOAD_BITS);
    let mut offset = BigUint::zero();
    let mut bit_position = 0usize;
    for width in &widths[..widths.len() - 1] {
        offset += BigUint::one() << (bit_position + width - 1);
        bit_position += width;
    }
    assert_eq!(bit_position + widths[widths.len() - 1], PAYLOAD_BITS);
    offset
}

fn encoding_offset() -> BigUint {
    encoding_offset_for_widths(&g31_widths_low_to_high())
}

pub(crate) fn words_from_payload(payload: &BigUint) -> [u32; PACKED_WORDS] {
    assert!((payload >> (PACKED_WORDS * 32)).is_zero());
    std::array::from_fn(|index| {
        ((payload >> (32 * index)) & BigUint::from(u32::MAX))
            .to_u32()
            .expect("masked payload word fits u32")
    })
}

/// Reproduce the G31 splitter's biased centered recoding and return its packed
/// unsigned payload. Telescoping `remaining = digit + radix * next` over all
/// windows proves `payload = scalar + encoding_offset()`; the assertion makes
/// that representation identity executable for every fixture below.
pub(crate) fn centered_payload_for_scalar_with_widths(
    scalar: &BigUint,
    widths: &[usize],
) -> BigUint {
    assert_eq!(widths.iter().sum::<usize>(), PAYLOAD_BITS);
    let mut remaining = scalar.clone();
    let mut payload = BigUint::zero();
    let mut bit_position = 0usize;

    for width in &widths[..widths.len() - 1] {
        let radix = 1u32 << width;
        let bias = radix / 2;
        let residue = (&remaining & BigUint::from(radix - 1))
            .to_u32()
            .expect("window residue fits u32");
        let encoded = if residue >= bias {
            remaining += BigUint::from(radix - residue);
            residue - bias
        } else {
            remaining -= BigUint::from(residue);
            residue + bias
        };
        remaining >>= width;
        payload |= BigUint::from(encoded) << bit_position;
        bit_position += width;
    }

    assert!(remaining < (BigUint::one() << 9usize));
    payload |= remaining << bit_position;
    assert_eq!(payload, encoding_offset_for_widths(widths) + scalar);
    payload
}

fn centered_payload_for_scalar(scalar: &BigUint) -> BigUint {
    centered_payload_for_scalar_with_widths(scalar, &g31_widths_low_to_high())
}

fn words_for_scalar(scalar: &BigUint) -> [u32; PACKED_WORDS] {
    words_from_payload(&centered_payload_for_scalar(scalar))
}

pub(crate) fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn witness_items_from_words(words: &[u32; PACKED_WORDS]) -> Vec<Vec<u8>> {
    words
        .iter()
        .map(|word| scriptnum_item(i64::from(*word as i32)))
        .collect()
}

fn complete_witness(words: &[u32; PACKED_WORDS]) -> Vec<Vec<u8>> {
    let mut witness = vec![Vec::new(); PRESERVED_NON_SCALAR_ITEMS];
    witness.extend(witness_items_from_words(words));
    assert_eq!(witness.len(), COMPLETE_ENTRY_ITEMS);
    witness
}

/// Consume one picked compressed-u32 word and return `low31 | sign_bit`.
///
/// The exact-encoding check makes the u32 representation unique even when the
/// execution harness does not enforce MINIMALDATA.  A five-byte item is valid
/// only when it is byte-for-byte the ScriptNum encoding of -2^31.  That value
/// is never passed to a numeric opcode.  For every negative four-byte value,
/// the two additions stay in `[0, 2^31-1]`.
fn exact_word_to_low31_and_sign() -> Script {
    script! {
        // Test the sole arithmetic-inaccessible value by raw-byte equality.
        // Every other five-or-more-byte item reaches a numeric opcode below
        // and fails; exact items of at most four bytes re-encode canonically.
        OP_DUP { -2_147_483_648i64 } OP_EQUAL
        OP_IF
            OP_DROP 0 1
        OP_ELSE
            // Re-encoding through `+ 0` must reproduce the hostile bytes.
            OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
            OP_DUP 0 OP_LESSTHAN
            OP_IF
                { i32::MAX } OP_ADD OP_1ADD 1
            OP_ELSE
                0
            OP_ENDIF
        OP_ENDIF
    }
}

/// Map a safe signed difference to -1, 0, or 1.
fn normalize_relation() -> Script {
    script! {
        OP_DUP 0 OP_LESSTHAN
        OP_IF OP_DROP -1 OP_ELSE OP_0NOTEQUAL OP_ENDIF
    }
}

/// Compare an unsigned u32 pair with a constant.
///
/// Before: `low31 | sign_bit`; after: `relation`, where relation is -1, 0,
/// or 1.  Equal sign halves are compared by subtracting low31 values, whose
/// difference is always within ScriptNum's signed-32-bit arithmetic range.
fn unsigned_pair_relation(constant: u32) -> Script {
    let constant_sign = constant >> 31;
    let constant_low = constant & i32::MAX as u32;
    if constant_sign == 0 {
        script! {
            OP_IF
                OP_DROP 1
            OP_ELSE
                { constant_low } OP_SUB { normalize_relation() }
            OP_ENDIF
        }
    } else {
        script! {
            OP_IF
                { constant_low } OP_SUB { normalize_relation() }
            OP_ELSE
                OP_DROP -1
            OP_ENDIF
        }
    }
}

/// Before: `word_relation | old_relation`; after: `new_relation`.
/// Once an earlier, more-significant word differs, it remains decisive.
fn merge_lexicographic_relation() -> Script {
    script! {
        OP_DUP OP_NOT
        OP_IF
            OP_DROP
        OP_ELSE
            OP_SWAP OP_DROP
        OP_ENDIF
    }
}

/// Consume one decoded word into lower- and upper-endpoint relation states.
///
/// Before: `low_state | high_state | low31 | sign_bit`; after:
/// `new_low_state | new_high_state`.
fn consume_word_for_interval(lower: u32, upper: u32) -> Script {
    script! {
        // Compare a duplicate pair with the exclusive upper endpoint.
        OP_2DUP
        { unsigned_pair_relation(upper) }
        3 OP_ROLL
        { merge_lexicographic_relation() }
        OP_TOALTSTACK

        // Compare the original pair with the inclusive lower endpoint.
        { unsigned_pair_relation(lower) }
        OP_SWAP
        { merge_lexicographic_relation() }
        OP_FROMALTSTACK
    }
}

/// Validate `C <= payload < C + l` while leaving all eight words untouched.
///
/// Before and after: `preserved | word[0] .. word[7]`.  There are no witness
/// hints.  Every word is certified even after a more-significant comparison
/// has decided the relation.
pub(crate) fn validate_scalar_words_for_widths_preserving(
    widths: &[usize],
    preserved_items: usize,
) -> Script {
    assert_eq!(widths.iter().sum::<usize>(), PAYLOAD_BITS);
    let offset = encoding_offset_for_widths(widths);
    let lower = words_from_payload(&offset);
    let upper_value = offset + scalar_order();
    assert!((&upper_value >> PAYLOAD_BITS).is_zero());
    let upper = words_from_payload(&upper_value);

    // The exclusive upper endpoint is below 2^253.  Consequently any set bit
    // in top padding positions 253..255 compares above it and is rejected.
    assert!(upper[7] < (1u32 << (PAYLOAD_BITS - 7 * 32)));
    assert!(preserved_items + PACKED_WORDS + 16 <= 1_000);

    script! {
        // Three-way relations to the inclusive lower and exclusive upper
        // endpoints, initially equal at the empty prefix.
        0 0
        for word_index in (0..PACKED_WORDS).rev() {
            // The originals never move; only the two relation states sit above
            // them.  Word seven is therefore at depth two.
            { (2 + PACKED_WORDS - 1 - word_index) as u32 } OP_PICK
            { exact_word_to_low31_and_sign() }
            { consume_word_for_interval(lower[word_index], upper[word_index]) }
        }

        // payload < C+l and payload >= C.
        0 OP_LESSTHAN OP_VERIFY
        0 OP_GREATERTHANOREQUAL OP_VERIFY
    }
}

fn validate_g31_scalar_words_preserving(preserved_items: usize) -> Script {
    validate_scalar_words_for_widths_preserving(&g31_widths_low_to_high(), preserved_items)
}

fn execute_accept(validator_bytes: &[u8], words: &[u32; PACKED_WORDS], description: &str) -> usize {
    let witness = complete_witness(words);
    let execution =
        execute_raw_script_with_inputs_strict(validator_bytes.to_vec(), witness.clone());
    assert!(
        execution.error.is_none(),
        "valid scalar rejected ({description}): {execution}"
    );
    // This is deliberately a preserving fragment, not a terminal locking
    // script. Lack of cleanstack makes `success` false while `error == None`
    // certifies that every opcode and terminal VERIFY completed.
    assert!(!execution.success);
    assert_eq!(execution.final_stack.len(), COMPLETE_ENTRY_ITEMS);
    for (index, original) in witness.iter().enumerate() {
        assert_eq!(execution.final_stack.get(index), *original);
    }
    execution.stats.max_nb_stack_items
}

fn execute_reject_with_witness(validator_bytes: &[u8], witness: Vec<Vec<u8>>, description: &str) {
    let execution = execute_raw_script_with_inputs_strict(validator_bytes.to_vec(), witness);
    assert!(
        execution.error.is_some(),
        "hostile scalar accepted ({description})"
    );
}

fn execute_reject(validator_bytes: &[u8], words: &[u32; PACKED_WORDS], description: &str) {
    execute_reject_with_witness(validator_bytes, complete_witness(words), description);
}

/// Measure raw bytes through the central policy without directly invoking an
/// upstream compiler: repetition crosses the 32-KiB cutoff, so policy returns
/// the unoptimized concatenation.  Division recovers one fragment exactly.
fn raw_fragment_len(fragment: Script) -> usize {
    const COPIES: usize = 128;
    let repeated = script! {
        for _ in 0..COPIES { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % COPIES, 0);
    repeated.len() / COPIES
}

fn main() {
    let order = scalar_order();
    let zero = BigUint::zero();
    let order_minus_one = &order - BigUint::one();
    let validator = validate_g31_scalar_words_preserving(PRESERVED_NON_SCALAR_ITEMS);
    let raw_bytes = raw_fragment_len(validator.clone());
    let policy_validator = validator.compile_with_policy();
    let policy_bytes = policy_validator.len();
    let validator_bytes = policy_validator.to_bytes();

    // Accept both interval endpoints.
    let mut strict_peak = execute_accept(&validator_bytes, &words_for_scalar(&zero), "zero");
    let upper_words = words_for_scalar(&order_minus_one);
    strict_peak = strict_peak.max(execute_accept(&validator_bytes, &upper_words, "l - 1"));

    // Exercise the only legal five-byte compressed word.  Choosing this
    // scalar makes payload word zero exactly 0x80000000 after the fixed offset.
    let offset_word_zero = words_from_payload(&encoding_offset())[0];
    let special_scalar = BigUint::from(0x8000_0000u64 + (1u64 << 32) - u64::from(offset_word_zero));
    let special_words = words_for_scalar(&special_scalar);
    assert_eq!(special_words[0], 0x8000_0000);
    strict_peak = strict_peak.max(execute_accept(
        &validator_bytes,
        &special_words,
        "exact -2^31 word",
    ));

    // The exclusive endpoint itself is not canonical.
    execute_reject(&validator_bytes, &words_for_scalar(&order), "s = l");

    // The payload immediately below the fixed offset decodes to s = -1.
    let below_lower = encoding_offset() - BigUint::one();
    execute_reject(
        &validator_bytes,
        &words_from_payload(&below_lower),
        "decoded s = -1",
    );

    // Setting the first padding bit creates a payload at least 2^253, above
    // the exclusive endpoint.  This isolates structural top-padding rejection.
    let mut invalid_padding = words_for_scalar(&zero);
    invalid_padding[7] |= 1u32 << (PAYLOAD_BITS - 7 * 32);
    execute_reject(&validator_bytes, &invalid_padding, "bit 253 padding set");

    // A redundant top sign byte denotes the same numeric word but must not be
    // another accepted encoding.
    let mut redundant_sign = complete_witness(&words_for_scalar(&zero));
    redundant_sign[PRESERVED_NON_SCALAR_ITEMS + 7].push(0);
    execute_reject_with_witness(
        &validator_bytes,
        redundant_sign,
        "redundant ScriptNum sign byte",
    );

    // Negative zero is numerically zero but is not a unique ScriptNum.
    let mut negative_zero = complete_witness(&words_for_scalar(&zero));
    negative_zero[PRESERVED_NON_SCALAR_ITEMS] = vec![0x80];
    execute_reject_with_witness(&validator_bytes, negative_zero, "negative zero");

    // A five-byte positive 2^31 is not the exact compressed encoding of the
    // u32 word with only its sign bit set.
    let mut malformed_five_byte = complete_witness(&special_words);
    malformed_five_byte[PRESERVED_NON_SCALAR_ITEMS] = scriptnum_item(2_147_483_648);
    execute_reject_with_witness(
        &validator_bytes,
        malformed_five_byte,
        "noncanonical five-byte word",
    );

    let representative_witness_bytes =
        serialize(&Witness::from_slice(&complete_witness(&upper_words))).len();

    println!("model=ed25519_g31_scalar_word_validator");
    println!("scalar_domain=0..l-1");
    println!("comparison=unsigned_u32_lexicographic_interval");
    println!("decomposed_scalar_bits=0");
    println!("physical_scalar_items={PACKED_WORDS}");
    println!("validator_incremental_hint_items=0");
    println!("preserved_trace_items={TRACE_ITEMS}");
    println!("preserved_quotient_hint_items={QUOTIENT_HINT_ITEMS}");
    println!("preserved_non_scalar_items={PRESERVED_NON_SCALAR_ITEMS}");
    println!("complete_entry_items={COMPLETE_ENTRY_ITEMS}");
    println!("validator_raw_script_bytes={raw_bytes}");
    println!("validator_policy_script_bytes={policy_bytes}");
    println!("representative_complete_witness_bytes={representative_witness_bytes}");
    println!("strict_max_combined_stack_items={strict_peak}");
    println!(
        "validator_peak_delta_items={}",
        strict_peak - COMPLETE_ENTRY_ITEMS
    );
    println!("exact_minus_2_pow_31_word_accepted=true");
    println!("rejects_s_equal_l=true");
    println!("rejects_decoded_s_equal_minus_one=true");
    println!("rejects_nonminimal_scriptnums=true");
    println!("rejects_invalid_top_padding=true");
    println!("fragment_preserves_all_entry_items=true");
    println!("terminal_cleanstack_predicate=required_from_caller");
    println!("execution_class=unclassified");
}
