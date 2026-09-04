//! Exact canonical-scalar validator instantiated for the 29-group Ed25519
//! schedule: eight lower width-8 groups, twenty lower width-9 groups, and one
//! top width-9 source group.
//!
//! This is not a reuse of the G31 interval constants.  It constructs the G29
//! bias offset and checks `C <= P < C+l` endpoints from that exact width vector.
//! The same eight compressed-u32 scalar words are preserved, including the
//! exact five-byte encoding of `-2^31`; no scalar bits or witness hints are
//! added.
//!
//! Run with:
//! `cargo run --locked --release --example ed25519_g29_scalar_word_validator`.

#[allow(dead_code)]
#[path = "ed25519_g31_scalar_word_validator.rs"]
mod shared;

use bitcoin::{consensus::encode::serialize, Witness};
use bitcoin_lab::support::{
    execution::execute_raw_script_with_inputs_strict,
    script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
};
use num_bigint::BigUint;
use num_traits::{One, Zero};

const PACKED_WORDS: usize = 8;
const PAYLOAD_BITS: usize = 253;
const TRANSITIONS: usize = 28;
const TRACE_ITEMS: usize = 3 * 8 * TRANSITIONS;
const QUOTIENT_HINT_ITEMS: usize = 61;
const PRESERVED_NON_SCALAR_ITEMS: usize = TRACE_ITEMS + QUOTIENT_HINT_ITEMS;
const COMPLETE_ENTRY_ITEMS: usize = PRESERVED_NON_SCALAR_ITEMS + PACKED_WORDS;

fn widths_low_to_high() -> Vec<usize> {
    let mut widths = vec![8; 8];
    widths.extend(std::iter::repeat_n(9, 20));
    widths.push(9);
    assert_eq!(widths.len(), TRANSITIONS + 1);
    assert_eq!(widths.iter().sum::<usize>(), PAYLOAD_BITS);
    widths
}

fn words_for_scalar(scalar: &BigUint) -> [u32; PACKED_WORDS] {
    shared::words_from_payload(&shared::centered_payload_for_scalar_with_widths(
        scalar,
        &widths_low_to_high(),
    ))
}

fn witness_items_from_words(words: &[u32; PACKED_WORDS]) -> Vec<Vec<u8>> {
    words
        .iter()
        .map(|word| shared::scriptnum_item(i64::from(*word as i32)))
        .collect()
}

fn complete_witness(words: &[u32; PACKED_WORDS]) -> Vec<Vec<u8>> {
    let mut witness = vec![Vec::new(); PRESERVED_NON_SCALAR_ITEMS];
    witness.extend(witness_items_from_words(words));
    assert_eq!(witness.len(), COMPLETE_ENTRY_ITEMS);
    witness
}

fn execute_accept(validator: &[u8], words: &[u32; PACKED_WORDS], label: &str) -> usize {
    let witness = complete_witness(words);
    let execution = execute_raw_script_with_inputs_strict(validator.to_vec(), witness.clone());
    assert!(
        execution.error.is_none(),
        "valid G29 scalar rejected ({label}): {execution}"
    );
    // Preserving fragment: multiple final items intentionally prevent a
    // terminal cleanstack success result.
    assert!(!execution.success);
    assert_eq!(execution.final_stack.len(), COMPLETE_ENTRY_ITEMS);
    for (index, original) in witness.iter().enumerate() {
        assert_eq!(execution.final_stack.get(index), *original, "{label}");
    }
    execution.stats.max_nb_stack_items
}

fn execute_reject_with_witness(validator: &[u8], witness: Vec<Vec<u8>>, label: &str) {
    let execution = execute_raw_script_with_inputs_strict(validator.to_vec(), witness);
    assert!(
        execution.error.is_some(),
        "hostile G29 scalar accepted ({label})"
    );
}

fn execute_reject(validator: &[u8], words: &[u32; PACKED_WORDS], label: &str) {
    execute_reject_with_witness(validator, complete_witness(words), label);
}

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
    assert_eq!(PRESERVED_NON_SCALAR_ITEMS, 733);
    assert_eq!(COMPLETE_ENTRY_ITEMS, 741);

    let widths = widths_low_to_high();
    let offset = shared::encoding_offset_for_widths(&widths);
    let order = shared::scalar_order();
    let upper_scalar = &order - BigUint::one();
    let fragment =
        shared::validate_scalar_words_for_widths_preserving(&widths, PRESERVED_NON_SCALAR_ITEMS);
    let raw_bytes = raw_fragment_len(fragment.clone());
    let policy = fragment.compile_with_policy();
    let policy_bytes = policy.len();
    let validator = policy.to_bytes();

    let mut strict_peak = execute_accept(&validator, &words_for_scalar(&BigUint::zero()), "zero");
    let upper_words = words_for_scalar(&upper_scalar);
    strict_peak = strict_peak.max(execute_accept(&validator, &upper_words, "l - 1"));

    // Exercise the sole legal five-byte u32 item, represented numerically as
    // ScriptNum -2^31.
    let offset_word_zero = shared::words_from_payload(&offset)[0];
    let special_scalar = BigUint::from(0x8000_0000u64 + (1u64 << 32) - u64::from(offset_word_zero));
    assert!(special_scalar < order);
    let special_words = words_for_scalar(&special_scalar);
    assert_eq!(special_words[0], 0x8000_0000);
    strict_peak = strict_peak.max(execute_accept(
        &validator,
        &special_words,
        "exact -2^31 word",
    ));

    execute_reject(&validator, &words_for_scalar(&order), "s = l");
    execute_reject(
        &validator,
        &shared::words_from_payload(&(offset.clone() - BigUint::one())),
        "decoded s = -1",
    );

    let mut invalid_padding = words_for_scalar(&BigUint::zero());
    invalid_padding[7] |= 1u32 << (PAYLOAD_BITS - 7 * 32);
    execute_reject(&validator, &invalid_padding, "bit 253 padding set");

    let mut redundant_sign = complete_witness(&words_for_scalar(&BigUint::zero()));
    redundant_sign[PRESERVED_NON_SCALAR_ITEMS + 7].push(0);
    execute_reject_with_witness(&validator, redundant_sign, "redundant ScriptNum sign byte");

    let mut negative_zero = complete_witness(&words_for_scalar(&BigUint::zero()));
    negative_zero[PRESERVED_NON_SCALAR_ITEMS] = vec![0x80];
    execute_reject_with_witness(&validator, negative_zero, "negative zero");

    let mut malformed_five_byte = complete_witness(&special_words);
    malformed_five_byte[PRESERVED_NON_SCALAR_ITEMS] = shared::scriptnum_item(2_147_483_648);
    execute_reject_with_witness(
        &validator,
        malformed_five_byte,
        "noncanonical positive 2^31",
    );

    let representative_witness_bytes =
        serialize(&Witness::from_slice(&complete_witness(&upper_words))).len();

    println!("model=ed25519_g29_scalar_word_validator");
    println!("layout=8_lower_w8_20_lower_w9_top_w9");
    println!("scalar_domain=0..l-1");
    println!("comparison=G29_specific_unsigned_u32_interval");
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
        "strict_peak_growth_above_complete_entry={}",
        strict_peak - COMPLETE_ENTRY_ITEMS
    );
}
