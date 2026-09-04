//! Lazy fixed-width quotient codec for the conservative Ed25519 affine trace.
//!
//! The three quotient-only relations in each transition have the proved
//! bounds
//!
//! ```text
//! |q0| <= 287_514  (signed 20-bit two's complement)
//! |q+| <= 584_302  (signed 21-bit two's complement)
//! |q-| <= 584_302  (signed 21-bit two's complement)
//! ```
//!
//! Twenty-eight tuples therefore occupy 1,736 bits, or 55 compressed-u32
//! witness items with 24 checked zero-padding bits.  This model decodes
//! only far enough to produce one three-quotient tuple, rotates any already
//! decoded prefix of the following tuple underneath it, consumes the current
//! tuple, and resumes.  It never materializes all 84 logical quotients.
//!
//! Run with:
//! `cargo run --locked --release --example ed25519_lazy_quotient_codec`.

use bitcoin::{consensus::encode::serialize, Witness};
use bitcoin_lab::{
    arithmetic::{u31::u31_to_bits_with_width, u32::stack::u32_uncompress},
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
    },
};

const TRANSITIONS: usize = 28;
const WIDTHS: [usize; 3] = [20, 21, 21];
const QUOTIENTS: usize = TRANSITIONS * WIDTHS.len();
const PAYLOAD_BITS: usize = TRANSITIONS * (WIDTHS[0] + WIDTHS[1] + WIDTHS[2]);
const PACKED_WORDS: usize = PAYLOAD_BITS.div_ceil(32);
const PADDING_BITS: usize = PACKED_WORDS * 32 - PAYLOAD_BITS;
const HINT_ITEMS: usize = PACKED_WORDS;

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn compressed_word_scriptnum(word: u32) -> i64 {
    i64::from(word as i32)
}

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

// Consumes one exact compressed word and leaves its most-significant bit
// nearest the top of altstack.  OP_FROMALTSTACK therefore streams MSB first.
fn word_to_alt_bits() -> Script {
    script! {
        { certify_exact_compressed_word() }
        { u32_uncompress() }
        for _ in 0..4 {
            { u31_to_bits_with_width(8) }
            for _ in 0..8 { OP_TOALTSTACK }
        }
    }
}

fn finish_twos_complement(width: usize) -> Script {
    script! {
        OP_DUP { 1u32 << (width - 1) } OP_GREATERTHANOREQUAL
        OP_IF { 1u32 << width } OP_SUB OP_ENDIF
    }
}

fn append_bit(first: bool) -> Script {
    if first {
        script! { OP_FROMALTSTACK }
    } else {
        script! { OP_DUP OP_ADD OP_FROMALTSTACK OP_ADD }
    }
}

// Rotate the three just-completed quotients above zero, one, or two already
// decoded items belonging to the following tuple.  Then stand in for the
// three relation verifiers by consuming exactly those quotient items.
fn consume_tuple(carry_items: usize) -> Script {
    assert!(carry_items <= 2);
    script! {
        if carry_items != 0 {
            for _ in 0..3 { { (carry_items + 2) as u32 } OP_ROLL }
        }
        OP_2DROP OP_DROP
    }
}

/// Consume all 55 physical hint items while exposing only one tuple at each
/// fragment boundary.  Word-boundary spill from the next tuple is retained as
/// at most two numeric items.  The padding bits are independently checked.
fn decode_lazily_and_consume() -> Script {
    let mut output = Script::new("lazy quotient stream");
    let mut quotient_index = 0usize;
    let mut bits_in_quotient = 0usize;
    let mut completed_in_tuple = 0usize;
    let mut carry_items = 0usize;

    for word_index in 0..PACKED_WORDS {
        output = script! {
            { output }
            if carry_items != 0 { { carry_items as u32 } OP_ROLL }
            { word_to_alt_bits() }
        };

        let mut tuple_completed_in_word = false;
        for bit_in_word in 0..32 {
            let global_bit = word_index * 32 + bit_in_word;
            if global_bit >= PAYLOAD_BITS {
                output = script! { { output } OP_FROMALTSTACK OP_NOT OP_VERIFY };
                continue;
            }

            output = script! {
                { output }
                { append_bit(bits_in_quotient == 0) }
            };
            bits_in_quotient += 1;
            let width = WIDTHS[quotient_index % WIDTHS.len()];
            if bits_in_quotient == width {
                output = script! { { output } { finish_twos_complement(width) } };
                quotient_index += 1;
                completed_in_tuple += 1;
                bits_in_quotient = 0;
                if completed_in_tuple == WIDTHS.len() {
                    // A 32-bit word cannot contain two 74-bit tuple endings,
                    // so deferring consumption to the end of the word is safe.
                    assert!(!tuple_completed_in_word);
                    tuple_completed_in_word = true;
                    completed_in_tuple = 0;
                }
            }
        }

        carry_items = completed_in_tuple + usize::from(bits_in_quotient != 0);
        // Before the current tuple completes this may be q0, q+, and a
        // partial q-.  After a tuple completes, at most two items belong to
        // the following tuple and are passed to consume_tuple.
        assert!(carry_items <= 3);
        if tuple_completed_in_word {
            assert!(carry_items <= 2);
            output = script! { { output } { consume_tuple(carry_items) } };
        }
    }

    assert_eq!(quotient_index, QUOTIENTS);
    assert_eq!(bits_in_quotient, 0);
    assert_eq!(completed_in_tuple, 0);
    assert_eq!(carry_items, 0);
    output
}

fn encode_twos_complement(value: i32, width: usize) -> u32 {
    let minimum = -(1i64 << (width - 1));
    let maximum = (1i64 << (width - 1)) - 1;
    assert!((minimum..=maximum).contains(&i64::from(value)));
    if value < 0 {
        ((1i64 << width) + i64::from(value)) as u32
    } else {
        value as u32
    }
}

fn packed_words(values: &[[i32; 3]; TRANSITIONS]) -> [u32; PACKED_WORDS] {
    let mut bits = Vec::with_capacity(PACKED_WORDS * 32);
    for tuple in values {
        for (value, width) in tuple.iter().copied().zip(WIDTHS) {
            let encoded = encode_twos_complement(value, width);
            for shift in (0..width).rev() {
                bits.push((encoded >> shift) & 1);
            }
        }
    }
    bits.extend(std::iter::repeat_n(0, PADDING_BITS));
    assert_eq!(bits.len(), PACKED_WORDS * 32);
    std::array::from_fn(|word_index| {
        bits[word_index * 32..word_index * 32 + 32]
            .iter()
            .fold(0u32, |word, bit| (word << 1) | bit)
    })
}

// The first serialized word must be nearest the top at execution entry.
fn witness_items(values: &[[i32; 3]; TRANSITIONS]) -> Vec<Vec<u8>> {
    packed_words(values)
        .into_iter()
        .rev()
        .map(|word| scriptnum_item(compressed_word_scriptnum(word)))
        .collect()
}

fn main() {
    assert_eq!(PAYLOAD_BITS, 1_736);
    assert_eq!(PACKED_WORDS, 55);
    assert_eq!(PADDING_BITS, 24);

    let limits = [287_514, 584_302, 584_302];
    let values = std::array::from_fn(|transition| {
        std::array::from_fn(|relation| {
            if (transition + relation) % 2 == 0 {
                limits[relation]
            } else {
                -limits[relation]
            }
        })
    });
    let witness = witness_items(&values);
    assert_eq!(witness.len(), HINT_ITEMS);

    let codec = decode_lazily_and_consume().compile_with_policy();
    assert!(codec.len() > MAX_OPTIMIZER_INPUT_BYTES);
    let executable =
        script! { { codec.clone() } OP_DEPTH 0 OP_NUMEQUALVERIFY OP_1 }.compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(executable.to_bytes(), witness.clone());
    assert!(
        execution.error.is_none(),
        "lazy quotient codec failed: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);

    println!("model=ed25519_lazy_affine_quotient_codec");
    println!("relations_per_transition={}", WIDTHS.len());
    println!("transitions={TRANSITIONS}");
    println!("logical_quotients={QUOTIENTS}");
    println!(
        "signed_widths_per_transition={},{},{}",
        WIDTHS[0], WIDTHS[1], WIDTHS[2]
    );
    println!("payload_bits={PAYLOAD_BITS}");
    println!("checked_padding_bits={PADDING_BITS}");
    println!("physical_hint_items={HINT_ITEMS}");
    println!("locking_script_bytes={}", codec.len());
    println!("locking_script_optimized=false");
    println!(
        "complete_hint_witness_bytes={}",
        serialize(&Witness::from_slice(&witness)).len()
    );
    println!(
        "strict_max_combined_stack_items={}",
        execution.stats.max_nb_stack_items
    );
    println!("maximum_logical_quotients_live=3");
    println!("maximum_incomplete_tuple_items=3");
    println!("maximum_next_tuple_carry_items=2");
    println!("execution_class=unclassified");
}
