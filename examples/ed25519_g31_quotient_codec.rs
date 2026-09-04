//! Quotient packing for the sound asymmetric-R0, 31-group Ed25519 schedule.
//!
//! Thirty transitions need signed `q0/q+/q-` widths `23/21/21`.  The low 20
//! bits of `q0` share the existing two-word, 62-bit transition-local encoding
//! with `q+` and `q-`.  The remaining three high bits of every `q0` are packed
//! ten-at-a-time into three nonnegative 30-bit words.  Thus all 90 logical
//! quotients occupy exactly 63 physical hint items at script entry:
//! 60 local-pair words plus three global high-bit words.
//!
//! The global words are streamed as numeric remainders.  No high-bit word is
//! expanded to individual stack bits, and only one three-bit extension is live
//! while its local pair is decoded.  Every callback boundary has an empty
//! altstack.
//!
//! Run with:
//! `cargo run --locked --release --example ed25519_g31_quotient_codec`.

use bitcoin::{consensus::encode::serialize, Witness};
use bitcoin_lab::support::{
    execution::execute_raw_script_with_inputs_strict,
    script::{script, Script, ScriptCompilation},
};

const TRANSITIONS: usize = 30;
const RELATIONS: usize = 3;
const PAIR_WORD_BITS: usize = 31;
const PAIR_WORDS_PER_TRANSITION: usize = 2;
const LOCAL_PAIR_ITEMS: usize = TRANSITIONS * PAIR_WORDS_PER_TRANSITION;
const Q0_HIGH_BITS: usize = 3;
const Q0_HIGH_CHUNKS_PER_WORD: usize = 10;
const Q0_HIGH_WORD_BITS: usize = Q0_HIGH_BITS * Q0_HIGH_CHUNKS_PER_WORD;
const Q0_HIGH_WORDS: usize = TRANSITIONS / Q0_HIGH_CHUNKS_PER_WORD;
const PHYSICAL_HINT_ITEMS: usize = LOCAL_PAIR_ITEMS + Q0_HIGH_WORDS;
const LOGICAL_QUOTIENTS: usize = TRANSITIONS * RELATIONS;

const Q0_WIDTH: usize = 23;
const Q0_LOW_WIDTH: usize = 20;
const Q_RELATION_WIDTH: usize = 21;

// Correlation-free bounds for x*y with three-digit limbs minus K*tau with
// four-digit limbs, followed by the two conservative three-digit relations.
const Q_MIN: [i32; RELATIONS] = [-3_499_801, -584_302, -565_752];
const Q_MAX: [i32; RELATIONS] = [3_299_033, 565_752, 584_302];

const TRACE_ITEMS: usize = TRANSITIONS * 3 * 8;
const SCALAR_ITEMS: usize = 8;
const NON_HINT_ENTRY_ITEMS: usize = TRACE_ITEMS + SCALAR_ITEMS;
const COMPLETE_ENTRY_ITEMS: usize = NON_HINT_ENTRY_ITEMS + PHYSICAL_HINT_ITEMS;

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

// Exact, minimally encoded, nonnegative ScriptNum in [0, 2^31).
fn certify_u31() -> Script {
    script! {
        OP_SIZE 5 OP_LESSTHAN OP_VERIFY
        OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
        OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
    }
}

// The three q0-extension words have one spare high bit apiece. Checking the
// [0,2^30) range binds all three padding bits to zero.
fn certify_q0_high_word() -> Script {
    script! {
        { certify_u31() }
        OP_DUP 0 { 1u32 << Q0_HIGH_WORD_BITS } OP_WITHIN OP_VERIFY
    }
}

fn bits_from_altstack_to_number(width: usize) -> Script {
    assert!(width > 0);
    script! {
        OP_FROMALTSTACK
        for _ in 1..width {
            OP_DUP OP_ADD OP_FROMALTSTACK OP_ADD
        }
    }
}

// Split a certified nonnegative value at 2^low_bits. Output is `high | low`.
// Only the requested high bits are materialized, and any pre-existing
// altstack suffix is preserved.
fn split_number(low_bits: usize, high_bits: usize) -> Script {
    assert!(high_bits > 0);
    assert!(low_bits + high_bits <= PAIR_WORD_BITS);
    script! {
        for bit in (low_bits..low_bits + high_bits).rev() {
            OP_DUP { (1u32 << bit) - 1 } OP_GREATERTHAN
            OP_SWAP OP_OVER
            OP_IF { 1u32 << bit } OP_SUB OP_ENDIF
        }
        OP_TOALTSTACK
        for _ in 0..high_bits { OP_TOALTSTACK }
        { bits_from_altstack_to_number(high_bits) }
        OP_FROMALTSTACK
    }
}

fn finish_twos_complement(width: usize) -> Script {
    script! {
        OP_DUP { 1u32 << (width - 1) } OP_GREATERTHANOREQUAL
        OP_IF { 1u32 << width } OP_SUB OP_ENDIF
    }
}

/// Decode two pair words to `q0_low20 | q+ | q-`.
///
/// The current q0 high-three-bit extension remains parked below this
/// fragment's temporary altstack entries and is not consumed here.
fn decode_local_pair() -> Script {
    script! {
        // high31 = q0_low20 * 2^11 + high_11(q+_unsigned).
        { certify_u31() }
        { split_number(11, Q0_LOW_WIDTH) }

        // Pull low31 through q0_low/high_11(q+) and split it as
        // low_10(q+) * 2^21 + q-_unsigned.
        2 OP_ROLL
        { certify_u31() }
        { split_number(Q_RELATION_WIDTH, 10) }

        // Join q+'s two pieces, leaving q- nearest the top.
        OP_TOALTSTACK OP_SWAP
        for _ in 0..10 { OP_DUP OP_ADD }
        OP_ADD OP_FROMALTSTACK

        { finish_twos_complement(Q_RELATION_WIDTH) }
        OP_SWAP { finish_twos_complement(Q_RELATION_WIDTH) } OP_SWAP
    }
}

// Input has the current high-extension word/remainder nearest the top and all
// remaining pair words beneath the `high_stream_items`-item extension block.
// Output is `q0 | q+ | q-`, with q- nearest the top, and the updated extension
// block immediately beneath it.
fn decode_next_tuple(
    high_word_remaining_bits: usize,
    high_stream_items: usize,
    certify_high_word: bool,
) -> Script {
    assert!(high_word_remaining_bits >= Q0_HIGH_BITS);
    assert!(high_stream_items > 0);

    let consumes_high_word = high_word_remaining_bits == Q0_HIGH_BITS;
    let remaining_high_stream_items = high_stream_items - usize::from(consumes_high_word);
    script! {
        if certify_high_word { { certify_q0_high_word() } }

        // Keep exactly one current three-bit extension on altstack while the
        // two pair words are routed and decoded. The local decoder is balanced,
        // so this extension remains the bottom altstack item until restored.
        if consumes_high_word {
            OP_TOALTSTACK
        } else {
            { split_number(high_word_remaining_bits - Q0_HIGH_BITS, Q0_HIGH_BITS) }
            OP_SWAP OP_TOALTSTACK
        }

        // Move pair high31 then low31 above the residual high-word block.
        if remaining_high_stream_items == 0 {
            1 OP_ROLL OP_SWAP
        } else {
            { remaining_high_stream_items as u32 } OP_ROLL
            { (remaining_high_stream_items + 1) as u32 } OP_ROLL
            OP_SWAP
        }
        { decode_local_pair() }

        // Reassemble signed q0 from high3 || low20.
        2 OP_ROLL OP_FROMALTSTACK
        for _ in 0..Q0_LOW_WIDTH { OP_DUP OP_ADD }
        OP_ADD
        { finish_twos_complement(Q0_WIDTH) }
        OP_ROT OP_ROT

        // Bind all hostile values to the proved asymmetric relation bounds.
        2 OP_PICK { Q_MIN[0] } { Q_MAX[0] + 1 } OP_WITHIN OP_VERIFY
        1 OP_PICK { Q_MIN[1] } { Q_MAX[1] + 1 } OP_WITHIN OP_VERIFY
        OP_DUP { Q_MIN[2] } { Q_MAX[2] + 1 } OP_WITHIN OP_VERIFY
    }
}

fn decode_all_and_consume() -> Script {
    let mut steps = Vec::with_capacity(TRANSITIONS);
    let mut high_stream_items = Q0_HIGH_WORDS;
    let mut high_word_remaining_bits = Q0_HIGH_WORD_BITS;
    for transition in 0..TRANSITIONS {
        steps.push(script! {
            { decode_next_tuple(
                high_word_remaining_bits,
                high_stream_items,
                transition % Q0_HIGH_CHUNKS_PER_WORD == 0,
            ) }
            // Stand in for the three relation closes.
            OP_2DROP OP_DROP
        });
        high_word_remaining_bits -= Q0_HIGH_BITS;
        if high_word_remaining_bits == 0 {
            high_stream_items -= 1;
            high_word_remaining_bits = Q0_HIGH_WORD_BITS;
        }
    }
    assert_eq!(high_stream_items, 0);
    script! { for step in steps { { step } } }
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

fn packed_pair(tuple: [i32; RELATIONS]) -> [u32; PAIR_WORDS_PER_TRANSITION] {
    let q0 = encode_twos_complement(tuple[0], Q0_WIDTH);
    let q_plus = encode_twos_complement(tuple[1], Q_RELATION_WIDTH);
    let q_minus = encode_twos_complement(tuple[2], Q_RELATION_WIDTH);
    let payload = (u64::from(q0 & ((1 << Q0_LOW_WIDTH) - 1)) << (2 * Q_RELATION_WIDTH))
        | (u64::from(q_plus) << Q_RELATION_WIDTH)
        | u64::from(q_minus);
    [
        (payload >> PAIR_WORD_BITS) as u32,
        (payload & ((1u64 << PAIR_WORD_BITS) - 1)) as u32,
    ]
}

// Pair witness order is low31 | high31, so high31 is nearest the top.
fn pair_items(tuple: [i32; RELATIONS]) -> [Vec<u8>; PAIR_WORDS_PER_TRANSITION] {
    let [high, low] = packed_pair(tuple);
    [
        scriptnum_item(i64::from(low)),
        scriptnum_item(i64::from(high)),
    ]
}

fn q0_high_words(tuples: &[[i32; RELATIONS]; TRANSITIONS]) -> [u32; Q0_HIGH_WORDS] {
    std::array::from_fn(|word_index| {
        tuples[word_index * Q0_HIGH_CHUNKS_PER_WORD..(word_index + 1) * Q0_HIGH_CHUNKS_PER_WORD]
            .iter()
            .fold(0u32, |word, tuple| {
                let q0 = encode_twos_complement(tuple[0], Q0_WIDTH);
                (word << Q0_HIGH_BITS) | (q0 >> Q0_LOW_WIDTH)
            })
    })
}

fn witness_items(tuples: &[[i32; RELATIONS]; TRANSITIONS]) -> Vec<Vec<u8>> {
    let mut items = tuples
        .iter()
        .rev()
        .flat_map(|tuple| pair_items(*tuple))
        .collect::<Vec<_>>();
    items.extend(
        q0_high_words(tuples)
            .into_iter()
            .rev()
            .map(|word| scriptnum_item(i64::from(word))),
    );
    assert_eq!(items.len(), PHYSICAL_HINT_ITEMS);
    items
}

fn execute_rejection(script: &bitcoin::ScriptBuf, witness: Vec<Vec<u8>>, description: &str) {
    let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), witness);
    assert!(
        execution.error.is_some(),
        "hostile G31 quotient witness accepted: {description}"
    );
}

fn main() {
    assert_eq!(Q0_HIGH_WORD_BITS, 30);
    assert_eq!(Q0_HIGH_WORDS, 3);
    assert_eq!(PHYSICAL_HINT_ITEMS, 63);
    assert_eq!(TRACE_ITEMS, 720);
    assert_eq!(COMPLETE_ENTRY_ITEMS, 791);

    let tuples = std::array::from_fn::<_, TRANSITIONS, _>(|transition| {
        std::array::from_fn(|relation| {
            if (transition + relation) % 2 == 0 {
                Q_MAX[relation]
            } else {
                Q_MIN[relation]
            }
        })
    });
    let hint_witness = witness_items(&tuples);

    // Compare two opposite signed boundary tuples explicitly. The full codec
    // below also consumes every tuple, but range success alone would not catch
    // a permutation of otherwise in-range fields.
    let first_two = script! {
        { decode_next_tuple(30, 3, true) }
        { tuples[0][2] } OP_NUMEQUALVERIFY
        { tuples[0][1] } OP_NUMEQUALVERIFY
        { tuples[0][0] } OP_NUMEQUALVERIFY
        { decode_next_tuple(27, 3, false) }
        { tuples[1][2] } OP_NUMEQUALVERIFY
        { tuples[1][1] } OP_NUMEQUALVERIFY
        { tuples[1][0] } OP_NUMEQUALVERIFY
        for _ in 0..PHYSICAL_HINT_ITEMS - 4 { OP_DROP }
        OP_1
    }
    .compile_with_policy();
    let first_two_execution =
        execute_raw_script_with_inputs_strict(first_two.to_bytes(), hint_witness.clone());
    assert!(
        first_two_execution.error.is_none(),
        "signed G31 quotient boundaries failed: {first_two_execution}"
    );

    let codec = decode_all_and_consume().compile_with_policy();
    let executable = script! {
        { decode_all_and_consume() }
        for _ in 0..NON_HINT_ENTRY_ITEMS { OP_DROP }
        OP_1
    }
    .compile_with_policy();
    let mut complete_witness = vec![Vec::new(); NON_HINT_ENTRY_ITEMS];
    complete_witness.extend(hint_witness.clone());
    let execution =
        execute_raw_script_with_inputs_strict(executable.to_bytes(), complete_witness.clone());
    assert!(
        execution.error.is_none(),
        "G31 quotient codec failed: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);

    // The range tests run against the same complete 791-item entry boundary.
    let mut above_q0 = tuples;
    above_q0[0][0] = Q_MAX[0] + 1;
    let mut below_q0 = tuples;
    below_q0[0][0] = Q_MIN[0] - 1;
    let mut above_q_plus = tuples;
    above_q_plus[0][1] = Q_MAX[1] + 1;
    let mut below_q_minus = tuples;
    below_q_minus[0][2] = Q_MIN[2] - 1;
    for (hostile, description) in [
        (above_q0, "q0 above asymmetric bound"),
        (below_q0, "q0 below asymmetric bound"),
        (above_q_plus, "q+ above conservative bound"),
        (below_q_minus, "q- below conservative bound"),
    ] {
        let mut witness = vec![Vec::new(); NON_HINT_ENTRY_ITEMS];
        witness.extend(witness_items(&hostile));
        execute_rejection(&executable, witness, description);
    }

    // Exercise raw canonicality and the spare high-word padding bit.
    let pair0_high_index = NON_HINT_ENTRY_ITEMS + LOCAL_PAIR_ITEMS - 1;
    let high0_index = COMPLETE_ENTRY_ITEMS - 1;
    let mut negative_pair = complete_witness.clone();
    negative_pair[pair0_high_index] = scriptnum_item(-1);
    execute_rejection(&executable, negative_pair, "negative pair word");

    let mut oversized_pair = complete_witness.clone();
    oversized_pair[pair0_high_index] = scriptnum_item(1i64 << 31);
    execute_rejection(&executable, oversized_pair, "five-byte pair word");

    let mut nonminimal_pair = complete_witness.clone();
    nonminimal_pair[pair0_high_index] = vec![0];
    execute_rejection(&executable, nonminimal_pair, "nonminimal pair word");

    let mut negative_high = complete_witness.clone();
    negative_high[high0_index] = scriptnum_item(-1);
    execute_rejection(&executable, negative_high, "negative q0 high word");

    let mut padded_high = complete_witness.clone();
    padded_high[high0_index] = scriptnum_item(1i64 << Q0_HIGH_WORD_BITS);
    execute_rejection(&executable, padded_high, "nonzero q0 high padding bit");

    let mut oversized_high = complete_witness.clone();
    oversized_high[high0_index] = scriptnum_item(1i64 << 31);
    execute_rejection(&executable, oversized_high, "five-byte q0 high word");

    let mut nonminimal_high = complete_witness;
    nonminimal_high[high0_index] = vec![0];
    execute_rejection(&executable, nonminimal_high, "nonminimal q0 high word");

    println!("model=ed25519_g31_asymmetric_quotient_codec");
    println!("transitions={TRANSITIONS}");
    println!("logical_quotients={LOGICAL_QUOTIENTS}");
    println!("signed_widths_per_transition=23,21,21");
    println!("local_pair_hint_items={LOCAL_PAIR_ITEMS}");
    println!("q0_high_hint_items={Q0_HIGH_WORDS}");
    println!("physical_hint_items={PHYSICAL_HINT_ITEMS}");
    println!("all_hints_coexist_at_entry=true");
    println!("trace_items={TRACE_ITEMS}");
    println!("scalar_items={SCALAR_ITEMS}");
    println!("complete_entry_items={COMPLETE_ENTRY_ITEMS}");
    println!("decoder_script_bytes={}", codec.len());
    println!(
        "complete_hint_witness_bytes={}",
        serialize(&Witness::from_slice(&hint_witness)).len()
    );
    println!(
        "strict_max_combined_stack_items={}",
        execution.stats.max_nb_stack_items
    );
    println!(
        "strict_local_peak_items={}",
        execution.stats.max_nb_stack_items as usize - NON_HINT_ENTRY_ITEMS
    );
    println!("maximum_logical_quotients_live=3");
    println!("maximum_q0_high_extensions_live=1");
    println!("maximum_q0_high_word_remainders=1");
    println!("callback_altstack_items=0");
    println!("execution_class=unclassified");
}
