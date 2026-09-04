//! Transition-local quotient packing for a conservative Ed25519 affine trace.
//!
//! Each transition's signed 20/21/21-bit quotient tuple is exactly 62 bits,
//! stored as two nonnegative 31-bit ScriptNums.  All 56 physical hint items
//! coexist at script entry, but only the next pair is decoded, immediately
//! consumed by its three relation checks, and then followed by the next pair.
//! This avoids both the 84-item unpacked witness and cross-transition bit
//! buffering.
//!
//! Run with:
//! `cargo run --locked --release --example ed25519_paired_quotient_codec`.

use bitcoin::{consensus::encode::serialize, Witness};
use bitcoin_lab::support::{
    execution::execute_raw_script_with_inputs_strict,
    script::{script, Script, ScriptCompilation},
};

const TRANSITIONS: usize = 28;
const WIDTHS: [usize; 3] = [20, 21, 21];
const WORD_BITS: usize = 31;
const WORDS_PER_TRANSITION: usize = 2;
const PHYSICAL_HINT_ITEMS: usize = TRANSITIONS * WORDS_PER_TRANSITION;
const LOGICAL_QUOTIENTS: usize = TRANSITIONS * WIDTHS.len();
const LIMITS: [i32; 3] = [287_514, 584_302, 584_302];

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

// The numeric path itself bounds a nonnegative four-byte ScriptNum by
// 2^31-1. The raw round trip additionally rejects negative zero, redundant
// sign bytes, and other aliases when interpreter flags do not.
fn certify_u31() -> Script {
    script! {
        OP_SIZE 5 OP_LESSTHAN OP_VERIFY
        OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
        OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
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

// Split a certified nonnegative `total_bits` value at 2^low_bits. Output is
// `high | low`. Only the high portion is decomposed, saving 32 comparison
// rounds per tuple versus expanding both complete 31-bit words.
fn split_number(low_bits: usize, high_bits: usize) -> Script {
    assert!(low_bits + high_bits <= WORD_BITS);
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

/// Decode the next two physical hint items into `q0 | q+ | q-`.
///
/// Input has the first 31-bit half nearest the top. Output has `q-` nearest
/// the top. The fragment uses no additional witness hints.
fn decode_next_tuple() -> Script {
    script! {
        // high31 = q0_unsigned * 2^11 + high_11(q+_unsigned).
        { certify_u31() }
        { split_number(11, 20) }

        // Pull low31 through q0/high_11(q+) and split it as
        // low_10(q+) * 2^21 + q-_unsigned.
        2 OP_ROLL
        { certify_u31() }
        { split_number(21, 10) }

        // Join q+'s two pieces. Keep q- aside so the public output order is
        // q0 | q+ | q-, with q- nearest the top.
        OP_TOALTSTACK OP_SWAP
        for _ in 0..10 { OP_DUP OP_ADD }
        OP_ADD OP_FROMALTSTACK

        // Interpret all three fixed-width values as two's complement.
        { finish_twos_complement(21) }
        OP_SWAP { finish_twos_complement(21) } OP_SWAP
        2 OP_ROLL { finish_twos_complement(20) }
        OP_ROT OP_ROT

        // Bind the physical packing to the proved conservative relation
        // bounds, rather than merely the wider two's-complement domains.
        2 OP_PICK { -LIMITS[0] } { LIMITS[0] + 1 } OP_WITHIN OP_VERIFY
        1 OP_PICK { -LIMITS[1] } { LIMITS[1] + 1 } OP_WITHIN OP_VERIFY
        OP_DUP { -LIMITS[2] } { LIMITS[2] + 1 } OP_WITHIN OP_VERIFY
    }
}

fn encode_twos_complement(value: i32, width: usize) -> u64 {
    let minimum = -(1i64 << (width - 1));
    let maximum = (1i64 << (width - 1)) - 1;
    assert!((minimum..=maximum).contains(&i64::from(value)));
    if value < 0 {
        ((1i64 << width) + i64::from(value)) as u64
    } else {
        value as u64
    }
}

fn packed_pair(tuple: [i32; 3]) -> [u32; 2] {
    let mut payload = 0u64;
    for (value, width) in tuple.into_iter().zip(WIDTHS) {
        payload = (payload << width) | encode_twos_complement(value, width);
    }
    [
        (payload >> WORD_BITS) as u32,
        (payload & ((1u64 << WORD_BITS) - 1)) as u32,
    ]
}

// Script entry order for one tuple is `low31 | high31`, so high31 is top.
fn pair_items(tuple: [i32; 3]) -> [Vec<u8>; 2] {
    let [high, low] = packed_pair(tuple);
    [
        scriptnum_item(i64::from(low)),
        scriptnum_item(i64::from(high)),
    ]
}

fn expect_rejection(items: Vec<Vec<u8>>, description: &str) {
    let script = script! { { decode_next_tuple() } OP_2DROP OP_DROP OP_1 }.compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), items);
    assert!(
        execution.error.is_some(),
        "hostile tuple accepted: {description}"
    );
}

fn main() {
    let tuples = std::array::from_fn::<_, TRANSITIONS, _>(|transition| {
        std::array::from_fn(|relation| {
            if (transition + relation) % 2 == 0 {
                LIMITS[relation]
            } else {
                -LIMITS[relation]
            }
        })
    });

    // Last transition is deepest; transition zero's high half is initially
    // nearest the top and can be decoded without a global rearrangement.
    let witness = tuples
        .iter()
        .rev()
        .flat_map(|tuple| pair_items(*tuple))
        .collect::<Vec<_>>();
    assert_eq!(witness.len(), PHYSICAL_HINT_ITEMS);

    for (index, item) in witness.iter().enumerate() {
        let certification = script! { { certify_u31() } OP_DROP OP_1 }.compile_with_policy();
        let checked =
            execute_raw_script_with_inputs_strict(certification.to_bytes(), vec![item.clone()]);
        assert!(
            checked.error.is_none(),
            "u31 item {index} failed: {checked}"
        );
    }

    let tuple_decoder = decode_next_tuple().compile_with_policy();
    let all_decoders = script! {
        for _ in 0..TRANSITIONS {
            { decode_next_tuple() }
            // Stand in for q0/q+/q- relation closes.
            OP_2DROP OP_DROP
        }
        OP_DEPTH 0 OP_NUMEQUALVERIFY OP_1
    }
    .compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(all_decoders.to_bytes(), witness.clone());
    assert!(
        execution.error.is_none(),
        "paired quotient codec failed: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);

    // Independently check the signed boundary tuple instead of merely
    // checking that the repeated consumer empties its stack.
    let boundary = [-LIMITS[0], LIMITS[1], -LIMITS[2]];
    let boundary_script = script! {
        { decode_next_tuple() }
        { boundary[2] } OP_NUMEQUALVERIFY
        { boundary[1] } OP_NUMEQUALVERIFY
        { boundary[0] } OP_NUMEQUALVERIFY
        OP_1
    }
    .compile_with_policy();
    let boundary_execution = execute_raw_script_with_inputs_strict(
        boundary_script.to_bytes(),
        pair_items(boundary).into_iter().collect(),
    );
    assert!(
        boundary_execution.error.is_none(),
        "signed boundary failed: {boundary_execution}"
    );

    // The physical halves are nonnegative, exact, at-most-four-byte
    // ScriptNums. Exercise each rejection independently.
    let mut negative_word = pair_items([0, 0, 0]).to_vec();
    negative_word[1] = scriptnum_item(-1);
    expect_rejection(negative_word, "negative high31 word");

    let mut oversized_word = pair_items([0, 0, 0]).to_vec();
    oversized_word[1] = scriptnum_item(1i64 << 31);
    expect_rejection(oversized_word, "five-byte high31 word");

    let mut nonminimal_word = pair_items([0, 0, 0]).to_vec();
    nonminimal_word[1] = vec![0];
    expect_rejection(nonminimal_word, "nonminimal zero high31 word");

    expect_rejection(
        pair_items([LIMITS[0] + 1, 0, 0]).to_vec(),
        "q0 above proved conservative bound",
    );
    expect_rejection(
        pair_items([0, -(LIMITS[1] + 1), 0]).to_vec(),
        "q+ below proved conservative bound",
    );

    println!("model=ed25519_transition_local_quotient_codec");
    println!("transitions={TRANSITIONS}");
    println!("logical_quotients={LOGICAL_QUOTIENTS}");
    println!(
        "signed_widths_per_transition={},{},{}",
        WIDTHS[0], WIDTHS[1], WIDTHS[2]
    );
    println!("physical_hint_items={PHYSICAL_HINT_ITEMS}");
    println!("tuple_decoder_bytes={}", tuple_decoder.len());
    println!("all_tuple_decoder_bytes={}", all_decoders.len() - 4);
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
    println!("execution_class=unclassified");
}
