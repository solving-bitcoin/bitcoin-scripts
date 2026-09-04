//! Physical-item-optimal quotient packing for the asymmetric-R0 G31 model.
//!
//! One transition needs signed `q0/q+/q-` widths `23/21/21`, or 65 bits.
//! Two exact compressed-u32 ScriptNums carry the low 64 bits.  One bit per
//! transition is streamed from a single exact nonnegative 30-bit word.  Thus
//! all 90 logical quotients occupy exactly 61 physical hint items at entry.
//!
//! Run with:
//! `cargo run --locked --release --example ed25519_g31_u32_quotient_codec`.

use bitcoin::{consensus::encode::serialize, Witness};
use bitcoin_lab::support::{
    execution::execute_raw_script_with_inputs_strict,
    script::{script, Script, ScriptCompilation},
};

const TRANSITIONS: usize = 30;
const RELATIONS: usize = 3;
const LOCAL_WORDS_PER_TRANSITION: usize = 2;
const LOCAL_WORD_ITEMS: usize = TRANSITIONS * LOCAL_WORDS_PER_TRANSITION;
const GLOBAL_HIGH_ITEMS: usize = 1;
const PHYSICAL_HINT_ITEMS: usize = LOCAL_WORD_ITEMS + GLOBAL_HIGH_ITEMS;
const LOGICAL_QUOTIENTS: usize = TRANSITIONS * RELATIONS;

const Q0_WIDTH: usize = 23;
const Q_RELATION_WIDTH: usize = 21;
const Q0_LOCAL_BITS: usize = 22;
const GLOBAL_HIGH_BITS: usize = TRANSITIONS;

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

fn compressed_word_scriptnum(word: u32) -> i64 {
    i64::from(word as i32)
}

// Keep one word only if its bytes are the unique compressed-u32 encoding.
// Canonical -2^31 is the only five-byte value accepted by four-byte numeric
// operations, and is compared before any such operation runs.
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

fn certify_global_high_word() -> Script {
    script! {
        OP_SIZE 5 OP_LESSTHAN OP_VERIFY
        OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
        OP_DUP 0 { 1u32 << GLOBAL_HIGH_BITS } OP_WITHIN OP_VERIFY
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

// Split a nonnegative at-most-31-bit number into `high | low`.
fn split_number(low_bits: usize, high_bits: usize) -> Script {
    assert!(high_bits > 0 && low_bits + high_bits <= 31);
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

// Input is an exact compressed-u32 ScriptNum. Output is `low31 | bit31`.
fn compressed_word_to_low31_and_sign() -> Script {
    script! {
        { certify_exact_compressed_word() }
        OP_DUP 0 OP_LESSTHAN
        OP_IF
            { i32::MAX } OP_ADD OP_1ADD 1
        OP_ELSE
            0
        OP_ENDIF
    }
}

fn finish_twos_complement(width: usize) -> Script {
    script! {
        OP_DUP { 1u32 << (width - 1) } OP_GREATERTHANOREQUAL
        OP_IF { 1u32 << width } OP_SUB OP_ENDIF
    }
}

/// Decode the two local compressed words plus the current global high bit.
///
/// Entry, above any preserved items, is `high32 | low32 | q0_bit22`; the
/// q0 bit is nearest the top and parked below balanced decoder temporaries.
/// Exit is `q0 | q+ | q-`, with q- nearest the top and an empty altstack.
fn decode_local_tuple() -> Script {
    script! {
        // Retain q0 bit 22 while decoding the low physical word.
        OP_TOALTSTACK
        { compressed_word_to_low31_and_sign() }
        // low31[0..20] is q-; low31[21..30] and bit31 form q+[0..10].
        OP_TOALTSTACK
        { split_number(21, 10) }
        OP_FROMALTSTACK
        OP_TOALTSTACK OP_SWAP
        OP_FROMALTSTACK
        for _ in 0..10 { OP_DUP OP_ADD }
        OP_ADD

        // Decode the high physical word through the two completed low parts.
        2 OP_ROLL
        { compressed_word_to_low31_and_sign() }
        // high31[0..9] is q+[11..20]; high31[10..30] and bit31 are
        // q0[0..21].
        OP_TOALTSTACK
        { split_number(10, 21) }

        // Join q+ high10 || low11.
        2 OP_ROLL OP_SWAP
        for _ in 0..11 { OP_DUP OP_ADD }
        OP_ADD

        // Join the high word's sign bit to q0 low21 while q+ stays live on
        // main stack. The global q0 bit remains below the sign bit on alt.
        OP_SWAP
        OP_FROMALTSTACK
        for _ in 0..21 { OP_DUP OP_ADD }
        OP_ADD

        // Join the one-bit global extension to q0 low22.
        OP_FROMALTSTACK
        for _ in 0..22 { OP_DUP OP_ADD }
        OP_ADD

        // Stack is q- | q+_unsigned | q0_unsigned. Rotate to public order.
        OP_ROT OP_ROT OP_SWAP
        { finish_twos_complement(Q_RELATION_WIDTH) }
        OP_SWAP { finish_twos_complement(Q_RELATION_WIDTH) } OP_SWAP
        2 OP_ROLL { finish_twos_complement(Q0_WIDTH) }
        OP_ROT OP_ROT

        2 OP_PICK { Q_MIN[0] } { Q_MAX[0] + 1 } OP_WITHIN OP_VERIFY
        1 OP_PICK { Q_MIN[1] } { Q_MAX[1] + 1 } OP_WITHIN OP_VERIFY
        OP_DUP { Q_MIN[2] } { Q_MAX[2] + 1 } OP_WITHIN OP_VERIFY
    }
}

// Input has all remaining local pairs below the one global word/remainder.
fn decode_next_tuple(remaining_global_bits: usize, certify_global: bool) -> Script {
    assert!((1..=GLOBAL_HIGH_BITS).contains(&remaining_global_bits));
    script! {
        if certify_global { { certify_global_high_word() } }
        if remaining_global_bits == 1 {
            OP_TOALTSTACK
            // Pull high32 and low32 in public decoder order.
            OP_SWAP
        } else {
            { split_number(remaining_global_bits - 1, 1) }
            OP_SWAP OP_TOALTSTACK
            // `remainder | high32 | low32`.
            1 OP_ROLL
            2 OP_ROLL
        }
        OP_FROMALTSTACK
        { decode_local_tuple() }
    }
}

fn decode_all_and_consume() -> Script {
    script! {
        for transition in 0..TRANSITIONS {
            { decode_next_tuple(GLOBAL_HIGH_BITS - transition, transition == 0) }
            OP_2DROP OP_DROP
        }
    }
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

fn packed_local_words(tuple: [i32; RELATIONS]) -> [u32; LOCAL_WORDS_PER_TRANSITION] {
    let q0 = encode_twos_complement(tuple[0], Q0_WIDTH);
    let q_plus = encode_twos_complement(tuple[1], Q_RELATION_WIDTH);
    let q_minus = encode_twos_complement(tuple[2], Q_RELATION_WIDTH);
    let low64 = (u64::from(q0 & ((1 << Q0_LOCAL_BITS) - 1)) << 42)
        | (u64::from(q_plus) << 21)
        | u64::from(q_minus);
    [(low64 >> 32) as u32, low64 as u32]
}

// Witness order is low32 | high32, so high32 is nearest the top once its
// transition is routed above the global remainder.
fn local_word_items(tuple: [i32; RELATIONS]) -> [Vec<u8>; LOCAL_WORDS_PER_TRANSITION] {
    let [high, low] = packed_local_words(tuple);
    [
        scriptnum_item(compressed_word_scriptnum(low)),
        scriptnum_item(compressed_word_scriptnum(high)),
    ]
}

fn global_high_word(tuples: &[[i32; RELATIONS]; TRANSITIONS]) -> u32 {
    tuples.iter().fold(0u32, |word, tuple| {
        let q0 = encode_twos_complement(tuple[0], Q0_WIDTH);
        (word << 1) | (q0 >> Q0_LOCAL_BITS)
    })
}

fn hint_witness(tuples: &[[i32; RELATIONS]; TRANSITIONS]) -> Vec<Vec<u8>> {
    let mut items = tuples
        .iter()
        .rev()
        .flat_map(|tuple| local_word_items(*tuple))
        .collect::<Vec<_>>();
    items.push(scriptnum_item(i64::from(global_high_word(tuples))));
    assert_eq!(items.len(), PHYSICAL_HINT_ITEMS);
    items
}

fn execute_rejection(script: &bitcoin::ScriptBuf, witness: Vec<Vec<u8>>, description: &str) {
    let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), witness);
    assert!(
        execution.error.is_some(),
        "hostile G31 u32 quotient witness accepted: {description}"
    );
}

fn main() {
    assert_eq!(Q0_WIDTH + 2 * Q_RELATION_WIDTH, 65);
    assert_eq!(PHYSICAL_HINT_ITEMS, 61);
    assert_eq!(COMPLETE_ENTRY_ITEMS, 789);

    let tuples = std::array::from_fn::<_, TRANSITIONS, _>(|transition| {
        std::array::from_fn(|relation| {
            if (transition + relation) % 2 == 0 {
                Q_MAX[relation]
            } else {
                Q_MIN[relation]
            }
        })
    });
    let hints = hint_witness(&tuples);

    let decoder = decode_all_and_consume().compile_with_policy();
    let executable = script! {
        { decode_all_and_consume() }
        for _ in 0..NON_HINT_ENTRY_ITEMS { OP_DROP }
        OP_1
    }
    .compile_with_policy();
    let mut complete_witness = vec![Vec::new(); NON_HINT_ENTRY_ITEMS];
    complete_witness.extend(hints.clone());
    let execution =
        execute_raw_script_with_inputs_strict(executable.to_bytes(), complete_witness.clone());
    assert!(
        execution.error.is_none(),
        "G31 u32 quotient codec failed: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);

    // Explicitly bind tuple order at both ends of the stream.
    for transition in [0, TRANSITIONS - 1] {
        let mut prefix = Vec::new();
        for prior in 0..=transition {
            prefix.push(decode_next_tuple(GLOBAL_HIGH_BITS - prior, prior == 0));
            if prior == transition {
                prefix.push(script! {
                    { tuples[prior][2] } OP_NUMEQUALVERIFY
                    { tuples[prior][1] } OP_NUMEQUALVERIFY
                    { tuples[prior][0] } OP_NUMEQUALVERIFY
                });
            } else {
                prefix.push(script! { OP_2DROP OP_DROP });
            }
        }
        prefix.push(script! {
            for _ in 0..PHYSICAL_HINT_ITEMS - (2 * (transition + 1) + usize::from(transition + 1 == TRANSITIONS)) {
                OP_DROP
            }
            OP_1
        });
        let script = script! { for step in prefix { { step } } }.compile_with_policy();
        let check = execute_raw_script_with_inputs_strict(script.to_bytes(), hints.clone());
        assert!(
            check.error.is_none(),
            "tuple {transition} order failed: {check}"
        );
    }

    for (relation, description) in [
        (0, "q0 above asymmetric bound"),
        (1, "q+ above conservative bound"),
        (2, "q- above conservative bound"),
    ] {
        let mut hostile = tuples;
        hostile[0][relation] = Q_MAX[relation] + 1;
        let mut witness = vec![Vec::new(); NON_HINT_ENTRY_ITEMS];
        witness.extend(hint_witness(&hostile));
        execute_rejection(&executable, witness, description);
    }

    let first_high_index = NON_HINT_ENTRY_ITEMS + LOCAL_WORD_ITEMS - 1;
    let first_low_index = first_high_index - 1;
    let global_index = COMPLETE_ENTRY_ITEMS - 1;
    for (index, replacement, description) in [
        (first_high_index, vec![0], "nonminimal high32"),
        (first_low_index, vec![0], "nonminimal low32"),
        (
            first_high_index,
            scriptnum_item(1i64 << 31),
            "noncanonical positive 2^31 high32",
        ),
        (
            global_index,
            scriptnum_item(1i64 << GLOBAL_HIGH_BITS),
            "nonzero global padding bit",
        ),
        (global_index, scriptnum_item(-1), "negative global word"),
    ] {
        let mut hostile = complete_witness.clone();
        hostile[index] = replacement;
        execute_rejection(&executable, hostile, description);
    }

    println!("model=ed25519_g31_u32_quotient_codec");
    println!("transitions={TRANSITIONS}");
    println!("logical_quotients={LOGICAL_QUOTIENTS}");
    println!("signed_widths_per_transition=23,21,21");
    println!("local_compressed_u32_items={LOCAL_WORD_ITEMS}");
    println!("global_high_bit_items={GLOBAL_HIGH_ITEMS}");
    println!("physical_hint_items={PHYSICAL_HINT_ITEMS}");
    println!("all_hints_coexist_at_entry=true");
    println!("trace_items={TRACE_ITEMS}");
    println!("scalar_items={SCALAR_ITEMS}");
    println!("complete_entry_items={COMPLETE_ENTRY_ITEMS}");
    println!("decoder_script_bytes={}", decoder.len());
    println!(
        "complete_hint_witness_bytes={}",
        serialize(&Witness::from_slice(&hints)).len()
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
    println!("maximum_global_high_extensions_live=1");
    println!("maximum_global_word_remainders=1");
    println!("callback_altstack_items=0");
    println!("execution_class=unclassified");
}
