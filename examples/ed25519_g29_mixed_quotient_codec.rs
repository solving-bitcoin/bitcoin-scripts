//! Optimal-item quotient packing for the mixed-relation G29 schedule.
//!
//! Twenty-eight transitions each need three signed 23-bit quotients. Two
//! exact compressed-u32 items carry the low 64 bits of each 69-bit tuple; five
//! nonnegative 28-bit bit-plane streams carry the remaining q0 bits. This is
//! the physical lower bound of 61 stack items for the 1,932-bit payload.
//!
//! Run with:
//! `cargo run --locked --release --example ed25519_g29_mixed_quotient_codec`.

use bitcoin::{consensus::encode::serialize, Witness};
use bitcoin_lab::support::{
    execution::execute_raw_script_with_inputs_strict,
    script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
};

const TRANSITIONS: usize = 28;
const RELATIONS: usize = 3;
const WIDTH: usize = 23;
const LOCAL_Q0_BITS: usize = 18;
const HIGH_Q0_BITS: usize = WIDTH - LOCAL_Q0_BITS;
const LOCAL_ITEMS: usize = 2 * TRANSITIONS;
const GLOBAL_ITEMS: usize = HIGH_Q0_BITS;
const PHYSICAL_HINT_ITEMS: usize = LOCAL_ITEMS + GLOBAL_ITEMS;
const LOGICAL_QUOTIENTS: usize = RELATIONS * TRANSITIONS;
const TRACE_ITEMS: usize = 3 * 8 * TRANSITIONS;
const SCALAR_ITEMS: usize = 8;
const NON_HINT_ENTRY_ITEMS: usize = TRACE_ITEMS + SCALAR_ITEMS;
const COMPLETE_ENTRY_ITEMS: usize = NON_HINT_ENTRY_ITEMS + PHYSICAL_HINT_ITEMS;

const SIGNED_MIN: i32 = -(1 << (WIDTH - 1));
const SIGNED_MAX: i32 = (1 << (WIDTH - 1)) - 1;

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

fn certify_global_word() -> Script {
    script! {
        OP_SIZE 5 OP_LESSTHAN OP_VERIFY
        OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
        OP_DUP 0 { 1u32 << TRANSITIONS } OP_WITHIN OP_VERIFY
    }
}

fn bits_from_altstack_to_number(width: usize) -> Script {
    script! {
        OP_FROMALTSTACK
        for _ in 1..width {
            OP_DUP OP_ADD OP_FROMALTSTACK OP_ADD
        }
    }
}

fn split_number(total_bits: usize, high_bits: usize) -> Script {
    assert!(high_bits > 0 && high_bits < total_bits && total_bits <= 31);
    let low_bits = total_bits - high_bits;
    script! {
        for bit in (low_bits..total_bits).rev() {
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

fn exact_word_to_low31_and_sign() -> Script {
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

fn finish_twos_complement() -> Script {
    script! {
        OP_DUP { 1u32 << (WIDTH - 1) } OP_GREATERTHANOREQUAL
        OP_IF { 1u32 << WIDTH } OP_SUB OP_ENDIF
    }
}

// Input is high32 | low32 | q0_high5. Output is q0 | q+ | q-.
fn decode_local_tuple() -> Script {
    script! {
        OP_TOALTSTACK

        // low32: q-[0..22] | q+[0..8].
        { exact_word_to_low31_and_sign() }
        OP_TOALTSTACK
        { split_number(31, 8) }
        OP_FROMALTSTACK
        OP_TOALTSTACK OP_SWAP OP_FROMALTSTACK
        for _ in 0..8 { OP_DUP OP_ADD }
        OP_ADD

        // high32: q+[9..22] | q0[0..17].
        2 OP_ROLL
        { exact_word_to_low31_and_sign() }
        OP_TOALTSTACK
        { split_number(31, 17) }

        // Join q+ high14 || low9.
        2 OP_ROLL OP_SWAP
        for _ in 0..9 { OP_DUP OP_ADD }
        OP_ADD

        // Join high-word bit31 to q0 low17, then global high5 to low18.
        OP_SWAP OP_FROMALTSTACK
        for _ in 0..17 { OP_DUP OP_ADD }
        OP_ADD
        OP_FROMALTSTACK
        for _ in 0..LOCAL_Q0_BITS { OP_DUP OP_ADD }
        OP_ADD

        // q- | q+ | q0 -> q0 | q+ | q-.
        OP_ROT OP_ROT OP_SWAP
        { finish_twos_complement() }
        OP_SWAP { finish_twos_complement() } OP_SWAP
        2 OP_ROLL { finish_twos_complement() }
        OP_ROT OP_ROT
    }
}

// Five global words remain as five numeric remainders until the last tuple.
// Processing the bottom word first preserves their bit-plane order.
fn extract_global_extension(remaining_bits: usize, first: bool) -> Script {
    assert!((1..=TRANSITIONS).contains(&remaining_bits));
    script! {
        for plane in 0..GLOBAL_ITEMS {
            if remaining_bits == 1 {
                { (GLOBAL_ITEMS - 1 - plane) as u32 } OP_ROLL
                if first { { certify_global_word() } }
                OP_TOALTSTACK
            } else {
                { (GLOBAL_ITEMS - 1) as u32 } OP_ROLL
                if first { { certify_global_word() } }
                { split_number(remaining_bits, 1) }
                OP_SWAP OP_TOALTSTACK
            }
        }
        // Altstack pops q0 extension bits least-significant first.
        0
        for shift in 0..GLOBAL_ITEMS {
            OP_FROMALTSTACK
            for _ in 0..shift { OP_DUP OP_ADD }
            OP_ADD
        }
    }
}

fn decode_next_tuple(remaining_bits: usize, first: bool) -> Script {
    script! {
        { extract_global_extension(remaining_bits, first) }
        OP_TOALTSTACK
        if remaining_bits == 1 {
            OP_SWAP
        } else {
            { GLOBAL_ITEMS as u32 } OP_ROLL
            { (GLOBAL_ITEMS + 1) as u32 } OP_ROLL
        }
        OP_FROMALTSTACK
        { decode_local_tuple() }
    }
}

fn decode_all_and_consume() -> Script {
    script! {
        for transition in 0..TRANSITIONS {
            { decode_next_tuple(TRANSITIONS - transition, transition == 0) }
            OP_2DROP OP_DROP
        }
    }
}

fn encode_twos_complement(value: i32) -> u32 {
    assert!((SIGNED_MIN..=SIGNED_MAX).contains(&value));
    if value < 0 {
        ((1i64 << WIDTH) + i64::from(value)) as u32
    } else {
        value as u32
    }
}

fn local_words(tuple: [i32; RELATIONS]) -> [u32; 2] {
    let q0 = encode_twos_complement(tuple[0]);
    let q_plus = encode_twos_complement(tuple[1]);
    let q_minus = encode_twos_complement(tuple[2]);
    let low64 = (u64::from(q0 & ((1 << LOCAL_Q0_BITS) - 1)) << (2 * WIDTH))
        | (u64::from(q_plus) << WIDTH)
        | u64::from(q_minus);
    [(low64 >> 32) as u32, low64 as u32]
}

fn local_items(tuple: [i32; RELATIONS]) -> [Vec<u8>; 2] {
    let [high, low] = local_words(tuple);
    [
        scriptnum_item(compressed_word_scriptnum(low)),
        scriptnum_item(compressed_word_scriptnum(high)),
    ]
}

fn global_words(tuples: &[[i32; RELATIONS]; TRANSITIONS]) -> [u32; GLOBAL_ITEMS] {
    std::array::from_fn(|plane| {
        tuples.iter().fold(0u32, |word, tuple| {
            let high = encode_twos_complement(tuple[0]) >> LOCAL_Q0_BITS;
            let bit = (high >> (GLOBAL_ITEMS - 1 - plane)) & 1;
            (word << 1) | bit
        })
    })
}

fn hint_witness(tuples: &[[i32; RELATIONS]; TRANSITIONS]) -> Vec<Vec<u8>> {
    let mut result = tuples
        .iter()
        .rev()
        .flat_map(|tuple| local_items(*tuple))
        .collect::<Vec<_>>();
    result.extend(
        global_words(tuples)
            .into_iter()
            .map(|word| scriptnum_item(i64::from(word))),
    );
    assert_eq!(result.len(), PHYSICAL_HINT_ITEMS);
    result
}

fn execute_rejection(script: &bitcoin::ScriptBuf, witness: Vec<Vec<u8>>, description: &str) {
    let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), witness);
    assert!(
        execution.error.is_some(),
        "hostile G29 mixed quotient witness accepted: {description}"
    );
}

/// Recover the raw fragment size through the repository compilation policy.
/// Two copies cross the 32-KiB optimizer cutoff, so the result is the exact
/// unoptimized size that applies when this codec is embedded in a 4-MB leaf.
fn raw_fragment_len(fragment: Script) -> usize {
    const COPIES: usize = 2;
    let repeated = script! {
        for _ in 0..COPIES { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % COPIES, 0);
    repeated.len() / COPIES
}

fn main() {
    assert_eq!(RELATIONS * WIDTH * TRANSITIONS, 1_932);
    assert_eq!(PHYSICAL_HINT_ITEMS, 61);
    assert_eq!(COMPLETE_ENTRY_ITEMS, 741);

    let tuples = std::array::from_fn::<_, TRANSITIONS, _>(|transition| {
        std::array::from_fn(|relation| {
            if (transition + relation) % 2 == 0 {
                SIGNED_MAX
            } else {
                SIGNED_MIN
            }
        })
    });
    let hints = hint_witness(&tuples);
    let decoder_fragment = decode_all_and_consume();
    let decoder_raw_bytes = raw_fragment_len(decoder_fragment.clone());
    let decoder = decoder_fragment.compile_with_policy();
    let executable = script! {
        { decode_all_and_consume() }
        for _ in 0..NON_HINT_ENTRY_ITEMS { OP_DROP }
        OP_1
    }
    .compile_with_policy();
    let mut complete = vec![Vec::new(); NON_HINT_ENTRY_ITEMS];
    complete.extend(hints.clone());
    let execution = execute_raw_script_with_inputs_strict(executable.to_bytes(), complete.clone());
    assert!(
        execution.error.is_none(),
        "G29 mixed codec failed: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);

    // Bind both stream endpoints and all three signed fields explicitly.
    for target in [0, TRANSITIONS - 1] {
        let check = script! {
            for transition in 0..=target {
                { decode_next_tuple(TRANSITIONS - transition, transition == 0) }
                if transition == target {
                    { tuples[transition][2] } OP_NUMEQUALVERIFY
                    { tuples[transition][1] } OP_NUMEQUALVERIFY
                    { tuples[transition][0] } OP_NUMEQUALVERIFY
                } else {
                    OP_2DROP OP_DROP
                }
            }
            for _ in 0..PHYSICAL_HINT_ITEMS - (2 * (target + 1) + if target + 1 == TRANSITIONS { GLOBAL_ITEMS } else { 0 }) {
                OP_DROP
            }
            OP_1
        }
        .compile_with_policy();
        let result = execute_raw_script_with_inputs_strict(check.to_bytes(), hints.clone());
        assert!(
            result.error.is_none(),
            "tuple {target} ordering failed: {result}"
        );
    }

    let first_high_index = NON_HINT_ENTRY_ITEMS + LOCAL_ITEMS - 1;
    let first_low_index = first_high_index - 1;
    let first_global_index = NON_HINT_ENTRY_ITEMS + LOCAL_ITEMS;
    for (index, replacement, description) in [
        (first_high_index, vec![0], "nonminimal high32"),
        (first_low_index, vec![0], "nonminimal low32"),
        (
            first_high_index,
            scriptnum_item(1i64 << 31),
            "noncanonical positive 2^31 high32",
        ),
        (
            first_global_index,
            scriptnum_item(-1),
            "negative global word",
        ),
        (
            first_global_index,
            scriptnum_item(1i64 << TRANSITIONS),
            "nonzero global padding bit",
        ),
    ] {
        let mut hostile = complete.clone();
        hostile[index] = replacement;
        execute_rejection(&executable, hostile, description);
    }

    println!("model=ed25519_g29_mixed_quotient_codec");
    println!("transitions={TRANSITIONS}");
    println!("logical_quotients={LOGICAL_QUOTIENTS}");
    println!("signed_widths_per_transition=23,23,23");
    println!("payload_bits={}", RELATIONS * WIDTH * TRANSITIONS);
    println!("local_compressed_u32_items={LOCAL_ITEMS}");
    println!("global_bitplane_items={GLOBAL_ITEMS}");
    println!("physical_hint_items={PHYSICAL_HINT_ITEMS}");
    println!("physical_item_lower_bound={}", 1_932usize.div_ceil(32));
    println!("all_hints_coexist_at_entry=true");
    println!("trace_items={TRACE_ITEMS}");
    println!("scalar_items={SCALAR_ITEMS}");
    println!("complete_entry_items={COMPLETE_ENTRY_ITEMS}");
    println!("decoder_policy_script_bytes={}", decoder.len());
    println!("decoder_raw_script_bytes={decoder_raw_bytes}");
    println!(
        "decoder_whole_leaf_optimizer_delta_bytes={}",
        decoder_raw_bytes - decoder.len()
    );
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
    println!("maximum_global_extensions_live=1");
    println!("global_remainder_items_until_final=5");
    println!("callback_altstack_items=0");
    println!("execution_class=unclassified");
}
