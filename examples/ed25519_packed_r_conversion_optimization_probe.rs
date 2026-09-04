//! Focused differential probe for the packed-u32 to BLAKE3-u4 boundary.
//!
//! This intentionally does not build or execute either scalar-multiplication
//! linker.  The source words are caller-certified circuit data; every variant
//! below requires exactly zero auxiliary witness hints.

use bitcoin::{script::Instruction, ScriptBuf};
use bitcoin_lab::{
    hashes::blake3::ed25519_challenge,
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation},
    },
};

const PRESERVED_ITEMS: usize = 297;
const R_WORD0_DEPTH: u32 = 289;
const PUBLIC_KEY: [u8; 32] = [
    0x7d, 0xb0, 0xdc, 0x92, 0x22, 0xf3, 0xc1, 0x83, 0x45, 0x7d, 0xdd, 0xe4, 0xc7, 0x08, 0xde, 0x8e,
    0x5e, 0xa6, 0xbf, 0x3d, 0x5c, 0x44, 0x04, 0xcc, 0xa1, 0x4b, 0x32, 0x72, 0x9a, 0x05, 0xc3, 0x2a,
];

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn compressed_word_item(word: u32) -> Vec<u8> {
    scriptnum_item(i64::from(word as i32))
}

fn packed_witness(words: &[u32; 8]) -> Vec<Vec<u8>> {
    words
        .iter()
        .rev()
        .map(|word| compressed_word_item(*word))
        .collect()
}

fn exact_prefix(words: &[u32; 8]) -> Vec<Vec<u8>> {
    let mut prefix = packed_witness(words);
    prefix.extend((0..R_WORD0_DEPTH as usize).map(|index| scriptnum_item(1 + (index % 97) as i64)));
    assert_eq!(prefix.len(), PRESERVED_ITEMS);
    prefix
}

fn extract_known_bit_immediate(bit: u32) -> Script {
    assert!((4..=30).contains(&bit));
    script! {
        OP_DUP { (1u32 << bit) - 1 } OP_GREATERTHAN
        OP_SWAP OP_OVER
        OP_IF { 1u32 << bit } OP_SUB OP_ENDIF
    }
}

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

fn duplicate_word_immediate() -> Script {
    script! {
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

        for bit in (28..=30u32).rev() { { extract_known_bit_immediate(bit) } }
        { combine_bits_below_remainder(4) }
        for high_bit in [27u32, 23, 19, 15, 11, 7] {
            for bit in (high_bit - 3..=high_bit).rev() { { extract_known_bit_immediate(bit) } }
            { combine_bits_below_remainder(4) }
        }
    }
}

fn immediate_conversion() -> Script {
    script! {
        for word in 0..8u32 {
            { R_WORD0_DEPTH + 9 * word } OP_PICK
            { duplicate_word_immediate() }
        }
    }
}

// Directly accumulate one nibble while retaining the word remainder. This is
// the natural grouped-nibble alternative, but the required stack rotations
// make it larger than extracting four bits and combining them once.
fn append_bit_to_nibble_accumulator(bit: u32) -> Script {
    script! {
        OP_SWAP OP_DUP OP_ADD OP_SWAP
        { extract_known_bit_immediate(bit) }
        OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
    }
}

fn duplicate_word_grouped_nibbles() -> Script {
    script! {
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

        for bit in (28..=30u32).rev() { { append_bit_to_nibble_accumulator(bit) } }
        for high_bit in [27u32, 23, 19, 15, 11, 7] {
            0 OP_SWAP
            for bit in (high_bit - 3..=high_bit).rev() {
                { append_bit_to_nibble_accumulator(bit) }
            }
        }
    }
}

fn grouped_nibble_conversion() -> Script {
    script! {
        for word in 0..8u32 {
            { R_WORD0_DEPTH + 9 * word } OP_PICK
            { duplicate_word_grouped_nibbles() }
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ThresholdOffsets {
    bit: u32,
    minus_one_from_top: u32,
    power_from_top: u32,
}

fn table_offsets(cutoff_bit: u32) -> Vec<ThresholdOffsets> {
    let bits = (cutoff_bit.max(4)..=30).rev().collect::<Vec<_>>();
    let item_count = 2 * bits.len();
    bits.into_iter()
        .enumerate()
        .map(|(index, bit)| ThresholdOffsets {
            bit,
            minus_one_from_top: (item_count - 1 - 2 * index) as u32,
            power_from_top: (item_count - 2 - 2 * index) as u32,
        })
        .collect()
}

fn push_threshold_table(offsets: &[ThresholdOffsets]) -> Script {
    script! {
        for entry in offsets {
            { (1u32 << entry.bit) - 1 }
            { 1u32 << entry.bit }
        }
    }
}

// `items_above_table` includes the current remainder.  A table lookup is a
// compile-time fixed OP_PICK; the table entries are script constants, never
// witness hints.
fn extract_known_bit_table(
    bit: u32,
    items_above_table: u32,
    offsets: &[ThresholdOffsets],
) -> Script {
    let Some(entry) = offsets.iter().find(|entry| entry.bit == bit) else {
        return extract_known_bit_immediate(bit);
    };
    let minus_one_depth = items_above_table + 1 + entry.minus_one_from_top;
    let power_depth = items_above_table + 1 + entry.power_from_top;
    script! {
        OP_DUP { minus_one_depth } OP_PICK OP_GREATERTHAN
        OP_SWAP OP_OVER
        OP_IF { power_depth } OP_PICK OP_SUB OP_ENDIF
    }
}

fn duplicate_word_table(word: u32, offsets: &[ThresholdOffsets]) -> Script {
    let prior_outputs = 8 * word;
    let mut completed_nibbles = 0u32;
    let mut pending_bits = 1u32; // the normalized sign bit is bit 31
    let mut body = Script::new("table-backed packed-word split");
    body = body.push_script(
        script! {
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

    for bit in (28..=30u32).rev() {
        let items_above = prior_outputs + completed_nibbles + pending_bits + 1;
        body = body
            .push_script(extract_known_bit_table(bit, items_above, offsets).compile_with_policy());
        pending_bits += 1;
    }
    body = body.push_script(combine_bits_below_remainder(4).compile_with_policy());
    pending_bits = 0;
    completed_nibbles += 1;

    for high_bit in [27u32, 23, 19, 15, 11, 7] {
        for bit in (high_bit - 3..=high_bit).rev() {
            let items_above = prior_outputs + completed_nibbles + pending_bits + 1;
            body = body.push_script(
                extract_known_bit_table(bit, items_above, offsets).compile_with_policy(),
            );
            pending_bits += 1;
        }
        body = body.push_script(combine_bits_below_remainder(4).compile_with_policy());
        pending_bits = 0;
        completed_nibbles += 1;
    }
    assert_eq!(completed_nibbles, 7);
    body
}

fn table_conversion(cutoff_bit: u32, remove_table: bool) -> Script {
    let offsets = table_offsets(cutoff_bit);
    let table_items = (2 * offsets.len()) as u32;
    script! {
        { push_threshold_table(&offsets) }
        for word in 0..8u32 {
            { R_WORD0_DEPTH + table_items + 9 * word } OP_PICK
            { duplicate_word_table(word, &offsets) }
        }

        if remove_table {
            // Remove every script-resident table item before entering BLAKE3.
            for _ in 0..64 { OP_TOALTSTACK }
            for _ in 0..table_items / 2 { OP_2DROP }
            if table_items % 2 != 0 { OP_DROP }
            for _ in 0..64 { OP_FROMALTSTACK }
        }
    }
}

fn drop_table_below_top(top_items: u32, table_items: u32) -> Script {
    script! {
        for _ in 0..top_items { OP_TOALTSTACK }
        for _ in 0..table_items / 2 { OP_2DROP }
        if table_items % 2 != 0 { OP_DROP }
        for _ in 0..top_items { OP_FROMALTSTACK }
    }
}

fn verify_u4(expected: &[u8]) -> Script {
    script! {
        for nibble in expected.iter().rev() { { *nibble } OP_NUMEQUALVERIFY }
    }
}

fn verify_raw_prefix(prefix: &[Vec<u8>]) -> Script {
    script! {
        for item in prefix.iter().rev() { { item.clone() } OP_EQUALVERIFY }
    }
}

fn verify_low128(digest: &[u8; 32]) -> Script {
    let nibbles = digest[..16]
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .collect::<Vec<_>>();
    verify_u4(&nibbles)
}

fn compile(script: Script) -> ScriptBuf {
    script.compile_with_policy()
}

fn strict_conversion(script: &ScriptBuf, words: &[u32; 8]) -> usize {
    let prefix = exact_prefix(words);
    let r_bytes: [u8; 32] = words
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let expected = ed25519_challenge::transcript_half_u4(&r_bytes);
    let complete = compile(script! {
        { Script::new("policy-precompiled conversion").push_script(script.clone()) }
        { verify_u4(&expected) }
        { verify_raw_prefix(&prefix) }
        OP_1
    });
    let execution = execute_raw_script_with_inputs_strict(complete.to_bytes(), prefix);
    assert!(
        execution.error.is_none(),
        "conversion failed for {words:08x?}: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);
    execution.stats.max_nb_stack_items
}

fn static_non_push_opcodes(script: &bitcoin::Script) -> usize {
    script
        .instructions()
        .map(|instruction| instruction.expect("generated script parses"))
        .filter(
            |instruction| matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() > 0x60),
        )
        .count()
}

fn main() {
    let baseline = compile(immediate_conversion());
    assert_eq!(
        baseline.len(),
        4_072,
        "pre-shared-threshold conversion checkpoint moved"
    );

    let mut candidates = (4..=31)
        .map(|cutoff| {
            let compiled = compile(table_conversion(cutoff, true));
            (cutoff, compiled)
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|(left_cutoff, left), (right_cutoff, right)| {
        left.len()
            .cmp(&right.len())
            .then_with(|| right_cutoff.cmp(left_cutoff))
    });
    let (winner_cutoff, winner) = &candidates[0];
    let grouped_nibbles = compile(grouped_nibble_conversion());
    assert_eq!(*winner_cutoff, 16);
    assert_eq!(winner.len(), 3_976);
    assert_eq!(grouped_nibbles.len(), 4_536);

    let boundary_words = [
        0x0000_0000,
        0x0000_0001,
        0x0000_ffff,
        0x7fff_ffff,
        0x8000_0000,
        0x8000_0001,
        0xffff_fffe,
        0xffff_ffff,
    ];
    let baseline_peak = strict_conversion(&baseline, &boundary_words);
    let grouped_nibble_peak = strict_conversion(&grouped_nibbles, &boundary_words);
    let mut winner_peak = strict_conversion(winner, &boundary_words);

    let mut state = 0x6a09_e667u32;
    for _ in 0..15 {
        let words = std::array::from_fn(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state
        });
        winner_peak = winner_peak.max(strict_conversion(winner, &words));
    }

    // Differentially validate the winning conversion in the real fixed-M
    // boundary against the host BLAKE3 implementation.
    let domain = *blake3::hash(b"bitcoin-lab/custom-ed25519-blake3-slope-v1").as_bytes();
    let message: [u8; 32] = std::array::from_fn(|index| (index as u8).wrapping_mul(7));
    let words = boundary_words;
    let r_bytes: [u8; 32] = words
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let prefix = exact_prefix(&words);
    let hash = compile(
        ed25519_challenge::key_specialized_compute_script_preserving_truncated_128_fixed_message(
            domain,
            PUBLIC_KEY,
            message,
            PRESERVED_ITEMS as u32,
        ),
    );
    let optimized_helper = compile(script! {
        { Script::new("policy-precompiled table-backed conversion").push_script(winner.clone()) }
        { Script::new("policy-precompiled fixed-M BLAKE3").push_script(hash.clone()) }
    });
    let production_helper = compile(
        ed25519_challenge::key_specialized_compute_script_preserving_truncated_128_fixed_message_from_certified_packed_r(
            domain,
            PUBLIC_KEY,
            message,
            PRESERVED_ITEMS as u32,
            R_WORD0_DEPTH,
        ),
    );
    assert_eq!(production_helper, optimized_helper);
    assert_eq!(optimized_helper.len(), 67_806);
    let digest = *blake3::hash(&[domain, PUBLIC_KEY, r_bytes, message].concat()).as_bytes();
    let complete = compile(script! {
        { Script::new("policy-precompiled optimized packed-R boundary").push_script(optimized_helper.clone()) }
        { verify_low128(&digest) }
        { verify_raw_prefix(&prefix) }
        OP_1
    });
    let execution = execute_raw_script_with_inputs_strict(complete.to_bytes(), prefix);
    assert!(
        execution.error.is_none(),
        "optimized packed-R BLAKE3 differs from host or changed prefix: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);
    assert_eq!(execution.stats.max_nb_stack_items, 824);

    // A boundary-level variant retains the constant table as extra preserved
    // state through BLAKE3, then moves only the 32 digest nibbles to remove it.
    // This trades 32 stack items for fewer shuffles and no change in hints.
    let winner_table_items = 2 * (31 - *winner_cutoff);
    let retained_conversion = compile(table_conversion(*winner_cutoff, false));
    let retained_hash = compile(
        ed25519_challenge::key_specialized_compute_script_preserving_truncated_128_fixed_message(
            domain,
            PUBLIC_KEY,
            message,
            PRESERVED_ITEMS as u32 + winner_table_items,
        ),
    );
    let retained_helper = compile(script! {
        { Script::new("policy-precompiled retained-table conversion").push_script(retained_conversion.clone()) }
        { Script::new("policy-precompiled retained-table fixed-M BLAKE3").push_script(retained_hash.clone()) }
        { drop_table_below_top(32, winner_table_items) }
    });
    let retained_complete = compile(script! {
        { Script::new("policy-precompiled retained-table packed-R boundary").push_script(retained_helper.clone()) }
        { verify_low128(&digest) }
        { verify_raw_prefix(&exact_prefix(&words)) }
        OP_1
    });
    let retained_execution =
        execute_raw_script_with_inputs_strict(retained_complete.to_bytes(), exact_prefix(&words));
    assert!(
        retained_execution.error.is_none(),
        "retained-table packed-R BLAKE3 differs from host or changed prefix: {retained_execution}"
    );
    assert_eq!(retained_execution.final_stack.len(), 1);
    assert!(retained_helper.len() > optimized_helper.len());

    println!("model=ed25519_packed_r_conversion_optimization_probe");
    println!("evidence=differentially-validated");
    println!("execution_class=unclassified");
    println!("preserved_input_items={PRESERVED_ITEMS}");
    println!("entry_hint_items=0");
    println!("helper_auxiliary_hint_items=0");
    println!("baseline_immediate_policy_bytes={}", baseline.len());
    println!(
        "baseline_immediate_static_non_push_opcodes={}",
        static_non_push_opcodes(&baseline)
    );
    println!("baseline_conversion_strict_peak={baseline_peak}");
    println!("grouped_nibble_policy_bytes={}", grouped_nibbles.len());
    println!("grouped_nibble_strict_peak={grouped_nibble_peak}");
    println!("winner_table_cutoff_bit={winner_cutoff}");
    println!("winner_table_items={winner_table_items}");
    println!("winner_conversion_policy_bytes={}", winner.len());
    println!(
        "winner_conversion_byte_saving={}",
        baseline.len() - winner.len()
    );
    println!(
        "winner_conversion_static_non_push_opcodes={}",
        static_non_push_opcodes(winner)
    );
    println!("winner_conversion_strict_peak={winner_peak}");
    println!("direct_fixed_m_hash_policy_bytes={}", hash.len());
    println!("optimized_boundary_policy_bytes={}", optimized_helper.len());
    println!("manual_post_policy_optimizer=false");
    println!("production_helper_matches_winner_byte_for_byte=true");
    println!(
        "optimized_boundary_strict_peak={}",
        execution.stats.max_nb_stack_items
    );
    println!(
        "retained_table_conversion_policy_bytes={}",
        retained_conversion.len()
    );
    println!("retained_table_hash_policy_bytes={}", retained_hash.len());
    println!(
        "retained_table_boundary_policy_bytes={}",
        retained_helper.len()
    );
    println!(
        "retained_table_boundary_byte_saving={}",
        baseline.len() + hash.len() - retained_helper.len()
    );
    println!(
        "retained_table_boundary_strict_peak={}",
        retained_execution.stats.max_nb_stack_items
    );
    println!("host_blake3_low128_match=true");
    println!("entire_297_item_prefix_preserved_byte_for_byte=true");
    println!("deterministic_conversion_vectors=16");
    println!("packed_word_certification=external_later_slope_transition");
    println!("long_scalar_leaf_built=false");
    println!("long_scalar_leaf_executed=false");

    for (cutoff, script) in candidates.into_iter().take(8) {
        println!("candidate_cutoff_{cutoff}_policy_bytes={}", script.len());
    }
}
