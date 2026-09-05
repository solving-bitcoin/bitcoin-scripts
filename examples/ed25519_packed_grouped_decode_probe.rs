//! Bounded direct-word-to-grouped-limb differential decoder experiment.

use bitcoin_lab::{
    fields::ed25519::{u5_balanced_table, u5_packed, u5_packed_grouped},
    support::{execution::execute_raw_script_with_inputs_strict, script::ScriptCompilation},
};

fn item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn witness(words: &[u32; 8]) -> Vec<Vec<u8>> {
    words
        .iter()
        .rev()
        .map(|word| item(i64::from(*word as i32)))
        .collect()
}

fn expected(words: &[u32; 8]) -> Vec<Vec<u8>> {
    let digits = u5_packed::digits_from_packed_words(words).unwrap();
    let mut start = 0;
    u5_packed_grouped::LIMB_DIGITS
        .iter()
        .map(|width| {
            let result = digits[start..start + width]
                .iter()
                .rev()
                .fold(0i64, |x, digit| 32 * x + i64::from(*digit) - 16);
            start += width;
            item(result)
        })
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

fn main() {
    let mut candidates = (0..=31)
        .map(|cutoff| {
            (
                cutoff,
                u5_packed_grouped::decode_with_table_cutoff(0, cutoff).compile_with_policy(),
            )
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(cutoff, compiled)| (compiled.len(), 31 - cutoff));
    let (cutoff, compiled) = &candidates[0];
    assert_eq!(*cutoff, 15);
    assert_eq!(compiled.len(), u5_packed_grouped::SCRIPT_BYTES);
    assert_eq!(
        *compiled,
        u5_packed_grouped::decode(0).compile_with_policy()
    );
    let mut maximum_peak = 0;
    let mut vectors = vec![[0; 8], [0x7fff_ffff; 8]];
    for word_index in 0..7 {
        for special in [1, 0x7fff_ffff, 0x8000_0000, 0x8000_0001, 0xffff_ffff] {
            let mut words = [0; 8];
            words[word_index] = special;
            vectors.push(words);
        }
    }
    let mut state = 0x6a09_e667u32;
    for _ in 0..16 {
        let mut words = std::array::from_fn(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state
        });
        words[7] &= 0x7fff_ffff;
        vectors.push(words);
    }
    let valid_count = vectors.len();
    for words in &vectors {
        let result = execute_raw_script_with_inputs_strict(compiled.to_bytes(), witness(&words));
        assert!(result.error.is_none(), "{words:x?}: {result}");
        let expected = expected(&words);
        assert_eq!(result.final_stack.len(), expected.len());
        for (index, expected) in expected.into_iter().enumerate() {
            assert_eq!(
                result.final_stack.get(index),
                expected,
                "{words:x?} limb {index}"
            );
        }
        maximum_peak = maximum_peak.max(result.stats.max_nb_stack_items);
    }
    for low in 0xffff_ffedu32..=0xffff_ffff {
        let mut words = [u32::MAX; 8];
        words[0] = low;
        words[7] = 0x7fff_ffff;
        let result = execute_raw_script_with_inputs_strict(compiled.to_bytes(), witness(&words));
        assert!(result.error.is_some(), "accepted canonical gap {low:x}");
    }
    let mut last_valid = [u32::MAX; 8];
    last_valid[0] = 0xffff_ffec;
    last_valid[7] = 0x7fff_ffff;
    let last = execute_raw_script_with_inputs_strict(compiled.to_bytes(), witness(&last_valid));
    assert!(last.error.is_none(), "{last}");
    for word in [0x8000_0000, 0xffff_ffff] {
        let mut words = [0; 8];
        words[7] = word;
        assert!(
            execute_raw_script_with_inputs_strict(compiled.to_bytes(), witness(&words))
                .error
                .is_some()
        );
    }
    for malformed in [vec![0u8; 5], vec![0xff; 5], vec![0u8; 6]] {
        let mut words = witness(&[0; 8]);
        words[7] = malformed;
        assert!(
            execute_raw_script_with_inputs_strict(compiled.to_bytes(), words)
                .error
                .is_some()
        );
    }
    for alias in [vec![0u8], vec![0x80], vec![1, 0]] {
        let mut words = witness(&[0; 8]);
        words[7] = alias;
        let result = execute_raw_script_with_inputs_strict(compiled.to_bytes(), words);
        assert!(
            result.error.is_some(),
            "strict flags accepted alias: {result}"
        );
    }
    assert_eq!(maximum_peak, u5_packed_grouped::STACK_ITEMS as usize);
    let mut maximum_frontier_words = [u32::MAX; 8];
    maximum_frontier_words[7] = 0x7fff_fffe;
    let mut maximum_frontier = vec![item(71); 937];
    maximum_frontier.extend(witness(&maximum_frontier_words));
    let frontier = execute_raw_script_with_inputs_strict(
        u5_packed_grouped::decode(937)
            .compile_with_policy()
            .to_bytes(),
        maximum_frontier,
    );
    assert!(
        frontier.error.is_none(),
        "maximum frontier failed: {frontier}"
    );
    assert_eq!(frontier.stats.max_nb_stack_items, 999);
    for index in 0..937 {
        assert_eq!(frontier.final_stack.get(index), item(71));
    }
    assert_eq!(u5_balanced_table::FIELD_DIGIT_COUNT, 51);
    println!("model=ed25519_packed_grouped_decode_probe");
    println!("evidence=differentially-validated");
    println!("execution_class=unclassified");
    println!("grouped_decoder_policy_bytes={}", compiled.len());
    println!("table_cutoff={cutoff}");
    println!("table_items={}", 31 - cutoff);
    println!("combined_stack_peak={maximum_peak}");
    println!("entry_data_items=8");
    println!("output_items=16");
    println!("hint_items_per_invocation=0");
    println!("hint_items_for_46_invocations=0");
    println!("valid_vectors={valid_count}");
    println!("canonical_gap_vectors=19");
    println!("strict_rejected_alias_vectors=3");
    println!("maximum_preserved_prefix_items=937");
    println!("maximum_preserved_prefix_strict_peak=999");
    println!("maximum_serialized_eight_item_input_bytes=48");
    println!("long_scalar_leaf_executed=false");
    for (cutoff, compiled) in candidates.iter().take(8) {
        println!("cutoff_{cutoff}_bytes={}", compiled.len());
    }
    let mut digit_candidates = (10..=31)
        .map(|cutoff| {
            (
                cutoff,
                u5_packed_grouped::decode_digits_with_table_cutoff(0, cutoff).compile_with_policy(),
            )
        })
        .collect::<Vec<_>>();
    digit_candidates.sort_by_key(|(cutoff, compiled)| (compiled.len(), 31 - cutoff));
    for (cutoff, compiled) in digit_candidates
        .iter()
        .filter(|(cutoff, _)| [15, 16, 20, 23, 31].contains(cutoff))
    {
        let mut peak = 0;
        for words in &vectors {
            let result = execute_raw_script_with_inputs_strict(compiled.to_bytes(), witness(words));
            assert!(
                result.error.is_none(),
                "digits cutoff{cutoff} {words:x?}: {result}"
            );
            let digits = u5_packed::digits_from_packed_words(words).unwrap();
            assert_eq!(result.final_stack.len(), 51);
            for (index, digit) in digits.iter().rev().enumerate() {
                assert_eq!(result.final_stack.get(index), item(i64::from(*digit)));
            }
            peak = peak.max(result.stats.max_nb_stack_items);
        }
        println!("digit_cutoff_{cutoff}_bytes={}", compiled.len());
        println!("digit_cutoff_{cutoff}_peak={peak}");
    }
    let digit_script = u5_packed_grouped::decode_digits(0).compile_with_policy();
    assert_eq!(digit_script.len(), u5_packed_grouped::DIGIT_SCRIPT_BYTES);
    assert_eq!(digit_script, digit_candidates[0].1);
    for low in 0xffff_ffedu32..=0xffff_ffff {
        let mut words = [u32::MAX; 8];
        words[0] = low;
        words[7] = 0x7fff_ffff;
        assert!(
            execute_raw_script_with_inputs_strict(digit_script.to_bytes(), witness(&words))
                .error
                .is_some()
        );
    }
    for invalid in [
        vec![0x00; 5],
        vec![0xff; 5],
        vec![0x00; 6],
        vec![0x80],
        vec![1, 0],
    ] {
        let mut words = witness(&[0; 8]);
        words[7] = invalid;
        assert!(
            execute_raw_script_with_inputs_strict(digit_script.to_bytes(), words)
                .error
                .is_some()
        );
    }
    for word in [0x8000_0000, 0xffff_ffff] {
        let mut words = [0; 8];
        words[7] = word;
        assert!(
            execute_raw_script_with_inputs_strict(digit_script.to_bytes(), witness(&words))
                .error
                .is_some()
        );
    }
    let mut digit_frontier = vec![item(79); 906];
    digit_frontier.extend(witness(&maximum_frontier_words));
    let digit_frontier = execute_raw_script_with_inputs_strict(
        u5_packed_grouped::decode_digits(906)
            .compile_with_policy()
            .to_bytes(),
        digit_frontier,
    );
    assert!(
        digit_frontier.error.is_none(),
        "digit frontier failed: {digit_frontier}"
    );
    assert_eq!(digit_frontier.stats.max_nb_stack_items, 999);
    for index in 0..906 {
        assert_eq!(digit_frontier.final_stack.get(index), item(79));
    }
    println!("digit_decoder_policy_bytes={}", digit_script.len());
    println!(
        "digit_decoder_stack_items={}",
        u5_packed_grouped::DIGIT_STACK_ITEMS
    );
    println!("digit_decoder_maximum_preserved_prefix_items=906");
    println!("digit_decoder_maximum_preserved_prefix_strict_peak=999");
    println!("digit_decoder_canonical_gap_rejections=19");
    println!("digit_decoder_auxiliary_hints_per_invocation=0");
    println!("digit_decoder_auxiliary_hints_for_47_invocations=0");
}
