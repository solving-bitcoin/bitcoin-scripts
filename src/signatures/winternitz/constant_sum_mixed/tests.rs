use super::*;
use crate::support::{execution::execute_raw_script_with_inputs_strict, script::ScriptCompilation};
use bitcoin::consensus::serialize;
use num_traits::One;

const ATTAINING_MAXIMUM: [u8; 20] = [
    0x00, 0x01, 0x30, 0x27, 0x5c, 0x86, 0xcf, 0x4a, 0x98, 0x7b, 0xa6, 0x2d, 0x99, 0x45, 0x1e, 0x92,
    0xb2, 0x80, 0x00, 0x00,
];

fn leaf(public_key: &MixedConstantSumPublicKey20, staged: bool) -> bitcoin::ScriptBuf {
    script! {
        OP_7 OP_TOALTSTACK
        { if staged {
            MixedConstantSumWinternitz20::checksig_verify_staged_and_clear(public_key)
        } else {
            MixedConstantSumWinternitz20::checksig_verify_isolated_and_clear(public_key)
        } }
        OP_DEPTH OP_0 OP_EQUALVERIFY
        OP_FROMALTSTACK OP_7 OP_EQUALVERIFY
        OP_TRUE
    }
    .compile_with_policy()
}

#[test]
fn exact_capacity_geometry_and_sizes_are_stable() {
    assert_eq!(
        MixedConstantSumWinternitz20::codeword_count().to_string(),
        "1474534644173396013943101947755055475538944000000"
    );
    assert!(MixedConstantSumWinternitz20::codeword_count() >= (BigUint::one() << 160usize));
    assert_eq!(encoding().classes.len(), 32_768);

    let key = MixedConstantSumWinternitz20::signing_key_from_seed([0x42; 32]);
    let public_key = MixedConstantSumWinternitz20::public_key(&key);
    let signature = MixedConstantSumWinternitz20::sign(key, &ATTAINING_MAXIMUM);
    let witness = signature.to_witness();
    assert_eq!(witness.len(), 66);
    assert_eq!(serialize(&witness).len(), 844);
    assert_eq!(
        MixedConstantSumWinternitz20::checksig_verify_isolated_and_clear(&public_key)
            .compile_with_policy()
            .len(),
        1491
    );
    assert_eq!(
        MixedConstantSumWinternitz20::checksig_verify_staged_and_clear(&public_key)
            .compile_with_policy()
            .len(),
        1490
    );
}

#[test]
fn message_mapping_roundtrips_and_both_guards_execute_strictly() {
    let public_key = MixedConstantSumWinternitz20::public_key(
        &MixedConstantSumWinternitz20::signing_key_from_seed([0x42; 32]),
    );
    let leaves = [leaf(&public_key, false), leaf(&public_key, true)];
    for message in [
        [0; 20],
        [0xff; 20],
        core::array::from_fn(|index| (index * 37) as u8),
        ATTAINING_MAXIMUM,
    ] {
        let signature = MixedConstantSumWinternitz20::sign(
            MixedConstantSumWinternitz20::signing_key_from_seed([0x42; 32]),
            &message,
        );
        assert_eq!(
            MixedConstantSumWinternitz20::decode_message(signature.digits()).unwrap(),
            message
        );
        for verifier in &leaves {
            let result = execute_raw_script_with_inputs_strict(
                verifier.to_bytes(),
                signature.to_witness().to_vec(),
            );
            assert!(result.success, "{result}");
            assert_eq!(result.final_stack.len(), 1);
            // The construction itself peaks at 111. This wrapper deliberately
            // retains one caller-owned altstack marker throughout verification.
            assert!(result.stats.max_nb_stack_items <= 112);
        }
    }
}

#[test]
fn every_pair_accepts_both_equal_sum_branches() {
    let seed = [0x64; 32];
    let namespace = namespace(&seed);
    let public_key = MixedConstantSumWinternitz20::public_key(
        &MixedConstantSumWinternitz20::signing_key_from_seed(seed),
    );
    let leaves = [leaf(&public_key, false), leaf(&public_key, true)];
    let all = (1u16 << PAIRS.len()) - 1;
    let masks = [0, all]
        .into_iter()
        .chain((0..PAIRS.len()).flat_map(|index| [1u16 << index, all ^ (1u16 << index)]));

    for mask in masks {
        let mut ordered = FIXED_DIGITS.to_vec();
        for (index, &(u, v, shift)) in PAIRS.iter().enumerate() {
            if (mask >> index) & 1 == 0 {
                ordered.extend([u, v]);
            } else {
                ordered.extend([u - shift, v + shift]);
            }
        }
        ordered.extend([MAX_DIGIT as u8; IMPLICIT_ENDPOINTS]);
        ordered.rotate_right(7);
        let digits: [u8; CHAINS] = ordered.try_into().unwrap();
        let nodes = core::array::from_fn(|key_index| {
            chain_value(
                chain_start(&namespace, key_index),
                digits[key_index] as usize,
            )
        });
        let signature = MixedConstantSumSignature20 {
            nodes,
            digits,
            class_mask: mask,
        };
        for verifier in &leaves {
            let result = execute_raw_script_with_inputs_strict(
                verifier.to_bytes(),
                signature.to_witness().to_vec(),
            );
            assert!(result.success, "mask={mask}: {result}");
        }
    }
}

#[test]
fn malformed_witnesses_are_rejected_without_engine_panics() {
    let key = MixedConstantSumWinternitz20::signing_key_from_seed([0x42; 32]);
    let public_key = MixedConstantSumWinternitz20::public_key(&key);
    let witness = MixedConstantSumWinternitz20::sign(key, &[0x42; 20])
        .to_witness()
        .to_vec();
    for staged in [false, true] {
        let verifier = leaf(&public_key, staged);
        let mut cases = Vec::new();
        let mut missing = witness.clone();
        missing.pop();
        cases.push(missing);
        let mut extra = witness.clone();
        extra.insert(0, vec![1]);
        cases.push(extra);
        for item in (1..witness.len()).step_by(2).take(6) {
            let mut corrupted = witness.clone();
            corrupted[item][0] ^= 1;
            cases.push(corrupted);
        }
        for selector in [vec![0x81], integer(CHAINS + 1), vec![0; 5]] {
            let mut invalid = witness.clone();
            invalid[0] = selector;
            cases.push(invalid);
        }
        for malformed in cases {
            let result = std::panic::catch_unwind(|| {
                execute_raw_script_with_inputs_strict(verifier.to_bytes(), malformed)
            })
            .expect("malformed witness must not panic the local interpreter");
            assert!(!result.success, "{result}");
        }
    }
}

#[test]
fn decoder_rejects_unused_tail_and_nonmember_histograms() {
    let tail = MixedConstantSumWinternitz20::codeword_count() - BigUint::one();
    let class = encoding()
        .classes
        .iter()
        .find(|class| tail >= class.offset && tail < &class.offset + &class.capacity)
        .unwrap();
    let digits = unrank_permutation(class.counts, tail - &class.offset, &class.capacity);
    assert_eq!(
        MixedConstantSumWinternitz20::decode_message(&digits),
        Err(InvalidMixedConstantSumEncoding)
    );

    let mut invalid = MixedConstantSumWinternitz20::encode_message(&[0; 20]).0;
    invalid[0] = 0;
    assert_eq!(
        MixedConstantSumWinternitz20::decode_message(&invalid),
        Err(InvalidMixedConstantSumEncoding)
    );
}
