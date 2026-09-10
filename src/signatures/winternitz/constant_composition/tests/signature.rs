//! Adversarial checks of the shrinking, trusted endpoint pool.
use super::*;
use crate::{
    signatures::winternitz::{FullWidth, Sha256, Sha256Hash160},
    support::{execution::execute_raw_script_with_inputs_strict, script::ScriptCompilation},
};
use bitcoin::hashes::{sha256, Hash};
use bitcoin_scriptexec::ExecError;
use std::collections::HashSet;

type Wots<H = Hash160, P = Preimage16> = ConstantCompositionWinternitz20<H, P>;

// Work in execution order, with a uniform [node, selector] test representation.
// The actual witness has forward [selector, node] pairs for altstack staging.
fn pairs(witness: &Witness) -> Vec<[Vec<u8>; 2]> {
    witness
        .to_vec()
        .chunks_exact(2)
        .map(|pair| [pair[1].clone(), pair[0].clone()])
        .collect()
}

fn witness(pairs: &[[Vec<u8>; 2]]) -> Vec<Vec<u8>> {
    pairs
        .iter()
        .flat_map(|pair| [pair[1].clone(), pair[0].clone()])
        .collect()
}

fn selected_keys(pairs: &[[Vec<u8>; 2]], key_count: usize) -> Vec<usize> {
    let mut pool: Vec<_> = (0..key_count).collect();
    pairs
        .iter()
        .map(|pair| {
            let index = pair[1]
                .iter()
                .enumerate()
                .map(|(i, &byte)| (byte as usize) << (8 * i))
                .sum::<usize>();
            pool.remove(index)
        })
        .collect()
}

fn route_keys(pairs: &mut [[Vec<u8>; 2]], keys: &[usize], key_count: usize) {
    let mut pool: Vec<_> = (0..key_count).collect();
    for (pair, &key) in pairs.iter_mut().zip(keys) {
        let index = pool.iter().position(|&candidate| candidate == key).unwrap();
        assert!(index < 128);
        pair[1] = if index == 0 {
            vec![]
        } else {
            vec![index as u8]
        };
        pool.remove(index);
    }
}

fn roundtrip<H: ChainHash, P: PreimageSize<H>>() {
    let key = Wots::<H, P>::signing_key_from_seed([0x42; 32]);
    assert_eq!(
        format!("{key:?}"),
        "ConstantCompositionSigningKey20([redacted])"
    );
    let public_key = Wots::<H, P>::public_key(&key);
    assert_eq!(
        public_key,
        ConstantCompositionPublicKey20::from_commitments(*public_key.commitments())
    );
    assert_eq!(
        public_key
            .commitments()
            .iter()
            .map(|item| item.as_ref().to_vec())
            .collect::<HashSet<_>>()
            .len(),
        Wots::<H, P>::CHAINS
    );
    let leaves = [false, true].map(|bounded| {
        let verifier = if bounded {
            Wots::<H, P>::checksig_verify_bounded_and_clear(&public_key)
        } else {
            Wots::<H, P>::checksig_verify_and_clear(&public_key)
        };
        script! {
            OP_7 OP_TOALTSTACK
            { verifier }
            OP_9 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_7 OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy()
    });
    for message in [
        [0; 20],
        [0xff; 20],
        core::array::from_fn(|i| (i * 37) as u8),
    ] {
        let signature =
            Wots::<H, P>::sign(Wots::<H, P>::signing_key_from_seed([0x42; 32]), &message);
        assert_eq!(
            Wots::<H, P>::decode_message(signature.digits()).unwrap(),
            message
        );
        let signature_witness = signature.to_witness();
        assert_eq!(signature_witness.len(), Wots::<H, P>::WITNESS_DATA_ITEMS);
        let pairs = pairs(&signature_witness);
        let keys = selected_keys(&pairs, Wots::<H, P>::CHAINS);
        assert_eq!(keys.len(), Wots::<H, P>::OPENINGS);
        assert_eq!(
            keys.iter().copied().collect::<HashSet<_>>().len(),
            keys.len()
        );
        for (pair, &key) in pairs.iter().zip(&keys) {
            assert_eq!(
                pair[0].len(),
                if signature.digits()[key] == 0 {
                    P::START_BYTES
                } else {
                    H::VALUE_BYTES
                }
            );
        }
        for leaf in &leaves {
            let inputs = [vec![vec![9]], signature_witness.to_vec()].concat();
            let result = execute_raw_script_with_inputs_strict(leaf.to_bytes(), inputs);
            assert!(result.success, "{result}");
            assert_eq!(result.final_stack.len(), 1);
            assert!(result.stats.max_nb_stack_items <= 1000);
        }
    }
}

#[test]
fn all_hash_profiles_and_start_widths_preserve_main_and_alt_state() {
    roundtrip::<Hash160, Preimage16>();
    roundtrip::<Hash160, FullWidth>();
    roundtrip::<Sha256, Preimage16>();
    roundtrip::<Sha256, FullWidth>();
    roundtrip::<Sha256Hash160, Preimage16>();
    roundtrip::<Sha256Hash160, FullWidth>();
}

fn malformed<H: ChainHash>() {
    let key = Wots::<H>::signing_key_from_seed([0x42; 32]);
    let public_key = Wots::<H>::public_key(&key);
    let signature = Wots::<H>::sign(key, &[0x42; 20]);
    let leaves = [false, true].map(|bounded| {
        script! {
            { if bounded {
                Wots::<H>::checksig_verify_bounded_and_clear(&public_key)
            } else {
                Wots::<H>::checksig_verify_and_clear(&public_key)
            } }
            OP_TRUE
        }
        .compile_with_policy()
    });
    let original = pairs(&signature.to_witness());
    for leaf in &leaves {
        for slot in 0..original.len() {
            for selector in [vec![0x81], vec![0; 5], vec![0, 0, 0, 0x80, 0]] {
                let mut bad = original.clone();
                bad[slot][1] = selector;
                let result = execute_raw_script_with_inputs_strict(leaf.to_bytes(), witness(&bad));
                assert!(!result.success, "slot={slot}: {result}");
            }
            let mut bad = original.clone();
            bad[slot][0][0] ^= 1;
            assert!(!execute_raw_script_with_inputs_strict(leaf.to_bytes(), witness(&bad)).success);
        }
        let mut missing = signature.to_witness().to_vec();
        missing.pop();
        assert!(!execute_raw_script_with_inputs_strict(leaf.to_bytes(), missing).success);
        let mut extra = signature.to_witness().to_vec();
        extra.insert(0, vec![1]);
        assert!(!execute_raw_script_with_inputs_strict(leaf.to_bytes(), extra).success);
    }
    let first_key = selected_keys(&original, Wots::<H>::CHAINS)[0];
    let mut commitments = *public_key.commitments();
    commitments[first_key] = commitments[(first_key + 1) % commitments.len()];
    let duplicated = ConstantCompositionPublicKey20::<H>::from_commitments(commitments);
    let leaf = script! { { Wots::<H>::checksig_verify_and_clear(&duplicated) } OP_TRUE }
        .compile_with_policy();
    assert!(!execute_raw_script_with_inputs_strict(leaf.to_bytes(), witness(&original)).success);
}

#[test]
fn hostile_numbers_mutated_nodes_missing_data_and_changed_keys_are_rejected() {
    malformed::<Hash160>();
    malformed::<Sha256>();
    malformed::<Sha256Hash160>();
}

fn reorder<H: ChainHash>() {
    let key = Wots::<H>::signing_key_from_seed([0x42; 32]);
    let public_key = Wots::<H>::public_key(&key);
    let signature = Wots::<H>::sign(key, &[0x42; 20]);
    let leaf = script! { { Wots::<H>::checksig_verify_and_clear(&public_key) } OP_TRUE }
        .compile_with_policy();
    let original = pairs(&signature.to_witness());
    let keys = selected_keys(&original, Wots::<H>::CHAINS);

    // Slot order within one digit class changes the witness but not the message.
    let (first, same) = (0..keys.len())
        .flat_map(|first| (first + 1..keys.len()).map(move |second| (first, second)))
        .find(|&(first, second)| {
            signature.digits()[keys[first]] == signature.digits()[keys[second]]
        })
        .unwrap();
    let mut aliases = original.clone();
    let mut alias_keys = keys.clone();
    aliases.swap(first, same);
    alias_keys.swap(first, same);
    route_keys(&mut aliases, &alias_keys, Wots::<H>::CHAINS);
    let result = execute_raw_script_with_inputs_strict(leaf.to_bytes(), witness(&aliases));
    assert!(result.success, "{result}");

    // Move a disclosed low-digit opening forward to a higher-digit slot. The
    // compensating key moves backward, and no publicly forwardable node for it
    // can satisfy that slot. This checks the one-time antichain argument.
    let different = (1..keys.len())
        .find(|&slot| signature.digits()[keys[slot]] > signature.digits()[keys[0]])
        .unwrap();
    let lower = signature.digits()[keys[0]];
    let higher = signature.digits()[keys[different]];
    let mut bad = original.clone();
    let mut bad_keys = keys.clone();
    bad.swap(0, different);
    bad_keys.swap(0, different);
    route_keys(&mut bad, &bad_keys, Wots::<H>::CHAINS);
    for _ in lower..higher {
        bad[different][0] = H::hash_parts(&[&bad[different][0]]).as_ref().to_vec();
    }
    for _ in higher as usize..=Wots::<H>::MAX_DIGIT {
        assert!(!execute_raw_script_with_inputs_strict(leaf.to_bytes(), witness(&bad)).success);
        bad[0][0] = H::hash_parts(&[&bad[0][0]]).as_ref().to_vec();
    }
}

#[test]
fn equal_digit_reordering_is_an_alias_but_forwarding_cannot_change_composition() {
    reorder::<Hash160>();
    reorder::<Sha256>();
    reorder::<Sha256Hash160>();
}

fn clamping<H: ChainHash>() {
    let public_key = Wots::<H>::public_key(&Wots::<H>::signing_key_from_seed([0x42; 32]));
    let signature = (0u32..256)
        .find_map(|counter| {
            let message = sha256::Hash::hash(&counter.to_be_bytes()).to_byte_array()[..20]
                .try_into()
                .unwrap();
            let candidate = Wots::<H>::sign(Wots::<H>::signing_key_from_seed([0x42; 32]), &message);
            ((candidate.digits()[Wots::<H>::CHAINS - 1] as usize) < Wots::<H>::MAX_DIGIT)
                .then_some(candidate)
        })
        .unwrap();
    let original = pairs(&signature.to_witness());
    let selected = selected_keys(&original, Wots::<H>::CHAINS);
    let slot = selected
        .iter()
        .position(|&key| key == Wots::<H>::CHAINS - 1)
        .unwrap();
    let mut oversized = original.clone();
    oversized[slot][1] = i32::MAX.to_le_bytes().to_vec();

    // A deliberately matching foreign endpoint is below all signature items.
    // Positive overflow must never select it from outside the trusted pool.
    let fabricated_node = vec![0xa7; 17];
    let mut endpoint = H::hash_parts(&[&fabricated_node]);
    for _ in 1..Wots::<H>::MAX_DIGIT {
        endpoint = H::hash_parts(&[endpoint.as_ref()]);
    }
    let trap = H::commit(endpoint).as_ref().to_vec();
    let mut escaped = original.clone();
    escaped[0][0] = fabricated_node;
    escaped[0][1] = i32::MAX.to_le_bytes().to_vec();
    for bounded in [false, true] {
        let leaf = script! {
            { if bounded {
                Wots::<H>::checksig_verify_bounded_and_clear(&public_key)
            } else {
                Wots::<H>::checksig_verify_and_clear(&public_key)
            } }
            { trap.clone() } OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        let inputs = [vec![trap.clone()], witness(&oversized)].concat();
        let result = execute_raw_script_with_inputs_strict(leaf.to_bytes(), inputs);
        assert_eq!(result.success, !bounded, "bounded={bounded}: {result}");
        let inputs = [vec![trap.clone()], witness(&escaped)].concat();
        assert!(!execute_raw_script_with_inputs_strict(leaf.to_bytes(), inputs).success);
    }
}

#[test]
fn selector_clamp_aliases_last_real_key_without_reaching_foreign_protocol_items() {
    clamping::<Hash160>();
    clamping::<Sha256>();
    clamping::<Sha256Hash160>();
}

#[test]
fn isolated_roll_boundary_returns_invalid_stack_operation() {
    type DefaultWots = ConstantCompositionWinternitz20;
    let key = DefaultWots::signing_key_from_seed([0x42; 32]);
    let public_key = DefaultWots::public_key(&key);
    let signature = DefaultWots::sign(key, &[0x42; 20]);
    let leaf = script! { { DefaultWots::checksig_verify_isolated_and_clear(&public_key) } OP_TRUE }
        .compile_with_policy();
    let valid =
        execute_raw_script_with_inputs_strict(leaf.to_bytes(), signature.to_witness().to_vec());
    assert!(valid.success, "{valid}");
    assert_eq!(valid.final_stack.len(), 1);
    assert_eq!(valid.final_stack.get(0), vec![1]);
    for slot in [0, DefaultWots::OPENINGS / 2, DefaultWots::OPENINGS - 1] {
        let mut malformed = signature.to_witness().to_vec();
        malformed[2 * slot] = integer(DefaultWots::CHAINS - slot);
        // Removing the selector leaves exactly CHAINS - slot endpoints.
        // That index is one past the trusted pool and must return rejection,
        // including at the boundary that the previous interpreter panicked on.
        let failure = execute_raw_script_with_inputs_strict(leaf.to_bytes(), malformed);
        assert!(!failure.success, "slot={slot}: {failure}");
        assert_eq!(
            failure.error,
            Some(ExecError::InvalidStackOperation),
            "slot={slot}: {failure}"
        );
    }
}
