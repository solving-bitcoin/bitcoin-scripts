//! SHA-256-pinned starts for streaming mixed-hash checkpoints.

use super::hash_path_script;
use crate::support::script::{script, Script};

/// The start check needs two items above the selectors and preimage.
pub const MAX_CHAIN_BITS: usize = 997;

/// Verify ordered `(positive_width, digest)` checkpoints and return a Boolean.
/// Supply the rounds and their bits in reverse processing order, with the
/// preimage on top. Tapscript requires canonical empty/01 selectors. The
/// widths must total at most 997; callers budget any surrounding stack state.
/// No hints. The caller must enforce the returned Boolean when composing.
pub fn verify(starting_sha256: [u8; 32], checkpoints: &[(usize, [u8; 20])]) -> Script {
    assert!(!checkpoints.is_empty(), "empty checkpoint chain");
    let mut total = 0;
    for &(width, _) in checkpoints {
        assert!(
            (1..=MAX_CHAIN_BITS - total).contains(&width),
            "invalid checkpoint width or total"
        );
        total += width;
    }
    script! {
        OP_DUP OP_SHA256 { starting_sha256.to_vec() } OP_EQUALVERIFY
        for (index, (width, digest)) in checkpoints.iter().enumerate() {
            { hash_path_script(*width) }
            if index + 1 < checkpoints.len() {
                OP_DUP { digest.to_vec() } OP_EQUALVERIFY
            } else {
                { digest.to_vec() } OP_EQUAL
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commitments::hash_path::{
            hash_path_commitment, hash_path_integer_commitment, hash_path_integer_witness,
            verify_hash_path_chain,
        },
        support::execution::execute_script_with_inputs_strict as run,
    };
    use bitcoin::hashes::{sha256, Hash};

    fn split_witness(x: &[u8], left: u32, right: u32) -> Vec<Vec<u8>> {
        let mut data = hash_path_integer_witness(&[], right, 4);
        data.pop();
        data.extend(hash_path_integer_witness(x, left, 4));
        data
    }
    #[test]
    fn exhaustive_two_round_openings_and_first_bit_substitution() {
        let x = [0x42; 32];
        let start = sha256::Hash::hash(&x).to_byte_array();
        for left in 0..16 {
            for right in 0..16 {
                let a = hash_path_integer_commitment(&x, left, 4);
                let b = hash_path_integer_commitment(&a, right, 4);
                let leaf = verify(start, &[(4, a), (4, b)]);
                assert!(run(leaf.clone(), split_witness(&x, left, right)).success);
                if left % 2 == 1 {
                    let forged = split_witness(&start, left - 1, right);
                    assert!(run(verify_hash_path_chain(4, a, 4, b), forged.clone()).success);
                    assert!(!run(leaf, forged).success);
                }
            }
        }
    }
    #[test]
    fn rejects_bad_checkpoints_selectors_and_witness_shape() {
        let x = [0x24; 32];
        let start = sha256::Hash::hash(&x).to_byte_array();
        let a = hash_path_integer_commitment(&x, 5, 4);
        let b = hash_path_integer_commitment(&a, 2, 4);
        let data = split_witness(&x, 5, 2);
        let leaf = verify(start, &[(4, a), (4, b)]);
        for index in 0..8 {
            for malformed in [vec![0], vec![2], vec![0x80], vec![1, 0], vec![0; 521]] {
                let mut bad = data.clone();
                bad[index] = malformed;
                assert!(!run(leaf.clone(), bad).success);
            }
        }
        for (left, right) in [([0; 20], b), (a, [0; 20])] {
            assert!(!run(verify(start, &[(4, left), (4, right)]), data.clone()).success);
        }
        let mut missing = data.clone();
        missing.pop();
        assert!(!run(leaf.clone(), missing).success);
        let mut extra = data;
        extra.insert(0, vec![77]);
        assert!(!run(leaf, extra).success);
    }
    #[test]
    fn preimage_and_combined_stack_boundaries() {
        for n in [0, 1, 80, 81, 520, 521] {
            let x = vec![42; n];
            let start = sha256::Hash::hash(&x).to_byte_array();
            let h = hash_path_commitment(&x, &[false]);
            assert_eq!(
                run(verify(start, &[(1, h)]), vec![vec![], x]).success,
                n <= 520
            );
        }
        let x = [0x42; 32];
        let start = sha256::Hash::hash(&x).to_byte_array();
        for n in [1, 7, 997] {
            let h = hash_path_commitment(&x, &vec![false; n]);
            let leaf = verify(start, &[(n, h)]);
            let spare = 997 - n;
            let mut data = vec![vec![77]; spare];
            data.extend(vec![vec![]; n]);
            data.push(x.to_vec());
            let r = run(
                script! {{leaf.clone()} OP_VERIFY for _ in 0..spare {77 OP_EQUALVERIFY} OP_TRUE},
                data.clone(),
            );
            assert!(r.success, "{r}");
            assert_eq!(r.stats.max_nb_stack_items, 1000);
            data.insert(0, vec![77]);
            let r = run(leaf, data);
            assert!(matches!(
                r.error,
                Some(bitcoin_scriptexec::ExecError::StackSize)
            ));
            assert_eq!(r.stats.max_nb_stack_items, 1001);
        }
    }
    #[test]
    fn rejects_invalid_configuration() {
        for points in [
            vec![],
            vec![(0, [0; 20])],
            vec![(998, [0; 20])],
            vec![(997, [0; 20]), (1, [0; 20])],
            vec![(usize::MAX, [0; 20])],
        ] {
            assert!(std::panic::catch_unwind(|| verify([0; 32], &points)).is_err());
        }
    }
}
