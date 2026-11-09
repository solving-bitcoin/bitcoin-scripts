//! Verify SHA-256 openings selected by their actual byte length.

use super::preimage_length::MAX_PREIMAGE_LENGTH;
use crate::support::script::{script, Script};

/// Consume one preimage and verify the digest at its length's slot.
///
/// Slot zero is `first_length`. Lengths are contiguous through
/// `first_length + commitments.len() - 1`, which must be at most 520.
/// `block_size` is in `1..=commitments.len()`. Only the selected block is
/// materialized on stack. Success preserves both caller stacks.
pub fn verify_length_keyed_sha256(
    first_length: usize,
    commitments: &[[u8; 32]],
    block_size: usize,
) -> Script {
    assert!(
        first_length <= MAX_PREIMAGE_LENGTH
            && !commitments.is_empty()
            && commitments.len() <= MAX_PREIMAGE_LENGTH + 1 - first_length,
        "digest slots must be a nonempty contiguous range of lengths in 0..=520"
    );
    assert!(
        (1..=commitments.len()).contains(&block_size),
        "block size must be in 1..=digest count"
    );
    script! {
        OP_SIZE OP_DUP { first_length } { first_length + commitments.len() }
        OP_WITHIN OP_VERIFY
        OP_SWAP OP_SHA256 OP_SWAP
        { dispatch(first_length, commitments, block_size) }
    }
}

// The top length has already been checked against the current slice.
fn dispatch(first_length: usize, commitments: &[[u8; 32]], block_size: usize) -> Script {
    if commitments.len() <= block_size {
        if let [digest] = commitments {
            return script! { OP_DROP { digest.to_vec() } OP_EQUALVERIFY };
        }
        return script! {
            { first_length } OP_SUB OP_TOALTSTACK
            for digest in commitments.iter().rev() { { digest.to_vec() } }
            OP_FROMALTSTACK OP_ROLL OP_TOALTSTACK
            for _ in 1..commitments.len() { OP_DROP }
            OP_FROMALTSTACK OP_EQUALVERIFY
        };
    }

    let left_count = commitments.len().div_ceil(block_size) / 2 * block_size;
    let (left, right) = commitments.split_at(left_count);
    let pivot = first_length + left_count;
    script! {
        OP_DUP { pivot } OP_LESSTHAN OP_IF
            { dispatch(first_length, left, block_size) }
        OP_ELSE
            { dispatch(pivot, right, block_size) }
        OP_ENDIF
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commitments::preimage_length::preimage_length_commitment,
        support::{
            script::ScriptCompilation,
            tapscript::{execute_tapscript, TapscriptProfile},
        },
    };
    use bitcoin::ScriptBuf;
    use bitcoin_scriptexec::ExecError;

    mod fixture {
        use super::preimage_length_commitment;
        include!("../../../research/length-keyed-sha256/fixture.rs");
    }

    fn leaf(first: usize, commitments: &[[u8; 32]], block: usize) -> ScriptBuf {
        script! { { verify_length_keyed_sha256(first, commitments, block) } OP_TRUE }
            .compile_with_policy()
    }

    #[test]
    fn every_length_selects_its_digest_across_partial_block_boundaries() {
        let first = 7;
        let count = 17;
        let commitments = fixture::commitments(first, count);
        for block in 1..=count {
            let leaf = leaf(first, &commitments, block);
            for length in first..first + count {
                for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
                    assert_eq!(
                        execute_tapscript(leaf.clone(), vec![fixture::preimage(length)], profile)
                            .accepted(),
                        Some(true),
                        "length {length}, block size {block}, {profile:?}",
                    );
                }
            }
        }
    }

    #[test]
    fn rejects_bad_bytes_wrong_slots_and_lengths_outside_the_window() {
        let first = 7;
        let mut commitments = fixture::commitments(first, 17);
        commitments.swap(0, 1);
        let exact_length_below_window = fixture::preimage(first - 1);
        commitments[2] = preimage_length_commitment(&exact_length_below_window);
        let mut wrong_bytes = fixture::preimage(first + 3);
        wrong_bytes[0] ^= 1;
        for block in [1, 4, 17] {
            let checked = leaf(first, &commitments, block);
            for invalid in [
                vec![],
                vec![fixture::preimage(first)],
                vec![fixture::preimage(first + 1)],
                vec![exact_length_below_window.clone()],
                vec![fixture::preimage(first + 17)],
                vec![wrong_bytes.clone()],
                vec![vec![], fixture::preimage(first + 4)],
            ] {
                assert_eq!(
                    execute_tapscript(checked.clone(), invalid, TapscriptProfile::Consensus)
                        .accepted(),
                    Some(false)
                );
            }
        }
    }

    #[test]
    fn empty_and_maximum_length_obey_the_two_local_profiles() {
        let commitments = fixture::commitments(0, 521);
        for block in [1, 8, 521] {
            let checked = leaf(0, &commitments, block);
            for length in [0, 1, 80, 81, 519, 520, 521] {
                let witness = vec![fixture::preimage(length)];
                let local = execute_tapscript(
                    checked.clone(),
                    witness.clone(),
                    TapscriptProfile::Consensus,
                );
                let policy = execute_tapscript(checked.clone(), witness, TapscriptProfile::Policy);
                assert_eq!(local.accepted(), Some(length <= 520));
                assert_eq!(policy.accepted(), Some(length <= 80));
            }
        }
        for (first, count, block) in [
            (0, 0, 1),
            (0, 1, 0),
            (0, 1, 2),
            (0, 522, 1),
            (521, 1, 1),
            (520, 2, 1),
            (usize::MAX, 1, 1),
        ] {
            let commitments = vec![[0; 32]; count];
            assert!(std::panic::catch_unwind(|| {
                verify_length_keyed_sha256(first, &commitments, block)
            })
            .is_err());
        }
    }

    #[test]
    fn blocked_table_preserves_more_caller_state_than_the_full_table() {
        let commitments = fixture::commitments(0, 521);
        for (block, filler, expected) in [(521, 475, true), (521, 476, false), (8, 476, true)] {
            let checked = script! {
                OP_TOALTSTACK
                { verify_length_keyed_sha256(0, &commitments, block) }
                OP_FROMALTSTACK 18 OP_EQUALVERIFY
                for _ in 0..filler { OP_DROP }
                17 OP_EQUALVERIFY OP_TRUE
            }
            .compile_with_policy();
            let mut witness = vec![vec![17]];
            witness.extend((0..filler).map(|_| vec![]));
            witness.extend([fixture::preimage(47), vec![18]]);
            let result = execute_tapscript(checked, witness, TapscriptProfile::Consensus);
            assert_eq!(result.accepted(), Some(expected));
            let run = result.execution().unwrap();
            if block == 521 && expected {
                assert_eq!(run.stats.max_nb_stack_items, 1000);
            } else if !expected {
                assert_eq!(run.error, Some(ExecError::StackSize));
            }
        }
    }
}
