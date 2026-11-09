//! Exact multiset equality over two lists of raw stack items.

use crate::arithmetic::scriptint::verify_canonical;
use crate::support::script::*;

pub const MAX_WIDTH: u32 = 332;

/// Verify equality with exact multiplicity and consume both vectors and hints.
///
/// Entry is `left[0] ... left[n-1] right[0] right[1] hint[1] ... right[n-1] hint[n-1]`.
/// Hint j is the top-relative depth of the item equal to right[j] in the
/// shrinking left pool when consuming right items in descending index order.
/// The final pair needs no hint. Both caller stacks are preserved for an
/// exact suffix. The combined peak is at most `3*n + 2` plus caller state
/// for n >= 2, or two plus caller state for n = 1.
pub fn verify_opaque_multiset_with_hints(n: u32) -> Script {
    assert!(
        (1..=MAX_WIDTH).contains(&n),
        "multiset width must be in 1..=332"
    );
    script! {
        for remaining in (2..=n).rev() {
            {verify_canonical()}
            OP_DUP 0 {remaining} OP_WITHIN OP_VERIFY
            // Above the left pool are `remaining` right items and
            // `remaining - 2` hints other than the current depth.
            {2 * remaining - 2} OP_ADD OP_ROLL OP_EQUALVERIFY
        }
        OP_EQUALVERIFY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{
        execution::ExecuteInfo,
        tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
    };
    use bitcoin::ScriptBuf;
    use bitcoin_scriptexec::ExecError;

    mod baseline {
        use crate::support::script::*;
        include!("../../../research/opaque-multiset/baseline.rs");
    }
    use baseline::{hint_depths, num, witness};

    fn complete(fragment: Script) -> ScriptBuf {
        script! {{fragment} OP_TRUE}.compile_with_policy()
    }

    fn run(script: ScriptBuf, witness: Vec<Vec<u8>>) -> ExecuteInfo {
        match execute_tapscript(script, witness, TapscriptProfile::Consensus).outcome {
            TapscriptOutcome::Executed(result) => result,
            outcome => panic!("expected local execution: {outcome:?}"),
        }
    }

    fn clean(result: ExecuteInfo) {
        assert!(result.success && result.stack_limit_enforced, "{result}");
        assert_eq!(result.final_stack.len(), 1);
        assert_eq!(result.final_stack.get(0), vec![1]);
    }

    #[test]
    fn both_schedules_match_sorted_raw_vectors_with_duplicates() {
        let alphabet = [vec![], vec![0x80], vec![1]];
        for n in 1..=3u32 {
            let vectors: Vec<Vec<Vec<u8>>> = (0..3usize.pow(n))
                .map(|mut rank| {
                    (0..n)
                        .map(|_| {
                            let item = alphabet[rank % 3].clone();
                            rank /= 3;
                            item
                        })
                        .collect()
                })
                .collect();
            let greedy = complete(baseline::verify_greedy(n));
            let hinted = complete(verify_opaque_multiset_with_hints(n));
            let dummy = vec![0; n as usize - 1];
            for left in &vectors {
                for right in &vectors {
                    let (mut a, mut b) = (left.clone(), right.clone());
                    a.sort();
                    b.sort();
                    let equal = a == b;
                    let depths = hint_depths(left, right);
                    assert_eq!(depths.is_some(), equal);
                    assert_eq!(
                        run(greedy.clone(), witness(left, right, None)).success,
                        equal
                    );
                    let input = witness(left, right, Some(depths.as_deref().unwrap_or(&dummy)));
                    assert_eq!(run(hinted.clone(), input).success, equal);
                }
            }
        }
    }

    #[test]
    fn rejects_bad_depths_opaque_aliases_and_reuse() {
        let left = [vec![0x41], vec![0x42; 520], vec![0x41]];
        let right = [left[1].clone(), left[2].clone(), left[0].clone()];
        let leaf = complete(verify_opaque_multiset_with_hints(3));
        let depths = hint_depths(&left, &right).unwrap();
        let valid = witness(&left, &right, Some(&depths));
        clean(run(leaf.clone(), valid.clone()));
        clean(run(
            complete(baseline::verify_greedy(3)),
            witness(&left, &right, None),
        ));
        for (position, limit) in [(5, 2), (7, 3)] {
            for (bad, error) in [
                (num(-1), ExecError::Verify),
                (num(limit), ExecError::Verify),
                (vec![0x80], ExecError::EqualVerify),
                (vec![1, 0], ExecError::EqualVerify),
                (vec![0; 5], ExecError::ScriptIntNumericOverflow),
                (vec![0; 521], ExecError::PushSize),
            ] {
                let mut input = valid.clone();
                input[position] = bad;
                let result = run(leaf.clone(), input);
                assert!(!result.success);
                assert_eq!(result.error, Some(error));
            }
        }
        let duplicate = vec![vec![0x41]; 3];
        for d1 in 0..2 {
            for d2 in 0..3 {
                assert!(!run(leaf.clone(), witness(&left, &duplicate, Some(&[d1, d2]))).success);
            }
        }
        for position in 0..valid.len() {
            let mut short = valid.clone();
            short.remove(position);
            assert!(!run(leaf.clone(), short).success);
        }
        let mut extra = valid;
        extra.insert(0, vec![]);
        assert!(!run(leaf, extra).success);
    }

    #[test]
    fn preserves_caller_stacks_at_the_hinted_frontier() {
        let n = MAX_WIDTH;
        let fragment = verify_opaque_multiset_with_hints(n);
        let script = script! {OP_TOALTSTACK {fragment} OP_FROMALTSTACK}.compile_with_policy();
        let data = vec![vec![0x9b, 0x80]; n as usize];
        let main = vec![0x55, 0x81];
        let alt = vec![0x19, 0x99];
        let mut input = vec![main.clone()];
        input.extend(witness(&data, &data, Some(&vec![0; n as usize - 1])));
        input.push(alt.clone());
        let result = run(script.clone(), input.clone());
        assert_eq!(result.error, None);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        assert_eq!(result.final_stack.len(), 2);
        assert_eq!(result.final_stack.get(0), main);
        assert_eq!(result.final_stack.get(1), alt);
        input.insert(0, vec![]);
        assert_eq!(run(script, input).error, Some(ExecError::StackSize));
        for width in [0, MAX_WIDTH + 1] {
            assert!(std::panic::catch_unwind(|| verify_opaque_multiset_with_hints(width)).is_err());
        }
    }
}
