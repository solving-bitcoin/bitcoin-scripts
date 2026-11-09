//! Length of the common prefix of two fixed-width opaque item vectors.

use crate::support::script::*;

pub const MAX_PAIRS: u32 = 499;

/// Consume `left[0] ... left[n-1] right[0] ... right[n-1]` and leave the
/// canonical length of their longest common prefix, in `0..=n`.
///
/// A prefix compares whole items by raw-byte equality. The fragment preserves
/// both caller stacks for an exact suffix, needs no hints, and peaks at
/// at most `2n+2` plus caller state for nonempty vectors.
pub fn opaque_common_prefix_len(n: u32) -> Script {
    assert!(n <= MAX_PAIRS, "opaque prefix supports 0..=499 pairs");
    script! {
        {n}
        for position in (0..n).rev() {
            OP_SWAP
            {position + 2} OP_ROLL
            OP_EQUAL
            OP_NOTIF OP_DROP {position} OP_ENDIF
        }
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
        include!("../../../research/opaque-common-prefix/baseline.rs");
    }

    const GENERATORS: [fn(u32) -> Script; 2] = [opaque_common_prefix_len, baseline::forward_prefix];

    fn checked(fragment: Script, expected: u32) -> ScriptBuf {
        script! {{fragment} {expected} OP_EQUALVERIFY OP_TRUE}.compile_with_policy()
    }

    fn run(script: ScriptBuf, input: Vec<Vec<u8>>) -> ExecuteInfo {
        match execute_tapscript(script, input, TapscriptProfile::Consensus).outcome {
            TapscriptOutcome::Executed(result) => result,
            outcome => panic!("expected execution: {outcome:?}"),
        }
    }

    fn clean(result: ExecuteInfo) {
        assert!(result.success && result.stack_limit_enforced, "{result}");
        assert_eq!(result.final_stack.len(), 1);
        assert_eq!(result.final_stack.get(0), vec![1]);
    }

    #[test]
    fn both_schedules_match_host_prefix_for_all_small_opaque_vectors() {
        for n in 0..=5 {
            let vectors: Vec<Vec<Vec<u8>>> = (0..1 << n)
                .map(|mask| {
                    (0..n)
                        .map(|bit| {
                            if mask >> bit & 1 == 1 {
                                vec![0x80]
                            } else {
                                vec![]
                            }
                        })
                        .collect()
                })
                .collect();
            for generate in GENERATORS {
                let leaves: Vec<_> = (0..=n).map(|len| checked(generate(n), len)).collect();
                for left in &vectors {
                    for right in &vectors {
                        let len = left.iter().zip(right).take_while(|(l, r)| l == r).count();
                        clean(run(
                            leaves[len].clone(),
                            [left.as_slice(), right.as_slice()].concat(),
                        ));
                    }
                }
            }
        }
    }

    #[test]
    fn distinguishes_first_mismatch_from_later_matches_and_checks_shape() {
        let left = vec![vec![0xaa; 520], vec![0x80], vec![1, 0], vec![0xc7]];
        let mut right = left.clone();
        right[1] = vec![];
        for generate in GENERATORS {
            let leaf = checked(generate(4), 1);
            let valid = [left.as_slice(), right.as_slice()].concat();
            clean(run(leaf.clone(), valid.clone()));
            assert!(!run(checked(generate(4), 3), valid.clone()).success);
            for position in 0..valid.len() {
                let mut short = valid.clone();
                short.remove(position);
                assert!(!run(leaf.clone(), short).success);
            }
            let mut extra = valid.clone();
            extra.insert(0, vec![]);
            assert!(!run(leaf.clone(), extra).success);
            let mut oversized = valid;
            oversized[7] = vec![0x42; 521];
            assert_eq!(run(leaf, oversized).error, Some(ExecError::PushSize));
        }
    }

    #[test]
    fn checks_exact_combined_stack_limits_and_preserves_both_caller_stacks() {
        let items = vec![vec![0x91, 0x36]; (2 * MAX_PAIRS) as usize];
        let result = run(
            checked(opaque_common_prefix_len(MAX_PAIRS), MAX_PAIRS),
            items.clone(),
        );
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        clean(result);
        let result = run(
            checked(baseline::forward_prefix(MAX_PAIRS), MAX_PAIRS),
            items,
        );
        assert_eq!(result.error, Some(ExecError::StackSize));
        let n = MAX_PAIRS - 1;
        let result = run(
            checked(baseline::forward_prefix(n), n),
            vec![vec![0x81, 0x42]; (2 * n) as usize],
        );
        assert_eq!(result.stats.max_nb_stack_items, 999);
        clean(result);

        let fragment = opaque_common_prefix_len(n);
        let script = script! {OP_TOALTSTACK {fragment} OP_FROMALTSTACK}.compile_with_policy();
        let main = vec![0x19, 0x83];
        let alt = vec![0x65, 0x98];
        let mut input = vec![main.clone()];
        input.extend(vec![vec![0x91, 0x36]; (2 * n) as usize]);
        input.push(alt.clone());
        let result = run(script.clone(), input.clone());
        assert_eq!(result.error, None);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        let mut expected = [0u8; 8];
        let len = bitcoin::script::write_scriptint(&mut expected, i64::from(n));
        let actual: Vec<_> = (0..result.final_stack.len())
            .map(|i| result.final_stack.get(i))
            .collect();
        assert_eq!(actual, [main, expected[..len].to_vec(), alt]);
        input.insert(0, vec![]);
        assert_eq!(run(script, input).error, Some(ExecError::StackSize));
        assert!(std::panic::catch_unwind(|| opaque_common_prefix_len(MAX_PAIRS + 1)).is_err());
    }
}
