//! Check a pair of raw ASCII letters for opposite case.

use crate::support::script::{script, Script};

/// Consumes two exact one-byte ASCII items denoting the same letter in opposite
/// cases. Leaves both caller stacks intact. Order is immaterial.
pub fn verify_opposite_ascii_case_pair() -> Script {
    script! {
        OP_SIZE 1 OP_EQUALVERIFY
        OP_SWAP
        OP_SIZE 1 OP_EQUALVERIFY
        OP_2DUP OP_MIN 65 91 OP_WITHIN OP_VERIFY
        OP_SUB OP_ABS 32 OP_NUMEQUALVERIFY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{
        script::ScriptCompilation,
        tapscript::{execute_tapscript, TapscriptProfile},
    };

    mod baseline {
        use super::*;
        include!("../../../research/ascii-opposite-case/baseline.rs");
    }

    #[test]
    fn every_pair_of_raw_bytes_matches_the_host_predicate() {
        let leaves = [
            verify_opposite_ascii_case_pair(),
            baseline::raw_mate(),
            baseline::independent_fold(),
        ]
        .map(|check| script! { { check } OP_TRUE }.compile_with_policy());
        for first in u8::MIN..=u8::MAX {
            for second in u8::MIN..=u8::MAX {
                let expected = first.is_ascii_alphabetic() && second == (first ^ 32);
                for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
                    for leaf in &leaves {
                        assert_eq!(
                            execute_tapscript(
                                leaf.clone(),
                                vec![vec![first], vec![second]],
                                profile,
                            )
                            .accepted(),
                            Some(expected),
                            "{first:02x}, {second:02x}, {profile:?}",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn rejects_punctuation_gap_aliases_missing_and_extra_items() {
        for check in [
            verify_opposite_ascii_case_pair(),
            baseline::raw_mate(),
            baseline::independent_fold(),
        ] {
            let leaf = script! { { check } OP_TRUE }.compile_with_policy();
            for witness in [
                vec![],
                vec![vec![b'A']],
                vec![vec![b'A'], vec![b'a'], vec![b'A']],
                vec![vec![], vec![b'a']],
                vec![vec![b'A'], vec![]],
                vec![vec![b'A', 0], vec![b'a']],
                vec![vec![b'A'], vec![b'a', 0]],
                vec![vec![b'A'; 520], vec![b'a']],
                vec![vec![b'A'], vec![b'a'; 520]],
                vec![vec![b'@'], vec![b'`']],
                vec![vec![b'['], vec![b'{']],
            ] {
                assert_eq!(
                    execute_tapscript(leaf.clone(), witness, TapscriptProfile::Consensus)
                        .accepted(),
                    Some(false)
                );
            }
        }
    }

    #[test]
    fn exact_combined_frontier_preserves_both_caller_stacks() {
        let caller_leaf = script! {
            OP_TOALTSTACK OP_TOALTSTACK
            for _ in 0..497 { { verify_opposite_ascii_case_pair() } }
            OP_FROMALTSTACK 18 OP_EQUALVERIFY
            OP_FROMALTSTACK 19 OP_EQUALVERIFY
            17 OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        let mut witness = vec![vec![17]];
        witness.extend((0..497).flat_map(|_| [vec![b'Z'], vec![b'z']]));
        witness.extend([vec![18], vec![19]]);
        let result = execute_tapscript(
            caller_leaf.clone(),
            witness.clone(),
            TapscriptProfile::Consensus,
        );
        assert_eq!(result.accepted(), Some(true));
        assert_eq!(result.execution().unwrap().stats.max_nb_stack_items, 1000);
        witness.insert(0, vec![20]);
        let result = execute_tapscript(caller_leaf, witness, TapscriptProfile::Consensus);
        assert_eq!(result.accepted(), Some(false));
        assert!(result.execution().unwrap().error.is_some());

        for pairs in [498, 499] {
            let leaf = script! {
                for _ in 0..pairs { { verify_opposite_ascii_case_pair() } }
                OP_TRUE
            }
            .compile_with_policy();
            let witness = (0..pairs).flat_map(|_| [vec![b'a'], vec![b'A']]).collect();
            let result = execute_tapscript(leaf, witness, TapscriptProfile::Consensus);
            assert_eq!(result.accepted(), Some(pairs == 498));
            if pairs == 498 {
                assert_eq!(result.execution().unwrap().stats.max_nb_stack_items, 999);
            } else {
                assert!(result.execution().unwrap().error.is_some());
            }
        }
    }

    #[test]
    fn dropping_the_shared_interval_accepts_punctuation() {
        let gap_only = script! {
            OP_SIZE 1 OP_EQUALVERIFY
            OP_SWAP OP_SIZE 1 OP_EQUALVERIFY
            OP_SUB OP_ABS 32 OP_NUMEQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        let witness = vec![vec![b'@'], vec![b'`']];
        assert_eq!(
            execute_tapscript(gap_only, witness, TapscriptProfile::Consensus).accepted(),
            Some(true)
        );
    }

    #[test]
    fn removing_the_byte_guards_accepts_numeric_aliases() {
        let unchecked = script! {
            OP_2DUP OP_MIN 65 91 OP_WITHIN OP_VERIFY
            OP_SUB OP_ABS 32 OP_NUMEQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        for witness in [
            vec![vec![b'A', 0], vec![b'a']],
            vec![vec![b'A'], vec![b'a', 0]],
        ] {
            let local = execute_tapscript(
                unchecked.clone(),
                witness.clone(),
                TapscriptProfile::Consensus,
            );
            let policy = execute_tapscript(unchecked.clone(), witness, TapscriptProfile::Policy);
            assert_eq!(local.accepted(), Some(true));
            assert_eq!(policy.accepted(), Some(false));
        }
    }
}
