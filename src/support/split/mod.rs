//! Stable bipartition of opaque items between the main and alt stacks.

use super::{
    script::{script, Script},
    selection::MAX_PAIRS,
};

/// Consumes interleaved payload/flag pairs. Appends false payloads and their
/// count to main, and true payloads to alt, both in input order.
///
/// Flags use native tapscript MINIMALIF. Callers need room for `2*n+2`
/// combined items in addition to their live state, or one item for `n=0`.
pub fn stable_split_items(pair_count: u32) -> Script {
    assert!(
        pair_count <= MAX_PAIRS,
        "stable split supports 0..=499 pairs"
    );
    script! {
        { 2 * pair_count }
        for _ in 0..pair_count {
            // The cursor equals the live main width below itself.
            OP_DUP OP_ROLL
            OP_OVER OP_ROLL
            OP_IF
                OP_TOALTSTACK 2 OP_SUB
            OP_ELSE
                OP_SWAP OP_1SUB
            OP_ENDIF
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{
        script::ScriptCompilation,
        tapscript::{execute_tapscript, TapscriptProfile},
    };
    use bitcoin::ScriptBuf;
    use bitcoin_scriptexec::ExecError;

    mod baseline {
        use super::*;
        include!("../../../research/opaque-stable-bipartition/baseline.rs");
    }

    mod fixture {
        use super::*;
        include!("../../../research/opaque-stable-bipartition/fixture.rs");
    }

    fn leaf(fragment: Script, records: &[(Vec<u8>, bool)]) -> ScriptBuf {
        script! {
            { fragment }
            { fixture::verify_outputs(records) }
            OP_TRUE
        }
        .compile_with_policy()
    }

    #[test]
    fn every_short_mask_matches_the_host_stable_partition() {
        for pairs in 0..=8 {
            for mask in 0..1 << pairs {
                let records: Vec<_> = (0..pairs)
                    .map(|i| {
                        let bytes = match i {
                            0 => vec![],
                            1 => vec![0x80],
                            _ => vec![i as u8, 0xff, 0, 0, 0xff],
                        };
                        (bytes, mask & (1 << i) != 0)
                    })
                    .collect();
                for split in [stable_split_items(pairs), baseline::recomputed_depth(pairs)] {
                    let leaf = leaf(split, &records);
                    for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
                        assert_eq!(
                            execute_tapscript(leaf.clone(), fixture::witness(&records), profile)
                                .accepted(),
                            Some(true),
                            "width {pairs}, mask {mask}, {profile:?}",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn rejects_hostile_flags_and_incorrect_complete_output_bindings() {
        let records = vec![
            (vec![0x80], false),
            (vec![0; 5], true),
            (vec![], false),
            (vec![0; 5], true),
        ];
        let leaf = leaf(stable_split_items(4), &records);
        let witness = fixture::witness(&records);
        assert_eq!(
            execute_tapscript(leaf.clone(), witness.clone(), TapscriptProfile::Consensus)
                .accepted(),
            Some(true)
        );
        for index in [1, 3, 5, 7] {
            for malformed in [vec![0], vec![0x80], vec![2], vec![1, 0], vec![0x81]] {
                let mut hostile = witness.clone();
                hostile[index] = malformed;
                let result = execute_tapscript(leaf.clone(), hostile, TapscriptProfile::Consensus);
                assert_eq!(result.accepted(), Some(false));
                assert_eq!(
                    result.execution().unwrap().error,
                    Some(ExecError::TapscriptMinimalIf)
                );
            }
        }
        for index in [0, 2, 4, 6] {
            let mut hostile = witness.clone();
            hostile[index] = vec![0x42];
            assert_eq!(
                execute_tapscript(leaf.clone(), hostile, TapscriptProfile::Consensus).accepted(),
                Some(false)
            );
        }
        let mut wrong_count = witness.clone();
        wrong_count[1] = vec![1];
        assert_eq!(
            execute_tapscript(leaf.clone(), wrong_count, TapscriptProfile::Consensus).accepted(),
            Some(false)
        );
        for hostile in [witness[..7].to_vec(), [vec![vec![0x42]], witness].concat()] {
            assert_eq!(
                execute_tapscript(leaf.clone(), hostile, TapscriptProfile::Consensus).accepted(),
                Some(false)
            );
        }
    }

    #[test]
    fn opaque_payloads_obey_entry_element_limits() {
        let records = [(vec![0xa5; 520], true), (vec![0x80; 520], false)];
        let leaf = leaf(stable_split_items(2), &records);
        let mut witness = fixture::witness(&records);
        assert_eq!(
            execute_tapscript(leaf.clone(), witness.clone(), TapscriptProfile::Consensus)
                .accepted(),
            Some(true)
        );
        assert_eq!(
            execute_tapscript(leaf.clone(), witness.clone(), TapscriptProfile::Policy).accepted(),
            Some(false)
        );
        witness[0].push(0);
        assert_eq!(
            execute_tapscript(leaf, witness, TapscriptProfile::Consensus).accepted(),
            Some(false)
        );
    }

    #[test]
    fn combined_frontier_and_both_caller_stacks_are_observable() {
        let records = fixture::alternating(498);
        let caller_leaf = script! {
            OP_TOALTSTACK
            { stable_split_items(498) }
            { fixture::verify_outputs(&records) }
            OP_FROMALTSTACK 18 OP_EQUALVERIFY
            17 OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        let mut witness = vec![vec![17]];
        witness.extend(fixture::witness(&records));
        witness.push(vec![18]);
        let result = execute_tapscript(
            caller_leaf.clone(),
            witness.clone(),
            TapscriptProfile::Consensus,
        );
        assert_eq!(result.accepted(), Some(true));
        assert_eq!(result.execution().unwrap().stats.max_nb_stack_items, 1000);
        witness.insert(0, vec![19]);
        let result = execute_tapscript(caller_leaf, witness, TapscriptProfile::Consensus);
        assert_eq!(result.accepted(), Some(false));
        assert_eq!(
            result.execution().unwrap().error,
            Some(ExecError::StackSize)
        );

        let records = fixture::alternating(MAX_PAIRS);
        let witness = fixture::witness(&records);
        for (split, accepted) in [
            (stable_split_items(MAX_PAIRS), true),
            (baseline::recomputed_depth(MAX_PAIRS), false),
        ] {
            let result = execute_tapscript(
                leaf(split, &records),
                witness.clone(),
                TapscriptProfile::Consensus,
            );
            assert_eq!(result.accepted(), Some(accepted));
            if accepted {
                assert_eq!(result.execution().unwrap().stats.max_nb_stack_items, 1000);
            } else {
                assert_eq!(
                    result.execution().unwrap().error,
                    Some(ExecError::StackSize)
                );
            }
        }
        assert!(std::panic::catch_unwind(|| stable_split_items(MAX_PAIRS + 1)).is_err());
    }
}
