//! Locate the sole raw mismatch in fixed-width interleaved vectors.

use super::script::{script, Script};

/// Consume `a[0] b[0] ... a[n-1] b[n-1]` and return the zero-based index
/// of the only unequal pair. Abort for zero or multiple mismatches.
/// Values are opaque. Both caller stacks are preserved.
pub fn unique_mismatch_index(width: u32) -> Script {
    assert!(
        (1..=500).contains(&width),
        "unique mismatch supports 1..=500 pairs"
    );
    script! {
        // Consume the top pair before allocating the index state.
        OP_EQUAL OP_IF 0 OP_ELSE { width } OP_ENDIF OP_TOALTSTACK
        for index in (0..width - 1).rev() {
            OP_EQUAL OP_NOTIF
                OP_FROMALTSTACK 0 OP_EQUALVERIFY
                { index + 1 } OP_TOALTSTACK
            OP_ENDIF
        }
        OP_FROMALTSTACK OP_DUP OP_VERIFY OP_1SUB
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
        include!("../../../research/opaque-single-mismatch/baseline.rs");
    }

    mod fixture {
        include!("../../../research/opaque-single-mismatch/fixture.rs");
    }

    fn leaf(fragment: Script, expected: Option<u32>) -> ScriptBuf {
        let check = match expected {
            Some(index) => script! { { index } OP_EQUALVERIFY },
            None => script! { OP_DROP },
        };
        script! { { fragment } { check } OP_TRUE }.compile_with_policy()
    }

    #[test]
    fn every_short_mismatch_mask_matches_the_host_index() {
        for width in 1..=8 {
            for mask in 0u32..1 << width {
                let witness = (0..width)
                    .flat_map(|i| {
                        let left = match i {
                            0 => vec![],
                            1 => vec![0x80],
                            _ => vec![0xff, i as u8, 0x00, 0x00, 0xff],
                        };
                        let right = if mask & (1 << i) == 0 {
                            left.clone()
                        } else {
                            vec![0]
                        };
                        [left, right]
                    })
                    .collect::<Vec<_>>();
                let differing: Vec<_> = witness
                    .chunks_exact(2)
                    .enumerate()
                    .filter_map(|(index, pair)| (pair[0] != pair[1]).then_some(index as u32))
                    .collect();
                let expected = match differing.as_slice() {
                    [index] => Some(*index),
                    _ => None,
                };
                for fragment in [unique_mismatch_index(width), baseline::dense_mask(width)] {
                    let leaf = leaf(fragment, expected);
                    for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
                        assert_eq!(
                            execute_tapscript(leaf.clone(), witness.clone(), profile).accepted(),
                            Some(expected.is_some()),
                            "width {width}, mask {mask}, {profile:?}",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn rejects_wrong_index_additional_mismatch_and_malformed_suffix() {
        let width = 128;
        let index = 77;
        let valid = fixture::single_difference(width, index);
        let checked = leaf(unique_mismatch_index(width), Some(index));
        assert_eq!(
            execute_tapscript(checked.clone(), valid.clone(), TapscriptProfile::Consensus)
                .accepted(),
            Some(true)
        );
        let wrong_index = leaf(unique_mismatch_index(width), Some(index - 1));
        assert_eq!(
            execute_tapscript(wrong_index, valid.clone(), TapscriptProfile::Consensus).accepted(),
            Some(false)
        );
        let mut second = valid.clone();
        second[1].push(0);
        let mut extra = valid.clone();
        extra.insert(0, vec![]);
        for invalid in [second, extra, valid[1..].to_vec()] {
            assert_eq!(
                execute_tapscript(checked.clone(), invalid, TapscriptProfile::Consensus).accepted(),
                Some(false)
            );
        }
    }

    #[test]
    fn equality_is_raw_and_obeys_entry_element_limits() {
        let checked = leaf(unique_mismatch_index(2), Some(1));
        let mut witness = vec![vec![0xaa; 520], vec![0xaa; 520], vec![], vec![0x80]];
        assert_eq!(
            execute_tapscript(
                checked.clone(),
                witness.clone(),
                TapscriptProfile::Consensus
            )
            .accepted(),
            Some(true)
        );
        assert_eq!(
            execute_tapscript(checked.clone(), witness.clone(), TapscriptProfile::Policy)
                .accepted(),
            Some(false)
        );
        witness[0].push(0);
        assert_eq!(
            execute_tapscript(checked, witness, TapscriptProfile::Consensus).accepted(),
            Some(false)
        );
    }

    #[test]
    fn allocation_after_the_first_comparison_preserves_the_full_frontier() {
        fn eager_state(width: u32) -> Script {
            script! {
                0 OP_TOALTSTACK
                for index in (0..width).rev() {
                    OP_EQUAL OP_NOTIF
                        OP_FROMALTSTACK 0 OP_EQUALVERIFY
                        { index + 1 } OP_TOALTSTACK
                    OP_ENDIF
                }
                OP_FROMALTSTACK OP_DUP OP_VERIFY OP_1SUB
            }
        }

        let width = 500;
        let witness = fixture::single_difference(width, width - 1);
        for (fragment, expected) in [
            (unique_mismatch_index(width), true),
            (baseline::dense_mask(width), true),
            (eager_state(width), false),
        ] {
            let result = execute_tapscript(
                leaf(fragment, Some(width - 1)),
                witness.clone(),
                TapscriptProfile::Consensus,
            );
            assert_eq!(result.accepted(), Some(expected));
            let run = result.execution().unwrap();
            if expected {
                assert_eq!(run.stats.max_nb_stack_items, 1000);
            } else {
                assert_eq!(run.error, Some(ExecError::StackSize));
            }
        }
        let control = execute_tapscript(
            leaf(eager_state(width - 1), Some(0)),
            fixture::single_difference(width - 1, 0),
            TapscriptProfile::Consensus,
        );
        assert_eq!(control.accepted(), Some(true));

        let caller_leaf = script! {
            OP_TOALTSTACK
            { unique_mismatch_index(499) } 7 OP_EQUALVERIFY
            OP_FROMALTSTACK 18 OP_EQUALVERIFY
            17 OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        let mut caller = vec![vec![17]];
        caller.extend(fixture::single_difference(499, 7));
        caller.push(vec![18]);
        let result = execute_tapscript(
            caller_leaf.clone(),
            caller.clone(),
            TapscriptProfile::Consensus,
        );
        assert_eq!(result.accepted(), Some(true));
        assert_eq!(result.execution().unwrap().stats.max_nb_stack_items, 1000);
        caller.insert(0, vec![19]);
        let result = execute_tapscript(caller_leaf, caller, TapscriptProfile::Consensus);
        assert_eq!(
            result.execution().unwrap().error,
            Some(ExecError::StackSize)
        );
        for width in [0, 501] {
            assert!(std::panic::catch_unwind(|| unique_mismatch_index(width)).is_err());
        }
    }
}
