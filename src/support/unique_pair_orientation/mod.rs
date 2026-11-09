//! Verify a unique orientation of each pair of opaque byte strings.

use crate::support::script::{script, Script};

mod schedule;

/// Consume 1..=249 quartets `a b c d` and return one canonical bit per
/// quartet, in original order. Zero means `(a,b) = (c,d)`. One means
/// `(a,b) = (d,c)`. Each quartet must admit exactly one orientation.
/// Preserves both caller stacks.
pub fn opaque_pair_orientations(width: u32) -> Script {
    assert!(
        (1..=249).contains(&width),
        "opaque pair orientations supports 1..=249 quartets"
    );
    schedule::batch(
        width,
        script! {
            // Test b == d to select the only possible orientation.
            2 OP_PICK OP_OVER OP_EQUAL
            OP_IF
                OP_DROP OP_ROT OP_TUCK OP_EQUALVERIFY
                // The straight match is ambiguous when a == b.
                OP_EQUAL OP_NOT OP_VERIFY
                0
            OP_ELSE
                OP_SWAP OP_ROT OP_EQUALVERIFY OP_EQUALVERIFY
                // Here b != d and a == d already establish a != b.
                1
            OP_ENDIF
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{
        script::ScriptCompilation,
        tapscript::{
            execute_tapscript, TapscriptOutcome, TapscriptPolicyRejection, TapscriptProfile,
        },
    };
    use bitcoin::ScriptBuf;
    use bitcoin_scriptexec::ExecError;

    mod baseline {
        use super::*;
        include!("../../../research/opaque-pair-orientation/baseline.rs");
    }

    mod fixture {
        include!("../../../research/opaque-pair-orientation/fixture.rs");
    }

    fn variants(width: u32) -> [Script; 2] {
        [opaque_pair_orientations(width), baseline::eager(width)]
    }

    fn checked(fragment: Script, bits: &[bool]) -> ScriptBuf {
        script! {
            { fragment }
            for &bit in bits.iter().rev() {
                { i64::from(bit) } OP_EQUALVERIFY
            }
            OP_TRUE
        }
        .compile_with_policy()
    }

    #[test]
    fn every_raw_equality_partition_matches_the_host_relation() {
        let alphabet = [vec![], vec![0], vec![0x80], vec![1]];
        for fragment in variants(1) {
            let [straight, reversed] = [false, true].map(|bit| checked(fragment.clone(), &[bit]));
            for code in 0..256 {
                let [a, b, c, d] = [0, 2, 4, 6].map(|shift| &alphabet[(code >> shift) & 3]);
                let direct = a == c && b == d;
                let swapped = a == d && b == c;
                let witness: Vec<_> = [a, b, c, d].into_iter().cloned().collect();
                for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
                    for (leaf, expected) in [
                        (&straight, direct && !swapped),
                        (&reversed, swapped && !direct),
                    ] {
                        assert_eq!(
                            execute_tapscript(leaf.clone(), witness.clone(), profile).accepted(),
                            Some(expected),
                            "{code} under {profile:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn batch_orders_outputs_and_checks_each_quartet_independently() {
        let bits = [true, false, false, true, false];
        let witness = fixture::witness(&bits);
        for fragment in variants(bits.len() as u32) {
            let leaf = checked(fragment.clone(), &bits);
            let run =
                |witness| execute_tapscript(leaf.clone(), witness, TapscriptProfile::Consensus);
            assert_eq!(run(witness.clone()).accepted(), Some(true));
            for index in 0..witness.len() {
                let mut changed = witness.clone();
                changed[index].push(7);
                assert_eq!(run(changed).accepted(), Some(false), "changed item {index}");
            }
            for count in [witness.len() - 1, witness.len() + 1] {
                let mut changed = witness.clone();
                changed.resize(count, vec![]);
                assert_eq!(run(changed).accepted(), Some(false));
            }
            let mut exchanged = witness.clone();
            exchanged.swap(2, 6);
            exchanged.swap(3, 7);
            assert_eq!(run(exchanged).accepted(), Some(false));

            let mut reversed = bits;
            reversed.reverse();
            assert_eq!(
                execute_tapscript(
                    checked(fragment, &reversed),
                    witness.clone(),
                    TapscriptProfile::Consensus,
                )
                .accepted(),
                Some(false)
            );
        }
    }

    #[test]
    fn payload_sizes_follow_the_local_profiles() {
        for fragment in variants(1) {
            let leaf = checked(fragment, &[true]);
            for length in [80, 81, 520, 521] {
                let payload = vec![0x80; length];
                let witness = vec![payload.clone(), vec![], vec![], payload];
                let strict =
                    execute_tapscript(leaf.clone(), witness.clone(), TapscriptProfile::Consensus);
                assert_eq!(strict.accepted(), Some(length <= 520));
                if length == 521 {
                    assert_eq!(strict.execution().unwrap().error, Some(ExecError::PushSize));
                }
                let policy = execute_tapscript(leaf.clone(), witness, TapscriptProfile::Policy);
                if length <= 80 {
                    assert_eq!(policy.accepted(), Some(true));
                } else {
                    assert!(matches!(
                        policy.outcome,
                        TapscriptOutcome::PolicyRejected(
                            TapscriptPolicyRejection::WitnessStackItemSize { index: 0, size }
                        ) if size == length
                    ));
                }
            }
        }
    }

    #[test]
    fn two_private_slots_preserve_both_caller_stacks_at_the_frontier() {
        let width = 249;
        let bits = vec![true; width as usize];
        let data = fixture::witness(&bits);
        for (index, fragment) in variants(width).into_iter().enumerate() {
            let leaf = checked(fragment.clone(), &bits);
            let standalone = execute_tapscript(leaf, data.clone(), TapscriptProfile::Consensus);
            assert_eq!(standalone.accepted(), Some(true));
            assert_eq!(
                standalone.execution().unwrap().stats.max_nb_stack_items,
                998 + index * 2
            );

            let caller_leaf = script! {
                OP_TOALTSTACK
                { fragment }
                for _ in 0..width { 1 OP_EQUALVERIFY }
                OP_FROMALTSTACK 19 OP_EQUALVERIFY
                17 OP_EQUALVERIFY OP_TRUE
            }
            .compile_with_policy();
            let mut caller_witness = vec![vec![17]];
            caller_witness.extend(data.clone());
            caller_witness.push(vec![19]);
            let result = execute_tapscript(
                caller_leaf.clone(),
                caller_witness.clone(),
                TapscriptProfile::Consensus,
            );
            assert_eq!(result.accepted(), Some(index == 0));
            if index == 0 {
                assert_eq!(result.execution().unwrap().stats.max_nb_stack_items, 1000);
                caller_witness.insert(0, vec![23]);
                let excess =
                    execute_tapscript(caller_leaf, caller_witness, TapscriptProfile::Consensus);
                assert_eq!(
                    excess.execution().unwrap().error,
                    Some(ExecError::StackSize)
                );
            } else {
                assert_eq!(
                    result.execution().unwrap().error,
                    Some(ExecError::StackSize)
                );
            }
        }
        for width in [0, 250] {
            assert!(std::panic::catch_unwind(|| opaque_pair_orientations(width)).is_err());
        }
    }

    #[test]
    fn accepting_any_orientation_allows_a_false_orientation_claim() {
        let weak = script! {
            2 OP_PICK OP_OVER OP_EQUAL
            OP_IF OP_DROP OP_ROT OP_EQUALVERIFY OP_DROP 0
            OP_ELSE OP_SWAP OP_ROT OP_EQUALVERIFY OP_EQUALVERIFY 1
            OP_ENDIF
        };
        let witness = vec![vec![0x80]; 4];
        for (fragment, expected) in [(weak, true), (opaque_pair_orientations(1), false)] {
            assert_eq!(
                execute_tapscript(
                    checked(fragment, &[false]),
                    witness.clone(),
                    TapscriptProfile::Consensus,
                )
                .accepted(),
                Some(expected)
            );
        }
    }
}
