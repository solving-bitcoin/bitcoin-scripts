//! Recover one erased nibble under two public checks modulo 17.

use crate::{
    arithmetic::{scriptint::mul_by_constant, u4::stack::verify_canonical_nibble},
    support::script::{script, Script},
};

mod schedule;

/// Consume the surviving canonical nibbles of a width-2-through-17 vector.
/// The erased zero-based position and checks `sum` and `weighted_sum`
/// are public. The latter weights each original nibble by its zero-based
/// position. Both checks are residues modulo 17. Return the missing nibble.
pub fn recover_u4_erasure(width: usize, erased: usize, sum: u8, weighted_sum: u8) -> Script {
    assert!(
        (2..=17).contains(&width),
        "erasure recovery supports width 2..=17"
    );
    assert!(erased < width, "erasure position must be inside the vector");
    assert!(
        sum < 17 && weighted_sum < 17,
        "checks must be residues modulo 17"
    );

    let weights: Vec<_> = (0..width)
        .map(|index| {
            let residue = (index as i32 - erased as i32).rem_euclid(17);
            if residue > 8 {
                residue - 17
            } else {
                residue
            }
        })
        .collect();
    let seed = (i32::from(weighted_sum) - erased as i32 * i32::from(sum)).rem_euclid(17);
    let (lower, upper) = schedule::bounds(seed, &weights);
    script! {
        { schedule::scan(erased, sum, seed, &weights) }
        { schedule::recover_digit(width, sum) }
        OP_FROMALTSTACK { schedule::reduce_mod17(lower, upper) }
        0 OP_EQUALVERIFY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::test_helpers::{assert_clean_true, run_tapscript},
        support::{script::ScriptCompilation, tapscript::TapscriptProfile},
    };
    use bitcoin::ScriptBuf;
    use bitcoin_scriptexec::ExecError;

    mod baseline {
        use super::*;
        include!("../../../../research/checked-u4-erasure/baseline.rs");
    }

    mod fixture {
        include!("../../../../research/checked-u4-erasure/fixture.rs");
    }

    fn variants(width: usize, erased: usize, sum: u8, weighted: u8) -> [Script; 2] {
        [
            recover_u4_erasure(width, erased, sum, weighted),
            baseline::direct(width, erased, sum, weighted),
        ]
    }

    fn leaf(fragment: Script, expected: Option<u8>) -> ScriptBuf {
        let terminal = match expected {
            Some(nibble) => script! { { nibble } OP_EQUALVERIFY },
            None => script! { OP_DROP },
        };
        script! { { fragment } { terminal } OP_TRUE }.compile_with_policy()
    }

    #[test]
    fn exhaustive_two_nibble_vectors_and_both_erasure_positions() {
        for a in 0..16 {
            for b in 0..16 {
                let values = [a, b];
                let (sum, weighted) = fixture::checks(&values);
                for erased in 0..2 {
                    for fragment in variants(2, erased, sum, weighted) {
                        let result = run_tapscript(
                            leaf(fragment, Some(values[erased])),
                            fixture::witness(&values, erased),
                            TapscriptProfile::Consensus,
                        );
                        assert_clean_true(&result);
                    }
                }
            }
        }
    }

    #[test]
    fn every_single_substitution_at_width_seventeen_is_detected() {
        let width = 17;
        let values = fixture::values(width);
        let (sum, weighted) = fixture::checks(&values);
        for erased in 0..width {
            for fragment in variants(width, erased, sum, weighted) {
                let witness = fixture::witness(&values, erased);
                for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
                    let result = run_tapscript(
                        leaf(fragment.clone(), Some(values[erased])),
                        witness.clone(),
                        profile,
                    );
                    assert_clean_true(&result);
                }
                let checked = leaf(fragment, None);
                for (position, &value) in values.iter().enumerate() {
                    if position == erased {
                        continue;
                    }
                    let slot = position - usize::from(position > erased);
                    for other in 0..16 {
                        if other != value {
                            let mut hostile = witness.clone();
                            hostile[slot] = fixture::item(other);
                            assert!(
                                !run_tapscript(
                                    checked.clone(),
                                    hostile,
                                    TapscriptProfile::Consensus
                                )
                                .success
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn rejects_malformed_nibbles_incompatible_checks_and_non_nibble_recovery() {
        let values = [0, 7, 3, 15];
        let erased = 1;
        let (sum, weighted) = fixture::checks(&values);
        let witness = fixture::witness(&values, erased);
        for fragment in variants(4, erased, sum, weighted) {
            let checked = leaf(fragment, Some(7));
            for index in 0..witness.len() {
                for bad in [
                    vec![16],
                    vec![0x81],
                    vec![0],
                    vec![0x80],
                    vec![3, 0],
                    vec![0; 520],
                ] {
                    let mut hostile = witness.clone();
                    hostile[index] = bad;
                    assert!(
                        !run_tapscript(checked.clone(), hostile, TapscriptProfile::Consensus)
                            .success
                    );
                }
            }
            for bad in [
                witness[1..].to_vec(),
                [vec![vec![]], witness.clone()].concat(),
            ] {
                assert!(!run_tapscript(checked.clone(), bad, TapscriptProfile::Consensus).success);
            }
        }
        for fragment in variants(4, erased, sum, (weighted + 1) % 17) {
            assert!(
                !run_tapscript(
                    leaf(fragment, None),
                    witness.clone(),
                    TapscriptProfile::Consensus
                )
                .success
            );
        }
        for fragment in variants(2, 0, 16, 0) {
            assert!(
                !run_tapscript(
                    leaf(fragment, None),
                    vec![vec![]],
                    TapscriptProfile::Consensus
                )
                .success
            );
        }
        for (width, erased, sum, weighted) in [
            (1, 0, 0, 0),
            (18, 0, 0, 0),
            (2, 2, 0, 0),
            (2, 0, 17, 0),
            (2, 0, 0, 17),
        ] {
            assert!(
                std::panic::catch_unwind(|| recover_u4_erasure(width, erased, sum, weighted))
                    .is_err()
            );
        }
    }

    #[test]
    fn two_changes_can_cancel_the_second_check() {
        let initial = [5, 5, 5];
        let alternate = [4, 7, 4];
        let (sum, weighted) = fixture::checks(&initial);
        assert_eq!(fixture::checks(&alternate), (sum, weighted));
        for fragment in variants(3, 0, sum, weighted) {
            let result = run_tapscript(
                leaf(fragment, Some(4)),
                fixture::witness(&alternate, 0),
                TapscriptProfile::Consensus,
            );
            assert_clean_true(&result);
        }
    }

    #[test]
    fn width_eighteen_repeats_the_erased_coefficient() {
        let original = [5; 18];
        let mut alternate = original;
        alternate[0] = 4;
        alternate[17] = 6;
        assert_eq!(fixture::checks(&original), fixture::checks(&alternate));
    }

    #[test]
    fn preserves_both_caller_stacks_at_the_width_seventeen_frontier() {
        let values = fixture::values(17);
        let erased = 8;
        let (sum, weighted) = fixture::checks(&values);
        let missing = values[erased];
        let leaf = script! {
            OP_TOALTSTACK
            { recover_u4_erasure(17, erased, sum, weighted) } { missing } OP_EQUALVERIFY
            OP_FROMALTSTACK 18 OP_EQUALVERIFY
            for _ in 0..978 { OP_DROP }
            17 OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        let mut witness = vec![vec![17]];
        witness.extend((0..978).map(|_| vec![]));
        witness.extend(fixture::witness(&values, erased));
        witness.push(vec![18]);
        let result = run_tapscript(leaf.clone(), witness.clone(), TapscriptProfile::Consensus);
        assert_clean_true(&result);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        witness.insert(0, vec![19]);
        let result = run_tapscript(leaf, witness, TapscriptProfile::Consensus);
        assert_eq!(result.error, Some(ExecError::StackSize));
    }
}
