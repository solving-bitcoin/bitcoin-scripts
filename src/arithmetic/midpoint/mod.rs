//! Verify a hinted floor midpoint of two signed ScriptNums.

use crate::support::script::{script, Script};

mod schedule;

/// Consume `a b q` and return canonical `q` after checking
/// `q = floor((a+b)/2)`. Inputs are at most four bytes, the proposed
/// midpoint is canonical, and both caller stacks survive.
pub fn verify_floor_midpoint() -> Script {
    script! {
        { schedule::prepare() } OP_ADD
        OP_OVER OP_DUP OP_ADD
        OP_OVER OP_EQUAL OP_IF
            OP_DROP
        OP_ELSE
            { schedule::push_odd_candidate() } OP_EQUALVERIFY
        OP_ENDIF
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::test_helpers::{assert_clean_true, run_tapscript, scriptnum},
        support::{script::ScriptCompilation, tapscript::TapscriptProfile},
    };
    use bitcoin::ScriptBuf;
    use bitcoin_scriptexec::ExecError;

    mod baseline {
        use super::*;
        include!("../../../research/hinted-signed-midpoint/baseline.rs");
    }

    mod fixture {
        use super::*;
        include!("../../../research/hinted-signed-midpoint/fixture.rs");
    }

    fn leaf(fragment: Script, expected: Option<i64>) -> ScriptBuf {
        let terminal = match expected {
            Some(q) => script! { { q } OP_EQUALVERIFY },
            None => script! { OP_DROP },
        };
        script! { { fragment } { terminal } OP_TRUE }.compile_with_policy()
    }

    fn data(a: i64, b: i64, q: i64, parity: Option<i64>) -> Vec<Vec<u8>> {
        [a, b, q].into_iter().chain(parity).map(scriptnum).collect()
    }

    fn check_pair(a: i64, b: i64, profile: TapscriptProfile) {
        let q = (a + b).div_euclid(2);
        let parity = (a + b).rem_euclid(2);
        for (fragment, explicit) in [
            (verify_floor_midpoint(), false),
            (baseline::explicit_parity(), true),
        ] {
            let r = explicit.then_some(parity);
            let verified =
                run_tapscript(leaf(fragment.clone(), Some(q)), data(a, b, q, r), profile);
            assert_clean_true(&verified);
            let terminal_only = leaf(fragment, None);
            for wrong in [q - 1, q + 1] {
                assert!(
                    !run_tapscript(terminal_only.clone(), data(a, b, wrong, r), profile).success
                );
            }
            if explicit {
                assert!(
                    !run_tapscript(terminal_only, data(a, b, q, Some(1 - parity)), profile).success
                );
            }
        }
    }

    #[test]
    fn exhaustive_short_pairs_bind_the_unique_floor_hint() {
        for a in -16..=16 {
            for b in -16..=16 {
                check_pair(a, b, TapscriptProfile::Consensus);
            }
        }
    }

    #[test]
    fn signed_endpoint_grid_matches_floor_rounding_in_both_profiles() {
        let m = i64::from(i32::MAX);
        let edges = [-m, -m + 1, -128, -1, 0, 1, 127, 128, m - 1, m];
        for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
            for a in edges {
                for b in edges {
                    check_pair(a, b, profile);
                }
            }
        }
    }

    #[test]
    fn rejects_overlong_and_noncanonical_hints_and_malformed_suffixes() {
        let m = i64::from(i32::MAX);
        for (fragment, explicit) in [
            (verify_floor_midpoint(), false),
            (baseline::explicit_parity(), true),
        ] {
            let leaf = leaf(fragment, None);
            let valid = data(0, 0, 0, explicit.then_some(0));
            for index in 0..3 {
                for malformed in [scriptnum(m + 1), scriptnum(-m - 1), vec![0, 0, 0, 0, 0x80]] {
                    let mut hostile = valid.clone();
                    hostile[index] = malformed;
                    assert!(
                        !run_tapscript(leaf.clone(), hostile, TapscriptProfile::Consensus).success
                    );
                }
            }
            for malformed in [vec![0], vec![0x80], vec![0, 0]] {
                let mut hostile = valid.clone();
                hostile[2] = malformed;
                assert!(!run_tapscript(leaf.clone(), hostile, TapscriptProfile::Consensus).success);
            }
            if explicit {
                for malformed in [vec![0], vec![0x80], vec![2], vec![1, 0]] {
                    let mut hostile = valid.clone();
                    hostile[3] = malformed;
                    let result = run_tapscript(leaf.clone(), hostile, TapscriptProfile::Consensus);
                    assert_eq!(result.error, Some(ExecError::TapscriptMinimalIf));
                }
            }
            let mut alias = valid.clone();
            alias[0] = vec![0x80];
            assert_clean_true(&run_tapscript(
                leaf.clone(),
                alias.clone(),
                TapscriptProfile::Consensus,
            ));
            assert!(!run_tapscript(leaf.clone(), alias, TapscriptProfile::Policy).success);
            for witness in [valid[1..].to_vec(), [vec![vec![]], valid].concat()] {
                assert!(!run_tapscript(leaf.clone(), witness, TapscriptProfile::Consensus).success);
            }
        }
    }

    #[test]
    fn preloaded_hints_and_caller_state_reach_exact_frontiers() {
        for (explicit, maximum, fragment) in [
            (false, 332, verify_floor_midpoint()),
            (true, 249, baseline::explicit_parity()),
        ] {
            for count in [maximum, maximum + 1] {
                let pairs = fixture::pairs(count);
                let mut witness = fixture::witness(&pairs, explicit);
                let batch = fixture::verify_batch(fragment.clone(), &pairs);
                if count == maximum {
                    let caller_leaf = script! {
                        OP_TOALTSTACK { batch } OP_FROMALTSTACK 18 OP_EQUALVERIFY OP_TRUE
                    }
                    .compile_with_policy();
                    witness.push(vec![18]);
                    let result = run_tapscript(caller_leaf, witness, TapscriptProfile::Consensus);
                    assert_clean_true(&result);
                    assert_eq!(result.stats.max_nb_stack_items, 1000);
                } else {
                    let checked = script! { { batch } OP_TRUE }.compile_with_policy();
                    let result = run_tapscript(checked, witness, TapscriptProfile::Consensus);
                    assert_eq!(result.error, Some(ExecError::StackSize));
                }
            }
        }
    }

    #[test]
    fn even_only_equality_cannot_verify_an_odd_floor_midpoint() {
        let even_only = script! {
            { schedule::prepare() } OP_ADD
            OP_OVER OP_DUP OP_ADD OP_EQUALVERIFY
            OP_DROP OP_TRUE
        }
        .compile_with_policy();
        assert_clean_true(&run_tapscript(
            even_only.clone(),
            data(0, 2, 1, None),
            TapscriptProfile::Consensus,
        ));
        assert!(
            !run_tapscript(
                even_only,
                data(-1, 0, -1, None),
                TapscriptProfile::Consensus
            )
            .success
        );
    }
}
