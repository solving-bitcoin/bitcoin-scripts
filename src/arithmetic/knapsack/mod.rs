//! Subset-sum verification of a witness selection against public weights.
//!
//! The witness is one selector item per weight. `OP_IF` adds the weight when
//! its selector is true; in tapscript MINIMALIF makes any selector other than
//! the empty item or `[1]` abort, so the selection is a canonical bit vector
//! at no extra script cost. The sum is compared with a public target.

use crate::support::script::*;

/// Largest number of weights: the combined peak is `n + 2`.
pub const SUBSET_SUM_MAX_ITEMS: u32 = 998;

/// Largest representable sum of weights: it must fit a four-byte ScriptNum.
pub const SUBSET_SUM_MAX_TOTAL: u64 = (1 << 31) - 1;

/// Verify that the selected weights sum to `target`.
///
/// Before (witness, bottom to top): selector `s[0] ... s[n-1]`, each the empty
/// item (not selected) or `[1]` (selected). After: `preserved | ok` with
/// `ok = 1` iff `sum(weights[i] for selected i) == target`. The sum of all
/// weights must fit a four-byte ScriptNum (checked at generation time). In
/// tapscript any other selector encoding aborts through MINIMALIF; outside
/// tapscript a truthy selector counts as selected, so the sum is still the
/// sum over the truthy selectors. No hints beyond the selection itself.
pub fn subset_sum_verify(weights: &[u32], target: u32) -> Script {
    assert!(
        (1..=SUBSET_SUM_MAX_ITEMS as usize).contains(&weights.len()),
        "item count out of range"
    );
    let total: u64 = weights.iter().map(|&w| u64::from(w)).sum();
    assert!(
        total <= SUBSET_SUM_MAX_TOTAL,
        "weights overflow a ScriptNum"
    );
    assert!(
        u64::from(target) <= SUBSET_SUM_MAX_TOTAL,
        "target too large"
    );
    script! {
        0
        // The top selector belongs to the last weight.
        for weight in weights.iter().rev() {
            OP_SWAP
            OP_IF { i64::from(*weight) } OP_ADD OP_ENDIF
        }
        { i64::from(target) } OP_NUMEQUAL
    }
}

/// Variant with explicit selector canonicality checks, for contexts without
/// consensus MINIMALIF (legacy and segwit v0 scripts).
///
/// Same contract as [`subset_sum_verify`], but each selector is also required
/// to be a numeric `0` or `1` and to equal its own reserialization, so aliases
/// such as `[1, 0]`, `[2]` and negative zero abort even when `OP_IF` is lenient.
pub fn subset_sum_verify_explicit(weights: &[u32], target: u32) -> Script {
    assert!(
        (1..=SUBSET_SUM_MAX_ITEMS as usize).contains(&weights.len()),
        "item count out of range"
    );
    let total: u64 = weights.iter().map(|&w| u64::from(w)).sum();
    assert!(
        total <= SUBSET_SUM_MAX_TOTAL,
        "weights overflow a ScriptNum"
    );
    assert!(
        u64::from(target) <= SUBSET_SUM_MAX_TOTAL,
        "target too large"
    );
    script! {
        0
        for weight in weights.iter().rev() {
            OP_SWAP
            OP_DUP 0 2 OP_WITHIN OP_VERIFY
            OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
            OP_IF { i64::from(*weight) } OP_ADD OP_ENDIF
        }
        { i64::from(target) } OP_NUMEQUAL
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{
        execution::execute_raw_script_with_inputs_strict,
        tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
    };

    fn selectors(bits: &[bool]) -> Vec<Vec<u8>> {
        bits.iter()
            .map(|&b| if b { vec![1u8] } else { Vec::new() })
            .collect()
    }

    fn sum_of(weights: &[u32], bits: &[bool]) -> u32 {
        weights
            .iter()
            .zip(bits)
            .filter(|(_, &b)| b)
            .map(|(&w, _)| w)
            .sum()
    }

    fn compile(weights: &[u32], target: u32) -> Vec<u8> {
        script! { { subset_sum_verify(weights, target) } }
            .compile_with_policy()
            .to_bytes()
    }

    #[test]
    fn exhaustive_subsets_match_the_sum_for_each_target() {
        let weights = [3u32, 5, 8, 13, 21, 34, 55, 89];
        // Compile once per target: the sum of every subset, plus off-by-one targets.
        let mut checked = 0;
        for target in [0u32, 1, 3, 8, 24, 100, 228, 229] {
            let compiled = compile(&weights, target);
            for code in 0..1u32 << weights.len() {
                let bits: Vec<bool> = (0..weights.len()).map(|i| (code >> i) & 1 == 1).collect();
                let result =
                    execute_raw_script_with_inputs_strict(compiled.clone(), selectors(&bits));
                assert!(result.error.is_none(), "{result}");
                assert_eq!(
                    result.success,
                    sum_of(&weights, &bits) == target,
                    "{bits:?}"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 8 * 256);
    }

    #[test]
    fn handles_zero_duplicate_and_large_weights() {
        let weights = [0u32, 7, 7, 2_000_000_000, 147_483_633];
        let total: u32 = weights.iter().sum();
        assert_eq!(u64::from(total), SUBSET_SUM_MAX_TOTAL);
        for (bits, target) in [
            ([true, true, true, true, true], total),
            ([false, true, false, false, false], 7),
            ([false, false, true, false, false], 7),
            ([true, false, false, false, false], 0),
            ([false, false, false, true, true], total),
        ] {
            let result =
                execute_raw_script_with_inputs_strict(compile(&weights, target), selectors(&bits));
            let expected = sum_of(&weights, &bits) == target;
            assert!(result.error.is_none(), "{result}");
            assert_eq!(result.success, expected, "{bits:?}");
        }
    }

    #[test]
    fn recorded_sizes_are_current() {
        // Weights (37i + 11) mod 65535 + 1, as in the metric fixture.
        for (n, plain, explicit) in [
            (8u32, 56usize, 136usize),
            (16, 112, 272),
            (32, 224, 544),
            (64, 448, 1_088),
            (128, 896, 2_176),
        ] {
            let weights: Vec<u32> = (0..n).map(|i| (37 * i + 11) % 65_535 + 1).collect();
            let measure = |script: Script| script.compile_with_policy().len();
            assert_eq!(
                measure(subset_sum_verify(&weights, 1_000)),
                plain,
                "plain {n}"
            );
            assert_eq!(
                measure(subset_sum_verify_explicit(&weights, 1_000)),
                explicit,
                "explicit {n}"
            );
        }
    }

    #[test]
    fn rejects_generation_overflow_and_bounds() {
        assert!(std::panic::catch_unwind(|| subset_sum_verify(&[], 0)).is_err());
        assert!(std::panic::catch_unwind(|| subset_sum_verify(&[u32::MAX], 0)).is_err());
        assert!(std::panic::catch_unwind(|| {
            subset_sum_verify(&[1_500_000_000, 1_500_000_000], 0)
        })
        .is_err());
        assert!(std::panic::catch_unwind(|| subset_sum_verify(&[1], u32::MAX)).is_err());
        assert!(std::panic::catch_unwind(|| {
            subset_sum_verify(&vec![1; SUBSET_SUM_MAX_ITEMS as usize + 1], 0)
        })
        .is_err());
    }

    /// Selector encodings other than the empty item and `[1]`.
    fn noncanonical_selectors() -> Vec<Vec<u8>> {
        vec![
            vec![2],
            vec![0x81],
            vec![1, 0],
            vec![0, 0],
            vec![0x80],
            vec![0x02, 0x00],
        ]
    }

    #[test]
    fn tapscript_profiles_treat_noncanonical_selectors_as_documented() {
        let weights = [4u32, 9];
        let script = bitcoin::ScriptBuf::from_bytes(compile(&weights, 9));
        for bad in noncanonical_selectors() {
            for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
                let witness = vec![Vec::new(), bad.clone()];
                let outcome = execute_tapscript(script.clone(), witness, profile).outcome;
                let TapscriptOutcome::Executed(result) = outcome else {
                    panic!("expected execution, got {outcome:?}");
                };
                // The top selector belongs to weights[1] = 9: only an exact [1] selects it.
                assert!(
                    result.error.is_some() && !result.success,
                    "{profile:?} accepted selector {bad:?}: {result}"
                );
            }
        }
        // The canonical encodings still verify under both profiles.
        for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
            let witness = vec![Vec::new(), vec![1u8]];
            let TapscriptOutcome::Executed(result) =
                execute_tapscript(script.clone(), witness, profile).outcome
            else {
                panic!("expected execution");
            };
            assert!(result.success, "{profile:?}: {result}");
        }
    }

    #[test]
    fn preserves_surrounding_state() {
        let weights = [2u32, 3, 5];
        let result = crate::support::execution::execute_script(script! {
            77 OP_TOALTSTACK
            99
            OP_0 OP_1 OP_1
            { subset_sum_verify(&weights, 8) }
            OP_VERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "{result}");
    }

    #[test]
    fn stack_frontier_is_exact() {
        use crate::support::script::MAX_OPTIMIZER_INPUT_BYTES;
        let weights = vec![1u32; SUBSET_SUM_MAX_ITEMS as usize];
        let run_at = |extra: usize| {
            let compiled = script! {
                { subset_sum_verify(&weights, 0) }
                OP_DROP
                for _ in 0..extra { OP_DROP }
                OP_TRUE
                for _ in 0..=MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
            }
            .compile_with_policy()
            .to_bytes();
            let mut witness = vec![vec![9u8]; extra];
            witness.extend(vec![Vec::new(); weights.len()]);
            execute_raw_script_with_inputs_strict(compiled, witness)
        };
        let base = run_at(0);
        assert!(base.success, "{base}");
        let spare = 1_000 - base.stats.max_nb_stack_items;
        assert!(run_at(spare).success);
        assert_eq!(
            run_at(spare + 1).error,
            Some(bitcoin_scriptexec::ExecError::StackSize)
        );
    }

    #[test]
    fn both_forms_abort_on_selector_aliases_in_the_local_tapscript_context() {
        use crate::support::execution::execute_script_buf_with_options;
        use bitcoin_scriptexec::Options;
        let weights = [4u32, 9];
        let lenient = Options {
            verify_minimal_if: false,
            enforce_stack_limit: true,
            require_minimal: false,
            ..Default::default()
        };
        for bad in noncanonical_selectors() {
            // Top selector = weights[1] = 9, bottom selector = weights[0] = 4 unselected.
            let witness = vec![Vec::new(), bad.clone()];
            // The local executor is a tapscript context: MINIMALIF is consensus there and
            // the Options flag does not switch it off, so the plain form aborts too.
            // Legacy and segwit-v0 leniency therefore cannot be exercised locally.
            let plain = execute_script_buf_with_options(
                bitcoin::ScriptBuf::from_bytes(compile(&weights, 9)),
                witness.clone(),
                lenient.clone(),
            )
            .expect("execution");
            assert!(
                plain.error.is_some() && !plain.success,
                "plain {bad:?}: {plain}"
            );
            // Explicit form aborts on every alias.
            let explicit = execute_script_buf_with_options(
                bitcoin::ScriptBuf::from_bytes(
                    script! { { subset_sum_verify_explicit(&weights, 9) } }
                        .compile_with_policy()
                        .to_bytes(),
                ),
                witness,
                lenient.clone(),
            )
            .expect("execution");
            assert!(
                explicit.error.is_some() && !explicit.success,
                "explicit {bad:?}: {explicit}"
            );
        }
        // Canonical selectors verify under the explicit form.
        let compiled = script! { { subset_sum_verify_explicit(&weights, 13) } }
            .compile_with_policy()
            .to_bytes();
        let result = execute_raw_script_with_inputs_strict(compiled, vec![vec![1], vec![1]]);
        assert!(result.success, "{result}");
    }
}
