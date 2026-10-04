//! Checked expansion of a canonical u4 run-length witness.
//!
//! A run is one nibble value repeated a positive number of times. The witness
//! is exactly `run_count` pairs `(symbol, length)`, with the first run deepest
//! and the last run's length on top. Lengths are at least 1, at most
//! `width - run_count + 1`, and sum to `width`. Adjacent symbols differ, so
//! the encoding of a given run count is unique. Symbols are canonical
//! ScriptNums in `0..=15`.
//!
//! The expander counts a length down with `OP_GREATERTHAN` rather than using
//! the length as an `OP_IF` condition. BIP342 minimal-if rejects every
//! condition other than a minimal 0 or 1, so a raw multi-value length is not
//! a legal countdown flag.
//!
//! There are no hint items. All `2 * run_count` payload items coexist at
//! script entry. Callers add preserved main-stack and altstack items to
//! [`u4_run_length_stack_peak`] when checking the 1,000-item limit.

use crate::support::script::*;

/// Extra combined stack items used by the length prologue, above the run pairs.
///
/// Pinned by `stack_peak_matches_the_checked_formula`.
const PHASE1_SLACK: u32 = 5;

/// Extra combined stack items above `width + run_count` while the longest
/// feasible run is emitted. Pinned by the same formula test.
const EXPANSION_SLACK: u32 = 2;

#[derive(Clone, Copy)]
struct RunPolicy {
    length_range: bool,
    length_canonical: bool,
    symbol_range: bool,
    symbol_canonical: bool,
    adjacent: bool,
    exact_width: bool,
}

impl RunPolicy {
    const fn all() -> Self {
        Self {
            length_range: true,
            length_canonical: true,
            symbol_range: true,
            symbol_canonical: true,
            adjacent: true,
            exact_width: true,
        }
    }
}

/// Largest length one run can have when every other run still has length 1.
pub fn u4_run_length_max(width: u32, run_count: u32) -> u32 {
    width - run_count + 1
}

/// Combined main-plus-alt stack peak of the fragment with no preserved state.
///
/// The two terms are the length-check prologue and the countdown emission of
/// the longest feasible run. The formula is an execution invariant of this
/// generator, not a consensus limit.
pub fn u4_run_length_stack_peak(width: u32, run_count: u32) -> u32 {
    let phase1 = 2 * run_count + PHASE1_SLACK;
    let expansion = width + run_count + EXPANSION_SLACK;
    phase1.max(expansion)
}

fn assert_shape(width: u32, run_count: u32) {
    assert!(run_count > 0, "run-length witness must contain a run");
    assert!(width >= run_count, "width must cover one item per run");
    assert!(
        u4_run_length_stack_peak(width, run_count) <= 1_000,
        "u4 run-length expansion exceeds Bitcoin Script's stack limit"
    );
}

fn verify_length(width: u32, run_count: u32, policy: RunPolicy) -> Script {
    let max_run = u4_run_length_max(width, run_count);
    script! {
        if policy.length_range {
            OP_DUP
            1
            { max_run + 1 }
            OP_WITHIN
            OP_VERIFY
        }
        if policy.length_canonical {
            OP_DUP
            OP_DUP
            OP_0
            OP_ADD
            OP_EQUALVERIFY
        }
    }
}

fn verify_symbol(policy: RunPolicy) -> Script {
    script! {
        if policy.symbol_range {
            OP_DUP
            0
            16
            OP_WITHIN
            OP_VERIFY
        }
        if policy.symbol_canonical {
            OP_DUP
            OP_DUP
            OP_0
            OP_ADD
            OP_EQUALVERIFY
        }
    }
}

fn emit_run(max_run: u32) -> Script {
    script! {
        for _ in 0..max_run {
            OP_DUP
            OP_0
            OP_GREATERTHAN
            OP_IF
                OP_1SUB
                OP_OVER
                OP_TOALTSTACK
            OP_ENDIF
        }
        OP_0
        OP_EQUALVERIFY
        OP_DROP
    }
}

fn expand_runs(width: u32, run_count: u32, policy: RunPolicy) -> Script {
    assert_shape(width, run_count);
    let max_run = u4_run_length_max(width, run_count);

    script! {
        OP_0
        for index in 0..run_count {
            { 1 + 2 * (run_count - 1 - index) }
            OP_PICK
            { verify_length(width, run_count, policy) }
            OP_ADD
        }
        if policy.exact_width {
            { width }
            OP_NUMEQUALVERIFY
        } else {
            OP_DROP
        }
        for index in 0..run_count {
            { 1 + 2 * (run_count - 1 - index) }
            OP_PICK
            { verify_symbol(policy) }
            OP_DROP
        }
        if policy.adjacent {
            for index in 0..run_count.saturating_sub(1) {
                { 1 + 2 * (run_count - 1 - index) }
                OP_PICK
                { 1 + (1 + 2 * (run_count - 2 - index)) }
                OP_PICK
                OP_NUMNOTEQUAL
                OP_VERIFY
            }
        }
        for _ in 0..run_count {
            { emit_run(max_run) }
        }
        for _ in 0..width {
            OP_FROMALTSTACK
        }
    }
}

/// Expand a canonical run-length witness into `width` nibbles.
///
/// Before: `preserved | symbol[0] | length[0] | ... | symbol[n-1] | length[n-1]`,
/// with the last length on top. After: `preserved | nibble[0] | ... | nibble[width-1]`,
/// with the last nibble on top. Preserved altstack items stay below the
/// emitted copies and remain after the fragment returns.
pub fn u4_expand_canonical_runs(width: u32, run_count: u32) -> Script {
    expand_runs(width, run_count, RunPolicy::all())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{
        execution::{
            execute_script_buf_with_options, execute_script_with_inputs_strict, ExecuteInfo,
        },
        script::ScriptCompilation,
    };
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin_scriptexec::{ExecError, Options};

    fn scriptnum(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let len = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..len].to_vec()
    }

    fn witness(runs: &[(i64, i64)]) -> Vec<Vec<u8>> {
        runs.iter()
            .flat_map(|(symbol, length)| [scriptnum(*symbol), scriptnum(*length)])
            .collect()
    }

    fn expanded(runs: &[(i64, i64)]) -> Vec<i64> {
        let mut nibbles = Vec::new();
        for &(symbol, length) in runs {
            assert!(length > 0);
            nibbles.extend(std::iter::repeat(symbol).take(length as usize));
        }
        nibbles
    }

    fn compare(nibbles: &[i64]) -> Script {
        script! {
            for nibble in nibbles.iter().rev() {
                { *nibble } OP_EQUALVERIFY
            }
            OP_TRUE
        }
    }

    fn run_public(width: u32, runs: &[(i64, i64)], nibbles: &[i64]) -> ExecuteInfo {
        execute_script_with_inputs_strict(
            script! {
                { u4_expand_canonical_runs(width, runs.len() as u32) }
                { compare(nibbles) }
            },
            witness(runs),
        )
    }

    fn run_policy(
        width: u32,
        runs: &[(i64, i64)],
        nibbles: &[i64],
        policy: RunPolicy,
        minimal: bool,
    ) -> ExecuteInfo {
        let mut options = Options::default();
        options.require_minimal = minimal;
        let script = script! {
            { expand_runs(width, runs.len() as u32, policy) }
            { compare(nibbles) }
        };
        execute_script_buf_with_options(script.compile_with_policy(), witness(runs), options)
            .expect("execution context should be constructible")
    }

    fn assert_clean_success(result: &ExecuteInfo) {
        assert!(result.success, "{result}");
        assert!(result.stack_limit_enforced);
        assert_eq!(result.error, None);
        assert_eq!(result.final_stack.len(), 1);
        assert_eq!(result.final_stack.get(0), vec![1]);
    }

    #[test]
    fn expands_asymmetric_runs_and_preserves_both_stacks() {
        let runs = [(0, 1), (15, 6), (1, 9)];
        let nibbles = expanded(&runs);
        let mut items = vec![vec![7]];
        items.extend(witness(&runs));
        let result = execute_script_with_inputs_strict(
            script! {
                9 OP_TOALTSTACK
                { u4_expand_canonical_runs(16, 3) }
                for nibble in nibbles.iter().rev() {
                    { *nibble } OP_EQUALVERIFY
                }
                7 OP_EQUALVERIFY
                OP_FROMALTSTACK
                9 OP_EQUAL
            },
            items,
        );
        assert_clean_success(&result);
        assert!(result.stats.max_nb_stack_items <= u4_run_length_stack_peak(16, 3) as usize + 2);
    }

    #[test]
    fn expands_short_singleton_and_multibyte_length_boundaries() {
        assert_clean_success(&run_public(1, &[(0, 1)], &[0]));
        assert_clean_success(&run_public(1, &[(15, 1)], &[15]));
        assert_clean_success(&run_public(
            4,
            &[(0, 1), (1, 1), (2, 1), (3, 1)],
            &[0, 1, 2, 3],
        ));

        let forward = [(1, 1), (2, 3)];
        let reverse = [(2, 3), (1, 1)];
        assert_clean_success(&run_public(4, &forward, &expanded(&forward)));
        assert_clean_success(&run_public(4, &reverse, &expanded(&reverse)));
        assert_ne!(expanded(&forward), expanded(&reverse));

        assert_clean_success(&run_public(128, &[(4, 128)], &vec![4; 128]));
        assert_clean_success(&run_public(200, &[(9, 200)], &vec![9; 200]));
    }

    #[test]
    fn rejects_malformed_items_at_every_position() {
        let runs = [(1, 1), (2, 1), (3, 2)];
        let width = 4;
        let valid = run_public(width, &runs, &expanded(&runs));
        assert_clean_success(&valid);

        let base = witness(&runs);
        let replacements = [
            (0, vec![0x10], ExecError::Verify),
            (0, vec![0x81], ExecError::Verify),
            (0, vec![0x01, 0x00], ExecError::MinimalData),
            (0, vec![1, 0, 0, 0, 0], ExecError::ScriptIntNumericOverflow),
            (1, vec![], ExecError::Verify),
            (1, vec![4], ExecError::Verify),
            (1, vec![0x81], ExecError::Verify),
            (1, vec![0x80], ExecError::MinimalData),
            (1, vec![0x01, 0x00], ExecError::MinimalData),
            (1, vec![1, 0, 0, 0, 0], ExecError::ScriptIntNumericOverflow),
        ];
        for position in [0, 2, 4] {
            for (offset, value, error) in &replacements {
                let mut items = base.clone();
                let index = position + *offset;
                items[index] = value.clone();
                let result = execute_script_with_inputs_strict(
                    script! {
                        { u4_expand_canonical_runs(width, 3) }
                        OP_TRUE
                    },
                    items,
                );
                assert_eq!(
                    result.error,
                    Some(error.clone()),
                    "position {index} value {value:?}: {result}"
                );
                assert!(!result.success);
            }
        }

        let short = execute_script_with_inputs_strict(
            script! {
                { u4_expand_canonical_runs(width, 3) }
                OP_TRUE
            },
            base[..2].to_vec(),
        );
        assert_eq!(short.error, Some(ExecError::InvalidStackOperation));

        let mut extra = base.clone();
        extra.push(vec![9]);
        let extra_top = execute_script_with_inputs_strict(
            script! {
                { u4_expand_canonical_runs(width, 3) }
                OP_TRUE
            },
            extra,
        );
        assert_eq!(extra_top.error, Some(ExecError::Verify));
    }

    #[test]
    fn length_range_check_rejects_a_zero_length_hole() {
        let hostile = [(1, 2), (4, 0), (3, 2)];
        let collapsed = [(1, 2), (3, 2)];
        let rejected = run_public(4, &hostile, &expanded(&collapsed));
        assert_eq!(rejected.error, Some(ExecError::Verify), "{rejected}");

        let mut policy = RunPolicy::all();
        policy.length_range = false;
        let mutated = run_policy(4, &hostile, &expanded(&collapsed), policy, true);
        assert_clean_success(&mutated);
        assert_ne!(mutated.error, Some(ExecError::Verify));
    }

    #[test]
    fn adjacent_check_rejects_split_runs_of_one_symbol() {
        let hostile = [(1, 2), (1, 2)];
        let produced = expanded(&hostile);
        let rejected = run_public(4, &hostile, &produced);
        assert_eq!(rejected.error, Some(ExecError::Verify), "{rejected}");

        let mut policy = RunPolicy::all();
        policy.adjacent = false;
        let mutated = run_policy(4, &hostile, &produced, policy, true);
        assert_clean_success(&mutated);
        assert_ne!(mutated.error, Some(ExecError::Verify));
    }

    #[test]
    fn exact_width_check_rejects_a_short_sum() {
        let hostile = [(1, 1), (2, 1)];
        let rejected = run_public(4, &hostile, &expanded(&hostile));
        assert_eq!(
            rejected.error,
            Some(ExecError::NumEqualVerify),
            "{rejected}"
        );

        let mut policy = RunPolicy::all();
        policy.exact_width = false;
        let mutated = run_policy(4, &hostile, &expanded(&hostile), policy, true);
        assert!(
            mutated.error != Some(ExecError::NumEqualVerify),
            "removing the sum check left the typed rejection in place: {mutated}"
        );
        assert!(!mutated.success);
    }

    #[test]
    fn canonical_reencode_check_is_load_bearing_without_minimaldata() {
        let mut items = witness(&[(1, 1), (2, 1)]);
        items[0] = vec![0x01, 0x00];
        let script = script! {
            { u4_expand_canonical_runs(2, 2) }
            { compare(&[1, 2]) }
        };
        let minimal = execute_script_with_inputs_strict(script.clone(), items.clone());
        assert_eq!(minimal.error, Some(ExecError::MinimalData), "{minimal}");

        let mut options = Options::default();
        options.require_minimal = false;
        let rejected = execute_script_buf_with_options(
            script.compile_with_policy(),
            items.clone(),
            options.clone(),
        )
        .expect("context");
        assert_eq!(rejected.error, Some(ExecError::EqualVerify), "{rejected}");

        let mut policy = RunPolicy::all();
        policy.symbol_canonical = false;
        policy.length_canonical = false;
        let mutated_script = script! {
            { expand_runs(2, 2, policy) }
            OP_2DROP
            OP_TRUE
        };
        let mutated =
            execute_script_buf_with_options(mutated_script.compile_with_policy(), items, options)
                .expect("context");
        assert_clean_success(&mutated);
        assert_ne!(mutated.error, Some(ExecError::EqualVerify));
    }

    #[test]
    fn raw_length_condition_is_rejected_by_minimal_if() {
        let rejected = execute_script_with_inputs_strict(
            script! {
                OP_DUP
                OP_IF
                    OP_1SUB
                OP_ENDIF
                OP_DROP
                OP_TRUE
            },
            vec![scriptnum(2)],
        );
        assert_eq!(rejected.error, Some(ExecError::TapscriptMinimalIf));

        let control = execute_script_with_inputs_strict(
            script! {
                OP_DUP
                OP_IF
                    OP_1SUB
                OP_ENDIF
                OP_0
                OP_EQUAL
            },
            vec![scriptnum(1)],
        );
        assert_clean_success(&control);
    }

    #[test]
    fn stack_peak_matches_the_checked_formula() {
        for (width, runs) in [(1, 1), (8, 1), (9, 1), (8, 2), (16, 2), (16, 4), (5, 5)] {
            let pairs = worst(width, runs);
            let result = execute_script_with_inputs_strict(
                script! {
                    { u4_expand_canonical_runs(width, runs) }
                    for _ in 0..width {
                        OP_DROP
                    }
                    OP_TRUE
                },
                witness(&pairs),
            );
            assert_clean_success(&result);
            assert_eq!(
                result.stats.max_nb_stack_items,
                u4_run_length_stack_peak(width, runs) as usize,
                "width {width} runs {runs}"
            );
        }

        let width = 8;
        let runs = 1;
        let base = u4_run_length_stack_peak(width, runs) as usize;
        let preserved = 1_000 - base;
        let mut at_limit = vec![vec![7]; preserved];
        at_limit.extend(witness(&worst(width, runs)));
        let full = execute_script_with_inputs_strict(
            script! {
                { u4_expand_canonical_runs(width, runs) }
                for _ in 0..width {
                    OP_DROP
                }
                for _ in 0..preserved {
                    OP_DROP
                }
                OP_TRUE
            },
            at_limit,
        );
        assert_clean_success(&full);
        assert_eq!(full.stats.max_nb_stack_items, 1_000);

        let mut over = vec![vec![7]];
        over.extend(vec![vec![7]; preserved]);
        over.extend(witness(&worst(width, runs)));
        let rejected = execute_script_with_inputs_strict(
            script! {
                { u4_expand_canonical_runs(width, runs) }
                OP_TRUE
            },
            over,
        );
        assert_eq!(rejected.error, Some(ExecError::StackSize));
    }

    #[test]
    fn repetitive_witness_saves_items_and_short_runs_do_not() {
        let direct = direct_checked_nibbles(16);
        let direct_bytes = direct.compile_with_policy().len();
        let repetitive = u4_expand_canonical_runs(16, 2).compile_with_policy();
        let tied = u4_expand_canonical_runs(16, 8).compile_with_policy();
        let alternating = u4_expand_canonical_runs(16, 16).compile_with_policy();

        assert_eq!(direct_bytes, 206);
        assert_eq!(repetitive.len(), 321);
        assert_eq!(tied.len(), 867);
        assert_eq!(alternating.len(), 698);
        assert_eq!(witness(&[(0, 8), (15, 8)]).len(), 4);
        assert_eq!(witness(&worst(16, 8)).len(), 16);
        assert_eq!(witness(&worst(16, 16)).len(), 32);

        let digest = sha256::Hash::hash(repetitive.as_bytes());
        assert_eq!(
            digest.to_string(),
            "00c8ca6ef44237329a54df1e49adeb7944393d22a7f1ed7065a207b0849d08f1"
        );
    }

    #[test]
    fn rejects_empty_and_uncountable_shapes() {
        assert!(std::panic::catch_unwind(|| u4_expand_canonical_runs(0, 0)).is_err());
        assert!(std::panic::catch_unwind(|| u4_expand_canonical_runs(4, 0)).is_err());
        assert!(std::panic::catch_unwind(|| u4_expand_canonical_runs(3, 4)).is_err());
        assert!(std::panic::catch_unwind(|| u4_expand_canonical_runs(1_000, 1)).is_err());
    }

    fn worst(width: u32, runs: u32) -> Vec<(i64, i64)> {
        let mut lengths = vec![1; runs as usize];
        lengths[runs as usize - 1] = i64::from(u4_run_length_max(width, runs));
        lengths
            .into_iter()
            .enumerate()
            .map(|(index, length)| ((index % 16) as i64, length))
            .collect()
    }

    fn direct_checked_nibbles(width: u32) -> Script {
        script! {
            for index in (0..width).rev() {
                { index }
                OP_PICK
                OP_DUP
                0
                16
                OP_WITHIN
                OP_VERIFY
                OP_DUP
                OP_DUP
                OP_0
                OP_ADD
                OP_EQUALVERIFY
                OP_DROP
            }
        }
    }
}
