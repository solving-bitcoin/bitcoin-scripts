//! Rolling modulo-three sums over overlapping nibble windows.

use super::mod3::{
    table::{mod3_to_altstack, push_mod3_table},
    U4_MOD3_TABLE_ITEMS,
};
use super::stack::{u4_drop, verify_canonical_nibble};
use crate::support::script::*;

mod schedule;
use schedule::{project_for_windows, sum_top_window};

pub const MAX_INPUTS: u32 = 1_000 - U4_MOD3_TABLE_ITEMS - 3;
pub const MAX_WINDOW: u32 = (U4_MOD3_TABLE_ITEMS - 1) / 2;

/// Consume canonical nibbles `x[0] ... x[n-1]` and emit their width-`window`
/// sums modulo three in increasing window-start order. There are no hints.
/// Both caller stacks are preserved for an exact input suffix. Peak combined
/// stack is at most `n + 19` plus preserved caller state.
pub fn u4_sliding_mod3(n: u32, window: u32) -> Script {
    assert!(
        (1..=MAX_INPUTS).contains(&n),
        "sliding mod3 requires 1..=981 inputs"
    );
    assert!(
        (1..=MAX_WINDOW.min(n)).contains(&window),
        "window must be 1..=min(7,n)"
    );

    let windows = n - window + 1;
    script! {
        {project_for_windows(n)}
        {sum_top_window(window)}
        {n} OP_ADD OP_PICK
        for remaining in (window..n).rev() {
            // Save the rightmost result. Its outgoing residue is just below it.
            OP_DUP OP_TOALTSTACK
            OP_SWAP OP_SUB
            {window} OP_PICK OP_ADD
            // The signed update is in -2..=4. Add 3 and the table depth.
            {remaining + 3} OP_ADD OP_PICK
        }
        OP_TOALTSTACK
        {u4_drop(U4_MOD3_TABLE_ITEMS + window)}
        for _ in 0..windows {OP_FROMALTSTACK}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::test_helpers::{assert_clean_true, run_tapscript, scriptnum},
        support::tapscript::TapscriptProfile,
    };
    use bitcoin::ScriptBuf;
    use bitcoin_scriptexec::ExecError;

    mod baseline {
        use crate::{
            arithmetic::u4::{
                mod3::U4_MOD3_TABLE_ITEMS,
                stack::{u4_drop, verify_canonical_nibble},
            },
            support::script::*,
        };
        include!("../../../../research/sliding-u4-mod3/baseline.rs");
    }

    const PROFILE: TapscriptProfile = TapscriptProfile::Consensus;
    const GENERATORS: [fn(u32, u32) -> Script; 2] = [u4_sliding_mod3, baseline::rescan];

    fn leaf(fragment: Script, residues: &[u32]) -> ScriptBuf {
        script! {
            {fragment}
            for residue in residues.iter().rev() {{*residue} OP_EQUALVERIFY}
            OP_TRUE
        }
        .compile_with_policy()
    }

    fn model(values: &[u32], window: usize) -> Vec<u32> {
        values
            .windows(window)
            .map(|w| w.iter().sum::<u32>() % 3)
            .collect()
    }

    fn witness(values: &[u32]) -> Vec<Vec<u8>> {
        values
            .iter()
            .map(|&value| scriptnum(i64::from(value)))
            .collect()
    }

    #[test]
    fn matches_direct_host_windows_in_increasing_order() {
        for window in 1..=5usize {
            for generate in GENERATORS {
                let fragment = generate(5, window as u32);
                for mut code in 0..3u32.pow(5) {
                    let values: Vec<_> = (0..5)
                        .map(|_| {
                            let value = [0, 7, 14][code as usize % 3];
                            code /= 3;
                            value
                        })
                        .collect();
                    let expected = model(&values, window);
                    assert_clean_true(&run_tapscript(
                        leaf(fragment.clone(), &expected),
                        witness(&values),
                        PROFILE,
                    ));
                }
            }
        }
        for (n, window) in [(6, 6), (7, 7), (8, 7), (16, 7), (32, 2), (128, 7)] {
            let values: Vec<_> = (0..n).map(|i| (11 * i + 3 * (i / 4)) % 16).collect();
            let expected = model(&values, window as usize);
            for generate in GENERATORS {
                assert_clean_true(&run_tapscript(
                    leaf(generate(n, window), &expected),
                    witness(&values),
                    PROFILE,
                ));
            }
        }
    }

    #[test]
    fn rejects_hostile_nibbles_shapes_and_wrong_window_results() {
        let values = [0, 4, 8, 2, 1, 15, 7, 5];
        for generate in GENERATORS {
            let fragment = generate(8, 7);
            let expected = model(&values, 7);
            let script = leaf(fragment.clone(), &expected);
            assert_clean_true(&run_tapscript(script.clone(), witness(&values), PROFILE));
            for position in 0..values.len() {
                for (bad, error) in [
                    (scriptnum(-1), ExecError::Verify),
                    (scriptnum(16), ExecError::Verify),
                    (vec![0x80], ExecError::EqualVerify),
                    (vec![1, 0], ExecError::EqualVerify),
                    (vec![0; 5], ExecError::ScriptIntNumericOverflow),
                    (vec![0; 521], ExecError::PushSize),
                ] {
                    let mut input = witness(&values);
                    input[position] = bad;
                    assert_eq!(
                        run_tapscript(script.clone(), input, PROFILE).error,
                        Some(error)
                    );
                }
            }
            for position in 0..expected.len() {
                let mut wrong = expected.clone();
                wrong[position] = (wrong[position] + 1) % 3;
                assert!(
                    !run_tapscript(leaf(fragment.clone(), &wrong), witness(&values), PROFILE)
                        .success
                );
            }
            let mut short = witness(&values);
            short.pop();
            assert!(!run_tapscript(script.clone(), short, PROFILE).success);
            let mut long = witness(&values);
            long.insert(0, vec![]);
            assert!(!run_tapscript(script, long, PROFILE).success);
        }
    }

    #[test]
    fn residues_do_not_bind_the_original_nibbles() {
        let script = leaf(u4_sliding_mod3(8, 7), &[0, 0]);
        for values in [[0; 8], [3; 8]] {
            assert_clean_true(&run_tapscript(script.clone(), witness(&values), PROFILE));
        }
    }

    #[test]
    fn proves_the_combined_stack_frontier_with_caller_state() {
        let width = 7;
        let result = run_tapscript(
            leaf(
                u4_sliding_mod3(MAX_INPUTS, width),
                &vec![1; (MAX_INPUTS - width + 1) as usize],
            ),
            vec![scriptnum(1); MAX_INPUTS as usize],
            PROFILE,
        );
        assert_clean_true(&result);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        let n = MAX_INPUTS - 2;
        let fragment = u4_sliding_mod3(n, width);
        let script = script! {
            OP_TOALTSTACK {fragment} OP_FROMALTSTACK
        }
        .compile_with_policy();
        let main = vec![0x91, 0x36];
        let alt = vec![0x82, 0x42];
        let mut input = vec![main.clone()];
        input.extend(vec![scriptnum(1); n as usize]);
        input.push(alt.clone());
        let result = run_tapscript(script.clone(), input.clone(), PROFILE);
        assert_eq!(result.error, None);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        assert_eq!(result.final_stack.len(), (n - width + 3) as usize);
        assert_eq!(result.final_stack.get(0), main);
        for i in 1..result.final_stack.len() - 1 {
            assert_eq!(result.final_stack.get(i), scriptnum(1));
        }
        assert_eq!(result.final_stack.get(result.final_stack.len() - 1), alt);
        input.insert(0, vec![]);
        assert_eq!(
            run_tapscript(script, input, PROFILE).error,
            Some(ExecError::StackSize)
        );
        for (n, w) in [(0, 1), (4, 0), (2, 3), (8, 8), (MAX_INPUTS + 1, 1)] {
            assert!(std::panic::catch_unwind(|| u4_sliding_mod3(n, w)).is_err());
        }
    }
}
