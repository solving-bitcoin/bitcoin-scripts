//! Earliest minimum over a checked nibble vector.

use super::stack::verify_canonical_nibble;
use crate::support::script::*;

mod packed;
use packed::split_score;

pub const MAX_WIDTH: u32 = 980;

/// Consume `x[0] ... x[n-1]` and return the minimum nibble and the first
/// position where it occurs. Input nibbles must be canonical ScriptNums.
///
/// The 16-entry table is internal and removed before returning. There are
/// no hints. Both caller stacks are preserved for an exact input suffix.
/// Combined peak is at most `n+20` plus preserved caller state.
pub fn u4_earliest_argmin(n: u32) -> Script {
    assert!(
        (1..=MAX_WIDTH).contains(&n),
        "argmin requires 1..=980 nibbles"
    );
    let stride = n.next_power_of_two();
    script! {
        for value in (0..16).rev() {{value * stride}}
        {16 * stride}
        for position in (0..n).rev() {
            // The best score sits above the table throughout the fold.
            17 OP_ROLL {verify_canonical_nibble()}
            OP_1ADD OP_PICK {position} OP_ADD OP_MIN
        }
        OP_TOALTSTACK
        for _ in 0..16 {OP_DROP}
        OP_FROMALTSTACK
        {split_score(stride)}
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
            arithmetic::{scriptint::mul_by_constant, u4::stack::verify_canonical_nibble},
            support::script::*,
        };
        include!("../../../../research/packed-u4-argmin/baseline.rs");
    }

    const PROFILE: TapscriptProfile = TapscriptProfile::Consensus;
    const GENERATORS: [fn(u32) -> Script; 3] = [
        u4_earliest_argmin,
        baseline::direct_state,
        baseline::packed_shift,
    ];

    fn leaf(fragment: Script, value: u8, index: usize) -> ScriptBuf {
        script! {
            {fragment} {index} OP_EQUALVERIFY {u32::from(value)} OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy()
    }

    #[test]
    fn matches_first_minimum_with_ties_and_non_power_of_two_widths() {
        let mut cases = Vec::new();
        for a in 0..16 {
            for b in 0..16 {
                cases.push(vec![a, b]);
            }
        }
        for n in 1..=4u32 {
            for mut number in 0..3u32.pow(n) {
                let vector: Vec<_> = (0..n)
                    .map(|_| {
                        let value = [0, 1, 15][number as usize % 3];
                        number /= 3;
                        value
                    })
                    .collect();
                cases.push(vector);
            }
        }
        for n in [7, 17, 32, 127, 128] {
            let mut vector: Vec<_> = (0..n).map(|i| (i * 7 % 15 + 1) as u8).collect();
            vector[n / 3] = 0;
            vector[n - 1] = 0;
            cases.push(vector);
        }
        for values in cases {
            let index = values
                .iter()
                .enumerate()
                .min_by_key(|&(_, value)| *value)
                .unwrap()
                .0;
            let witness: Vec<_> = values
                .iter()
                .map(|&value| scriptnum(i64::from(value)))
                .collect();
            for generate in GENERATORS {
                assert_clean_true(&run_tapscript(
                    leaf(generate(values.len() as u32), values[index], index),
                    witness.clone(),
                    PROFILE,
                ));
            }
        }
    }

    #[test]
    fn rejects_malformed_nibbles_and_wrong_tie_breaks() {
        let witness: Vec<_> = [7, 0, 4, 0].into_iter().map(scriptnum).collect();
        for generate in GENERATORS {
            let fragment = generate(4);
            let cleanup = script! {{fragment.clone()} OP_2DROP OP_TRUE}.compile_with_policy();
            for position in 0..4 {
                for (bad, error) in [
                    (scriptnum(-1), ExecError::Verify),
                    (scriptnum(16), ExecError::Verify),
                    (vec![0x80], ExecError::EqualVerify),
                    (vec![1, 0], ExecError::EqualVerify),
                    (vec![0; 5], ExecError::ScriptIntNumericOverflow),
                    (vec![0; 521], ExecError::PushSize),
                ] {
                    let mut input = witness.clone();
                    input[position] = bad;
                    assert_eq!(
                        run_tapscript(cleanup.clone(), input, PROFILE).error,
                        Some(error)
                    );
                }
            }
            assert_clean_true(&run_tapscript(
                leaf(fragment.clone(), 0, 1),
                witness.clone(),
                PROFILE,
            ));
            assert!(!run_tapscript(leaf(fragment.clone(), 0, 3), witness.clone(), PROFILE).success);
            assert!(!run_tapscript(leaf(fragment.clone(), 1, 1), witness.clone(), PROFILE).success);
            for size in [0, 1, 2, 3, 5] {
                assert!(
                    !run_tapscript(leaf(fragment.clone(), 0, 0), vec![vec![]; size], PROFILE)
                        .success
                );
            }
        }
    }

    #[test]
    fn table_frontier_preserves_caller_stacks() {
        let standalone = run_tapscript(
            leaf(u4_earliest_argmin(MAX_WIDTH), 7, 0),
            vec![scriptnum(7); MAX_WIDTH as usize],
            PROFILE,
        );
        assert_clean_true(&standalone);
        assert_eq!(standalone.stats.max_nb_stack_items, 1000);

        let n = MAX_WIDTH - 2;
        let script = script! {
            OP_TOALTSTACK {u4_earliest_argmin(n)} OP_FROMALTSTACK
        }
        .compile_with_policy();
        let main = vec![0x91, 0x36];
        let alt = vec![0x82, 0x42];
        let mut witness = vec![main.clone()];
        witness.extend(vec![scriptnum(7); n as usize]);
        witness.push(alt.clone());
        let result = run_tapscript(script.clone(), witness.clone(), PROFILE);
        assert_eq!(result.error, None);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        let actual: Vec<_> = (0..result.final_stack.len())
            .map(|i| result.final_stack.get(i))
            .collect();
        assert_eq!(actual, [main, scriptnum(7), vec![], alt]);
        witness.insert(0, vec![]);
        assert_eq!(
            run_tapscript(script, witness, PROFILE).error,
            Some(ExecError::StackSize)
        );
        for width in [0, MAX_WIDTH + 1] {
            assert!(std::panic::catch_unwind(|| u4_earliest_argmin(width)).is_err());
        }
    }
}
