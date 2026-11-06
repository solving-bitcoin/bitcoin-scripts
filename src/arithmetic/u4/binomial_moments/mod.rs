//! Exact positional binomial moments of offset-centered u4 data.

use super::stack::verify_canonical_nibble;
use crate::support::script::*;

mod recurrence;
use recurrence::{advance, centered_nibble};

pub const MAX_INPUTS: u32 = 997;

/// Consume canonical nibbles `x[0] ... x[n-1]` and return, bottom to top,
/// `sum(x[i]-8)`, `sum(i*(x[i]-8))`, and `sum(binomial(i,2)*(x[i]-8))`.
/// Width is `0..=997`. There are no hints. Both caller stacks are preserved
/// for an exact input suffix. Nonempty peak is at most `n + 3` plus caller
/// state. The empty case pushes three zeros.
pub fn u4_centered_binomial_moments(n: u32) -> Script {
    assert!(n <= MAX_INPUTS, "binomial moments require 0..=997 nibbles");
    if n == 0 {
        return script! {0 0 0};
    }
    script! {
        // The first element seeds M0. M1 and M2 are still zero.
        {centered_nibble()}
        if n >= 2 {
            OP_SWAP {centered_nibble()}
            OP_OVER OP_ADD OP_SWAP
        } else {
            0 0
        }
        if n >= 3 {
            // Allocate M2 after validating the third element.
            2 OP_ROLL {centered_nibble()}
            OP_OVER OP_TOALTSTACK
            OP_TOALTSTACK OP_OVER OP_ADD
            OP_SWAP OP_FROMALTSTACK OP_ADD OP_SWAP
            for _ in 3..n {{advance()}}
            OP_FROMALTSTACK
        } else if n == 2 {
            0
        }
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
        include!("../../../../research/u4-binomial-moments/baseline.rs");
    }

    const PROFILE: TapscriptProfile = TapscriptProfile::Consensus;
    const GENERATORS: [fn(u32) -> Script; 3] = [
        u4_centered_binomial_moments,
        baseline::eager,
        baseline::direct,
    ];

    fn leaf(fragment: Script, expected: [i64; 3]) -> ScriptBuf {
        script! {
            {fragment}
            for value in expected.into_iter().rev() {{value} OP_EQUALVERIFY}
            OP_TRUE
        }
        .compile_with_policy()
    }

    fn data(values: &[u32]) -> Vec<Vec<u8>> {
        values
            .iter()
            .map(|&value| scriptnum(i64::from(value)))
            .collect()
    }

    fn model(values: &[u32]) -> [i64; 3] {
        let mut moments = [0; 3];
        for (i, &value) in values.iter().enumerate() {
            let index = i as i64;
            let centered = i64::from(value) - 8;
            moments[0] += centered;
            moments[1] += index * centered;
            moments[2] += (index * (index - 1) / 2) * centered;
        }
        moments
    }

    #[test]
    fn agrees_with_direct_host_moments() {
        let mut cases = Vec::new();
        for n in 0..=5u32 {
            for mut code in 0..3u32.pow(n) {
                cases.push(
                    (0..n)
                        .map(|_| {
                            let value = [0, 8, 15][code as usize % 3];
                            code /= 3;
                            value
                        })
                        .collect::<Vec<_>>(),
                );
            }
        }
        for n in [17, 32, 128] {
            cases.push((0..n).map(|i| (11 * i + 3 * (i / 4)) % 16).collect());
        }
        for i in 0..17 {
            let mut impulse = vec![8; 17];
            impulse[i] = 9;
            cases.push(impulse);
        }
        let mut leaves = std::collections::BTreeMap::new();
        for values in cases {
            let n = values.len() as u32;
            let scripts = leaves.entry(n).or_insert_with(|| {
                GENERATORS.map(|generate| {
                    script! {
                        OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK
                        {generate(n)}
                        for _ in 0..3 {OP_FROMALTSTACK OP_EQUALVERIFY}
                        OP_TRUE
                    }
                    .compile_with_policy()
                })
            });
            let mut witness = data(&values);
            witness.extend(model(&values).into_iter().rev().map(scriptnum));
            for script in scripts {
                assert_clean_true(&run_tapscript(script.clone(), witness.clone(), PROFILE));
            }
        }
    }

    #[test]
    fn rejects_malformed_nibbles_wrong_outputs_and_counts() {
        let values = [0, 15, 8, 1];
        let expected = model(&values);
        for generate in GENERATORS {
            let fragment = generate(4);
            let script = leaf(fragment.clone(), expected);
            assert_clean_true(&run_tapscript(script.clone(), data(&values), PROFILE));
            for position in 0..4 {
                for (bad, error) in [
                    (scriptnum(-1), ExecError::Verify),
                    (scriptnum(16), ExecError::Verify),
                    (vec![0x80], ExecError::EqualVerify),
                    (vec![1, 0], ExecError::EqualVerify),
                    (vec![0; 5], ExecError::ScriptIntNumericOverflow),
                    (vec![0; 521], ExecError::PushSize),
                ] {
                    let mut witness = data(&values);
                    witness[position] = bad;
                    assert_eq!(
                        run_tapscript(script.clone(), witness, PROFILE).error,
                        Some(error)
                    );
                }
            }
            for position in 0..3 {
                let mut wrong = expected;
                wrong[position] += 1;
                assert!(
                    !run_tapscript(leaf(fragment.clone(), wrong), data(&values), PROFILE).success
                );
            }
            assert!(!run_tapscript(script.clone(), data(&values[..3]), PROFILE).success);
            let mut extra = data(&values);
            extra.insert(0, vec![]);
            assert!(!run_tapscript(script, extra, PROFILE).success);
        }
    }

    #[test]
    fn a_third_difference_can_cancel_all_three_moments() {
        let script = leaf(u4_centered_binomial_moments(4), [0; 3]);
        for values in [[8, 8, 8, 8], [9, 5, 11, 7]] {
            assert_eq!(model(&values), [0; 3]);
            assert_clean_true(&run_tapscript(script.clone(), data(&values), PROFILE));
        }
    }

    #[test]
    fn reaches_the_limit_with_exact_signed_arithmetic_and_caller_state() {
        let n = MAX_INPUTS;
        let zeros = vec![0; n as usize];
        let expected = model(&zeros);
        assert_eq!(expected[2], -1_317_395_920);
        let result = run_tapscript(
            leaf(u4_centered_binomial_moments(n), expected),
            data(&zeros),
            PROFILE,
        );
        assert_clean_true(&result);
        assert_eq!(result.stats.max_nb_stack_items, 1000);

        let n = MAX_INPUTS - 2;
        let eager = run_tapscript(
            leaf(baseline::eager(n), [0; 3]),
            vec![scriptnum(8); n as usize],
            PROFILE,
        );
        assert_eq!(eager.error, Some(ExecError::StackSize));

        let script = script! {
            OP_TOALTSTACK {u4_centered_binomial_moments(n)} OP_FROMALTSTACK
        }
        .compile_with_policy();
        let main = vec![0x91, 0x36];
        let alt = vec![0x82, 0x42];
        let mut witness = vec![main.clone()];
        witness.extend(vec![scriptnum(8); n as usize]);
        witness.push(alt.clone());
        let result = run_tapscript(script.clone(), witness.clone(), PROFILE);
        assert_eq!(result.error, None);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        let actual: Vec<_> = (0..result.final_stack.len())
            .map(|i| result.final_stack.get(i))
            .collect();
        assert_eq!(
            actual,
            [main, scriptnum(0), scriptnum(0), scriptnum(0), alt]
        );
        witness.insert(0, vec![]);
        assert_eq!(
            run_tapscript(script, witness, PROFILE).error,
            Some(ExecError::StackSize)
        );
        assert!(std::panic::catch_unwind(|| u4_centered_binomial_moments(MAX_INPUTS + 1)).is_err());
    }
}
