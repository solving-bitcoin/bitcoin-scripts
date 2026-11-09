//! Constant step length along the sixteen-element nibble circle.

use super::stack::verify_canonical_nibble;
use crate::support::script::*;

mod scan;
use scan::scan_with;

pub const MAX_INPUTS: u32 = 997;

/// Consume `n` canonical nibbles and return the common shortest circular
/// distance between adjacent items. Reject a differing distance. Either
/// direction is allowed independently at every edge. The final item is not
/// compared with the first. Requires `2..=997` inputs and zero hints.
/// Both caller stacks survive an exact suffix. Combined peak is at most
/// `n + 3` plus preserved caller state.
pub fn u4_uniform_lee_step(n: u32) -> Script {
    assert!(
        (2..=MAX_INPUTS).contains(&n),
        "uniform Lee step requires 2..=997 nibbles"
    );
    scan_with(
        n,
        script! {OP_ABS 8 OP_SUB OP_ABS},
        script! {8 OP_SWAP OP_SUB},
    )
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
        use crate::{arithmetic::u4::stack::verify_canonical_nibble, support::script::*};
        include!("../../../../research/uniform-u4-lee-step/baseline.rs");
    }

    const PROFILE: TapscriptProfile = TapscriptProfile::Consensus;
    const GENERATORS: [fn(u32) -> Script; 2] = [u4_uniform_lee_step, baseline::direct];

    fn leaf(fragment: Script, distance: u32) -> ScriptBuf {
        script! {{fragment} {distance} OP_EQUALVERIFY OP_TRUE}.compile_with_policy()
    }

    fn data(values: &[u32]) -> Vec<Vec<u8>> {
        values
            .iter()
            .map(|&value| scriptnum(i64::from(value)))
            .collect()
    }

    fn distance(x: u32, y: u32) -> u32 {
        let forward = (16 + y - x) % 16;
        let backward = (16 + x - y) % 16;
        forward.min(backward)
    }

    #[test]
    fn matches_all_pairs_and_triples_in_the_host_metric() {
        for n in [2u32, 3] {
            let leaves = GENERATORS.map(|generate| {
                script! {
                    OP_TOALTSTACK {generate(n)}
                    OP_FROMALTSTACK OP_EQUALVERIFY OP_TRUE
                }
                .compile_with_policy()
            });
            for mut code in 0..16u32.pow(n) {
                let values: Vec<_> = (0..n)
                    .map(|_| {
                        let value = code & 15;
                        code >>= 4;
                        value
                    })
                    .collect();
                let expected = distance(values[0], values[1]);
                let uniform = values
                    .windows(2)
                    .all(|pair| distance(pair[0], pair[1]) == expected);
                let mut witness = data(&values);
                witness.push(scriptnum(i64::from(expected)));
                for script in &leaves {
                    let result = run_tapscript(script.clone(), witness.clone(), PROFILE);
                    if uniform {
                        assert_clean_true(&result);
                    } else {
                        assert!(!result.success);
                    }
                }
            }
        }
    }

    #[test]
    fn allows_direction_changes_and_checks_every_hostile_item() {
        let values = [14, 1, 14, 1];
        for generate in GENERATORS {
            let fragment = generate(4);
            let script = leaf(fragment.clone(), 3);
            assert_clean_true(&run_tapscript(script.clone(), data(&values), PROFILE));
            assert_clean_true(&run_tapscript(
                leaf(generate(3), 3),
                data(&[0, 3, 6]),
                PROFILE,
            ));
            assert!(!run_tapscript(leaf(generate(3), 3), data(&[0, 2, 6]), PROFILE,).success);
            assert_clean_true(&run_tapscript(
                leaf(generate(3), 8),
                data(&[15, 7, 15]),
                PROFILE,
            ));
            assert_clean_true(&run_tapscript(
                leaf(generate(3), 0),
                data(&[9, 9, 9]),
                PROFILE,
            ));
            assert!(!run_tapscript(leaf(fragment.clone(), 2), data(&values), PROFILE).success);
            assert!(!run_tapscript(script.clone(), data(&[14, 1, 14, 2]), PROFILE).success);
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
            assert!(!run_tapscript(script.clone(), data(&values[..3]), PROFILE).success);
            let mut long = data(&values);
            long.insert(0, vec![]);
            assert!(!run_tapscript(script, long, PROFILE).success);
        }
    }

    #[test]
    fn proves_stack_frontier_and_preserves_caller_data() {
        let n = MAX_INPUTS;
        let standalone = run_tapscript(
            leaf(u4_uniform_lee_step(n), 8),
            data(&(0..n).map(|i| (i % 2) * 8).collect::<Vec<_>>()),
            PROFILE,
        );
        assert_clean_true(&standalone);
        assert_eq!(standalone.stats.max_nb_stack_items, 1000);
        let n = MAX_INPUTS - 2;
        let script = script! {
            OP_TOALTSTACK {u4_uniform_lee_step(n)} OP_FROMALTSTACK
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
        assert_eq!(actual, [main, scriptnum(0), alt]);
        witness.insert(0, vec![]);
        assert_eq!(
            run_tapscript(script, witness, PROFILE).error,
            Some(ExecError::StackSize)
        );
        for width in [0, 1, MAX_INPUTS + 1] {
            assert!(std::panic::catch_unwind(|| u4_uniform_lee_step(width)).is_err());
        }
    }
}
