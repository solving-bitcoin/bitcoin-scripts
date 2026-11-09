//! Verify and decode a nonempty interval represented by binary flags.

use crate::support::script::*;

/// Maximum standalone width before accounting for caller state.
pub const MAX_FLAGS: u32 = 998;

/// Consume `... flag[n-1] ... flag[0]` and return `... start length`.
///
/// The mask must have one nonempty run of true flags. Native tapscript
/// MINIMALIF enforces exact empty or `[1]` flag encodings. The interval
/// uses zero-based indices. Both caller stacks are preserved for an exact
/// input suffix. No hints are required.
pub fn decode_single_run(n: u32) -> Script {
    assert!(
        (1..=MAX_FLAGS).contains(&n),
        "run mask requires 1..=998 flags"
    );
    script! {
        // Consume the first flag before allocating state.
        OP_IF 0 1 OP_ELSE 1 0 OP_ENDIF
        for _ in 1..n {
            2 OP_ROLL
            OP_IF
                OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY OP_1ADD
            OP_ELSE
                // A negative length marks a run that has closed.
                OP_DUP OP_0NOTEQUAL
                OP_IF OP_ABS OP_NEGATE
                OP_ELSE OP_SWAP OP_1ADD OP_SWAP
                OP_ENDIF
            OP_ENDIF
        }
        OP_ABS OP_DUP OP_VERIFY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::test_helpers::{assert_clean_true, run_tapscript, scriptnum},
        support::tapscript::TapscriptProfile,
    };
    use bitcoin_scriptexec::ExecError;

    mod baseline {
        use crate::support::script::*;
        include!("../../../research/single-run-mask/baseline.rs");
    }

    const PROFILE: TapscriptProfile = TapscriptProfile::Consensus;
    const GENERATORS: [fn(u32) -> Script; 2] =
        [decode_single_run, baseline::decode_with_closed_flag];

    fn checked(fragment: Script, start: usize, length: usize) -> bitcoin::ScriptBuf {
        script! {
            {fragment} {length} OP_EQUALVERIFY {start} OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy()
    }

    fn witness(flags: &[bool]) -> Vec<Vec<u8>> {
        flags
            .iter()
            .rev()
            .map(|&value| scriptnum(i64::from(value)))
            .collect()
    }

    #[test]
    fn both_schedules_match_every_small_binary_mask() {
        for n in 1..=8 {
            for mask in 0..1u32 << n {
                let flags: Vec<_> = (0..n).map(|i| mask >> i & 1 == 1).collect();
                let set: Vec<_> = (0..n as usize).filter(|&i| flags[i]).collect();
                for generate in GENERATORS {
                    let fragment = generate(n);
                    if let (Some(&first), Some(&last)) = (set.first(), set.last()) {
                        if last - first + 1 == set.len() {
                            assert_clean_true(&run_tapscript(
                                checked(fragment, first, set.len()),
                                witness(&flags),
                                PROFILE,
                            ));
                            continue;
                        }
                    }
                    let cleanup = script! {{fragment} OP_2DROP OP_TRUE}.compile_with_policy();
                    let result = run_tapscript(cleanup, witness(&flags), PROFILE);
                    assert_eq!(result.error, Some(ExecError::Verify), "{flags:?}");
                }
            }
        }
    }

    #[test]
    fn enforces_native_flag_encoding_and_terminal_binding() {
        let flags = [false, true, true, false, false];
        let valid = witness(&flags);
        for generate in GENERATORS {
            let fragment = generate(flags.len() as u32);
            let cleanup = script! {{fragment.clone()} OP_2DROP OP_TRUE}.compile_with_policy();
            for position in 0..flags.len() {
                for bad in [vec![0], vec![2], vec![0x80], vec![1, 0], vec![0; 5]] {
                    let mut input = valid.clone();
                    input[position] = bad;
                    let result = run_tapscript(cleanup.clone(), input, PROFILE);
                    assert_eq!(result.error, Some(ExecError::TapscriptMinimalIf));
                }
            }
            let mut oversized = valid.clone();
            oversized[0] = vec![0; 521];
            assert_eq!(
                run_tapscript(cleanup.clone(), oversized, PROFILE).error,
                Some(ExecError::PushSize)
            );
            let checked_leaf = checked(fragment.clone(), 1, 2);
            assert_clean_true(&run_tapscript(checked_leaf.clone(), valid.clone(), PROFILE));
            assert!(
                !run_tapscript(checked(fragment.clone(), 0, 2), valid.clone(), PROFILE).success
            );
            assert!(!run_tapscript(checked(fragment, 1, 3), valid.clone(), PROFILE).success);
            let mut short = valid.clone();
            short.remove(2);
            assert!(!run_tapscript(checked_leaf.clone(), short, PROFILE).success);
            let mut extra = valid.clone();
            extra.insert(0, vec![]);
            assert!(!run_tapscript(checked_leaf, extra, PROFILE).success);
        }
    }

    #[test]
    fn preserves_caller_state_and_checks_the_stack_frontier() {
        let n = MAX_FLAGS - 2;
        let fragment = decode_single_run(n);
        let script = script! {OP_TOALTSTACK {fragment} OP_FROMALTSTACK}.compile_with_policy();
        let mut flags = vec![false; n as usize];
        flags[1..167].fill(true);
        let main = vec![0x51, 0x91];
        let alt = vec![0x36, 0x72];
        let mut input = vec![main.clone()];
        input.extend(witness(&flags));
        input.push(alt.clone());
        let result = run_tapscript(script.clone(), input.clone(), PROFILE);
        assert_eq!(result.error, None);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        let actual: Vec<_> = (0..result.final_stack.len())
            .map(|i| result.final_stack.get(i))
            .collect();
        assert_eq!(actual, [main, scriptnum(1), scriptnum(166), alt]);
        input.insert(0, vec![]);
        assert_eq!(
            run_tapscript(script, input, PROFILE).error,
            Some(ExecError::StackSize)
        );
        assert!(std::panic::catch_unwind(|| decode_single_run(0)).is_err());
        assert!(std::panic::catch_unwind(|| decode_single_run(MAX_FLAGS + 1)).is_err());
    }

    #[test]
    fn separate_flag_costs_one_more_live_item_at_standalone_frontier() {
        for (n, generate, expected_error) in [
            (MAX_FLAGS, GENERATORS[0], None),
            (MAX_FLAGS - 1, GENERATORS[1], None),
            (MAX_FLAGS, GENERATORS[1], Some(ExecError::StackSize)),
        ] {
            let mut flags = vec![false; n as usize];
            flags[1..167].fill(true);
            let leaf = checked(generate(n), 1, 166);
            let result = run_tapscript(leaf, witness(&flags), PROFILE);
            assert_eq!(result.error, expected_error);
            if expected_error.is_none() {
                assert_clean_true(&result);
                assert_eq!(result.stats.max_nb_stack_items, 1000);
            }
        }
    }

    #[test]
    fn adjacent_transition_count_alone_cannot_identify_an_interval() {
        use crate::arithmetic::u4::transition_count::u4_nibbles_transition_count;

        let count = script! {
            {u4_nibbles_transition_count(5)} 2 OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        let inside = witness(&[false, true, true, true, false]);
        let split = witness(&[true, false, false, false, true]);
        for input in [&inside, &split] {
            assert_clean_true(&run_tapscript(count.clone(), input.clone(), PROFILE));
        }
        let fragment = decode_single_run(5);
        assert_clean_true(&run_tapscript(
            checked(fragment.clone(), 1, 3),
            inside,
            PROFILE,
        ));
        let cleanup = script! {{fragment} OP_2DROP OP_TRUE}.compile_with_policy();
        assert_eq!(
            run_tapscript(cleanup, split, PROFILE).error,
            Some(ExecError::Verify)
        );
    }
}
