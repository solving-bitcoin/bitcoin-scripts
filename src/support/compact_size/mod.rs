//! Decode the one- and three-byte CompactSize forms from separate raw items.

use crate::{arithmetic::scriptint::mul_by_constant, support::script::*};

mod schedule;
use schedule::decode_with;

/// Decode a canonical CompactSize in `0..=65535`. The prefix is the top item.
/// For a three-byte form, the low byte is below the prefix and the high byte
/// is below the low byte. Each input is an exact raw one-byte vector.
/// Both caller stacks survive the exact suffix. The fragment returns one
/// canonical ScriptNum and uses no hints.
pub fn decode_compact_size_u16_from_raw_items() -> Script {
    let marker = script! {{vec![0xfdu8]}};
    let byte = script! {
        OP_SIZE 1 OP_EQUALVERIFY
        OP_DUP {vec![0x00u8]} OP_EQUAL
        OP_IF
            OP_DROP 0
        OP_ELSE
            OP_DUP {vec![0x80u8]} OP_EQUAL
            OP_IF
                OP_DROP 128
            OP_ELSE
                // The remaining raw bytes are canonical signed ScriptNums.
                OP_DUP 0 OP_LESSTHAN
                OP_IF 128 OP_SWAP OP_SUB OP_ENDIF
            OP_ENDIF
        OP_ENDIF
    };
    decode_with(marker, byte)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::tapscript::{execute_tapscript, TapscriptProfile};
    use bitcoin::{consensus::encode::serialize, ScriptBuf, VarInt};

    mod baseline {
        use crate::{
            arithmetic::{scriptint::mul_by_constant, u32::stack::verify_canonical_byte},
            support::script::*,
        };
        include!("../../../research/compactsize-raw-decoder/baseline.rs");
    }

    mod fixture {
        include!("../../../research/compactsize-raw-decoder/fixture.rs");
    }

    const GENERATORS: [fn() -> Script; 2] =
        [decode_compact_size_u16_from_raw_items, baseline::numeric];

    fn leaf(fragment: Script, expected: u32) -> ScriptBuf {
        script! {{fragment} {expected} OP_EQUALVERIFY OP_TRUE}.compile_with_policy()
    }

    #[test]
    fn matches_host_serialization_for_every_supported_value() {
        let leaves = GENERATORS.map(|generate| {
            script! {
                OP_TOALTSTACK {generate()} OP_FROMALTSTACK OP_EQUALVERIFY OP_TRUE
            }
            .compile_with_policy()
        });
        for value in 0..=u16::MAX {
            let wire = serialize(&VarInt(u64::from(value)));
            for (schedule, script) in leaves.iter().enumerate() {
                let mut witness = fixture::items(&wire, schedule == 0);
                witness.push(fixture::scriptnum(i64::from(value)));
                let result =
                    execute_tapscript(script.clone(), witness, TapscriptProfile::Consensus);
                assert_eq!(
                    result.accepted(),
                    Some(true),
                    "value {value}, schedule {schedule}: {result:?}"
                );
            }
        }
    }

    #[test]
    fn aliases_and_boundary_values_are_valid_in_both_local_profiles() {
        for value in [0, 1, 127, 128, 129, 252, 253, 255, 256, 32768, 32896, 65535] {
            let wire = serialize(&VarInt(u64::from(value)));
            for (schedule, generate) in GENERATORS.into_iter().enumerate() {
                let script = leaf(generate(), value);
                for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
                    let result = execute_tapscript(
                        script.clone(),
                        fixture::items(&wire, schedule == 0),
                        profile,
                    );
                    assert_eq!(
                        result.accepted(),
                        Some(true),
                        "value {value}, schedule {schedule}: {result:?}"
                    );
                    let execution = result.execution().unwrap();
                    assert_eq!(execution.final_stack.len(), 1);
                    assert_eq!(execution.final_stack.get(0), vec![1]);
                }
            }
        }
    }

    #[test]
    fn rejects_hostile_prefix_lengths_nonminimal_values_and_aliases() {
        for (schedule, generate) in GENERATORS.into_iter().enumerate() {
            let fragment = generate();
            let script = script! {{fragment.clone()} OP_DROP OP_TRUE}.compile_with_policy();
            for wire in [
                vec![],
                vec![0xfd],
                vec![0xfd, 0xfd],
                vec![0xfd, 0xfc, 0x00],
                vec![0xfe],
                vec![0xff],
                vec![0xfe, 0x00, 0x00, 0x01, 0x00],
                vec![0x01, 0x00],
                vec![0xfd, 0xfd, 0x00, 0x00],
            ] {
                let result = execute_tapscript(
                    script.clone(),
                    fixture::items(&wire, schedule == 0),
                    TapscriptProfile::Consensus,
                );
                assert_eq!(
                    result.accepted(),
                    Some(false),
                    "wire {wire:?}, schedule {schedule}: {result:?}"
                );
            }
            for position in 0..3 {
                let bad = if schedule == 0 {
                    [vec![], vec![0x01, 0x00], vec![0; 521]]
                } else {
                    [vec![0x80], vec![0x01, 0x00], vec![0; 521]]
                };
                for item in bad {
                    let mut witness = fixture::items(&[0xfd, 0xff, 0xff], schedule == 0);
                    witness[position] = item;
                    assert_eq!(
                        execute_tapscript(script.clone(), witness, TapscriptProfile::Consensus)
                            .accepted(),
                        Some(false)
                    );
                }
            }
            let wrong = leaf(fragment, 32767);
            assert_eq!(
                execute_tapscript(
                    wrong,
                    fixture::items(&[0xfd, 0x00, 0x80], schedule == 0),
                    TapscriptProfile::Consensus
                )
                .accepted(),
                Some(false)
            );
        }
    }

    #[test]
    fn preserves_surrounding_items_for_both_prefix_forms() {
        let main = vec![0x91, 0x36];
        let alt = vec![0x82, 0x42];
        for (schedule, generate) in GENERATORS.into_iter().enumerate() {
            let script = script! {OP_TOALTSTACK {generate()} OP_FROMALTSTACK}.compile_with_policy();
            for value in [128u64, 65535] {
                let wire = serialize(&VarInt(value));
                let witness = [
                    vec![main.clone()],
                    fixture::items(&wire, schedule == 0),
                    vec![alt.clone()],
                ]
                .concat();
                let result =
                    execute_tapscript(script.clone(), witness, TapscriptProfile::Consensus);
                let execution = result.execution().unwrap();
                assert_eq!(execution.error, None);
                let actual: Vec<_> = (0..execution.final_stack.len())
                    .map(|i| execution.final_stack.get(i))
                    .collect();
                assert_eq!(
                    actual,
                    [main.clone(), fixture::scriptnum(value as i64), alt.clone()]
                );
            }
        }
    }

    #[test]
    fn direct_numeric_use_of_raw_negative_zero_loses_128() {
        let weak = script! {0 OP_ADD 0 OP_EQUALVERIFY OP_TRUE}.compile_with_policy();
        let witness = vec![vec![0x80]];
        assert_eq!(
            execute_tapscript(weak.clone(), witness.clone(), TapscriptProfile::Consensus)
                .accepted(),
            Some(true)
        );
        assert_eq!(
            execute_tapscript(weak, witness.clone(), TapscriptProfile::Policy).accepted(),
            Some(false)
        );
        let exact = leaf(decode_compact_size_u16_from_raw_items(), 128);
        assert_eq!(
            execute_tapscript(exact, witness, TapscriptProfile::Policy).accepted(),
            Some(true)
        );
    }

    #[test]
    fn long_form_respects_the_combined_stack_limit() {
        use bitcoin_scriptexec::ExecError;

        let script = script! {
            OP_TOALTSTACK {decode_compact_size_u16_from_raw_items()} OP_FROMALTSTACK
        }
        .compile_with_policy();
        let main = vec![0x91, 0x36];
        let alt = vec![0x82, 0x42];
        let mut witness = vec![main.clone(); 994];
        witness.extend(fixture::items(&[0xfd, 0xff, 0xff], true));
        witness.push(alt.clone());
        let result =
            execute_tapscript(script.clone(), witness.clone(), TapscriptProfile::Consensus);
        let execution = result.execution().unwrap();
        assert_eq!(execution.error, None);
        assert_eq!(execution.stats.max_nb_stack_items, 1000);
        assert_eq!(execution.final_stack.len(), 996);
        assert_eq!(execution.final_stack.get(993), main);
        assert_eq!(execution.final_stack.get(994), fixture::scriptnum(65535));
        assert_eq!(execution.final_stack.get(995), alt);
        witness.insert(0, vec![]);
        let result = execute_tapscript(script, witness, TapscriptProfile::Consensus);
        assert_eq!(
            result.execution().unwrap().error,
            Some(ExecError::StackSize)
        );
    }
}
