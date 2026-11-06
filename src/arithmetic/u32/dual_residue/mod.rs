//! Joint modulo-seven and modulo-nine projection of a canonical u32.

use super::stack::verify_canonical_byte;
use crate::{arithmetic::scriptint::mul_by_constant, support::script::*};

mod ops;
use ops::{reduce_nonnegative, verify_word, weighted_sum};

/// Consume a canonical u32, most significant byte first, and return
/// `... value_mod_7 value_mod_9`. Both caller stacks are preserved for
/// the exact four-item suffix. There are no hints and the peak is seven
/// combined items plus caller state.
pub fn u32_residues_7_9() -> Script {
    script! {
        {verify_word()}
        // 256 is congruent to 4 modulo 63; 4^3 is congruent to 1.
        {weighted_sum(16, 4)}
        {reduce_nonnegative(63, 22 * 255)}
        OP_DUP {reduce_nonnegative(7, 62)}
        OP_SWAP {reduce_nonnegative(9, 62)}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::test_helpers::{assert_clean_true, run_tapscript, scriptnum, word_witness},
        support::tapscript::TapscriptProfile,
    };
    use bitcoin::ScriptBuf;
    use bitcoin_scriptexec::ExecError;

    mod baseline {
        use crate::{
            arithmetic::{scriptint::mul_by_constant, u32::stack::verify_canonical_byte},
            support::{script::*, script_ops::OP_4DUP},
        };
        include!("../../../../research/dual-u32-residues/baseline.rs");
    }

    const PROFILE: TapscriptProfile = TapscriptProfile::Consensus;
    const GENERATORS: [fn() -> Script; 2] = [u32_residues_7_9, baseline::separate_residues];

    fn leaf(fragment: Script, word: u32) -> ScriptBuf {
        script! {
            {fragment} {word % 9} OP_EQUALVERIFY {word % 7} OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy()
    }

    #[test]
    fn matches_exact_residues_at_every_byte_position() {
        for generate in GENERATORS {
            let mut words = vec![
                0,
                1,
                6,
                7,
                8,
                9,
                62,
                63,
                64,
                0x7fff_ffff,
                0x8000_0000,
                u32::MAX,
            ];
            for lane in 0..4 {
                for byte in 0..=255 {
                    let mut bytes = [0x25, 0x4a, 0x87, 0xb1];
                    bytes[lane] = byte;
                    words.push(u32::from_be_bytes(bytes));
                }
            }
            for i in 0..128u32 {
                words.push(i.wrapping_mul(0x9e37_79b9).rotate_left(i % 32));
            }
            for word in words {
                assert_clean_true(&run_tapscript(
                    leaf(generate(), word),
                    word_witness(word).map(scriptnum).collect(),
                    PROFILE,
                ));
            }
        }
    }

    #[test]
    fn rejects_out_of_range_and_noncanonical_bytes_at_every_position() {
        for generate in GENERATORS {
            let checked = leaf(generate(), 0);
            for lane in 0..4 {
                for (bad, error) in [
                    (scriptnum(-1), ExecError::Verify),
                    (scriptnum(256), ExecError::Verify),
                    (vec![0], ExecError::EqualVerify),
                    (vec![0x80], ExecError::EqualVerify),
                    (vec![0, 0], ExecError::EqualVerify),
                    (vec![0; 5], ExecError::ScriptIntNumericOverflow),
                    (vec![0; 521], ExecError::PushSize),
                ] {
                    let mut input = vec![vec![]; 4];
                    input[lane] = bad;
                    let result = run_tapscript(checked.clone(), input, PROFILE);
                    assert!(!result.success);
                    assert_eq!(result.error, Some(error));
                }
            }
            for size in [0, 1, 2, 3, 5] {
                assert!(!run_tapscript(checked.clone(), vec![vec![]; size], PROFILE).success);
            }
        }
    }

    #[test]
    fn preserves_both_caller_stacks_at_exact_frontier() {
        let word = 0xfedc_ba98;
        let script =
            script! {OP_TOALTSTACK {u32_residues_7_9()} OP_FROMALTSTACK}.compile_with_policy();
        let prefix = vec![vec![0x91, 0x36]; 992];
        let alt = vec![0x82, 0x42];
        let mut witness = prefix.clone();
        witness.extend(word_witness(word).map(scriptnum));
        witness.push(alt.clone());
        let result = run_tapscript(script.clone(), witness.clone(), PROFILE);
        assert_eq!(result.error, None);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        let actual: Vec<_> = (0..result.final_stack.len())
            .map(|i| result.final_stack.get(i))
            .collect();
        assert_eq!(
            actual,
            [
                prefix,
                vec![
                    scriptnum(i64::from(word % 7)),
                    scriptnum(i64::from(word % 9)),
                    alt
                ]
            ]
            .concat()
        );
        witness.insert(0, vec![]);
        assert_eq!(
            run_tapscript(script, witness, PROFILE).error,
            Some(ExecError::StackSize)
        );
    }

    #[test]
    fn residue_pair_cannot_bind_the_whole_word() {
        let checked = leaf(u32_residues_7_9(), 42);
        for word in [42, 105] {
            assert_clean_true(&run_tapscript(
                checked.clone(),
                word_witness(word).map(scriptnum).collect(),
                PROFILE,
            ));
        }
    }
}
