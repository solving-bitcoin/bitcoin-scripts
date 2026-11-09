//! Carry-out of two canonically compressed u32 words.

use crate::support::{
    script::{script, Script},
    script_ops::OP_2MUL,
};

// Leave a usable numeric operand and its class. Class 2 marks an ordinary
// negative operand and class 3 marks the exact five-byte sentinel.
fn classify_compressed_word() -> Script {
    script! {
        OP_SIZE 5 OP_LESSTHAN OP_IF
            OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
            OP_DUP 0 OP_LESSTHAN { OP_2MUL() }
        OP_ELSE
            { -2_147_483_648i64 } OP_EQUALVERIFY
            0 3
        OP_ENDIF
    }
}

/// Consume two canonical signed ScriptNum encodings of u32 words and return
/// one canonical carry bit. Accepts the exact five-byte 0x80000000 sentinel.
/// Preserves both caller stacks.
pub fn u32_compressed_carry() -> Script {
    script! {
        { classify_compressed_word() }
        OP_ROT { classify_compressed_word() }
        OP_ROT OP_ADD
        OP_DUP 2 OP_NUMEQUAL OP_IF
            // One ordinary negative and one nonnegative value. Their
            // signed sum fits in four bytes and detects the unsigned carry.
            OP_DROP OP_ADD 0 OP_GREATERTHANOREQUAL
        OP_ELSE
            OP_NIP OP_NIP 4 OP_GREATERTHANOREQUAL
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
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    mod baseline {
        use crate::{
            arithmetic::u32::{
                cmp::u32_compressed_lessthan,
                stack::{u32_fromaltstack, u32_toaltstack, u32_uncompress_canonical},
                zip::u32_zip,
            },
            support::script::{script, Script},
        };
        include!("../../../../research/compressed-u32-carry/baseline.rs");
    }

    fn encoding(word: u32) -> Vec<u8> {
        scriptnum(i64::from(word as i32))
    }

    fn leaves() -> [[ScriptBuf; 2]; 3] {
        [
            u32_compressed_carry(),
            baseline::complement_comparison(),
            baseline::expanded_ripple(),
        ]
        .map(|fragment| {
            [0, 1].map(|bit| {
                script! { { fragment.clone() } { bit } OP_EQUALVERIFY OP_TRUE }
                    .compile_with_policy()
            })
        })
    }

    fn check_pair(leaves: &[[ScriptBuf; 2]; 3], a: u32, b: u32, profile: TapscriptProfile) {
        let expected = usize::from(a.overflowing_add(b).1);
        for leaf in leaves {
            let witness = vec![encoding(a), encoding(b)];
            let result = run_tapscript(leaf[expected].clone(), witness.clone(), profile);
            assert_clean_true(&result);
            assert!(!run_tapscript(leaf[1 - expected].clone(), witness, profile).success);
        }
    }

    #[test]
    fn all_sign_class_pairs_and_threshold_neighborhoods() {
        let leaves = leaves();
        let edges = [
            0,
            1,
            127,
            128,
            0x7fff_fffe,
            0x7fff_ffff,
            0x8000_0000,
            0x8000_0001,
            u32::MAX,
        ];
        for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
            for a in edges {
                for b in edges {
                    check_pair(&leaves, a, b, profile);
                }
                for b in [u32::MAX - a, 0u32.wrapping_sub(a), 1u32.wrapping_sub(a)] {
                    check_pair(&leaves, a, b, profile);
                    check_pair(&leaves, b, a, profile);
                }
            }
        }
    }

    #[test]
    fn deterministic_full_word_samples_match_the_host_carry() {
        let leaves = leaves();
        let mut rng = StdRng::seed_from_u64(0x37_43_41_52_52_59);
        for _ in 0..256 {
            check_pair(
                &leaves,
                rng.next_u32(),
                rng.next_u32(),
                TapscriptProfile::Consensus,
            );
        }
    }

    #[test]
    fn hostile_aliases_and_wrong_sentinels_fail_in_both_positions() {
        let leaves = leaves();
        for malformed in [
            vec![0],
            vec![0x80],
            vec![1, 0],
            vec![1, 0x80],
            vec![0, 0, 0, 0, 0x80],
            vec![0, 0, 0, 0x80, 0, 0x80],
            scriptnum(2_147_483_648),
            scriptnum(-2_147_483_649),
        ] {
            for witness in [
                vec![malformed.clone(), encoding(0)],
                vec![encoding(0), malformed],
            ] {
                for leaf in &leaves {
                    for script in leaf {
                        assert!(
                            !run_tapscript(
                                script.clone(),
                                witness.clone(),
                                TapscriptProfile::Consensus,
                            )
                            .success
                        );
                    }
                }
            }
        }
        for count in [0, 1, 3] {
            assert!(
                !run_tapscript(
                    leaves[0][0].clone(),
                    vec![encoding(0); count],
                    TapscriptProfile::Consensus,
                )
                .success
            );
        }
    }

    #[test]
    fn preserves_both_caller_stacks_and_returns_canonical_bits() {
        let leaf = script! {
            OP_TOALTSTACK
            { u32_compressed_carry() } 1 OP_EQUALVERIFY
            OP_FROMALTSTACK 18 OP_EQUALVERIFY
            17 OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        let result = run_tapscript(
            leaf,
            vec![
                vec![17],
                encoding(0x7fff_ffff),
                encoding(0x8000_0001),
                vec![18],
            ],
            TapscriptProfile::Consensus,
        );
        assert_clean_true(&result);
    }

    #[test]
    fn mixed_operands_reach_the_combined_limit_with_994_caller_items() {
        let leaf = script! {
            OP_TOALTSTACK
            { u32_compressed_carry() } 1 OP_EQUALVERIFY
            OP_FROMALTSTACK 18 OP_EQUALVERIFY
            for _ in 0..992 { OP_DROP }
            17 OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        let mut witness = vec![vec![17]];
        witness.extend((0..992).map(|_| vec![]));
        witness.extend([encoding(0x7fff_ffff), encoding(0x8000_0001), vec![18]]);
        let result = run_tapscript(leaf.clone(), witness.clone(), TapscriptProfile::Consensus);
        assert_clean_true(&result);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        witness.insert(0, vec![19]);
        let result = run_tapscript(leaf, witness, TapscriptProfile::Consensus);
        assert_eq!(result.error, Some(ExecError::StackSize));
    }

    #[test]
    fn consecutive_class_numbers_have_an_ambiguous_sum() {
        let class = |word| match word {
            0..=0x7fff_ffff => 0,
            0x8000_0000 => 2,
            _ => 1,
        };
        let no_carry = (0u32, 0x8000_0000);
        let carry = (0xffff_ffffu32, 0xffff_ffff);
        assert_eq!(
            class(no_carry.0) + class(no_carry.1),
            class(carry.0) + class(carry.1)
        );
        assert!(!no_carry.0.overflowing_add(no_carry.1).1);
        assert!(carry.0.overflowing_add(carry.1).1);
    }
}
