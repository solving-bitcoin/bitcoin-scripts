//! Checked signed decoding of a fixed-width base -2 digit vector.

use crate::support::script::{script, Script};

mod schedule;

/// Consume 1..=32 raw canonical bits, most significant on top, and return
/// their canonical four-byte-or-smaller ScriptNum. Abort on overflow.
/// Both caller stacks are preserved.
pub fn decode_negabinary(width: u32) -> Script {
    assert!((1..=32).contains(&width), "negabinary supports 1..=32 bits");
    script! {
        { schedule::verify_bit() }
        for _ in 1..width {
            OP_SWAP { schedule::verify_bit() }
            // Evaluate digit - accumulator - accumulator in that order.
            OP_OVER OP_SUB OP_SWAP OP_SUB
        }
        if width == 32 {
            OP_SIZE 4 OP_LESSTHANOREQUAL OP_VERIFY
        }
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

    mod baseline {
        use super::*;
        include!("../../../research/checked-negabinary-decoder/baseline.rs");
    }

    mod fixture {
        use super::*;
        include!("../../../research/checked-negabinary-decoder/fixture.rs");
    }

    fn decoders(width: u32) -> [Script; 2] {
        [decode_negabinary(width), baseline::multiply_first(width)]
    }

    fn checked(decoder: Script, value: i64) -> ScriptBuf {
        script! { { decoder } { value } OP_EQUALVERIFY OP_TRUE }.compile_with_policy()
    }

    #[test]
    fn exhaustive_sixteen_bit_vectors_match_the_positional_sum() {
        let width = 16;
        let leaves = decoders(width)
            .map(|decode| script! { { decode } OP_EQUALVERIFY OP_TRUE }.compile_with_policy());
        for mask in 0u32..1 << width {
            let mut expected = 0;
            let mut bits = Vec::new();
            for position in 0..width {
                let bit = (mask >> position) & 1;
                expected += i64::from(bit) * (-2i64).pow(position);
                bits.push(scriptnum(i64::from(bit)));
            }
            let witness: Vec<_> = std::iter::once(scriptnum(expected)).chain(bits).collect();
            for leaf in &leaves {
                let result =
                    run_tapscript(leaf.clone(), witness.clone(), TapscriptProfile::Consensus);
                assert_clean_true(&result);
            }
        }
    }

    #[test]
    fn signed_extrema_and_final_overflow_match_in_both_profiles() {
        for (width, expected) in [
            (1, 0),
            (1, 1),
            (2, -2),
            (8, -37),
            (31, -715_827_882),
            (31, 1_431_655_765),
            (32, -2_147_483_647),
            (32, -1),
            (32, 1_431_655_765),
        ] {
            for decoder in decoders(width) {
                let leaf = checked(decoder, expected);
                for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
                    let result =
                        run_tapscript(leaf.clone(), fixture::bits(expected, width), profile);
                    assert_clean_true(&result);
                }
            }
        }
        for decoder in decoders(32) {
            let leaf = script! { { decoder } OP_DROP OP_TRUE }.compile_with_policy();
            for expected in [-2_863_311_530, -2_147_483_649, -2_147_483_648] {
                for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
                    let result = run_tapscript(leaf.clone(), fixture::bits(expected, 32), profile);
                    assert!(!result.success);
                }
            }
        }
    }

    #[test]
    fn every_bit_position_rejects_raw_aliases_and_malformed_items() {
        for decoder in decoders(8) {
            let leaf = checked(decoder, 0);
            let valid = fixture::bits(0, 8);
            for index in 0..8 {
                for malformed in [vec![0], vec![0x80], vec![2], vec![1, 0], vec![0; 520]] {
                    let mut witness = valid.clone();
                    witness[index] = malformed;
                    let result = run_tapscript(leaf.clone(), witness, TapscriptProfile::Consensus);
                    assert!(!result.success);
                }
            }
            for len in [0, 7, 9] {
                let result =
                    run_tapscript(leaf.clone(), vec![vec![]; len], TapscriptProfile::Consensus);
                assert!(!result.success);
            }
        }
        for width in [0, 33] {
            assert!(std::panic::catch_unwind(|| decode_negabinary(width)).is_err());
        }
    }

    #[test]
    fn unguarded_multiply_first_rejects_a_representable_result() {
        let weak = script! {
            { schedule::verify_bit() }
            for _ in 1..32 {
                OP_SWAP { schedule::verify_bit() } OP_SWAP
                OP_DUP OP_ADD OP_SUB
            }
            { -2_147_483_647i64 } OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        let result = run_tapscript(
            weak,
            fixture::bits(-2_147_483_647, 32),
            TapscriptProfile::Consensus,
        );
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn full_width_batches_preserve_both_caller_stacks_at_the_frontier() {
        let values = fixture::values(31);
        let leaf = script! {
            OP_TOALTSTACK
            { fixture::verify_batch(decode_negabinary(32), &values) }
            OP_FROMALTSTACK 18 OP_EQUALVERIFY
            OP_DROP OP_DROP OP_DROP
            17 OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        let mut witness = vec![vec![17], vec![], vec![], vec![]];
        witness.extend(fixture::witness(&values, 32));
        witness.push(vec![18]);
        let result = run_tapscript(leaf.clone(), witness.clone(), TapscriptProfile::Consensus);
        assert_clean_true(&result);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        witness.insert(0, vec![19]);
        let result = run_tapscript(leaf, witness, TapscriptProfile::Consensus);
        assert_eq!(result.error, Some(ExecError::StackSize));
    }
}
