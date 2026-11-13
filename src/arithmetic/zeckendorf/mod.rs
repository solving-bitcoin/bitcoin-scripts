//! Canonical nonnegative decoding of a fixed-width Zeckendorf bit vector.

use crate::{
    arithmetic::scriptint,
    support::script::{script, Script},
};

/// Largest supported Fibonacci weight vector; its complete sum fits ScriptNum.
pub const MAX_ZECKENDORF_WIDTH: u32 = 43;

/// Consume `width` raw canonical no-adjacent bits, most significant on top,
/// and return their canonical nonnegative ScriptNum using weights 1, 2, 3, 5,
/// and so on. Bit zero, with weight one, is deepest. Both caller stacks are
/// otherwise preserved. No witness value or auxiliary hint is consumed.
pub fn decode_zeckendorf(width: u32) -> Script {
    assert!(
        (1..=MAX_ZECKENDORF_WIDTH).contains(&width),
        "Zeckendorf supports 1..=43 bits"
    );

    let mut weights = Vec::with_capacity(width as usize);
    let (mut previous, mut current) = (0u64, 1u64);
    for _ in 0..width {
        let weight = previous + current;
        weights.push(weight);
        previous = current;
        current = weight;
    }
    let total: u64 = weights.iter().sum();
    assert!(
        total <= u64::from(scriptint::MAX_SCRIPTNUM),
        "weights overflow a ScriptNum"
    );

    script! {
        // At each iteration the original bit vector is unchanged. The first
        // PICK copies the higher bit at source depth `offset`; the second uses
        // `offset + 2` because that copy added one item between the pair.
        for offset in (0..width - 1).rev() {
            { offset } OP_PICK { offset + 2 } OP_PICK
            OP_2DUP OP_ADD 2 OP_LESSTHAN OP_VERIFY OP_2DROP
        }
        0
        for weight in weights.iter().rev() {
            OP_SWAP
            OP_DUP 0 2 OP_WITHIN OP_VERIFY
            { scriptint::verify_canonical() }
            OP_IF { *weight as i64 } OP_ADD OP_ENDIF
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

    const WIDTH12_WEIGHTS: [u32; 12] = [1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233];

    fn bits(mask: u64, width: u32) -> Vec<Vec<u8>> {
        (0..width)
            .map(|position| scriptnum(((mask >> position) & 1) as i64))
            .collect()
    }

    fn checked(width: u32, expected: i64) -> ScriptBuf {
        script! { { decode_zeckendorf(width) } { expected } OP_EQUALVERIFY OP_TRUE }
            .compile_with_policy()
    }

    fn exact_arity_checked(width: u32, expected: i64) -> ScriptBuf {
        script! {
            OP_DEPTH { width } OP_EQUALVERIFY
            { decode_zeckendorf(width) } { expected } OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy()
    }

    #[test]
    fn exhaustive_width12_vectors_are_a_bijection_onto_zero_through_376() {
        let reject = script! { { decode_zeckendorf(12) } OP_DROP OP_TRUE }.compile_with_policy();
        let mut seen = [false; 377];
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        for mask in 0u64..1 << 12 {
            // This independent oracle uses fixed Fibonacci weights and the
            // ordinary binary-mask adjacency relation, not generator output.
            let canonical = mask & (mask >> 1) == 0;
            let expected = WIDTH12_WEIGHTS
                .iter()
                .enumerate()
                .filter(|(position, _)| mask & (1u64 << *position) != 0)
                .map(|(_, weight)| *weight as usize)
                .sum::<usize>();
            let result = if canonical {
                assert!(expected <= 376);
                assert!(!seen[expected], "duplicate decoded value {expected}");
                seen[expected] = true;
                accepted += 1;
                run_tapscript(
                    checked(12, expected as i64),
                    bits(mask, 12),
                    TapscriptProfile::Consensus,
                )
            } else {
                rejected += 1;
                run_tapscript(reject.clone(), bits(mask, 12), TapscriptProfile::Consensus)
            };
            if canonical {
                assert_clean_true(&result);
            } else {
                assert!(
                    !result.success,
                    "accepted adjacent mask {mask:#06x}: {result}"
                );
            }
        }
        assert_eq!((accepted, rejected), (377, 4096 - 377));
        assert!(seen.into_iter().all(|value| value));
    }

    #[test]
    fn zero_one_canonical100_and_width43_boundaries_decode_exactly() {
        for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
            for (width, mask, expected) in [
                (12, 0, 0),
                (1, 1, 1),
                // Least significant first: 3 + 8 + 89 = 100.
                (12, (1 << 2) | (1 << 4) | (1 << 9), 100),
                // Alternating bits through weight 701,408,733; no adjacency.
                (43, 0, 0),
            ] {
                assert_clean_true(&run_tapscript(
                    checked(width, expected),
                    bits(mask, width),
                    profile,
                ));
            }
            let maximum43: Vec<_> = (0..43)
                .map(|position| scriptnum(i64::from(position % 2 == 0)))
                .collect();
            assert_clean_true(&run_tapscript(
                checked(43, 1_134_903_169),
                maximum43,
                profile,
            ));
            let mut highest_weight = vec![Vec::new(); 43];
            highest_weight[42] = vec![1];
            assert_clean_true(&run_tapscript(
                checked(43, 701_408_733),
                highest_weight,
                profile,
            ));
        }
        for (position, expected_total) in [(43, 1_836_311_901u64), (44, 2_971_215_071u64)] {
            let (mut previous, mut current) = (0u64, 1u64);
            let mut total = 0u64;
            for _ in 0..position {
                let weight = previous + current;
                total += weight;
                previous = current;
                current = weight;
            }
            assert_eq!(total, expected_total);
        }
        for width in [0, MAX_ZECKENDORF_WIDTH + 1] {
            assert!(std::panic::catch_unwind(|| decode_zeckendorf(width)).is_err());
        }
    }

    #[test]
    fn every_position_rejects_aliases_negative_zero_and_malformed_numbers() {
        let leaf = checked(12, 0);
        let valid = bits(0, 12);
        for position in 0..12 {
            for (malformed, error) in [
                (vec![0], ExecError::EqualVerify),
                (vec![0, 0], ExecError::EqualVerify),
                (vec![0, 0, 0, 0], ExecError::EqualVerify),
                (vec![1, 0], ExecError::EqualVerify),
                (vec![1, 0, 0, 0], ExecError::EqualVerify),
                (vec![0x80], ExecError::EqualVerify),
                (vec![0, 0, 0, 0x80], ExecError::EqualVerify),
                (vec![2], ExecError::Verify),
                (vec![0x81], ExecError::Verify),
                (vec![0; 5], ExecError::ScriptIntNumericOverflow),
                (vec![0; 520], ExecError::ScriptIntNumericOverflow),
                (vec![0; 521], ExecError::PushSize),
            ] {
                let mut witness = valid.clone();
                witness[position] = malformed;
                let result = run_tapscript(leaf.clone(), witness, TapscriptProfile::Consensus);
                assert_eq!(result.error, Some(error), "position {position}: {result}");
                assert!(!result.success);
            }
        }
    }

    #[test]
    fn unequal_and_noncanonical_expansions_and_wrong_arity_reject() {
        let canonical100 = bits((1 << 2) | (1 << 4) | (1 << 9), 12);
        let adjacent100 = bits((1 << 2) | (1 << 4) | (1 << 7) | (1 << 8), 12);
        let result = run_tapscript(checked(12, 100), adjacent100, TapscriptProfile::Consensus);
        assert_eq!(result.error, Some(ExecError::Verify));

        // Ordinary power-of-two binary 100 = 64 + 32 + 4 has adjacent weights.
        let binary100 = bits((1 << 2) | (1 << 5) | (1 << 6), 12);
        let result = run_tapscript(checked(12, 100), binary100, TapscriptProfile::Consensus);
        assert_eq!(result.error, Some(ExecError::Verify));

        // Flipping weight one changes the exact result without an adjacency failure.
        let mut value101 = canonical100.clone();
        value101[0] = vec![1];
        let result = run_tapscript(checked(12, 100), value101, TapscriptProfile::Consensus);
        assert_eq!(result.error, Some(ExecError::EqualVerify));

        let exact = exact_arity_checked(12, 0);
        for length in [0usize, 11, 13] {
            let result = run_tapscript(
                exact.clone(),
                vec![Vec::new(); length],
                TapscriptProfile::Consensus,
            );
            assert!(!result.success, "accepted {length} records: {result}");
        }
        assert_clean_true(&run_tapscript(
            exact,
            vec![Vec::new(); 12],
            TapscriptProfile::Consensus,
        ));
    }

    #[test]
    fn exact_combined_stack_limit_accepts_and_one_more_item_rejects() {
        let preserved = 1_000usize - (12 + 4) - 1;
        let mut items = vec![scriptnum(7); preserved];
        items.extend(bits((1 << 2) | (1 << 4) | (1 << 9), 12));
        let leaf = script! {
            19 OP_TOALTSTACK
            { decode_zeckendorf(12) } 100 OP_EQUALVERIFY
            for _ in 0..preserved { OP_DROP }
            OP_FROMALTSTACK OP_DROP OP_TRUE
        }
        .compile_with_policy();
        let accepted = run_tapscript(leaf.clone(), items.clone(), TapscriptProfile::Policy);
        assert_clean_true(&accepted);
        assert_eq!(accepted.stats.max_nb_stack_items, 1_000);

        items.insert(0, scriptnum(7));
        let rejected = run_tapscript(
            script! {
                19 OP_TOALTSTACK
                { decode_zeckendorf(12) }
                OP_TRUE
            }
            .compile_with_policy(),
            items,
            TapscriptProfile::Policy,
        );
        assert_eq!(rejected.error, Some(ExecError::StackSize));
    }

    #[test]
    fn caller_main_and_altstack_items_survive_at_the_measured_peak() {
        let leaf = script! {
            OP_TOALTSTACK
            { decode_zeckendorf(12) } 100 OP_EQUALVERIFY
            18 OP_EQUALVERIFY 17 OP_EQUALVERIFY
            OP_FROMALTSTACK 19 OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        let mut witness = vec![scriptnum(17), scriptnum(18)];
        witness.extend(bits((1 << 2) | (1 << 4) | (1 << 9), 12));
        witness.push(scriptnum(19));
        for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
            let result = run_tapscript(leaf.clone(), witness.clone(), profile);
            assert_clean_true(&result);
            assert_eq!(result.stats.max_nb_stack_items, 19);
        }
    }
}
