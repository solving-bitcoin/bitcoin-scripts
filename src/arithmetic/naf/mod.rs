//! Checked non-adjacent-form (NAF) witnesses for nonnegative ScriptNums.
//!
//! Every operand and digit is checked for a raw, minimally encoded, at-most
//! four-byte ScriptNum. The intersection of the digit range and the adjacent
//! absolute-sum check proves both the `{-1,0,1}` alphabet and the NAF spacing
//! rule. Reconstructing high-to-low checks the integer relation without a
//! multiplication or division opcode. Accepted inputs remain on the stack for
//! a downstream scalar schedule; they are not serialized again.

use crate::{arithmetic::scriptint, support::script::*};

fn assert_width(width: u32) {
    assert!((1..=32).contains(&width), "NAF supports 1..=32 digits");
}

/// Conservative combined main-plus-alt stack bound with no caller state.
///
/// Includes the scalar, all digits, duplicated validation inputs, and one
/// reconstruction accumulator. Every preserved main- or altstack item adds to
/// this bound. A composed policy-compiled leaf may have a smaller measured
/// peak, so metric fixtures report their own exact peak rather than assuming
/// this bound. Arithmetic remains in the four-byte domain for accepted inputs.
pub fn scriptnum_naf_stack_bound(width: u32) -> u32 {
    assert_width(width);
    width + 5
}

/// Verify a fixed-width NAF opening while retaining its original stack layout.
///
/// Before: `preserved | scalar | digit[0] | ... | digit[width-1]`, with the
/// most significant digit on top. After a valid verification the stack is
/// unchanged. The scalar is one nonnegative data item; every digit is an
/// incremental arithmetic hint. All `width + 1` items coexist at script entry.
/// The fragment has no terminal predicate and leaves all altstack items intact.
///
/// Accepted inputs prove `scalar = sum(digit[i] * 2^i)`, every digit is in
/// `{-1,0,1}`, consecutive digits are not both nonzero, and the scalar is a
/// canonical nonnegative four-byte-or-smaller ScriptNum. Thus the opening is
/// the unique zero-padded NAF for that scalar in this representation domain.
pub fn verify_scriptnum_naf(width: u32) -> Script {
    assert_width(width);
    script! {
        { width } OP_PICK
        OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
        { scriptint::verify_canonical() }
        OP_DROP

        for offset in 0..width {
            { offset } OP_PICK
            OP_DUP -1 2 OP_WITHIN OP_VERIFY
            { scriptint::verify_canonical() }
            OP_DROP
        }

        for offset in 0..width.saturating_sub(1) {
            { offset } OP_PICK OP_ABS
            // The first copied digit adds one item above the second source.
            { offset + 2 } OP_PICK OP_ABS
            OP_ADD 2 OP_LESSTHAN OP_VERIFY
        }

        OP_0
        for offset in 1..=width {
            { offset } OP_PICK
            OP_DUP OP_1 OP_EQUAL
            OP_IF
                // 2*a+1; any overflowing intermediate makes the claim unmatchable.
                OP_DROP OP_DUP OP_ADD OP_1ADD
            OP_ELSE
                OP_DUP OP_0 OP_EQUAL
                OP_IF
                    OP_DROP OP_DUP OP_ADD
                OP_ELSE
                    // For d=-1, form 2*a-1 as a+(a-1). This keeps the
                    // maximum scalar's final cancellation inside four bytes.
                    OP_DROP OP_DUP OP_1SUB OP_ADD
                OP_ENDIF
            OP_ENDIF
        }
        { width + 1 } OP_PICK
        OP_NUMEQUALVERIFY
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

    fn scalar_witness(scalar: i64, digits: &[i64]) -> Vec<Vec<u8>> {
        std::iter::once(scriptnum(scalar))
            .chain(digits.iter().copied().map(scriptnum))
            .collect()
    }

    fn reference_naf(mut scalar: i64) -> Vec<i64> {
        assert!(scalar >= 0);
        let mut digits = Vec::new();
        while scalar > 0 {
            let digit = if scalar % 2 == 1 {
                let digit = 2 - (scalar % 4);
                scalar -= digit;
                digit
            } else {
                0
            };
            scalar /= 2;
            digits.push(digit);
        }
        digits
    }

    fn padded_naf(scalar: i64, width: u32) -> (i64, Vec<i64>) {
        let mut digits = reference_naf(scalar);
        assert!(
            digits.len() <= width as usize,
            "{scalar} does not fit {width}"
        );
        digits.resize(width as usize, 0);
        (scalar, digits)
    }

    fn positional_sum(digits: &[i64]) -> i64 {
        digits
            .iter()
            .enumerate()
            .map(|(index, digit)| digit * (1i64 << index))
            .sum()
    }

    fn is_nonnegative_naf(scalar: i64, digits: &[i64]) -> bool {
        scalar >= 0
            && positional_sum(digits) == scalar
            && digits.windows(2).all(|pair| pair[0] == 0 || pair[1] == 0)
    }

    /// The fragment retains its operand and every digit, so compare them against
    /// the caller's exact original raw items before reaching a truthy terminal.
    fn checking_leaf(width: u32, witness: &[Vec<u8>]) -> ScriptBuf {
        script! {
            { verify_scriptnum_naf(width) }
            for expected in witness.iter().rev() {
                { expected.clone() } OP_EQUALVERIFY
            }
            OP_TRUE
        }
        .compile_with_policy()
    }

    fn assert_holds(witness: Vec<Vec<u8>>, width: u32) {
        let leaf = checking_leaf(width, &witness);
        for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
            let result = run_tapscript(leaf.clone(), witness.clone(), profile);
            assert_clean_true(&result);
            assert!(result.stats.max_nb_stack_items as u32 <= scriptnum_naf_stack_bound(width));
        }
    }

    fn assert_rejects(witness: Vec<Vec<u8>>, width: u32) {
        let leaf = checking_leaf(width, &witness);
        for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
            let result = run_tapscript(leaf.clone(), witness.clone(), profile);
            assert!(!result.success, "accepted invalid NAF witness: {result}");
        }
    }

    #[test]
    fn isolated_pair_uses_the_depth_above_the_first_copy() {
        let witness = scalar_witness(2, &[0, 1]);
        let pair = run_tapscript(
            checking_leaf(2, &witness),
            witness,
            TapscriptProfile::Policy,
        );
        assert_clean_true(&pair);
    }

    #[test]
    fn reference_naf_matches_every_eight_bit_scalar_and_retains_the_opening() {
        for scalar in 0..=255i64 {
            let (scalar, digits) = padded_naf(scalar, 9);
            assert!(is_nonnegative_naf(scalar, &digits));
            let witness = scalar_witness(scalar, &digits);
            let compiled = checking_leaf(9, &witness);
            let result = run_tapscript(compiled, witness, TapscriptProfile::Policy);
            assert!(result.success, "scalar {scalar}: {result}");
            assert_clean_true(&result);
        }
    }

    #[test]
    fn exhaustive_ternary_four_digit_vectors_enforce_spacing_and_value() {
        for packed in 0..3i64.pow(4) {
            let mut remaining = packed;
            let mut digits = Vec::new();
            for _ in 0..4 {
                digits.push(remaining % 3 - 1);
                remaining /= 3;
            }
            let scalar = positional_sum(&digits);
            let witness = scalar_witness(scalar, &digits);
            if is_nonnegative_naf(scalar, &digits) {
                assert_holds(witness, 4);
            } else {
                assert_rejects(witness, 4);
            }
        }
    }

    #[test]
    fn every_alternative_adjacent_nonzero_pair_is_rejected_at_matching_value() {
        for offset in 0..3usize {
            let mut digits = vec![0, 1, 0, 1];
            digits[offset] = 1;
            digits[offset + 1] = 1;
            let witness = scalar_witness(positional_sum(&digits), &digits);
            let leaf = checking_leaf(4, &witness);
            let result = run_tapscript(leaf, witness, TapscriptProfile::Policy);
            assert_eq!(result.error, Some(ExecError::Verify), "{result}");
        }

        let alternative = scalar_witness(3, &[1, 1, 0]);
        let canonical = scalar_witness(3, &padded_naf(3, 3).1);
        assert_holds(canonical, 3);
        assert_rejects(alternative, 3);

        let negative = scalar_witness(-5, &[-1, 0, -1]);
        assert_rejects(negative, 3);
    }

    #[test]
    fn every_input_position_rejects_noncanonical_aliases_without_policy_help() {
        let (scalar, digits) = padded_naf(173, 9);
        let base = scalar_witness(scalar, &digits);
        for position in 0..base.len() {
            let mut alias = base.clone();
            if position == 0 {
                alias[position] = vec![0xad, 0x00, 0x00];
            } else {
                alias[position] = match digits[position - 1] {
                    0 => vec![0x00],
                    1 => vec![0x01, 0x00],
                    -1 => vec![0x01, 0x80],
                    other => unreachable!("unexpected test digit {other}"),
                };
            }
            let policy = run_tapscript(
                checking_leaf(9, &alias),
                alias.clone(),
                TapscriptProfile::Policy,
            );
            assert_eq!(
                policy.error,
                Some(ExecError::MinimalData),
                "position {position}"
            );
            let consensus =
                run_tapscript(checking_leaf(9, &alias), alias, TapscriptProfile::Consensus);
            assert_eq!(
                consensus.error,
                Some(ExecError::EqualVerify),
                "position {position}"
            );
        }
    }

    #[test]
    fn zero_aliases_and_oversized_scalar_are_rejected_without_policy_help() {
        for position in 0..2 {
            let mut items = scalar_witness(0, &[0]);
            items[position] = vec![0x80];
            let policy = run_tapscript(
                checking_leaf(1, &items),
                items.clone(),
                TapscriptProfile::Policy,
            );
            assert_eq!(
                policy.error,
                Some(ExecError::MinimalData),
                "position {position}"
            );
            let consensus =
                run_tapscript(checking_leaf(1, &items), items, TapscriptProfile::Consensus);
            assert_eq!(
                consensus.error,
                Some(ExecError::EqualVerify),
                "position {position}"
            );
        }

        let oversized = vec![vec![1, 0, 0, 0, 0], vec![]];
        for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
            let result = run_tapscript(checking_leaf(1, &oversized), oversized.clone(), profile);
            assert_eq!(result.error, Some(ExecError::ScriptIntNumericOverflow));
        }
    }

    #[test]
    fn every_digit_rejects_out_of_range_and_oversized_items() {
        let (scalar, digits) = padded_naf(173, 9);
        let base = scalar_witness(scalar, &digits);
        for index in 0..digits.len() {
            for invalid in [scriptnum(2), scriptnum(-2), vec![1, 0, 0, 0, 0]] {
                let mut items = base.clone();
                items[index + 1] = invalid;
                assert_rejects(items, 9);
            }
        }
    }

    #[test]
    fn missing_extra_and_mismatched_items_are_not_accepted() {
        let (scalar, digits) = padded_naf(173, 9);
        let base = scalar_witness(scalar, &digits);
        for len in 0..base.len() {
            assert_rejects(base[..len].to_vec(), 9);
        }
        let mut extra = base.clone();
        extra.push(scriptnum(7));
        assert_rejects(extra, 9);
        assert_rejects(scalar_witness(scalar + 1, &digits), 9);
    }

    #[test]
    fn retained_opening_preserves_unrelated_caller_state() {
        let (scalar, digits) = padded_naf(173, 9);
        let mut items = vec![scriptnum(77), scriptnum(99)];
        items.extend(scalar_witness(scalar, &digits));
        let expected = items.clone();
        let result = run_tapscript(
            script! {
                9 OP_TOALTSTACK
                { verify_scriptnum_naf(9) }
                for expected in expected.iter().rev() {
                    { expected.clone() } OP_EQUALVERIFY
                }
                OP_FROMALTSTACK 9 OP_NUMEQUALVERIFY
                OP_TRUE
            }
            .compile_with_policy(),
            items,
            TapscriptProfile::Policy,
        );
        assert_clean_true(&result);
        assert!(result.stats.max_nb_stack_items as u32 <= scriptnum_naf_stack_bound(9) + 3);
    }

    #[test]
    fn maximum_width_is_accepted_and_one_more_item_reaches_stack_failure() {
        let mut maximum_digits = vec![0; 32];
        maximum_digits[0] = -1;
        maximum_digits[31] = 1;
        assert_holds(scalar_witness(2_147_483_647, &maximum_digits), 32);

        let digits: Vec<i64> = (0..32).map(|index| i64::from(index % 2 == 0)).collect();
        let scalar = positional_sum(&digits);
        assert_eq!(scalar, 1_431_655_765);
        let witness = scalar_witness(scalar, &digits);
        assert_holds(witness.clone(), 32);

        let preserved = 1_000 - scriptnum_naf_stack_bound(32) as usize - 1;
        let mut at_limit = vec![vec![7]; preserved];
        at_limit.extend(witness.clone());
        let result = run_tapscript(
            script! {
                9 OP_TOALTSTACK
                { verify_scriptnum_naf(32) }
                for _ in 0..preserved + 33 { OP_DROP }
                OP_FROMALTSTACK 9 OP_NUMEQUALVERIFY
                OP_TRUE
            }
            .compile_with_policy(),
            at_limit.clone(),
            TapscriptProfile::Policy,
        );
        assert_clean_true(&result);
        assert!(result.stats.max_nb_stack_items <= 1_000);

        let mut over = vec![vec![7]];
        over.extend(at_limit);
        let rejected = run_tapscript(
            script! {
                9 OP_TOALTSTACK
                { verify_scriptnum_naf(32) }
                OP_TRUE
            }
            .compile_with_policy(),
            over,
            TapscriptProfile::Policy,
        );
        assert_eq!(rejected.error, Some(ExecError::StackSize), "{rejected}");
    }

    #[test]
    fn rejects_unsupported_generation_widths() {
        for width in [0, 33] {
            assert!(std::panic::catch_unwind(|| verify_scriptnum_naf(width)).is_err());
            assert!(std::panic::catch_unwind(|| scriptnum_naf_stack_bound(width)).is_err());
        }
    }

    #[test]
    fn singleton_zero_and_one_have_signed_distance_from_the_alternative_ternary_form() {
        assert_holds(scalar_witness(0, &[0]), 1);
        assert_holds(scalar_witness(1, &[1]), 1);
        assert_rejects(scalar_witness(-1, &[-1]), 1);
    }
}
