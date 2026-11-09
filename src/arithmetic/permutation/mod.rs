//! Canonical, hint-free decoding of small lexicographic permutation ranks.

use crate::{arithmetic::scriptint::verify_canonical, support::script::*};

/// 12! fits four-byte ScriptNum arithmetic; 13! does not.
pub const MAX_PERMUTATION_WIDTH: u32 = 12;

/// Number of permutations in the supported alphabet.
pub fn permutation_count(width: u32) -> u32 {
    assert!(
        (1..=MAX_PERMUTATION_WIDTH).contains(&width),
        "width must be in 1..=12"
    );
    (1..=width).product()
}

/// Expand one canonical rank in `0..width!` to its lexicographic permutation.
///
/// Input: `preserved | rank`. Output (top first): `p[0], ..., p[width-1]`.
/// Existing main and alt stack items are preserved. There are no witness hints.
/// Callers must consume the outputs and supply a terminal predicate.
pub fn decode_rank(width: u32) -> Script {
    let count = permutation_count(width);
    script! {
        { verify_canonical() }
        OP_DUP 0 { count } OP_WITHIN OP_VERIFY
        OP_TOALTSTACK
        for symbol in (0..width).rev() {
            { symbol }
        }
        OP_FROMALTSTACK
        for remaining in (2..=width).rev() {
            // Residual r < remaining!, so floor(r / (remaining-1)!) < remaining.
            // Binary threshold subtraction computes that bounded quotient
            // without disabled OP_DIV, a table, or a hostile quotient hint.
            { crate::arithmetic::scriptint::bounded::div_rem_unchecked(
                permutation_count(remaining - 1),
                permutation_count(remaining) - 1,
            ) }
            // Pool | quotient | residual -> Pool | residual | selected.
            // +1 accounts for the residual above the shrinking trusted pool.
            OP_SWAP OP_1ADD OP_ROLL OP_TOALTSTACK
        }
        0 OP_EQUALVERIFY
        OP_TOALTSTACK
        for _ in 0..width {
            OP_FROMALTSTACK
        }
    }
}

/// Baseline: decode `width-1` canonical Lehmer digits from a shrinking pool.
///
/// Input (top first): `d[0], ..., d[width-2]`; each `d[i] < width-i`.
/// Output (top first): `p[0], ..., p[width-1]`. Zero hints; preserved state is
/// untouched. The final digit is implicitly zero and has no witness item.
pub fn decode_digits(width: u32) -> Script {
    permutation_count(width);
    script! {
        for symbol in (0..width).rev() {
            { symbol }
        }
        for remaining in (2..=width).rev() {
            { remaining } OP_ROLL
            { verify_canonical() }
            OP_DUP 0 { remaining } OP_WITHIN OP_VERIFY
            OP_ROLL OP_TOALTSTACK
        }
        OP_TOALTSTACK
        for _ in 0..width {
            OP_FROMALTSTACK
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

    // Lexicographic successor enumeration is independent of factoradic division.
    fn next_permutation(values: &mut [u32]) -> bool {
        let Some(i) = (0..values.len().saturating_sub(1))
            .rev()
            .find(|&i| values[i] < values[i + 1])
        else {
            return false;
        };
        let j = (i + 1..values.len())
            .rev()
            .find(|&j| values[j] > values[i])
            .unwrap();
        values.swap(i, j);
        values[i + 1..].reverse();
        true
    }

    fn expected_leaf(fragment: Script, expected: &[u32]) -> bitcoin::ScriptBuf {
        script! {
            { fragment }
            for value in expected {
                { *value } OP_EQUALVERIFY
            }
            OP_TRUE
        }
        .compile_with_policy()
    }

    fn lehmer_witness(permutation: &[u32]) -> Vec<Vec<u8>> {
        (0..permutation.len() - 1)
            .rev()
            .map(|i| {
                scriptnum(
                    permutation[i + 1..]
                        .iter()
                        .filter(|&&x| x < permutation[i])
                        .count() as i64,
                )
            })
            .collect()
    }

    #[test]
    fn exhaustive_lexicographic_permutations_through_width_six() {
        for width in 1..=6 {
            let mut expected: Vec<_> = (0..width).collect();
            let mut rank = 0;
            loop {
                let packed = run_tapscript(
                    expected_leaf(decode_rank(width), &expected),
                    vec![scriptnum(rank)],
                    TapscriptProfile::Consensus,
                );
                assert_clean_true(&packed);
                let digits = run_tapscript(
                    expected_leaf(decode_digits(width), &expected),
                    lehmer_witness(&expected),
                    TapscriptProfile::Consensus,
                );
                assert_clean_true(&digits);
                rank += 1;
                if !next_permutation(&mut expected) {
                    break;
                }
            }
            assert_eq!(rank as u32, permutation_count(width));
        }
    }

    #[test]
    fn wider_boundaries_and_deterministic_ranks() {
        for width in 7..=12 {
            let mut ranks = vec![0, 1, 127, 128, 255, 256, permutation_count(width) - 1];
            // Exercise every quotient transition on both sides, including
            // thresholds beyond the exhaustively enumerated small widths.
            for remaining in 2..=width {
                let block = permutation_count(remaining - 1);
                for quotient in 1..remaining {
                    ranks.extend([quotient * block - 1, quotient * block]);
                }
            }
            ranks.sort_unstable();
            ranks.dedup();
            for mut rank in ranks {
                let original = rank;
                let mut pool: Vec<_> = (0..width).collect();
                let mut expected = Vec::new();
                for remaining in (1..=width).rev() {
                    let divisor = if remaining == 1 {
                        1
                    } else {
                        permutation_count(remaining - 1)
                    };
                    expected.push(pool.remove((rank / divisor) as usize));
                    rank %= divisor;
                }
                let result = run_tapscript(
                    expected_leaf(decode_rank(width), &expected),
                    vec![scriptnum(original as i64)],
                    TapscriptProfile::Consensus,
                );
                assert_clean_true(&result);
                let result = run_tapscript(
                    expected_leaf(decode_digits(width), &expected),
                    lehmer_witness(&expected),
                    TapscriptProfile::Consensus,
                );
                assert_clean_true(&result);
            }
        }
    }

    #[test]
    fn rejects_hostile_ranks_even_without_global_minimaldata() {
        let leaf = expected_leaf(decode_rank(4), &[0, 1, 2, 3]);
        for raw in [
            scriptnum(-1),
            scriptnum(24),
            scriptnum(2_147_483_647),
            vec![0],
            vec![0x80],
            vec![1, 0],
            vec![0; 5],
            vec![0; 521],
        ] {
            let result = run_tapscript(leaf.clone(), vec![raw], TapscriptProfile::Consensus);
            assert!(!result.success, "accepted malformed rank: {result}");
        }
        assert!(!run_tapscript(leaf.clone(), vec![], TapscriptProfile::Consensus).success);
        assert!(!run_tapscript(leaf, vec![vec![], vec![]], TapscriptProfile::Consensus).success);
    }

    #[test]
    fn rejects_hostile_lehmer_digits_at_every_position() {
        for width in 2..=12 {
            let expected: Vec<_> = (0..width).collect();
            let leaf = expected_leaf(decode_digits(width), &expected);
            for position in 0..width - 1 {
                for bad in [
                    scriptnum(-1),
                    scriptnum((width - position) as i64),
                    vec![0],
                    vec![0x80],
                    vec![0; 5],
                ] {
                    let mut witness = vec![vec![]; (width - 1) as usize];
                    witness[(width - 2 - position) as usize] = bad;
                    assert!(
                        !run_tapscript(leaf.clone(), witness, TapscriptProfile::Consensus).success
                    );
                }
            }
        }
    }

    #[test]
    fn preserves_surrounding_state_and_detects_stack_overflow() {
        let leaf = script! {
            1 OP_ROLL OP_TOALTSTACK
            { decode_rank(4) }
            0 OP_EQUALVERIFY 1 OP_EQUALVERIFY 2 OP_EQUALVERIFY 3 OP_EQUALVERIFY
            77 OP_EQUALVERIFY
            OP_FROMALTSTACK 99 OP_EQUAL
        }
        .compile_with_policy();
        assert_clean_true(&run_tapscript(
            leaf,
            vec![scriptnum(77), scriptnum(99), vec![]],
            TapscriptProfile::Consensus,
        ));
        let leaf = script! { { decode_rank(12) } }.compile_with_policy();
        let mut witness = vec![vec![]; 990];
        witness.push(vec![]);
        assert!(!run_tapscript(leaf, witness, TapscriptProfile::Consensus).success);
    }

    #[test]
    fn exact_composition_frontiers_include_preserved_main_and_alt_items() {
        for width in [4, 8, 12] {
            for (fragment, payload, peak) in [
                (
                    decode_rank(width),
                    vec![scriptnum(i64::from(permutation_count(width) - 1))],
                    width + 4,
                ),
                (
                    decode_digits(width),
                    (1..width).map(|d| scriptnum(i64::from(d))).collect(),
                    2 * width + 2,
                ),
            ] {
                let preserved = 1000 - peak;
                let leaf = script! {
                    { payload.len() } OP_ROLL OP_TOALTSTACK
                    { fragment.clone() }
                    for value in (0..width).rev() { { value } OP_EQUALVERIFY }
                    for _ in 0..preserved-1 { 77 OP_EQUALVERIFY }
                    OP_FROMALTSTACK 99 OP_EQUAL
                }
                .compile_with_policy();
                let mut witness = vec![scriptnum(77); (preserved - 1) as usize];
                witness.push(scriptnum(99));
                witness.extend(payload.clone());
                let result = run_tapscript(leaf, witness, TapscriptProfile::Consensus);
                assert_clean_true(&result);
                assert_eq!(result.stats.max_nb_stack_items, 1000);
                let mut overflowing = vec![scriptnum(77); preserved as usize];
                overflowing.push(scriptnum(99));
                let leaf = script! { { payload.len() } OP_ROLL OP_TOALTSTACK { fragment } }
                    .compile_with_policy();
                overflowing.extend(payload);
                let result = run_tapscript(leaf, overflowing, TapscriptProfile::Consensus);
                assert!(matches!(
                    result.error,
                    Some(bitcoin_scriptexec::ExecError::StackSize)
                ));
                assert_eq!(result.stats.max_nb_stack_items, 1001);
            }
        }
    }

    #[test]
    fn rejects_unsupported_widths() {
        for width in [0, 13, u32::MAX] {
            assert!(std::panic::catch_unwind(|| decode_rank(width)).is_err());
            assert!(std::panic::catch_unwind(|| decode_digits(width)).is_err());
        }
    }
}
