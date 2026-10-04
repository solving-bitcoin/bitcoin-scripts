//! Checked factoradic (Lehmer code) decoding over u4 digit vectors.
//!
//! A width-`n` Lehmer code is a sequence of `n` digits `c_0 .. c_{n-1}` with
//! the per-position bounds `0 <= c_i <= n-1-i`: a descending staircase of
//! digit domains. Such a code encodes the integer
//!
//! ```text
//! v = c_0 * (n-1)! + c_1 * (n-2)! + ... + c_{n-1} * 0!    (0 <= v < n!)
//! ```
//!
//! which is the lexicographic rank of a permutation of `n` objects. The top
//! digit bound `n-1` fits the u4 carrier domain up to `n = 16`, but the value
//! itself is carried in one ScriptNum: every Horner accumulator and the
//! terminal `OP_WITHIN` operand must stay inside the 4-byte consensus
//! numeric-operand domain ±(2^31−1), and the maximum codeword `n! − 1`
//! exceeds it at `n = 13` (13! − 1 > 2^31 − 1). The generator therefore
//! accepts `1 <= n <= 12`.
//!
//! The fragment consumes the `n` digit items from the top of the stack (the
//! top item is `c_0`, the most significant digit), proves every digit with an
//! embedded per-position `OP_WITHIN` bound, accumulates `v` in a single
//! ScriptNum through the Horner ladder `v <- v * (n-i) + c_i`, and returns
//! one item `0 <= v < n!` after a terminal self-check. The multiplication by
//! the generation-time constant `n - i` is unrolled repeated addition: the
//! `OP_MUL` opcode family fails every script that executes it, so it is not a
//! consensus implementation. All repeated-addition partial sums are at most
//! the final value `n! − 1 <= 12! − 1 < 2^31 − 1`, inside the 4-byte operand
//! domain. No hints, no table, no altstack use.
//!
//! The range-checked variant proves only `0 <= c_i < n-i`; under the local
//! consensus profile, which does not apply MINIMALDATA to consumed numbers,
//! a non-minimal ScriptNum alias of an in-range value is accepted and
//! normalized by the arithmetic. The canonical variant additionally rejects
//! raw aliases per digit, giving a byte-unique witness encoding.

use crate::arithmetic::u4::stack::verify_canonical_nibble;
use crate::support::script::*;
use bitcoin::script::Builder;

/// Largest width whose maximum codeword `n! − 1` stays inside the 4-byte
/// consensus numeric-operand domain: `12! − 1 <= 2^31 − 1 < 13! − 1`.
pub const FACTORADIC_U4_MAX_WIDTH: u32 = 12;

/// `n!` for `n <= 20`, the largest width whose value fits a `u64`.
pub fn factorial(n: u32) -> u64 {
    assert!(n <= 20, "factorial of {n} exceeds u64");
    (1..=n as u64).fold(1u64, |acc, k| acc * k)
}

/// Decode a width-`n` Lehmer code to its value.
///
/// `digits[i]` is `c_i`, the most significant digit first. Asserts the
/// per-position bounds; the Script fragment proves the same bounds on-chain.
pub fn lehmer_value(width: u32, digits: &[u32]) -> u64 {
    assert_eq!(digits.len(), width as usize, "digit count must equal width");
    let mut value: u64 = 0;
    for (i, &digit) in digits.iter().enumerate() {
        let bound = width - 1 - i as u32;
        assert!(
            digit <= bound,
            "Lehmer digit {i} = {digit} exceeds bound {bound}"
        );
        value = value * (width as u64 - i as u64) + digit as u64;
    }
    value
}

/// Lehmer code of a permutation of `0..n`: `c_i` counts the smaller elements
/// to the right of position `i`, so `0 <= c_i <= n-1-i`.
pub fn lehmer_of_permutation(perm: &[u32]) -> Vec<u32> {
    (0..perm.len())
        .map(|i| perm[i..].iter().filter(|&&x| x < perm[i]).count() as u32)
        .collect()
}

/// Lexicographic rank of a permutation, computed from its Lehmer code.
pub fn lexicographic_rank(perm: &[u32]) -> u64 {
    lehmer_value(perm.len() as u32, &lehmer_of_permutation(perm))
}

fn push_factorial(width: u32) -> Script {
    Script::new("factorial bound").push_script(
        Builder::new()
            .push_int(factorial(width) as i64)
            .into_script(),
    )
}

/// Build the checked width-`n` Lehmer decoder with the given digit check.
fn u4_lehmer_to_value_inner(width: u32, canonical: bool) -> Script {
    assert!(
        (1..=FACTORADIC_U4_MAX_WIDTH).contains(&width),
        "factoradic width must be 1..={FACTORADIC_U4_MAX_WIDTH}; the maximum codeword n!-1 must fit the 4-byte consensus numeric-operand domain"
    );

    let mut out = script! {};
    for i in 0..width {
        let bound = width - 1 - i;
        let multiplier = width - i;
        out = script! {
            { out }
            if i > 0 {
                OP_SWAP
            }
            if canonical {
                { verify_canonical_nibble() }
            }
            OP_DUP 0 { bound + 1 } OP_WITHIN OP_VERIFY
            if i > 0 {
                OP_SWAP
                for _ in 1..multiplier {
                    OP_DUP
                }
                for _ in 1..multiplier {
                    OP_ADD
                }
                OP_ADD
            }
        }
    }

    script! {
        { out }
        OP_DUP 0 { push_factorial(width) } OP_WITHIN OP_VERIFY
    }
}

/// Build the range-checked width-`n` Lehmer decoder.
///
/// Before: `preserved | c_{n-1} | ... | c_1 | c_0`, with `c_0` on top.
/// After: `preserved | v`, one item with `0 <= v < n!`.
///
/// Every digit is proven `0 <= c_i < n-i` with `OP_WITHIN`. Non-minimal
/// ScriptNum aliases of in-range values are accepted under the local consensus
/// profile and normalized by the arithmetic; under a profile that applies
/// MINIMALDATA, the interpreter rejects them before the fragment runs.
pub fn u4_lehmer_to_value(width: u32) -> Script {
    u4_lehmer_to_value_inner(width, false)
}

/// Build the canonical width-`n` Lehmer decoder.
///
/// Same contract as [`u4_lehmer_to_value`], additionally proving every digit
/// is a byte-unique canonical nibble (minimal ScriptNum encoding) before the
/// per-position range check.
pub fn u4_lehmer_to_value_canonical(width: u32) -> Script {
    u4_lehmer_to_value_inner(width, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{
        execute_script_with_inputs, execute_script_with_inputs_strict,
    };
    use crate::support::tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile};
    use bitcoin_scriptexec::ExecError;

    fn scriptnum(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let len = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..len].to_vec()
    }

    fn witness_from_digits(digits: &[u32]) -> Vec<Vec<u8>> {
        // The witness vector pushes its first item deepest, so the most
        // significant digit `c_0` must be the last item. Zero is the empty
        // item; every other digit is one byte, the minimal encodings.
        digits
            .iter()
            .rev()
            .map(|d| if *d == 0 { vec![] } else { vec![*d as u8] })
            .collect()
    }

    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn random_permutation(width: usize, state: &mut u64) -> Vec<u32> {
        let mut perm: Vec<u32> = (0..width as u32).collect();
        for i in (1..width).rev() {
            let j = (splitmix64(state) % (i + 1) as u64) as usize;
            perm.swap(i, j);
        }
        perm
    }

    fn value_witness(perm: &[u32]) -> Vec<Vec<u8>> {
        witness_from_digits(&lehmer_of_permutation(perm))
    }

    fn expect_value(fragment: &Script, witness: Vec<Vec<u8>>, expected: u64) {
        let constant = Script::new("expected value")
            .push_script(Builder::new().push_int(expected as i64).into_script());
        let result = execute_script_with_inputs_strict(
            script! {
                { fragment.clone() }
                { constant }
                OP_NUMEQUAL
                OP_VERIFY
                OP_TRUE
            },
            witness,
        );
        assert!(result.success, "expected value {expected}: {result}");
        assert!(result.stack_limit_enforced);
        assert_eq!(result.final_stack.len(), 1);
        assert_eq!(result.final_stack.get(0), vec![1]);
    }

    fn expect_rejected(fragment: &Script, witness: Vec<Vec<u8>>) {
        let result = execute_script_with_inputs(fragment.clone(), witness);
        assert!(!result.success, "accepted out-of-bounds witness: {result}");
    }

    /// Execute under the local consensus profile, which does not apply
    /// MINIMALDATA to numeric operands. Rejections of non-minimal aliases
    /// here therefore come from the fragment, not from the interpreter.
    fn execute_consensus(
        script: Script,
        witness: Vec<Vec<u8>>,
    ) -> crate::support::execution::ExecuteInfo {
        let result = execute_tapscript(
            script.compile_with_policy(),
            witness,
            TapscriptProfile::Consensus,
        );
        let TapscriptOutcome::Executed(execution) = result.outcome else {
            panic!("unexpected tapscript outcome: {result:?}");
        };
        execution
    }

    fn next_permutation(perm: &mut [u32]) -> bool {
        let width = perm.len();
        let mut p = width.saturating_sub(1);
        while p > 0 && perm[p - 1] >= perm[p] {
            p -= 1;
        }
        if p == 0 {
            return false;
        }
        p -= 1;
        let mut q = width - 1;
        while perm[q] <= perm[p] {
            q -= 1;
        }
        perm.swap(p, q);
        perm[p + 1..].reverse();
        true
    }

    #[test]
    fn decodes_zero_and_max_codewords() {
        const WIDTH: u32 = 12;
        let fragment = u4_lehmer_to_value(WIDTH);

        expect_value(&fragment, witness_from_digits(&[0; WIDTH as usize]), 0);

        let max: Vec<u32> = (0..WIDTH).rev().collect();
        let result = execute_script_with_inputs_strict(fragment.clone(), witness_from_digits(&max));
        assert!(result.success, "max codeword rejected: {result}");
        let mut bytes = [0u8; 8];
        let len = bitcoin::script::write_scriptint(&mut bytes, (factorial(WIDTH) - 1) as i64);
        assert_eq!(result.final_stack.get(0), bytes[..len].to_vec());
        assert!(result.stats.max_nb_stack_items <= 1_000);
    }

    #[test]
    fn single_digit_positions_match_place_values() {
        const WIDTH: u32 = 12;
        let fragment = u4_lehmer_to_value(WIDTH);
        for i in 0..WIDTH {
            let bound = WIDTH - 1 - i;
            let mut digits = vec![0u32; WIDTH as usize];
            digits[i as usize] = bound;
            let expected = bound as u64 * factorial(bound);
            expect_value(&fragment, witness_from_digits(&digits), expected);
        }
    }

    #[test]
    fn decodes_permutation_ranks_for_small_widths() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for width in 1..=8usize {
            let fragment = u4_lehmer_to_value(width as u32);
            let mut seen = std::collections::BTreeSet::new();
            if width <= 5 {
                // Exhaustive: every permutation of `width`.
                let mut perm: Vec<u32> = (0..width as u32).collect();
                loop {
                    seen.insert(perm.clone());
                    if !next_permutation(&mut perm) {
                        break;
                    }
                }
            } else {
                for _ in 0..32 {
                    seen.insert(random_permutation(width, &mut state));
                }
            }
            for perm in &seen {
                let expected = lexicographic_rank(perm);
                expect_value(&fragment, value_witness(perm), expected);
            }
        }
    }

    #[test]
    fn decodes_fixed_seed_permutations_at_width_twelve() {
        const WIDTH: u32 = 12;
        let fragment = u4_lehmer_to_value(WIDTH);
        let mut state = 2026_1004u64;
        for _ in 0..24 {
            let perm = random_permutation(WIDTH as usize, &mut state);
            expect_value(&fragment, value_witness(&perm), lexicographic_rank(&perm));
        }
    }

    #[test]
    fn rejects_out_of_bound_digits_at_every_position() {
        const WIDTH: u32 = 12;
        let fragment = u4_lehmer_to_value(WIDTH);
        for i in 0..WIDTH {
            let bound = WIDTH - 1 - i;
            let mut digits = vec![0u32; WIDTH as usize];
            digits[i as usize] = bound + 1;
            expect_rejected(&fragment, witness_from_digits(&digits));
        }
    }

    #[test]
    fn rejects_hostile_encodings() {
        const WIDTH: u32 = 12;
        let fragment = u4_lehmer_to_value(WIDTH);
        for hostile in [-1i64, 16, 255, 256, 1 << 30] {
            let mut witness = (0..WIDTH).map(|_| vec![]).collect::<Vec<_>>();
            witness
                .last_mut()
                .unwrap()
                .extend_from_slice(&scriptnum(hostile));
            expect_rejected(&fragment, witness);
        }

        // An oversized zero: 521 bytes exceeds the 520-byte element limit.
        let mut witness = (0..WIDTH).map(|_| vec![]).collect::<Vec<_>>();
        witness.last_mut().unwrap().resize(521, 0);
        expect_rejected(&fragment, witness);
    }

    #[test]
    fn numeric_variant_accepts_aliases_canonical_rejects_them() {
        const WIDTH: u32 = 3;
        let numeric = u4_lehmer_to_value(WIDTH);
        let canonical = u4_lehmer_to_value_canonical(WIDTH);

        // c_0 = 1 as the non-minimal two-byte alias [0x01, 0x00]; the
        // remaining digits are zero. Under the local consensus profile the
        // numeric variant accepts the alias and the canonical variant must
        // reject it from the fragment, not from MINIMALDATA.
        let mut witness = vec![vec![], vec![]];
        witness.push(vec![0x01, 0x00]);

        let accepted = execute_consensus(numeric.clone(), witness.clone());
        assert!(
            accepted.success,
            "numeric variant rejected alias: {accepted}"
        );
        assert_eq!(accepted.final_stack.get(0), scriptnum(2));

        let rejected = execute_consensus(canonical.clone(), witness.clone());
        assert!(
            !rejected.success,
            "canonical variant accepted alias: {rejected}"
        );
        assert_ne!(
            rejected.error,
            Some(ExecError::MinimalData),
            "rejection must come from the fragment, not MINIMALDATA: {rejected}"
        );

        // The minimal encoding of the same value passes both variants,
        // including under the strict profile.
        let honest = vec![vec![], vec![], vec![1]];
        expect_value(&canonical, honest, 2);
    }

    #[test]
    fn canonical_variant_matches_numeric_on_minimal_digits() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for width in 1..=8usize {
            let canonical = u4_lehmer_to_value_canonical(width as u32);
            for _ in 0..16 {
                let perm = random_permutation(width, &mut state);
                let expected = lexicographic_rank(&perm);
                expect_value(&canonical, value_witness(&perm), expected);
            }
        }
    }

    #[test]
    fn preserves_unrelated_state() {
        const WIDTH: u32 = 4;
        let fragment = u4_lehmer_to_value(WIDTH);
        let digits: Vec<u32> = (0..WIDTH).rev().collect();
        let expected = lehmer_value(WIDTH, &digits);
        let result = execute_script_with_inputs_strict(
            script! {
                7 OP_TOALTSTACK
                { fragment }
                { expected as i64 } OP_NUMEQUAL OP_VERIFY
                OP_FROMALTSTACK
                7 OP_EQUAL
            },
            witness_from_digits(&digits),
        );
        assert!(result.success, "state preservation failed: {result}");
        assert_eq!(result.final_stack.len(), 1);
        assert_eq!(result.final_stack.get(0), vec![1u8]);
    }

    #[test]
    fn rejects_width_boundaries() {
        assert!(std::panic::catch_unwind(|| u4_lehmer_to_value(0)).is_err());
        assert!(std::panic::catch_unwind(|| u4_lehmer_to_value(13)).is_err());
        assert!(std::panic::catch_unwind(|| u4_lehmer_to_value_canonical(13)).is_err());
        let one = u4_lehmer_to_value(1);
        expect_value(&one, vec![vec![]], 0);
        expect_rejected(&one, vec![vec![1u8]]);
    }

    #[test]
    fn max_width_value_stays_inside_numeric_operands() {
        // The width ceiling is set by the 4-byte consensus numeric-operand
        // domain, not by the u4 digit carrier: 12!-1 fits, 13!-1 does not.
        let max_12 = (factorial(12) - 1) as i64;
        assert!(max_12 > 0 && max_12 <= i32::MAX as i64);
        assert!((factorial(13) - 1) as u64 > i32::MAX as u64);

        let max: Vec<u32> = (0..FACTORADIC_U4_MAX_WIDTH).rev().collect();
        let result = execute_script_with_inputs_strict(
            u4_lehmer_to_value(FACTORADIC_U4_MAX_WIDTH),
            witness_from_digits(&max),
        );
        assert!(result.success, "maximum codeword rejected: {result}");
        let mut bytes = [0u8; 8];
        let len = bitcoin::script::write_scriptint(&mut bytes, max_12);
        assert_eq!(result.final_stack.get(0), bytes[..len].to_vec());
        assert!(result.stats.max_nb_stack_items <= 1_000);
    }

    #[test]
    fn host_helpers_match_enumerated_ranks() {
        for width in 1..=8usize {
            let mut perm: Vec<u32> = (0..width as u32).collect();
            let mut rank = 0u64;
            loop {
                assert_eq!(
                    lexicographic_rank(&perm),
                    rank,
                    "width {width} permutation {perm:?} misranked"
                );
                rank += 1;
                if !next_permutation(&mut perm) {
                    break;
                }
            }
            assert_eq!(rank, factorial(width as u32));
        }
    }
}
