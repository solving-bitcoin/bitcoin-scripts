//! Hint-checked symbol histogram of a checked u4 vector.
//!
//! The repository counts one fixed symbol per pass (`count`). A full 16-symbol
//! histogram by that route is 16 passes. Here the prover supplies all 16 counts;
//! the script packs the claimed counts and the vector's own symbol counts into
//! the same few base-`(n + 1)` lane words and requires them to be equal. Every
//! claimed count is range-checked to `0..=n`, so both sides have digits below the
//! base, nothing carries and equal words mean equal counts.

use crate::arithmetic::scriptint::mul_by_constant;
use crate::support::script::*;

/// Largest vector: the combined peak is `n + 38`.
pub const U4_HISTOGRAM_MAX_LEN: u32 = 962;

const MAX_SCRIPTNUM: u64 = (1 << 31) - 1;

/// Lanes per accumulator word for vectors of length `len`.
pub fn u4_histogram_lanes_per_word(len: u32) -> u32 {
    assert!(
        (1..=U4_HISTOGRAM_MAX_LEN).contains(&len),
        "length out of range"
    );
    let base = u64::from(len) + 1;
    let (mut lanes, mut power) = (0u32, 1u64);
    while power * base <= MAX_SCRIPTNUM + 1 {
        power *= base;
        lanes += 1;
    }
    lanes.min(16)
}

fn words(len: u32) -> u32 {
    16u32.div_ceil(u4_histogram_lanes_per_word(len))
}

fn table_entry(symbol: u32, word: u32, lanes: u32, base: i64) -> i64 {
    if symbol / lanes == word {
        base.pow(symbol - word * lanes)
    } else {
        0
    }
}

/// Verify claimed symbol counts and return them.
///
/// Before (witness, bottom to top): `x[0] ... x[n-1]`, then `c[0] ... c[15]` with
/// `c[15]` on top. After: `c[0] ... c[15]`, the vector consumed. The script
/// aborts unless every `x[i]` is in `0..=15`, every `c[s]` is in `0..=n` and
/// `c[s]` equals the number of elements equal to `s`. Hint items: sixteen.
pub fn u4_nibbles_histogram_hinted(len: u32) -> Script {
    let lanes = u4_histogram_lanes_per_word(len);
    let word_count = words(len);
    let base = i64::from(len) + 1;
    script! {
        // Every claimed count lies in 0..=n, so no lane can overflow its digit.
        for symbol in 0..16u32 {
            { symbol } OP_PICK 0 { len + 1 } OP_WITHIN OP_VERIFY
        }
        for word in 0..word_count {
            // Claimed target word from the hinted counts.
            { horner_target(word, lanes, base) }
            // Table T[0] on top, then the accumulator.
            for symbol in (0..16u32).rev() { { table_entry(symbol, word, lanes, base) } }
            0
            for index in 0..len {
                // Items above x[index]: later nibbles, 16 counts, target, 16 table, acc.
                { (len - 1 - index) + 16 + 1 + 16 + 1 } OP_PICK
                if word == 0 { OP_DUP 0 16 OP_WITHIN OP_VERIFY }
                OP_DUP 2 OP_ADD OP_PICK OP_NIP
                OP_ADD
            }
            // Stack top: S, then the 16 table items, then the claimed target.
            { 16 + 1 } OP_PICK OP_NUMEQUALVERIFY
            for _ in 0..8 { OP_2DROP }
            OP_DROP
        }
        // Keep the counts: park them, drop the vector, restore in order.
        for _ in 0..16 { OP_TOALTSTACK }
        { drop_items(len) }
        for _ in 0..16 { OP_FROMALTSTACK }
    }
}

/// Horner sum of the claimed counts of one word: `sum_lane c[word*lanes+lane] * base^lane`.
fn horner_target(word: u32, lanes: u32, base: i64) -> Script {
    // Counts are stored c[0] deepest .. c[15] on top, so c[s] is at depth 15 - s.
    let symbols: Vec<u32> = (0..lanes)
        .map(|lane| word * lanes + lane)
        .filter(|&s| s < 16)
        .collect();
    script! {
        // Highest symbol first.
        { 15 - *symbols.last().unwrap() } OP_PICK
        for &symbol in symbols.iter().rev().skip(1) {
            { mul_by_constant(base as u32) }
            // One extra item (the accumulator) sits above the counts.
            { 15 - symbol + 1 } OP_PICK OP_ADD
        }
    }
}

fn drop_items(count: u32) -> Script {
    script! {
        for _ in 0..count / 2 { OP_2DROP }
        if count % 2 == 1 { OP_DROP }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::u4::count::u4_nibbles_count;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};
    use bitcoin_scriptexec::ExecError;

    fn num(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let len = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..len].to_vec()
    }

    fn counts_of(values: &[u8]) -> [i64; 16] {
        let mut counts = [0i64; 16];
        for &v in values {
            counts[v as usize] += 1;
        }
        counts
    }

    /// Compile once per length: the expected counts are the lowest witness items.
    fn leaf(len: usize) -> Vec<u8> {
        script! {
            { u4_nibbles_histogram_hinted(len as u32) }
            // Compare the returned c[15] .. c[0] with the expected copies below them.
            for symbol in (0..16).rev() { { symbol + 1 } OP_ROLL OP_EQUALVERIFY }
            OP_TRUE
        }
        .compile_with_policy()
        .to_bytes()
    }

    fn run(
        compiled: &[u8],
        values: &[u8],
        claimed: [i64; 16],
        expected: [i64; 16],
    ) -> Option<bool> {
        let mut witness: Vec<Vec<u8>> = expected.iter().map(|&c| num(c)).collect();
        witness.extend(values.iter().map(|&v| num(i64::from(v))));
        witness.extend(claimed.iter().map(|&c| num(c)));
        let result = execute_raw_script_with_inputs_strict(compiled.to_vec(), witness);
        if result.error.is_some() {
            None
        } else {
            Some(result.success)
        }
    }

    #[test]
    fn honest_counts_are_returned_in_order() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for len in [1usize, 2, 3, 8, 16, 33, 64] {
            let compiled = leaf(len);
            for round in 0..8 {
                let modulus = if round % 2 == 0 { 16 } else { 3 };
                let values: Vec<u8> = (0..len).map(|_| (next() % modulus) as u8).collect();
                let counts = counts_of(&values);
                assert_eq!(
                    run(&compiled, &values, counts, counts),
                    Some(true),
                    "{values:?}"
                );
            }
        }
    }

    #[test]
    fn matches_the_fixed_symbol_count_primitive() {
        let values = [3u8, 15, 0, 3, 9, 15, 3];
        let counts = counts_of(&values);
        for symbol in [0u8, 3, 9, 15, 7] {
            let result = execute_script(script! {
                for v in values { { i64::from(v) } }
                { u4_nibbles_count(symbol, values.len() as u32) }
                { counts[symbol as usize] } OP_EQUAL
            });
            assert!(result.success, "symbol {symbol}: {result}");
        }
        assert_eq!(run(&leaf(7), &values, counts, counts), Some(true));
    }

    #[test]
    fn rejects_every_forged_count() {
        let values = [3u8, 15, 0, 3, 9, 15, 3];
        let counts = counts_of(&values);
        let compiled = leaf(values.len());
        for symbol in 0..16 {
            for delta in [-3i64, -2, -1, 1, 2, 3] {
                let mut forged = counts;
                forged[symbol] += delta;
                assert_ne!(
                    run(&compiled, &values, forged, forged),
                    Some(true),
                    "symbol {symbol} delta {delta}"
                );
            }
        }
        // A forged count vector with the same total is rejected too.
        let mut moved = counts;
        moved[3] -= 1;
        moved[4] += 1;
        assert_ne!(run(&compiled, &values, moved, moved), Some(true));
        // Carry-style aliases: shift weight between adjacent lanes.
        for s in 0..15 {
            let mut forged = counts;
            forged[s] += 1;
            forged[s + 1] -= 1;
            assert_ne!(
                run(&compiled, &values, forged, forged),
                Some(true),
                "lane {s}"
            );
        }
    }

    #[test]
    fn random_forgeries_never_verify() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let values = [1u8, 1, 14, 5, 5, 5];
        let counts = counts_of(&values);
        let compiled = leaf(values.len());
        for _ in 0..1500 {
            let mut forged = [0i64; 16];
            for c in forged.iter_mut() {
                *c = (next() % 9) as i64 - 1;
            }
            let accepted = run(&compiled, &values, forged, forged) == Some(true);
            assert_eq!(accepted, forged == counts, "{forged:?}");
        }
    }

    #[test]
    fn rejects_out_of_range_counts_and_nibbles() {
        let values = [2u8, 2, 7];
        let counts = counts_of(&values);
        let compiled = leaf(values.len());
        for bad in [-1i64, 4, 255] {
            let mut forged = counts;
            forged[11] = bad;
            assert_eq!(run(&compiled, &values, forged, forged), None, "count {bad}");
        }
        for bad in [-1i64, 16, 255] {
            for position in 0..values.len() {
                let mut witness: Vec<Vec<u8>> = counts.iter().map(|&c| num(c)).collect();
                witness.extend(values.iter().map(|&v| num(i64::from(v))));
                witness[16 + position] = num(bad);
                witness.extend(counts.iter().map(|&c| num(c)));
                let result = execute_raw_script_with_inputs_strict(compiled.clone(), witness);
                assert_eq!(
                    result.error,
                    Some(ExecError::Verify),
                    "nibble {bad} at {position}"
                );
            }
        }
    }

    #[test]
    fn recorded_sizes_are_current() {
        // (n, hinted bytes)
        for (n, hinted) in [
            (4u32, 432usize),
            (8, 559),
            (16, 956),
            (32, 1_503),
            (64, 3_158),
            (128, 5_988),
        ] {
            let size = script! { { u4_nibbles_histogram_hinted(n) } }
                .compile_with_policy()
                .len();
            assert_eq!(size, hinted, "n {n}");
        }
    }

    #[test]
    fn preserves_state_and_hits_the_stack_frontier() {
        use crate::support::script::MAX_OPTIMIZER_INPUT_BYTES;
        assert!(std::panic::catch_unwind(|| u4_nibbles_histogram_hinted(0)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_histogram_hinted(U4_HISTOGRAM_MAX_LEN + 1)
        })
        .is_err());
        let n = U4_HISTOGRAM_MAX_LEN as usize;
        let values = vec![7u8; n];
        let counts = counts_of(&values);
        let run_at = |extra: usize| {
            let compiled = script! {
                { u4_nibbles_histogram_hinted(n as u32) }
                for _ in 0..16 { OP_DROP }
                for _ in 0..extra { OP_DROP }
                OP_TRUE
                for _ in 0..=MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
            }
            .compile_with_policy()
            .to_bytes();
            let mut witness = vec![vec![9u8]; extra];
            witness.extend(values.iter().map(|&v| num(i64::from(v))));
            witness.extend(counts.iter().map(|&c| num(c)));
            execute_raw_script_with_inputs_strict(compiled, witness)
        };
        let base = run_at(0);
        assert!(base.success, "{base}");
        let spare = 1_000 - base.stats.max_nb_stack_items;
        assert!(run_at(spare).success);
        assert_eq!(run_at(spare + 1).error, Some(ExecError::StackSize));
    }
}
