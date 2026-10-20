//! Exact multiset equality of two checked u4 vectors via packed histogram differences.
//!
//! Each nibble `x` contributes the generation-time constant `B^(x mod L)` to
//! word `x / L`, where `B = 2n + 1`. Vector `A` adds and vector `B` subtracts, so
//! every radix-`B` lane holds `count_A(x) - count_B(x)`, which lies in
//! `-n..=n` and therefore determines a unique signed digit. A word is zero iff
//! all of its lanes are zero.

use crate::support::script::*;

/// Largest vector length. The measured combined-stack peak is `2n + 21 +
/// preserved`; callers must keep it at or below 1,000 (`n = 489` leaves one
/// spare item).
pub const U4_MULTISET_EQUAL_MAX_LEN: u32 = 489;

const MAX_SCRIPTNUM: u64 = (1 << 31) - 1;

/// Lanes per accumulator word for vectors of length `len`.
pub fn u4_multiset_lanes_per_word(len: u32) -> u32 {
    assert!(
        (1..=U4_MULTISET_EQUAL_MAX_LEN).contains(&len),
        "length out of range"
    );
    let base = 2 * len as u64 + 1;
    // |accumulator| <= (base^lanes - 1) / 2 must fit in a four-byte ScriptNum.
    let mut lanes = 0u32;
    let mut power = 1u64;
    while power * base <= 2 * MAX_SCRIPTNUM + 1 {
        power *= base;
        lanes += 1;
    }
    lanes
}

/// Number of accumulator words (and table passes) for vectors of length `len`.
pub fn u4_multiset_words(len: u32) -> u32 {
    16u32.div_ceil(u4_multiset_lanes_per_word(len))
}

/// Compare the multisets of two equal-length u4 vectors.
///
/// Before: `preserved | a[0] .. a[len-1] | b[0] .. b[len-1]`, last item on top.
/// After: `preserved | equal`, where `equal` is `1` when the multisets are equal
/// and `0` otherwise. Every hostile nibble is range-checked; an out-of-range
/// value aborts the script. No hint items are used.
pub fn u4_nibbles_multiset_equal(len: u32) -> Script {
    let lanes = u4_multiset_lanes_per_word(len);
    let words = u4_multiset_words(len);
    let base = 2 * len as i64 + 1;
    let inputs = 2 * len;

    script! {
        for word in 0..words {
            // Table T[0..15] with T[0] nearest the top, then the accumulator.
            for symbol in (0..16u32).rev() {
                { table_entry(symbol, word, lanes, base) }
            }
            0
            for index in 0..inputs {
                // Stack top: acc, T[0..15], inputs; input `index` from the top.
                { 17 + index } OP_PICK
                if word == 0 {
                    OP_DUP 0 16 OP_WITHIN OP_VERIFY
                }
                OP_DUP 2 OP_ADD OP_PICK
                OP_NIP
                if index < len { OP_ADD } else { OP_SUB }
            }
            OP_NOT
            if word > 0 { OP_FROMALTSTACK OP_BOOLAND }
            OP_TOALTSTACK
            for _ in 0..8 { OP_2DROP }
        }
        for _ in 0..len { OP_2DROP }
        OP_FROMALTSTACK
    }
}

fn table_entry(symbol: u32, word: u32, lanes: u32, base: i64) -> i64 {
    if symbol / lanes == word {
        base.pow(symbol - word * lanes)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{
        execute_raw_script_with_inputs_strict, execute_script, execute_script_buf_with_options,
    };
    use crate::support::script::{script, ScriptCompilation};
    use bitcoin_scriptexec::{ExecError, Options};

    fn witness(a: &[u8], b: &[u8]) -> Vec<Vec<u8>> {
        a.iter()
            .chain(b)
            .map(|&n| if n == 0 { Vec::new() } else { vec![n] })
            .collect()
    }

    fn run(a: &[u8], b: &[u8]) -> bool {
        assert_eq!(a.len(), b.len());
        let compiled = script! {
            { u4_nibbles_multiset_equal(a.len() as u32) }
            OP_SWAP 99 OP_EQUALVERIFY
        }
        .compile_with_policy()
        .to_bytes();
        let mut inputs = vec![vec![99u8]]; // preserved sentinel
        inputs.extend(witness(a, b));
        let result = execute_raw_script_with_inputs_strict(compiled, inputs);
        assert!(result.error.is_none(), "unexpected failure: {result}");
        result.success
    }

    fn model(a: &[u8], b: &[u8]) -> bool {
        let (mut a, mut b) = (a.to_vec(), b.to_vec());
        a.sort();
        b.sort();
        a == b
    }

    /// Deterministic xorshift stream; no external RNG so vectors never change.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn lane_geometry_is_exact() {
        for (len, lanes, words) in [(1, 20, 1), (4, 10, 2), (8, 7, 3), (16, 6, 3), (489, 3, 6)] {
            assert_eq!(u4_multiset_lanes_per_word(len), lanes, "len {len}");
            assert_eq!(u4_multiset_words(len), words, "len {len}");
            let base = 2 * len as u128 + 1;
            assert!((base.pow(lanes) - 1) / 2 <= (1 << 31) - 1);
            assert!((base.pow(lanes + 1) - 1) / 2 > (1 << 31) - 1);
        }
    }

    #[test]
    fn recorded_sizes_are_current() {
        for (len, bytes) in [(4, 275), (8, 637), (16, 1_158), (64, 5_523)] {
            let compiled = script! { { u4_nibbles_multiset_equal(len) } }.compile_with_policy();
            assert_eq!(compiled.len(), bytes, "len {len}");
        }
    }

    #[test]
    fn matches_sorted_model_on_deterministic_vectors() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for len in [1usize, 2, 3, 8, 16] {
            for round in 0..24 {
                let a: Vec<u8> = (0..len).map(|_| (rng.next() % 16) as u8).collect();
                let mut b = a.clone();
                // Shuffle half of the rounds; mutate one nibble in the others.
                for i in (1..len).rev() {
                    b.swap(i, (rng.next() % (i as u64 + 1)) as usize);
                }
                if round % 2 == 1 {
                    let k = (rng.next() % len as u64) as usize;
                    b[k] = (b[k] + 1 + (rng.next() % 15) as u8) % 16;
                }
                assert_eq!(run(&a, &b), model(&a, &b), "a={a:?} b={b:?}");
            }
        }
    }

    #[test]
    fn rejects_lane_aliasing_attempts() {
        // Adjacent-symbol swaps and extreme concentration must not collide.
        assert!(!run(&[0, 0, 0, 0], &[1, 1, 1, 1]));
        assert!(!run(&[15, 15, 15, 15], &[0, 0, 0, 0]));
        assert!(!run(&[0, 1, 1, 1], &[0, 0, 0, 1]));
        assert!(!run(&[0, 0, 15, 15], &[1, 1, 14, 14]));
        assert!(!run(&[6, 6, 6, 6, 6, 6, 6, 6], &[7, 7, 7, 7, 7, 7, 7, 6]));
        assert!(run(&[15, 0, 7, 7], &[7, 15, 7, 0]));
        // Every single-symbol multiset against every other, at a word boundary length.
        for x in 0..16u8 {
            for y in 0..16u8 {
                assert_eq!(run(&[x; 8], &[y; 8]), x == y, "x={x} y={y}");
            }
        }
    }

    #[test]
    fn rejects_out_of_range_nibbles_in_either_vector() {
        for bad in [-1i64, 16, 255] {
            for position in 0..4 {
                let mut items: Vec<i64> = vec![1, 2, 3, 4, 4, 3, 2, 1];
                items[position * 2 % 8] = bad;
                let result = execute_script(script! {
                    for item in items { { item } }
                    { u4_nibbles_multiset_equal(4) }
                    OP_DROP OP_TRUE
                });
                assert_eq!(result.error, Some(ExecError::Verify), "bad {bad}: {result}");
            }
        }
        // Out-of-range value that would alias a different stack slot if unchecked.
        let result = execute_script(script! {
            0 0 0 0 0 0 0 16
            { u4_nibbles_multiset_equal(4) }
            OP_DROP OP_TRUE
        });
        assert_eq!(result.error, Some(ExecError::Verify));
    }

    #[test]
    fn rejects_generation_bounds() {
        assert!(std::panic::catch_unwind(|| u4_nibbles_multiset_equal(0)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_multiset_equal(U4_MULTISET_EQUAL_MAX_LEN + 1)
        })
        .is_err());
    }

    #[test]
    fn accepts_nonminimal_numeric_encodings() {
        let options = Options {
            require_minimal: false,
            enforce_stack_limit: true,
            ..Default::default()
        };
        let compiled = script! { { u4_nibbles_multiset_equal(2) } }.compile_with_policy();
        let result = execute_script_buf_with_options(
            compiled,
            vec![vec![1, 0], vec![0x80], vec![0], vec![1]],
            options,
        )
        .expect("nonminimal execution");
        assert!(result.success, "{result}");
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            1 2 3 3 1 2
            { u4_nibbles_multiset_equal(3) }
            1 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "{result}");
    }

    #[test]
    fn exact_stack_frontier_at_maximum_length() {
        let len = U4_MULTISET_EQUAL_MAX_LEN as usize;
        let a: Vec<u8> = (0..len).map(|i| (i % 16) as u8).collect();
        let mut b = a.clone();
        b.reverse();
        let exact = run_strict(&a, &b, 1);
        assert!(exact.success, "{exact}");
        assert_eq!(exact.stats.max_nb_stack_items, 1_000);
        let rejected = run_strict(&a, &b, 2);
        assert_eq!(rejected.error, Some(ExecError::StackSize), "{rejected}");
    }

    fn run_strict(a: &[u8], b: &[u8], extra: usize) -> crate::support::execution::ExecuteInfo {
        let len = a.len() as u32;
        let compiled = script! {
            { u4_nibbles_multiset_equal(len) }
            1 OP_EQUALVERIFY
            for _ in 0..extra { 9 OP_EQUALVERIFY }
            OP_TRUE
        }
        .compile_with_policy()
        .to_bytes();
        let mut inputs = vec![vec![9u8]; extra];
        inputs.extend(witness(a, b));
        execute_raw_script_with_inputs_strict(compiled, inputs)
    }
}
