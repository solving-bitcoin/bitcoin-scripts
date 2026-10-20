//! Exact fixed-composition check of a checked u4 vector.
//!
//! "Composition" is the multiset of symbols. The check decides whether a vector
//! contains each nibble value exactly a public number of times, which includes
//! "is a permutation of 0..=15" and any constant-sum or constant-composition
//! shape. Each nibble adds `B^lane` to one of a few accumulator words, where
//! `B = n + 1`; no lane can carry because a count never exceeds `n`, so the
//! words equal the public targets exactly when every count matches.

use super::stack::u4_drop;
use crate::support::script::*;

/// Largest vector length: the combined peak is `n + 21`.
pub const U4_COMPOSITION_MAX_LEN: u32 = 979;

const MAX_SCRIPTNUM: u64 = (1 << 31) - 1;

/// Lanes per accumulator word for vectors of length `len`.
pub fn u4_composition_lanes_per_word(len: u32) -> u32 {
    assert!(
        (1..=U4_COMPOSITION_MAX_LEN).contains(&len),
        "length out of range"
    );
    let base = u64::from(len) + 1;
    let (mut lanes, mut power) = (0u32, 1u64);
    // Every word sum is below base^lanes, which must fit a four-byte ScriptNum.
    while power * base <= MAX_SCRIPTNUM + 1 {
        power *= base;
        lanes += 1;
    }
    lanes
}

/// Number of accumulator words for vectors of length `len`.
pub fn u4_composition_words(len: u32) -> u32 {
    16u32.div_ceil(u4_composition_lanes_per_word(len))
}

/// Decide whether the vector contains nibble `s` exactly `counts[s]` times for
/// every `s`.
///
/// Before: `preserved | a[0] ... a[n-1]`, last item on top, with
/// `n = sum(counts)`. After: `preserved | ok` in `{0, 1}`. Every nibble is
/// range-checked; an out-of-range value aborts. No hints.
pub fn u4_nibbles_have_composition(counts: &[u32; 16]) -> Script {
    let len: u32 = counts.iter().sum();
    let lanes = u4_composition_lanes_per_word(len);
    let words = u4_composition_words(len);
    let base = i64::from(len) + 1;
    script! {
        for word in 0..words {
            for symbol in (0..16u32).rev() {
                { table_entry(symbol, word, lanes, base) }
            }
            0
            for index in 0..len {
                // Stack top: acc, T[0..15], inputs; input `index` from the top.
                { 17 + index } OP_PICK
                if word == 0 {
                    OP_DUP 0 16 OP_WITHIN OP_VERIFY
                }
                OP_DUP 2 OP_ADD OP_PICK
                OP_NIP
                OP_ADD
            }
            { target_word(counts, word, lanes, base) } OP_NUMEQUAL
            if word > 0 { OP_FROMALTSTACK OP_BOOLAND }
            OP_TOALTSTACK
            for _ in 0..8 { OP_2DROP }
        }
        { u4_drop(len) }
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

fn target_word(counts: &[u32; 16], word: u32, lanes: u32, base: i64) -> i64 {
    (0..lanes)
        .map(|lane| {
            let symbol = word * lanes + lane;
            if symbol < 16 {
                i64::from(counts[symbol as usize]) * base.pow(lane)
            } else {
                0
            }
        })
        .sum()
}

/// Pairwise comparator for the permutation case: true iff all `n` nibbles are distinct.
///
/// Before: `preserved | a[0] ... a[n-1]`. After: `preserved | distinct`. For
/// `n = 16` the vector is a permutation of `0..=15` exactly when it is distinct.
pub fn u4_nibbles_pairwise_distinct(len: u32) -> Script {
    assert!((1..=128).contains(&len), "length out of range");
    script! {
        for index in 0..len {
            { len - 1 - index } OP_PICK
            0 16 OP_WITHIN OP_VERIFY
        }
        0
        for left in 0..len {
            for right in left + 1..len {
                { len - left } OP_PICK
                { len - right + 1 } OP_PICK
                OP_EQUAL
                OP_ADD
            }
        }
        OP_NOT
        OP_TOALTSTACK
        { u4_drop(len) }
        OP_FROMALTSTACK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};
    use bitcoin_scriptexec::ExecError;

    fn item(value: u8) -> Vec<u8> {
        if value == 0 {
            Vec::new()
        } else {
            vec![value]
        }
    }

    fn counts_of(values: &[u8]) -> [u32; 16] {
        let mut counts = [0u32; 16];
        for &v in values {
            counts[v as usize] += 1;
        }
        counts
    }

    /// Run a composition check; the answer is the final truth value.
    fn run(compiled: &[u8], values: &[u8]) -> bool {
        let witness = values.iter().map(|&v| item(v)).collect();
        let result = execute_raw_script_with_inputs_strict(compiled.to_vec(), witness);
        assert!(result.error.is_none(), "values {values:?}: {result}");
        result.success
    }

    fn compile(counts: &[u32; 16]) -> Vec<u8> {
        script! { { u4_nibbles_have_composition(counts) } }
            .compile_with_policy()
            .to_bytes()
    }

    #[test]
    fn lane_geometry_is_exact() {
        for (len, lanes, words) in [
            (1, 31, 1),
            (4, 13, 2),
            (8, 9, 2),
            (16, 7, 3),
            (32, 6, 3),
            (979, 3, 6),
        ] {
            assert_eq!(u4_composition_lanes_per_word(len), lanes, "len {len}");
            assert_eq!(u4_composition_words(len), words, "len {len}");
            let base = u128::from(len) + 1;
            assert!(base.pow(lanes) <= 1 << 31);
            assert!(base.pow(lanes + 1) > 1 << 31);
        }
    }

    #[test]
    fn accepts_exactly_the_vectors_with_the_target_composition() {
        // Every arrangement of a 5-symbol composition, plus every wrong composition of length 5
        // over a 3-symbol alphabet, against a counting model.
        let target = counts_of(&[0, 0, 7, 7, 15]);
        let compiled = compile(&target);
        for code in 0..4u32.pow(5) {
            let values: Vec<u8> = (0..5)
                .map(|i| [0u8, 7, 15, 3][((code >> (2 * i)) & 3) as usize])
                .collect();
            assert_eq!(
                run(&compiled, &values),
                counts_of(&values) == target,
                "{values:?}"
            );
        }
    }

    #[test]
    fn decides_permutations_of_all_sixteen_nibbles() {
        let compiled = compile(&[1; 16]);
        let identity: Vec<u8> = (0..16).collect();
        assert!(run(&compiled, &identity));
        let mut reversed = identity.clone();
        reversed.reverse();
        assert!(run(&compiled, &reversed));
        // Near misses: one duplicate and one missing symbol, at every position.
        for position in 0..16 {
            let mut broken = identity.clone();
            broken[position] = (broken[position] + 1) % 16;
            assert!(!run(&compiled, &broken), "position {position}");
        }
        // Boundary multiplicity: every symbol equal.
        assert!(!run(&compiled, &[0; 16]));
        assert!(!run(&compiled, &[15; 16]));
        // A deterministic shuffle is accepted.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..30 {
            let mut shuffled = identity.clone();
            for i in (1..16).rev() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                shuffled.swap(i, (state % (i as u64 + 1)) as usize);
            }
            assert!(run(&compiled, &shuffled), "{shuffled:?}");
        }
    }

    #[test]
    fn rejects_lane_aliasing_attempts() {
        // Adjacent-symbol exchanges and full concentration must not collide.
        let target = counts_of(&[0, 1, 2, 3]);
        let compiled = compile(&target);
        assert!(run(&compiled, &[3, 2, 1, 0]));
        assert!(!run(&compiled, &[0, 0, 2, 2]));
        assert!(!run(&compiled, &[1, 1, 1, 1]));
        assert!(!run(&compiled, &[0, 1, 2, 4]));
        let wide = counts_of(&[8; 24]);
        let compiled = compile(&wide);
        assert!(run(&compiled, &[8; 24]));
        assert!(!run(&compiled, &{
            let mut v = [8u8; 24];
            v[23] = 9;
            v
        }));
    }

    #[test]
    fn rejects_out_of_range_nibbles_at_every_position() {
        let compiled = compile(&counts_of(&[1, 2, 3, 4]));
        for bad in [-1i64, 16, 255] {
            for position in 0..4 {
                let result = execute_script(script! {
                    for index in 0..4 { { if index == position { bad } else { 1 } } }
                    { u4_nibbles_have_composition(&counts_of(&[1, 2, 3, 4])) }
                    OP_DROP OP_TRUE
                });
                assert_eq!(
                    result.error,
                    Some(ExecError::Verify),
                    "bad {bad} at {position}"
                );
            }
        }
        let _ = compiled;
    }

    #[test]
    fn preserves_surrounding_state() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            3 1 3
            { u4_nibbles_have_composition(&counts_of(&[1, 3, 3])) }
            1 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "{result}");
    }

    #[test]
    fn recorded_sizes_are_current() {
        let balanced = |n: u32| {
            let mut counts = [0u32; 16];
            for i in 0..n {
                counts[(i % 16) as usize] += 1;
            }
            counts
        };
        let mut eight_sevens = [0u32; 16];
        eight_sevens[7] = 8;
        let measure = |script: Script| script.compile_with_policy().len();
        for (counts, bytes) in [
            (eight_sevens, 279usize),
            (balanced(16), 649),
            (balanced(32), 1_172),
            (balanced(64), 2_817),
        ] {
            assert_eq!(
                measure(u4_nibbles_have_composition(&counts)),
                bytes,
                "{counts:?}"
            );
        }
        assert_eq!(measure(u4_nibbles_pairwise_distinct(16)), 823);
    }

    #[test]
    fn rejects_generation_bounds() {
        assert!(std::panic::catch_unwind(|| u4_nibbles_have_composition(&[0; 16])).is_err());
        let mut too_long = [0u32; 16];
        too_long[0] = U4_COMPOSITION_MAX_LEN + 1;
        assert!(std::panic::catch_unwind(move || u4_nibbles_have_composition(&too_long)).is_err());
    }

    #[test]
    fn pairwise_comparator_agrees_on_permutations() {
        let compiled = script! { { u4_nibbles_pairwise_distinct(16) } }
            .compile_with_policy()
            .to_bytes();
        let identity: Vec<u8> = (0..16).collect();
        assert!(run(&compiled, &identity));
        for position in 0..16 {
            let mut broken = identity.clone();
            broken[position] = (broken[position] + 1) % 16;
            assert!(!run(&compiled, &broken));
        }
    }

    #[test]
    fn stack_frontier_is_exact_at_the_maximum_length() {
        use crate::support::script::MAX_OPTIMIZER_INPUT_BYTES;
        let mut counts = [0u32; 16];
        counts[7] = U4_COMPOSITION_MAX_LEN;
        let run_at = |extra: usize| {
            let compiled = script! {
                { u4_nibbles_have_composition(&counts) }
                OP_VERIFY
                for _ in 0..extra { OP_DROP }
                OP_TRUE
                for _ in 0..=MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
            }
            .compile_with_policy()
            .to_bytes();
            let mut witness = vec![vec![9u8]; extra];
            witness.extend(vec![vec![7u8]; U4_COMPOSITION_MAX_LEN as usize]);
            execute_raw_script_with_inputs_strict(compiled, witness)
        };
        let base = run_at(0);
        assert!(base.success, "{base}");
        let spare = 1_000 - base.stats.max_nb_stack_items;
        assert!(run_at(spare).success);
        assert_eq!(run_at(spare + 1).error, Some(ExecError::StackSize));
    }
}
