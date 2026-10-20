//! Exact inversion count of a checked u4 vector.

use super::stack::u4_drop;
use crate::support::script::*;

/// Largest vector length. The bound is script size, not stack depth: the
/// fragment has `n(n-1)/2` comparisons.
pub const U4_INVERSIONS_MAX_LEN: u32 = 128;

/// Count pairs `i < j` with `a[i] > a[j]` in a checked u4 vector.
///
/// Before: `preserved | a[0] ... a[n-1]`, last item on top. After:
/// `preserved | count`, with `count` in `0..=n(n-1)/2`. Equal nibbles are not
/// inversions. Every nibble is range-checked; no hints are used.
pub fn u4_nibbles_inversions(len: u32) -> Script {
    assert!(
        (1..=U4_INVERSIONS_MAX_LEN).contains(&len),
        "length out of range"
    );
    script! {
        for index in 0..len {
            { len - 1 - index } OP_PICK
            0 16 OP_WITHIN OP_VERIFY
        }
        0
        for left in 0..len {
            for right in left + 1..len {
                // Stack top: acc, a[n-1] ... a[0]; a[k] sits at depth n - k.
                { len - left } OP_PICK
                { len - right + 1 } OP_PICK
                OP_GREATERTHAN
                OP_ADD
            }
        }
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

    fn model(values: &[u8]) -> i64 {
        let mut count = 0;
        for (i, a) in values.iter().enumerate() {
            for b in &values[i + 1..] {
                if a > b {
                    count += 1;
                }
            }
        }
        count
    }

    fn run(values: &[u8]) -> i64 {
        let expected = model(values);
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            for value in values { { *value as i64 } }
            { u4_nibbles_inversions(values.len() as u32) }
            { expected } OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "values {values:?}: {result}");
        expected
    }

    #[test]
    fn matches_model_exhaustively_for_short_vectors() {
        for len in 1..=4usize {
            let total = 16u32.pow(len as u32);
            for code in 0..total {
                let values: Vec<u8> = (0..len).map(|i| ((code >> (4 * i)) & 15) as u8).collect();
                run(&values);
            }
        }
    }

    #[test]
    fn matches_model_on_boundary_and_deterministic_vectors() {
        assert_eq!(
            run(&[15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]),
            120
        );
        assert_eq!(
            run(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
            0
        );
        assert_eq!(run(&[7; 16]), 0);
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for len in [5usize, 8, 16, 24, 32] {
            for _ in 0..8 {
                let values: Vec<u8> = (0..len)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        (state % 16) as u8
                    })
                    .collect();
                run(&values);
            }
        }
    }

    #[test]
    fn rejects_out_of_range_nibbles_at_every_position() {
        for bad in [-1i64, 16, 255] {
            for position in 0..4 {
                let result = execute_script(script! {
                    for index in 0..4 { { if index == position { bad } else { 3 } } }
                    { u4_nibbles_inversions(4) }
                    OP_DROP OP_TRUE
                });
                assert_eq!(
                    result.error,
                    Some(ExecError::Verify),
                    "bad {bad} at {position}"
                );
            }
        }
    }

    #[test]
    fn recorded_sizes_are_current() {
        for (len, bytes) in [
            (2, 19),
            (4, 60),
            (8, 218),
            (16, 822),
            (32, 3_709),
            (64, 15_629),
            (128, 64_178),
        ] {
            let compiled = script! { { u4_nibbles_inversions(len) } }.compile_with_policy();
            assert_eq!(compiled.len(), bytes, "len {len}");
        }
    }

    #[test]
    fn rejects_generation_bounds() {
        assert!(std::panic::catch_unwind(|| u4_nibbles_inversions(0)).is_err());
        assert!(
            std::panic::catch_unwind(|| u4_nibbles_inversions(U4_INVERSIONS_MAX_LEN + 1)).is_err()
        );
    }

    #[test]
    fn permutation_inversions_equal_the_lehmer_digit_sum() {
        use crate::arithmetic::factoradic::lehmer_of_permutation;
        // Every permutation of 0..5, via Heap's algorithm in lexicographic order.
        let mut perm: Vec<u32> = (0..5).collect();
        loop {
            let values: Vec<u8> = perm.iter().map(|&v| v as u8).collect();
            let digit_sum: u32 = lehmer_of_permutation(&perm).iter().sum();
            assert_eq!(run(&values), i64::from(digit_sum), "perm {perm:?}");
            // next lexicographic permutation
            let Some(i) = (0..perm.len() - 1).rev().find(|&i| perm[i] < perm[i + 1]) else {
                break;
            };
            let j = (i + 1..perm.len())
                .rev()
                .find(|&j| perm[j] > perm[i])
                .unwrap();
            perm.swap(i, j);
            perm[i + 1..].reverse();
        }
    }

    #[test]
    fn maximum_length_runs_under_the_strict_stack_limit() {
        let len = U4_INVERSIONS_MAX_LEN;
        let values: Vec<u8> = (0..len).map(|i| (15 - (i % 16)) as u8).collect();
        let expected = model(&values);
        let compiled = script! {
            { u4_nibbles_inversions(len) }
            { expected } OP_EQUALVERIFY
            OP_TRUE
        }
        .compile_with_policy()
        .to_bytes();
        let witness = values
            .iter()
            .map(|&v| if v == 0 { Vec::new() } else { vec![v] })
            .collect();
        let result = execute_raw_script_with_inputs_strict(compiled, witness);
        assert!(result.success, "{result}");
        assert_eq!(result.stats.max_nb_stack_items, len as usize + 3);
    }
}
