//! k-th smallest nibble of a checked u4 vector.
//!
//! A witness-claimed value is verified with two linear counting passes, while
//! the hint-free selector ranks every element against every other element.

use super::stack::u4_drop;
use crate::support::script::*;

/// Largest hinted vector: the combined peak is `n + 4`.
pub const U4_KTH_HINTED_MAX_LEN: u32 = 996;

/// Largest hint-free vector; the script grows quadratically.
pub const U4_KTH_SELECT_MAX_LEN: u32 = 32;

fn assert_params(len: u32, k: u32, max: u32) {
    assert!((1..=max).contains(&len), "length out of range");
    assert!((1..=len).contains(&k), "rank out of range");
}

/// Verify that a witness-claimed nibble is the `k`-th smallest (1-based).
///
/// Before: `preserved | a[0] ... a[n-1] | claim`. After: `preserved | claim`, or
/// the script aborts. With `L = #{a < claim}` and `U = #{a <= claim}` the claim is
/// the `k`-th smallest exactly when `L < k <= U`, which also forces it to occur in
/// the vector. `k = (n + 1) / 2` gives the lower median. Every nibble and the
/// claim are range-checked.
pub fn u4_nibbles_kth_smallest_hinted(len: u32, k: u32) -> Script {
    assert_params(len, k, U4_KTH_HINTED_MAX_LEN);
    script! {
        OP_DUP 0 16 OP_WITHIN OP_VERIFY
        for index in 0..len {
            { len - index } OP_PICK
            0 16 OP_WITHIN OP_VERIFY
        }
        // L: elements strictly below the claim.
        0
        for index in 0..len {
            { len - index + 1 } OP_PICK
            2 OP_PICK OP_LESSTHAN
            OP_ADD
        }
        { k } OP_LESSTHAN OP_VERIFY
        // U: elements at or below the claim.
        0
        for index in 0..len {
            { len - index + 1 } OP_PICK
            2 OP_PICK OP_LESSTHANOREQUAL
            OP_ADD
        }
        { k } OP_GREATERTHANOREQUAL OP_VERIFY
        OP_TOALTSTACK
        { u4_drop(len) }
        OP_FROMALTSTACK
    }
}

/// Select the `k`-th smallest nibble (1-based) without hints.
///
/// Before: `preserved | a[0] ... a[n-1]`. After: `preserved | value` in `0..=15`.
/// Every element is ranked against all others; the elements whose rank interval
/// contains `k` all equal the answer. Quadratic in script size.
pub fn u4_nibbles_kth_smallest(len: u32, k: u32) -> Script {
    assert_params(len, k, U4_KTH_SELECT_MAX_LEN);
    script! {
        for index in 0..len {
            { len - 1 - index } OP_PICK
            0 16 OP_WITHIN OP_VERIFY
        }
        -1
        for index in 0..len {
            // Candidate c = a[index]; stack: res, c.
            { len - index } OP_PICK
            0
            for other in 0..len {
                { len - 1 - other + 3 } OP_PICK
                2 OP_PICK OP_LESSTHAN
                OP_ADD
            }
            OP_TOALTSTACK
            0
            for other in 0..len {
                { len - 1 - other + 3 } OP_PICK
                2 OP_PICK OP_LESSTHANOREQUAL
                OP_ADD
            }
            OP_FROMALTSTACK
            // Stack: res, c, U, L.
            { k } OP_LESSTHAN
            OP_SWAP { k } OP_GREATERTHANOREQUAL
            OP_BOOLAND
            OP_IF
            OP_ELSE
                OP_DROP -1
            OP_ENDIF
            OP_MAX
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

    fn num(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let len = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..len].to_vec()
    }

    fn model(values: &[u8], k: u32) -> i64 {
        let mut sorted = values.to_vec();
        sorted.sort();
        i64::from(sorted[k as usize - 1])
    }

    /// Hint-free selector, with the expected value as the lowest witness item.
    fn select_leaf(len: u32, k: u32) -> Vec<u8> {
        script! { { u4_nibbles_kth_smallest(len, k) } OP_EQUAL }
            .compile_with_policy()
            .to_bytes()
    }

    fn run_select(compiled: &[u8], values: &[u8], k: u32) -> bool {
        let mut witness = vec![num(model(values, k))];
        witness.extend(values.iter().map(|&v| num(i64::from(v))));
        let result = execute_raw_script_with_inputs_strict(compiled.to_vec(), witness);
        assert!(result.error.is_none(), "values {values:?} k {k}: {result}");
        result.success
    }

    /// Hinted verifier: `Some(passed)` or `None` on an abort.
    fn run_hinted(values: &[u8], k: u32, claim: i64) -> Option<bool> {
        let compiled = script! {
            { u4_nibbles_kth_smallest_hinted(values.len() as u32, k) }
            { claim } OP_EQUAL
        }
        .compile_with_policy()
        .to_bytes();
        let mut witness: Vec<Vec<u8>> = values.iter().map(|&v| num(i64::from(v))).collect();
        witness.push(num(claim));
        let result = execute_raw_script_with_inputs_strict(compiled, witness);
        if result.error.is_some() {
            None
        } else {
            Some(result.success)
        }
    }

    #[test]
    fn selector_matches_a_sorted_model_exhaustively_on_small_alphabets() {
        for len in 1..=5u32 {
            for k in 1..=len {
                let compiled = select_leaf(len, k);
                for code in 0..3u32.pow(len) {
                    let values: Vec<u8> = (0..len)
                        .map(|i| ((code / 3u32.pow(i)) % 3) as u8 * 7)
                        .collect();
                    assert!(run_select(&compiled, &values, k), "values {values:?} k {k}");
                }
            }
        }
    }

    #[test]
    fn selector_matches_the_model_on_deterministic_longer_vectors() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for len in [8u32, 9, 16] {
            for k in [1, (len + 1) / 2, len] {
                let compiled = select_leaf(len, k);
                for _ in 0..6 {
                    let values: Vec<u8> = (0..len)
                        .map(|_| {
                            state ^= state << 13;
                            state ^= state >> 7;
                            state ^= state << 17;
                            (state % 16) as u8
                        })
                        .collect();
                    assert!(run_select(&compiled, &values, k), "values {values:?} k {k}");
                }
            }
        }
    }

    #[test]
    fn hinted_verifier_accepts_exactly_the_kth_smallest() {
        for len in 1..=5u32 {
            for k in 1..=len {
                for code in 0..3u32.pow(len) {
                    let values: Vec<u8> = (0..len)
                        .map(|i| ((code / 3u32.pow(i)) % 3) as u8 * 7)
                        .collect();
                    for claim in 0..16i64 {
                        let correct = model(&values, k) == claim;
                        assert_eq!(
                            run_hinted(&values, k, claim) == Some(true),
                            correct,
                            "values {values:?} k {k} claim {claim}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn hinted_verifier_rejects_plurality_and_absent_claims_and_bad_ranges() {
        // Median of [1, 1, 5, 9, 9, 9, 9] (k = 4) is 9; the plurality 9 is right, but
        // the second-most-common 1 is not, and the absent 4 never satisfies L < k <= U.
        let values = [1u8, 1, 5, 9, 9, 9, 9];
        assert_eq!(run_hinted(&values, 4, 9), Some(true));
        assert_ne!(run_hinted(&values, 4, 1), Some(true));
        assert_ne!(run_hinted(&values, 4, 4), Some(true));
        assert_ne!(run_hinted(&values, 4, 5), Some(true));
        // Out-of-range claims abort, even when no element equals them.
        for claim in [-1i64, 16, 255] {
            assert_eq!(run_hinted(&values, 4, claim), None, "claim {claim}");
        }
    }

    #[test]
    fn recorded_sizes_are_current() {
        // (n, k = lower median, hinted bytes, hint-free bytes)
        for (n, hinted, select) in [
            (3u32, 69usize, 178usize),
            (4, 88, 286),
            (8, 162, 956),
            (16, 312, 3_512),
            (32, 656, 14_223),
        ] {
            let k = (n + 1) / 2;
            let measure = |script: Script| script.compile_with_policy().len();
            assert_eq!(
                measure(u4_nibbles_kth_smallest_hinted(n, k)),
                hinted,
                "hinted {n}"
            );
            assert_eq!(measure(u4_nibbles_kth_smallest(n, k)), select, "select {n}");
        }
    }

    #[test]
    fn rejects_out_of_range_nibbles_in_the_vector() {
        for bad in [-1i64, 16, 255] {
            for position in 0..4 {
                for make in [
                    u4_nibbles_kth_smallest(4, 2),
                    script! { 3 { u4_nibbles_kth_smallest_hinted(4, 2) } },
                ] {
                    let result = execute_script(script! {
                        for index in 0..4 { { if index == position { bad } else { 3 } } }
                        { make }
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
    }

    #[test]
    fn preserves_surrounding_state_and_checks_generation_bounds() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            9 2 7 4
            { u4_nibbles_kth_smallest(4, 2) }
            4 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "{result}");
        assert!(std::panic::catch_unwind(|| u4_nibbles_kth_smallest(4, 0)).is_err());
        assert!(std::panic::catch_unwind(|| u4_nibbles_kth_smallest(4, 5)).is_err());
        assert!(std::panic::catch_unwind(|| u4_nibbles_kth_smallest_hinted(0, 1)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_kth_smallest(U4_KTH_SELECT_MAX_LEN + 1, 1)
        })
        .is_err());
    }

    #[test]
    fn hinted_stack_frontier_is_exact() {
        use crate::support::script::MAX_OPTIMIZER_INPUT_BYTES;
        let len = U4_KTH_HINTED_MAX_LEN;
        let run_at = |extra: usize| {
            let compiled = script! {
                { u4_nibbles_kth_smallest_hinted(len, (len + 1) / 2) }
                OP_DROP
                for _ in 0..extra { OP_DROP }
                OP_TRUE
                for _ in 0..=MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
            }
            .compile_with_policy()
            .to_bytes();
            let mut witness = vec![vec![9u8]; extra];
            witness.extend(vec![vec![7u8]; len as usize]);
            witness.push(vec![7u8]);
            execute_raw_script_with_inputs_strict(compiled, witness)
        };
        let base = run_at(0);
        assert!(base.success, "{base}");
        let spare = 1_000 - base.stats.max_nb_stack_items;
        assert!(run_at(spare).success);
        assert_eq!(run_at(spare + 1).error, Some(ExecError::StackSize));
    }
}
