//! Strict-majority element of a checked u4 vector.
//!
//! The hint-free form runs a Boyer-Moore vote followed by a verification
//! count. The hinted form only accepts a witness-claimed majority and can
//! therefore never report that none exists.

use super::stack::u4_drop;
use crate::support::script::*;

/// Largest vector length: the combined peak is `n + 4`.
pub const U4_MAJORITY_MAX_LEN: u32 = 996;

fn range_checks(len: u32) -> Script {
    script! {
        for index in 0..len {
            { len - 1 - index } OP_PICK
            0 16 OP_WITHIN OP_VERIFY
        }
    }
}

/// Decide whether one nibble occurs in more than half of the positions.
///
/// Before: `preserved | a[0] ... a[n-1]`, last item on top. After:
/// `preserved | m`, where `m` is the strict-majority nibble in `0..=15`, or `-1`
/// when none exists (including exact ties). Every nibble is range-checked; no
/// hints are used.
pub fn u4_nibbles_majority(len: u32) -> Script {
    assert!(
        (1..=U4_MAJORITY_MAX_LEN).contains(&len),
        "length out of range"
    );
    script! {
        { range_checks(len) }
        // Vote state: candidate below counter.
        0 0
        for index in 0..len {
            // The first unprocessed element is the deepest input.
            { len - index + 1 } OP_PICK
            OP_OVER OP_0NOTEQUAL
            OP_IF
                2 OP_PICK OP_NUMEQUAL
                OP_DUP OP_ADD 1 OP_SUB OP_ADD
            OP_ELSE
                OP_NIP OP_NIP 1
            OP_ENDIF
        }
        // Verify: count occurrences of the candidate.
        OP_DROP
        0
        for index in 0..len {
            { len - index + 1 } OP_PICK
            2 OP_PICK OP_NUMEQUAL
            OP_ADD
        }
        // Stack top: count, candidate. Strict majority iff 2 * count > n.
        OP_DUP OP_ADD { len } OP_GREATERTHAN
        OP_IF
        OP_ELSE
            OP_DROP -1
        OP_ENDIF
        OP_TOALTSTACK
        { u4_drop(len) }
        OP_FROMALTSTACK
    }
}

/// Verify that a witness-claimed nibble is a strict majority.
///
/// Before: `preserved | a[0] ... a[n-1] | claim`. After: `preserved | claim`,
/// or the script aborts when the claim is out of range or not a strict
/// majority. A vector without a strict majority can only be rejected, never
/// reported, because no claim satisfies the check.
pub fn u4_nibbles_majority_hinted(len: u32) -> Script {
    assert!(
        (1..=U4_MAJORITY_MAX_LEN).contains(&len),
        "length out of range"
    );
    script! {
        OP_DUP 0 16 OP_WITHIN OP_VERIFY
        { range_checks_under_claim(len) }
        0
        for index in 0..len {
            { len - index + 1 } OP_PICK
            2 OP_PICK OP_NUMEQUAL
            OP_ADD
        }
        // Doubling consumes the count, leaving the claim on top.
        OP_DUP OP_ADD { len } OP_GREATERTHAN OP_VERIFY
        OP_TOALTSTACK
        { u4_drop(len) }
        OP_FROMALTSTACK
    }
}

fn range_checks_under_claim(len: u32) -> Script {
    script! {
        for index in 0..len {
            { len - index } OP_PICK
            0 16 OP_WITHIN OP_VERIFY
        }
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

    fn model(values: &[u8]) -> i64 {
        for candidate in 0..16u8 {
            if values.iter().filter(|&&v| v == candidate).count() * 2 > values.len() {
                return i64::from(candidate);
            }
        }
        -1
    }

    /// Compile once; the expected answer is the lowest witness item.
    fn compile(len: usize) -> Vec<u8> {
        script! {
            { u4_nibbles_majority(len as u32) }
            OP_EQUAL
        }
        .compile_with_policy()
        .to_bytes()
    }

    fn run(compiled: &[u8], values: &[u8]) -> bool {
        let mut witness = vec![num(model(values))];
        witness.extend(values.iter().map(|&v| num(i64::from(v))));
        let result = execute_raw_script_with_inputs_strict(compiled.to_vec(), witness);
        assert!(result.error.is_none(), "values {values:?}: {result}");
        result.success
    }

    #[test]
    fn matches_the_model_exhaustively_on_small_alphabets() {
        for len in 1..=7usize {
            let compiled = compile(len);
            for code in 0..3u32.pow(len as u32) {
                let values: Vec<u8> = (0..len)
                    .map(|i| ((code / 3u32.pow(i as u32)) % 3) as u8 * 5)
                    .collect();
                assert!(run(&compiled, &values), "values {values:?}");
            }
        }
    }

    #[test]
    fn matches_the_model_on_ties_boundaries_and_boyer_moore_adversaries() {
        let compiled4 = compile(4);
        assert!(run(&compiled4, &[1, 1, 2, 2])); // tie: none
        assert!(run(&compiled4, &[3, 3, 3, 9]));
        let compiled5 = compile(5);
        // The candidate flips late and the true majority is only just present.
        assert!(run(&compiled5, &[1, 2, 3, 3, 3]));
        assert!(run(&compiled5, &[3, 3, 1, 2, 3]));
        assert!(run(&compiled5, &[3, 1, 3, 2, 3]));
        // The Boyer-Moore survivor is a minority symbol, so verification must reject it.
        assert!(run(&compiled5, &[1, 1, 2, 2, 3]));
        assert!(run(&compile(1), &[0]));
        assert!(run(&compile(1), &[15]));
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for len in [6usize, 9, 16, 33] {
            let compiled = compile(len);
            for _ in 0..40 {
                // Bias toward a small alphabet so majorities actually occur.
                let values: Vec<u8> = (0..len)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        if state % 3 == 0 {
                            (state >> 8) as u8 % 16
                        } else {
                            7
                        }
                    })
                    .collect();
                assert!(run(&compiled, &values), "values {values:?}");
            }
        }
    }

    #[test]
    fn rejects_out_of_range_nibbles_at_every_position() {
        for bad in [-1i64, 16, 255] {
            for position in 0..5 {
                let result = execute_script(script! {
                    for index in 0..5 { { if index == position { bad } else { 3 } } }
                    { u4_nibbles_majority(5) }
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
        // (len, zero-hint bytes, hinted bytes)
        for (len, zero, hinted) in [
            (1, 41, 23),
            (2, 70, 36),
            (4, 130, 62),
            (8, 248, 112),
            (16, 486, 213),
            (32, 1_006, 446),
            (64, 2_046, 910),
        ] {
            let measure = |script: Script| script.compile_with_policy().len();
            assert_eq!(measure(u4_nibbles_majority(len)), zero, "zero {len}");
            assert_eq!(
                measure(u4_nibbles_majority_hinted(len)),
                hinted,
                "hinted {len}"
            );
        }
    }

    #[test]
    fn preserves_surrounding_state() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            4 4 9 4 2
            { u4_nibbles_majority(5) }
            4 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "{result}");
    }

    fn run_hinted(values: &[u8], claim: i64) -> Option<bool> {
        let compiled = script! {
            { u4_nibbles_majority_hinted(values.len() as u32) }
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
    fn hinted_form_accepts_only_true_strict_majorities() {
        for len in 1..=6usize {
            for code in 0..3u32.pow(len as u32) {
                let values: Vec<u8> = (0..len)
                    .map(|i| ((code / 3u32.pow(i as u32)) % 3) as u8 * 5)
                    .collect();
                for claim in [0i64, 5, 10, 7] {
                    let is_majority = model(&values) == claim;
                    assert_eq!(
                        run_hinted(&values, claim) == Some(true),
                        is_majority,
                        "values {values:?} claim {claim}"
                    );
                }
            }
        }
        // Out-of-range claims abort even when they equal no element.
        assert_eq!(run_hinted(&[1, 1, 1], 16), None);
        assert_eq!(run_hinted(&[1, 1, 1], -1), None);
        // No claim can report the absence of a majority.
        for claim in 0..16 {
            assert_ne!(run_hinted(&[1, 1, 2, 2], claim), Some(true));
        }
    }

    #[test]
    fn rejects_generation_bounds_and_hits_the_stack_frontier() {
        use crate::support::script::MAX_OPTIMIZER_INPUT_BYTES;
        assert!(std::panic::catch_unwind(|| u4_nibbles_majority(0)).is_err());
        assert!(std::panic::catch_unwind(|| u4_nibbles_majority(U4_MAJORITY_MAX_LEN + 1)).is_err());
        for (name, make) in [
            ("zero-hint", u4_nibbles_majority as fn(u32) -> Script),
            ("hinted", u4_nibbles_majority_hinted),
        ] {
            let run = |extra: usize| {
                let compiled = script! {
                    { make(U4_MAJORITY_MAX_LEN) }
                    OP_DROP
                    for _ in 0..extra { OP_DROP }
                    OP_TRUE
                    for _ in 0..=MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
                }
                .compile_with_policy()
                .to_bytes();
                let mut witness = vec![vec![9u8]; extra];
                witness.extend(vec![vec![7u8]; U4_MAJORITY_MAX_LEN as usize]);
                if name == "hinted" {
                    witness.push(vec![7u8]);
                }
                execute_raw_script_with_inputs_strict(compiled, witness)
            };
            let base = run(0);
            assert!(base.success, "{name}: {base}");
            let spare = 1_000 - base.stats.max_nb_stack_items;
            assert!(run(spare).success, "{name}");
            let rejected = run(spare + 1);
            assert_eq!(
                rejected.error,
                Some(ExecError::StackSize),
                "{name}: {rejected}"
            );
        }
    }
}
