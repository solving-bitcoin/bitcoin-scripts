//! Table-free base-16 integer residue modulo 17 over canonical u4 limbs.

use super::stack::verify_canonical_nibble;
use crate::support::script::*;

/// Standalone bound; combined preserved state must satisfy `n + 3 + p <= 1000`.
pub const U4_MOD17_MAX_BATCH: u32 = 997;

fn normalize_negative() -> Script {
    script! {
        OP_DUP 0 OP_LESSTHAN
        OP_IF 17 OP_ADD OP_ENDIF
    }
}

/// Consume a nonempty big-endian canonical nibble vector and return its
/// represented unsigned integer modulo 17, as a canonical ScriptNum in 0..=16.
///
/// Before: `preserved | nibble[0] ... nibble[n-1]` (last nibble on top).
/// After: `preserved | residue`. The altstack is never touched. Every input
/// is checked for numeric range and raw minimal encoding before arithmetic.
/// This is a fragment; callers supply an observable terminal predicate.
///
/// Since 16 = -1 modulo 17, folding from the top uses `r = x - r`.
/// Each difference lies in -16..=15 and needs at most one addition of 17.
/// For even lengths the final sign is reversed to recover big-endian order.
pub fn u4_nibbles_to_mod17(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "modulo-17 batch must not be empty");
    assert!(
        nibble_count <= U4_MOD17_MAX_BATCH,
        "modulo-17 batch exceeds stack limit"
    );
    script! {
        { verify_canonical_nibble() }
        for _ in 1..nibble_count {
            OP_SWAP
            { verify_canonical_nibble() }
            OP_SWAP OP_SUB
            { normalize_negative() }
        }
        if nibble_count % 2 == 0 {
            OP_NEGATE
            { normalize_negative() }
        }
    }
}

/// Delayed-reduction schedule for the same residue as [`u4_nibbles_to_mod17`].
///
/// The alternating sum is kept exact (no per-step normalization), made
/// nonnegative with one public offset, and reduced by a ladder of conditional
/// subtractions of `17 * 2^k`. Same stack contract and input checks.
pub fn u4_nibbles_to_mod17_delayed(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "modulo-17 batch must not be empty");
    assert!(
        nibble_count <= U4_MOD17_MAX_BATCH,
        "modulo-17 batch exceeds stack limit"
    );
    // |alternating sum| <= 15 * ceil(n / 2); shift into 0..=2 * offset.
    let bound = 15 * i64::from(nibble_count.div_ceil(2));
    let offset = 17 * ((bound + 16) / 17);
    let top = 63 - ((2 * offset / 17) as u64).leading_zeros();
    script! {
        { verify_canonical_nibble() }
        for _ in 1..nibble_count {
            OP_SWAP
            { verify_canonical_nibble() }
            OP_SWAP OP_SUB
        }
        if nibble_count % 2 == 0 {
            OP_NEGATE
        }
        { offset } OP_ADD
        for level in (0..=top).rev() {
            OP_DUP { 17i64 << level } OP_GREATERTHANOREQUAL
            OP_IF { 17i64 << level } OP_SUB OP_ENDIF
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::execute_script_with_inputs_strict;

    fn check(values: &[u8]) {
        // Independent, conventional left-to-right base-16 integer evaluation.
        let expected = values
            .iter()
            .fold(0u32, |r, &x| (16 * r + u32::from(x)) % 17);
        let result = execute_script_with_inputs_strict(
            script! { { u4_nibbles_to_mod17(values.len() as u32) } { expected } OP_EQUAL },
            values
                .iter()
                .map(|&x| if x == 0 { vec![] } else { vec![x] })
                .collect(),
        );
        assert!(result.success, "values={values:?}: {result}");
        assert_eq!(result.final_stack.len(), 1);
    }

    #[test]
    fn exhaustive_one_two_and_three_digit_integers() {
        for x in 0..16 {
            check(&[x]);
            for y in 0..16 {
                check(&[x, y]);
                for z in 0..16 {
                    check(&[x, y, z]);
                }
            }
        }
    }

    #[test]
    fn deterministic_long_vectors_and_generation_bounds() {
        for n in [4, 5, 16, 31, 32, 33, 128, U4_MOD17_MAX_BATCH] {
            check(
                &(0..n)
                    .map(|i| ((i * 7 + i / 3) % 16) as u8)
                    .collect::<Vec<_>>(),
            );
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_mod17(0)).is_err());
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_mod17(U4_MOD17_MAX_BATCH + 1)).is_err());
    }

    #[test]
    fn delayed_schedule_matches_the_running_schedule_and_base_16_evaluation() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut cases: Vec<Vec<u8>> = vec![vec![15; 64], vec![0; 64], vec![15, 0, 15, 0, 15]];
        for len in [1usize, 2, 3, 4, 5, 8, 16, 31, 32, 33, 64, 127, 128] {
            for _ in 0..8 {
                cases.push(
                    (0..len)
                        .map(|_| {
                            state ^= state << 13;
                            state ^= state >> 7;
                            state ^= state << 17;
                            (state % 16) as u8
                        })
                        .collect(),
                );
            }
        }
        for values in cases {
            let expected = values
                .iter()
                .fold(0u32, |r, &x| (16 * r + u32::from(x)) % 17);
            let witness: Vec<Vec<u8>> = values
                .iter()
                .map(|&x| if x == 0 { vec![] } else { vec![x] })
                .collect();
            let result = execute_script_with_inputs_strict(
                script! { { u4_nibbles_to_mod17_delayed(values.len() as u32) } { expected } OP_EQUAL },
                witness,
            );
            assert!(result.success, "values={values:?}: {result}");
        }
        // Exhaustive for one to three digits.
        for x in 0..16u8 {
            for y in 0..16u8 {
                for z in 0..16u8 {
                    for values in [vec![x], vec![x, y], vec![x, y, z]] {
                        let expected = values
                            .iter()
                            .fold(0u32, |r, &d| (16 * r + u32::from(d)) % 17);
                        let witness: Vec<Vec<u8>> = values
                            .iter()
                            .map(|&d| if d == 0 { vec![] } else { vec![d] })
                            .collect();
                        let result = execute_script_with_inputs_strict(
                            script! { { u4_nibbles_to_mod17_delayed(values.len() as u32) } { expected } OP_EQUAL },
                            witness,
                        );
                        assert!(result.success, "values={values:?}: {result}");
                    }
                }
            }
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_mod17_delayed(0)).is_err());
        assert!(
            std::panic::catch_unwind(|| u4_nibbles_to_mod17_delayed(U4_MOD17_MAX_BATCH + 1))
                .is_err()
        );
    }
}
