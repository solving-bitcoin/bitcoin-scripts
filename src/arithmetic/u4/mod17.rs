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
}
