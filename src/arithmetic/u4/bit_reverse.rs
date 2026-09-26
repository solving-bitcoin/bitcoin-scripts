//! Checked reversal of the four bits in each u4 nibble.

use super::stack::{u4_drop, verify_canonical_nibble};
use crate::support::script::*;

pub const U4_BIT_REVERSE_TABLE_ITEMS: u32 = 16;

/// Largest batch whose strict combined stack peak is at most 1,000.
pub const U4_BIT_REVERSE_MAX_BATCH: u32 = 1_000 - U4_BIT_REVERSE_TABLE_ITEMS - 3;

fn reverse_nibble(nibble: u32) -> u32 {
    ((nibble & 1) << 3) | ((nibble & 2) << 1) | ((nibble & 4) >> 1) | ((nibble & 8) >> 3)
}

fn push_table() -> Script {
    script! {
        for nibble in (0..U4_BIT_REVERSE_TABLE_ITEMS).rev() {
            { reverse_nibble(nibble) }
        }
    }
}

/// Consume a contiguous nibble batch and replace each nibble with its
/// four-bit reversal. Inputs are range-checked before table indexing.
pub fn u4_nibbles_to_bit_reverse(nibble_count: u32) -> Script {
    u4_nibbles_to_bit_reverse_impl(nibble_count, false)
}

/// Consume minimally encoded nibbles and reverse their four bits.
pub fn u4_nibbles_to_bit_reverse_canonical(nibble_count: u32) -> Script {
    u4_nibbles_to_bit_reverse_impl(nibble_count, true)
}

fn u4_nibbles_to_bit_reverse_impl(nibble_count: u32, canonical: bool) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_BIT_REVERSE_MAX_BATCH,
        "bit-reversal batch exceeds Bitcoin Script's stack limit"
    );
    script! {
        { push_table() }
        for _ in 0..nibble_count {
            { U4_BIT_REVERSE_TABLE_ITEMS } OP_ROLL
            if canonical {
                { verify_canonical_nibble() }
            } else {
                OP_DUP OP_0 OP_16 OP_WITHIN OP_VERIFY
            }
            OP_PICK OP_TOALTSTACK
        }
        { u4_drop(U4_BIT_REVERSE_TABLE_ITEMS) }
        for _ in 0..nibble_count {
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::execute_script;

    fn verify(inputs: &[u32]) {
        let result = execute_script(script! {
            for input in inputs {
                { *input }
            }
            { u4_nibbles_to_bit_reverse(inputs.len() as u32) }
            for input in inputs.iter().rev() {
                { reverse_nibble(*input) } OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(result.success, "bit reversal failed: {result}");
    }

    #[test]
    fn reverses_every_nibble_and_preserves_batch_order() {
        verify(&(0..16).collect::<Vec<_>>());
        verify(&[0x1, 0xa, 0x5, 0xe]);
    }

    #[test]
    fn rejects_out_of_range_nibbles() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid }
                { u4_nibbles_to_bit_reverse(1) }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
    }

    #[test]
    fn rejects_invalid_batch_sizes() {
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_bit_reverse(0)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_to_bit_reverse(U4_BIT_REVERSE_MAX_BATCH + 1)
        })
        .is_err());
    }

    #[test]
    fn canonical_reversal_matches_reference_values() {
        let result = execute_script(script! {
            1 10 5 14
            { u4_nibbles_to_bit_reverse_canonical(4) }
            7 OP_EQUALVERIFY
            10 OP_EQUALVERIFY
            5 OP_EQUALVERIFY
            8 OP_EQUAL
        });
        assert!(result.success, "canonical bit reversal failed: {result}");
    }

    #[test]
    fn canonical_reversal_rejects_malformed_nibbles() {
        let script = script! {
            { u4_nibbles_to_bit_reverse_canonical(4) }
            for _ in 0..4 { OP_DROP }
            OP_TRUE
        };
        for position in 0..4 {
            for replacement in [vec![1, 0], vec![0, 1], vec![0x80]] {
                let mut witness = vec![vec![1]; 4];
                witness[position] = replacement;
                let result =
                    crate::support::execution::execute_script_with_inputs(script.clone(), witness);
                assert!(
                    !result.success,
                    "accepted malformed nibble at {position}: {result}"
                );
            }
        }
    }

    #[test]
    fn canonical_reversal_preserves_surrounding_stacks() {
        let result = crate::support::execution::execute_script_with_inputs_strict(
            script! {
                99 OP_TOALTSTACK
                { u4_nibbles_to_bit_reverse_canonical(2) }
                OP_DROP OP_DROP
                77 OP_EQUALVERIFY
                OP_FROMALTSTACK 99 OP_EQUALVERIFY
                OP_TRUE
            },
            vec![vec![77], vec![1], vec![2]],
        );
        assert!(result.success, "{result}");
    }
}
