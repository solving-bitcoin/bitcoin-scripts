//! Hamming weight for a stack of canonical four-bit limbs.
//!
//! The lookup table is shared across the whole batch. Each nibble is checked
//! before it is used as an `OP_PICK` depth, and the count is accumulated on the
//! altstack so the table stays below the next input.

use crate::support::script::*;

pub const LOOKUP_TABLE_ITEMS: u32 = 16;

/// Count the set bits in `nibble_count` canonical nibbles.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`, with `nibble[n-1]`
/// on top. After: `preserved | popcount`, where every input and temporary
/// table item has been consumed. The result is at most `4 * nibble_count`.
pub fn popcount(nibble_count: u32) -> Script {
    assert!(nibble_count > 0);
    assert!(nibble_count + LOOKUP_TABLE_ITEMS + 2 <= 1_000);

    script! {
        // The top table entry is popcount(0), so depth nibble+1 selects it.
        for nibble in (0..16u32).rev() {
            { nibble.count_ones() }
        }

        for _ in 0..nibble_count {
            // Pull the next input over the table. The table remains directly
            // below it, independent of how many inputs are left.
            { LOOKUP_TABLE_ITEMS } OP_ROLL
            OP_DUP OP_0 OP_16 OP_WITHIN OP_VERIFY
            OP_DUP OP_1ADD OP_PICK
            OP_SWAP OP_DROP
            OP_TOALTSTACK
        }

        for _ in 0..LOOKUP_TABLE_ITEMS / 2 {
            OP_2DROP
        }

        OP_FROMALTSTACK
        for _ in 1..nibble_count {
            OP_FROMALTSTACK OP_ADD
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{
        execution::{
            execute_script, execute_script_with_inputs, execute_script_with_inputs_strict,
        },
        script::ScriptCompilation,
    };

    fn verify(inputs: &[i32]) {
        let expected = inputs.iter().map(|value| value.count_ones()).sum::<u32>();
        let result = execute_script(script! {
            for input in inputs {
                { *input }
            }
            { popcount(inputs.len() as u32) }
            { expected }
            OP_EQUAL
        });
        assert!(result.success, "popcount failed: {result}");
    }

    #[test]
    fn counts_exhaustive_two_nibble_inputs() {
        for high in 0..16 {
            for low in 0..16 {
                verify(&[high, low]);
            }
        }
    }

    #[test]
    fn handles_zero_and_all_ones_boundaries() {
        verify(&[0; 8]);
        verify(&[15; 8]);
    }

    #[test]
    fn rejects_hostile_out_of_range_nibbles() {
        for invalid in [-1, 16, 255] {
            let result = execute_script(script! {
                for _ in 0..7 { OP_0 }
                { invalid }
                { popcount(8) }
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
    }

    #[test]
    fn rejects_hostile_witness_values() {
        for invalid in [vec![0x10], vec![0x81], vec![0xff, 0x00]] {
            let mut witness = vec![vec![0]; 8];
            witness[7] = invalid.clone();
            let result = execute_script_with_inputs(script! { { popcount(8) } }, witness);
            assert!(
                !result.success,
                "accepted hostile witness value: {invalid:?}"
            );
        }
    }

    #[test]
    fn preserves_unrelated_stack_state() {
        let result = execute_script(script! {
            99
            1 2 4 8
            { popcount(4) }
            4 OP_EQUALVERIFY
            99 OP_EQUAL
        });
        assert!(result.success, "preserved state was corrupted: {result}");
    }

    #[test]
    fn beats_bit_decomposition_when_only_the_count_is_needed() {
        let baseline = script! {
            { crate::arithmetic::u4::bits::u4_nibbles_to_be_bits(8, true) }
            for _ in 0..31 { OP_ADD }
        };
        assert_eq!(baseline.clone().compile_with_policy().len(), 331);
        let result = execute_script_with_inputs_strict(
            script! {
                { baseline }
                32 OP_EQUALVERIFY
                OP_TRUE
            },
            vec![vec![15]; 8],
        );
        assert!(result.success, "baseline failed: {result}");
        assert_eq!(result.stats.max_nb_stack_items, 93);
    }
}
