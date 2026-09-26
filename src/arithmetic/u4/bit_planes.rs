//! Checked conversion from u4 nibbles to bit-plane order.
//!
//! The existing u4 bit converter emits four adjacent bits per nibble. This
//! adapter transposes that result so each plane contains one bit from every
//! input nibble, which is the layout used by bit-sliced consumers.

use super::bits::{u4_nibbles_to_be_bits_toaltstack, U4_BITS_MAX_BATCH};
use super::stack::verify_canonical_nibble;
use crate::support::script::*;

/// Reorder the four bits of each nibble into four contiguous bit planes.
fn transpose(nibble_count: u32) -> Script {
    let mut remaining = (0..4 * nibble_count).collect::<Vec<_>>();
    let mut depths = Vec::with_capacity(4 * nibble_count as usize);
    for plane in (0..4).rev() {
        for lane in (0..nibble_count).rev() {
            let source = 4 * lane + plane;
            let position = remaining
                .iter()
                .position(|candidate| *candidate == source)
                .expect("bit source must remain available");
            depths.push((remaining.len() - 1 - position) as u32);
            remaining.remove(position);
        }
    }
    script! {
        // Select the desired top-to-bottom order. The sentinel and any
        // unrelated state are below these items and do not affect depths.
        for depth in depths {
            { depth } OP_ROLL OP_TOALTSTACK
        }
    }
}

/// Consume contiguous checked nibbles and return their bits grouped by plane.
///
/// The input is `preserved | nibble[0] | ... | nibble[n-1]`, with the last
/// nibble on top. The output is
/// `preserved | plane0[0..n] | plane1[0..n] | plane2[0..n] | plane3[0..n]`,
/// with plane 3's final bit on top. `check_inputs=false` has the same caller
/// obligation as the underlying u4 bit converter.
pub fn u4_nibbles_to_bit_planes(nibble_count: u32, check_inputs: bool) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_BITS_MAX_BATCH,
        "nibble-to-bit-plane batch exceeds Bitcoin Script's stack limit"
    );
    let transpose = transpose(nibble_count);
    script! {
        { u4_nibbles_to_be_bits_toaltstack(nibble_count, check_inputs) }
        OP_0
        for _ in 0..4 * nibble_count {
            OP_FROMALTSTACK
        }
        { transpose }
        OP_DROP
        for _ in 0..4 * nibble_count {
            OP_FROMALTSTACK
        }
    }
}

/// Consume minimally encoded nibbles and return their bits grouped by plane.
pub fn u4_nibbles_to_bit_planes_canonical(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_BITS_MAX_BATCH,
        "nibble-to-bit-plane batch exceeds Bitcoin Script's stack limit"
    );
    script! {
        for _ in 0..nibble_count {
            { verify_canonical_nibble() }
            OP_TOALTSTACK
        }
        for _ in 0..nibble_count {
            OP_FROMALTSTACK
        }
        { u4_nibbles_to_bit_planes(nibble_count, true) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{execute_script, execute_script_with_inputs_strict};
    use bitcoin_scriptexec::ExecError;

    fn verify(inputs: &[u32], expected_planes: &[u32]) {
        let result = execute_script(script! {
            for input in inputs {
                { *input }
            }
            { u4_nibbles_to_bit_planes(inputs.len() as u32, true) }
            for bit in expected_planes.iter().rev() {
                { *bit } OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(result.success, "bit-plane transpose failed: {result}");
    }

    #[test]
    fn groups_each_bit_position_across_the_batch() {
        verify(
            &[0b0001, 0b1010, 0b1100],
            &[1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1],
        );
    }

    #[test]
    fn preserves_unrelated_main_and_alt_stack_items() {
        let result = execute_script(script! {
            OP_7
            OP_TOALTSTACK
            OP_9
            1 2
            { u4_nibbles_to_bit_planes(2, true) }
            for bit in [1, 0, 0, 1, 0, 0, 0, 0].iter().rev() {
                { *bit } OP_EQUALVERIFY
            }
            9 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_7 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "stack preservation failed: {result}");
    }

    #[test]
    fn rejects_out_of_range_nibbles() {
        for position in 0..4 {
            let mut input = vec![1; 4];
            input[position] = if position % 2 == 0 { -1 } else { 16 };
            let result = execute_script(script! {
                for nibble in input { { nibble } }
                { u4_nibbles_to_bit_planes(4, true) }
                for _ in 0..16 { OP_DROP }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble at {position}");
        }

        for position in 0..4 {
            let mut witness = vec![vec![1]; 4];
            witness[position] = vec![0, 0, 0, 0, 1];
            let result = execute_script_with_inputs_strict(
                script! {
                    { u4_nibbles_to_bit_planes(4, true) }
                    for _ in 0..16 { OP_DROP }
                    OP_TRUE
                },
                witness,
            );
            assert!(!result.success, "accepted oversized nibble at {position}");
        }
    }

    #[test]
    fn rejects_invalid_batch_sizes() {
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_bit_planes(0, true)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_to_bit_planes(U4_BITS_MAX_BATCH + 1, true)
        })
        .is_err());
    }

    #[test]
    fn strict_range_only_frontier_and_preservation() {
        let maximum = execute_script_with_inputs_strict(
            script! {
                { u4_nibbles_to_bit_planes(U4_BITS_MAX_BATCH, true) }
                for _ in 0..4 * U4_BITS_MAX_BATCH { OP_DROP }
                OP_TRUE
            },
            vec![vec![1]; U4_BITS_MAX_BATCH as usize],
        );
        assert!(maximum.success, "maximum bit-plane batch failed: {maximum}");
        assert_eq!(maximum.stats.max_nb_stack_items, 997);

        let mut preserved = vec![vec![77], vec![88]];
        preserved.extend(vec![vec![1]; U4_BITS_MAX_BATCH as usize]);
        let with_state = execute_script_with_inputs_strict(
            script! {
                OP_9 OP_TOALTSTACK
                { u4_nibbles_to_bit_planes(U4_BITS_MAX_BATCH, true) }
                for _ in 0..4 * U4_BITS_MAX_BATCH { OP_DROP }
                88 OP_EQUALVERIFY
                77 OP_EQUALVERIFY
                OP_FROMALTSTACK 9 OP_EQUALVERIFY
                OP_TRUE
            },
            preserved,
        );
        assert!(with_state.success, "preserved state failed: {with_state}");

        let mut over_budget = vec![vec![77], vec![88], vec![99]];
        over_budget.extend(vec![vec![1]; U4_BITS_MAX_BATCH as usize]);
        let rejected = execute_script_with_inputs_strict(
            script! { OP_9 OP_TOALTSTACK { u4_nibbles_to_bit_planes(U4_BITS_MAX_BATCH, true) } },
            over_budget,
        );
        assert_eq!(rejected.error, Some(ExecError::StackSize));
    }

    #[test]
    fn strict_canonical_frontier() {
        let maximum = execute_script_with_inputs_strict(
            script! {
                { u4_nibbles_to_bit_planes_canonical(U4_BITS_MAX_BATCH) }
                for _ in 0..4 * U4_BITS_MAX_BATCH { OP_DROP }
                OP_TRUE
            },
            vec![vec![1]; U4_BITS_MAX_BATCH as usize],
        );
        assert!(maximum.success, "maximum canonical batch failed: {maximum}");
        assert_eq!(maximum.stats.max_nb_stack_items, 997);
    }

    #[test]
    fn canonical_bit_planes_match_reference_values() {
        let result = execute_script(script! {
            1 10 12
            { u4_nibbles_to_bit_planes_canonical(3) }
            for bit in [1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1].iter().rev() {
                { *bit } OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(
            result.success,
            "canonical bit-plane conversion failed: {result}"
        );
    }

    #[test]
    fn canonical_bit_planes_reject_malformed_nibbles() {
        let script = script! {
            { u4_nibbles_to_bit_planes_canonical(4) }
            for _ in 0..16 { OP_DROP }
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
    fn canonical_bit_planes_preserve_surrounding_stacks() {
        let result = crate::support::execution::execute_script_with_inputs_strict(
            script! {
                99 OP_TOALTSTACK
                { u4_nibbles_to_bit_planes_canonical(2) }
                for _ in 0..8 { OP_DROP }
                77 OP_EQUALVERIFY
                OP_FROMALTSTACK 99 OP_EQUALVERIFY
                OP_TRUE
            },
            vec![vec![77], vec![1], vec![2]],
        );
        assert!(result.success, "{result}");
    }
}
