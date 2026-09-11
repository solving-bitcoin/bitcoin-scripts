//! Checked conversion from u4 nibbles to bit-plane order.
//!
//! The existing u4 bit converter emits four adjacent bits per nibble. This
//! adapter transposes that result so each plane contains one bit from every
//! input nibble, which is the layout used by bit-sliced consumers.

use super::bits::{u4_nibbles_to_be_bits_toaltstack, U4_BITS_MAX_BATCH};
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::execute_script;

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
            OP_DROP
            OP_FROMALTSTACK OP_7 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "stack preservation failed: {result}");
    }

    #[test]
    fn rejects_out_of_range_nibbles() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid }
                { u4_nibbles_to_bit_planes(1, true) }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
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
}
