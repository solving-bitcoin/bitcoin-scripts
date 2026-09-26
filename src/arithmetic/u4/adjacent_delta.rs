//! Checked forward differences for contiguous u4 vectors.

use super::stack::u4_drop;
use crate::support::script::*;

/// Largest standalone batch that keeps input and output schedules below the
/// 1,000-item combined stack limit.
pub const U4_ADJACENT_DELTA_MAX_BATCH: u32 = 499;

/// Replace each checked nibble with the forward difference to its successor.
///
/// Stack before: `preserved | nibble[0] ... nibble[n-1]`.
/// Stack after: `preserved | delta[0] ... delta[n-2]`, where
/// `delta[i] = (nibble[i + 1] - nibble[i]) mod 16`.
pub fn u4_nibbles_to_adjacent_delta(nibble_count: u32) -> Script {
    assert!(
        nibble_count >= 2,
        "adjacent delta needs at least two nibbles"
    );
    assert!(
        nibble_count <= U4_ADJACENT_DELTA_MAX_BATCH,
        "adjacent-delta batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for index in 0..nibble_count {
            { nibble_count - 1 - index } OP_PICK
            OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
            16 OP_LESSTHAN OP_VERIFY
        }
        for index in (0..nibble_count - 1).rev() {
            { nibble_count - 1 - index } OP_PICK
            { nibble_count - 1 - index } OP_PICK
            OP_SWAP OP_SUB
            OP_DUP 0 OP_LESSTHAN
            OP_IF
                16 OP_ADD
            OP_ENDIF
            OP_TOALTSTACK
        }
        { u4_drop(nibble_count) }
        for _ in 0..nibble_count - 1 {
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::u4::stack::u4_hex_to_nibbles,
        support::{execution::execute_script, script::script},
    };

    #[test]
    fn emits_forward_modulo_sixteen_deltas() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("1f30") }
            { u4_nibbles_to_adjacent_delta(4) }
            13 OP_EQUALVERIFY
            4 OP_EQUALVERIFY
            14 OP_EQUAL
        });
        assert!(result.success, "adjacent delta failed: {result}");
    }

    #[test]
    fn handles_equal_and_wraparound_pairs() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("00ff") }
            { u4_nibbles_to_adjacent_delta(4) }
            0 OP_EQUALVERIFY
            15 OP_EQUALVERIFY
            0 OP_EQUAL
        });
        assert!(result.success, "delta boundary failed: {result}");
    }

    #[test]
    fn rejects_invalid_nibbles_and_batch_sizes() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid } 1
                { u4_nibbles_to_adjacent_delta(2) }
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_adjacent_delta(1)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_to_adjacent_delta(U4_ADJACENT_DELTA_MAX_BATCH + 1)
        })
        .is_err());
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            { u4_hex_to_nibbles("1234") }
            { u4_nibbles_to_adjacent_delta(4) }
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUAL
        });
        assert!(result.success, "stack preservation failed: {result}");
    }
}
