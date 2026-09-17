//! Fixed-symbol occurrence counts for checked u4 limbs.

use super::stack::u4_drop;
use crate::support::script::*;

/// Largest batch that fits the 1,000-item stack limit without unrelated state.
pub const U4_COUNT_MAX_BATCH: u32 = 1_000 - 2;

/// Count occurrences of one generation-time nibble in a checked u4 batch.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
/// on top. After: `preserved | count`, where `count` is in `0..=n`.
pub fn u4_nibbles_count(value: u8, nibble_count: u32) -> Script {
    assert!(value < 16, "count target must be a u4 nibble");
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_COUNT_MAX_BATCH,
        "nibble-count batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for index in 0..nibble_count {
            { index } OP_PICK
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            OP_DROP
        }

        0
        for index in 0..nibble_count {
            { value }
            { index + 2 } OP_PICK
            OP_EQUAL
            OP_ADD
        }

        OP_TOALTSTACK
        { u4_drop(nibble_count) }
        OP_FROMALTSTACK
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
    fn counts_boundary_and_repeated_symbols() {
        for (input, target, expected) in [
            ("0123456789abcdef", 0, 1),
            ("001122", 1, 2),
            ("ffff", 15, 4),
        ] {
            let result = execute_script(script! {
                { u4_hex_to_nibbles(input) }
                { u4_nibbles_count(target, input.len() as u32) }
                { expected } OP_EQUAL
            });
            assert!(result.success, "symbol count failed for {input}: {result}");
        }
    }

    #[test]
    fn rejects_invalid_nibbles_and_generation_bounds() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid }
                { u4_nibbles_count(0, 1) }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_count(16, 1)).is_err());
        assert!(std::panic::catch_unwind(|| u4_nibbles_count(0, 0)).is_err());
        assert!(
            std::panic::catch_unwind(|| { u4_nibbles_count(0, U4_COUNT_MAX_BATCH + 1) }).is_err()
        );
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            0 1 0
            { u4_nibbles_count(0, 3) }
            2 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "symbol count changed surrounding state: {result}"
        );
    }
}
