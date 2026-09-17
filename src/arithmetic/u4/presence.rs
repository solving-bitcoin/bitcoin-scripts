//! Membership-mask projection for checked u4 limbs.

use super::stack::u4_drop;
use crate::support::script::*;

/// Largest batch that fits the 1,000-item stack limit without unrelated state.
pub const U4_PRESENCE_MAX_BATCH: u32 = 1_000 - 16 - 2;

/// Consume checked u4 nibbles and return one presence bit for each nibble.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
/// on top. After: `preserved | present[0] ... present[15]`, where `present[n]`
/// is one iff nibble `n` appeared in the input. Every input is range-checked.
pub fn u4_nibbles_to_presence_bits(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_PRESENCE_MAX_BATCH,
        "nibble-presence batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for index in 0..nibble_count {
            { index } OP_PICK
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            OP_DROP
        }

        for nibble in (0..16).rev() {
            0
            for index in 0..nibble_count {
                { nibble }
                { index + 2 } OP_PICK
                OP_EQUAL
                OP_BOOLOR
            }
            OP_TOALTSTACK
        }

        { u4_drop(nibble_count) }
        for _ in 0..16 {
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
    fn projects_presence_bits() {
        for (input, expected) in [
            ("0123456789abcdef", [1; 16]),
            ("001122", [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            ("f0f0", [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        ] {
            let result = execute_script(script! {
                { u4_hex_to_nibbles(input) }
                { u4_nibbles_to_presence_bits(input.len() as u32) }
                for bit in expected.into_iter().rev() {
                    { bit } OP_EQUALVERIFY
                }
                OP_TRUE
            });
            assert!(result.success, "presence bits failed for {input}: {result}");
        }
    }

    #[test]
    fn rejects_invalid_nibbles_and_batch_sizes() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid }
                { u4_nibbles_to_presence_bits(1) }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_presence_bits(0)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_to_presence_bits(U4_PRESENCE_MAX_BATCH + 1)
        })
        .is_err());
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            0 1 2
            { u4_nibbles_to_presence_bits(3) }
            for nibble in (0..16).rev() {
                if nibble <= 2 { 1 } else { 0 }
                OP_EQUALVERIFY
            }
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "presence bits changed surrounding state: {result}"
        );
    }
}
