//! Embedded-cap saturation for checked u4 limbs.

use crate::support::script::*;

/// Largest batch that fits the 1,000-item stack limit without unrelated state.
pub const U4_CLAMP_MAX_BATCH: u32 = 1_000 - 2;

/// Replace each checked u4 nibble with `min(nibble, maximum)`.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
/// on top. After: `preserved | clamped[0] | ... | clamped[n-1]`, with the last
/// result on top. The cap is public generation-time data and must be a u4.
pub fn u4_nibbles_to_clamp(maximum: u8, nibble_count: u32) -> Script {
    assert!(maximum < 16, "clamp maximum must be a u4 nibble");
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_CLAMP_MAX_BATCH,
        "nibble-clamp batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for index in (0..nibble_count).rev() {
            { index } OP_ROLL
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            OP_DUP { maximum } OP_GREATERTHAN
            OP_IF
                OP_DROP { maximum }
            OP_ENDIF
            OP_TOALTSTACK
        }
        for _ in 0..nibble_count {
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::u4::stack::u4_hex_to_nibbles,
        support::{
            execution::{execute_script, execute_script_with_inputs},
            script::script,
        },
    };

    #[test]
    fn clamps_all_nibbles_to_an_embedded_cap_in_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("0123456789abcdef") }
            { u4_nibbles_to_clamp(4, 16) }
            0 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            2 OP_EQUALVERIFY
            3 OP_EQUALVERIFY
            4 OP_EQUALVERIFY
            4 OP_EQUALVERIFY
            4 OP_EQUALVERIFY
            4 OP_EQUALVERIFY
            4 OP_EQUALVERIFY
            4 OP_EQUALVERIFY
            4 OP_EQUALVERIFY
            4 OP_EQUALVERIFY
            4 OP_EQUALVERIFY
            4 OP_EQUALVERIFY
            4 OP_EQUALVERIFY
            4 OP_EQUAL
        });
        assert!(result.success, "nibble clamp failed: {result}");
    }

    #[test]
    fn rejects_invalid_nibbles_and_generation_bounds() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid }
                { u4_nibbles_to_clamp(4, 1) }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_clamp(16, 1)).is_err());
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_clamp(4, 0)).is_err());
        assert!(
            std::panic::catch_unwind(|| { u4_nibbles_to_clamp(4, U4_CLAMP_MAX_BATCH + 1) })
                .is_err()
        );

        let result = execute_script_with_inputs(
            script! {
                { u4_nibbles_to_clamp(4, 1) }
                OP_TRUE
            },
            vec![vec![16]],
        );
        assert!(!result.success, "accepted an out-of-range raw witness item");
    }

    #[test]
    fn handles_cap_endpoints() {
        for (maximum, input, expected) in [(0, 0, 0), (0, 15, 0), (15, 14, 14), (15, 15, 15)] {
            let result = execute_script(script! {
                { input }
                { u4_nibbles_to_clamp(maximum, 1) }
                { expected } OP_EQUAL
            });
            assert!(
                result.success,
                "clamp endpoint failed: maximum={maximum}, input={input}"
            );
        }
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            3 5 15
            { u4_nibbles_to_clamp(5, 3) }
            3 OP_EQUALVERIFY
            5 OP_EQUALVERIFY
            5 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "nibble clamp changed surrounding state: {result}"
        );
    }
}
