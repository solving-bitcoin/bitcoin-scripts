//! Checked zero-mask projection for canonical u4 limbs.

use super::stack::verify_canonical_nibble;
use crate::support::script::*;

/// Largest batch that fits the strict combined stack limit without unrelated
/// state. Two temporary items are needed by the canonical check.
pub const U4_ZERO_MAX_BATCH: u32 = 997;

/// Consume canonical nibbles and replace each with `nibble == 0`.
///
/// Before: `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
/// on top. After: `preserved | zero[0] | ... | zero[n-1]`, with the last
/// boolean on top. No lookup table or auxiliary hint is required.
pub fn u4_nibbles_to_zero_mask(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_ZERO_MAX_BATCH,
        "nibble-zero batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for _ in 0..nibble_count {
            { verify_canonical_nibble() }
            OP_0 OP_NUMEQUAL OP_TOALTSTACK
        }
        for _ in 0..nibble_count {
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};

    #[test]
    fn projects_zero_mask_in_batch_order() {
        let result = execute_script(script! {
            0 1 15 0
            { u4_nibbles_to_zero_mask(4) }
            1 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            0 OP_EQUALVERIFY
            1 OP_EQUAL
        });
        assert!(result.success, "zero-mask projection failed: {result}");
    }

    #[test]
    fn rejects_out_of_range_and_noncanonical_inputs() {
        for invalid in [-1, 16, 255] {
            let result = execute_script(script! {
                { invalid }
                { u4_nibbles_to_zero_mask(1) }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }

        let script = u4_nibbles_to_zero_mask(1).compile_with_policy().to_bytes();
        for raw in [vec![0x00], vec![0x80], vec![0x10], vec![0x01, 0x00]] {
            let result = execute_raw_script_with_inputs_strict(script.clone(), vec![raw.clone()]);
            assert!(!result.success, "accepted noncanonical witness {raw:?}");
        }
    }

    #[test]
    fn batch_respects_strict_stack_limit() {
        let result = execute_script(script! {
            for _ in 0..64 { OP_0 }
            { u4_nibbles_to_zero_mask(64) }
            { crate::arithmetic::u4::stack::u4_drop(64) }
            OP_TRUE
        });
        assert!(result.success, "maximum batch failed: {result}");
        assert_eq!(result.stats.max_nb_stack_items, 67);
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_zero_mask(0)).is_err());
        assert!(
            std::panic::catch_unwind(|| { u4_nibbles_to_zero_mask(U4_ZERO_MAX_BATCH + 1) })
                .is_err()
        );
    }
}
