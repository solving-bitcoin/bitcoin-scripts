//! Checked packing of canonical u4 zero predicates into byte masks.

use super::stack::verify_canonical_nibble;
use crate::support::script::*;

/// Number of input nibbles consumed by one packed mask.
pub const U4_ZERO_BITMASK_NIBBLES: u32 = 8;

/// Largest complete batch whose inputs and local temporaries fit the strict
/// stack limit.
pub const U4_ZERO_BITMASK_MAX_NIBBLES: u32 = 992;

/// Consume eight canonical nibbles and return their zero predicate as a byte.
///
/// Before: `preserved | nibble[0] | ... | nibble[7]`, with `nibble[7]` on top.
/// After: `preserved | mask`, where bit `i` is set iff `nibble[i] == 0`.
/// The result is a numeric ScriptNum and no lookup table or hint is required.
fn pack_zero_bitmask() -> Script {
    script! {
        OP_0
        for _ in 0..U4_ZERO_BITMASK_NIBBLES {
            OP_DUP OP_ADD
            OP_SWAP
            { verify_canonical_nibble() }
            OP_0 OP_NUMEQUAL
            OP_ADD
        }
    }
}

/// Consume a multiple of eight canonical nibbles and return one mask per group.
///
/// The masks retain group order: bit `i` of each result corresponds to the
/// `i`th nibble in that group. Outputs are restored to the main stack after
/// intermediate masks are moved to the altstack.
pub fn u4_nibbles_to_zero_bitmasks(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count % U4_ZERO_BITMASK_NIBBLES == 0,
        "nibble batch must contain complete eight-nibble groups"
    );
    assert!(
        nibble_count <= U4_ZERO_BITMASK_MAX_NIBBLES,
        "zero-bitmask batch exceeds Bitcoin Script's stack limit"
    );

    let group_count = nibble_count / U4_ZERO_BITMASK_NIBBLES;
    script! {
        for _ in 0..group_count {
            { pack_zero_bitmask() }
            OP_TOALTSTACK
        }
        for _ in 0..group_count {
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};

    #[test]
    fn packs_zero_bits_in_input_order_and_preserves_state() {
        let result = execute_script(script! {
            7 OP_TOALTSTACK
            9
            0 1 15 0 2 15 3 4
            0 15 1 2 3 4 5 6
            { u4_nibbles_to_zero_bitmasks(16) }
            1 OP_EQUALVERIFY
            9 OP_EQUALVERIFY
            9 OP_EQUALVERIFY
            OP_FROMALTSTACK 7 OP_EQUAL
        });
        assert!(result.success, "zero bitmask packing failed: {result}");
    }

    #[test]
    fn rejects_invalid_numeric_and_raw_inputs() {
        for invalid in [-1, 16, 255] {
            let result = execute_script(script! {
                1 1 1 1 1 1 1
                { invalid }
                { u4_nibbles_to_zero_bitmasks(8) }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }

        let script = u4_nibbles_to_zero_bitmasks(8)
            .compile_with_policy()
            .to_bytes();
        for invalid in [vec![0x80], vec![0x10], vec![0x01, 0x00]] {
            let mut inputs = vec![vec![1]; 7];
            inputs.push(invalid.clone());
            let result = execute_raw_script_with_inputs_strict(script.clone(), inputs);
            assert!(!result.success, "accepted malformed witness {invalid:?}");
        }
    }

    #[test]
    fn accepts_all_canonical_nibble_values() {
        let result = execute_script(script! {
            0 1 2 3 4 5 6 7
            8 9 10 11 12 13 14 15
            { u4_nibbles_to_zero_bitmasks(16) }
            0 OP_EQUALVERIFY
            1 OP_EQUAL
        });
        assert!(result.success, "rejected canonical nibbles: {result}");
    }

    #[test]
    fn rejects_incomplete_and_over_limit_batches() {
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_zero_bitmasks(0)).is_err());
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_zero_bitmasks(7)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_to_zero_bitmasks(U4_ZERO_BITMASK_MAX_NIBBLES + 8)
        })
        .is_err());
    }
}
