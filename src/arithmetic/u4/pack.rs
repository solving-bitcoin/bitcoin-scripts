use super::stack::{u4_drop, u4_pair_to_u8};
use crate::support::script::*;

/// Largest standalone even batch before accounting for unrelated live state.
pub const U4_PACK_MAX_BATCH: u32 = 664;

/// Consume checked high/low nibble pairs and return their packed bytes.
///
/// Stack before: `preserved | nibble[0] ... nibble[n-1]`.
/// Stack after: `preserved | byte[0] ... byte[n/2-1]`.
pub fn u4_nibbles_to_bytes(nibble_count: u32) -> Script {
    assert!(
        nibble_count >= 2 && nibble_count % 2 == 0,
        "nibble batch must have a positive even width"
    );
    assert!(
        nibble_count <= U4_PACK_MAX_BATCH,
        "nibble-pack batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for pair in (0..nibble_count / 2).rev() {
            { nibble_count - 1 - pair * 2 } OP_PICK
            { nibble_count - 1 - pair * 2 } OP_PICK
            { u4_pair_to_u8(true) }
            OP_TOALTSTACK
        }
        { u4_drop(nibble_count) }
        for _ in 0..nibble_count / 2 {
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
    fn packs_all_pairs_in_input_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("1234abcd") }
            { u4_nibbles_to_bytes(8) }
            0xcd OP_EQUALVERIFY
            0xab OP_EQUALVERIFY
            0x34 OP_EQUALVERIFY
            0x12 OP_EQUAL
        });
        assert!(result.success, "batch packing failed: {result}");
    }

    #[test]
    fn rejects_invalid_nibbles_and_batch_sizes() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid } 1
                { u4_nibbles_to_bytes(2) }
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
        for invalid_size in [0, 1, 3] {
            assert!(std::panic::catch_unwind(|| u4_nibbles_to_bytes(invalid_size)).is_err());
        }
        assert!(
            std::panic::catch_unwind(|| { u4_nibbles_to_bytes(U4_PACK_MAX_BATCH + 2) }).is_err()
        );
    }

    #[test]
    fn preserves_surrounding_stack_items() {
        let result = execute_script(script! {
            77
            { u4_hex_to_nibbles("1122") }
            { u4_nibbles_to_bytes(4) }
            0x22 OP_EQUALVERIFY
            0x11 OP_EQUALVERIFY
            77 OP_EQUAL
        });
        assert!(result.success, "stack preservation failed: {result}");
    }
}
