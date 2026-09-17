use super::stack::u4_drop;
use crate::support::script::*;

/// Largest standalone batch before accounting for unrelated live stack state.
pub const U4_TRANSITION_COUNT_MAX_BATCH: u32 = 997;

/// Count unequal adjacent pairs in a checked u4 vector.
///
/// Stack before: `preserved | nibble[0] ... nibble[n-1]`.
/// Stack after: `preserved | transition_count`, where the count is in
/// `0..=n-1`.
pub fn u4_nibbles_transition_count(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "transition count needs a nonempty vector");
    assert!(
        nibble_count <= U4_TRANSITION_COUNT_MAX_BATCH,
        "transition-count batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for index in 0..nibble_count {
            { nibble_count - 1 - index } OP_PICK
            OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
            16 OP_LESSTHAN OP_VERIFY
        }
        0 OP_TOALTSTACK
        for index in (0..nibble_count - 1).rev() {
            { nibble_count - 1 - index } OP_PICK
            { nibble_count - 1 - index } OP_PICK
            OP_EQUAL OP_NOT
            OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        }
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
    fn counts_transitions_and_preserves_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("112234") }
            { u4_nibbles_transition_count(6) }
            3 OP_EQUAL
        });
        assert!(result.success, "transition count failed: {result}");

        let constant = execute_script(script! {
            { u4_hex_to_nibbles("ffff") }
            { u4_nibbles_transition_count(4) }
            0 OP_EQUAL
        });
        assert!(
            constant.success,
            "constant vector counted a transition: {constant}"
        );
    }

    #[test]
    fn rejects_invalid_nibbles_and_batch_sizes() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid } 1
                { u4_nibbles_transition_count(2) }
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_transition_count(0)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_transition_count(U4_TRANSITION_COUNT_MAX_BATCH + 1)
        })
        .is_err());
    }

    #[test]
    fn preserves_surrounding_stack_items_and_singletons() {
        let singleton = execute_script(script! {
            7
            { u4_hex_to_nibbles("a") }
            { u4_nibbles_transition_count(1) }
            0 OP_EQUALVERIFY
            7 OP_EQUAL
        });
        assert!(singleton.success, "singleton failed: {singleton}");

        let result = execute_script(script! {
            77
            { u4_hex_to_nibbles("1122") }
            { u4_nibbles_transition_count(4) }
            1 OP_EQUALVERIFY
            77 OP_EQUAL
        });
        assert!(result.success, "stack preservation failed: {result}");
    }
}
