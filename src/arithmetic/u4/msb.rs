//! Batched most-significant-bit projection for range-checked u4 limbs.

use crate::support::script::*;

/// Largest direct-threshold batch before unrelated stack state.
pub const U4_MSB_MAX_BATCH: u32 = 998;

/// Consume range-checked nibbles and replace each with its most-significant bit.
pub fn u4_nibbles_to_msb(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_MSB_MAX_BATCH,
        "nibble-MSB batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        for _ in 0..nibble_count {
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            OP_DUP 8 OP_GREATERTHANOREQUAL
            OP_TOALTSTACK
            OP_DROP
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
            execution::{execute_script, execute_script_with_inputs_strict},
            script::script,
        },
    };
    use bitcoin_scriptexec::ExecError;

    #[test]
    fn projects_asymmetric_boundary_values_in_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("78f") }
            { u4_nibbles_to_msb(3) }
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUAL
        });
        assert!(result.success, "MSB projection failed: {result}");
    }

    #[test]
    fn rejects_invalid_nibbles_at_each_position() {
        for position in 0..3 {
            let mut input = vec![1; 3];
            input[position] = if position % 2 == 0 { -1 } else { 16 };
            let result = execute_script(script! {
                for nibble in input { { nibble } }
                { u4_nibbles_to_msb(3) }
                OP_2DROP OP_DROP OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble at {position}");
        }

        for position in 0..3 {
            let mut witness = vec![vec![1]; 3];
            witness[position] = vec![0, 0, 0, 0, 1];
            let result = execute_script_with_inputs_strict(
                script! {
                    { u4_nibbles_to_msb(3) }
                    OP_2DROP OP_DROP OP_TRUE
                },
                witness,
            );
            assert!(!result.success, "accepted oversized nibble at {position}");
        }
    }

    #[test]
    fn respects_direct_threshold_stack_frontier() {
        let maximum = execute_script_with_inputs_strict(
            script! {
                { u4_nibbles_to_msb(U4_MSB_MAX_BATCH) }
                { crate::arithmetic::u4::stack::u4_drop(U4_MSB_MAX_BATCH) }
                OP_TRUE
            },
            vec![Vec::new(); U4_MSB_MAX_BATCH as usize],
        );
        assert!(maximum.success, "maximum MSB batch failed: {maximum}");
        assert_eq!(maximum.stats.max_nb_stack_items, 1000);

        let mut preserved = vec![vec![7]];
        preserved.extend(vec![Vec::new(); 996]);
        let with_state = execute_script_with_inputs_strict(
            script! {
                OP_9 OP_TOALTSTACK
                { u4_nibbles_to_msb(996) }
                { crate::arithmetic::u4::stack::u4_drop(996) }
                7 OP_EQUALVERIFY
                OP_FROMALTSTACK 9 OP_EQUALVERIFY
                OP_TRUE
            },
            preserved,
        );
        assert!(with_state.success, "preserved state failed: {with_state}");

        let mut over_budget = vec![vec![7]];
        over_budget.extend(vec![Vec::new(); 997]);
        let rejected = execute_script_with_inputs_strict(
            script! { OP_9 OP_TOALTSTACK { u4_nibbles_to_msb(997) } },
            over_budget,
        );
        assert_eq!(rejected.error, Some(ExecError::StackSize));
    }

    #[test]
    #[should_panic(expected = "nibble-MSB batch exceeds Bitcoin Script's stack limit")]
    fn rejects_batch_above_stack_limit() {
        let _ = u4_nibbles_to_msb(U4_MSB_MAX_BATCH + 1);
    }
}
