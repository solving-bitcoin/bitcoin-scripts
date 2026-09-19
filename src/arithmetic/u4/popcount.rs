use super::stack::u4_drop;
use crate::support::script::*;

/// Persistent items used by the nibble-popcount lookup table.
pub const U4_POPCOUNT_TABLE_ITEMS: u32 = 16;

/// Largest batch that fits the 1,000-item stack limit without unrelated state.
pub const U4_POPCOUNT_MAX_BATCH: u32 = 1_000 - U4_POPCOUNT_TABLE_ITEMS - 2;

fn popcount(value: u32) -> u32 {
    value.count_ones()
}

fn push_popcount_table() -> Script {
    script! {
        for value in (0..U4_POPCOUNT_TABLE_ITEMS).rev() {
            { popcount(value) }
        }
    }
}

/// Consume checked u4 nibbles and replace each with its Hamming weight.
pub fn u4_nibbles_to_popcount(nibble_count: u32) -> Script {
    assert!(nibble_count > 0, "nibble batch must not be empty");
    assert!(
        nibble_count <= U4_POPCOUNT_MAX_BATCH,
        "nibble-popcount batch exceeds Bitcoin Script's stack limit"
    );

    script! {
        { push_popcount_table() }
        for _ in 0..nibble_count {
            { U4_POPCOUNT_TABLE_ITEMS } OP_ROLL
            OP_DUP OP_0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP OP_16 OP_LESSTHAN OP_VERIFY
            OP_PICK OP_TOALTSTACK
        }
        { u4_drop(U4_POPCOUNT_TABLE_ITEMS) }
        for _ in 0..nibble_count {
            OP_FROMALTSTACK
        }
    }
}

/// Consume checked u4 nibbles and return their total Hamming weight.
pub fn u4_popcount(nibble_count: u32) -> Script {
    script! {
        { u4_nibbles_to_popcount(nibble_count) }
        for _ in 1..nibble_count {
            OP_ADD
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

    #[test]
    fn counts_all_nibble_weights_in_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("0123456789abcdef") }
            { u4_nibbles_to_popcount(16) }
            4 OP_EQUALVERIFY
            3 OP_EQUALVERIFY
            3 OP_EQUALVERIFY
            2 OP_EQUALVERIFY
            3 OP_EQUALVERIFY
            2 OP_EQUALVERIFY
            2 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            3 OP_EQUALVERIFY
            2 OP_EQUALVERIFY
            2 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            2 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            0 OP_EQUAL
        });
        assert!(result.success, "nibble popcount failed: {result}");
    }

    #[test]
    fn rejects_out_of_range_nibbles_and_batch_sizes() {
        for invalid in [-1, 16] {
            let result = execute_script(script! {
                { invalid }
                { u4_nibbles_to_popcount(1) }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid nibble {invalid}");
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_popcount(0)).is_err());
        assert!(
            std::panic::catch_unwind(|| { u4_nibbles_to_popcount(U4_POPCOUNT_MAX_BATCH + 1) })
                .is_err()
        );
    }

    #[test]
    fn preserves_surrounding_stack_items() {
        let result = execute_script(script! {
            77
            { u4_hex_to_nibbles("1234") }
            { u4_nibbles_to_popcount(4) }
            1 OP_EQUALVERIFY
            2 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            1 OP_EQUALVERIFY
            77 OP_EQUAL
        });
        assert!(result.success, "stack preservation failed: {result}");
    }

    #[test]
    fn sums_checked_nibble_popcounts() {
        for high in 0u32..16 {
            for low in 0u32..16 {
                let result = execute_script(script! {
                    { high }
                    { low }
                    { u4_popcount(2) }
                    { high.count_ones() + low.count_ones() }
                    OP_EQUAL
                });
                assert!(
                    result.success,
                    "popcount failed for {high}, {low}: {result}"
                );
            }
        }
    }

    #[test]
    fn enforces_aggregate_stack_frontier() {
        let at_limit = execute_script_with_inputs_strict(
            script! {
                { u4_popcount(U4_POPCOUNT_MAX_BATCH) }
                0 OP_EQUALVERIFY OP_TRUE
            },
            vec![vec![]; U4_POPCOUNT_MAX_BATCH as usize],
        );
        assert!(at_limit.success, "standalone frontier failed: {at_limit}");
        assert_eq!(
            at_limit.stats.max_nb_stack_items, 1_000,
            "frontier metric changed: {at_limit}"
        );

        let with_state = execute_script_with_inputs_strict(
            script! {
                99 OP_TOALTSTACK
                { u4_popcount(U4_POPCOUNT_MAX_BATCH - 2) }
                0 OP_EQUALVERIFY
                OP_FROMALTSTACK 99 OP_EQUALVERIFY
                77 OP_EQUAL
            },
            {
                let mut witness = vec![vec![77]];
                witness.extend(vec![vec![]; (U4_POPCOUNT_MAX_BATCH - 2) as usize]);
                witness
            },
        );
        assert!(
            with_state.success,
            "preserved-state frontier failed: {with_state}"
        );

        let over_state = execute_script_with_inputs_strict(
            script! {
                99 OP_TOALTSTACK
                { u4_popcount(U4_POPCOUNT_MAX_BATCH - 1) }
            },
            {
                let mut witness = vec![vec![77]];
                witness.extend(vec![vec![]; (U4_POPCOUNT_MAX_BATCH - 1) as usize]);
                witness
            },
        );
        assert_eq!(
            over_state.error,
            Some(bitcoin_scriptexec::ExecError::StackSize)
        );
    }
}
