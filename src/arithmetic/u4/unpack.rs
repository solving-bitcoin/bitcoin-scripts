//! Checked conversion from bytes to big-endian u4 nibbles.
//!
//! A 512-item lookup table stores the high and low nibble for every byte.
//! The table is shared by the whole batch; decoded nibbles are parked on the
//! altstack while the remaining bytes are processed.

use super::stack::u4_drop;
use crate::support::script::*;

pub const U4_UNPACK_TABLE_ITEMS: u32 = 512;

/// Largest batch whose strict combined main/alt-stack peak is at most 1,000.
pub const U4_UNPACK_MAX_BATCH: u32 = (1_000 - U4_UNPACK_TABLE_ITEMS - 2) / 2;

fn table_value(index: u32) -> u32 {
    let byte = index / 2;
    if index & 1 == 0 {
        byte >> 4
    } else {
        byte & 0x0f
    }
}

fn push_table() -> Script {
    script! {
        for index in (0..U4_UNPACK_TABLE_ITEMS).rev() {
            { table_value(index) }
        }
    }
}

fn decode_one_byte() -> Script {
    script! {
        // The byte is immediately above the table after OP_ROLL.
        OP_DUP OP_0 { 256 } OP_WITHIN OP_VERIFY

        // Lookup high(byte / 16), then low(byte % 16) at depths 2*byte and
        // 2*byte+1. Keep the input until both table queries are complete.
        OP_DUP OP_DUP OP_ADD { 1 } OP_ADD
        OP_PICK OP_TOALTSTACK
        OP_DUP OP_ADD OP_1 OP_ADD
        OP_PICK OP_TOALTSTACK
    }
}

fn validate_batch_size(byte_count: u32) {
    assert!(byte_count > 0, "byte batch must not be empty");
    assert!(
        byte_count <= U4_UNPACK_MAX_BATCH,
        "byte-to-nibble batch exceeds Bitcoin Script's stack limit"
    );
}

/// Consume `byte_count` bytes and replace them with two canonical nibbles per
/// byte. The input is `byte[0] | ... | byte[n-1]`, with `byte[n-1]` on top.
/// The output is `high[0] | low[0] | ... | high[n-1] | low[n-1]`, with the
/// final low nibble on top.
pub fn u4_bytes_to_nibbles(byte_count: u32) -> Script {
    validate_batch_size(byte_count);
    script! {
        { push_table() }
        for _ in 0..byte_count {
            { U4_UNPACK_TABLE_ITEMS } OP_ROLL
            { decode_one_byte() }
        }
        { u4_drop(U4_UNPACK_TABLE_ITEMS) }
        for _ in 0..byte_count {
            OP_FROMALTSTACK OP_FROMALTSTACK OP_SWAP
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::execute_script;

    fn verify(inputs: &[u32], expected: &[u32]) {
        let result = execute_script(script! {
            for input in inputs {
                { *input }
            }
            { u4_bytes_to_nibbles(inputs.len() as u32) }
            for nibble in expected.iter().rev() {
                { *nibble } OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(result.success, "byte unpack failed: {result}");
    }

    #[test]
    fn boundary_bytes_decode_in_input_order() {
        verify(
            &[0x00, 0x01, 0x0f, 0x10, 0x80, 0xff],
            &[0, 0, 0, 1, 0, 15, 1, 0, 8, 0, 15, 15],
        );
    }

    #[test]
    fn rejects_non_bytes() {
        for invalid in [-1, 256] {
            let result = execute_script(script! {
                { invalid }
                { u4_bytes_to_nibbles(1) }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid byte {invalid}");
        }
    }

    #[test]
    fn batch_size_guard_accounts_for_altstack_outputs() {
        let result = execute_script(script! {
            for _ in 0..U4_UNPACK_MAX_BATCH {
                OP_0
            }
            { u4_bytes_to_nibbles(U4_UNPACK_MAX_BATCH) }
            { u4_drop(2 * U4_UNPACK_MAX_BATCH) }
            OP_TRUE
        });
        assert!(result.success, "maximum batch failed: {result}");
        assert_eq!(result.stats.max_nb_stack_items, 1_000);

        assert!(std::panic::catch_unwind(|| u4_bytes_to_nibbles(0)).is_err());
        assert!(
            std::panic::catch_unwind(|| { u4_bytes_to_nibbles(U4_UNPACK_MAX_BATCH + 1) }).is_err()
        );
    }
}
