//! Packing checked u4 pairs into numeric byte values.

use crate::support::script::{script, Script};

/// Pack `byte_count` big-endian u4 pairs into numeric byte values.
///
/// Stack before: `high[0] low[0] ... high[n-1] low[n-1]`.
/// Stack after: `byte[0] ... byte[n-1]`, with the last byte on top. The
/// outputs are ScriptNum integers in `0..=255`, not raw one-byte elements.
pub fn pack_bytes(byte_count: u32) -> Script {
    assert!(byte_count > 0, "byte count must be nonzero");
    let nibble_count = byte_count * 2;

    script! {
        for index in 0..nibble_count {
            { index }
            OP_PICK
            OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
            16 OP_LESSTHAN OP_VERIFY
        }

        for _ in 0..byte_count {
            OP_SWAP
            OP_DUP OP_ADD
            OP_DUP OP_ADD
            OP_DUP OP_ADD
            OP_DUP OP_ADD
            OP_ADD
            OP_TOALTSTACK
        }
        for _ in 0..byte_count {
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
    fn packs_all_single_bytes() {
        for value in 0..=255u16 {
            let hex = format!("{value:02x}");
            let result = execute_script(script! {
                { u4_hex_to_nibbles(&hex) }
                { pack_bytes(1) }
                { i64::from(value) } OP_EQUAL
            });
            assert!(result.success, "value={value:#04x}: {result}");
        }
    }

    #[test]
    fn packs_multiple_bytes_in_input_order() {
        let result = execute_script(script! {
            { u4_hex_to_nibbles("80ff01") }
            { pack_bytes(3) }
            1 OP_EQUALVERIFY
            255 OP_EQUALVERIFY
            128 OP_EQUAL
        });
        assert!(result.success, "{result}");
    }

    #[test]
    fn rejects_an_out_of_range_nibble() {
        let result = execute_script(script! {
            0 16
            { pack_bytes(1) }
        });
        assert!(!result.success);
    }

    #[test]
    #[should_panic(expected = "byte count must be nonzero")]
    fn rejects_zero_width() {
        let _ = pack_bytes(0);
    }
}
