//! CRC-8/SMBus over a high-nibble-first message, consumed from the stack top.
use crate::{
    arithmetic::{
        scriptint::mul_by_constant,
        u4::{
            logic::{
                u4_drop_half_lookup, u4_drop_half_table, u4_half_table_operation,
                u4_push_half_lookup, u4_push_half_xor_table,
            },
            stack::u4_drop,
        },
    },
    support::script::*,
};

/// Maximum complete message with no unrelated live caller items.
pub const CRC8_SMBUS_MAX_BYTES: u32 = 406;
// Remainders of i*x^8 modulo x^8+x^2+x+1, for i=0..15.
const FEEDBACK: [u8; 16] = [0, 7, 14, 9, 28, 27, 18, 21, 56, 63, 54, 49, 36, 35, 42, 45];

/// Consume `2*byte_count` hostile numeric nibbles and return a canonical
/// ScriptNum CRC byte. The first message byte's high nibble is on top, then
/// its low nibble, then the next byte. Older main/alt-stack bytes survive.
///
/// Width is 0..=406 bytes, with zero initialization, polynomial 0x07,
/// MSB-first processing, no reflection and no final xor. Nonempty combined
/// peak is `2*byte_count+188`, including all future inputs; add caller state.
/// Every input is range checked in 0..=15 and uses at most four numeric bytes.
/// Numeric aliases are allowed when the execution profile permits them.
/// There are zero witness hints. CRC is not authentication; the caller binds
/// input provenance and supplies the terminal predicate. Empty input returns
/// canonical zero, which is valid checksum data but false as a bare predicate.
pub fn crc8_smbus_nibbles(byte_count: u32) -> Script {
    assert!(
        byte_count <= CRC8_SMBUS_MAX_BYTES,
        "CRC-8 message exceeds the combined stack bound"
    );
    if byte_count == 0 {
        return script! {0};
    }
    script! {
        {u4_push_half_xor_table()} {u4_push_half_lookup()}
        for i in (0..16).rev() { {FEEDBACK[i]>>4} {FEEDBACK[i]&15} }
        0 0
        for _ in 0..2*byte_count {
            186 OP_ROLL
            OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP 16 OP_LESSTHAN OP_VERIFY
            // H L d -> L (H xor d); 32 feedback items and L separate lookup.
            OP_ROT {u4_half_table_operation(35)}
            OP_DUP OP_ADD OP_DUP 2 OP_ADD OP_PICK OP_SWAP 3 OP_ADD OP_PICK
            OP_ROT {u4_half_table_operation(35)} OP_SWAP
        }
        OP_SWAP {mul_by_constant(16)} OP_ADD OP_TOALTSTACK
        {u4_drop(32)} {u4_drop_half_lookup()} {u4_drop_half_table()}
        OP_FROMALTSTACK
    }
}
