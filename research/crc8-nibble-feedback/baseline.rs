//! Frozen initial schedules for matched research baselines, not public APIs.
#[cfg(test)]
use bitcoin_lab::arithmetic::{
    scriptint::mul_by_constant,
    u4::{
        logic::{
            u4_drop_half_lookup, u4_drop_half_table, u4_half_table_operation, u4_push_half_lookup,
            u4_push_half_xor_table,
        },
        stack::u4_drop,
    },
};
use bitcoin_lab::support::script::*;
pub fn reduce(mut x: u16) -> u8 {
    for bit in (8..16).rev() {
        if x & (1 << bit) != 0 {
            x ^= 0x107 << (bit - 8);
        }
    }
    x as u8
}
// Independent polynomial remainder of the message times x^8.
pub fn oracle(digits: &[u8], initial: u8) -> u8 {
    let mut c = initial;
    for &d in digits {
        assert!(d < 16);
        c = reduce((u16::from(c) << 4) ^ (u16::from(d) << 8));
    }
    c
}
pub fn guard() -> Script {
    script! {OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY OP_DUP 16 OP_LESSTHAN OP_VERIFY}
}
#[cfg(test)]
const TABLE_ITEMS: u32 = 136 + 16 + 32;
#[cfg(test)]
pub fn feedback(count: u32, initial: u8) -> Script {
    if count == 0 {
        return script! {{initial}};
    }
    script! {
        {u4_push_half_xor_table()} {u4_push_half_lookup()}
        for i in (0u16..16).rev() { {reduce(i<<8)>>4} {reduce(i<<8)&15} }
        {initial>>4} {initial&15}
        for _ in 0..count {
            {TABLE_ITEMS+2} OP_ROLL {guard()}
            // H L d -> L d H -> L (H xor d).
            OP_ROT {u4_half_table_operation(35)}
            OP_DUP OP_ADD OP_DUP 2 OP_ADD OP_PICK OP_SWAP 3 OP_ADD OP_PICK
            // L Tlow Thigh -> Tlow (L xor Thigh) -> newH newL.
            OP_ROT {u4_half_table_operation(35)} OP_SWAP
        }
        OP_SWAP {mul_by_constant(16)} OP_ADD OP_TOALTSTACK
        {u4_drop(32)} {u4_drop_half_lookup()} {u4_drop_half_table()}
        OP_FROMALTSTACK
    }
}
pub fn bit_step() -> Script {
    script! {
        // b0..b7 d -> b0..b6 f; f = b7 xor d.
        OP_NUMNOTEQUAL
        7 OP_ROLL OP_OVER OP_NUMNOTEQUAL
        7 OP_ROLL 2 OP_PICK OP_NUMNOTEQUAL
        for _ in 0..5 {7 OP_ROLL}
    }
}
pub fn serial(count: u32, initial: u8) -> Script {
    serial_with_step(count, initial, bit_step())
}
pub fn serial_with_step(count: u32, initial: u8, step: Script) -> Script {
    script! {
        for bit in 0..8 { {(initial>>bit)&1} }
        for _ in 0..count {
            8 OP_ROLL {guard()}
            for weight in [8,4,2,1] {
                OP_DUP {weight} OP_GREATERTHANOREQUAL OP_TUCK
                OP_IF {weight} OP_SUB OP_ENDIF
            }
            OP_DROP
            for _ in 0..4 {OP_TOALTSTACK}
            for _ in 0..4 {OP_FROMALTSTACK {step.clone()}}
        }
        for _ in 0..7 {OP_DUP OP_ADD OP_ADD}
    }
}
