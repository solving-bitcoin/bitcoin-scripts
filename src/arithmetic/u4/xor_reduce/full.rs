use super::{script, u4_drop, u4_push_full_xor_table, Script, U4_XOR_TABLE_ITEMS};

pub(super) fn reduce_with_validation(nibble_count: u32, validate: Script) -> Script {
    script! {
        for _ in 0..nibble_count {
            {validate.clone()}
            OP_TOALTSTACK
        }
        {u4_push_full_xor_table()}
        for _ in 0..nibble_count {
            OP_FROMALTSTACK
        }
        for reduction in 1..nibble_count {
            OP_SWAP
            for _ in 0..4 {
                OP_DUP OP_ADD
            }
            OP_SWAP OP_ADD
            {nibble_count - reduction - 1}
            OP_ADD
            OP_PICK
        }
        OP_TOALTSTACK
        {u4_drop(U4_XOR_TABLE_ITEMS)}
        OP_FROMALTSTACK
    }
}
