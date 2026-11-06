use super::{
    push_one_hot_table, script, u4_drop, verify_canonical_nibble, Script, U4_ONE_HOT_TABLE_ITEMS,
};

pub(super) fn sum_one_hot(n: u32) -> Script {
    script! {
        if n == 0 {
            0
        } else {
            {push_one_hot_table()}
            0
            for _ in 0..n {
                {U4_ONE_HOT_TABLE_ITEMS + 1} OP_ROLL {verify_canonical_nibble()}
                OP_1ADD OP_PICK OP_ADD
            }
            OP_TOALTSTACK {u4_drop(U4_ONE_HOT_TABLE_ITEMS)} OP_FROMALTSTACK
        }
    }
}
