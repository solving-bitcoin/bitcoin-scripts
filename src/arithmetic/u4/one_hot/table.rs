use super::{script, Script, U4_ONE_HOT_TABLE_ITEMS};

pub fn push_one_hot_table() -> Script {
    script! {
        for value in (0..U4_ONE_HOT_TABLE_ITEMS).rev() {
            { 1u32 << value }
        }
    }
}
