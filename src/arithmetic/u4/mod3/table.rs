use super::{script, Script, U4_MOD3_TABLE_ITEMS};

pub fn push_mod3_table() -> Script {
    script! {
        for value in (0..U4_MOD3_TABLE_ITEMS).rev() {
            { value % 3 }
        }
    }
}

/// Project the batch into the altstack in reverse, leaving the table in place.
pub fn mod3_to_altstack(nibble_count: u32, validate: Script) -> Script {
    script! {
        for _ in 0..nibble_count {
            { U4_MOD3_TABLE_ITEMS } OP_ROLL
            { validate.clone() }
            OP_PICK OP_TOALTSTACK
        }
    }
}
