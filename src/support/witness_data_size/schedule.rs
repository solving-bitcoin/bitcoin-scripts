use bitcoin::VarInt;

use super::{script, Script};

pub(super) const LONG_COMPACTSIZE: u32 = 253;

pub(super) fn fixed_bytes(items: u32) -> u32 {
    items + VarInt(u64::from(items)).size() as u32
}

/// Preserve the fixed suffix while accumulating its serialized size.
pub(super) fn check_with(items: u32, cap: u32, surcharge: Script) -> Script {
    script! {
        {fixed_bytes(items)}
        for depth in 1..=items {
            {depth} OP_PICK OP_SIZE OP_NIP
            {surcharge.clone()}
            OP_ADD
        }
        {cap} OP_LESSTHANOREQUAL OP_VERIFY
    }
}
