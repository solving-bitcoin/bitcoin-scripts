use super::{script, Script};

// Check one raw item against script constants and preserve the item.
pub(super) fn verify_any_match<const WIDTH: usize>(entries: &[[u8; WIDTH]]) -> Script {
    script! {
        0
        for entry in entries {
            OP_OVER { entry.to_vec() } OP_EQUAL OP_BOOLOR
        }
        OP_VERIFY
    }
}
