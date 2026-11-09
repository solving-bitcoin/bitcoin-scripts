use super::{script, Script};

pub(super) fn verify_bit() -> Script {
    script! {
        OP_DUP 0 OP_EQUAL
        OP_OVER 1 OP_EQUAL
        OP_BOOLOR OP_VERIFY
    }
}
