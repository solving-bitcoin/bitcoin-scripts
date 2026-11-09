use super::{script, verify_canonical, Script};

pub(super) fn initial_depth(n: u32) -> Script {
    script! {
        OP_DUP 0 {n} OP_WITHIN OP_VERIFY {verify_canonical()}
        {n} OP_SWAP OP_SUB
    }
}

pub(super) fn wrap_depth(limit: u32) -> Script {
    script! {
        OP_DUP {limit} OP_NUMEQUAL
        OP_IF OP_DROP 0 OP_ENDIF
    }
}
