use super::{script, verify_canonical, Script};

pub(super) fn verify_input() -> Script {
    script! {
        OP_SIZE 4 OP_LESSTHANOREQUAL OP_VERIFY
        { verify_canonical() }
    }
}

pub(super) fn order_pair() -> Script {
    script! {
        { verify_input() } OP_SWAP { verify_input() }
        OP_2DUP OP_GREATERTHAN OP_IF OP_SWAP OP_ENDIF
    }
}

pub(super) fn update_single() -> Script {
    script! {
        OP_ROT { verify_input() }
        OP_TUCK OP_MAX OP_TOALTSTACK OP_MIN OP_FROMALTSTACK
    }
}
