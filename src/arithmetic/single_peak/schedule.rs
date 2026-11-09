use super::{script, Script};

fn verify_width() -> Script {
    script! { OP_SIZE 4 OP_LESSTHANOREQUAL OP_VERIFY }
}

// Check the rightmost strict descent and put the zero ascent count on alt.
pub(super) fn start() -> Script {
    script! {
        { verify_width() }
        OP_SWAP { verify_width() } OP_SWAP
        OP_OVER OP_SWAP OP_GREATERTHAN OP_VERIFY
        0 OP_TOALTSTACK
    }
}

// Check the next left value and leave it with the left-to-right ascent bit.
pub(super) fn strict_ascent() -> Script {
    script! {
        OP_SWAP { verify_width() } OP_SWAP
        OP_2DUP OP_NUMNOTEQUAL OP_VERIFY
        OP_OVER OP_SWAP OP_LESSTHAN
    }
}

pub(super) fn finish() -> Script {
    script! { OP_DROP OP_FROMALTSTACK OP_DUP OP_VERIFY }
}
