use super::{script, Script};

fn verify_width() -> Script {
    script! { OP_SIZE 4 OP_LESSTHANOREQUAL OP_VERIFY }
}

// Check the three numeric items and arrange q below the two addends.
pub(super) fn prepare() -> Script {
    script! {
        { verify_width() } OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
        OP_ROT { verify_width() }
        OP_ROT { verify_width() }
    }
}

// From q sum, append q + (q+1) as an opaque canonical arithmetic result.
pub(super) fn push_odd_candidate() -> Script {
    script! {
        OP_OVER { i32::MAX as i64 } OP_LESSTHAN OP_VERIFY
        OP_OVER OP_DUP OP_1ADD OP_ADD
    }
}
