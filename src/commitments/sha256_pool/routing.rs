use super::{script, verify_canonical, Script};

pub(super) fn push_digests(digests: &[[u8; 32]]) -> Script {
    script! {
        for digest in digests.iter().rev() {{digest.to_vec()}}
    }
}

pub(super) fn check_rank(bound: usize) -> Script {
    script! {
        OP_DUP 0 {bound} OP_WITHIN OP_VERIFY
        {verify_canonical()}
    }
}
