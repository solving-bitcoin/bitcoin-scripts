use super::{script, Script};

pub(super) fn batch(width: u32, pair: Script) -> Script {
    script! {
        for _ in 1..width {
            { pair.clone() } OP_TOALTSTACK
        }
        { pair }
        for _ in 1..width {
            OP_FROMALTSTACK
        }
    }
}
