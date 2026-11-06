use super::{script, Script};

/// Split a score below 16*stride into its four-bit quotient and index.
pub(super) fn split_score(stride: u32) -> Script {
    script! {
        0 OP_SWAP
        for bit in (0..4).rev() {
            OP_DUP {stride << bit} OP_GREATERTHANOREQUAL
            OP_IF
                {stride << bit} OP_SUB
                OP_SWAP {1u32 << bit} OP_ADD OP_SWAP
            OP_ENDIF
        }
    }
}
