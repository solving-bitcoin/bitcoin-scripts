use super::{script, verify_canonical_nibble, Script};

pub(super) fn centered_nibble() -> Script {
    script! {{verify_canonical_nibble()} 8 OP_SUB}
}

/// Main: `... x M0 M1`. Alt: `... M2`.
/// Update from the old lower moments before adding x to M0.
pub(super) fn advance() -> Script {
    script! {
        OP_FROMALTSTACK OP_OVER OP_ADD OP_TOALTSTACK
        OP_OVER OP_ADD
        OP_SWAP 2 OP_ROLL {centered_nibble()} OP_ADD OP_SWAP
    }
}
