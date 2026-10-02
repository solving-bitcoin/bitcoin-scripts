//! Comparison-only left-to-right Horner scheduler; not a public primitive.
use bitcoin_lab::arithmetic::u4::stack::verify_canonical_nibble;
use bitcoin_lab::support::script::{script, Script};

pub fn forward_horner(n: u32) -> Script {
    assert!(n > 0);
    script! {
        0 OP_TOALTSTACK
        for remaining in (0..n).rev() {
            { remaining } OP_ROLL
            { verify_canonical_nibble() }
            OP_FROMALTSTACK OP_SUB
            OP_DUP 0 OP_LESSTHAN
            OP_IF 17 OP_ADD OP_ENDIF
            OP_TOALTSTACK
        }
        OP_FROMALTSTACK
    }
}
