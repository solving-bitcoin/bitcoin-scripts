//! Research-only matched forward routing and explicit numeric flag guards.
use bitcoin_lab::{arithmetic::scriptint::verify_canonical, support::script::*};
pub fn flag() -> Script {
    script! {OP_DUP 0 2 OP_WITHIN OP_VERIFY{verify_canonical()}}
}
pub fn backward_explicit(n: u32) -> Script {
    assert!(n <= 500);
    script! {
        0
        for _ in 0..n {
            OP_SWAP {flag()} OP_IF
                OP_SWAP OP_TOALTSTACK OP_1ADD
            OP_ELSE OP_SWAP OP_DROP OP_ENDIF
        }
        for i in 0..n {
            OP_DUP {i} OP_GREATERTHAN
            OP_IF OP_FROMALTSTACK OP_SWAP OP_ENDIF
        }
    }
}
pub fn forward_native(n: u32) -> Script {
    forward(n, false)
}
pub fn forward_explicit(n: u32) -> Script {
    forward(n, true)
}
fn forward(n: u32, explicit: bool) -> Script {
    assert!(n <= 500);
    script! {
        0
        for i in 0..n {
            {2*(n-i)-1} OP_ROLL if explicit{{flag()}} OP_IF
                {2*(n-i)-1} OP_ROLL OP_TOALTSTACK OP_1ADD
            OP_ELSE {2*(n-i)-1} OP_ROLL OP_DROP OP_ENDIF
        }
        for i in 0..n {
            OP_DUP {i} OP_GREATERTHAN
            OP_IF OP_FROMALTSTACK OP_SWAP OP_ENDIF
        }
        for i in 1..n {
            OP_DUP {i} OP_GREATERTHAN
            OP_IF {i+1} OP_ROLL OP_SWAP OP_ENDIF
        }
    }
}
