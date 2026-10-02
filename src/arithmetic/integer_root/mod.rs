//! Integer floor roots using a residual and fixed root-bit trials.
use crate::{arithmetic::scriptint::mul_by_constant, support::script::*};

/// Consume one at-most-four-byte ScriptNum in `0..=2^bit_count-1` and return
/// its canonical integer floor square root. Both caller stacks are preserved.
///
/// `bit_count` is in 1..=31. Every hostile input is numerically range checked;
/// nonminimal aliases are allowed when the execution profile permits them.
/// There are no witness hints. The caller binds the result and supplies a
/// terminal predicate; a zero root is valid data but a false bare predicate.
///
/// State is residual `x-r*r` and root r. A trial bit b is accepted precisely
/// when residual >= `(r+b)^2-r^2 = 2*r*b+b*b`. Every intermediate fits the
/// four-byte numeric domain, even at bit_count=31. Combined peak is at most five
/// items including the input; add all caller main/alt state and future inputs.
pub fn scriptnum_isqrt(bit_count: u32) -> Script {
    assert!(
        (1..=31).contains(&bit_count),
        "integer root width must be in 1..=31"
    );
    let maximum = (1u32 << bit_count) - 1;
    let root_bits = (bit_count + 1) / 2;
    script! {
        OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
        OP_DUP {maximum} OP_LESSTHANOREQUAL OP_VERIFY
        0
        for bit in (0..root_bits).rev() {
            OP_DUP {mul_by_constant(2*(1u32<<bit))} {(1u32<<bit).pow(2)} OP_ADD
            2 OP_PICK OP_OVER OP_GREATERTHANOREQUAL
            OP_IF
                OP_ROT OP_SWAP OP_SUB OP_SWAP {1u32<<bit} OP_ADD
            OP_ELSE
                OP_DROP
            OP_ENDIF
        }
        OP_NIP
    }
}
