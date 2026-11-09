use super::{mul_by_constant, script, verify_canonical_byte, Script};

pub(super) fn verify_word() -> Script {
    script! {
        for _ in 0..4 {
            3 OP_ROLL {verify_canonical_byte()}
        }
    }
}

/// Compute b0 + hi*b1 + lo*b2 + b3 from the four checked big-endian bytes.
pub(super) fn weighted_sum(hi: i32, lo: i32) -> Script {
    script! {
        OP_SWAP {mul_by_constant(lo.unsigned_abs())}
        if lo < 0 { OP_SUB } else { OP_ADD }
        OP_SWAP {mul_by_constant(hi.unsigned_abs())}
        if hi < 0 { OP_SUB } else { OP_ADD }
        OP_ADD
    }
}

pub(super) fn reduce_nonnegative(modulus: u32, upper: u32) -> Script {
    let quotient = upper / modulus;
    let steps = (0..u32::BITS - quotient.leading_zeros())
        .rev()
        .map(|bit| modulus << bit);
    script! {
        for step in steps {
            OP_DUP {step} OP_GREATERTHANOREQUAL
            OP_IF {step} OP_SUB OP_ENDIF
        }
    }
}
