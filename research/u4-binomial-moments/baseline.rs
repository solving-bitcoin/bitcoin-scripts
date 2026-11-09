mod recurrence {
    include!("../../src/arithmetic/u4/binomial_moments/recurrence.rs");
}

pub fn eager(n: u32) -> Script {
    script! {
        0 0 0 OP_TOALTSTACK
        for _ in 0..n {{recurrence::advance()}}
        OP_FROMALTSTACK
    }
}

pub fn direct(n: u32) -> Script {
    script! {
        0 0 0 OP_TOALTSTACK
        for position in (0..n).rev() {
            2 OP_ROLL {recurrence::centered_nibble()}
            OP_DUP {mul_by_constant(position*position.saturating_sub(1)/2)}
            OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
            OP_DUP {mul_by_constant(position)}
            OP_ROT OP_ADD
            OP_TOALTSTACK OP_ADD OP_FROMALTSTACK
        }
        OP_FROMALTSTACK
    }
}
