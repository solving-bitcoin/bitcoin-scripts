#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::treepp::{script, Script};

pub fn OP_CHECKSEQUENCEVERIFY() -> Script {
    script! {OP_CSV}
}

pub fn OP_4PICK() -> Script {
    script! {
        4 OP_ADD
        OP_DUP  OP_PICK OP_SWAP
        OP_DUP  OP_PICK OP_SWAP
        OP_DUP  OP_PICK OP_SWAP
        OP_1SUB OP_PICK
    }
}

pub fn OP_4ROLL() -> Script {
    script! {
        4 OP_ADD
        OP_DUP  OP_ROLL OP_SWAP
        OP_DUP  OP_ROLL OP_SWAP
        OP_DUP  OP_ROLL OP_SWAP
        OP_1SUB OP_ROLL
    }
}

pub fn OP_4DUP() -> Script {
    script! {
        OP_2OVER OP_2OVER
    }
}

pub fn OP_4DROP() -> Script {
    script! {
        OP_2DROP OP_2DROP
    }
}

pub fn OP_4SWAP() -> Script {
    script! {
        7 OP_ROLL 7 OP_ROLL
        7 OP_ROLL 7 OP_ROLL
    }
}

pub fn OP_4TOALTSTACK() -> Script {
    script! {
        OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK
    }
}

pub fn OP_4FROMALTSTACK() -> Script {
    script! {
        OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
    }
}

pub fn OP_2MUL() -> Script {
    script! {
        OP_DUP OP_ADD
    }
}

pub fn OP_4MUL() -> Script {
    script! {
        OP_DUP OP_ADD OP_DUP OP_ADD
    }
}

pub fn op_2k_mul(k: u32) -> Script {
    script! {
        for _ in 0..k{
            {OP_2MUL()}
        }
    }
}

pub fn OP_16MUL() -> Script {
    script! {
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
    }
}

pub fn OP_256MUL() -> Script {
    script! {
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
    }
}

pub fn OP_NDUP(n: usize) -> Script {
    let times_3_dup = if n > 3 { (n - 3) / 3 } else { 0 };
    let remaining = if n > 3 { (n - 3) % 3 } else { 0 };

    script! {
        if n >= 1 {
            OP_DUP
        }
        if n >= 3 {
            OP_2DUP
        }
        else if n >= 2{
            OP_DUP
        }
        for _ in 0..times_3_dup {
            OP_3DUP
        }
        if remaining == 2{
            OP_2DUP
        }
        else if remaining == 1{
            OP_DUP
        }
    }
}

pub fn push_to_stack(element: usize, n: usize) -> Script {
    script! {
        if n >= 1{
                {element} {OP_NDUP(n - 1)}
        }
    }
}

#[deprecated(note = "use arithmetic::scriptint::mul_by_constant")]
pub fn NMUL(multiplier: u32) -> Script {
    crate::arithmetic::scriptint::mul_by_constant(multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run;
    use crate::u32::stack::u32_equal;

    #[test]
    fn op_4pick_copies_top_and_deeper_groups() {
        let pick_top = script! {
            1 2 3 4
            0
            { OP_4PICK() }
            1 2 3 4
            { u32_equal() }
            OP_TOALTSTACK
            OP_2DROP OP_2DROP
            OP_FROMALTSTACK
        };
        let pick_below_top = script! {
            1 2 3 4
            5 6 7 8
            4
            { OP_4PICK() }
            1 2 3 4
            { u32_equal() }
            OP_TOALTSTACK
            OP_2DROP OP_2DROP
            OP_2DROP OP_2DROP
            OP_FROMALTSTACK
        };

        run(pick_top);
        run(pick_below_top);
    }

    #[test]
    #[allow(deprecated)]
    fn nmul_compatibility_wrapper() {
        run(script! {
            7
            { NMUL(13) }
            91 OP_EQUAL
        });
    }
}
