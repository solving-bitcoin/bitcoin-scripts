use crate::script::*;

use super::{u31_add, u31_mul, u31_sub, U31Config};

/// Multiply two degree-one polynomials using three base-field products.
///
/// Input, deepest to top: `a1, b1, a2, b2`.
/// Output, deepest to top: `a1*a2`, `a1*b2 + a2*b1`, `b1*b2`.
pub fn karatsuba_small<C: U31Config>() -> Script {
    script! {
        OP_OVER 4 OP_PICK
        { u31_mul::<C>() }
        OP_TOALTSTACK
        OP_DUP
        3 OP_PICK
        { u31_mul::<C>() }
        OP_TOALTSTACK
        { u31_add::<C>() }
        OP_TOALTSTACK
        { u31_add::<C>() }
        OP_FROMALTSTACK
        { u31_mul::<C>() }
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_2DUP
        { u31_add::<C>() }
        3 OP_ROLL
        OP_SWAP
        { u31_sub::<C>() }
        OP_ROT
    }
}

/// Double Karatsuba for two degree-three polynomials.
///
/// Input, deepest to top: `a1,b1,c1,d1,a2,b2,c2,d2`. The nine output
/// coefficients are the three-coefficient low, cross, and high products.
pub fn karatsuba_big<C: U31Config>() -> Script {
    script! {
        7 OP_PICK
        7 OP_PICK
        5 OP_PICK
        5 OP_PICK
        { karatsuba_small::<C>() }
        OP_TOALTSTACK
        OP_TOALTSTACK
        OP_TOALTSTACK
        OP_2DUP
        7 OP_PICK
        7 OP_PICK
        { karatsuba_small::<C>() }
        OP_TOALTSTACK
        OP_TOALTSTACK
        OP_TOALTSTACK
        OP_ROT
        { u31_add::<C>() }
        OP_TOALTSTACK
        { u31_add::<C>() }
        OP_TOALTSTACK
        OP_ROT
        { u31_add::<C>() }
        OP_TOALTSTACK
        { u31_add::<C>() }
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        { karatsuba_small::<C>() }
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        8 OP_ROLL
        3 OP_PICK
        7 OP_PICK
        { u31_add::<C>() }
        { u31_sub::<C>() }
        8 OP_ROLL
        3 OP_PICK
        7 OP_PICK
        { u31_add::<C>() }
        { u31_sub::<C>() }
        8 OP_ROLL
        3 OP_PICK
        7 OP_PICK
        { u31_add::<C>() }
        { u31_sub::<C>() }
        8 OP_ROLL
        8 OP_ROLL
        8 OP_ROLL
    }
}

/// Karatsuba multiplication over a quadratic extension with `i^2 = -1`.
///
/// Input, deepest to top: `a1,b1,a2,b2`, representing `a + b*i`.
/// Output, deepest to top: imaginary part, real part.
pub fn karatsuba_complex_small<C: U31Config>() -> Script {
    script! {
        OP_OVER 4 OP_PICK
        { u31_mul::<C>() }
        OP_TOALTSTACK
        OP_DUP
        3 OP_PICK
        { u31_mul::<C>() }
        OP_TOALTSTACK
        { u31_add::<C>() }
        OP_TOALTSTACK
        { u31_add::<C>() }
        OP_FROMALTSTACK
        { u31_mul::<C>() }
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_2DUP
        { u31_add::<C>() }
        3 OP_ROLL
        OP_SWAP
        { u31_sub::<C>() }
        OP_TOALTSTACK
        { u31_sub::<C>() }
        OP_FROMALTSTACK
        OP_SWAP
    }
}

/// Double Karatsuba over the quadratic extension with `i^2 = -1`.
pub fn karatsuba_complex_big<C: U31Config>() -> Script {
    script! {
        7 OP_PICK
        7 OP_PICK
        5 OP_PICK
        5 OP_PICK
        { karatsuba_complex_small::<C>() }
        OP_TOALTSTACK
        OP_TOALTSTACK
        OP_2DUP
        7 OP_PICK
        7 OP_PICK
        { karatsuba_complex_small::<C>() }
        OP_TOALTSTACK
        OP_TOALTSTACK
        OP_ROT
        { u31_add::<C>() }
        OP_TOALTSTACK
        { u31_add::<C>() }
        OP_TOALTSTACK
        OP_ROT
        { u31_add::<C>() }
        OP_TOALTSTACK
        { u31_add::<C>() }
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        { karatsuba_complex_small::<C>() }
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        5 OP_ROLL
        2 OP_PICK
        5 OP_PICK
        { u31_add::<C>() }
        { u31_sub::<C>() }
        5 OP_ROLL
        2 OP_PICK
        5 OP_PICK
        { u31_add::<C>() }
        { u31_sub::<C>() }
        5 OP_ROLL
        5 OP_ROLL
    }
}
