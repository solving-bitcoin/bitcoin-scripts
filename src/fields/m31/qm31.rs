//! Degree-four M31 extension configuration.

use crate::{
    arithmetic::u31::{karatsuba_complex_big, u31_add, u31_double, u31_sub, U31ExtConfig},
    fields::m31::u31::M31,
    support::script::*,
};

/// `F_(p²)[y]/(y² - 2 - i)` over `F_p[i]/(i² + 1)`.
pub struct QM31;

impl U31ExtConfig for QM31 {
    type BaseFieldConfig = M31;
    const DEGREE: u32 = 4;

    fn mul_impl() -> Script {
        script! {
            { karatsuba_complex_big::<M31>() }
            4 OP_ROLL
            OP_DUP
            { u31_double::<M31>() }
            6 OP_ROLL
            OP_DUP
            { u31_double::<M31>() }
            OP_ROT
            OP_ROT
            { u31_sub::<M31>() }
            3 OP_ROLL
            { u31_add::<M31>() }
            OP_ROT
            OP_ROT
            { u31_add::<M31>() }
            OP_ROT
            { u31_add::<M31>() }
            OP_SWAP
        }
    }
}
