//! Degree-four BabyBear extension configuration.

use crate::{
    arithmetic::u31::{karatsuba_big, u31_add, u31_double, u31_sub, U31ExtConfig},
    fields::babybear::u31::BabyBear,
    support::script::*,
};

/// Degree-four BabyBear extension using the RISC Zero polynomial `x^4 + 11`.
pub struct BabyBear4;

impl BabyBear4 {
    fn mul_minus_11() -> Script {
        script! {
            OP_DUP
            { u31_double::<BabyBear>() }
            { u31_double::<BabyBear>() }
            OP_DUP
            { u31_double::<BabyBear>() }
            { u31_add::<BabyBear>() }
            { u31_sub::<BabyBear>() }
        }
    }
}

impl U31ExtConfig for BabyBear4 {
    type BaseFieldConfig = BabyBear;
    const DEGREE: u32 = 4;

    fn mul_impl() -> Script {
        script! {
            { karatsuba_big::<BabyBear>() }
            6 OP_ROLL
            6 OP_ROLL
            { u31_add::<BabyBear>() }
            { Self::mul_minus_11() }
            { u31_add::<BabyBear>() }
            5 OP_ROLL
            { Self::mul_minus_11() }
            2 OP_ROLL
            { u31_add::<BabyBear>() }
            5 OP_ROLL
            { Self::mul_minus_11() }
            3 OP_ROLL
            4 OP_ROLL
            { u31_add::<BabyBear>() }
            { u31_add::<BabyBear>() }
            OP_SWAP
            OP_ROT
        }
    }
}
