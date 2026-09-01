use crate::support::script::*;

use super::{
    karatsuba_big, karatsuba_complex_big, u31_add, u31_double, u31_mul_by_constant, u31_mul_common,
    u31_sub, u31_to_bits, BabyBear, U31Config, M31,
};

/// Configuration for a degree-`DEGREE` extension over a 31-bit base field.
pub trait U31ExtConfig {
    type BaseFieldConfig: U31Config;
    const DEGREE: u32;

    fn mul_impl() -> Script;
}

/// Degree-four M31 extension built as `F_(p²)[y]/(y² - 2 - i)` over
/// `F_p[i]/(i² + 1)`.
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

/// Add two extension-field elements coefficient-wise.
pub fn u31ext_add<C: U31ExtConfig>() -> Script {
    script! {
        for i in 0..C::DEGREE - 1 {
            { C::DEGREE - i } OP_ROLL
            { u31_add::<C::BaseFieldConfig>() }
            OP_TOALTSTACK
        }
        { u31_add::<C::BaseFieldConfig>() }
        for _ in 0..C::DEGREE - 1 {
            OP_FROMALTSTACK
        }
    }
}

/// Verify equality of two extension-field elements, consuming both.
pub fn u31ext_equalverify<C: U31ExtConfig>() -> Script {
    script! {
        for i in 0..C::DEGREE - 1 {
            { C::DEGREE - i } OP_ROLL
            OP_EQUALVERIFY
        }
        OP_EQUALVERIFY
    }
}

/// Subtract two extension-field elements coefficient-wise.
pub fn u31ext_sub<C: U31ExtConfig>() -> Script {
    script! {
        for i in 0..C::DEGREE - 1 {
            { C::DEGREE - i } OP_ROLL
            OP_SWAP
            { u31_sub::<C::BaseFieldConfig>() }
            OP_TOALTSTACK
        }
        { u31_sub::<C::BaseFieldConfig>() }
        for _ in 0..C::DEGREE - 1 {
            OP_FROMALTSTACK
        }
    }
}

/// Double an extension-field element coefficient-wise.
pub fn u31ext_double<C: U31ExtConfig>() -> Script {
    script! {
        for _ in 0..C::DEGREE - 1 {
            { u31_double::<C::BaseFieldConfig>() }
            OP_TOALTSTACK
        }
        { u31_double::<C::BaseFieldConfig>() }
        for _ in 0..C::DEGREE - 1 {
            OP_FROMALTSTACK
        }
    }
}

/// Multiply two extension-field elements.
pub fn u31ext_mul<C: U31ExtConfig>() -> Script {
    C::mul_impl()
}

/// Multiply a degree-four extension element by a witness-supplied base-field
/// element, reusing one bit decomposition across all four coefficients.
pub fn u31ext_mul_u31<C: U31ExtConfig>() -> Script {
    assert_eq!(
        C::DEGREE,
        4,
        "shared-decomposition helper requires degree four"
    );

    script! {
        { u31_to_bits() }

        // Make four copies of the 31-bit decomposition, three on the main
        // stack and one on the altstack at a time.
        for _ in 0..31 {
            30 OP_PICK
        }
        for _ in 0..31 {
            OP_TOALTSTACK
        }
        for _ in 0..31 {
            30 OP_PICK
        }
        for _ in 0..31 {
            OP_TOALTSTACK
        }
        for _ in 0..31 {
            30 OP_PICK
        }
        for _ in 0..31 {
            OP_TOALTSTACK
        }
        for _ in 0..31 {
            OP_TOALTSTACK
        }

        3 OP_ROLL
        { u31_mul_common::<C::BaseFieldConfig>() }
        3 OP_ROLL
        { u31_mul_common::<C::BaseFieldConfig>() }
        3 OP_ROLL
        { u31_mul_common::<C::BaseFieldConfig>() }
        3 OP_ROLL
        { u31_mul_common::<C::BaseFieldConfig>() }
    }
}

/// Multiply every coefficient by the same generation-time base-field
/// constant.
pub fn u31ext_mul_u31_by_constant<C: U31ExtConfig>(constant: u32) -> Script {
    assert_eq!(C::DEGREE, 4, "constant helper requires degree four");

    script! {
        OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK
        { u31_mul_by_constant::<C::BaseFieldConfig>(constant) }
        OP_FROMALTSTACK
        { u31_mul_by_constant::<C::BaseFieldConfig>(constant) }
        OP_FROMALTSTACK
        { u31_mul_by_constant::<C::BaseFieldConfig>(constant) }
        OP_FROMALTSTACK
        { u31_mul_by_constant::<C::BaseFieldConfig>(constant) }
    }
}

/// Move one extension element to the altstack.
pub fn u31ext_toaltstack<C: U31ExtConfig>() -> Script {
    script! {
        for _ in 0..C::DEGREE {
            OP_TOALTSTACK
        }
    }
}

/// Restore one extension element from the altstack.
pub fn u31ext_fromaltstack<C: U31ExtConfig>() -> Script {
    script! {
        for _ in 0..C::DEGREE {
            OP_FROMALTSTACK
        }
    }
}

/// Copy the extension element at `offset`, where zero denotes the top element.
pub fn u31ext_copy<C: U31ExtConfig>(offset: usize) -> Script {
    let depth = offset * C::DEGREE as usize + C::DEGREE as usize - 1;
    script! {
        for _ in 0..C::DEGREE {
            { depth } OP_PICK
        }
    }
}

/// Roll the extension element at `offset` to the top.
pub fn u31ext_roll<C: U31ExtConfig>(offset: usize) -> Script {
    let depth = offset * C::DEGREE as usize + C::DEGREE as usize - 1;
    script! {
        for _ in 0..C::DEGREE {
            { depth } OP_ROLL
        }
    }
}
