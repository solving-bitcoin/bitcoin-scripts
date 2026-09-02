use crate::support::script::*;

use super::{
    u31_add, u31_double, u31_mul_by_constant, u31_mul_common, u31_sub, u31_to_bits, U31Config,
};

/// Configuration for a degree-`DEGREE` extension over a 31-bit base field.
pub trait U31ExtConfig {
    type BaseFieldConfig: U31Config;
    const DEGREE: u32;

    fn mul_impl() -> Script;
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
