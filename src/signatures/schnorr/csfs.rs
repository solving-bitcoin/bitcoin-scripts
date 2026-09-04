//! Explicit BIP340 check-signature-from-stack research verifier.
//!
//! The locking script is specialized only to an x-only public key. The
//! message, `r`, `s`, lifted nonce point, and all arithmetic hints are hostile
//! witness data. Unlike the fixed-instance certificate in the parent module,
//! this construction computes the BIP340 challenge in Script and verifies the
//! complete `sG - challenge*P = R` multi-scalar multiplication.

use bitcoin::hashes::{sha256, Hash};
use num_bigint::BigUint;

use crate::{
    arithmetic::{bigint::U256, scriptint},
    fields::secp256k1::bigint9::{self as field, MulHints, SquareHints},
    hashes::sha256::sha2_u4,
    support::script::*,
};

use super::{
    add_mod, generator, group_order, lift_x, mul_mod, negate_point, point_add, sub_mod, AffinePoint,
};

const RADIX: i32 = 512;
const LINEAR_CARRY_COUNT: usize = field::FIELD_DIGIT_COUNT - 1;
const WINDOW_BITS: usize = 8;
const WINDOW_COUNT: usize = 256usize.div_ceil(WINDOW_BITS);

/// The witness encodes each 32-byte input as nine unsigned 29-bit limbs.
pub const U256_LIMBS: usize = U256::N_LIMBS as usize;

/// Errors detected while constructing a public-key-specialized verifier or an
/// honest hint witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CsfsError {
    InvalidPublicKey,
    InvalidNonce,
    GeneratorPrefixMismatch,
}

/// Signature-independent locking script specialized to one BIP340 public key.
#[derive(Clone, Debug)]
pub struct CsfsVerifier {
    script: Script,
    public_key: [u8; 32],
    generator_low32_leaf: Option<u32>,
}

impl CsfsVerifier {
    pub fn script(&self) -> Script {
        self.script.clone()
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Produce the expanded hostile witness for a message/signature pair.
    /// The signature itself is not compiled into [`Self::script`].
    pub fn witness(
        &self,
        message: [u8; 32],
        signature: [u8; 64],
    ) -> Result<Vec<Vec<u8>>, CsfsError> {
        build_witness(
            self.public_key,
            message,
            signature,
            self.generator_low32_leaf,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LinearHints {
    result: BigUint,
    quotient: i32,
    carries: [i32; LINEAR_CARRY_COUNT],
}

fn modulus_digits() -> [i32; field::FIELD_DIGIT_COUNT] {
    // p = 16*512^28 - 32*512^3 - 2*512 + 47.
    let mut digits = [0i32; field::FIELD_DIGIT_COUNT];
    digits[0] = 47;
    digits[1] = -2;
    digits[3] = -32;
    digits[28] = 16;
    digits
}

fn hinted_linear(lhs: &BigUint, rhs: &BigUint, subtract: bool) -> LinearHints {
    let p = field::modulus();
    assert!(lhs < &p && rhs < &p);
    let result = if subtract {
        sub_mod(lhs, rhs, &p)
    } else {
        add_mod(lhs, rhs, &p)
    };
    let quotient = if subtract {
        if lhs < rhs {
            -1
        } else {
            0
        }
    } else if lhs + rhs >= p {
        1
    } else {
        0
    };
    let lhs_digits = field::field_digits(lhs);
    let rhs_digits = field::field_digits(rhs);
    let result_digits = field::field_digits(&result);
    let p_digits = modulus_digits();
    let rhs_sign = if subtract { -1i64 } else { 1i64 };
    let mut previous = 0i64;
    let mut carries = [0i32; LINEAR_CARRY_COUNT];
    for index in 0..field::FIELD_DIGIT_COUNT {
        let coefficient = i64::from(lhs_digits[index]) + rhs_sign * i64::from(rhs_digits[index])
            - i64::from(result_digits[index])
            - i64::from(quotient) * i64::from(p_digits[index])
            + previous;
        if index < LINEAR_CARRY_COUNT {
            assert_eq!(coefficient % i64::from(RADIX), 0);
            previous = coefficient / i64::from(RADIX);
            carries[index] = i32::try_from(previous).expect("linear carry fits ScriptNum");
        } else {
            assert_eq!(coefficient, 0);
        }
    }
    LinearHints {
        result,
        quotient,
        carries,
    }
}

fn hinted_sub_two(lhs: &BigUint, rhs_1: &BigUint, rhs_2: &BigUint) -> LinearHints {
    let p = field::modulus();
    assert!(lhs < &p && rhs_1 < &p && rhs_2 < &p);
    let rhs_sum = rhs_1 + rhs_2;
    let (result, quotient) = if lhs >= &rhs_sum {
        (lhs - &rhs_sum, 0)
    } else if lhs + &p >= rhs_sum {
        (lhs + &p - &rhs_sum, -1)
    } else {
        (lhs + (&p << 1usize) - &rhs_sum, -2)
    };
    let lhs_digits = field::field_digits(lhs);
    let rhs_1_digits = field::field_digits(rhs_1);
    let rhs_2_digits = field::field_digits(rhs_2);
    let result_digits = field::field_digits(&result);
    let p_digits = modulus_digits();
    let mut previous = 0i64;
    let mut carries = [0i32; LINEAR_CARRY_COUNT];
    for index in 0..field::FIELD_DIGIT_COUNT {
        let coefficient = i64::from(lhs_digits[index])
            - i64::from(rhs_1_digits[index])
            - i64::from(rhs_2_digits[index])
            - i64::from(result_digits[index])
            - i64::from(quotient) * i64::from(p_digits[index])
            + previous;
        if index < LINEAR_CARRY_COUNT {
            assert_eq!(coefficient % i64::from(RADIX), 0);
            previous = coefficient / i64::from(RADIX);
            carries[index] = i32::try_from(previous).expect("linear carry fits ScriptNum");
        } else {
            assert_eq!(coefficient, 0);
        }
    }
    LinearHints {
        result,
        quotient,
        carries,
    }
}

fn hinted_scale_three(value: &BigUint) -> LinearHints {
    let p = field::modulus();
    assert!(value < &p);
    let unreduced = value * BigUint::from(3u8);
    let quotient = if unreduced >= (&p << 1usize) {
        2
    } else if unreduced >= p {
        1
    } else {
        0
    };
    let result = &unreduced % &p;
    let value_digits = field::field_digits(value);
    let result_digits = field::field_digits(&result);
    let p_digits = modulus_digits();
    let mut previous = 0i64;
    let mut carries = [0i32; LINEAR_CARRY_COUNT];
    for index in 0..field::FIELD_DIGIT_COUNT {
        let coefficient = 3 * i64::from(value_digits[index])
            - i64::from(result_digits[index])
            - i64::from(quotient) * i64::from(p_digits[index])
            + previous;
        if index < LINEAR_CARRY_COUNT {
            assert_eq!(coefficient % i64::from(RADIX), 0);
            previous = coefficient / i64::from(RADIX);
            carries[index] = i32::try_from(previous).expect("linear carry fits ScriptNum");
        } else {
            assert_eq!(coefficient, 0);
        }
    }
    LinearHints {
        result,
        quotient,
        carries,
    }
}

fn scriptnum_item(value: i32) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value));
    bytes[..length].to_vec()
}

fn append_field(witness: &mut Vec<Vec<u8>>, value: &BigUint) {
    witness.extend(
        field::field_digits(value)
            .iter()
            .rev()
            .map(|digit| scriptnum_item(*digit)),
    );
}

fn append_u256(witness: &mut Vec<Vec<u8>>, value: &BigUint) {
    witness.extend(
        U256::biguint_to_limbs(value.clone())
            .iter()
            .rev()
            .map(|limb| scriptnum_item(*limb as i32)),
    );
}

fn append_linear_hints(witness: &mut Vec<Vec<u8>>, hints: &LinearHints) {
    append_field(witness, &hints.result);
    witness.push(scriptnum_item(hints.quotient));
    witness.extend(
        hints
            .carries
            .iter()
            .rev()
            .map(|carry| scriptnum_item(*carry)),
    );
}

fn append_mul_hints(witness: &mut Vec<Vec<u8>>, hints: &MulHints) {
    witness.extend(hints.witness_items());
}

fn append_square_hints(witness: &mut Vec<Vec<u8>>, hints: &SquareHints) {
    witness.extend(hints.witness_items());
}

fn pull_bottom_items(count: usize) -> Script {
    script! {
        for _ in 0..count {
            OP_DEPTH OP_1SUB OP_ROLL
        }
    }
}

fn field_copy(mut depth: u32) -> Script {
    depth = (depth + 1) * field::FIELD_DIGIT_COUNT as u32 - 1;
    script! {
        if depth < 128 {
            for _ in 0..field::FIELD_DIGIT_COUNT {
                { depth } OP_PICK
            }
        } else {
            { depth + 1 }
            for _ in 0..field::FIELD_DIGIT_COUNT - 1 {
                OP_DUP OP_PICK OP_SWAP
            }
            OP_1SUB OP_PICK
        }
    }
}

fn field_copy_at_item_depth(mut depth: u32) -> Script {
    // Callers identify a field by the depth of its least-significant digit,
    // which is the top item of the 29-digit value. OP_PICK must start at the
    // most-significant digit so repeated picks reproduce the canonical order.
    depth += field::FIELD_DIGIT_COUNT as u32 - 1;
    script! {
        if depth < 128 {
            for _ in 0..field::FIELD_DIGIT_COUNT {
                { depth } OP_PICK
            }
        } else {
            { depth + 1 }
            for _ in 0..field::FIELD_DIGIT_COUNT - 1 {
                OP_DUP OP_PICK OP_SWAP
            }
            OP_1SUB OP_PICK
        }
    }
}

fn field_roll(mut depth: u32) -> Script {
    if depth == 0 {
        return script! {};
    }
    depth = (depth + 1) * field::FIELD_DIGIT_COUNT as u32 - 1;
    script! {
        for _ in 0..field::FIELD_DIGIT_COUNT {
            { depth } OP_ROLL
        }
    }
}

fn field_drop() -> Script {
    script! {
        for _ in 0..field::FIELD_DIGIT_COUNT / 2 { OP_2DROP }
        if field::FIELD_DIGIT_COUNT % 2 != 0 { OP_DROP }
    }
}

fn field_to_altstack() -> Script {
    script! { for _ in 0..field::FIELD_DIGIT_COUNT { OP_TOALTSTACK } }
}

fn field_from_altstack() -> Script {
    script! { for _ in 0..field::FIELD_DIGIT_COUNT { OP_FROMALTSTACK } }
}

fn field_copy_zip(mut lhs: u32, mut rhs: u32) -> Script {
    lhs = (lhs + 1) * field::FIELD_DIGIT_COUNT as u32 - 1;
    rhs = (rhs + 1) * field::FIELD_DIGIT_COUNT as u32 - 1;
    script! {
        for index in 0..field::FIELD_DIGIT_COUNT as u32 {
            { lhs + index } OP_PICK
            { rhs + index + 1 } OP_PICK
        }
    }
}

fn field_equal_keep(lhs: u32, rhs: u32) -> Script {
    script! {
        { field_copy_zip(lhs, rhs) }
        for _ in 0..field::FIELD_DIGIT_COUNT {
            OP_EQUAL OP_TOALTSTACK
        }
        for _ in 0..field::FIELD_DIGIT_COUNT { OP_FROMALTSTACK }
        for _ in 0..field::FIELD_DIGIT_COUNT - 1 { OP_BOOLAND }
    }
}

fn field_equalverify(mut lhs: u32, mut rhs: u32) -> Script {
    lhs = (lhs + 1) * field::FIELD_DIGIT_COUNT as u32 - 1;
    rhs = (rhs + 1) * field::FIELD_DIGIT_COUNT as u32 - 1;
    assert_ne!(lhs, rhs);
    if lhs < rhs {
        script! {
            for index in 0..field::FIELD_DIGIT_COUNT as u32 {
                { lhs + index } OP_ROLL
                { rhs } OP_ROLL
            }
            for _ in 0..field::FIELD_DIGIT_COUNT { OP_EQUALVERIFY }
        }
    } else {
        script! {
            for index in 0..field::FIELD_DIGIT_COUNT as u32 {
                { lhs } OP_ROLL
                { rhs + index + 1 } OP_ROLL
            }
            for _ in 0..field::FIELD_DIGIT_COUNT { OP_EQUALVERIFY }
        }
    }
}

fn field_is_zero_keep(depth: u32) -> Script {
    let digit_zero_depth = depth * field::FIELD_DIGIT_COUNT as u32;
    script! {
        1
        for index in 0..field::FIELD_DIGIT_COUNT as u32 {
            { digit_zero_depth + index + 1 } OP_PICK OP_NOT OP_BOOLAND
        }
    }
}

fn push_field(value: &BigUint) -> Script {
    let digits = field::field_digits(value);
    script! { for digit in digits.iter().rev() { { *digit } } }
}

fn push_zero_field() -> Script {
    script! { for _ in 0..field::FIELD_DIGIT_COUNT { 0 } }
}

fn verify_linear_relation(subtract: bool) -> Script {
    let p_digits = modulus_digits();
    let carry_count = LINEAR_CARRY_COUNT as u32;
    let quotient_depth = carry_count;
    let result_depth = carry_count + 1;
    let rhs_depth = result_depth + field::FIELD_DIGIT_COUNT as u32;
    let lhs_depth = rhs_depth + field::FIELD_DIGIT_COUNT as u32;
    script! {
        { quotient_depth } OP_PICK
        OP_DUP -2 2 OP_WITHIN OP_VERIFY
        OP_DROP

        for index in 0..field::FIELD_DIGIT_COUNT as u32 {
            { lhs_depth + index } OP_PICK
            { rhs_depth + index + 1 } OP_PICK
            if subtract { OP_SUB } else { OP_ADD }
            { result_depth + index + 1 } OP_PICK OP_SUB
            if p_digits[index as usize] != 0 {
                { quotient_depth + 1 } OP_PICK
                { scriptint::mul_by_constant(p_digits[index as usize].unsigned_abs()) }
                if p_digits[index as usize] < 0 { OP_NEGATE }
                OP_SUB
            }
            if index > 0 {
                { index } OP_PICK OP_ADD
            }
            if index < carry_count {
                { index + 1 } OP_PICK
                { scriptint::mul_by_constant(RADIX as u32) }
                OP_EQUALVERIFY
            } else {
                0 OP_EQUALVERIFY
            }
        }
    }
}

fn verify_sub_two_relation() -> Script {
    let p_digits = modulus_digits();
    let carry_count = LINEAR_CARRY_COUNT as u32;
    let quotient_depth = carry_count;
    let result_depth = carry_count + 1;
    let rhs_2_depth = result_depth + field::FIELD_DIGIT_COUNT as u32;
    let rhs_1_depth = rhs_2_depth + field::FIELD_DIGIT_COUNT as u32;
    let lhs_depth = rhs_1_depth + field::FIELD_DIGIT_COUNT as u32;
    script! {
        { quotient_depth } OP_PICK
        OP_DUP -3 1 OP_WITHIN OP_VERIFY
        OP_DROP

        for index in 0..field::FIELD_DIGIT_COUNT as u32 {
            { lhs_depth + index } OP_PICK
            { rhs_1_depth + index + 1 } OP_PICK OP_SUB
            { rhs_2_depth + index + 1 } OP_PICK OP_SUB
            { result_depth + index + 1 } OP_PICK OP_SUB
            if p_digits[index as usize] != 0 {
                { quotient_depth + 1 } OP_PICK
                { scriptint::mul_by_constant(p_digits[index as usize].unsigned_abs()) }
                if p_digits[index as usize] < 0 { OP_NEGATE }
                OP_SUB
            }
            if index > 0 {
                { index } OP_PICK OP_ADD
            }
            if index < carry_count {
                { index + 1 } OP_PICK
                { scriptint::mul_by_constant(RADIX as u32) }
                OP_EQUALVERIFY
            } else {
                0 OP_EQUALVERIFY
            }
        }
    }
}

fn verify_scale_three_relation() -> Script {
    let p_digits = modulus_digits();
    let carry_count = LINEAR_CARRY_COUNT as u32;
    let quotient_depth = carry_count;
    let result_depth = carry_count + 1;
    let value_depth = result_depth + field::FIELD_DIGIT_COUNT as u32;
    script! {
        { quotient_depth } OP_PICK
        OP_DUP 0 3 OP_WITHIN OP_VERIFY
        OP_DROP

        for index in 0..field::FIELD_DIGIT_COUNT as u32 {
            { value_depth + index } OP_PICK
            { scriptint::mul_by_constant(3) }
            { result_depth + index + 1 } OP_PICK OP_SUB
            if p_digits[index as usize] != 0 {
                { quotient_depth + 1 } OP_PICK
                { scriptint::mul_by_constant(p_digits[index as usize].unsigned_abs()) }
                if p_digits[index as usize] < 0 { OP_NEGATE }
                OP_SUB
            }
            if index > 0 {
                { index } OP_PICK OP_ADD
            }
            if index < carry_count {
                { index + 1 } OP_PICK
                { scriptint::mul_by_constant(RADIX as u32) }
                OP_EQUALVERIFY
            } else {
                0 OP_EQUALVERIFY
            }
        }
    }
}

fn linear_keep(lhs_depth: u32, rhs_depth: u32, subtract: bool) -> Script {
    script! {
        { field_copy(lhs_depth) }
        { field_copy(rhs_depth + 1) }
        { pull_bottom_items(
            field::FIELD_DIGIT_COUNT + 1 + LINEAR_CARRY_COUNT,
        ) }
        { field::certify_value_at_depth((1 + LINEAR_CARRY_COUNT) as u32) }
        { verify_linear_relation(subtract) }
        for _ in 0..(1 + LINEAR_CARRY_COUNT) / 2 { OP_2DROP }
        if (1 + LINEAR_CARRY_COUNT) % 2 != 0 { OP_DROP }
        { field_to_altstack() }
        { field_drop() }
        { field_drop() }
        { field_from_altstack() }
    }
}

fn add_keep(lhs_depth: u32, rhs_depth: u32) -> Script {
    linear_keep(lhs_depth, rhs_depth, false)
}

fn sub_keep(lhs_depth: u32, rhs_depth: u32) -> Script {
    linear_keep(lhs_depth, rhs_depth, true)
}

fn sub_two_keep(lhs_depth: u32, rhs_1_depth: u32, rhs_2_depth: u32) -> Script {
    script! {
        { field_copy(lhs_depth) }
        { field_copy(rhs_1_depth + 1) }
        { field_copy(rhs_2_depth + 2) }
        { pull_bottom_items(
            field::FIELD_DIGIT_COUNT + 1 + LINEAR_CARRY_COUNT,
        ) }
        { field::certify_value_at_depth((1 + LINEAR_CARRY_COUNT) as u32) }
        { verify_sub_two_relation() }
        for _ in 0..(1 + LINEAR_CARRY_COUNT) / 2 { OP_2DROP }
        if (1 + LINEAR_CARRY_COUNT) % 2 != 0 { OP_DROP }
        { field_to_altstack() }
        { field_drop() }
        { field_drop() }
        { field_drop() }
        { field_from_altstack() }
    }
}

fn scale_three_keep(depth: u32) -> Script {
    script! {
        { field_copy(depth) }
        { pull_bottom_items(
            field::FIELD_DIGIT_COUNT + 1 + LINEAR_CARRY_COUNT,
        ) }
        { field::certify_value_at_depth((1 + LINEAR_CARRY_COUNT) as u32) }
        { verify_scale_three_relation() }
        for _ in 0..(1 + LINEAR_CARRY_COUNT) / 2 { OP_2DROP }
        if (1 + LINEAR_CARRY_COUNT) % 2 != 0 { OP_DROP }
        { field_to_altstack() }
        { field_drop() }
        { field_from_altstack() }
    }
}

fn mul_keep(lhs_depth: u32, rhs_depth: u32) -> Script {
    script! {
        { field_copy(lhs_depth) }
        { field_copy(rhs_depth + 1) }
        { pull_bottom_items(field::HINT_ITEM_COUNT) }
        { field::mul_mod_hinted(0) }
    }
}

fn square_keep(depth: u32) -> Script {
    script! {
        { field_copy(depth) }
        { pull_bottom_items(field::HINT_ITEM_COUNT) }
        { field::square_mod_hinted(0) }
    }
}

fn point_copy(depth: u32) -> Script {
    script! {
        { field_copy(2 * depth + 1) }
        { field_copy(2 * depth + 1) }
    }
}

fn point_roll(depth: u32) -> Script {
    if depth == 0 {
        return script! {};
    }
    script! {
        { field_roll(2 * depth + 1) }
        { field_roll(2 * depth + 1) }
    }
}

fn point_drop() -> Script {
    script! { { field_drop() } { field_drop() } }
}

fn point_to_altstack() -> Script {
    script! { { field_to_altstack() } { field_to_altstack() } }
}

fn point_from_altstack() -> Script {
    script! { { field_from_altstack() } { field_from_altstack() } }
}

fn point_is_identity_keep(depth: u32) -> Script {
    script! {
        { field_is_zero_keep(2 * depth) }
        { field_is_zero_keep(2 * depth + 1) }
        OP_BOOLAND
    }
}

fn push_point(point: Option<&AffinePoint>) -> Script {
    match point {
        Some(point) => script! { { push_field(&point.x) } { push_field(&point.y) } },
        None => script! { { push_zero_field() } { push_zero_field() } },
    }
}

fn pull_slope() -> Script {
    script! {
        { pull_bottom_items(field::FIELD_DIGIT_COUNT) }
        { field::certify_value() }
    }
}

fn prepare_general_slope_relation() -> Script {
    // Input: T.x T.y Q.x Q.y alpha. Append denominator and numerator.
    script! {
        { sub_keep(2, 4) } // dx = Q.x - T.x
        { sub_keep(2, 4) } // dy = Q.y - T.y
    }
}

fn prepare_tangent_slope_relation() -> Script {
    // Input: T.x T.y Q.x Q.y alpha, with T == Q. Append the
    // denominator 2*T.y and numerator 3*T.x^2 in the same layout as the
    // general branch, allowing both paths to share the expensive product.
    script! {
        { add_keep(3, 3) } // 2*T.y
        { square_keep(5) } // T.x^2
        { scale_three_keep(0) } // 3*T.x^2
        { field_to_altstack() }
        { field_drop() } // T.x^2
        { field_from_altstack() }
    }
}

fn check_prepared_slope_relation() -> Script {
    // Input: T.x T.y Q.x Q.y alpha denominator numerator.
    script! {
        { mul_keep(2, 1) } // alpha * denominator
        { field_equalverify(0, 1) }
        { field_drop() } // denominator
    }
}

fn finish_affine_add() -> Script {
    // Input: T.x T.y Q.x Q.y alpha.
    script! {
        { square_keep(0) } // alpha^2
        { sub_two_keep(0, 5, 3) } // x3 = alpha^2 - T.x - Q.x
        { sub_keep(6, 0) } // T.x - x3
        { mul_keep(3, 0) } // alpha * (T.x - x3)
        { sub_keep(0, 7) } // y3

        // Keep x3/y3 and discard the inputs and intermediates.
        { field_to_altstack() } // y3
        { field_roll(2) }       // x3 above product and x-difference
        { field_to_altstack() }
        for _ in 0..8 { { field_drop() } }
        { field_from_altstack() }
        { field_from_altstack() }
    }
}

fn point_add_complete() -> Script {
    script! {
        { point_is_identity_keep(0) }
        OP_IF
            { point_drop() }
        OP_ELSE
            { point_is_identity_keep(1) }
            OP_IF
                { point_roll(1) }
                { point_drop() }
            OP_ELSE
                { field_equal_keep(3, 1) }
                OP_IF
                    { field_equal_keep(2, 0) }
                    OP_IF
                        { pull_slope() }
                        { prepare_tangent_slope_relation() }
                        1
                    OP_ELSE
                        { point_drop() }
                        { point_drop() }
                        { push_point(None) }
                        0
                    OP_ENDIF
                OP_ELSE
                    { pull_slope() }
                    { prepare_general_slope_relation() }
                    1
                OP_ENDIF
                OP_IF
                    { check_prepared_slope_relation() }
                    { finish_affine_add() }
                OP_ENDIF
            OP_ENDIF
        OP_ENDIF
    }
}

fn u256_to_balanced_field() -> Script {
    script! {
        { U256::transform_limbsize(29, 9) }
        0
        for _ in 0..field::FIELD_DIGIT_COUNT - 1 {
            OP_ADD
            OP_DUP 256 OP_GREATERTHANOREQUAL
            OP_IF
                512 OP_SUB OP_TOALTSTACK 1
            OP_ELSE
                OP_TOALTSTACK 0
            OP_ENDIF
        }
        OP_ADD
        for _ in 0..field::FIELD_DIGIT_COUNT - 1 { OP_FROMALTSTACK }
    }
}

fn push_nibbles(bytes: &[u8]) -> Script {
    script! {
        for byte in bytes {
            { byte >> 4 }
            { byte & 15 }
        }
    }
}

fn select_point_range(table: &[Option<AffinePoint>], lo: usize, hi: usize) -> Script {
    debug_assert!(lo < hi && hi <= table.len());
    if hi - lo == 1 {
        return script! { OP_DROP { push_point(table[lo].as_ref()) } };
    }
    let middle = (lo + hi) / 2;
    script! {
        OP_DUP { middle } OP_LESSTHAN
        OP_IF
            { select_point_range(table, lo, middle) }
        OP_ELSE
            { select_point_range(table, middle, hi) }
        OP_ENDIF
    }
}

fn select_point(table: &[Option<AffinePoint>]) -> Script {
    assert!(table.len() > 1);
    select_point_range(table, 0, table.len())
}

fn window_tables(base: &AffinePoint) -> Vec<Vec<Option<AffinePoint>>> {
    let mut tables = Vec::with_capacity(WINDOW_COUNT);
    let mut window_base = base.clone();
    for window_index in 0..WINDOW_COUNT {
        let remaining_bits = 256usize.saturating_sub(window_index * WINDOW_BITS);
        let maximum_magnitude = if window_index + 1 == WINDOW_COUNT {
            1usize << remaining_bits
        } else {
            1usize << (WINDOW_BITS - 1)
        };
        let table_len = maximum_magnitude + 1;
        let mut table = Vec::with_capacity(table_len);
        let mut current = None;
        table.push(None);
        for _ in 1..table_len {
            current = point_add(current.as_ref(), Some(&window_base));
            table.push(current.clone());
        }
        tables.push(table);
        for _ in 0..WINDOW_BITS {
            window_base = point_add(Some(&window_base), Some(&window_base))
                .expect("prime-order base does not double to infinity");
        }
    }
    tables
}

fn scalar_windows(value: &BigUint) -> Vec<usize> {
    let mut windows = value.to_radix_le(1u32 << WINDOW_BITS);
    windows.resize(WINDOW_COUNT, 0);
    assert_eq!(windows.len(), WINDOW_COUNT);
    windows.into_iter().map(usize::from).collect()
}

fn scalar_signed_windows(value: &BigUint) -> Vec<i16> {
    let radix = 1i16 << WINDOW_BITS;
    let half = radix / 2;
    let mut carry = 0i16;
    let unsigned = scalar_windows(value);
    let top_unsigned = unsigned[WINDOW_COUNT - 1];
    let mut windows = unsigned
        .into_iter()
        .take(WINDOW_COUNT - 1)
        .map(|window| {
            let combined = i16::try_from(window).expect("window fits i16") + carry;
            if combined >= half {
                carry = 1;
                combined - radix
            } else {
                carry = 0;
                combined
            }
        })
        .collect::<Vec<_>>();
    let top = i16::try_from(top_unsigned).expect("top window fits i16") + carry;
    windows.push(top);
    windows
}

fn u256_to_signed_windows_altstack() -> Script {
    let radix = 1u32 << WINDOW_BITS;
    let half = radix / 2;
    script! {
        { U256::transform_limbsize(29, WINDOW_BITS as u32) }
        0
        for _ in 0..WINDOW_COUNT - 1 {
            OP_ADD
            OP_DUP { half } OP_GREATERTHANOREQUAL
            OP_IF
                { radix } OP_SUB OP_TOALTSTACK 1
            OP_ELSE
                OP_TOALTSTACK 0
            OP_ENDIF
        }
        OP_ADD OP_TOALTSTACK
    }
}

fn negate_selected_point() -> Script {
    let p_digits = modulus_digits();
    script! {
        // The selected nonidentity table point is a trusted constant. Convert
        // y to p-y directly in balanced radix 512, carrying from low to high.
        0
        for digit in p_digits {
            OP_SWAP OP_NEGATE OP_ADD
            if digit != 0 { { digit } OP_ADD }
            OP_DUP 256 OP_GREATERTHANOREQUAL
            OP_IF
                512 OP_SUB OP_TOALTSTACK 1
            OP_ELSE
                OP_DUP -256 OP_LESSTHAN
                OP_IF
                    512 OP_ADD OP_TOALTSTACK -1
                OP_ELSE
                    OP_TOALTSTACK 0
                OP_ENDIF
            OP_ENDIF
        }
        0 OP_EQUALVERIFY
        for _ in 0..field::FIELD_DIGIT_COUNT { OP_FROMALTSTACK }
    }
}

fn select_signed_point(table: &[Option<AffinePoint>]) -> Script {
    script! {
        OP_DUP 0 OP_LESSTHAN OP_TOALTSTACK
        OP_ABS
        { select_point(table) }
        OP_FROMALTSTACK
        OP_IF
            { negate_selected_point() }
        OP_ENDIF
    }
}

fn curve_check_keep() -> Script {
    let seven = BigUint::from(7u8);
    script! {
        { point_copy(0) }
        { square_keep(1) }
        { mul_keep(0, 2) }
        { push_field(&seven) }
        { add_keep(1, 0) }
        { square_keep(4) }
        { field_equalverify(0, 1) }
        for _ in 0..5 { { field_drop() } }

        // BIP340 uses the even affine lift. Since the least-significant
        // balanced radix-512 digit has the field element's parity, proving it
        // is twice a small witnessed integer establishes evenness.
        { pull_bottom_items(1) }
        OP_DUP OP_ADD
        1 OP_PICK
        OP_EQUALVERIFY
    }
}

// Input: r | s | message. Preserve all three values and append the BIP340
// challenge as a 256-bit integer (29-bit limbs, least-significant limb on top).
fn challenge_hash_script(public_key: &[u8; 32]) -> Script {
    let tag_hash = sha256::Hash::hash(b"BIP0340/challenge").to_byte_array();
    script! {
        { U256::copy(0) }
        { U256::transform_limbsize(29, 4) }
        for _ in 0..64 { OP_TOALTSTACK }
        { U256::copy(2) }
        { U256::transform_limbsize(29, 4) }
        for _ in 0..64 { OP_TOALTSTACK }
        { push_nibbles(&tag_hash) }
        { push_nibbles(&tag_hash) }
        for _ in 0..64 { OP_FROMALTSTACK }
        { push_nibbles(public_key) }
        for _ in 0..64 { OP_FROMALTSTACK }
        { sha2_u4::sha256(160) }
        { U256::transform_limbsize(4, 29) }
    }
}

// Input tail: R.y | r | s | message. Arithmetic hints may precede it. Output:
// s | challenge on the main stack and R=(r, R.y) on the altstack.
fn input_and_nonce_prefix(public_key: &[u8; 32]) -> Script {
    let order = group_order();
    script! {
        { field::certify_value_at_depth((3 * U256_LIMBS) as u32) }
        for depth in 0..3u32 {
            { U256::copy(depth) }
            { U256::verify_bigint_on_stack() }
            { U256::drop() }
        }
        { U256::copy(1) }
        { U256::push_biguint(order) }
        { U256::lessthan(1, 0) }
        OP_VERIFY

        { challenge_hash_script(public_key) }

        // Message is no longer needed: retain r, s, and the full hash.
        { U256::toaltstack() }
        { U256::drop() }
        { U256::fromaltstack() }

        // Bind r to the supplied even affine nonce point and check the curve.
        { U256::copy(2) }
        { u256_to_balanced_field() }
        { field::certify_value() }
        { field_copy_at_item_depth(
            field::FIELD_DIGIT_COUNT as u32 + 3 * U256_LIMBS as u32,
        ) }
        { curve_check_keep() }
        { point_to_altstack() }

        // Discard the original r/R.y encodings while retaining s and hash.
        { U256::toaltstack() }
        { U256::toaltstack() }
        { U256::drop() }
        { field_drop() }
        { U256::fromaltstack() }
        { U256::fromaltstack() }
    }
}

fn verifier_script(
    public_key: [u8; 32],
    public_point: &AffinePoint,
    generator_low32_leaf: Option<u32>,
) -> Script {
    let generator_tables = window_tables(&generator());
    let challenge_tables = window_tables(&negate_point(public_point));
    let (leaf_digits, leaf_point) = generator_low32_leaf
        .map(|low32| generator_low32_prefix(&generator_tables, low32))
        .unwrap_or(([0; 4], None));

    script! {
        { input_and_nonce_prefix(&public_key) }

        // Put both scalars above R on altstack, most-significant window first.
        { u256_to_signed_windows_altstack() }
        { u256_to_signed_windows_altstack() }

        if generator_low32_leaf.is_some() {
            { push_point(leaf_point.as_ref()) }
            for table_index in (4..WINDOW_COUNT).rev() {
                OP_FROMALTSTACK
                { select_signed_point(&generator_tables[table_index]) }
                { point_add_complete() }
            }
            for table_index in (0..4).rev() {
                OP_FROMALTSTACK
                { i32::from(leaf_digits[table_index]) }
                OP_EQUALVERIFY
            }
        } else {
            { push_point(None) }
            for table_index in (0..WINDOW_COUNT).rev() {
                OP_FROMALTSTACK
                { select_signed_point(&generator_tables[table_index]) }
                { point_add_complete() }
            }
        }
        for table_index in (0..WINDOW_COUNT).rev() {
            OP_FROMALTSTACK
            { select_signed_point(&challenge_tables[table_index]) }
            { point_add_complete() }
        }

        { point_from_altstack() }
        { field_equalverify(0, 2) }
        { field_equalverify(0, 1) }
        OP_TRUE
    }
}

fn append_curve_hints(witness: &mut Vec<Vec<u8>>, point: &AffinePoint) {
    let p = field::modulus();
    let x2 = mul_mod(&point.x, &point.x, &p);
    append_square_hints(witness, &field::hinted_square(&point.x));
    append_mul_hints(witness, &field::hinted_mul(&x2, &point.x));
    let x3 = mul_mod(&x2, &point.x, &p);
    append_linear_hints(witness, &hinted_linear(&x3, &BigUint::from(7u8), false));
    append_square_hints(witness, &field::hinted_square(&point.y));
    witness.push(scriptnum_item(field::field_digits(&point.y)[0] / 2));
}

fn append_general_add_hints(
    witness: &mut Vec<Vec<u8>>,
    lhs: &AffinePoint,
    rhs: &AffinePoint,
) -> AffinePoint {
    let p = field::modulus();
    let dx = sub_mod(&rhs.x, &lhs.x, &p);
    let dy = sub_mod(&rhs.y, &lhs.y, &p);
    let alpha = mul_mod(&dy, &dx.modpow(&(&p - BigUint::from(2u8)), &p), &p);
    append_field(witness, &alpha);
    append_linear_hints(witness, &hinted_linear(&rhs.x, &lhs.x, true));
    append_linear_hints(witness, &hinted_linear(&rhs.y, &lhs.y, true));
    append_mul_hints(witness, &field::hinted_mul(&alpha, &dx));
    append_square_hints(witness, &field::hinted_square(&alpha));
    let alpha2 = mul_mod(&alpha, &alpha, &p);
    let x3_hints = hinted_sub_two(&alpha2, &lhs.x, &rhs.x);
    let x3 = x3_hints.result.clone();
    append_linear_hints(witness, &x3_hints);
    let x_difference = sub_mod(&lhs.x, &x3, &p);
    append_linear_hints(witness, &hinted_linear(&lhs.x, &x3, true));
    let product = mul_mod(&alpha, &x_difference, &p);
    append_mul_hints(witness, &field::hinted_mul(&alpha, &x_difference));
    let y3 = sub_mod(&product, &lhs.y, &p);
    append_linear_hints(witness, &hinted_linear(&product, &lhs.y, true));
    AffinePoint { x: x3, y: y3 }
}

fn append_double_hints(witness: &mut Vec<Vec<u8>>, point: &AffinePoint) -> AffinePoint {
    let p = field::modulus();
    let denominator = add_mod(&point.y, &point.y, &p);
    let x2 = mul_mod(&point.x, &point.x, &p);
    let twice_x2 = add_mod(&x2, &x2, &p);
    let numerator = add_mod(&twice_x2, &x2, &p);
    let alpha = mul_mod(
        &numerator,
        &denominator.modpow(&(&p - BigUint::from(2u8)), &p),
        &p,
    );
    append_field(witness, &alpha);
    append_linear_hints(witness, &hinted_linear(&point.y, &point.y, false));
    append_square_hints(witness, &field::hinted_square(&point.x));
    append_linear_hints(witness, &hinted_scale_three(&x2));
    append_mul_hints(witness, &field::hinted_mul(&alpha, &denominator));
    append_square_hints(witness, &field::hinted_square(&alpha));
    let alpha2 = mul_mod(&alpha, &alpha, &p);
    let x3_hints = hinted_sub_two(&alpha2, &point.x, &point.x);
    let x3 = x3_hints.result.clone();
    append_linear_hints(witness, &x3_hints);
    let x_difference = sub_mod(&point.x, &x3, &p);
    append_linear_hints(witness, &hinted_linear(&point.x, &x3, true));
    let product = mul_mod(&alpha, &x_difference, &p);
    append_mul_hints(witness, &field::hinted_mul(&alpha, &x_difference));
    let y3 = sub_mod(&product, &point.y, &p);
    append_linear_hints(witness, &hinted_linear(&product, &point.y, true));
    AffinePoint { x: x3, y: y3 }
}

fn append_point_add_hints(
    witness: &mut Vec<Vec<u8>>,
    lhs: Option<&AffinePoint>,
    rhs: Option<&AffinePoint>,
) -> Option<AffinePoint> {
    match (lhs, rhs) {
        (None, None) => None,
        (None, Some(rhs)) => Some(rhs.clone()),
        (Some(lhs), None) => Some(lhs.clone()),
        (Some(lhs), Some(rhs)) if lhs.x == rhs.x && lhs.y != rhs.y => None,
        (Some(lhs), Some(rhs)) if lhs == rhs => Some(append_double_hints(witness, lhs)),
        (Some(lhs), Some(rhs)) => Some(append_general_add_hints(witness, lhs, rhs)),
    }
}

fn append_signed_selection_hints(
    _witness: &mut Vec<Vec<u8>>,
    table: &[Option<AffinePoint>],
    digit: i16,
) -> Option<AffinePoint> {
    let magnitude = usize::from(digit.unsigned_abs());
    let selected = table[magnitude].clone();
    if digit < 0 {
        let selected = selected.expect("a negative digit has nonzero magnitude");
        Some(negate_point(&selected))
    } else {
        selected
    }
}

fn generator_low32_prefix(
    tables: &[Vec<Option<AffinePoint>>],
    low32: u32,
) -> ([i16; 4], Option<AffinePoint>) {
    let windows = scalar_signed_windows(&BigUint::from(low32));
    let digits: [i16; 4] = windows[..4].try_into().expect("four low-byte windows");
    let mut point = None;
    for (table_index, digit) in digits.iter().copied().enumerate() {
        let magnitude = usize::from(digit.unsigned_abs());
        let selected = tables[table_index][magnitude].as_ref().map(|selected| {
            if digit < 0 {
                negate_point(selected)
            } else {
                selected.clone()
            }
        });
        point = point_add(point.as_ref(), selected.as_ref());
    }
    (digits, point)
}

fn challenge_bytes(r: &[u8; 32], public_key: &[u8; 32], message: &[u8; 32]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(b"BIP0340/challenge").to_byte_array();
    let mut preimage = Vec::with_capacity(160);
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(r);
    preimage.extend_from_slice(public_key);
    preimage.extend_from_slice(message);
    sha256::Hash::hash(&preimage).to_byte_array()
}

fn build_witness(
    public_key: [u8; 32],
    message: [u8; 32],
    signature: [u8; 64],
    generator_low32_leaf: Option<u32>,
) -> Result<Vec<Vec<u8>>, CsfsError> {
    let public_x = BigUint::from_bytes_be(&public_key);
    let public_point = lift_x(&public_x).ok_or(CsfsError::InvalidPublicKey)?;
    let r_bytes: [u8; 32] = signature[..32].try_into().expect("fixed r length");
    let r = BigUint::from_bytes_be(&r_bytes);
    let nonce = lift_x(&r).ok_or(CsfsError::InvalidNonce)?;
    let s = BigUint::from_bytes_be(&signature[32..]);
    let hash = BigUint::from_bytes_be(&challenge_bytes(&r_bytes, &public_key, &message));

    let generator_tables = window_tables(&generator());
    let challenge_tables = window_tables(&negate_point(&public_point));
    let mut witness = Vec::new();
    append_curve_hints(&mut witness, &nonce);

    if let Some(expected_low32) = generator_low32_leaf {
        let actual_low32 = s.to_u32_digits().first().copied().unwrap_or(0);
        if actual_low32 != expected_low32 {
            return Err(CsfsError::GeneratorPrefixMismatch);
        }
    }
    let mut accumulator = generator_low32_leaf
        .map(|low32| generator_low32_prefix(&generator_tables, low32).1)
        .unwrap_or(None);
    let s_windows = scalar_signed_windows(&s);
    let first_generator_window = if generator_low32_leaf.is_some() { 4 } else { 0 };
    for table_index in (first_generator_window..WINDOW_COUNT).rev() {
        let selected = append_signed_selection_hints(
            &mut witness,
            &generator_tables[table_index],
            s_windows[table_index],
        );
        accumulator = append_point_add_hints(&mut witness, accumulator.as_ref(), selected.as_ref());
    }
    let hash_windows = scalar_signed_windows(&hash);
    for table_index in (0..WINDOW_COUNT).rev() {
        let selected = append_signed_selection_hints(
            &mut witness,
            &challenge_tables[table_index],
            hash_windows[table_index],
        );
        accumulator = append_point_add_hints(&mut witness, accumulator.as_ref(), selected.as_ref());
    }

    append_field(&mut witness, &nonce.y);
    append_u256(&mut witness, &r);
    append_u256(&mut witness, &s);
    append_u256(&mut witness, &BigUint::from_bytes_be(&message));
    Ok(witness)
}

/// Construct a BIP340 check-signature-from-stack research verifier for one
/// committed x-only public key. The returned Script is independent of message
/// and signature.
pub fn verifier(public_key: [u8; 32]) -> Result<CsfsVerifier, CsfsError> {
    let public_point =
        lift_x(&BigUint::from_bytes_be(&public_key)).ok_or(CsfsError::InvalidPublicKey)?;
    Ok(CsfsVerifier {
        script: verifier_script(public_key, &public_point, None),
        public_key,
        generator_low32_leaf: None,
    })
}

/// Construct one leaf of a conceptual 2^32-leaf Taproot lookup tree. The leaf
/// is specialized to the low 32 bits of `s` and replaces those four fixed-base
/// window selections/additions with one committed affine accumulator point.
pub fn verifier_with_generator_low32_leaf(
    public_key: [u8; 32],
    low32: u32,
) -> Result<CsfsVerifier, CsfsError> {
    let public_point =
        lift_x(&BigUint::from_bytes_be(&public_key)).ok_or(CsfsError::InvalidPublicKey)?;
    Ok(CsfsVerifier {
        script: verifier_script(public_key, &public_point, Some(low32)),
        public_key,
        generator_low32_leaf: Some(low32),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

    use crate::support::{execution::execute_script_with_inputs, script::ScriptCompilation};

    fn fixture() -> ([u8; 32], [u8; 32], [u8; 64]) {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&keypair);
        let message = [42u8; 32];
        let signature = secp.sign_schnorr_no_aux_rand(&Message::from_digest(message), &keypair);
        (public.serialize(), message, *signature.as_ref())
    }

    #[test]
    fn linear_hint_relations_execute() {
        let p = field::modulus();
        for (lhs, rhs) in [
            (BigUint::from(2u8), BigUint::from(3u8)),
            (&p - BigUint::from(1u8), BigUint::from(7u8)),
        ] {
            for subtract in [false, true] {
                let hints = hinted_linear(&lhs, &rhs, subtract);
                let mut witness = Vec::new();
                append_linear_hints(&mut witness, &hints);
                append_field(&mut witness, &lhs);
                append_field(&mut witness, &rhs);
                let script = script! {
                    { field::certify_value_at_depth(field::FIELD_DIGIT_COUNT as u32) }
                    { field::certify_value() }
                    { linear_keep(1, 0, subtract) }
                    { push_field(&hints.result) }
                    { field_equalverify(0, 1) }
                    { field_drop() }
                    { field_drop() }
                    OP_TRUE
                };
                let result = execute_script_with_inputs(script, witness);
                assert!(result.success, "linear relation failed: {result}");
            }
        }
    }

    #[test]
    fn corrupted_linear_hint_is_rejected() {
        let lhs = BigUint::from(2u8);
        let rhs = BigUint::from(3u8);
        let hints = hinted_linear(&lhs, &rhs, false);
        let mut witness = Vec::new();
        append_linear_hints(&mut witness, &hints);
        witness[field::FIELD_DIGIT_COUNT] = scriptnum_item(1);
        append_field(&mut witness, &lhs);
        append_field(&mut witness, &rhs);
        let script = script! {
            { field::certify_value_at_depth(field::FIELD_DIGIT_COUNT as u32) }
            { field::certify_value() }
            { add_keep(1, 0) }
            OP_TRUE
        };
        let result = execute_script_with_inputs(script, witness);
        assert!(!result.success, "corrupted linear quotient was accepted");
    }

    fn point_witness(point: Option<&AffinePoint>) -> Vec<Vec<u8>> {
        let mut witness = Vec::new();
        match point {
            Some(point) => {
                append_field(&mut witness, &point.x);
                append_field(&mut witness, &point.y);
            }
            None => {
                append_field(&mut witness, &BigUint::from(0u8));
                append_field(&mut witness, &BigUint::from(0u8));
            }
        }
        witness
    }

    #[test]
    fn complete_affine_addition_executes_all_branches() {
        let g = generator();
        let twice = point_add(Some(&g), Some(&g)).unwrap();
        let negative = negate_point(&g);
        for (lhs, rhs) in [
            (None, Some(g.clone())),
            (Some(g.clone()), None),
            (Some(g.clone()), Some(negative)),
            (Some(g.clone()), Some(g.clone())),
            (Some(g.clone()), Some(twice.clone())),
        ] {
            let mut hints = Vec::new();
            let expected = append_point_add_hints(&mut hints, lhs.as_ref(), rhs.as_ref());
            let mut witness = hints;
            witness.extend(point_witness(lhs.as_ref()));
            witness.extend(point_witness(rhs.as_ref()));
            let script = script! {
                if lhs.is_some() {
                    { field::certify_value_at_depth(
                        (3 * field::FIELD_DIGIT_COUNT) as u32,
                    ) }
                    { field::certify_value_at_depth(
                        (2 * field::FIELD_DIGIT_COUNT) as u32,
                    ) }
                }
                if rhs.is_some() {
                    { field::certify_value_at_depth(field::FIELD_DIGIT_COUNT as u32) }
                    { field::certify_value() }
                }
                { point_add_complete() }
                { push_point(expected.as_ref()) }
                { field_equalverify(0, 2) }
                { field_equalverify(0, 1) }
                OP_TRUE
            };
            let result = execute_script_with_inputs(script, witness);
            assert!(result.success, "{lhs:?} + {rhs:?}: {result}");
        }
    }

    #[test]
    fn u256_conversion_matches_native_field_encoding() {
        for value in [
            BigUint::from(0u8),
            BigUint::from(1u8),
            field::modulus() - BigUint::from(1u8),
        ] {
            let mut witness = Vec::new();
            append_u256(&mut witness, &value);
            let script = script! {
                { U256::verify_bigint_on_stack() }
                { u256_to_balanced_field() }
                { field::certify_value() }
                { push_field(&value) }
                { field_equalverify(0, 1) }
                OP_TRUE
            };
            let result = execute_script_with_inputs(script, witness);
            assert!(result.success, "conversion failed for {value}: {result}");
        }
    }

    #[test]
    fn signed_window_recode_covers_full_scalar_domain() {
        for value in [
            BigUint::from(0u8),
            BigUint::from(1u8),
            BigUint::from(1u8) << 255usize,
            group_order() - BigUint::from(1u8),
        ] {
            let windows = scalar_signed_windows(&value);
            let mut witness = Vec::new();
            append_u256(&mut witness, &value);
            let script = script! {
                { u256_to_signed_windows_altstack() }
                for index in (0..WINDOW_COUNT).rev() {
                    OP_FROMALTSTACK
                    { i32::from(windows[index]) }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            };
            let result = execute_script_with_inputs(script, witness);
            assert!(result.success, "signed recode failed for {value}: {result}");
        }
    }

    #[test]
    fn supplied_nonce_curve_and_even_y_are_verified() {
        let (_, _, signature) = fixture();
        let nonce = lift_x(&BigUint::from_bytes_be(&signature[..32])).unwrap();
        let mut witness = Vec::new();
        append_curve_hints(&mut witness, &nonce);
        witness.extend(point_witness(Some(&nonce)));
        let script = script! {
            { field::certify_value_at_depth(field::FIELD_DIGIT_COUNT as u32) }
            { field::certify_value() }
            { curve_check_keep() }
            { point_drop() }
            OP_TRUE
        };
        let result = execute_script_with_inputs(script, witness);
        assert!(result.success, "nonce curve check failed: {result}");
    }

    #[test]
    fn odd_nonce_lift_is_rejected() {
        let (_, _, signature) = fixture();
        let nonce = lift_x(&BigUint::from_bytes_be(&signature[..32])).unwrap();
        let odd_nonce = negate_point(&nonce);
        assert!(odd_nonce.y.bit(0));
        let mut witness = Vec::new();
        append_curve_hints(&mut witness, &odd_nonce);
        witness.extend(point_witness(Some(&odd_nonce)));
        let script = script! {
            { field::certify_value_at_depth(field::FIELD_DIGIT_COUNT as u32) }
            { field::certify_value() }
            { curve_check_keep() }
            OP_TRUE
        };
        let result = execute_script_with_inputs(script, witness);
        assert!(!result.success, "odd nonce lift was accepted");
    }

    #[test]
    fn bip340_challenge_hash_matches_host() {
        let (public, message, signature) = fixture();
        let r_bytes: [u8; 32] = signature[..32].try_into().unwrap();
        let expected = BigUint::from_bytes_be(&challenge_bytes(&r_bytes, &public, &message));
        let mut witness = Vec::new();
        append_u256(&mut witness, &BigUint::from_bytes_be(&r_bytes));
        append_u256(&mut witness, &BigUint::from_bytes_be(&signature[32..]));
        append_u256(&mut witness, &BigUint::from_bytes_be(&message));
        let script = script! {
            { challenge_hash_script(&public) }
            { U256::push_biguint(expected) }
            { U256::equalverify(0, 1) }
            { U256::drop() }
            { U256::drop() }
            { U256::drop() }
            OP_TRUE
        };
        let result = execute_script_with_inputs(script, witness);
        assert!(result.success, "BIP340 challenge mismatch: {result}");
    }

    #[test]
    fn input_prefix_preserves_scalars_and_nonce() {
        let (public, message, signature) = fixture();
        let r_bytes: [u8; 32] = signature[..32].try_into().unwrap();
        let r = BigUint::from_bytes_be(&r_bytes);
        let nonce = lift_x(&r).unwrap();
        let s = BigUint::from_bytes_be(&signature[32..]);
        let hash = BigUint::from_bytes_be(&challenge_bytes(&r_bytes, &public, &message));
        let mut witness = Vec::new();
        append_curve_hints(&mut witness, &nonce);
        append_field(&mut witness, &nonce.y);
        append_u256(&mut witness, &r);
        append_u256(&mut witness, &s);
        append_u256(&mut witness, &BigUint::from_bytes_be(&message));
        let script = script! {
            { input_and_nonce_prefix(&public) }
            { U256::push_biguint(hash) }
            { U256::equalverify(0, 1) }
            { U256::push_biguint(s) }
            { U256::equalverify(0, 1) }
            { point_from_altstack() }
            { push_point(Some(&nonce)) }
            { field_equalverify(0, 2) }
            { field_equalverify(0, 1) }
            OP_TRUE
        };
        let result = execute_script_with_inputs(script, witness);
        assert!(result.success, "input prefix mismatch: {result}");
    }

    #[test]
    fn input_prefix_rejects_s_equal_to_group_order() {
        let (public, message, signature) = fixture();
        let r = BigUint::from_bytes_be(&signature[..32]);
        let nonce = lift_x(&r).unwrap();
        let mut witness = Vec::new();
        append_curve_hints(&mut witness, &nonce);
        append_field(&mut witness, &nonce.y);
        append_u256(&mut witness, &r);
        append_u256(&mut witness, &group_order());
        append_u256(&mut witness, &BigUint::from_bytes_be(&message));
        let result = execute_script_with_inputs(input_and_nonce_prefix(&public), witness);
        assert!(!result.success, "s=n was accepted");
    }

    #[test]
    #[ignore = "expensive component-size diagnostic"]
    fn reports_csfs_component_sizes() {
        let (public, _, _) = fixture();
        let public_point = lift_x(&BigUint::from_bytes_be(&public)).unwrap();
        let table = window_tables(&generator()).remove(0);
        eprintln!(
            "complete_add={} select_table={} input_prefix={} mul={} square={} linear={} table={}",
            point_add_complete().compile_with_policy().len(),
            select_point(&table).compile_with_policy().len(),
            input_and_nonce_prefix(&public).compile_with_policy().len(),
            field::mul_mod_hinted(0).compile_with_policy().len(),
            field::square_mod_hinted(0).compile_with_policy().len(),
            linear_keep(0, 1, false).compile_with_policy().len(),
            field::table_setup(0).compile_with_policy().len(),
        );
        let _ = public_point;
    }

    #[test]
    #[ignore = "megabyte-scale MSM diagnostic"]
    fn generator_window_msm_matches_host() {
        let (_, _, signature) = fixture();
        let scalar = BigUint::from_bytes_be(&signature[32..]);
        let windows = scalar_signed_windows(&scalar);
        let tables = window_tables(&generator());
        let mut witness = Vec::new();
        let mut accumulator = None;
        for table_index in (0..WINDOW_COUNT).rev() {
            let selected = append_signed_selection_hints(
                &mut witness,
                &tables[table_index],
                windows[table_index],
            );
            accumulator =
                append_point_add_hints(&mut witness, accumulator.as_ref(), selected.as_ref());
        }
        append_u256(&mut witness, &scalar);
        let script = script! {
            { U256::verify_bigint_on_stack() }
            { u256_to_signed_windows_altstack() }
            { push_point(None) }
            for table_index in (0..WINDOW_COUNT).rev() {
                OP_FROMALTSTACK
                { select_signed_point(&tables[table_index]) }
                { point_add_complete() }
            }
            { push_point(accumulator.as_ref()) }
            { field_equalverify(0, 2) }
            { field_equalverify(0, 1) }
            OP_TRUE
        };
        let result = execute_script_with_inputs(script, witness);
        assert!(result.success, "generator MSM mismatch: {result}");
    }

    #[test]
    #[ignore = "multi-megabyte MSM diagnostic"]
    fn two_scalar_window_msm_matches_host() {
        let (public, message, signature) = fixture();
        let public_point = lift_x(&BigUint::from_bytes_be(&public)).unwrap();
        let r_bytes: [u8; 32] = signature[..32].try_into().unwrap();
        let s = BigUint::from_bytes_be(&signature[32..]);
        let hash_bytes = challenge_bytes(&r_bytes, &public, &message);
        let hash = BigUint::from_bytes_be(&hash_bytes);
        let s_windows = scalar_signed_windows(&s);
        let hash_windows = scalar_signed_windows(&hash);
        let generator_tables = window_tables(&generator());
        let challenge_tables = window_tables(&negate_point(&public_point));
        let mut witness = Vec::new();
        let mut accumulator = None;
        for table_index in (0..WINDOW_COUNT).rev() {
            let selected = append_signed_selection_hints(
                &mut witness,
                &generator_tables[table_index],
                s_windows[table_index],
            );
            accumulator =
                append_point_add_hints(&mut witness, accumulator.as_ref(), selected.as_ref());
        }
        for table_index in (0..WINDOW_COUNT).rev() {
            let selected = append_signed_selection_hints(
                &mut witness,
                &challenge_tables[table_index],
                hash_windows[table_index],
            );
            accumulator =
                append_point_add_hints(&mut witness, accumulator.as_ref(), selected.as_ref());
        }
        append_u256(&mut witness, &s);
        append_u256(&mut witness, &hash);
        let script = script! {
            { u256_to_signed_windows_altstack() }
            { u256_to_signed_windows_altstack() }
            { push_point(None) }
            for table_index in (0..WINDOW_COUNT).rev() {
                OP_FROMALTSTACK
                { select_signed_point(&generator_tables[table_index]) }
                { point_add_complete() }
            }
            for table_index in (0..WINDOW_COUNT).rev() {
                OP_FROMALTSTACK
                { select_signed_point(&challenge_tables[table_index]) }
                { point_add_complete() }
            }
            { push_point(accumulator.as_ref()) }
            { field_equalverify(0, 2) }
            { field_equalverify(0, 1) }
            OP_TRUE
        };
        let result = execute_script_with_inputs(script, witness);
        assert!(result.success, "two-scalar MSM mismatch: {result}");
    }

    #[test]
    #[ignore = "multi-megabyte research-unlimited verifier"]
    fn signature_is_witness_data_and_validates_end_to_end() {
        let (public, message, signature) = fixture();
        let secp = Secp256k1::verification_only();
        let public_reference = XOnlyPublicKey::from_slice(&public).unwrap();
        let signature_reference =
            bitcoin::secp256k1::schnorr::Signature::from_slice(&signature).unwrap();
        assert!(secp
            .verify_schnorr(
                &signature_reference,
                &Message::from_digest(message),
                &public_reference,
            )
            .is_ok());
        let verifier = verifier(public).unwrap();
        let witness = verifier.witness(message, signature).unwrap();
        let witness_items = witness.len();
        let witness_bytes =
            bitcoin::consensus::encode::serialize(&bitcoin::Witness::from_slice(&witness)).len();
        let compiled = verifier.script().compile_with_policy();
        let static_non_push_opcodes = compiled
            .instructions()
            .map(|instruction| instruction.unwrap())
            .filter(|instruction| {
                matches!(instruction, bitcoin::script::Instruction::Op(opcode) if opcode.to_u8() > 0x60)
            })
            .count();
        let result = execute_script_with_inputs(verifier.script(), witness);
        assert!(result.success, "CSFS verification failed: {result}");
        assert_eq!(result.final_stack.len(), 1);
        assert_eq!(compiled.len(), 8_292_228);
        assert_eq!(witness_bytes, 81_740);
        assert_eq!(witness_items, 32_556);
        assert_eq!(result.stats.max_nb_stack_items, 33_589);
        assert_eq!(static_non_push_opcodes, 4_593_240);
        eprintln!(
            "CSFS script={} witness={} items={} stack={} opcodes={} stats={:?}",
            compiled.len(),
            witness_bytes,
            witness_items,
            result.stats.max_nb_stack_items,
            static_non_push_opcodes,
            result.stats,
        );
    }

    #[test]
    #[ignore = "multi-megabyte 2^32-taptree leaf experiment"]
    fn taptree_low32_leaf_savings_execute() {
        let (public, message, signature) = fixture();
        let low32 = u32::from_be_bytes(signature[60..64].try_into().unwrap());
        let baseline = verifier(public).unwrap();
        let leaf = verifier_with_generator_low32_leaf(public, low32).unwrap();
        let baseline_witness = baseline.witness(message, signature).unwrap();
        let leaf_witness = leaf.witness(message, signature).unwrap();
        let baseline_script_bytes = baseline.script().compile_with_policy().len();
        let leaf_script_bytes = leaf.script().compile_with_policy().len();
        let baseline_witness_bytes =
            bitcoin::consensus::encode::serialize(&bitcoin::Witness::from_slice(&baseline_witness))
                .len();
        let leaf_witness_bytes =
            bitcoin::consensus::encode::serialize(&bitcoin::Witness::from_slice(&leaf_witness))
                .len();
        let result = execute_script_with_inputs(leaf.script(), leaf_witness);
        assert!(result.success, "2^32-taptree leaf failed: {result}");
        let script_savings = baseline_script_bytes - leaf_script_bytes;
        let arithmetic_witness_savings = baseline_witness_bytes - leaf_witness_bytes;
        const DEPTH_32_CONTROL_BLOCK_DELTA: usize = 1_026;
        assert_eq!(baseline_script_bytes, 8_292_228);
        assert_eq!(leaf_script_bytes, 7_850_893);
        assert_eq!(script_savings, 441_335);
        assert_eq!(baseline_witness_bytes, 81_740);
        assert_eq!(leaf_witness_bytes, 77_869);
        assert_eq!(arithmetic_witness_savings, 3_871);
        eprintln!(
            "taptree baseline_script={} leaf_script={} script_savings={} baseline_witness={} leaf_witness={} arithmetic_witness_savings={} control_path_delta={} net_revealed_witness_savings={}",
            baseline_script_bytes,
            leaf_script_bytes,
            script_savings,
            baseline_witness_bytes,
            leaf_witness_bytes,
            arithmetic_witness_savings,
            DEPTH_32_CONTROL_BLOCK_DELTA,
            script_savings + arithmetic_witness_savings - DEPTH_32_CONTROL_BLOCK_DELTA,
        );
    }

    #[test]
    #[ignore = "multi-megabyte research-unlimited invalid-signature check"]
    fn changed_message_is_rejected_end_to_end() {
        let (public, mut message, signature) = fixture();
        message[0] ^= 1;
        let secp = Secp256k1::verification_only();
        let public_reference = XOnlyPublicKey::from_slice(&public).unwrap();
        let signature_reference =
            bitcoin::secp256k1::schnorr::Signature::from_slice(&signature).unwrap();
        assert!(secp
            .verify_schnorr(
                &signature_reference,
                &Message::from_digest(message),
                &public_reference,
            )
            .is_err());
        let verifier = verifier(public).unwrap();
        let witness = verifier.witness(message, signature).unwrap();
        let result = execute_script_with_inputs(verifier.script(), witness);
        assert!(!result.success, "changed message unexpectedly verified");
    }
}
