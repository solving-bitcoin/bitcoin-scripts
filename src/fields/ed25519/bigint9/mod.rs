//! Exact hinted multiplication in the Ed25519 base field.
//!
//! Values use 29 balanced radix-512 digits in a factor-8 domain:
//! `E(x) = x / 8 (mod p)`. For encoded inputs `a` and `b`, multiplication
//! returns `8*a*b = E(x*y)`. With `B=512` and `p=2^255-19`, the identity
//! `8*B^28 = p+19` folds every high product coefficient directly:
//!
//! `F_i = 8*C_i + 19*C_(i+28)` for `i=0..27`, and `F_28=19*C_56`.
//!
//! One witnessed residual and 28 exact radix-512 carries prove
//! `F-t*p=r`. The output is derived by Script and certified canonical.

use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, ToPrimitive, Zero};

use crate::{
    arithmetic::{scriptint, u31::U31_LOOKUP_STACK_LIMIT},
    fields::secp256k1::bigint9::{
        factor16::{add_scaled_product, product_arrays, STORED_COEFFICIENT_COUNT},
        karatsuba_coefficients, table_setup,
    },
    support::script::*,
};

/// Number of balanced radix-512 digits in an encoded field value.
pub const FIELD_DIGIT_COUNT: usize = 29;
/// Number of signed residual values in one multiplication hint.
pub const RESIDUAL_ITEM_COUNT: usize = 1;
/// Number of exact radix-512 relation carries.
pub const RELATION_CARRY_COUNT: usize = 28;
/// Incremental witness items for one multiplication.
pub const HINT_ITEM_COUNT: usize = RESIDUAL_ITEM_COUNT + RELATION_CARRY_COUNT;
/// Complete witness items: two encoded operands and one hint group.
pub const MUL_WITNESS_ITEM_COUNT: usize = 2 * FIELD_DIGIT_COUNT + HINT_ITEM_COUNT;
/// Exact combined-stack peak with no unrelated live state.
pub const HINTED_MUL_STACK_ITEMS: u32 = 719;
/// Maximum unrelated state that can coexist under the 1,000-item limit.
pub const MAX_PRESERVED_ITEMS: u32 = U31_LOOKUP_STACK_LIMIT - HINTED_MUL_STACK_ITEMS;
/// Rigorous lower bound for every honest folded residual.
pub const RESIDUAL_MIN: i32 = -5_558;
/// Rigorous upper bound for every honest folded residual.
pub const RESIDUAL_MAX: i32 = 5_557;
/// Rigorous absolute bound for every honest relation carry.
pub const RELATION_CARRY_ABS_BOUND: i32 = 98_834;
/// Rigorous absolute bound before any radix-512 carry extraction.
pub const PRE_CARRY_ABS_BOUND: i32 = 50_602_882;

const RADIX_BITS: usize = 9;
const RADIX: i32 = 512;
const HALF_RADIX: i32 = 256;

/// Balanced radix-512 representation, least-significant digit first.
pub type FieldDigits = [i32; FIELD_DIGIT_COUNT];
/// Exact relation carries, least-significant first.
pub type RelationCarries = [i32; RELATION_CARRY_COUNT];

/// Host-generated witness for one factor-8 field multiplication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MulHints {
    /// Canonical encoded result `8*lhs*rhs mod p`.
    pub remainder: BigUint,
    /// Signed quotient in the folded identity `F-t*p=r`.
    pub residual: i32,
    /// Exact radix-512 carries, least-significant first.
    pub carries: RelationCarries,
}

impl MulHints {
    /// Push `t c[27] ... c[0]`, leaving `c[0]` on top.
    pub fn push_script(&self) -> Script {
        script! {
            { self.residual }
            for carry in self.carries.iter().rev() {
                { *carry }
            }
        }
    }

    /// Return raw Script-number witness items in push order.
    pub fn witness_items(&self) -> Vec<Vec<u8>> {
        std::iter::once(&self.residual)
            .chain(self.carries.iter().rev())
            .map(|value| scriptnum_item(*value))
            .collect()
    }
}

/// Exact locking-script attribution for one private-table multiplication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OneShotCostBreakdown {
    pub table_setup: usize,
    pub table_drop: usize,
    pub product_generation: usize,
    pub folded_relation: usize,
    pub cleanup: usize,
}

impl OneShotCostBreakdown {
    pub fn total(self) -> usize {
        self.table_setup
            + self.table_drop
            + self.product_generation
            + self.folded_relation
            + self.cleanup
    }

    pub fn table_overhead(self) -> usize {
        self.table_setup + self.table_drop
    }

    pub fn computation(self) -> usize {
        self.product_generation + self.folded_relation + self.cleanup
    }
}

/// Return `p = 2^255 - 19`.
pub fn modulus() -> BigUint {
    (BigUint::one() << 255usize) - BigUint::from(19u32)
}

fn balanced_digits_unchecked(value: &BigUint) -> FieldDigits {
    let mut value = value.clone();
    std::array::from_fn(|index| {
        if index + 1 == FIELD_DIGIT_COUNT {
            return value.to_i32().expect("top Ed25519 field digit fits i32");
        }
        let unsigned = (&value & BigUint::from((RADIX - 1) as u32))
            .to_u32()
            .expect("a radix-512 digit fits u32") as i32;
        let digit = if unsigned >= HALF_RADIX {
            unsigned - RADIX
        } else {
            unsigned
        };
        if digit >= 0 {
            value -= BigUint::from(digit as u32);
        } else {
            value += BigUint::from((-digit) as u32);
        }
        value >>= RADIX_BITS;
        digit
    })
}

/// Encode a canonical field value as exact balanced radix-512 digits.
pub fn field_digits(value: &BigUint) -> FieldDigits {
    assert!(
        value < &modulus(),
        "Ed25519 field value must be smaller than p"
    );
    balanced_digits_unchecked(value)
}

/// Encode an ordinary field value as `x/8 mod p`.
pub fn encode(value: &BigUint) -> BigUint {
    let p = modulus();
    assert!(value < &p, "Ed25519 field value must be smaller than p");
    // p == 5 (mod 8), so (3p+1)/8 is the integer inverse of 8 modulo p.
    let inverse_8 = (&p * BigUint::from(3u32) + BigUint::one()) >> 3usize;
    value * inverse_8 % p
}

/// Decode a factor-8 representation to an ordinary field value.
pub fn decode(value: &BigUint) -> BigUint {
    let p = modulus();
    assert!(value < &p, "encoded Ed25519 value must be smaller than p");
    value * BigUint::from(8u32) % p
}

fn folded_coefficients_from_product(product: &[i64; 57]) -> [i64; FIELD_DIGIT_COUNT] {
    std::array::from_fn(|index| {
        let low = if index < 28 { 8 * product[index] } else { 0 };
        low + 19 * product[index + 28]
    })
}

fn reconstruct_coefficients(coefficients: &[i64]) -> BigInt {
    coefficients
        .iter()
        .rev()
        .fold(BigInt::zero(), |value, coefficient| {
            value * RADIX + BigInt::from(*coefficient)
        })
}

/// Generate the residual/carry witness and encoded canonical result.
pub fn hinted_mul(lhs: &BigUint, rhs: &BigUint) -> MulHints {
    let p = modulus();
    assert!(lhs < &p, "left encoded operand must be canonical");
    assert!(rhs < &p, "right encoded operand must be canonical");
    let remainder = (lhs * rhs * BigUint::from(8u32)) % &p;
    let lhs_digits = field_digits(lhs);
    let rhs_digits = field_digits(rhs);
    let remainder_digits = field_digits(&remainder);
    let product = karatsuba_coefficients(&lhs_digits, &rhs_digits);
    let folded = folded_coefficients_from_product(&product);
    let folded_integer = reconstruct_coefficients(&folded);
    let remainder_integer = BigInt::from_biguint(Sign::Plus, remainder.clone());
    let p_integer = BigInt::from_biguint(Sign::Plus, p);
    let delta = folded_integer - remainder_integer;
    assert_eq!(&delta % &p_integer, BigInt::zero());
    let residual_integer = &delta / &p_integer;
    let residual = residual_integer
        .to_i32()
        .unwrap_or_else(|| panic!("factor-8 residual exceeds ScriptNum: {residual_integer}"));
    assert!(
        (RESIDUAL_MIN..=RESIDUAL_MAX).contains(&residual),
        "factor-8 residual exceeds its proven interval"
    );

    let mut previous = 0i64;
    let mut carries = [0i32; RELATION_CARRY_COUNT];
    for coefficient_index in 0..FIELD_DIGIT_COUNT {
        let mut coefficient = previous + folded[coefficient_index];
        if coefficient_index == 0 {
            coefficient += 19 * i64::from(residual);
        }
        if coefficient_index == FIELD_DIGIT_COUNT - 1 {
            coefficient -= 8 * i64::from(residual);
        }
        coefficient -= i64::from(remainder_digits[coefficient_index]);
        if coefficient_index < RELATION_CARRY_COUNT {
            assert_eq!(
                coefficient % i64::from(RADIX),
                0,
                "factor-8 relation coefficient {coefficient_index}"
            );
            previous = coefficient / i64::from(RADIX);
            carries[coefficient_index] =
                i32::try_from(previous).expect("factor-8 relation carry fits ScriptNum");
            assert!(
                carries[coefficient_index].unsigned_abs() <= RELATION_CARRY_ABS_BOUND as u32,
                "factor-8 relation carry exceeds its proven bound"
            );
        } else {
            assert_eq!(coefficient, 0, "final factor-8 relation coefficient");
        }
    }

    MulHints {
        remainder,
        residual,
        carries,
    }
}

fn push_balanced(digits: &[i32]) -> Script {
    script! {
        for digit in digits.iter().rev() {
            { *digit }
        }
    }
}

/// Push a canonical encoded value with digit zero on top.
pub fn push_value(value: &BigUint) -> Script {
    push_balanced(&field_digits(value))
}

/// Push two encoded canonical operands followed by one hint group.
pub fn push_mul_witness(lhs: &BigUint, rhs: &BigUint, hints: &MulHints) -> Script {
    script! {
        { push_value(lhs) }
        { push_value(rhs) }
        { hints.push_script() }
    }
}

fn scriptnum_item(value: i32) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value));
    bytes[..length].to_vec()
}

fn assert_stack_peak(preserved_items: u32, operation: &str) {
    assert!(
        u64::from(preserved_items) + u64::from(HINTED_MUL_STACK_ITEMS)
            <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "{operation} exceeds Bitcoin Script's stack limit"
    );
}

fn verify_field_range_keep_at_depth(value_depth: u32) -> Script {
    let p = balanced_digits_unchecked(&modulus());
    debug_assert_eq!(p[0], -19);
    debug_assert_eq!(p[FIELD_DIGIT_COUNT - 1], 8);
    script! {
        { value_depth + (FIELD_DIGIT_COUNT - 1) as u32 } OP_PICK
        OP_DUP 0 9 OP_WITHIN OP_VERIFY

        // Top digits 1..7 imply 0 < value < p regardless of the tail.
        OP_DUP 0 OP_GREATERTHAN
        OP_OVER 8 OP_LESSTHAN
        OP_BOOLAND
        OP_IF
            OP_DROP
        OP_ELSE
            // At top=0 prove a nonnegative tail; at top=8 prove tail<-19.
            8 OP_NUMEQUAL
            0
            for index in 0..FIELD_DIGIT_COUNT - 1 {
                { value_depth + index as u32 + 2 } OP_PICK
                if p[index] != 0 {
                    2 OP_PICK
                    OP_IF
                        { p[index] } OP_SUB
                    OP_ENDIF
                }
                OP_DUP OP_0NOTEQUAL
                OP_IF
                    OP_NIP
                OP_ELSE
                    OP_DROP
                OP_ENDIF
            }
            OP_DUP 0 OP_LESSTHAN
            OP_ROT OP_EQUALVERIFY
            OP_DROP
        OP_ENDIF
    }
}

/// Certify one encoded balanced-radix value in place as canonical.
pub fn certify_value() -> Script {
    certify_value_at_depth(0)
}

/// Certify a value below `items_above` live stack items.
pub fn certify_value_at_depth(items_above: u32) -> Script {
    assert!(
        u64::from(items_above) + FIELD_DIGIT_COUNT as u64 + 4 <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "Ed25519 field certification exceeds Bitcoin Script's stack limit"
    );
    script! {
        for index in 0..FIELD_DIGIT_COUNT - 1 {
            { items_above + index as u32 } OP_PICK
            { -HALF_RADIX } { HALF_RADIX } OP_WITHIN OP_VERIFY
        }
        { verify_field_range_keep_at_depth(items_above) }
    }
}

fn coefficient_relation() -> Script {
    let carry_depth = 1 + STORED_COEFFICIENT_COUNT as u32;
    let mut body = Script::new("factor-8 Ed25519 folded relation");
    body = script! { { body } { product_arrays() } };
    for coefficient_index in 0..FIELD_DIGIT_COUNT {
        if coefficient_index < 28 {
            body = script! {
                { body }
                { add_scaled_product(
                    coefficient_index,
                    8,
                    coefficient_index != 0,
                    0,
                ) }
                { add_scaled_product(coefficient_index + 28, 19, true, 0) }
            };
        } else {
            body = script! {
                { body }
                { add_scaled_product(56, 19, true, 0) }
            };
        }

        let remaining_carries = RELATION_CARRY_COUNT.saturating_sub(coefficient_index) as u32;
        if coefficient_index == 0 {
            body = script! {
                { body }
                { 1 + STORED_COEFFICIENT_COUNT as u32 + remaining_carries } OP_PICK
                { scriptint::mul_by_constant(19) }
                OP_ADD
            };
        } else if coefficient_index + 1 == FIELD_DIGIT_COUNT {
            body = script! {
                { body }
                { 1 + STORED_COEFFICIENT_COUNT as u32 + remaining_carries } OP_PICK
                { scriptint::mul_by_constant(8) }
                OP_SUB
            };
        }

        if coefficient_index < RELATION_CARRY_COUNT {
            body = script! {
                { body }
                { carry_depth } OP_ROLL
                OP_TUCK { scriptint::mul_by_constant(RADIX as u32) }
                OP_SUB
                OP_DUP { -HALF_RADIX } { HALF_RADIX } OP_WITHIN OP_VERIFY
                OP_TOALTSTACK
            };
        } else {
            body = script! { { body } OP_TOALTSTACK };
        }
    }
    body
}

fn cleanup() -> Script {
    script! {
        for _ in 0..STORED_COEFFICIENT_COUNT / 2 {
            OP_2DROP
        }
        if STORED_COEFFICIENT_COUNT % 2 != 0 {
            OP_DROP
        }
        for _ in 0..(2 * FIELD_DIGIT_COUNT + RESIDUAL_ITEM_COUNT) / 2 {
            OP_2DROP
        }
        if (2 * FIELD_DIGIT_COUNT + RESIDUAL_ITEM_COUNT) % 2 != 0 {
            OP_DROP
        }
        for _ in 0..FIELD_DIGIT_COUNT {
            OP_FROMALTSTACK
        }
        { verify_field_range_keep_at_depth(0) }
    }
}

/// Verify one multiplication of two previously certified encoded values.
///
/// Input: `preserved | lhs[28..0] rhs[28..0] t c[27..0]`.
/// Output: `preserved | r[28..0]`, with digit zero nearest the top.
pub fn mul_mod_hinted(preserved_items: u32) -> Script {
    assert_stack_peak(preserved_items, "factor-8 Ed25519 hinted multiplication");
    script! {
        { table_setup(0) }
        { coefficient_relation() }
        { cleanup() }
    }
}

/// Certify both encoded operands in the raw witness layout.
pub fn certify_mul_operands() -> Script {
    script! {
        { certify_value_at_depth(HINT_ITEM_COUNT as u32) }
        { certify_value_at_depth((HINT_ITEM_COUNT + FIELD_DIGIT_COUNT) as u32) }
    }
}

/// Standalone gate that also certifies both raw witness operands.
pub fn mul_mod_hinted_from_raw_witness(preserved_items: u32) -> Script {
    assert_stack_peak(
        preserved_items,
        "raw factor-8 Ed25519 hinted multiplication",
    );
    script! {
        { certify_mul_operands() }
        { mul_mod_hinted(preserved_items) }
    }
}

/// Compile exact certified-input byte categories.
pub fn one_shot_cost_breakdown() -> OneShotCostBreakdown {
    let parent = crate::fields::secp256k1::bigint9::factor16::one_shot_cost_breakdown();
    OneShotCostBreakdown {
        table_setup: parent.table_setup,
        table_drop: parent.table_drop,
        product_generation: parent.product_generation,
        folded_relation: coefficient_relation().compile_with_policy().len()
            - parent.table_drop
            - parent.product_generation,
        cleanup: cleanup().compile_with_policy().len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{consensus::encode::serialize, Witness};
    use num_bigint::RandBigInt;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::support::execution::execute_raw_script_with_inputs_strict;

    fn witness_items(lhs: &BigUint, rhs: &BigUint, hints: &MulHints) -> Vec<Vec<u8>> {
        field_digits(lhs)
            .iter()
            .rev()
            .chain(field_digits(rhs).iter().rev())
            .map(|digit| scriptnum_item(*digit))
            .chain(hints.witness_items())
            .collect()
    }

    fn execute_case(compiled_gate: &[u8], lhs: &BigUint, rhs: &BigUint) -> (MulHints, usize) {
        let hints = hinted_mul(lhs, rhs);
        let execution = execute_raw_script_with_inputs_strict(
            compiled_gate.to_vec(),
            witness_items(lhs, rhs, &hints),
        );
        assert!(execution.error.is_none(), "factor-8 execution: {execution}");
        assert_eq!(execution.final_stack.len(), FIELD_DIGIT_COUNT);
        for (index, digit) in field_digits(&hints.remainder).iter().rev().enumerate() {
            assert_eq!(execution.final_stack.get(index), scriptnum_item(*digit));
        }
        (hints, execution.stats.max_nb_stack_items)
    }

    #[test]
    fn fold_is_exact_for_every_product_basis_coefficient() {
        let p = BigInt::from_biguint(Sign::Plus, modulus());
        let radix = BigInt::from(RADIX);
        for product_index in 0..57 {
            for basis_value in [-1i64, 1] {
                let mut product = [0i64; 57];
                product[product_index] = basis_value;
                let folded = reconstruct_coefficients(&folded_coefficients_from_product(&product));
                let original = BigInt::from(8 * basis_value)
                    * radix.pow(u32::try_from(product_index).unwrap());
                assert_eq!((folded - original) % &p, BigInt::zero());
            }
        }
    }

    #[test]
    #[ignore = "expensive 20KB generated-script execution; run explicitly with --ignored"]
    fn boundaries_and_seeded_cases_execute() {
        let p = modulus();
        let mut cases = vec![
            (BigUint::zero(), BigUint::zero()),
            (BigUint::one(), &p - BigUint::one()),
            (&p - BigUint::one(), &p - BigUint::one()),
            (&p >> 1usize, &p >> 1usize),
        ];
        let mut rng = ChaCha20Rng::seed_from_u64(0x4544_3235_3531_394d);
        for _ in 0..16 {
            cases.push((rng.gen_biguint_below(&p), rng.gen_biguint_below(&p)));
        }
        let compiled_gate = mul_mod_hinted_from_raw_witness(0)
            .compile_with_policy()
            .to_bytes();
        let mut maximum_peak = 0usize;
        for (lhs, rhs) in cases {
            maximum_peak = maximum_peak.max(execute_case(&compiled_gate, &lhs, &rhs).1);
        }
        assert_eq!(maximum_peak, HINTED_MUL_STACK_ITEMS as usize);
    }

    #[test]
    fn encoding_is_closed_under_multiplication() {
        let p = modulus();
        let logical_values = [
            BigUint::zero(),
            BigUint::one(),
            BigUint::from(2u32),
            BigUint::from(255u32),
            &p >> 1usize,
            &p - BigUint::from(2u32),
            &p - BigUint::one(),
        ];
        for logical_lhs in &logical_values {
            for logical_rhs in &logical_values {
                let lhs = encode(logical_lhs);
                let rhs = encode(logical_rhs);
                let hints = hinted_mul(&lhs, &rhs);
                let logical_product = logical_lhs * logical_rhs % &p;
                assert_eq!(hints.remainder, encode(&logical_product));
                assert_eq!(decode(&hints.remainder), logical_product);
            }
        }
    }

    fn convolution_bounds(lhs: &[u64], rhs: &[u64]) -> Vec<u64> {
        let mut result = vec![0u64; lhs.len() + rhs.len() - 1];
        for (lhs_index, lhs_bound) in lhs.iter().enumerate() {
            for (rhs_index, rhs_bound) in rhs.iter().enumerate() {
                result[lhs_index + rhs_index] += lhs_bound * rhs_bound;
            }
        }
        result
    }

    #[test]
    fn analytic_residual_carry_and_scriptnum_bounds() {
        let low_bounds = [HALF_RADIX as u64; 14];
        let mut high_bounds = [HALF_RADIX as u64; 15];
        high_bounds[14] = 8;
        let mut difference_bounds = [HALF_RADIX as u64; 15];
        difference_bounds[14] = 9;
        let z0 = convolution_bounds(&low_bounds, &low_bounds);
        let z2 = convolution_bounds(&high_bounds, &high_bounds);
        let zd = convolution_bounds(&difference_bounds, &difference_bounds);
        let product_bounds: [u64; 57] = std::array::from_fn(|index| {
            z0.get(index).copied().unwrap_or(0)
                + index
                    .checked_sub(14)
                    .and_then(|i| z0.get(i))
                    .copied()
                    .unwrap_or(0)
                + index
                    .checked_sub(14)
                    .and_then(|i| z2.get(i))
                    .copied()
                    .unwrap_or(0)
                + index
                    .checked_sub(14)
                    .and_then(|i| zd.get(i))
                    .copied()
                    .unwrap_or(0)
                + index
                    .checked_sub(28)
                    .and_then(|i| z2.get(i))
                    .copied()
                    .unwrap_or(0)
        });
        let folded_bounds: [u64; FIELD_DIGIT_COUNT] = std::array::from_fn(|index| {
            (if index < 28 {
                8 * product_bounds[index]
            } else {
                0
            }) + 19 * product_bounds[index + 28]
        });
        let folded_abs = folded_bounds
            .iter()
            .rev()
            .fold(BigUint::zero(), |value, coefficient| {
                value * u32::try_from(RADIX).unwrap() + BigUint::from(*coefficient)
            });
        let p = modulus();
        let positive_residual = (&folded_abs / &p).to_i32().unwrap();
        let negative_residual_abs = ((&folded_abs + &p - BigUint::one()) / &p).to_i32().unwrap();
        assert_eq!(positive_residual, RESIDUAL_MAX);
        assert_eq!(-negative_residual_abs, RESIDUAL_MIN);

        let residual_abs = RESIDUAL_MIN.unsigned_abs() as u64;
        let mut carry_bound = 0u64;
        let mut maximum_carry = 0u64;
        let mut maximum_pre_carry = 0u64;
        for coefficient_index in 0..RELATION_CARRY_COUNT {
            let pre_carry = carry_bound
                + folded_bounds[coefficient_index]
                + if coefficient_index == 0 {
                    19 * residual_abs
                } else {
                    0
                }
                + HALF_RADIX as u64;
            maximum_pre_carry = maximum_pre_carry.max(pre_carry);
            carry_bound = pre_carry.div_ceil(RADIX as u64);
            maximum_carry = maximum_carry.max(carry_bound);
        }
        assert_eq!(maximum_carry, RELATION_CARRY_ABS_BOUND as u64);
        assert_eq!(maximum_pre_carry, PRE_CARRY_ABS_BOUND as u64);
        assert!(maximum_pre_carry < u64::from(scriptint::MAX_SCRIPTNUM));
        assert!(
            19 * product_bounds.iter().copied().max().unwrap()
                < u64::from(scriptint::MAX_SCRIPTNUM)
        );
    }

    #[test]
    #[ignore = "expensive generated-script adversarial execution; run explicitly with --ignored"]
    fn every_hint_item_is_bound() {
        let p = modulus();
        let lhs = &p - BigUint::one();
        let rhs = &p - BigUint::from(2u32);
        let hints = hinted_mul(&lhs, &rhs);
        let compiled_gate = mul_mod_hinted(0).compile_with_policy().to_bytes();
        for carry_index in 0..RELATION_CARRY_COUNT {
            let mut malformed = hints.clone();
            malformed.carries[carry_index] += 1;
            let rejected = execute_raw_script_with_inputs_strict(
                compiled_gate.clone(),
                witness_items(&lhs, &rhs, &malformed),
            );
            assert!(
                rejected.error.is_some(),
                "tampered carry {carry_index} accepted"
            );
        }
        for delta in [-1, 1] {
            let mut malformed = hints.clone();
            malformed.residual += delta;
            let rejected = execute_raw_script_with_inputs_strict(
                compiled_gate.clone(),
                witness_items(&lhs, &rhs, &malformed),
            );
            assert!(
                rejected.error.is_some(),
                "tampered residual {delta} accepted"
            );
        }
    }

    #[test]
    #[ignore = "expensive generated-script malformed-operand execution; run explicitly with --ignored"]
    fn raw_operand_range_is_enforced() {
        let p = modulus();
        let lhs = &p - BigUint::one();
        let rhs = BigUint::from(7u32);
        let hints = hinted_mul(&lhs, &rhs);
        let compiled_gate = mul_mod_hinted_from_raw_witness(0)
            .compile_with_policy()
            .to_bytes();
        let accepted = execute_raw_script_with_inputs_strict(
            compiled_gate.clone(),
            witness_items(&lhs, &rhs, &hints),
        );
        assert!(
            accepted.error.is_none(),
            "canonical operands rejected: {accepted}"
        );

        let mut noncanonical = field_digits(&lhs);
        noncanonical[0] += RADIX;
        let malformed_witness = noncanonical
            .iter()
            .rev()
            .chain(field_digits(&rhs).iter().rev())
            .map(|digit| scriptnum_item(*digit))
            .chain(hints.witness_items())
            .collect();
        let rejected = execute_raw_script_with_inputs_strict(compiled_gate, malformed_witness);
        assert!(rejected.error.is_some(), "noncanonical operand accepted");
    }

    #[test]
    fn exact_stack_limit_is_guarded() {
        assert!(std::panic::catch_unwind(|| mul_mod_hinted(MAX_PRESERVED_ITEMS + 1)).is_err());
    }

    #[test]
    #[ignore = "expensive optimized metric compilation; run explicitly with --ignored"]
    fn benchmark_surface_is_stable() {
        let cost = one_shot_cost_breakdown();
        assert_eq!(cost.total(), mul_mod_hinted(0).compile_with_policy().len());
        assert_eq!(cost.table_overhead(), 1_793);

        let p = modulus();
        let encoded = encode(&(&p - BigUint::one()));
        let hints = hinted_mul(&encoded, &encoded);
        assert_eq!(hints.witness_items().len(), HINT_ITEM_COUNT);
        assert!(serialize(&Witness::from_slice(&hints.witness_items())).len() > 1);
    }
}
