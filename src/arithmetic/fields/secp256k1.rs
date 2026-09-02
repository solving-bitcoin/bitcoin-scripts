//! Exact hinted multiplication in the secp256k1 base field.
//!
//! Field elements use 29 balanced radix-`2^9` digits. Multiplication uses the
//! exact quarter-square identity
//!
//! `x*y = floor((|x+y|)^2/4) - floor((|x-y|)^2/4)`
//!
//! and one shared 513-item table. Reduction is not an RNS congruence: 56
//! witnessed carries verify the exact integer identity `lhs*rhs = q*p + r`,
//! where `p = 2^256 - 2^32 - 977`. The returned digits are range checked and
//! proved to encode `0 <= r < p`, so there is no CRT-wraparound ambiguity.
//!
//! The multiplication fragments require both operands to have passed
//! [`certify_value`] (or an equivalent exact binding) on the same verified
//! script path. Quotient digits intentionally are not range checked. They are
//! existential coefficients of one exact integer `q`, are never returned, and
//! cannot create a false field result; oversized hostile values fail closed in
//! four-byte Script arithmetic.

use num_bigint::BigUint;
use num_traits::{One, ToPrimitive};

use crate::{
    arithmetic::{scriptint, u31::U31_LOOKUP_STACK_LIMIT},
    support::script::*,
};

/// Number of balanced radix-512 digits in a field value.
pub const FIELD_DIGIT_COUNT: usize = 29;

/// Number of balanced radix-2^23 digits used for the quotient hint.
pub const QUOTIENT_DIGIT_COUNT: usize = 12;

/// Number of exact radix-512 relation carries.
pub const RELATION_CARRY_COUNT: usize = 56;

/// Incremental witness items for one multiplication: quotient plus carries.
pub const HINT_ITEM_COUNT: usize = QUOTIENT_DIGIT_COUNT + RELATION_CARRY_COUNT;

/// Items in the resident quarter-square table.
pub const TABLE_ITEM_COUNT: u32 = 513;

/// Measured combined-stack peak of either multiplication layout with no
/// unrelated live state. The 1,000-item guard is also enforced at generation.
pub const HINTED_MUL_STACK_ITEMS: u32 = 644;

const RADIX_BITS: usize = 9;
const RADIX: i32 = 512;
const HALF_RADIX: i32 = 256;
const TABLE_MAX: usize = 512;
const TABLE_BIAS: i32 = 32_752;
const QUOTIENT_RADIX_BITS: usize = 23;
const QUOTIENT_RADIX: i32 = 1 << QUOTIENT_RADIX_BITS;
const HALF_QUOTIENT_RADIX: i32 = QUOTIENT_RADIX / 2;

/// Balanced radix-512 representation, least-significant digit first.
pub type FieldDigits = [i32; FIELD_DIGIT_COUNT];

/// Mixed-radix quotient representation, least-significant digit first.
pub type QuotientDigits = [i32; QUOTIENT_DIGIT_COUNT];

/// Exact coefficient carries, least-significant carry first.
pub type RelationCarries = [i32; RELATION_CARRY_COUNT];

/// Host-generated hints for one exact modular multiplication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MulHints {
    /// Canonical field result corresponding to these hints.
    pub remainder: BigUint,
    /// Existential quotient coefficients. Canonicality is not a verifier
    /// requirement, but the host generator emits a balanced representation.
    pub quotient: QuotientDigits,
    /// Exact radix-512 relation carries.
    pub carries: RelationCarries,
}

impl MulHints {
    /// Push quotient digits and carries in the order consumed by the gate.
    ///
    /// Stack after: `... q[11] ... q[0] c[55] ... c[0]`, with `c[0]` on top.
    pub fn push_script(&self) -> Script {
        script! {
            { push_balanced(&self.quotient) }
            for carry in self.carries.iter().rev() {
                { *carry }
            }
        }
    }

    /// Return raw Script-number witness items in push order.
    pub fn witness_items(&self) -> Vec<Vec<u8>> {
        self.quotient
            .iter()
            .rev()
            .chain(self.carries.iter().rev())
            .map(|value| scriptnum_item(*value))
            .collect()
    }
}

/// Exact locking-script attribution for the self-contained one-shot gate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OneShotCostBreakdown {
    /// Push the 513 biased quarter-square entries.
    pub table_setup: usize,
    /// Drop the 513 entries after this multiplication.
    pub table_drop: usize,
    /// The 841 signed digit products.
    pub digit_products: usize,
    /// Quotient correction, carry equations, routing, and result validation.
    pub relation_and_output: usize,
}

impl OneShotCostBreakdown {
    /// Complete one-shot fragment size.
    pub fn total(self) -> usize {
        self.table_setup + self.table_drop + self.digit_products + self.relation_and_output
    }

    /// Static lookup-memory overhead.
    pub fn table_overhead(self) -> usize {
        self.table_setup + self.table_drop
    }

    /// Actual per-multiplication computation, excluding table push/drop.
    pub fn computation(self) -> usize {
        self.digit_products + self.relation_and_output
    }
}

/// Exact locking-script attribution when the table remains resident.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResidentCostBreakdown {
    /// One-time table setup.
    pub table_setup: usize,
    /// One multiplication that leaves the table resident.
    pub mul_with_table: usize,
    /// Route one result around the final table drop.
    pub final_cleanup: usize,
}

impl ResidentCostBreakdown {
    /// Setup, one resident multiplication, and final cleanup.
    pub fn one_multiplication_total(self) -> usize {
        self.table_setup + self.mul_with_table + self.final_cleanup
    }
}

/// Return `p = 2^256 - 2^32 - 977`.
pub fn modulus() -> BigUint {
    (BigUint::one() << 256usize) - (BigUint::one() << 32usize) - BigUint::from(977u32)
}

fn balanced_digits_unchecked(value: &BigUint) -> FieldDigits {
    let mut value = value.clone();
    std::array::from_fn(|index| {
        if index + 1 == FIELD_DIGIT_COUNT {
            return value.to_i32().expect("top field digit fits i32");
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
        "secp256k1 field value must be smaller than p"
    );
    balanced_digits_unchecked(value)
}

fn quotient_digits(value: &BigUint) -> QuotientDigits {
    let mut value = value.clone();
    std::array::from_fn(|index| {
        if index + 1 == QUOTIENT_DIGIT_COUNT {
            return value.to_i32().expect("top quotient digit fits i32");
        }
        let unsigned = (&value & BigUint::from((QUOTIENT_RADIX - 1) as u32))
            .to_u32()
            .expect("a quotient digit fits u32") as i32;
        let digit = if unsigned >= HALF_QUOTIENT_RADIX {
            unsigned - QUOTIENT_RADIX
        } else {
            unsigned
        };
        if digit >= 0 {
            value -= BigUint::from(digit as u32);
        } else {
            value += BigUint::from((-digit) as u32);
        }
        value >>= QUOTIENT_RADIX_BITS;
        digit
    })
}

/// Centered radix-512 coefficients of
/// `2^bit_remainder * (977 + 2^32 - 2^256) = -2^bit_remainder*p`.
fn correction_terms(bit_remainder: usize) -> Vec<(usize, i32)> {
    let mut coefficients = [0i32; 32];
    coefficients[0] += 977i32 << bit_remainder;
    coefficients[(32 + bit_remainder) / RADIX_BITS] += 1i32 << ((32 + bit_remainder) % RADIX_BITS);
    coefficients[(256 + bit_remainder) / RADIX_BITS] -=
        1i32 << ((256 + bit_remainder) % RADIX_BITS);
    for index in 0..coefficients.len() - 1 {
        while coefficients[index] > 255 {
            coefficients[index] -= RADIX;
            coefficients[index + 1] += 1;
        }
        while coefficients[index] < -256 {
            coefficients[index] += RADIX;
            coefficients[index + 1] -= 1;
        }
    }
    coefficients
        .into_iter()
        .enumerate()
        .filter(|(_, coefficient)| *coefficient != 0)
        .collect()
}

fn quotient_terms_at(coefficient_index: usize) -> Vec<(usize, i32)> {
    let mut terms = Vec::new();
    for quotient_index in 0..QUOTIENT_DIGIT_COUNT {
        let exponent = QUOTIENT_RADIX_BITS * quotient_index;
        let base_index = exponent / RADIX_BITS;
        let remainder = exponent % RADIX_BITS;
        for (relative_index, coefficient) in correction_terms(remainder) {
            if base_index + relative_index == coefficient_index {
                terms.push((quotient_index, coefficient));
            }
        }
    }
    terms
}

fn relation_carries(
    lhs: &FieldDigits,
    rhs: &FieldDigits,
    quotient: &QuotientDigits,
    remainder: &FieldDigits,
) -> RelationCarries {
    let mut previous = 0i64;
    std::array::from_fn(|coefficient_index| {
        let mut coefficient = previous;
        for lhs_index in 0..FIELD_DIGIT_COUNT {
            if coefficient_index >= lhs_index && coefficient_index - lhs_index < FIELD_DIGIT_COUNT {
                coefficient +=
                    i64::from(lhs[lhs_index]) * i64::from(rhs[coefficient_index - lhs_index]);
            }
        }
        for (quotient_index, multiplier) in quotient_terms_at(coefficient_index) {
            coefficient += i64::from(multiplier) * i64::from(quotient[quotient_index]);
        }
        if coefficient_index < FIELD_DIGIT_COUNT {
            coefficient -= i64::from(remainder[coefficient_index]);
        }
        assert_eq!(
            coefficient % i64::from(RADIX),
            0,
            "exact relation coefficient {coefficient_index} is not divisible by 512"
        );
        let next = coefficient / i64::from(RADIX);
        previous = next;
        i32::try_from(next).expect("honest relation carry fits ScriptNum")
    })
}

/// Generate the quotient/carry witness and canonical result for `lhs*rhs mod p`.
pub fn hinted_mul(lhs: &BigUint, rhs: &BigUint) -> MulHints {
    let p = modulus();
    assert!(lhs < &p, "left operand must be canonical");
    assert!(rhs < &p, "right operand must be canonical");
    let product = lhs * rhs;
    let quotient_value = &product / &p;
    let remainder = &product % &p;
    let lhs_digits = balanced_digits_unchecked(lhs);
    let rhs_digits = balanced_digits_unchecked(rhs);
    let quotient = quotient_digits(&quotient_value);
    let remainder_digits = balanced_digits_unchecked(&remainder);
    let carries = relation_carries(&lhs_digits, &rhs_digits, &quotient, &remainder_digits);
    MulHints {
        remainder,
        quotient,
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

/// Push a canonical field value with digit zero on top.
pub fn push_value(value: &BigUint) -> Script {
    push_balanced(&field_digits(value))
}

/// Push two canonical operands followed by one multiplication's hints.
///
/// This is a convenience for complete witness tests. Composable protocols
/// normally keep certified operands as live script state and push only
/// [`MulHints::push_script`].
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

fn assert_stack_peak(preserved_items: u32, operation_peak: u32, operation: &str) {
    assert!(
        u64::from(preserved_items) + u64::from(operation_peak) <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "{operation} exceeds Bitcoin Script's stack limit"
    );
}

fn table_setup_unchecked() -> Script {
    script! {
        for value in (0..=TABLE_MAX).rev() {
            { ((value * value) / 4) as i32 - TABLE_BIAS }
        }
    }
}

/// Push the 513 biased quarter-square entries, with entry zero on top.
///
/// `preserved_items` is the number of items already live below the table.
pub fn table_setup(preserved_items: u32) -> Script {
    assert_stack_peak(
        preserved_items,
        TABLE_ITEM_COUNT,
        "secp256k1 quarter-square table setup",
    );
    table_setup_unchecked()
}

/// Drop a quarter-square table that is directly on top of the main stack.
pub fn table_drop() -> Script {
    script! {
        for _ in 0..TABLE_MAX / 2 {
            OP_2DROP
        }
        OP_DROP
    }
}

/// Drop a resident table directly below one 29-digit field value.
///
/// Input: `... table value`. Output: `... value`.
pub fn final_table_cleanup_with_one_value() -> Script {
    script! {
        for _ in 0..FIELD_DIGIT_COUNT {
            OP_TOALTSTACK
        }
        { table_drop() }
        for _ in 0..FIELD_DIGIT_COUNT {
            OP_FROMALTSTACK
        }
    }
}

/// Verify that already range-checked balanced digits encode `0 <= value < p`.
fn verify_field_range_keep() -> Script {
    let p = balanced_digits_unchecked(&modulus());
    debug_assert_eq!(p[FIELD_DIGIT_COUNT - 1], 16);
    script! {
        { (FIELD_DIGIT_COUNT - 1) as u32 } OP_PICK
        OP_DUP 0 17 OP_WITHIN OP_VERIFY

        // Top digits 1..15 imply 0 < value < p regardless of the tail.
        OP_DUP 0 OP_GREATERTHAN
        OP_OVER 16 OP_LESSTHAN
        OP_BOOLAND
        OP_IF
            OP_DROP
        OP_ELSE
            // At the two boundaries, scan low-to-high. Every nonzero
            // difference replaces the status, so the final status is the
            // most-significant nonzero difference.
            16 OP_EQUAL
            0
            for index in 0..FIELD_DIGIT_COUNT - 1 {
                { index as u32 + 2 } OP_PICK
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

            // top=16 needs tail<p_tail (negative status); top=0 needs a
            // nonnegative tail. Equality of these booleans proves the range.
            OP_DUP 0 OP_LESSTHAN
            OP_ROT OP_EQUALVERIFY
            OP_DROP
        OP_ENDIF
    }
}

/// Certify one balanced-radix value in place as a canonical field element.
///
/// Input/output: `... d[28] ... d[0]`, with digit zero on top. Lower digits
/// are checked in `[-256,256)`; the field-range verifier supplies the stronger
/// `0..=16` constraint on the top digit and proves the exact integer is below
/// the secp256k1 modulus.
pub fn certify_value() -> Script {
    script! {
        for index in 0..FIELD_DIGIT_COUNT - 1 {
            { index as u32 } OP_PICK
            { -HALF_RADIX } { HALF_RADIX } OP_WITHIN OP_VERIFY
        }
        { verify_field_range_keep() }
    }
}

fn product_into_accumulator(lhs_depth: u32, rhs_depth_after_lhs: u32, table_depth: u32) -> Script {
    let first_lookup_depth = table_depth + 1;
    let second_lookup_depth = table_depth - 1;
    script! {
        { lhs_depth } OP_PICK
        { rhs_depth_after_lhs } OP_PICK
        // Q(|x+y|) - Q(|x-y|). The common table bias cancels.
        OP_2DUP OP_SUB OP_ABS
        { first_lookup_depth } OP_ADD OP_PICK OP_TOALTSTACK
        OP_ADD OP_ABS
        if second_lookup_depth == 1 {
            OP_1ADD
        } else {
            { second_lookup_depth } OP_ADD
        }
        OP_PICK OP_FROMALTSTACK
        OP_SUB
        OP_ADD
    }
}

fn exact_naf_mul(coefficient: u32) -> Script {
    let mut remaining = coefficient;
    let mut digits = Vec::new();
    while remaining != 0 {
        if remaining & 1 == 0 {
            digits.push(0i8);
            remaining >>= 1;
        } else {
            let digit = 2i8 - (remaining % 4) as i8;
            digits.push(digit);
            if digit > 0 {
                remaining -= 1;
            } else {
                remaining += 1;
            }
            remaining >>= 1;
        }
    }
    digits.reverse();
    script! {
        if digits.is_empty() {
            OP_DROP 0
        } else {
            OP_DUP
            for digit in digits.into_iter().skip(1) {
                OP_DUP OP_ADD
                if digit == 1 {
                    OP_OVER OP_ADD
                } else if digit == -1 {
                    OP_OVER OP_SUB
                }
            }
            OP_NIP
        }
    }
}

/// Precomputed shortest chains found by breadth-first search over Script stack
/// operations, with at most five live items and every affine coefficient in
/// `[-511,511]`. Thus even the largest live multiple at an honest quotient
/// endpoint is `511*2^22 < MAX_SCRIPTNUM`.
fn exact_precomputed_mul(coefficient: u32) -> Option<Script> {
    Some(match coefficient {
        1 => script! {},
        2 => script! { OP_DUP OP_ADD },
        4 => script! { OP_DUP OP_ADD OP_DUP OP_ADD },
        8 => script! { OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD },
        15 => script! {
            OP_DUP OP_DUP OP_ADD OP_DUP OP_ADD OP_ADD
            OP_DUP OP_DUP OP_ADD OP_ADD
        },
        16 => script! {
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
        },
        23 => script! {
            OP_DUP OP_DUP OP_ADD OP_2DUP OP_ADD OP_ADD
            OP_2DUP OP_ADD OP_ADD OP_DUP OP_ADD OP_ADD
        },
        31 => script! {
            OP_DUP OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_DUP OP_ADD OP_DUP OP_ADD OP_SWAP OP_SUB
        },
        32 => script! {
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_DUP OP_ADD
        },
        47 => script! {
            OP_DUP OP_2DUP OP_ADD OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_DUP OP_ADD OP_DUP OP_ADD OP_SWAP OP_SUB
        },
        61 => script! {
            OP_DUP OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_2DUP OP_SUB OP_SUB OP_DUP OP_ADD OP_DUP OP_ADD OP_ADD
        },
        64 => script! {
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_DUP OP_ADD OP_DUP OP_ADD
        },
        94 => script! {
            OP_DUP OP_ADD OP_DUP OP_2DUP OP_ADD OP_ADD OP_DUP OP_ADD
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_SWAP OP_SUB
        },
        122 => script! {
            OP_DUP OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_2DUP OP_SUB OP_SUB OP_DUP OP_ADD OP_DUP OP_ADD OP_ADD
            OP_DUP OP_ADD
        },
        128 => script! {
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
        },
        136 => script! {
            OP_DUP OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
        },
        188 => script! {
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_2DUP OP_ADD OP_ADD
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_SWAP OP_SUB
        },
        240 => script! {
            OP_DUP OP_DUP OP_ADD OP_DUP OP_ADD OP_ADD OP_DUP OP_DUP OP_ADD
            OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
        },
        244 => script! {
            OP_DUP OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_2DUP OP_SUB OP_SUB OP_DUP OP_ADD OP_DUP OP_ADD OP_ADD
            OP_DUP OP_ADD OP_DUP OP_ADD
        },
        256 => script! {
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
        },
        _ => return None,
    })
}

fn exact_small_constant_mul(coefficient: u32) -> Script {
    if coefficient <= 1 {
        return script! {};
    }
    let mut candidates = vec![
        scriptint::mul_by_constant(coefficient),
        exact_naf_mul(coefficient),
    ];
    if let Some(chain) = exact_precomputed_mul(coefficient) {
        candidates.push(chain);
    }
    candidates
        .into_iter()
        .min_by_key(|candidate| candidate.clone().compile().len())
        .expect("at least one exact multiplication chain")
}

fn hinted_mul_gate(table_above_inputs: bool) -> Script {
    let mut body = Script::new("exact secp256k1 hinted multiplication");
    body = script! { { body } 0 };
    for coefficient_index in 0..=2 * FIELD_DIGIT_COUNT - 2 {
        let remaining_carries = RELATION_CARRY_COUNT.saturating_sub(coefficient_index) as u32;
        for lhs_index in 0..FIELD_DIGIT_COUNT {
            if coefficient_index >= lhs_index && coefficient_index - lhs_index < FIELD_DIGIT_COUNT {
                let rhs_index = coefficient_index - lhs_index;
                // Above the operands: accumulator, table (in the one-shot
                // layout), unconsumed carries, quotient, rhs, lhs.
                let (lhs_depth, rhs_depth, table_depth) = if table_above_inputs {
                    (
                        TABLE_ITEM_COUNT
                            + 1
                            + remaining_carries
                            + (QUOTIENT_DIGIT_COUNT + FIELD_DIGIT_COUNT) as u32
                            + lhs_index as u32,
                        TABLE_ITEM_COUNT
                            + 2
                            + remaining_carries
                            + QUOTIENT_DIGIT_COUNT as u32
                            + rhs_index as u32,
                        2,
                    )
                } else {
                    (
                        1 + remaining_carries
                            + (QUOTIENT_DIGIT_COUNT + FIELD_DIGIT_COUNT) as u32
                            + lhs_index as u32,
                        2 + remaining_carries + QUOTIENT_DIGIT_COUNT as u32 + rhs_index as u32,
                        (2 * FIELD_DIGIT_COUNT + QUOTIENT_DIGIT_COUNT) as u32
                            + remaining_carries
                            + 2,
                    )
                };
                body = script! {
                    { body }
                    { product_into_accumulator(lhs_depth, rhs_depth, table_depth) }
                };
            }
        }

        for (quotient_index, multiplier) in quotient_terms_at(coefficient_index) {
            let quotient_depth = if table_above_inputs {
                TABLE_ITEM_COUNT + 1
            } else {
                1
            } + remaining_carries
                + quotient_index as u32;
            let multiplication = exact_small_constant_mul(multiplier.unsigned_abs());
            body = script! {
                { body }
                { quotient_depth } OP_PICK
                { multiplication }
                if multiplier > 0 {
                    OP_ADD
                } else {
                    OP_SUB
                }
            };
        }

        if coefficient_index < RELATION_CARRY_COUNT {
            body = if table_above_inputs {
                script! { { body } { TABLE_ITEM_COUNT + 1 } OP_ROLL }
            } else {
                script! { { body } OP_SWAP }
            };
            if coefficient_index < FIELD_DIGIT_COUNT {
                body = script! {
                    { body }
                    OP_DUP { scriptint::mul_by_constant(RADIX as u32) }
                    OP_ROT OP_SWAP OP_SUB
                    if coefficient_index + 1 < FIELD_DIGIT_COUNT {
                        OP_DUP { -HALF_RADIX } { HALF_RADIX } OP_WITHIN OP_VERIFY
                    }
                    OP_TOALTSTACK
                };
            } else {
                body = script! {
                    { body }
                    OP_DUP { scriptint::mul_by_constant(RADIX as u32) }
                    OP_ROT OP_EQUALVERIFY
                };
            }
        } else {
            body = script! { { body } 0 OP_EQUALVERIFY };
        }
    }

    script! {
        { body }
        if table_above_inputs {
            { table_drop() }
        }
        // Drop quotient and both consumed operands.
        for _ in 0..(2 * FIELD_DIGIT_COUNT + QUOTIENT_DIGIT_COUNT) / 2 {
            OP_2DROP
        }
        if (2 * FIELD_DIGIT_COUNT + QUOTIENT_DIGIT_COUNT) % 2 != 0 {
            OP_DROP
        }
        // Restore r with its least-significant digit on top.
        for _ in 0..FIELD_DIGIT_COUNT {
            OP_FROMALTSTACK
        }
        { verify_field_range_keep() }
    }
}

/// Verify one modular multiplication with a private table.
///
/// Input layout (top at right):
/// `preserved | lhs[28..0] rhs[28..0] q[11..0] c[55..0]`.
/// Both operands must already be certified canonical values. The fragment
/// consumes operands and hints, pushes/drops its table, and returns one
/// certified result as `r[28] ... r[0]`.
pub fn mul_mod_hinted(preserved_items: u32) -> Script {
    assert_stack_peak(
        preserved_items,
        HINTED_MUL_STACK_ITEMS,
        "secp256k1 hinted multiplication",
    );
    script! {
        { table_setup_unchecked() }
        { hinted_mul_gate(true) }
    }
}

/// Verify one multiplication while leaving a shared table resident.
///
/// Input layout:
/// `preserved | table | lhs[28..0] rhs[28..0] q[11..0] c[55..0]`.
/// The table must be directly below this gate's state. Output is
/// `preserved | table | r[28..0]`. The operands carry the same prior
/// certification requirement as [`mul_mod_hinted`].
pub fn mul_mod_hinted_with_table(preserved_items: u32) -> Script {
    assert_stack_peak(
        preserved_items,
        HINTED_MUL_STACK_ITEMS,
        "resident-table secp256k1 hinted multiplication",
    );
    hinted_mul_gate(false)
}

fn product_script_bytes(table_above_inputs: bool) -> usize {
    let mut bytes = 0usize;
    for coefficient_index in 0..=2 * FIELD_DIGIT_COUNT - 2 {
        let remaining_carries = RELATION_CARRY_COUNT.saturating_sub(coefficient_index) as u32;
        for lhs_index in 0..FIELD_DIGIT_COUNT {
            if coefficient_index >= lhs_index && coefficient_index - lhs_index < FIELD_DIGIT_COUNT {
                let rhs_index = coefficient_index - lhs_index;
                let (lhs_depth, rhs_depth, table_depth) = if table_above_inputs {
                    (
                        TABLE_ITEM_COUNT
                            + 1
                            + remaining_carries
                            + (QUOTIENT_DIGIT_COUNT + FIELD_DIGIT_COUNT) as u32
                            + lhs_index as u32,
                        TABLE_ITEM_COUNT
                            + 2
                            + remaining_carries
                            + QUOTIENT_DIGIT_COUNT as u32
                            + rhs_index as u32,
                        2,
                    )
                } else {
                    (
                        1 + remaining_carries
                            + (QUOTIENT_DIGIT_COUNT + FIELD_DIGIT_COUNT) as u32
                            + lhs_index as u32,
                        2 + remaining_carries + QUOTIENT_DIGIT_COUNT as u32 + rhs_index as u32,
                        (2 * FIELD_DIGIT_COUNT + QUOTIENT_DIGIT_COUNT) as u32
                            + remaining_carries
                            + 2,
                    )
                };
                bytes += product_into_accumulator(lhs_depth, rhs_depth, table_depth)
                    .compile()
                    .len();
            }
        }
    }
    bytes
}

/// Exact byte attribution for [`mul_mod_hinted`].
pub fn one_shot_cost_breakdown() -> OneShotCostBreakdown {
    let table_setup = table_setup_unchecked().compile().len();
    let table_drop = table_drop().compile().len();
    let digit_products = product_script_bytes(true);
    let gate = hinted_mul_gate(true).compile().len();
    OneShotCostBreakdown {
        table_setup,
        table_drop,
        digit_products,
        relation_and_output: gate - table_drop - digit_products,
    }
}

/// Exact byte attribution for the resident-table API.
pub fn resident_cost_breakdown() -> ResidentCostBreakdown {
    ResidentCostBreakdown {
        table_setup: table_setup_unchecked().compile().len(),
        mul_with_table: hinted_mul_gate(false).compile().len(),
        final_cleanup: final_table_cleanup_with_one_value().compile().len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::{BigInt, RandBigInt, Sign};
    use num_traits::Zero;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::support::execution::execute_script;

    fn reconstruct(digits: &FieldDigits) -> BigInt {
        digits
            .iter()
            .rev()
            .fold(BigInt::zero(), |value, digit| value * RADIX + digit)
    }

    fn signed_balanced_digits(value: &BigInt) -> FieldDigits {
        let mut value = value.clone();
        std::array::from_fn(|index| {
            if index + 1 == FIELD_DIGIT_COUNT {
                return value.to_i32().expect("signed top digit fits i32");
            }
            let mut remainder = (&value % RADIX).to_i32().unwrap();
            if remainder < 0 {
                remainder += RADIX;
            }
            let digit = if remainder >= HALF_RADIX {
                remainder - RADIX
            } else {
                remainder
            };
            value = (value.clone() - digit) / RADIX;
            digit
        })
    }

    fn push_custom_witness(
        lhs: &FieldDigits,
        rhs: &FieldDigits,
        quotient: &QuotientDigits,
        carries: &RelationCarries,
    ) -> Script {
        script! {
            { push_balanced(lhs) }
            { push_balanced(rhs) }
            { push_balanced(quotient) }
            for carry in carries.iter().rev() {
                { *carry }
            }
        }
    }

    fn expected_check(value: &BigUint) -> Script {
        let digits = field_digits(value);
        script! {
            for digit in digits {
                { digit } OP_EQUALVERIFY
            }
            OP_TRUE
        }
    }

    #[test]
    fn exact_constant_chains_cover_quotient_endpoints() {
        for coefficient in [
            1u32, 2, 4, 8, 15, 16, 23, 31, 32, 47, 61, 64, 94, 122, 128, 136, 188, 240, 244, 256,
        ] {
            for value in [
                -HALF_QUOTIENT_RADIX,
                -HALF_QUOTIENT_RADIX + 1,
                -1,
                0,
                1,
                HALF_QUOTIENT_RADIX - 1,
            ] {
                let result = execute_script(script! {
                    { value }
                    { exact_small_constant_mul(coefficient) }
                    { i64::from(value) * i64::from(coefficient) }
                    OP_EQUAL
                });
                assert!(result.success, "{coefficient} * {value}: {result}");
            }
        }
    }

    #[test]
    fn honest_intermediates_have_scriptnum_headroom() {
        let max_scriptnum = u64::from(scriptint::MAX_SCRIPTNUM);
        let lower_q_bound = HALF_QUOTIENT_RADIX as u64;
        // After eleven balanced 23-bit chunks, q<p leaves at most 8 in the
        // top chunk (including rounding carries from the lower chunks).
        let top_q_bound = 8u64;
        let mut previous_carry_bound = 0u64;
        for coefficient_index in 0..=2 * FIELD_DIGIT_COUNT - 2 {
            let product_bound = (0..FIELD_DIGIT_COUNT)
                .filter(|lhs_index| {
                    coefficient_index >= *lhs_index
                        && coefficient_index - *lhs_index < FIELD_DIGIT_COUNT
                })
                .map(|lhs_index| {
                    let rhs_index = coefficient_index - lhs_index;
                    let lhs_bound = if lhs_index + 1 == FIELD_DIGIT_COUNT {
                        16u64
                    } else {
                        HALF_RADIX as u64
                    };
                    let rhs_bound = if rhs_index + 1 == FIELD_DIGIT_COUNT {
                        16u64
                    } else {
                        HALF_RADIX as u64
                    };
                    lhs_bound * rhs_bound
                })
                .sum::<u64>();
            let correction_bound = quotient_terms_at(coefficient_index)
                .into_iter()
                .map(|(index, multiplier)| {
                    let digit_bound = if index + 1 == QUOTIENT_DIGIT_COUNT {
                        top_q_bound
                    } else {
                        lower_q_bound
                    };
                    u64::from(multiplier.unsigned_abs()) * digit_bound
                })
                .sum::<u64>();
            let accumulator_bound = previous_carry_bound + product_bound + correction_bound;
            assert!(
                accumulator_bound <= max_scriptnum,
                "coefficient {coefficient_index} accumulator can overflow"
            );
            let next_carry_bound =
                (accumulator_bound + HALF_RADIX as u64 + RADIX as u64 - 1) / RADIX as u64;
            assert!(
                next_carry_bound * RADIX as u64 <= max_scriptnum,
                "coefficient {coefficient_index} carry multiply can overflow"
            );
            previous_carry_bound = next_carry_bound;
        }
        assert!(511u64 * lower_q_bound <= max_scriptnum);
    }

    #[test]
    fn multiplication_accepts_boundaries_and_seeded_random_values() {
        let p = modulus();
        let mut rng = ChaCha20Rng::seed_from_u64(0x5153_5541_5245);
        let mut cases = vec![
            (BigUint::zero(), BigUint::zero()),
            (BigUint::one(), &p - BigUint::one()),
            (&p - BigUint::one(), &p - BigUint::one()),
        ];
        for _ in 0..8 {
            cases.push((rng.gen_biguint_below(&p), rng.gen_biguint_below(&p)));
        }

        for (lhs, rhs) in cases {
            let hints = hinted_mul(&lhs, &rhs);
            assert_eq!(
                reconstruct(&field_digits(&lhs)),
                BigInt::from_biguint(Sign::Plus, lhs.clone())
            );
            assert_eq!(
                reconstruct(&field_digits(&rhs)),
                BigInt::from_biguint(Sign::Plus, rhs.clone())
            );

            let one_shot = execute_script(script! {
                { push_mul_witness(&lhs, &rhs, &hints) }
                { mul_mod_hinted(0) }
                { expected_check(&hints.remainder) }
            });
            assert!(one_shot.success, "lhs={lhs} rhs={rhs}: {one_shot}");
            assert!(
                one_shot.stats.max_nb_stack_items <= HINTED_MUL_STACK_ITEMS as usize,
                "unexpected one-shot stack peak: {one_shot}"
            );

            let resident = execute_script(script! {
                { table_setup(0) }
                { push_mul_witness(&lhs, &rhs, &hints) }
                { mul_mod_hinted_with_table(0) }
                { final_table_cleanup_with_one_value() }
                { expected_check(&hints.remainder) }
            });
            assert!(resident.success, "resident lhs={lhs} rhs={rhs}: {resident}");
            assert!(
                resident.stats.max_nb_stack_items <= HINTED_MUL_STACK_ITEMS as usize,
                "unexpected resident stack peak: {resident}"
            );

            for value in [&lhs, &rhs, &hints.remainder] {
                let certified = execute_script(script! {
                    { push_value(value) }
                    { certify_value() }
                    for _ in 0..FIELD_DIGIT_COUNT {
                        OP_DROP
                    }
                    OP_TRUE
                });
                assert!(
                    certified.success,
                    "certificate rejected {value}: {certified}"
                );
            }
        }
    }

    #[test]
    fn exact_relation_rejects_malformed_hints_and_non_field_results() {
        let p = modulus();
        let lhs = &p - BigUint::one();
        let rhs = lhs.clone();
        let hints = hinted_mul(&lhs, &rhs);
        let lhs_digits = field_digits(&lhs);
        let rhs_digits = field_digits(&rhs);

        let mut wrong_carries = hints.carries;
        wrong_carries[17] += 1;
        let wrong_carry = execute_script(script! {
            { table_setup(0) }
            { push_custom_witness(&lhs_digits, &rhs_digits, &hints.quotient, &wrong_carries) }
            { mul_mod_hinted_with_table(0) }
            OP_TRUE
        });
        assert!(!wrong_carry.success, "wrong carry was accepted");

        let product = &lhs * &rhs;
        let quotient_value = &product / &p;
        let remainder = &product % &p;
        for (bad_quotient, bad_remainder) in [
            (
                &quotient_value + BigUint::one(),
                BigInt::from_biguint(Sign::Plus, remainder.clone())
                    - BigInt::from_biguint(Sign::Plus, p.clone()),
            ),
            (
                &quotient_value - BigUint::one(),
                BigInt::from_biguint(Sign::Plus, remainder.clone())
                    + BigInt::from_biguint(Sign::Plus, p.clone()),
            ),
        ] {
            let quotient = quotient_digits(&bad_quotient);
            let remainder_digits = signed_balanced_digits(&bad_remainder);
            let carries = relation_carries(&lhs_digits, &rhs_digits, &quotient, &remainder_digits);
            let rejected = execute_script(script! {
                { table_setup(0) }
                { push_custom_witness(&lhs_digits, &rhs_digits, &quotient, &carries) }
                { mul_mod_hinted_with_table(0) }
                OP_TRUE
            });
            assert!(!rejected.success, "non-field remainder was accepted");
        }
    }

    #[test]
    fn quotient_digits_need_not_be_canonical() {
        let p = modulus();
        let lhs = &p - BigUint::one();
        let rhs = lhs.clone();
        let hints = hinted_mul(&lhs, &rhs);
        let lhs_digits = field_digits(&lhs);
        let rhs_digits = field_digits(&rhs);
        let remainder_digits = field_digits(&hints.remainder);
        let mut quotient = hints.quotient;
        quotient[0] += QUOTIENT_RADIX;
        quotient[1] -= 1;
        let carries = relation_carries(&lhs_digits, &rhs_digits, &quotient, &remainder_digits);
        let accepted = execute_script(script! {
            { table_setup(0) }
            { push_custom_witness(&lhs_digits, &rhs_digits, &quotient, &carries) }
            { mul_mod_hinted_with_table(0) }
            { final_table_cleanup_with_one_value() }
            { expected_check(&hints.remainder) }
        });
        assert!(accepted.success, "equivalent quotient encoding: {accepted}");
    }

    #[test]
    fn field_certificate_rejects_boundaries_and_bad_digits() {
        for invalid in [
            balanced_digits_unchecked(&modulus()),
            signed_balanced_digits(&BigInt::from(-1)),
            {
                let mut digits = balanced_digits_unchecked(&BigUint::zero());
                digits[0] = HALF_RADIX;
                digits
            },
        ] {
            let rejected = execute_script(script! {
                { push_balanced(&invalid) }
                { certify_value() }
                OP_TRUE
            });
            assert!(!rejected.success, "invalid field value was accepted");
        }
    }

    #[test]
    fn cost_attribution_is_exact() {
        let one_shot = one_shot_cost_breakdown();
        assert_eq!(
            one_shot.table_setup,
            table_setup_unchecked().compile().len()
        );
        assert_eq!(one_shot.table_drop, table_drop().compile().len());
        assert_eq!(one_shot.total(), mul_mod_hinted(0).compile().len());

        let resident = resident_cost_breakdown();
        assert_eq!(
            resident.mul_with_table,
            mul_mod_hinted_with_table(0).compile().len()
        );
        assert_eq!(
            resident.final_cleanup,
            final_table_cleanup_with_one_value().compile().len()
        );
    }

    #[test]
    #[should_panic(expected = "exceeds Bitcoin Script's stack limit")]
    fn multiplication_rejects_excess_preserved_state() {
        let _ = mul_mod_hinted(U31_LOOKUP_STACK_LIMIT - HINTED_MUL_STACK_ITEMS + 1);
    }
}
