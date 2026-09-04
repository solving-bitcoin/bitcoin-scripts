//! Instance-specialized BIP340 verification over the native secp256k1 field.
//!
//! The generated Script commits to one public key, 32-byte message, and
//! signature. Host code performs the public SHA-256 challenge and scalar
//! multiplications, while Script certifies the remaining affine group equation
//! `R + eP = sG` with the exact bigint9 field multiplier. This is useful when a
//! protocol already fixes the complete signature instance before constructing
//! a tapleaf; it is not a replacement for `OP_CHECKSIG` when the signature is
//! chosen at spend time.

pub mod csfs;

use bitcoin::hashes::{sha256, Hash};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Zero};

use crate::{
    fields::secp256k1::bigint9::{self as field, MulHints, SquareHints},
    support::script::*,
};

/// BIP340's 32-byte x-only public key size.
pub const PUBLIC_KEY_SIZE: usize = 32;
/// BIP340 fixes the signed message input to 32 bytes.
pub const MESSAGE_SIZE: usize = 32;
/// BIP340 signatures are `r || s`, with two 32-byte integers.
pub const SIGNATURE_SIZE: usize = 64;

/// Complete witness items in the optimized verifier: two raw multiplication
/// groups plus one raw square group.
pub const VERIFICATION_WITNESS_ITEMS: usize =
    2 * field::MUL_WITNESS_ITEM_COUNT + field::SQUARE_WITNESS_ITEM_COUNT;

/// The optimized execution first consumes the square while preserving both
/// multiplication groups, then executes a two-product batch.
pub const VERIFICATION_STACK_ITEMS: u32 = 882;

/// Width used by the signed non-adjacent-form scalar multiplication engine.
/// Width five balances the eight-entry odd-multiple tables against one
/// nonzero digit per six positions on average.
pub const WNAF_WINDOW_WIDTH: usize = 5;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AffinePoint {
    pub(super) x: BigUint,
    pub(super) y: BigUint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct JacobianPoint {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

impl JacobianPoint {
    fn infinity() -> Self {
        Self {
            x: BigUint::zero(),
            y: BigUint::one(),
            z: BigUint::zero(),
        }
    }

    fn from_affine(point: &AffinePoint) -> Self {
        Self {
            x: point.x.clone(),
            y: point.y.clone(),
            z: BigUint::one(),
        }
    }

    fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// dbl-2009-l for short-Weierstrass curves with `a = 0`.
    fn double(&self) -> Self {
        if self.is_infinity() || self.y.is_zero() {
            return Self::infinity();
        }
        let p = field::modulus();
        let xx = mul_mod(&self.x, &self.x, &p);
        let yy = mul_mod(&self.y, &self.y, &p);
        let yyyy = mul_mod(&yy, &yy, &p);
        let s = mul_mod(&BigUint::from(4u8), &mul_mod(&self.x, &yy, &p), &p);
        let m = mul_mod(&BigUint::from(3u8), &xx, &p);
        let x = sub_mod(&mul_mod(&m, &m, &p), &add_mod(&s, &s, &p), &p);
        let y = sub_mod(
            &mul_mod(&m, &sub_mod(&s, &x, &p), &p),
            &mul_mod(&BigUint::from(8u8), &yyyy, &p),
            &p,
        );
        let z = mul_mod(&BigUint::from(2u8), &mul_mod(&self.y, &self.z, &p), &p);
        Self { x, y, z }
    }

    /// madd-2007-bl: mixed Jacobian-affine addition for `a = 0`.
    fn add_mixed(&self, rhs: &AffinePoint) -> Self {
        if self.is_infinity() {
            return Self::from_affine(rhs);
        }
        let p = field::modulus();
        let z1z1 = mul_mod(&self.z, &self.z, &p);
        let u2 = mul_mod(&rhs.x, &z1z1, &p);
        let s2 = mul_mod(&rhs.y, &mul_mod(&self.z, &z1z1, &p), &p);
        if u2 == self.x {
            return if s2 == self.y {
                self.double()
            } else {
                Self::infinity()
            };
        }
        let h = sub_mod(&u2, &self.x, &p);
        let hh = mul_mod(&h, &h, &p);
        let i = mul_mod(&BigUint::from(4u8), &hh, &p);
        let j = mul_mod(&h, &i, &p);
        let r = mul_mod(&BigUint::from(2u8), &sub_mod(&s2, &self.y, &p), &p);
        let v = mul_mod(&self.x, &i, &p);
        let x = sub_mod(
            &sub_mod(&mul_mod(&r, &r, &p), &j, &p),
            &add_mod(&v, &v, &p),
            &p,
        );
        let y = sub_mod(
            &mul_mod(&r, &sub_mod(&v, &x, &p), &p),
            &mul_mod(&BigUint::from(2u8), &mul_mod(&self.y, &j, &p), &p),
            &p,
        );
        let z = sub_mod(
            &sub_mod(
                &mul_mod(&add_mod(&self.z, &h, &p), &add_mod(&self.z, &h, &p), &p),
                &z1z1,
                &p,
            ),
            &hh,
            &p,
        );
        Self { x, y, z }
    }

    fn to_affine(&self) -> Option<AffinePoint> {
        if self.is_infinity() {
            return None;
        }
        let p = field::modulus();
        let z_inv = inverse(&self.z, &p);
        let z_inv_2 = mul_mod(&z_inv, &z_inv, &p);
        Some(AffinePoint {
            x: mul_mod(&self.x, &z_inv_2, &p),
            y: mul_mod(&self.y, &mul_mod(&z_inv_2, &z_inv, &p), &p),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SignedScalar {
    negative: bool,
    magnitude: BigUint,
}

impl SignedScalar {
    fn from_bigint(value: BigInt) -> Self {
        let (sign, magnitude) = value.into_parts();
        Self {
            negative: sign == Sign::Minus,
            magnitude,
        }
    }
}

/// A locking script and its hostile-but-checked arithmetic witness for one
/// fixed BIP340 instance.
#[derive(Clone, Debug)]
pub struct VerificationProgram {
    script: Script,
    witness: Vec<Vec<u8>>,
    challenge: Option<BigUint>,
}

impl VerificationProgram {
    /// The complete terminal-predicate script. It leaves exactly one truthy
    /// item on success and no unconsumed witness state.
    pub fn script(&self) -> Script {
        self.script.clone()
    }

    /// The complete witness item vector in Bitcoin bottom-to-top order.
    pub fn witness(&self) -> Vec<Vec<u8>> {
        self.witness.clone()
    }

    /// The BIP340 challenge scalar, or `None` when public encoding checks made
    /// the instance reject before a challenge could be used.
    pub fn challenge(&self) -> Option<&BigUint> {
        self.challenge.as_ref()
    }

    /// Whether this is the common field-certified program rather than an
    /// early rejecting program for malformed or exceptional public inputs.
    pub fn has_field_proof(&self) -> bool {
        !self.witness.is_empty()
    }
}

pub(super) fn group_order() -> BigUint {
    BigUint::parse_bytes(
        b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .expect("constant secp256k1 group order parses")
}

pub(super) fn generator() -> AffinePoint {
    AffinePoint {
        x: BigUint::parse_bytes(
            b"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            16,
        )
        .expect("constant generator x parses"),
        y: BigUint::parse_bytes(
            b"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            16,
        )
        .expect("constant generator y parses"),
    }
}

pub(super) fn sub_mod(lhs: &BigUint, rhs: &BigUint, modulus: &BigUint) -> BigUint {
    if lhs >= rhs {
        lhs - rhs
    } else {
        modulus - (rhs - lhs)
    }
}

pub(super) fn add_mod(lhs: &BigUint, rhs: &BigUint, modulus: &BigUint) -> BigUint {
    (lhs + rhs) % modulus
}

pub(super) fn mul_mod(lhs: &BigUint, rhs: &BigUint, modulus: &BigUint) -> BigUint {
    (lhs * rhs) % modulus
}

fn inverse(value: &BigUint, modulus: &BigUint) -> BigUint {
    debug_assert!(!value.is_zero());
    value.modpow(&(modulus - BigUint::from(2u8)), modulus)
}

fn endomorphism_beta() -> BigUint {
    BigUint::parse_bytes(
        b"7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee",
        16,
    )
    .expect("constant secp256k1 endomorphism beta parses")
}

fn endomorphism_lambda() -> BigUint {
    BigUint::parse_bytes(
        b"5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72",
        16,
    )
    .expect("constant secp256k1 endomorphism lambda parses")
}

fn endomorphism(point: &AffinePoint) -> AffinePoint {
    AffinePoint {
        x: mul_mod(&point.x, &endomorphism_beta(), &field::modulus()),
        y: point.y.clone(),
    }
}

fn round_div(numerator: BigUint, denominator: &BigUint) -> BigUint {
    (numerator + (denominator >> 1usize)) / denominator
}

/// Gallant-Lambert-Vanstone lattice split using the reduced secp256k1 basis.
/// Returns signed `k1,k2` satisfying `k = k1 + lambda*k2 (mod n)`.
fn split_lambda(scalar: &BigUint) -> (SignedScalar, SignedScalar) {
    let n = group_order();
    let a1 = BigUint::parse_bytes(b"3086d221a7d46bcde86c90e49284eb15", 16).unwrap();
    let minus_b1 = BigUint::parse_bytes(b"e4437ed6010e88286f547fa90abfe4c3", 16).unwrap();
    let a2 = BigUint::parse_bytes(b"114ca50f7a8e2f3f657c1108d9d44cfd8", 16).unwrap();
    let b2 = a1.clone();
    let c1 = round_div(scalar * &b2, &n);
    let c2 = round_div(scalar * &minus_b1, &n);

    let scalar = BigInt::from_biguint(Sign::Plus, scalar.clone());
    let c1 = BigInt::from_biguint(Sign::Plus, c1);
    let c2 = BigInt::from_biguint(Sign::Plus, c2);
    let a1 = BigInt::from_biguint(Sign::Plus, a1);
    let a2 = BigInt::from_biguint(Sign::Plus, a2);
    let minus_b1 = BigInt::from_biguint(Sign::Plus, minus_b1);
    let b2 = BigInt::from_biguint(Sign::Plus, b2);

    let original = scalar.clone();
    let k1 = scalar - &c1 * a1 - &c2 * a2;
    // b1 is negative, hence -c1*b1 - c2*b2 = c1*(-b1)-c2*b2.
    let k2 = c1 * minus_b1 - c2 * b2;
    let split = (SignedScalar::from_bigint(k1), SignedScalar::from_bigint(k2));
    debug_assert_eq!(
        (signed_scalar_mod(&split.0, &n)
            + mul_mod(&signed_scalar_mod(&split.1, &n), &endomorphism_lambda(), &n))
            % &n,
        original.to_biguint().expect("input scalar is nonnegative") % &n,
    );
    split
}

fn signed_scalar_mod(scalar: &SignedScalar, modulus: &BigUint) -> BigUint {
    let magnitude = &scalar.magnitude % modulus;
    if scalar.negative && !magnitude.is_zero() {
        modulus - magnitude
    } else {
        magnitude
    }
}

fn wnaf(scalar: &SignedScalar, width: usize) -> Vec<i16> {
    assert!((2..=8).contains(&width));
    let radix = 1u32 << width;
    let half = radix >> 1;
    let mask = BigUint::from(radix - 1);
    let mut value = scalar.magnitude.clone();
    let mut digits = Vec::new();
    while !value.is_zero() {
        let mut digit = 0i16;
        if value.bit(0) {
            let residue = (&value & &mask).to_u32_digits();
            let residue = residue.first().copied().unwrap_or(0);
            digit = if residue >= half {
                residue as i16 - radix as i16
            } else {
                residue as i16
            };
            if digit > 0 {
                value -= BigUint::from(digit as u16);
            } else {
                value += BigUint::from((-digit) as u16);
            }
        }
        digits.push(if scalar.negative { -digit } else { digit });
        value >>= 1usize;
    }
    digits
}

fn batch_to_affine(points: &[JacobianPoint]) -> Vec<AffinePoint> {
    if points.is_empty() {
        return vec![];
    }
    assert!(points.iter().all(|point| !point.is_infinity()));
    let p = field::modulus();
    let mut prefixes = Vec::with_capacity(points.len());
    let mut product = BigUint::one();
    for point in points {
        prefixes.push(product.clone());
        product = mul_mod(&product, &point.z, &p);
    }
    let mut inverse_product = inverse(&product, &p);
    let mut inverses = vec![BigUint::zero(); points.len()];
    for index in (0..points.len()).rev() {
        inverses[index] = mul_mod(&inverse_product, &prefixes[index], &p);
        inverse_product = mul_mod(&inverse_product, &points[index].z, &p);
    }
    points
        .iter()
        .zip(inverses)
        .map(|(point, z_inv)| {
            let z_inv_2 = mul_mod(&z_inv, &z_inv, &p);
            AffinePoint {
                x: mul_mod(&point.x, &z_inv_2, &p),
                y: mul_mod(&point.y, &mul_mod(&z_inv_2, &z_inv, &p), &p),
            }
        })
        .collect()
}

/// Precompute `[1,3,5,...]P` in Jacobian coordinates and normalize the whole
/// table with Montgomery's trick (one field inversion).
fn precompute_odd_multiples(point: &AffinePoint, width: usize) -> Vec<AffinePoint> {
    let entries = 1usize << (width - 2);
    let twice = JacobianPoint::from_affine(point)
        .double()
        .to_affine()
        .expect("a secp256k1 prime-order point does not double to infinity");
    let mut current = JacobianPoint::from_affine(point);
    let mut projective = Vec::with_capacity(entries);
    for _ in 0..entries {
        projective.push(current.clone());
        current = current.add_mixed(&twice);
    }
    batch_to_affine(&projective)
}

pub(super) fn negate_point(point: &AffinePoint) -> AffinePoint {
    let p = field::modulus();
    AffinePoint {
        x: point.x.clone(),
        y: if point.y.is_zero() {
            BigUint::zero()
        } else {
            &p - &point.y
        },
    }
}

fn select_signed(table: &[AffinePoint], digit: i16) -> AffinePoint {
    debug_assert!(digit != 0 && digit & 1 != 0);
    let index = (digit.unsigned_abs() as usize - 1) / 2;
    let point = table[index].clone();
    if digit < 0 {
        negate_point(&point)
    } else {
        point
    }
}

/// Interleaved GLV+wNAF multiplication. Only one odd-multiple table is built;
/// applying beta to it yields the table for `lambda*P` without more additions.
fn scalar_mul(point: &AffinePoint, scalar: &BigUint) -> Option<AffinePoint> {
    let (k1, k2) = split_lambda(scalar);
    let digits_1 = wnaf(&k1, WNAF_WINDOW_WIDTH);
    let digits_2 = wnaf(&k2, WNAF_WINDOW_WIDTH);
    let table = precompute_odd_multiples(point, WNAF_WINDOW_WIDTH);
    let endomorphism_table = table.iter().map(endomorphism).collect::<Vec<_>>();
    let bit_length = digits_1.len().max(digits_2.len());
    let mut accumulator = JacobianPoint::infinity();
    for index in (0..bit_length).rev() {
        accumulator = accumulator.double();
        let digit_1 = digits_1.get(index).copied().unwrap_or(0);
        if digit_1 != 0 {
            accumulator = accumulator.add_mixed(&select_signed(&table, digit_1));
        }
        let digit_2 = digits_2.get(index).copied().unwrap_or(0);
        if digit_2 != 0 {
            accumulator = accumulator.add_mixed(&select_signed(&endomorphism_table, digit_2));
        }
    }
    accumulator.to_affine()
}

pub(super) fn lift_x(x: &BigUint) -> Option<AffinePoint> {
    let p = field::modulus();
    if x >= &p {
        return None;
    }
    let c = (x.modpow(&BigUint::from(3u8), &p) + BigUint::from(7u8)) % &p;
    // p = 3 mod 4, so c^((p+1)/4) is a square root when one exists.
    let mut y = c.modpow(&((&p + BigUint::one()) >> 2usize), &p);
    if mul_mod(&y, &y, &p) != c {
        return None;
    }
    if y.bit(0) {
        y = &p - y;
    }
    Some(AffinePoint { x: x.clone(), y })
}

pub(super) fn point_add(
    lhs: Option<&AffinePoint>,
    rhs: Option<&AffinePoint>,
) -> Option<AffinePoint> {
    let p = field::modulus();
    let (Some(lhs), Some(rhs)) = (lhs, rhs) else {
        return lhs.cloned().or_else(|| rhs.cloned());
    };

    let slope = if lhs.x == rhs.x {
        if add_mod(&lhs.y, &rhs.y, &p).is_zero() {
            return None;
        }
        let numerator = mul_mod(&BigUint::from(3u8), &mul_mod(&lhs.x, &lhs.x, &p), &p);
        let denominator = add_mod(&lhs.y, &lhs.y, &p);
        mul_mod(&numerator, &inverse(&denominator, &p), &p)
    } else {
        let numerator = sub_mod(&rhs.y, &lhs.y, &p);
        let denominator = sub_mod(&rhs.x, &lhs.x, &p);
        mul_mod(&numerator, &inverse(&denominator, &p), &p)
    };

    let x = sub_mod(
        &sub_mod(&mul_mod(&slope, &slope, &p), &lhs.x, &p),
        &rhs.x,
        &p,
    );
    let y = sub_mod(&mul_mod(&slope, &sub_mod(&lhs.x, &x, &p), &p), &lhs.y, &p);
    Some(AffinePoint { x, y })
}

#[cfg(test)]
fn scalar_mul_reference(point: &AffinePoint, scalar: &BigUint) -> Option<AffinePoint> {
    let mut result = None;
    let mut addend = Some(point.clone());
    for bit in 0..256u64 {
        if scalar.bit(bit) {
            result = point_add(result.as_ref(), addend.as_ref());
        }
        addend = point_add(addend.as_ref(), addend.as_ref());
    }
    result
}

fn challenge(r: &[u8; 32], public_key: &[u8; 32], message: &[u8; 32]) -> BigUint {
    let tag_hash = sha256::Hash::hash(b"BIP0340/challenge").to_byte_array();
    let mut preimage = Vec::with_capacity(160);
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(r);
    preimage.extend_from_slice(public_key);
    preimage.extend_from_slice(message);
    BigUint::from_bytes_be(&sha256::Hash::hash(&preimage).to_byte_array()) % group_order()
}

fn scriptnum_item(value: i32) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value));
    bytes[..length].to_vec()
}

fn append_value_witness(witness: &mut Vec<Vec<u8>>, value: &BigUint) {
    witness.extend(
        field::field_digits(value)
            .iter()
            .rev()
            .map(|digit| scriptnum_item(*digit)),
    );
}

fn append_mul_witness(witness: &mut Vec<Vec<u8>>, lhs: &BigUint, rhs: &BigUint, hints: &MulHints) {
    append_value_witness(witness, lhs);
    append_value_witness(witness, rhs);
    witness.extend(hints.witness_items());
}

fn append_square_witness(witness: &mut Vec<Vec<u8>>, value: &BigUint, hints: &SquareHints) {
    append_value_witness(witness, value);
    witness.extend(hints.witness_items());
}

fn bind_value_at_depth(value: &BigUint, items_above: u32) -> Script {
    let digits = field::field_digits(value);
    script! {
        for (index, digit) in digits.into_iter().enumerate() {
            { items_above + index as u32 } OP_PICK
            { digit } OP_EQUALVERIFY
        }
    }
}

fn check_top_value(value: &BigUint) -> Script {
    let digits = field::field_digits(value);
    script! {
        for digit in digits {
            { digit } OP_EQUALVERIFY
        }
    }
}

fn rejecting_program(challenge: Option<BigUint>) -> VerificationProgram {
    VerificationProgram {
        script: script! { OP_FALSE },
        witness: vec![],
        challenge,
    }
}

/// Build an instance-specialized BIP340 verification program.
///
/// This function does not call a native Schnorr verifier. It parses BIP340's
/// ranges and even-y lifts, derives the tagged-hash challenge, computes the two
/// public scalar multiples, and emits an exact Script proof of the remaining
/// affine relation. The public scalar multiplications are therefore part of
/// the trusted generator boundary. The returned witness contains only
/// canonical field operands and exact quotient/carry hints; Script binds every
/// operand to the generated instance before consuming it.
pub fn hinted_verify(
    public_key: [u8; PUBLIC_KEY_SIZE],
    message: [u8; MESSAGE_SIZE],
    signature: [u8; SIGNATURE_SIZE],
) -> VerificationProgram {
    let p = field::modulus();
    let n = group_order();
    let public_x = BigUint::from_bytes_be(&public_key);
    let r_bytes: [u8; 32] = signature[..32]
        .try_into()
        .expect("fixed signature prefix length");
    let r_x = BigUint::from_bytes_be(&r_bytes);
    let s = BigUint::from_bytes_be(&signature[32..]);

    let Some(public_point) = lift_x(&public_x) else {
        return rejecting_program(None);
    };
    if r_x >= p || s >= n {
        return rejecting_program(None);
    }
    let Some(nonce_point) = lift_x(&r_x) else {
        return rejecting_program(None);
    };

    let e = challenge(&r_bytes, &public_key, &message);
    let challenge_point = scalar_mul(&public_point, &e);
    let signature_point = scalar_mul(&generator(), &s);

    // The overwhelmingly common affine branch. Exceptional cases are handled
    // as explicit constant outcomes because the instance is fixed at script
    // generation and affine slope equations have no denominator there.
    let (Some(challenge_point), Some(signature_point)) =
        (challenge_point.as_ref(), signature_point.as_ref())
    else {
        let valid = point_add(Some(&nonce_point), challenge_point.as_ref()) == signature_point;
        return VerificationProgram {
            script: if valid {
                script! { OP_TRUE }
            } else {
                script! { OP_FALSE }
            },
            witness: vec![],
            challenge: Some(e),
        };
    };

    let doubling = nonce_point == *challenge_point;
    if nonce_point.x == challenge_point.x && !doubling {
        // Two distinct curve points with one x coordinate are negatives, so
        // their sum is infinity. `signature_point` is finite in this branch.
        return rejecting_program(Some(e));
    }

    let slope = if doubling {
        let numerator = mul_mod(
            &BigUint::from(3u8),
            &mul_mod(&nonce_point.x, &nonce_point.x, &p),
            &p,
        );
        let denominator = add_mod(&nonce_point.y, &nonce_point.y, &p);
        mul_mod(&numerator, &inverse(&denominator, &p), &p)
    } else {
        let numerator = sub_mod(&challenge_point.y, &nonce_point.y, &p);
        let denominator = sub_mod(&challenge_point.x, &nonce_point.x, &p);
        mul_mod(&numerator, &inverse(&denominator, &p), &p)
    };

    let (denominator, numerator) = if doubling {
        (
            add_mod(&nonce_point.y, &nonce_point.y, &p),
            mul_mod(
                &BigUint::from(3u8),
                &mul_mod(&nonce_point.x, &nonce_point.x, &p),
                &p,
            ),
        )
    } else {
        (
            sub_mod(&challenge_point.x, &nonce_point.x, &p),
            sub_mod(&challenge_point.y, &nonce_point.y, &p),
        )
    };
    let x_difference = sub_mod(&nonce_point.x, &signature_point.x, &p);
    let y_sum = add_mod(&signature_point.y, &nonce_point.y, &p);
    let square_expected = add_mod(
        &add_mod(&signature_point.x, &nonce_point.x, &p),
        &challenge_point.x,
        &p,
    );

    let products = [
        (slope.clone(), denominator, numerator),
        (slope.clone(), x_difference, y_sum),
    ];
    let product_hints = products
        .iter()
        .map(|(lhs, rhs, _)| field::hinted_mul(lhs, rhs))
        .collect::<Vec<_>>();
    let square_hints = field::hinted_square(&slope);

    // Witness layout is G1 | G0 | square, so the square can be consumed first
    // while preserving exactly two multiplication groups. The remaining G1 |
    // G0 layout then feeds the two-product shared-table gate directly.
    let mut witness = Vec::with_capacity(VERIFICATION_WITNESS_ITEMS);
    for (product, hints) in products.iter().zip(&product_hints).rev() {
        append_mul_witness(&mut witness, &product.0, &product.1, hints);
    }
    append_square_witness(&mut witness, &slope, &square_hints);
    debug_assert_eq!(witness.len(), VERIFICATION_WITNESS_ITEMS);

    let square_group_items = field::SQUARE_WITNESS_ITEM_COUNT as u32;
    let mul_group_items = field::MUL_WITNESS_ITEM_COUNT as u32;
    let square_operand_depth = field::HINT_ITEM_COUNT as u32;
    let script = script! {
        // Bind every hostile operand to the fixed BIP340 instance before any
        // arithmetic gate can consume it.
        { bind_value_at_depth(&slope, square_operand_depth) }
        for gate_index in 0..2u32 {
            { bind_value_at_depth(
                &products[gate_index as usize].1,
                square_group_items
                    + gate_index * mul_group_items
                    + field::HINT_ITEM_COUNT as u32,
            ) }
            { bind_value_at_depth(
                &products[gate_index as usize].0,
                square_group_items
                    + gate_index * mul_group_items
                    + field::HINT_ITEM_COUNT as u32
                    + field::FIELD_DIGIT_COUNT as u32,
            ) }
        }

        // A specialized square is materially smaller than treating lambda^2
        // as a third ordinary multiplication, even though it owns a table.
        { field::square_mod_hinted_from_raw_witness(
            (2 * field::MUL_WITNESS_ITEM_COUNT) as u32,
        ) }
        { check_top_value(&square_expected) }

        { field::mul_mod_hinted_batch_from_raw_witness(2, 0) }
        { check_top_value(&products[0].2) }
        { check_top_value(&products[1].2) }
        OP_TRUE
    };

    VerificationProgram {
        script,
        witness,
        challenge: Some(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use crate::support::{execution::execute_script_with_inputs_strict, script::ScriptCompilation};

    fn fixture() -> ([u8; 32], [u8; 32], [u8; 64]) {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[3u8; 32]).expect("fixture secret key");
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let (public_key, _) = XOnlyPublicKey::from_keypair(&keypair);
        let message_bytes = [42u8; 32];
        let message = Message::from_digest(message_bytes);
        let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
        let signature_bytes = *signature.as_ref();
        (public_key.serialize(), message_bytes, signature_bytes)
    }

    fn execute(program: &VerificationProgram) -> crate::support::execution::ExecuteInfo {
        execute_script_with_inputs_strict(program.script(), program.witness())
    }

    #[test]
    fn glv_wnaf_jacobian_engine_matches_the_affine_reference() {
        let n = group_order();
        let generator = generator();
        let mut rng = ChaCha20Rng::seed_from_u64(0x5343_484e_4f52_5221);
        let mut scalars = vec![
            BigUint::zero(),
            BigUint::one(),
            BigUint::from(2u8),
            &n - BigUint::one(),
        ];
        for _ in 0..16 {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            scalars.push(BigUint::from_bytes_be(&bytes) % &n);
        }

        for scalar in scalars {
            let (k1, k2) = split_lambda(&scalar);
            assert!(k1.magnitude.bits() <= 129, "oversized GLV k1");
            assert!(k2.magnitude.bits() <= 129, "oversized GLV k2");
            assert_eq!(
                scalar_mul(&generator, &scalar),
                scalar_mul_reference(&generator, &scalar),
                "GLV/wNAF mismatch for scalar {scalar}"
            );
        }

        assert_eq!(
            scalar_mul(&generator, &endomorphism_lambda()),
            Some(endomorphism(&generator)),
            "beta map must realize multiplication by lambda"
        );
    }

    #[test]
    fn mixed_jacobian_formulas_match_affine_addition() {
        let generator = generator();
        let twice = point_add(Some(&generator), Some(&generator)).unwrap();
        let thrice = point_add(Some(&twice), Some(&generator)).unwrap();
        assert_eq!(
            JacobianPoint::from_affine(&generator).double().to_affine(),
            Some(twice.clone())
        );
        assert_eq!(
            JacobianPoint::from_affine(&twice)
                .add_mixed(&generator)
                .to_affine(),
            Some(thrice)
        );

        let table = precompute_odd_multiples(&generator, WNAF_WINDOW_WIDTH);
        for (index, point) in table.iter().enumerate() {
            let scalar = BigUint::from(2 * index + 1);
            assert_eq!(
                Some(point.clone()),
                scalar_mul_reference(&generator, &scalar),
                "bad odd-multiple table entry {index}"
            );
        }
    }

    #[test]
    fn verifies_a_deterministic_bip340_signature_with_strict_stack_checks() {
        let (public_key, message, signature) = fixture();
        let program = hinted_verify(public_key, message, signature);
        let result = execute(&program);
        let compiled = program.script().compile_with_policy();
        let opcode_count = compiled
            .instructions()
            .map(|instruction| instruction.unwrap())
            .filter(|instruction| {
                matches!(instruction, bitcoin::script::Instruction::Op(opcode) if opcode.to_u8() > 0x60)
            })
            .count();
        let witness_bytes = bitcoin::consensus::encode::serialize(&bitcoin::Witness::from_slice(
            &program.witness(),
        ))
        .len();
        assert!(program.has_field_proof());
        assert!(result.success, "valid BIP340 instance failed: {result}");
        assert_eq!(result.final_stack.len(), 1);
        assert_eq!(compiled.len(), 58_596);
        assert_eq!(witness_bytes, 1_039);
        assert_eq!(program.witness().len(), VERIFICATION_WITNESS_ITEMS);
        assert_eq!(opcode_count, 37_323);
        assert_eq!(
            result.stats.max_nb_stack_items,
            VERIFICATION_STACK_ITEMS as usize
        );
        assert!(compiled.len() > 32 * 1024);
    }

    #[test]
    fn agrees_with_libsecp256k1_on_valid_and_invalid_instances() {
        let (public_key, message, signature_bytes) = fixture();
        let secp = Secp256k1::verification_only();
        let public = XOnlyPublicKey::from_slice(&public_key).unwrap();
        let signature =
            bitcoin::secp256k1::schnorr::Signature::from_slice(&signature_bytes).unwrap();
        assert!(secp
            .verify_schnorr(&signature, &Message::from_digest(message), &public)
            .is_ok());
        assert!(execute(&hinted_verify(public_key, message, signature_bytes)).success);

        let mut wrong_message = message;
        wrong_message[0] ^= 1;
        assert!(secp
            .verify_schnorr(&signature, &Message::from_digest(wrong_message), &public,)
            .is_err());
        assert!(!execute(&hinted_verify(public_key, wrong_message, signature_bytes)).success);

        let mut wrong_signature = signature_bytes;
        wrong_signature[63] ^= 1;
        let wrong = bitcoin::secp256k1::schnorr::Signature::from_slice(&wrong_signature).unwrap();
        assert!(secp
            .verify_schnorr(&wrong, &Message::from_digest(message), &public)
            .is_err());
        assert!(!execute(&hinted_verify(public_key, message, wrong_signature)).success);
    }

    #[test]
    fn rejects_malformed_public_encodings_and_hostile_field_witnesses() {
        let (public_key, message, signature) = fixture();

        let mut invalid_s = signature;
        invalid_s[32..].copy_from_slice(&group_order().to_bytes_be());
        let range_rejection = hinted_verify(public_key, message, invalid_s);
        assert!(!range_rejection.has_field_proof());
        assert!(!execute(&range_rejection).success);

        let mut invalid_r = signature;
        invalid_r[..32].copy_from_slice(&field::modulus().to_bytes_be());
        let nonce_rejection = hinted_verify(public_key, message, invalid_r);
        assert!(!nonce_rejection.has_field_proof());
        assert!(!execute(&nonce_rejection).success);

        let invalid_public_key: [u8; 32] = field::modulus().to_bytes_be().try_into().unwrap();
        let key_rejection = hinted_verify(invalid_public_key, message, signature);
        assert!(!key_rejection.has_field_proof());
        assert!(!execute(&key_rejection).success);

        let honest = hinted_verify(public_key, message, signature);
        for index in [0, honest.witness.len() / 2, honest.witness.len() - 1] {
            let mut corrupted = honest.clone();
            if corrupted.witness[index].is_empty() {
                corrupted.witness[index].push(1);
            } else {
                corrupted.witness[index][0] ^= 1;
            }
            assert!(
                !execute(&corrupted).success,
                "corrupted witness item {index} was accepted"
            );
        }
    }
}
