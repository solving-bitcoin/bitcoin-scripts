//! Host-only algebra model for a compact Montgomery slope-chain certificate.
//!
//! This explores a custom BLAKE3 Ed25519-style verifier with a 128-bit
//! challenge. It deliberately generates no Bitcoin Script. The purpose is to
//! validate the two-relation trace algebra and its torsion-coset exception
//! avoidance before investing in a Script kernel.

use bitcoin_lab::{
    curves::ed25519::{basepoint_constants, edwards_d},
    fields::ed25519::{
        u5_balanced_table::{field_digits, modulus},
        u5_packed::packed_words_from_digits,
    },
};
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_traits::{One, Zero};

const MONTGOMERY_A: u32 = 486_662;
const FIELD_PACKED_ITEMS: usize = 8;
const S_GROUPS: usize = 29;
const H_GROUPS: usize = 16;
const SELECTED_GROUPS: usize = S_GROUPS + H_GROUPS;
const TRANSITIONS: usize = SELECTED_GROUPS - 1;
const TRACE_FIELDS_PER_TRANSITION: usize = 2;
const QUOTIENT_HINTS_PER_TRANSITION: usize = 2;
const PACKET_ITEMS: usize =
    TRACE_FIELDS_PER_TRANSITION * FIELD_PACKED_ITEMS + QUOTIENT_HINTS_PER_TRANSITION;
const RESPONSE_TRANSITIONS: usize = S_GROUPS - 1;
const CHALLENGE_TRANSITIONS: usize = H_GROUPS;
const SIGNED_23_METADATA_BITS: usize = 9;
const FIRST_CONTINUITY_METADATA_BITS: usize = 10;
const RESPONSE_Q_METADATA_BITS: usize = FIRST_CONTINUITY_METADATA_BITS
    + SIGNED_23_METADATA_BITS
    + (RESPONSE_TRANSITIONS - 1) * 2 * SIGNED_23_METADATA_BITS;
const CHALLENGE_Q_METADATA_BITS: usize = CHALLENGE_TRANSITIONS * 2 * SIGNED_23_METADATA_BITS;
const TRANSCRIPT_BITS: usize = 512;
const RESPONSE_SCALAR_BITS: usize = 253;

#[derive(Clone, Debug, Eq, PartialEq)]
struct EdwardsPoint {
    x: BigUint,
    y: BigUint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MontgomeryPoint {
    u: BigUint,
    v: BigUint,
}

fn add_mod(lhs: &BigUint, rhs: &BigUint, p: &BigUint) -> BigUint {
    (lhs + rhs) % p
}

fn sub_mod(lhs: &BigUint, rhs: &BigUint, p: &BigUint) -> BigUint {
    if lhs >= rhs {
        lhs - rhs
    } else {
        p - (rhs - lhs)
    }
}

fn mul_mod(lhs: &BigUint, rhs: &BigUint, p: &BigUint) -> BigUint {
    (lhs * rhs) % p
}

fn invert(value: &BigUint, p: &BigUint) -> BigUint {
    assert!(!value.is_zero());
    value.modpow(&(p - BigUint::from(2u8)), p)
}

fn negate(point: &EdwardsPoint, p: &BigUint) -> EdwardsPoint {
    EdwardsPoint {
        x: if point.x.is_zero() {
            BigUint::zero()
        } else {
            p - &point.x
        },
        y: point.y.clone(),
    }
}

fn add(lhs: &EdwardsPoint, rhs: &EdwardsPoint, p: &BigUint, d: &BigUint) -> EdwardsPoint {
    let xyab = mul_mod(&mul_mod(&lhs.x, &lhs.y, p), &mul_mod(&rhs.x, &rhs.y, p), p);
    let tau = mul_mod(d, &xyab, p);
    let x_numerator = add_mod(&mul_mod(&lhs.x, &rhs.y, p), &mul_mod(&lhs.y, &rhs.x, p), p);
    let y_numerator = add_mod(&mul_mod(&lhs.y, &rhs.y, p), &mul_mod(&lhs.x, &rhs.x, p), p);
    EdwardsPoint {
        x: mul_mod(
            &x_numerator,
            &invert(&add_mod(&BigUint::one(), &tau, p), p),
            p,
        ),
        y: mul_mod(
            &y_numerator,
            &invert(&sub_mod(&BigUint::one(), &tau, p), p),
            p,
        ),
    }
}

fn scalar_mul(mut scalar: BigUint, point: &EdwardsPoint, p: &BigUint, d: &BigUint) -> EdwardsPoint {
    let mut accumulator = EdwardsPoint {
        x: BigUint::zero(),
        y: BigUint::one(),
    };
    let mut power = point.clone();
    while !scalar.is_zero() {
        if (&scalar & BigUint::one()) == BigUint::one() {
            accumulator = add(&accumulator, &power, p, d);
        }
        power = add(&power, &power, p, d);
        scalar >>= 1usize;
    }
    accumulator
}

fn sqrt(value: &BigUint, p: &BigUint, sqrt_minus_one: &BigUint) -> BigUint {
    let mut root = value.modpow(&((p + BigUint::from(3u8)) >> 3usize), p);
    if mul_mod(&root, &root, p) != *value {
        root = mul_mod(&root, sqrt_minus_one, p);
    }
    assert_eq!(mul_mod(&root, &root, p), *value);
    root
}

fn to_montgomery(
    point: &EdwardsPoint,
    p: &BigUint,
    montgomery_v_scale: &BigUint,
) -> MontgomeryPoint {
    let one = BigUint::one();
    // The Edwards-to-Montgomery birational map has an exceptional formula at
    // the Edwards order-two point T=(0,-1), but T itself is the ordinary
    // affine Montgomery point (0,0). Zero digits deliberately select T.
    if point.x.is_zero() && point.y == p - &one {
        return MontgomeryPoint {
            u: BigUint::zero(),
            v: BigUint::zero(),
        };
    }
    let u = mul_mod(
        &add_mod(&one, &point.y, p),
        &invert(&sub_mod(&one, &point.y, p), p),
        p,
    );
    let v = mul_mod(&mul_mod(montgomery_v_scale, &u, p), &invert(&point.x, p), p);
    let curve_rhs = add_mod(
        &add_mod(
            &mul_mod(&mul_mod(&u, &u, p), &u, p),
            &mul_mod(&BigUint::from(MONTGOMERY_A), &mul_mod(&u, &u, p), p),
            p,
        ),
        &u,
        p,
    );
    assert_eq!(mul_mod(&v, &v, p), curve_rhs);
    MontgomeryPoint { u, v }
}

fn centered_digits(mut scalar: BigUint, widths_low_to_high: &[usize]) -> Vec<i32> {
    let original = scalar.clone();
    let mut digits = Vec::with_capacity(widths_low_to_high.len());
    let mut offset = 0usize;
    for width in &widths_low_to_high[..widths_low_to_high.len() - 1] {
        let mask = (BigUint::one() << width) - BigUint::one();
        let raw: u32 = (&scalar & &mask).try_into().expect("window digit fits u32");
        scalar >>= width;
        let radix = 1i32 << width;
        let mut digit = i32::try_from(raw).expect("window digit fits i32");
        if digit >= radix / 2 {
            digit -= radix;
            scalar += BigUint::one();
        }
        digits.push(digit);
        offset += width;
    }
    digits.push(scalar.try_into().expect("top digit fits i32"));

    let reconstructed: BigInt = digits
        .iter()
        .zip(widths_low_to_high)
        .scan(0usize, |shift, (digit, width)| {
            let term = (*digit, *shift);
            *shift += width;
            Some(term)
        })
        .fold(BigInt::zero(), |sum, (digit, shift)| {
            sum + (BigInt::from(digit) << shift)
        });
    assert_eq!(reconstructed, BigInt::from(original));
    debug_assert_eq!(
        offset + *widths_low_to_high.last().unwrap(),
        widths_low_to_high.iter().sum::<usize>()
    );
    digits
}

fn signed_multiple(digit: i32, base: &EdwardsPoint, p: &BigUint, d: &BigUint) -> EdwardsPoint {
    let magnitude = scalar_mul(BigUint::from(digit.unsigned_abs()), base, p, d);
    if digit < 0 {
        negate(&magnitude, p)
    } else {
        magnitude
    }
}

fn scalar_order() -> BigUint {
    (BigUint::one() << 252usize)
        + BigUint::parse_bytes(b"27742317777372353535851937790883648493", 10).unwrap()
}

fn standard_edwards_encoding(point: &EdwardsPoint) -> [u8; 32] {
    let mut bytes = point.y.to_bytes_le();
    bytes.resize(32, 0);
    assert_eq!(bytes.len(), 32);
    assert_eq!(bytes[31] >> 7, 0);
    if (&point.x & BigUint::one()) == BigUint::one() {
        bytes[31] |= 0x80;
    }
    bytes.try_into().unwrap()
}

/// Canonical internal field encoding used by the Script backend: eight
/// little-endian u32 words containing the unique biased radix-32 digits.
fn packed_field_encoding(value: &BigUint) -> [u8; 32] {
    let words = packed_words_from_digits(&field_digits(value));
    words
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn centered_scalar_encoding(scalar: &BigUint, widths_low_to_high: &[usize]) -> [u8; 32] {
    assert!(scalar < &scalar_order());
    let mut offset = BigUint::zero();
    let mut position = 0usize;
    for width in &widths_low_to_high[..widths_low_to_high.len() - 1] {
        offset += BigUint::one() << (position + width - 1);
        position += width;
    }
    let payload = offset + scalar;
    assert!(payload.bits() <= 253);
    let mut bytes = payload.to_bytes_le();
    bytes.resize(32, 0);
    bytes.try_into().unwrap()
}

fn positional_points(
    scalar: &BigUint,
    widths: &[usize],
    base: &EdwardsPoint,
    negate_scalar: bool,
    p: &BigUint,
    d: &BigUint,
) -> Vec<EdwardsPoint> {
    let digits = centered_digits(scalar.clone(), widths);
    let mut position_base = base.clone();
    let mut points = Vec::with_capacity(widths.len());
    for (digit, width) in digits.into_iter().zip(widths) {
        let digit = if negate_scalar { -digit } else { digit };
        points.push(signed_multiple(digit, &position_base, p, d));
        for _ in 0..*width {
            position_base = add(&position_base, &position_base, p, d);
        }
    }
    points
}

fn main() {
    let p = modulus();
    let d = edwards_d();
    let sqrt_minus_one = BigUint::parse_bytes(
        b"19681161376707505956807079304988542015446066515923890162744021073123829784752",
        10,
    )
    .unwrap();
    assert_eq!(
        mul_mod(&sqrt_minus_one, &sqrt_minus_one, &p),
        &p - BigUint::one()
    );
    let montgomery_v_scale = sqrt(&(&p - BigUint::from(486_664u32)), &p, &sqrt_minus_one);

    let base = basepoint_constants();
    let base = EdwardsPoint {
        x: base.a,
        y: base.b,
    };
    let t = EdwardsPoint {
        x: BigUint::zero(),
        y: &p - BigUint::one(),
    };
    let u_torsion = EdwardsPoint {
        x: sqrt_minus_one,
        y: BigUint::zero(),
    };
    assert_eq!(add(&u_torsion, &u_torsion, &p, &d), t);
    let identity = EdwardsPoint {
        x: BigUint::zero(),
        y: BigUint::one(),
    };
    assert_eq!(add(&t, &t, &p, &d), identity);

    let s_widths = [vec![8usize; 8], vec![9usize; 21]].concat();
    // Sixteen byte-wide challenge groups cut the fixed -A table almost in
    // half. The top centered digit can still carry to 256, so its selector
    // has nine bits while the other fifteen tables have 129 leaves each.
    let h_widths = vec![8usize; H_GROUPS];
    assert_eq!(s_widths.len(), S_GROUPS);
    assert_eq!(s_widths.iter().sum::<usize>(), 253);
    assert_eq!(h_widths.len(), H_GROUPS);
    assert_eq!(h_widths.iter().sum::<usize>(), 128);

    // The first 15 centered digits can carry one into the final byte. Its
    // authenticated table therefore includes 0..=256 rather than only the
    // nominal 0..=255 range.
    let worst_case_challenge = (BigUint::one() << 128usize) - BigUint::one();
    let worst_case_h_digits = centered_digits(worst_case_challenge, &h_widths);
    assert!((0..=256).contains(worst_case_h_digits.last().unwrap()));

    // End-to-end custom signature fixture. A is fixed/key-specialized. The
    // signature encodes R as the backend-canonical packed u(R-U), and s as
    // the canonical G29 centered-window payload C+s.
    let private_scalar = BigUint::from(987_654_321u64);
    let public_key = scalar_mul(private_scalar.clone(), &base, &p, &d);
    let nonce = BigUint::parse_bytes(b"123456789012345678901234567890123456789", 10).unwrap();
    assert!(nonce < scalar_order());
    let nonce_point = scalar_mul(nonce.clone(), &base, &p, &d);
    let shifted_nonce_point = add(&negate(&u_torsion, &p), &nonce_point, &p, &d);
    let shifted_nonce_m = to_montgomery(&shifted_nonce_point, &p, &montgomery_v_scale);
    let shifted_nonce_encoding = packed_field_encoding(&shifted_nonce_m.u);
    let public_key_encoding = standard_edwards_encoding(&public_key);
    let domain = *blake3::hash(b"bitcoin-lab/custom-ed25519-blake3-slope-v1").as_bytes();
    let message: [u8; 32] = std::array::from_fn(|index| (index as u8).wrapping_mul(7));
    let transcript = [
        domain.as_slice(),
        public_key_encoding.as_slice(),
        shifted_nonce_encoding.as_slice(),
        message.as_slice(),
    ]
    .concat();
    let digest = blake3::hash(&transcript);
    let challenge = BigUint::from_bytes_le(&digest.as_bytes()[..16]);
    assert!(challenge.bits() <= 128);
    let response = (&nonce + &challenge * &private_scalar) % scalar_order();
    let response_encoding = centered_scalar_encoding(&response, &s_widths);
    let signature = [shifted_nonce_encoding, response_encoding].concat();
    assert_eq!(signature.len(), 64);

    let mut s_points = positional_points(&response, &s_widths, &base, false, &p, &d);
    let mut h_points = positional_points(&challenge, &h_widths, &public_key, true, &p, &d);
    let mut prime_points = vec![s_points.pop().unwrap()];
    prime_points.extend(s_points.into_iter().rev());
    prime_points.extend(h_points.drain(..).rev());
    assert_eq!(prime_points.len(), SELECTED_GROUPS);

    // T=(0,-1) has order two. U=(sqrt(-1),0) has order four and 2U=T.
    // Translating every selected subgroup point by T maps a zero digit to a
    // real affine point and preserves signed-table symmetry. Starting in U's
    // coset makes the running point alternate between U and -U, so its
    // Montgomery u coordinate can never equal a selected point's u.
    let selected = prime_points
        .iter()
        .map(|point| add(&t, point, &p, &d))
        .collect::<Vec<_>>();
    for point in &prime_points {
        assert_eq!(
            negate(&add(&t, point, &p, &d), &p),
            add(&t, &negate(point, &p), &p, &d)
        );
    }

    // The selected top-table leaf directly authenticates
    // P_0=U+(T+Q_0)=-U+Q_0 as (u_0,v_0). Q_0 need not remain live: the first
    // checked transition uses v_0 directly, then later transitions use the
    // uniform chained relation.
    let mut current = add(&u_torsion, &selected[0], &p, &d);
    let mut current_m = to_montgomery(&current, &p, &montgomery_v_scale);
    let mut previous_lambda: Option<BigUint> = None;
    let mut previous_selected: Option<MontgomeryPoint> = None;

    for selected_point in &selected[1..] {
        let selected_m = to_montgomery(selected_point, &p, &montgomery_v_scale);
        let denominator = sub_mod(&selected_m.u, &current_m.u, &p);
        assert!(!denominator.is_zero(), "torsion-coset invariant failed");
        let lambda = mul_mod(
            &sub_mod(&selected_m.v, &current_m.v, &p),
            &invert(&denominator, &p),
            &p,
        );
        let next = add(&current, selected_point, &p, &d);
        let next_m = to_montgomery(&next, &p, &montgomery_v_scale);

        let square_relation = sub_mod(
            &mul_mod(&lambda, &lambda, &p),
            &add_mod(
                &add_mod(&current_m.u, &selected_m.u, &p),
                &add_mod(&next_m.u, &BigUint::from(MONTGOMERY_A), &p),
                &p,
            ),
            &p,
        );
        assert!(square_relation.is_zero());

        if let (Some(previous_lambda), Some(previous_selected)) =
            (&previous_lambda, &previous_selected)
        {
            let continuity = sub_mod(
                &add_mod(
                    &mul_mod(&lambda, &sub_mod(&selected_m.u, &current_m.u, &p), &p),
                    &mul_mod(
                        previous_lambda,
                        &sub_mod(&previous_selected.u, &current_m.u, &p),
                        &p,
                    ),
                    &p,
                ),
                &add_mod(&selected_m.v, &previous_selected.v, &p),
                &p,
            );
            assert!(continuity.is_zero());
        } else {
            let initial_continuity = sub_mod(
                &mul_mod(&lambda, &sub_mod(&selected_m.u, &current_m.u, &p), &p),
                &sub_mod(&selected_m.v, &current_m.v, &p),
                &p,
            );
            assert!(initial_continuity.is_zero());
        }

        // This is the eliminated v coordinate. It is reconstructed only in
        // the host proof and is not part of the proposed per-step packet.
        assert_eq!(
            next_m.v,
            sub_mod(
                &mul_mod(&lambda, &sub_mod(&selected_m.u, &next_m.u, &p), &p,),
                &selected_m.v,
                &p,
            )
        );

        current = next;
        current_m = next_m;
        previous_lambda = Some(lambda);
        previous_selected = Some(selected_m);
    }

    let expected_prime = add(
        &scalar_mul(response, &base, &p, &d),
        &negate(&scalar_mul(challenge, &public_key, &p, &d), &p),
        &p,
        &d,
    );
    let expected_torsion = scalar_mul(BigUint::from(SELECTED_GROUPS), &t, &p, &d);
    assert_eq!(expected_prime, nonce_point);
    let shifted_expected = add(&negate(&u_torsion, &p), &expected_prime, &p, &d);
    assert_eq!(
        add(&u_torsion, &expected_torsion, &p, &d),
        negate(&u_torsion, &p)
    );
    assert_eq!(current, shifted_expected);
    assert_eq!(
        current_m.u,
        to_montgomery(&current, &p, &montgomery_v_scale).u
    );
    assert_eq!(packed_field_encoding(&current_m.u), shifted_nonce_encoding);

    println!("model=ed25519_montgomery_slope_chain_host");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=host-algebra");
    println!("execution_class=unclassified");
    println!("bitcoin_script_generated=false");
    println!("challenge_bits=128");
    println!("signature_scheme=rfc8032-incompatible-truncated-blake3-challenge");
    println!("signature_bytes={}", signature.len());
    println!("signature_equation_valid=true");
    println!("transcript=D32||standard_compressed_A32||packed_shifted_u_R32||M32");
    println!("response_encoding=centered_G29_payload_C_plus_s");
    println!("selected_groups={SELECTED_GROUPS}");
    println!("response_groups={S_GROUPS}");
    println!("challenge_groups={H_GROUPS}");
    println!("challenge_group_width_bits=8");
    println!("transitions={TRANSITIONS}");
    println!("trace_fields_per_transition={TRACE_FIELDS_PER_TRANSITION}");
    println!("quotient_hint_items_per_transition={QUOTIENT_HINTS_PER_TRANSITION}");
    println!("packet_items_per_transition={PACKET_ITEMS}");
    println!(
        "trace_circuit_data_items={}",
        TRANSITIONS * 2 * FIELD_PACKED_ITEMS
    );
    println!(
        "quotient_hint_items_total={}",
        TRANSITIONS * QUOTIENT_HINTS_PER_TRANSITION
    );
    println!("packet_items_total={}", TRANSITIONS * PACKET_ITEMS);
    println!(
        "complete_entry_items_with_carried_transcript_and_scalar={}",
        TRANSITIONS * PACKET_ITEMS
    );
    println!("separate_scalar_entry_items=0");
    println!("response_q_metadata_capacity_bits={RESPONSE_Q_METADATA_BITS}");
    println!(
        "response_trace_padding_bits_used={}",
        TRANSCRIPT_BITS - RESPONSE_Q_METADATA_BITS
    );
    println!("challenge_q_metadata_capacity_bits={CHALLENGE_Q_METADATA_BITS}");
    println!("carried_response_scalar_bits={RESPONSE_SCALAR_BITS}");
    println!(
        "challenge_q_metadata_spare_bits={}",
        CHALLENGE_Q_METADATA_BITS - RESPONSE_SCALAR_BITS
    );
    println!(
        "modeled_live_items_after_materializing_8_scalar_words={}",
        TRANSITIONS * PACKET_ITEMS + 8
    );
    println!("top_initializer_compiled_fields=2");
    println!("endpoint_encoding=canonical_u_of_R_minus_U");
    println!("affine_denominators_nonzero=true");
    println!("script_bytes=unmeasured");
    println!("combined_stack_peak=unmeasured");
}
