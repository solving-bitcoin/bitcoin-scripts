//! Deterministic honest argument builders for the custom BLAKE3-128 H16
//! Montgomery-slope verifiers.
//!
//! This is a host-only generation and consistency probe. It derives the
//! response, challenge, every affine trace point and slope, and every
//! profile-specific exact relation quotient (88/92/94 for G29/G31/G32), plus
//! the scalar/transcript carrier metadata and final endpoint. It deliberately
//! does not build or execute the multi-megabyte verifier, its BLAKE3 Script, or
//! any scalar-multiplication Script.

#[allow(dead_code)]
#[path = "ed25519_fixed_table_actual_model.rs"]
mod table_model;

#[allow(dead_code)]
#[path = "ed25519_slope_carrier_codec.rs"]
mod carrier_codec;

use bitcoin::{consensus::encode::serialize, Witness};
use bitcoin_lab::{
    curves::ed25519::{
        basepoint_constants, edwards_d,
        montgomery_slope::{
            chained_transition_host_audit_from_direct_limbs,
            chained_transition_hybrid_host_audit_from_direct_limbs,
            first_transition_host_audit_from_direct_limbs,
            first_transition_hybrid_host_audit_from_direct_limbs, DirectCoordinateLimbs,
            SlopeHints, SlopeTransitionHostAudit, CHAINED_CONTINUITY_QUOTIENT_ABS_MAX,
            CURVE_QUOTIENT_MAX, CURVE_QUOTIENT_MIN, FIRST_CONTINUITY_QUOTIENT_ABS_MAX,
        },
    },
    fields::ed25519::{u5_balanced_table, u5_packed},
};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, ToPrimitive, Zero};

const PUBLIC_KEY_SCALAR: u64 = 987_654_321;
const RESPONSE_GROUPS: usize = 29;
const RESPONSE_TRANSITIONS: usize = RESPONSE_GROUPS - 1;
const CHALLENGE_GROUPS: usize = 16;
const TRANSITIONS: usize = RESPONSE_TRANSITIONS + CHALLENGE_GROUPS;
const PACKED_WORDS: usize = 8;
const TRACE_ITEMS_PER_PACKET: usize = 2 * PACKED_WORDS;
const Q_ITEMS_PER_PACKET: usize = 2;
const PACKET_ITEMS: usize = TRACE_ITEMS_PER_PACKET + Q_ITEMS_PER_PACKET;
const TRACE_ITEMS: usize = TRANSITIONS * TRACE_ITEMS_PER_PACKET;
const HINT_ITEMS: usize = TRANSITIONS * Q_ITEMS_PER_PACKET;
const ENTRY_ITEMS: usize = TRANSITIONS * PACKET_ITEMS;
const QFREE_SCALAR_ITEMS: usize = 8;
const QFREE_ENTRY_ITEMS: usize = TRACE_ITEMS + QFREE_SCALAR_ITEMS;
const G31_RESPONSE_GROUPS: usize = 31;
const G31_RESPONSE_TRANSITIONS: usize = G31_RESPONSE_GROUPS - 1;
const G31_TRANSITIONS: usize = G31_RESPONSE_TRANSITIONS + CHALLENGE_GROUPS;
const G31_TRACE_ITEMS: usize = G31_TRANSITIONS * TRACE_ITEMS_PER_PACKET;
const G31_ENTRY_ITEMS: usize = G31_TRACE_ITEMS + QFREE_SCALAR_ITEMS;
const G31_WIDTH9_LOWER_POSITIONS: [usize; 5] = [20, 21, 22, 23, 26];
const EXPECTED_G31_RESPONSE_WIDTHS: [usize; G31_RESPONSE_GROUPS] = [
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 8, 8, 9, 8, 8, 8, 8,
];
const G31_PROJECTED_LINKED_SCRIPT_BYTES: usize = 3_853_845;
const EXPECTED_G31_Z_HEX: &str = "2d58fc6d0857cc2724cd2283b9b4774f197d05a0000102040808081010101000";
const EXPECTED_G31_ARGUMENT_WITNESS_BYTES: usize = 3_721;
const EXPECTED_G31_TRACE_VECTOR_BYTES: usize = 3_682;
const EXPECTED_G31_SCALAR_VECTOR_BYTES: usize = 40;
const EXPECTED_G31_ARGUMENT_WITNESS_BLAKE3: &str =
    "807cfdeab38e23316ca5988b9b229ae1d64cbebe2c6261db9690e16a3ddc0110";
const EXPECTED_G31_CURVE_QUOTIENT_INTERVAL: (i32, i32) = (-1_228_890, 911_978);
const EXPECTED_G31_CURVE_CARRY_INTERVAL: (i64, i64) = (-23_346_570, 21_167_866);
const EXPECTED_G31_FIRST_CONTINUITY_QUOTIENT: i32 = 38_337;
const EXPECTED_G31_FIRST_CONTINUITY_CARRY_INTERVAL: (i64, i64) = (-6_554_982, 10_386_674);
const EXPECTED_G31_CHAINED_CONTINUITY_QUOTIENT_INTERVAL: (i32, i32) = (-760_980, 643_390);
const EXPECTED_G31_CHAINED_CONTINUITY_CARRY_INTERVAL: (i64, i64) = (-31_878_743, 32_260_603);
const EXPECTED_G31_COMPLETE_WITNESS_CONSTANT: usize = 3_760;
const EXPECTED_G31_TARGET_WEIGHT_CONSTANT: usize = 4_138;
const EXPECTED_G31_MINIMUM_BLOCK_WEIGHT_CONSTANT: usize = 4_906;
const G32_RESPONSE_GROUPS: usize = 32;
const G32_RESPONSE_TRANSITIONS: usize = G32_RESPONSE_GROUPS - 1;
const G32_TRANSITIONS: usize = G32_RESPONSE_TRANSITIONS + CHALLENGE_GROUPS;
const G32_TRACE_ITEMS: usize = G32_TRANSITIONS * TRACE_ITEMS_PER_PACKET;
const G32_ENTRY_ITEMS: usize = G32_TRACE_ITEMS + QFREE_SCALAR_ITEMS;
const G32_U5_FINAL_PACKET_ITEMS: usize = 51 + PACKED_WORDS;
const G32_U5_TRACE_ITEMS: usize =
    G32_TRACE_ITEMS - TRACE_ITEMS_PER_PACKET + G32_U5_FINAL_PACKET_ITEMS;
const G32_U5_ENTRY_ITEMS: usize = G32_U5_TRACE_ITEMS + QFREE_SCALAR_ITEMS;
const G32_WIDTH7_LOWER_POSITIONS: [usize; 3] = [21, 25, 29];
const EXPECTED_G32_RESPONSE_WIDTHS: [usize; G32_RESPONSE_GROUPS] = [
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 7, 8, 8, 8, 7, 8, 8,
];
const EXPECTED_G32_Z_HEX: &str = "2d58fc6d0857cc2724cd2283b9b4774f197d05a0804040404020202020101000";
const EXPECTED_G32_TRACE_VECTOR_BYTES: usize = 3_762;
const EXPECTED_G32_SCALAR_VECTOR_BYTES: usize = 40;
const EXPECTED_G32_ARGUMENT_WITNESS_BYTES: usize = 3_801;
const EXPECTED_G32_ARGUMENT_WITNESS_BLAKE3: &str =
    "487a1cf549ca480ad397b31d976957f808d8ccca917285371f59397ba2247e03";
const EXPECTED_G32_U5_TRACE_VECTOR_BYTES: usize = 3_824;
const EXPECTED_G32_U5_ARGUMENT_WITNESS_BYTES: usize = 3_863;
const EXPECTED_G32_U5_ARGUMENT_WITNESS_BLAKE3: &str =
    "896812f002f5c8b1a2816eed80ceb84e9822a9202ae226771a48091a6ef8c5d1";
const EXPECTED_G32_U5_COMPLETE_WITNESS_CONSTANT: usize = 3_902;
const EXPECTED_G32_U5_TARGET_WEIGHT_CONSTANT: usize = 4_280;
const EXPECTED_G32_U5_MINIMUM_BLOCK_WEIGHT_CONSTANT: usize = 5_048;
const EXPECTED_G32_U5_CONSERVATIVE_ARGUMENT_WITNESS_BYTES: usize = 4_617;
const EXPECTED_G32_U5_CONSERVATIVE_TARGET_WEIGHT_CONSTANT: usize = 5_034;
const EXPECTED_G32_U5_CONSERVATIVE_MINIMUM_BLOCK_WEIGHT_CONSTANT: usize = 5_802;
const EXPECTED_G32_TRANSITION_AUDIT_BLAKE3: &str =
    "39b80a67b6be1791810841c8bcd99fa894c356f93f8f499d03ddf20ce6c83b95";
const EXPECTED_G32_CURVE_QUOTIENT_INTERVAL: (i32, i32) = (-1_228_890, 911_978);
const EXPECTED_G32_CURVE_CARRY_INTERVAL: (i64, i64) = (-23_346_570, 21_167_866);
const EXPECTED_G32_FIRST_CONTINUITY_QUOTIENT: i32 = -249_700;
const EXPECTED_G32_FIRST_CONTINUITY_CARRY_INTERVAL: (i64, i64) = (-16_963_155, 14_977_586);
const EXPECTED_G32_CHAINED_CONTINUITY_QUOTIENT_INTERVAL: (i32, i32) = (-760_980, 643_390);
const EXPECTED_G32_CHAINED_CONTINUITY_CARRY_INTERVAL: (i64, i64) = (-31_878_743, 32_260_603);
const G32_HYBRID_U5_LINKED_SCRIPT_BYTES: usize = 2_999_983;
const G32_HYBRID_U5_LINKED_SCRIPT_STATIC_NON_PUSH_OPCODES: usize = 1_729_242;
const SCALAR_BITS: usize = 253;
const SCALAR_CARRIER_ITEMS: usize = 29;
const SCALAR_CARRIER_BITS: usize = 9;
const SCALAR_CARRIED_BITS: usize = SCALAR_CARRIER_ITEMS * SCALAR_CARRIER_BITS;
const TRANSCRIPT_BITS: usize = 512;
const TRANSCRIPT_CARRIED_BITS: usize = 513;
const TRANSCRIPT_CHUNK_WIDTHS: [usize; RESPONSE_TRANSITIONS] = [
    21, 20, 20, 20, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
    18, 18, 18, 18,
];
const PRODUCT_STARTS: [usize; 16] = [0, 4, 8, 12, 15, 18, 21, 24, 27, 30, 33, 36, 39, 42, 45, 48];
const LINEAR_STARTS: [usize; 9] = [0, 4, 10, 16, 22, 28, 34, 40, 46];

const EXPECTED_PUBLIC_KEY: [u8; 32] = [
    0x7d, 0xb0, 0xdc, 0x92, 0x22, 0xf3, 0xc1, 0x83, 0x45, 0x7d, 0xdd, 0xe4, 0xc7, 0x08, 0xde, 0x8e,
    0x5e, 0xa6, 0xbf, 0x3d, 0x5c, 0x44, 0x04, 0xcc, 0xa1, 0x4b, 0x32, 0x72, 0x9a, 0x05, 0xc3, 0x2a,
];
const EXPECTED_DOMAIN_HEX: &str =
    "fa127341786f99905cbe988ae146443624be8eaf478ff357bd1068f01863b581";
const EXPECTED_MESSAGE_HEX: &str =
    "00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9";
const EXPECTED_RTILDE_HEX: &str =
    "b30df25e5fc18a3c9bbe43dc66880f1419e7e96f678e7572fec75948cac6743d";
const EXPECTED_Z_HEX: &str = "2d58fc6d0857cc27a44da4064144170f19fd8521040810204080000102040800";
const EXPECTED_CHALLENGE: &str = "182193721635494548417245769475669779992";
const EXPECTED_RESPONSE: &str = "179944416555824166728582174042849730468341602221";
const EXPECTED_V_SCALE: &str =
    "6853475219497561581579357271197624642482790079785650197046958215289687604742";
const EXPECTED_ARGUMENT_WITNESS_BYTES: usize = 3_958;
const EXPECTED_ARGUMENT_WITNESS_BLAKE3: &str =
    "972a0d8d76b4246f88b24aeb148813bc9c863c9ee16ecfb52bb1026a4ba71c6a";
const EXPECTED_QFREE_ARGUMENT_WITNESS_BYTES: usize = 3_561;
const EXPECTED_QFREE_TRACE_VECTOR_BYTES: usize = 3_522;
const EXPECTED_QFREE_SCALAR_VECTOR_BYTES: usize = 40;
const EXPECTED_QFREE_ARGUMENT_WITNESS_BLAKE3: &str =
    "a78ec4fe4999fa3d00c6412e7119117d3b0ce1296e2a2c63c9c18beaa624eddd";
const EXPECTED_QFREE_CURVE_QUOTIENT_INTERVAL: (i32, i32) = (-977_396, 517_495);
const EXPECTED_QFREE_CURVE_CARRY_INTERVAL: (i64, i64) = (-15_502_210, 18_536_294);
const EXPECTED_QFREE_FIRST_CONTINUITY_QUOTIENT: i32 = 38_337;
const EXPECTED_QFREE_FIRST_CONTINUITY_CARRY_INTERVAL: (i64, i64) = (-6_554_982, 10_386_674);
const EXPECTED_QFREE_CHAINED_CONTINUITY_QUOTIENT_INTERVAL: (i32, i32) = (-760_980, 716_035);
const EXPECTED_QFREE_CHAINED_CONTINUITY_CARRY_INTERVAL: (i64, i64) = (-33_165_039, 32_260_603);
const EXPECTED_QFREE_COMPLETE_WITNESS_CONSTANT: usize = 3_600;
const EXPECTED_QFREE_TARGET_WEIGHT_CONSTANT: usize = 3_978;
const EXPECTED_QFREE_MINIMUM_BLOCK_WEIGHT_CONSTANT: usize = 4_746;
const CONSERVATIVE_QFREE_ARGUMENT_WITNESS_BYTES: usize = 4_275;
const CONSERVATIVE_QFREE_TARGET_WEIGHT_CONSTANT: usize = 4_692;
const CONSERVATIVE_QFREE_MINIMUM_BLOCK_WEIGHT_CONSTANT: usize = 5_460;
const CONSERVATIVE_ARGUMENT_WITNESS_BYTES: usize = 4_667;
const TARGET_STRIPPED_WEIGHT: usize = 376;
const WITNESS_MARKER_FLAG_BYTES: usize = 2;
const LEAF_COMPACT_SIZE_BYTES: usize = 5;
const SERIALIZED_CONTROL_BLOCK_BYTES: usize = 34;
const MINIMUM_OTHER_BLOCK_WEIGHT: usize = 768;

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

#[derive(Clone, Debug)]
struct Packet {
    u_next: BigUint,
    lambda_next: BigUint,
    selected_direct: DirectCoordinateLimbs,
    hints: SlopeHints,
    audit: SlopeTransitionHostAudit,
}

/// Host model of the proposed expanded state kept between slope transitions.
///
/// `lambda_stored_digits` deliberately names the exact biased `[0,31]`
/// decoder output. The streamed product maps those selector codes to centered
/// multiples; subtracting 16 here would change that kernel contract.
#[derive(Clone, Debug, Eq, PartialEq)]
struct HybridState {
    u_product_limbs: [i32; 16],
    lambda_stored_digits: [i32; 51],
    selected_direct: DirectCoordinateLimbs,
}

#[derive(Clone, Copy, Debug)]
struct WireAudit {
    q_continuity: i32,
    q_curve: i32,
    continuity_metadata: u16,
    curve_metadata: u16,
    continuity_q_bits: usize,
    lambda_padding: u8,
    u_padding: u8,
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
    let x_num = add_mod(&mul_mod(&lhs.x, &rhs.y, p), &mul_mod(&lhs.y, &rhs.x, p), p);
    let y_num = add_mod(&mul_mod(&lhs.y, &rhs.y, p), &mul_mod(&lhs.x, &rhs.x, p), p);
    EdwardsPoint {
        x: mul_mod(&x_num, &invert(&add_mod(&BigUint::one(), &tau, p), p), p),
        y: mul_mod(&y_num, &invert(&sub_mod(&BigUint::one(), &tau, p), p), p),
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

fn sqrt_mod(value: &BigUint, p: &BigUint, sqrt_minus_one: &BigUint) -> BigUint {
    let mut root = value.modpow(&((p + BigUint::from(3u8)) >> 3usize), p);
    if mul_mod(&root, &root, p) != *value {
        root = mul_mod(&root, sqrt_minus_one, p);
    }
    assert_eq!(mul_mod(&root, &root, p), *value);
    root
}

fn to_montgomery(point: &EdwardsPoint, p: &BigUint, v_scale: &BigUint) -> MontgomeryPoint {
    let one = BigUint::one();
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
    let v = mul_mod(&mul_mod(v_scale, &u, p), &invert(&point.x, p), p);
    let u2 = mul_mod(&u, &u, p);
    assert_eq!(
        mul_mod(&v, &v, p),
        add_mod(
            &add_mod(
                &mul_mod(&u2, &u, p),
                &mul_mod(&BigUint::from(486_662u32), &u2, p),
                p,
            ),
            &u,
            p,
        )
    );
    MontgomeryPoint { u, v }
}

fn scalar_order() -> BigUint {
    (BigUint::one() << 252usize)
        + BigUint::parse_bytes(b"27742317777372353535851937790883648493", 10)
            .expect("scalar order parses")
}

fn response_widths() -> Vec<usize> {
    [vec![8usize; 8], vec![9usize; 21]].concat()
}

fn g31_response_widths() -> Vec<usize> {
    let widths = (0..G31_RESPONSE_GROUPS)
        .map(|position| {
            if position < G31_RESPONSE_TRANSITIONS && G31_WIDTH9_LOWER_POSITIONS.contains(&position)
            {
                9
            } else {
                8
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(widths.len(), G31_RESPONSE_GROUPS);
    assert_eq!(widths, EXPECTED_G31_RESPONSE_WIDTHS);
    assert_eq!(widths.iter().sum::<usize>(), SCALAR_BITS);
    assert_eq!(widths[G31_RESPONSE_GROUPS - 1], 8);
    widths
}

fn g32_response_widths() -> Vec<usize> {
    let widths = (0..G32_RESPONSE_GROUPS)
        .map(|position| {
            if position < G32_RESPONSE_TRANSITIONS && G32_WIDTH7_LOWER_POSITIONS.contains(&position)
            {
                7
            } else {
                8
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(widths.len(), G32_RESPONSE_GROUPS);
    assert_eq!(widths, EXPECTED_G32_RESPONSE_WIDTHS);
    assert_eq!(widths.iter().sum::<usize>(), SCALAR_BITS);
    assert_eq!(widths[G32_RESPONSE_GROUPS - 1], 8);
    widths
}

fn centered_digits(mut scalar: BigUint, widths: &[usize]) -> Vec<i32> {
    let original = scalar.clone();
    let mut result = Vec::with_capacity(widths.len());
    let mut shift = 0usize;
    for width in &widths[..widths.len() - 1] {
        let mask = (BigUint::one() << width) - BigUint::one();
        let raw = (&scalar & mask).to_u32().expect("window residue fits u32");
        scalar >>= width;
        let radix = 1i32 << width;
        let mut digit = raw as i32;
        if digit >= radix / 2 {
            digit -= radix;
            scalar += BigUint::one();
        }
        result.push(digit);
        shift += width;
    }
    result.push(scalar.to_i32().expect("top digit fits i32"));
    let recovered = result
        .iter()
        .zip(widths)
        .scan(0usize, |position, (digit, width)| {
            let term = BigInt::from(*digit) << *position;
            *position += width;
            Some(term)
        })
        .fold(BigInt::zero(), |sum, term| sum + term);
    assert_eq!(recovered, BigInt::from(original));
    assert_eq!(
        shift + widths[widths.len() - 1],
        widths.iter().sum::<usize>()
    );
    result
}

/// Bias each little-endian challenge byte independently. If
/// `e_i=byte_i-127`, then `h=sum(e_i*2^(8i))+K_127`, where the fixed
/// `K_127=0x7f7f...7f` contribution is folded into the response initializer.
fn independent_challenge_digits(challenge: &BigUint) -> Vec<i32> {
    let mut bytes = challenge.to_bytes_le();
    assert!(bytes.len() <= CHALLENGE_GROUPS);
    bytes.resize(CHALLENGE_GROUPS, 0);
    let digits = bytes
        .into_iter()
        .map(|byte| i32::from(byte) - 127)
        .collect::<Vec<_>>();
    let reconstructed = digits
        .iter()
        .enumerate()
        .fold(BigInt::zero(), |sum, (position, digit)| {
            sum + (BigInt::from(*digit) << (8 * position))
        });
    assert_eq!(
        reconstructed + BigInt::from(table_model::h16_independent_challenge_bias_scalar()),
        BigInt::from(challenge.clone())
    );
    assert!(digits.iter().all(|digit| (-127..=128).contains(digit)));
    digits
}

fn position_bases(
    widths: &[usize],
    base: &EdwardsPoint,
    p: &BigUint,
    d: &BigUint,
) -> Vec<EdwardsPoint> {
    let mut current = base.clone();
    widths
        .iter()
        .map(|width| {
            let result = current.clone();
            for _ in 0..*width {
                current = add(&current, &current, p, d);
            }
            result
        })
        .collect()
}

fn selected_point(
    digit: i32,
    position_base: &EdwardsPoint,
    t: &EdwardsPoint,
    p: &BigUint,
    d: &BigUint,
) -> EdwardsPoint {
    let magnitude = scalar_mul(BigUint::from(digit.unsigned_abs()), position_base, p, d);
    let positive = add(t, &magnitude, p, d);
    if digit < 0 {
        negate(&positive, p)
    } else {
        positive
    }
}

fn direct_from_leaf(leaf: &[i32; 25]) -> DirectCoordinateLimbs {
    DirectCoordinateLimbs {
        product: std::array::from_fn(|index| leaf[15 - index]),
        linear: std::array::from_fn(|index| leaf[16 + 8 - index]),
    }
}

fn bigint_residue(value: BigInt, p: &BigUint) -> BigUint {
    let modulus = BigInt::from_biguint(Sign::Plus, p.clone());
    let residue = value % &modulus;
    if residue.sign() == Sign::Minus {
        (residue + modulus)
            .to_biguint()
            .expect("normalized residue is nonnegative")
    } else {
        residue.to_biguint().expect("residue is nonnegative")
    }
}

fn reconstruct_limbs(limbs: &[i32], starts: &[usize], p: &BigUint) -> BigUint {
    assert_eq!(limbs.len(), starts.len());
    let integer = limbs
        .iter()
        .zip(starts)
        .fold(BigInt::zero(), |sum, (limb, start)| {
            sum + (BigInt::from(*limb) << (5 * start))
        });
    bigint_residue(integer, p)
}

fn direct_coordinates(direct: &DirectCoordinateLimbs, p: &BigUint) -> MontgomeryPoint {
    MontgomeryPoint {
        u: reconstruct_limbs(&direct.product, &PRODUCT_STARTS, p),
        v: reconstruct_limbs(&direct.linear, &LINEAR_STARTS, p),
    }
}

fn standard_edwards_encoding(point: &EdwardsPoint) -> [u8; 32] {
    let mut bytes = point.y.to_bytes_le();
    bytes.resize(32, 0);
    assert_eq!(bytes.len(), 32);
    assert_eq!(bytes[31] >> 7, 0);
    if (&point.x & BigUint::one()) == BigUint::one() {
        bytes[31] |= 0x80;
    }
    bytes.try_into().expect("Edwards encoding is 32 bytes")
}

fn packed_field_bytes(value: &BigUint) -> [u8; 32] {
    u5_packed::packed_words_from_digits(&u5_balanced_table::field_digits(value))
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>()
        .try_into()
        .expect("packed field encoding is 32 bytes")
}

fn response_encoding_offset(widths: &[usize]) -> BigUint {
    let mut offset = BigUint::zero();
    let mut position = 0usize;
    for width in &widths[..widths.len() - 1] {
        offset += BigUint::one() << (position + width - 1);
        position += width;
    }
    assert_eq!(position + widths[widths.len() - 1], SCALAR_BITS);
    offset
}

fn g29_offset() -> BigUint {
    response_encoding_offset(&response_widths())
}

fn fixed_32_le(value: &BigUint) -> [u8; 32] {
    let mut bytes = value.to_bytes_le();
    assert!(bytes.len() <= 32);
    bytes.resize(32, 0);
    bytes.try_into().expect("value is 32 bytes")
}

struct ChainBuilder {
    p: BigUint,
    d: BigUint,
    v_scale: BigUint,
    current: EdwardsPoint,
    current_m: MontgomeryPoint,
    initial_direct: DirectCoordinateLimbs,
    previous_direct: Option<DirectCoordinateLimbs>,
    previous_lambda: Option<BigUint>,
    transitions: usize,
    symmetric_square_audit: bool,
}

impl ChainBuilder {
    fn transition(
        &mut self,
        selected: EdwardsPoint,
        selected_direct: DirectCoordinateLimbs,
    ) -> Packet {
        let selected_m = to_montgomery(&selected, &self.p, &self.v_scale);
        assert_eq!(direct_coordinates(&selected_direct, &self.p), selected_m);
        let denominator = sub_mod(&selected_m.u, &self.current_m.u, &self.p);
        assert!(!denominator.is_zero(), "torsion-coset denominator is zero");
        let lambda = mul_mod(
            &sub_mod(&selected_m.v, &self.current_m.v, &self.p),
            &invert(&denominator, &self.p),
            &self.p,
        );
        let next = add(&self.current, &selected, &self.p, &self.d);
        let next_m = to_montgomery(&next, &self.p, &self.v_scale);
        assert_eq!(
            mul_mod(&lambda, &lambda, &self.p),
            add_mod(
                &add_mod(&self.current_m.u, &selected_m.u, &self.p),
                &add_mod(&next_m.u, &BigUint::from(486_662u32), &self.p),
                &self.p,
            )
        );

        let audit = match (&self.previous_direct, &self.previous_lambda) {
            (None, None) if self.symmetric_square_audit => {
                first_transition_hybrid_host_audit_from_direct_limbs(
                    &self.initial_direct,
                    &next_m.u,
                    &lambda,
                    &selected_direct,
                )
            }
            (None, None) => first_transition_host_audit_from_direct_limbs(
                &self.initial_direct,
                &next_m.u,
                &lambda,
                &selected_direct,
            ),
            (Some(previous_direct), Some(previous_lambda)) if self.symmetric_square_audit => {
                chained_transition_hybrid_host_audit_from_direct_limbs(
                    &self.current_m.u,
                    previous_lambda,
                    previous_direct,
                    &next_m.u,
                    &lambda,
                    &selected_direct,
                )
            }
            (Some(previous_direct), Some(previous_lambda)) => {
                chained_transition_host_audit_from_direct_limbs(
                    &self.current_m.u,
                    previous_lambda,
                    previous_direct,
                    &next_m.u,
                    &lambda,
                    &selected_direct,
                )
            }
            _ => unreachable!("previous state is all-or-nothing"),
        };
        let hints = audit.hints();
        assert!((CURVE_QUOTIENT_MIN..=CURVE_QUOTIENT_MAX).contains(&hints.curve));
        if self.transitions == 0 {
            assert!(hints.continuity.abs() <= FIRST_CONTINUITY_QUOTIENT_ABS_MAX);
        } else {
            assert!(hints.continuity.abs() <= CHAINED_CONTINUITY_QUOTIENT_ABS_MAX);
        }

        self.current = next;
        self.current_m = next_m.clone();
        self.previous_direct = Some(selected_direct);
        self.previous_lambda = Some(lambda.clone());
        self.transitions += 1;
        Packet {
            u_next: next_m.u,
            lambda_next: lambda,
            selected_direct,
            hints,
            audit,
        }
    }
}

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn packed_items_with_padding(value: &BigUint, padding: u8) -> Vec<Vec<u8>> {
    assert!(padding <= 1);
    let ordinary = u5_packed::packed_value_witness_items(value);
    let mut words = u5_packed::packed_words_from_digits(&u5_balanced_table::field_digits(value));
    assert_eq!(words[7] >> 31, 0);
    words[7] |= u32::from(padding) << 31;
    let padded = words
        .iter()
        .rev()
        .map(|word| scriptnum_item(i64::from(*word as i32)))
        .collect::<Vec<_>>();
    if padding == 0 {
        assert_eq!(padded, ordinary);
    } else {
        assert_eq!(words[7] & 0x7fff_ffff, {
            let canonical =
                u5_packed::packed_words_from_digits(&u5_balanced_table::field_digits(value));
            canonical[7]
        });
    }
    padded
}

fn encode_carrier(metadata: u16, q: i32, q_bits: usize) -> i64 {
    let carrier = carrier_codec::encode_carrier(metadata, q, q_bits)
        .expect("honest fixture must avoid the unique -2^31 carrier hole");
    let (decoded_metadata, decoded_q) = decode_carrier(carrier, q_bits);
    assert_eq!((decoded_metadata, decoded_q), (metadata, q));
    carrier
}

fn decode_carrier(carrier: i64, q_bits: usize) -> (u16, i32) {
    assert_ne!(carrier, -(1i64 << 31));
    let metadata_bits = 32 - q_bits;
    let (payload, sign) = if carrier < 0 {
        (-carrier - 1, 1u16)
    } else {
        (carrier, 0u16)
    };
    let residue_mask = (1i64 << q_bits) - 1;
    let q = (payload & residue_mask) - (1i64 << (q_bits - 1));
    let metadata_low = (payload >> q_bits) as u16;
    (
        metadata_low | (sign << (metadata_bits - 1)),
        i32::try_from(q).expect("decoded q fits i32"),
    )
}

fn packet_items(
    packet: &Packet,
    continuity_metadata: u16,
    curve_metadata: u16,
    continuity_q_bits: usize,
    lambda_padding: u8,
    u_padding: u8,
) -> (Vec<Vec<u8>>, WireAudit) {
    let mut items = packed_items_with_padding(&packet.u_next, u_padding);
    items.extend(packed_items_with_padding(
        &packet.lambda_next,
        lambda_padding,
    ));
    items.push(scriptnum_item(encode_carrier(
        continuity_metadata,
        packet.hints.continuity,
        continuity_q_bits,
    )));
    items.push(scriptnum_item(encode_carrier(
        curve_metadata,
        packet.hints.curve,
        23,
    )));
    assert_eq!(items.len(), PACKET_ITEMS);
    (
        items,
        WireAudit {
            q_continuity: packet.hints.continuity,
            q_curve: packet.hints.curve,
            continuity_metadata,
            curve_metadata,
            continuity_q_bits,
            lambda_padding,
            u_padding,
        },
    )
}

fn qfree_packet_items(packet: &Packet) -> Vec<Vec<u8>> {
    let mut items = u5_packed::packed_value_witness_items(&packet.u_next);
    items.extend(u5_packed::packed_value_witness_items(&packet.lambda_next));
    assert_eq!(items.len(), TRACE_ITEMS_PER_PACKET);
    assert!(items.iter().all(|item| item.len() <= 5));
    items
}

/// Production final-challenge packet for the hybrid-u5 boundary. The original
/// canonical biased digits are supplied in public stack order `d50..d0`, with
/// `d0` nearest the top of the 51-item block, followed by the ordinary packed
/// lambda words. The hash helper certifies and copies these same digits before
/// the terminal slope kernel later consumes them.
fn qfree_u5_final_packet_items(packet: &Packet) -> Vec<Vec<u8>> {
    let digits = decoded_stored_digits(&packet.u_next);
    let mut items = digits
        .into_iter()
        .rev()
        .map(|digit| scriptnum_item(i64::from(digit)))
        .collect::<Vec<_>>();
    assert_eq!(items.len(), 51);
    assert!(items.iter().all(|item| item.len() <= 1));
    items.extend(u5_packed::packed_value_witness_items(&packet.lambda_next));
    assert_eq!(items.len(), G32_U5_FINAL_PACKET_ITEMS);
    assert!(items.iter().all(|item| item.len() <= 5));
    items
}

fn qfree_scalar_items(payload: &BigUint) -> Vec<Vec<u8>> {
    let words: [u32; QFREE_SCALAR_ITEMS] = std::array::from_fn(|index| {
        ((payload >> (32 * index)) & BigUint::from(u32::MAX))
            .to_u32()
            .expect("masked scalar payload word fits u32")
    });
    let reconstructed = words
        .iter()
        .enumerate()
        .fold(BigUint::zero(), |value, (index, word)| {
            value + (BigUint::from(*word) << (32 * index))
        });
    assert_eq!(&reconstructed, payload);
    words
        .into_iter()
        .map(|word| scriptnum_item(i64::from(word as i32)))
        .collect()
}

fn decoded_stored_digits(value: &BigUint) -> [i32; 51] {
    let expected = u5_balanced_table::field_digits(value);
    let words = u5_packed::packed_words_from_digits(&expected);
    let decoded =
        u5_packed::digits_from_packed_words(&words).expect("canonical packed field words decode");
    assert_eq!(decoded, expected);
    assert_eq!(u5_balanced_table::value_from_field_digits(&decoded), *value);
    decoded
}

fn slope_mixed_limbs_from_stored_digits(stored: &[i32; 51]) -> [i32; 16] {
    let mut start = 0usize;
    let limbs = std::array::from_fn(|limb_index| {
        let width = if limb_index < 3 { 4 } else { 3 };
        let limb = stored[start..start + width]
            .iter()
            .rev()
            .fold(0i32, |accumulator, digit| accumulator * 32 + (*digit - 16));
        start += width;
        limb
    });
    assert_eq!(start, 51);
    limbs
}

fn hybrid_state_from_packet(packet: &Packet) -> HybridState {
    let u_stored_digits = decoded_stored_digits(&packet.u_next);
    let u_product_limbs = slope_mixed_limbs_from_stored_digits(&u_stored_digits);
    let canonical_u_direct =
        DirectCoordinateLimbs::from_canonical(&packet.u_next, &BigUint::zero());
    assert_eq!(u_product_limbs, canonical_u_direct.product);

    HybridState {
        u_product_limbs,
        lambda_stored_digits: decoded_stored_digits(&packet.lambda_next),
        selected_direct: packet.selected_direct,
    }
}

fn hybrid_state_u(state: &HybridState, p: &BigUint) -> BigUint {
    reconstruct_limbs(&state.u_product_limbs, &PRODUCT_STARTS, p)
}

fn hybrid_state_lambda(state: &HybridState) -> BigUint {
    u5_balanced_table::value_from_field_digits(&state.lambda_stored_digits)
}

fn audit_hybrid_transition_states(
    response_packets: &[Packet],
    challenge_packets: &[Packet],
    initial_direct: &DirectCoordinateLimbs,
    p: &BigUint,
) -> Vec<HybridState> {
    // Script executes each low-to-high table block from the top of the stack:
    // response high-to-low, then challenge high-to-low.
    let execution_packets = response_packets
        .iter()
        .rev()
        .chain(challenge_packets.iter().rev())
        .collect::<Vec<_>>();
    let states = execution_packets
        .iter()
        .map(|packet| hybrid_state_from_packet(packet))
        .collect::<Vec<_>>();
    assert_eq!(states.len(), execution_packets.len());
    assert_eq!(16 + 51 + 16 + 9, 92);

    for (index, (packet, state)) in execution_packets.iter().zip(&states).enumerate() {
        let u_next = hybrid_state_u(state, p);
        let lambda_next = hybrid_state_lambda(state);
        assert_eq!(u_next, packet.u_next);
        assert_eq!(lambda_next, packet.lambda_next);
        assert_eq!(state.selected_direct, packet.selected_direct);

        let audit = if index == 0 {
            first_transition_hybrid_host_audit_from_direct_limbs(
                initial_direct,
                &u_next,
                &lambda_next,
                &state.selected_direct,
            )
        } else {
            let previous = &states[index - 1];
            chained_transition_hybrid_host_audit_from_direct_limbs(
                &hybrid_state_u(previous, p),
                &hybrid_state_lambda(previous),
                &previous.selected_direct,
                &u_next,
                &lambda_next,
                &state.selected_direct,
            )
        };
        assert_eq!(audit, packet.audit);
    }
    states
}

fn transition_audit_hash(
    response_packets: &[Packet],
    challenge_packets: &[Packet],
) -> blake3::Hash {
    let execution_packets = response_packets
        .iter()
        .rev()
        .chain(challenge_packets.iter().rev())
        .collect::<Vec<_>>();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bitcoin-lab/montgomery-slope-transition-audit-v1");
    hasher.update(&(execution_packets.len() as u32).to_le_bytes());
    for (index, packet) in execution_packets.into_iter().enumerate() {
        hasher.update(&(index as u32).to_le_bytes());
        for value in [
            packet.audit.curve.quotient,
            packet.audit.continuity.quotient,
        ] {
            hasher.update(&value.to_le_bytes());
        }
        for value in [
            packet.audit.curve.reverse_carry_min,
            packet.audit.curve.reverse_carry_max,
            packet.audit.continuity.reverse_carry_min,
            packet.audit.continuity.reverse_carry_max,
        ] {
            hasher.update(&value.to_le_bytes());
        }
    }
    hasher.finalize()
}

fn transcript_chunks(transcript: &[u8; 64]) -> [u32; RESPONSE_TRANSITIONS] {
    let mut global_bit = 0usize;
    let chunks = std::array::from_fn(|chunk| {
        let mut value = 0u32;
        for local_bit in 0..TRANSCRIPT_CHUNK_WIDTHS[chunk] {
            if global_bit < TRANSCRIPT_BITS {
                value |=
                    u32::from((transcript[global_bit / 8] >> (global_bit % 8)) & 1) << local_bit;
            }
            global_bit += 1;
        }
        value
    });
    assert_eq!(global_bit, TRANSCRIPT_CARRIED_BITS);
    assert_eq!(chunks[27] >> 17, 0, "global carried bit 512 is zero");
    chunks
}

fn scalar_chunks(payload: &BigUint) -> [u16; SCALAR_CARRIER_ITEMS] {
    let chunks = std::array::from_fn(|index| {
        ((payload >> (SCALAR_CARRIER_BITS * index)) & BigUint::from(0x1ffu32))
            .to_u16()
            .expect("nine-bit scalar chunk fits u16")
    });
    for bit in SCALAR_BITS..SCALAR_CARRIED_BITS {
        assert!(((payload >> bit) & BigUint::one()).is_zero());
    }
    chunks
}

fn response_metadata(chunk: u32, execution_index: usize) -> (u16, u16, u8, u8) {
    let continuity_bits = if execution_index == 0 { 10 } else { 9 };
    let curve = (chunk & 0x1ff) as u16;
    let continuity = ((chunk >> 9) & ((1u32 << continuity_bits) - 1)) as u16;
    let remainder = chunk >> (9 + continuity_bits);
    if execution_index < 4 {
        assert!(remainder < 4);
        let lambda_padding = (remainder & 1) as u8;
        let u_padding = ((remainder >> 1) & 1) as u8;
        (continuity, curve, lambda_padding, u_padding)
    } else {
        assert_eq!(remainder, 0);
        (continuity, curve, 0, 0)
    }
}

fn compact_size_bytes(value: usize) -> usize {
    match value {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn serialized_item_vector_bytes(items: &[Vec<u8>]) -> usize {
    compact_size_bytes(items.len())
        + items
            .iter()
            .map(|item| compact_size_bytes(item.len()) + item.len())
            .sum::<usize>()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn run_honest_fixture(qfree_mode: bool) {
    assert_eq!(TRANSCRIPT_CHUNK_WIDTHS.iter().sum::<usize>(), 513);
    assert_eq!(TRACE_ITEMS, 704);
    assert_eq!(HINT_ITEMS, 88);
    assert_eq!(ENTRY_ITEMS, 792);
    assert_eq!(QFREE_ENTRY_ITEMS, 712);
    assert_eq!(SCALAR_CARRIED_BITS - SCALAR_BITS, 8);

    let p = u5_balanced_table::modulus();
    let d = edwards_d();
    let sqrt_minus_one = BigUint::parse_bytes(
        b"19681161376707505956807079304988542015446066515923890162744021073123829784752",
        10,
    )
    .expect("sqrt(-1) parses");
    assert_eq!(
        mul_mod(&sqrt_minus_one, &sqrt_minus_one, &p),
        &p - BigUint::one()
    );
    let v_scale = sqrt_mod(&(&p - BigUint::from(486_664u32)), &p, &sqrt_minus_one);
    assert_eq!(v_scale.to_str_radix(10), EXPECTED_V_SCALE);
    let base_constants = basepoint_constants();
    let base = EdwardsPoint {
        x: base_constants.a,
        y: base_constants.b,
    };
    let t = EdwardsPoint {
        x: BigUint::zero(),
        y: &p - BigUint::one(),
    };
    let u = EdwardsPoint {
        x: sqrt_minus_one,
        y: BigUint::zero(),
    };
    assert_eq!(add(&u, &u, &p, &d), t);

    let private_scalar = BigUint::from(PUBLIC_KEY_SCALAR);
    let public_key = scalar_mul(private_scalar.clone(), &base, &p, &d);
    let public_key_encoding = standard_edwards_encoding(&public_key);
    assert_eq!(public_key_encoding, EXPECTED_PUBLIC_KEY);

    let nonce =
        BigUint::parse_bytes(b"123456789012345678901234567890123456789", 10).expect("nonce parses");
    assert!(nonce < scalar_order());
    let nonce_point = scalar_mul(nonce.clone(), &base, &p, &d);
    let shifted_nonce = add(&negate(&u, &p), &nonce_point, &p, &d);
    let shifted_nonce_m = to_montgomery(&shifted_nonce, &p, &v_scale);
    let rtilde = packed_field_bytes(&shifted_nonce_m.u);
    let domain = *blake3::hash(b"bitcoin-lab/custom-ed25519-blake3-slope-v1").as_bytes();
    let message: [u8; 32] = std::array::from_fn(|index| (index as u8).wrapping_mul(7));
    assert_eq!(hex(&domain), EXPECTED_DOMAIN_HEX);
    assert_eq!(hex(&message), EXPECTED_MESSAGE_HEX);
    assert_eq!(hex(&rtilde), EXPECTED_RTILDE_HEX);
    let digest = blake3::hash(
        &[
            domain.as_slice(),
            public_key_encoding.as_slice(),
            rtilde.as_slice(),
            message.as_slice(),
        ]
        .concat(),
    );
    let challenge = BigUint::from_bytes_le(&digest.as_bytes()[..16]);
    assert!(challenge.bits() <= 128);
    assert_eq!(challenge.to_str_radix(10), EXPECTED_CHALLENGE);
    let response = (&nonce + &challenge * &private_scalar) % scalar_order();
    assert_eq!(response.to_str_radix(10), EXPECTED_RESPONSE);
    let scalar_payload = g29_offset() + &response;
    assert!(scalar_payload.bits() <= SCALAR_BITS as u64);
    let z = fixed_32_le(&scalar_payload);
    assert_eq!(hex(&z), EXPECTED_Z_HEX);
    let signature = [rtilde.as_slice(), z.as_slice()].concat();
    assert_eq!(signature.len(), 64);

    let response_widths = response_widths();
    let challenge_widths = vec![8usize; CHALLENGE_GROUPS];
    let response_digits = centered_digits(response.clone(), &response_widths);
    let challenge_digits = independent_challenge_digits(&challenge);
    let mut payload_position = 0usize;
    for (group, width) in response_widths.iter().copied().enumerate() {
        let code = ((&scalar_payload >> payload_position) & BigUint::from((1u32 << width) - 1))
            .to_i32()
            .expect("response payload code fits i32");
        let expected = if group + 1 == RESPONSE_GROUPS {
            response_digits[group]
        } else {
            response_digits[group] + (1i32 << (width - 1))
        };
        assert_eq!(code, expected, "G29 C+s code at group {group}");
        payload_position += width;
    }
    assert_eq!(payload_position, SCALAR_BITS);
    let response_bases = position_bases(&response_widths, &base, &p, &d);
    let negative_public_key = negate(&public_key, &p);
    let challenge_bases = position_bases(&challenge_widths, &negative_public_key, &p, &d);

    let table_model::MontgomeryDirectH16HostTables {
        response_low_to_high: response_tables,
        challenge_low_to_high: challenge_tables,
        public_key_compressed: table_public_key,
    } = table_model::montgomery_direct_h16_independent_byte_host_tables_for_public_key(
        EXPECTED_PUBLIC_KEY,
    )
    .expect("the fixed external public-key boundary accepts the benchmark key");
    assert_eq!(table_public_key, public_key_encoding);
    assert_eq!(response_tables.len(), RESPONSE_GROUPS);
    assert_eq!(challenge_tables.len(), CHALLENGE_GROUPS);

    let top_digit = response_digits[RESPONSE_GROUPS - 1];
    assert!((0..=256).contains(&top_digit));
    let initial_direct =
        direct_from_leaf(&response_tables[RESPONSE_GROUPS - 1][top_digit as usize]);
    let top_contribution = scalar_mul(
        BigUint::from(top_digit as u32),
        &response_bases[RESPONSE_GROUPS - 1],
        &p,
        &d,
    );
    let response_initializer_shift = negate(
        &scalar_mul(
            table_model::h16_independent_challenge_bias_scalar(),
            &public_key,
            &p,
            &d,
        ),
        &p,
    );
    let initial = add(
        &add(&u, &t, &p, &d),
        &add(&response_initializer_shift, &top_contribution, &p, &d),
        &p,
        &d,
    );
    let initial_m = to_montgomery(&initial, &p, &v_scale);
    assert_eq!(direct_coordinates(&initial_direct, &p), initial_m);

    let mut chain = ChainBuilder {
        p: p.clone(),
        d: d.clone(),
        v_scale: v_scale.clone(),
        current: initial,
        current_m: initial_m,
        initial_direct,
        previous_direct: None,
        previous_lambda: None,
        transitions: 0,
        symmetric_square_audit: false,
    };
    let mut response_packets: Vec<Option<Packet>> = vec![None; RESPONSE_TRANSITIONS];
    let mut challenge_packets: Vec<Option<Packet>> = vec![None; CHALLENGE_GROUPS];

    for group in (0..RESPONSE_TRANSITIONS).rev() {
        let digit = response_digits[group];
        let magnitude = digit.unsigned_abs() as usize;
        let mut direct = direct_from_leaf(&response_tables[group][magnitude]);
        if digit < 0 {
            direct = direct.literal_negative();
        }
        let selected = selected_point(digit, &response_bases[group], &t, &p, &d);
        response_packets[group] = Some(chain.transition(selected, direct));
    }
    for group in (0..CHALLENGE_GROUPS).rev() {
        let digit = challenge_digits[group];
        let magnitude = digit.unsigned_abs() as usize;
        let mut direct = direct_from_leaf(&challenge_tables[group][magnitude]);
        if digit < 0 {
            direct = direct.literal_negative();
        }
        let selected = selected_point(digit, &challenge_bases[group], &t, &p, &d);
        challenge_packets[group] = Some(chain.transition(selected, direct));
    }
    assert_eq!(chain.transitions, TRANSITIONS);

    let equation_point = add(
        &scalar_mul(response.clone(), &base, &p, &d),
        &negate(&scalar_mul(challenge.clone(), &public_key, &p, &d), &p),
        &p,
        &d,
    );
    assert_eq!(equation_point, nonce_point);
    assert_eq!(chain.current, shifted_nonce);
    assert_eq!(chain.current_m.u, shifted_nonce_m.u);
    assert_eq!(packed_field_bytes(&chain.current_m.u), rtilde);

    let transcript: [u8; 64] = rtilde
        .into_iter()
        .chain(message)
        .collect::<Vec<_>>()
        .try_into()
        .expect("Rtilde32||M32 is 64 bytes");
    let transcript_chunks = transcript_chunks(&transcript);
    let scalar_chunks = scalar_chunks(&scalar_payload);

    let response_packets = response_packets
        .into_iter()
        .map(|packet| packet.expect("every response packet is populated"))
        .collect::<Vec<_>>();
    let challenge_packets = challenge_packets
        .into_iter()
        .map(|packet| packet.expect("every challenge packet is populated"))
        .collect::<Vec<_>>();

    if qfree_mode {
        let all_packets = response_packets
            .iter()
            .chain(challenge_packets.iter())
            .collect::<Vec<_>>();
        assert_eq!(all_packets.len(), TRANSITIONS);
        assert!(all_packets
            .iter()
            .all(|packet| packet.hints == packet.audit.hints()));

        let mut witness = Vec::with_capacity(QFREE_ENTRY_ITEMS);
        // Exact q-free scheduler entry, bottom-to-top: challenge p28..p43,
        // response p0..p27, then the eight low-to-high scalar words.
        for packet in &challenge_packets {
            witness.extend(qfree_packet_items(packet));
        }
        for packet in &response_packets {
            witness.extend(qfree_packet_items(packet));
        }
        let scalar_items = qfree_scalar_items(&scalar_payload);
        assert_eq!(scalar_items.len(), QFREE_SCALAR_ITEMS);
        witness.extend(scalar_items);
        assert_eq!(witness.len(), QFREE_ENTRY_ITEMS);
        assert!(witness[..TRACE_ITEMS].iter().all(|item| item.len() <= 5));
        assert!(witness[TRACE_ITEMS..].iter().all(|item| item.len() <= 5));

        let serialized_witness = serialize(&Witness::from_slice(&witness));
        let exact_witness_bytes = serialized_witness.len();
        assert_eq!(exact_witness_bytes, serialized_item_vector_bytes(&witness));
        let exact_trace_vector_bytes = serialized_item_vector_bytes(&witness[..TRACE_ITEMS]);
        let exact_scalar_vector_bytes = serialized_item_vector_bytes(&witness[TRACE_ITEMS..]);
        let witness_hash = blake3::hash(&serialized_witness);
        assert_eq!(exact_witness_bytes, EXPECTED_QFREE_ARGUMENT_WITNESS_BYTES);
        assert_eq!(exact_trace_vector_bytes, EXPECTED_QFREE_TRACE_VECTOR_BYTES);
        assert_eq!(
            exact_scalar_vector_bytes,
            EXPECTED_QFREE_SCALAR_VECTOR_BYTES
        );
        assert_eq!(
            witness_hash.to_string(),
            EXPECTED_QFREE_ARGUMENT_WITNESS_BLAKE3
        );
        assert_eq!(compact_size_bytes(QFREE_ENTRY_ITEMS), 3);
        assert_eq!(compact_size_bytes(QFREE_ENTRY_ITEMS + 2), 3);
        let exact_complete_witness_constant =
            exact_witness_bytes + LEAF_COMPACT_SIZE_BYTES + SERIALIZED_CONTROL_BLOCK_BYTES;
        let exact_target_weight_constant =
            TARGET_STRIPPED_WEIGHT + WITNESS_MARKER_FLAG_BYTES + exact_complete_witness_constant;
        let exact_minimum_block_weight_constant =
            exact_target_weight_constant + MINIMUM_OTHER_BLOCK_WEIGHT;
        assert_eq!(
            exact_complete_witness_constant,
            EXPECTED_QFREE_COMPLETE_WITNESS_CONSTANT
        );
        assert_eq!(
            exact_target_weight_constant,
            EXPECTED_QFREE_TARGET_WEIGHT_CONSTANT
        );
        assert_eq!(
            exact_minimum_block_weight_constant,
            EXPECTED_QFREE_MINIMUM_BLOCK_WEIGHT_CONSTANT
        );
        let conservative_argument_witness_bytes = compact_size_bytes(QFREE_ENTRY_ITEMS)
            + TRACE_ITEMS * (1 + 5)
            + QFREE_SCALAR_ITEMS * (1 + 5);
        assert_eq!(
            conservative_argument_witness_bytes,
            CONSERVATIVE_QFREE_ARGUMENT_WITNESS_BYTES
        );
        let conservative_target_weight_constant = TARGET_STRIPPED_WEIGHT
            + WITNESS_MARKER_FLAG_BYTES
            + conservative_argument_witness_bytes
            + LEAF_COMPACT_SIZE_BYTES
            + SERIALIZED_CONTROL_BLOCK_BYTES;
        let conservative_minimum_block_weight_constant =
            conservative_target_weight_constant + MINIMUM_OTHER_BLOCK_WEIGHT;
        assert_eq!(
            conservative_target_weight_constant,
            CONSERVATIVE_QFREE_TARGET_WEIGHT_CONSTANT
        );
        assert_eq!(
            conservative_minimum_block_weight_constant,
            CONSERVATIVE_QFREE_MINIMUM_BLOCK_WEIGHT_CONSTANT
        );

        let curve_quotient_min = all_packets
            .iter()
            .map(|packet| packet.audit.curve.quotient)
            .min()
            .unwrap();
        let curve_quotient_max = all_packets
            .iter()
            .map(|packet| packet.audit.curve.quotient)
            .max()
            .unwrap();
        let curve_carry_min = all_packets
            .iter()
            .map(|packet| packet.audit.curve.reverse_carry_min)
            .min()
            .unwrap();
        let curve_carry_max = all_packets
            .iter()
            .map(|packet| packet.audit.curve.reverse_carry_max)
            .max()
            .unwrap();
        let continuity_quotient_min = all_packets
            .iter()
            .map(|packet| packet.audit.continuity.quotient)
            .min()
            .unwrap();
        let continuity_quotient_max = all_packets
            .iter()
            .map(|packet| packet.audit.continuity.quotient)
            .max()
            .unwrap();
        let continuity_carry_min = all_packets
            .iter()
            .map(|packet| packet.audit.continuity.reverse_carry_min)
            .min()
            .unwrap();
        let continuity_carry_max = all_packets
            .iter()
            .map(|packet| packet.audit.continuity.reverse_carry_max)
            .max()
            .unwrap();

        let first = response_packets
            .last()
            .expect("p27 is the first executed response packet");
        let chained_packets = response_packets[..RESPONSE_TRANSITIONS - 1]
            .iter()
            .chain(challenge_packets.iter())
            .collect::<Vec<_>>();
        assert_eq!(chained_packets.len(), TRANSITIONS - 1);
        let chained_continuity_quotient_min = chained_packets
            .iter()
            .map(|packet| packet.audit.continuity.quotient)
            .min()
            .unwrap();
        let chained_continuity_quotient_max = chained_packets
            .iter()
            .map(|packet| packet.audit.continuity.quotient)
            .max()
            .unwrap();
        let chained_continuity_carry_min = chained_packets
            .iter()
            .map(|packet| packet.audit.continuity.reverse_carry_min)
            .min()
            .unwrap();
        let chained_continuity_carry_max = chained_packets
            .iter()
            .map(|packet| packet.audit.continuity.reverse_carry_max)
            .max()
            .unwrap();
        assert_eq!(
            (curve_quotient_min, curve_quotient_max),
            EXPECTED_QFREE_CURVE_QUOTIENT_INTERVAL
        );
        assert_eq!(
            (curve_carry_min, curve_carry_max),
            EXPECTED_QFREE_CURVE_CARRY_INTERVAL
        );
        assert_eq!(
            first.audit.continuity.quotient,
            EXPECTED_QFREE_FIRST_CONTINUITY_QUOTIENT
        );
        assert_eq!(
            (
                first.audit.continuity.reverse_carry_min,
                first.audit.continuity.reverse_carry_max,
            ),
            EXPECTED_QFREE_FIRST_CONTINUITY_CARRY_INTERVAL
        );
        assert_eq!(
            (
                chained_continuity_quotient_min,
                chained_continuity_quotient_max,
            ),
            EXPECTED_QFREE_CHAINED_CONTINUITY_QUOTIENT_INTERVAL
        );
        assert_eq!(
            (chained_continuity_carry_min, chained_continuity_carry_max,),
            EXPECTED_QFREE_CHAINED_CONTINUITY_CARRY_INTERVAL
        );

        println!("model=ed25519_montgomery_h16_qfree_honest_witness");
        println!("evidence=locally-reproduced");
        println!("evidence_boundary=host-generation-and-witness-serialization");
        println!("execution_class=unclassified");
        println!("whole_script_generated=false");
        println!("whole_script_executed=false");
        println!("long_scalar_blake_or_field_script_execution=false");
        println!("deterministic_private_scalar={PUBLIC_KEY_SCALAR}");
        println!("benchmark_private_scalar_disclosed=true");
        println!("production_table_generator_secret_scalar_inputs=0");
        println!("deterministic_nonce={nonce}");
        println!("domain_separator={}", hex(&domain));
        println!("public_key_rfc8032={}", hex(&public_key_encoding));
        println!("fixed_message={}", hex(&message));
        println!("rtilde_packed_field={}", hex(&rtilde));
        println!("challenge_le128={challenge}");
        println!("response_s={response}");
        println!("response_payload_C_plus_s={scalar_payload}");
        println!("response_payload_z32={}", hex(&z));
        println!("signature_Rtilde_plus_z={}", hex(&signature));
        println!("signature_equation_sB_minus_hA_equals_R=true");
        println!("host_endpoint_minus_U_plus_sB_minus_hA_matches_Rtilde=true");
        println!("derived_transition_pairs_host_verified={TRANSITIONS}");
        println!("derived_scalar_relations_host_verified={}", 2 * TRANSITIONS);
        println!(
            "derived_relation_checks=exact_divisibility_plus_forward_and_reverse_radix32_carries"
        );
        println!("entry_layout=challenge16_trace_only_then_response28_trace_only_then_scalar8");
        println!("trace_data_items={TRACE_ITEMS}");
        println!("scalar_word_items={QFREE_SCALAR_ITEMS}");
        println!("incremental_hint_items_per_transition=0");
        println!("quotient_hint_items=0");
        println!("complete_entry_items={QFREE_ENTRY_ITEMS}");
        println!("all_704_trace_and_8_scalar_items_coexist_at_entry=true");
        println!("quotients_materialized_on_host_for_audit_only=true");
        println!("quotients_are_verifier_derived_not_witness_supplied=true");
        println!("curve_quotient_actual_interval=[{curve_quotient_min},{curve_quotient_max}]");
        println!("curve_reverse_carry_actual_interval=[{curve_carry_min},{curve_carry_max}]");
        println!(
            "first_continuity_quotient_actual={}",
            first.audit.continuity.quotient
        );
        println!(
            "first_continuity_reverse_carry_actual_interval=[{},{}]",
            first.audit.continuity.reverse_carry_min, first.audit.continuity.reverse_carry_max
        );
        println!("chained_continuity_quotient_actual_interval=[{chained_continuity_quotient_min},{chained_continuity_quotient_max}]");
        println!("chained_continuity_reverse_carry_actual_interval=[{chained_continuity_carry_min},{chained_continuity_carry_max}]");
        println!("continuity_quotient_actual_interval=[{continuity_quotient_min},{continuity_quotient_max}]");
        println!("continuity_reverse_carry_actual_interval=[{continuity_carry_min},{continuity_carry_max}]");
        println!("all_trace_payloads_at_most_five_bytes=true");
        println!("all_scalar_payloads_at_most_five_bytes=true");
        println!("exact_704_trace_item_vector_bytes={exact_trace_vector_bytes}");
        println!("exact_8_scalar_item_vector_bytes={exact_scalar_vector_bytes}");
        println!("exact_712_argument_witness_bytes={exact_witness_bytes}");
        println!(
            "exact_714_item_complete_witness_bytes_formula=S+{exact_complete_witness_constant}"
        );
        println!("exact_fixture_target_weight_formula=S+{exact_target_weight_constant}");
        println!(
            "exact_fixture_minimum_block_weight_formula=S+{exact_minimum_block_weight_constant}"
        );
        println!("conservative_712_argument_witness_bytes={conservative_argument_witness_bytes}");
        println!("conservative_target_weight_formula=S+{conservative_target_weight_constant}");
        println!(
            "conservative_minimum_block_weight_formula=S+{conservative_minimum_block_weight_constant}"
        );
        println!("serialized_argument_witness_blake3={witness_hash}");
        println!("includes=complete 712-item argument witness only: 704 canonical packed trace-data items and eight canonical compressed-u32 scalar words; zero quotient hints; exact table representatives and all 88 derived relation identities checked on host; leaf script, control block, transaction, full Script execution, and Bitcoin Core validation excluded");
        return;
    }

    let mut witness = Vec::with_capacity(ENTRY_ITEMS);
    let mut audits = Vec::with_capacity(TRANSITIONS);
    for physical_packet in 0..RESPONSE_TRANSITIONS {
        let execution_index = RESPONSE_TRANSITIONS - 1 - physical_packet;
        let chunk = transcript_chunks[execution_index];
        let (continuity_meta, curve_meta, lambda_padding, u_padding) =
            response_metadata(chunk, execution_index);
        let continuity_q_bits = if execution_index == 0 { 22 } else { 23 };
        let (items, audit) = packet_items(
            &response_packets[physical_packet],
            continuity_meta,
            curve_meta,
            continuity_q_bits,
            lambda_padding,
            u_padding,
        );
        witness.extend(items);
        audits.push(audit);
    }

    let mut scalar_metadata = [[0u16; 2]; CHALLENGE_GROUPS];
    let mut scalar_cursor = 0usize;
    for group in (0..CHALLENGE_GROUPS).rev() {
        if scalar_cursor < SCALAR_CARRIER_ITEMS {
            scalar_metadata[group][1] = scalar_chunks[scalar_cursor]; // q_curve
            scalar_cursor += 1;
        }
        if scalar_cursor < SCALAR_CARRIER_ITEMS {
            scalar_metadata[group][0] = scalar_chunks[scalar_cursor]; // q_continuity
            scalar_cursor += 1;
        }
    }
    assert_eq!(scalar_cursor, SCALAR_CARRIER_ITEMS);
    assert_eq!(scalar_metadata[0], [0, 0]);
    assert_eq!(scalar_metadata[1][0], 0);
    for group in 0..CHALLENGE_GROUPS {
        let (items, audit) = packet_items(
            &challenge_packets[group],
            scalar_metadata[group][0],
            scalar_metadata[group][1],
            23,
            0,
            0,
        );
        witness.extend(items);
        audits.push(audit);
    }
    assert_eq!(witness.len(), ENTRY_ITEMS);
    assert_eq!(audits.len(), TRANSITIONS);

    // Re-read both metadata streams from their physical packet slots. This
    // locks the generator to the router and midpoint mappings independently
    // of the construction loops above.
    for (chunk_index, expected) in transcript_chunks.iter().copied().enumerate() {
        let packet = RESPONSE_TRANSITIONS - 1 - chunk_index;
        let audit = audits[packet];
        let rebuilt = u32::from(audit.curve_metadata)
            | (u32::from(audit.continuity_metadata) << 9)
            | (u32::from(audit.lambda_padding) << (9 + 32 - audit.continuity_q_bits))
            | (u32::from(audit.u_padding) << (10 + 32 - audit.continuity_q_bits));
        assert_eq!(rebuilt, expected, "response transcript chunk mapping");
    }
    let mut recovered_scalar_chunks = Vec::with_capacity(SCALAR_CARRIER_ITEMS);
    for group in (0..CHALLENGE_GROUPS).rev() {
        if recovered_scalar_chunks.len() == SCALAR_CARRIER_ITEMS {
            break;
        }
        let audit = audits[RESPONSE_TRANSITIONS + group];
        recovered_scalar_chunks.push(audit.curve_metadata);
        if recovered_scalar_chunks.len() < SCALAR_CARRIER_ITEMS {
            recovered_scalar_chunks.push(audit.continuity_metadata);
        }
    }
    assert_eq!(recovered_scalar_chunks.as_slice(), scalar_chunks.as_slice());

    let trace_items = witness
        .chunks_exact(PACKET_ITEMS)
        .flat_map(|packet| packet[..TRACE_ITEMS_PER_PACKET].iter().cloned())
        .collect::<Vec<_>>();
    let hint_items = witness
        .chunks_exact(PACKET_ITEMS)
        .flat_map(|packet| packet[TRACE_ITEMS_PER_PACKET..].iter().cloned())
        .collect::<Vec<_>>();
    assert_eq!(trace_items.len(), TRACE_ITEMS);
    assert_eq!(hint_items.len(), HINT_ITEMS);
    assert!(trace_items.iter().all(|item| item.len() <= 5));
    assert!(hint_items.iter().all(|item| item.len() <= 4));
    let exact_witness_bytes = serialize(&Witness::from_slice(&witness)).len();
    assert_eq!(exact_witness_bytes, serialized_item_vector_bytes(&witness));
    assert_eq!(exact_witness_bytes, EXPECTED_ARGUMENT_WITNESS_BYTES);
    let exact_trace_vector_bytes = serialized_item_vector_bytes(&trace_items);
    let exact_hint_vector_bytes = serialized_item_vector_bytes(&hint_items);
    let conservative_witness_bytes =
        compact_size_bytes(ENTRY_ITEMS) + TRACE_ITEMS * (1 + 5) + HINT_ITEMS * (1 + 4);
    assert_eq!(
        conservative_witness_bytes,
        CONSERVATIVE_ARGUMENT_WITNESS_BYTES
    );
    assert!(exact_witness_bytes <= conservative_witness_bytes);
    let witness_hash = blake3::hash(&serialize(&Witness::from_slice(&witness)));
    assert_eq!(witness_hash.to_string(), EXPECTED_ARGUMENT_WITNESS_BLAKE3);
    // The 792- and 794-item witness counts both use a three-byte CompactSize,
    // so the exact argument vector's count prefix remains valid when adding
    // the leaf and depth-zero control block.
    assert_eq!(compact_size_bytes(ENTRY_ITEMS), 3);
    assert_eq!(compact_size_bytes(ENTRY_ITEMS + 2), 3);
    let exact_complete_witness_constant =
        exact_witness_bytes + LEAF_COMPACT_SIZE_BYTES + SERIALIZED_CONTROL_BLOCK_BYTES;
    let exact_target_weight_constant =
        TARGET_STRIPPED_WEIGHT + WITNESS_MARKER_FLAG_BYTES + exact_complete_witness_constant;
    let exact_minimum_block_constant = exact_target_weight_constant + MINIMUM_OTHER_BLOCK_WEIGHT;
    assert_eq!(exact_complete_witness_constant, 3_997);
    assert_eq!(exact_target_weight_constant, 4_375);
    assert_eq!(exact_minimum_block_constant, 5_143);

    let curve_min = audits.iter().map(|audit| audit.q_curve).min().unwrap();
    let curve_max = audits.iter().map(|audit| audit.q_curve).max().unwrap();
    let continuity_min = audits.iter().map(|audit| audit.q_continuity).min().unwrap();
    let continuity_max = audits.iter().map(|audit| audit.q_continuity).max().unwrap();

    println!("model=ed25519_montgomery_h16_honest_witness");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=host-generation-and-witness-serialization");
    println!("execution_class=unclassified");
    println!("whole_script_generated=false");
    println!("whole_script_executed=false");
    println!("long_scalar_blake_or_field_script_execution=false");
    println!("deterministic_private_scalar={PUBLIC_KEY_SCALAR}");
    println!("benchmark_private_scalar_disclosed=true");
    println!("production_table_generator_secret_scalar_inputs=0");
    println!("deterministic_nonce={nonce}");
    println!("domain_separator={}", hex(&domain));
    println!("public_key_rfc8032={}", hex(&public_key_encoding));
    println!("fixed_message={}", hex(&message));
    println!("montgomery_map=u=(1+y)/(1-y),v=sqrt(-486664)*u/x");
    println!("montgomery_v_scale={v_scale}");
    println!("rtilde_packed_field={}", hex(&rtilde));
    println!("challenge_le128={challenge}");
    println!("challenge_recode_schedule=independent_signed_bytes_bias127");
    println!("challenge_recode_identity=h=sum(e_i*2^(8i))+K_127");
    println!("challenge_recode_digit_interval=-127..128");
    println!("response_initializer_shift=-K_127_times_A");
    println!("response_s={response}");
    println!("response_payload_C_plus_s={scalar_payload}");
    println!("response_payload_z32={}", hex(&z));
    println!("signature_Rtilde_plus_z={}", hex(&signature));
    println!("signature_equation_valid=true");
    println!("host_endpoint_minus_U_plus_sB_minus_hA_matches_Rtilde=true");
    println!("table_leaf_direct_limb_reconstruction_checked_for_all_45_selections=true");
    println!("literal_negative_v_limb_representation_used=true");
    println!("affine_denominators_nonzero=true");
    println!("entry_packet_order=response_p0_through_p27_then_challenge_p28_through_p43");
    println!("response_execution_order=p27_through_p0");
    println!("challenge_execution_order=p43_through_p28");
    println!("trace_data_items={TRACE_ITEMS}");
    println!("incremental_hint_items_per_transition=2");
    println!("quotient_hint_items={HINT_ITEMS}");
    println!("complete_entry_items={ENTRY_ITEMS}");
    println!("all_88_hints_and_704_trace_items_coexist_at_entry=true");
    println!("separate_scalar_or_transcript_entry_items=0");
    println!("curve_quotient_actual_interval=[{curve_min},{curve_max}]");
    println!("continuity_quotient_actual_interval=[{continuity_min},{continuity_max}]");
    println!("all_carriers_avoid_negative_2pow31_hole=true");
    println!("all_hint_payloads_at_most_four_bytes=true");
    println!("all_trace_payloads_at_most_five_bytes=true");
    println!("scalar_carrier_items={SCALAR_CARRIER_ITEMS}");
    println!("scalar_carried_bits={SCALAR_CARRIED_BITS}");
    println!("scalar_payload_bits={SCALAR_BITS}");
    println!(
        "scalar_forced_zero_spare_bits={}",
        SCALAR_CARRIED_BITS - SCALAR_BITS
    );
    println!("transcript_chunk_items={RESPONSE_TRANSITIONS}");
    println!("transcript_chunk_widths=21,20,20,20,18x24");
    println!("transcript_bits={TRANSCRIPT_BITS}");
    println!("transcript_forced_zero_spare_bits=1");
    println!("response_packet_27_minus_j_maps_to_transcript_chunk_j=true");
    println!("response_chunk_order=curve_meta_then_continuity_meta_then_lambda_pad_then_u_pad");
    println!("challenge_scalar_carrier_order=p43_curve,p43_continuity_down_to_p29_curve=true");
    println!("exact_792_argument_witness_bytes={exact_witness_bytes}");
    println!("conservative_792_argument_witness_bytes={conservative_witness_bytes}");
    println!("exact_794_item_complete_witness_bytes_formula=S+{exact_complete_witness_constant}");
    println!("exact_fixture_target_weight_formula=S+{exact_target_weight_constant}");
    println!("exact_fixture_minimum_block_weight_formula=S+{exact_minimum_block_constant}");
    println!("conservative_target_weight_formula=S+5084");
    println!("conservative_minimum_block_weight_formula=S+5852");
    println!("exact_704_trace_item_vector_bytes={exact_trace_vector_bytes}");
    println!("exact_88_hint_item_vector_bytes={exact_hint_vector_bytes}");
    println!("serialized_argument_witness_blake3={witness_hash}");
    println!("includes=complete 792-item argument witness only: 704 packed trace-data items, 88 mandatory quotient-hint carriers, embedded C+s and Rtilde32||M32 metadata, exact table representatives, and host endpoint proof; leaf script, control block, transaction, full Script execution, and Bitcoin Core validation excluded");
}

fn run_g31_qfree_honest_fixture() {
    assert_eq!(G31_RESPONSE_TRANSITIONS, 30);
    assert_eq!(G31_TRANSITIONS, 46);
    assert_eq!(G31_TRACE_ITEMS, 736);
    assert_eq!(G31_ENTRY_ITEMS, 744);

    let response_widths = table_model::montgomery_direct_h16_qfree_g31_response_widths();
    assert_eq!(response_widths, g31_response_widths());
    let p = u5_balanced_table::modulus();
    let d = edwards_d();
    let sqrt_minus_one = BigUint::parse_bytes(
        b"19681161376707505956807079304988542015446066515923890162744021073123829784752",
        10,
    )
    .expect("sqrt(-1) parses");
    assert_eq!(
        mul_mod(&sqrt_minus_one, &sqrt_minus_one, &p),
        &p - BigUint::one()
    );
    let v_scale = sqrt_mod(&(&p - BigUint::from(486_664u32)), &p, &sqrt_minus_one);
    assert_eq!(v_scale.to_str_radix(10), EXPECTED_V_SCALE);
    let base_constants = basepoint_constants();
    let base = EdwardsPoint {
        x: base_constants.a,
        y: base_constants.b,
    };
    let t = EdwardsPoint {
        x: BigUint::zero(),
        y: &p - BigUint::one(),
    };
    let u = EdwardsPoint {
        x: sqrt_minus_one,
        y: BigUint::zero(),
    };
    assert_eq!(add(&u, &u, &p, &d), t);

    let private_scalar = BigUint::from(PUBLIC_KEY_SCALAR);
    let public_key = scalar_mul(private_scalar.clone(), &base, &p, &d);
    let public_key_encoding = standard_edwards_encoding(&public_key);
    assert_eq!(public_key_encoding, EXPECTED_PUBLIC_KEY);

    let nonce =
        BigUint::parse_bytes(b"123456789012345678901234567890123456789", 10).expect("nonce parses");
    assert!(nonce < scalar_order());
    let nonce_point = scalar_mul(nonce.clone(), &base, &p, &d);
    let shifted_nonce = add(&negate(&u, &p), &nonce_point, &p, &d);
    let shifted_nonce_m = to_montgomery(&shifted_nonce, &p, &v_scale);
    let rtilde = packed_field_bytes(&shifted_nonce_m.u);
    let domain = *blake3::hash(b"bitcoin-lab/custom-ed25519-blake3-slope-v1").as_bytes();
    let message: [u8; 32] = std::array::from_fn(|index| (index as u8).wrapping_mul(7));
    assert_eq!(hex(&domain), EXPECTED_DOMAIN_HEX);
    assert_eq!(hex(&message), EXPECTED_MESSAGE_HEX);
    assert_eq!(hex(&rtilde), EXPECTED_RTILDE_HEX);
    let digest = blake3::hash(
        &[
            domain.as_slice(),
            public_key_encoding.as_slice(),
            rtilde.as_slice(),
            message.as_slice(),
        ]
        .concat(),
    );
    let challenge = BigUint::from_bytes_le(&digest.as_bytes()[..16]);
    assert!(challenge.bits() <= 128);
    assert_eq!(challenge.to_str_radix(10), EXPECTED_CHALLENGE);
    let response = (&nonce + &challenge * &private_scalar) % scalar_order();
    assert_eq!(response.to_str_radix(10), EXPECTED_RESPONSE);
    let scalar_payload = response_encoding_offset(&response_widths) + &response;
    assert!(scalar_payload.bits() <= SCALAR_BITS as u64);
    let z = fixed_32_le(&scalar_payload);
    assert_eq!(hex(&z), EXPECTED_G31_Z_HEX);
    let signature = [rtilde.as_slice(), z.as_slice()].concat();
    assert_eq!(signature.len(), 64);

    let response_digits = centered_digits(response.clone(), &response_widths);
    let challenge_widths = vec![8usize; CHALLENGE_GROUPS];
    let challenge_digits = independent_challenge_digits(&challenge);
    let mut payload_position = 0usize;
    for (group, width) in response_widths.iter().copied().enumerate() {
        let code = ((&scalar_payload >> payload_position) & BigUint::from((1u32 << width) - 1))
            .to_i32()
            .expect("response payload code fits i32");
        let expected = if group + 1 == G31_RESPONSE_GROUPS {
            response_digits[group]
        } else {
            response_digits[group] + (1i32 << (width - 1))
        };
        assert_eq!(code, expected, "G31 C+s code at group {group}");
        payload_position += width;
    }
    assert_eq!(payload_position, SCALAR_BITS);
    let response_bases = position_bases(&response_widths, &base, &p, &d);
    let negative_public_key = negate(&public_key, &p);
    let challenge_bases = position_bases(&challenge_widths, &negative_public_key, &p, &d);

    let table_model::MontgomeryDirectH16HostTables {
        response_low_to_high: response_tables,
        challenge_low_to_high: challenge_tables,
        public_key_compressed: table_public_key,
    } = table_model::montgomery_direct_h16_qfree_g31_host_tables_for_public_key(
        EXPECTED_PUBLIC_KEY,
    )
    .expect("the fixed external public-key boundary accepts the benchmark key");
    assert_eq!(table_public_key, public_key_encoding);
    assert_eq!(response_tables.len(), G31_RESPONSE_GROUPS);
    assert_eq!(challenge_tables.len(), CHALLENGE_GROUPS);

    let top_digit = response_digits[G31_RESPONSE_GROUPS - 1];
    assert!(top_digit >= 0);
    let top_digit = top_digit as usize;
    assert!(top_digit < response_tables[G31_RESPONSE_GROUPS - 1].len());
    let initial_direct = direct_from_leaf(&response_tables[G31_RESPONSE_GROUPS - 1][top_digit]);
    let top_contribution = scalar_mul(
        BigUint::from(top_digit as u32),
        &response_bases[G31_RESPONSE_GROUPS - 1],
        &p,
        &d,
    );
    let response_initializer_shift = negate(
        &scalar_mul(
            table_model::h16_independent_challenge_bias_scalar(),
            &public_key,
            &p,
            &d,
        ),
        &p,
    );
    let initial = add(
        &add(&u, &t, &p, &d),
        &add(&response_initializer_shift, &top_contribution, &p, &d),
        &p,
        &d,
    );
    let initial_m = to_montgomery(&initial, &p, &v_scale);
    assert_eq!(direct_coordinates(&initial_direct, &p), initial_m);

    let mut chain = ChainBuilder {
        p: p.clone(),
        d: d.clone(),
        v_scale: v_scale.clone(),
        current: initial,
        current_m: initial_m,
        initial_direct,
        previous_direct: None,
        previous_lambda: None,
        transitions: 0,
        symmetric_square_audit: true,
    };
    let mut response_packets: Vec<Option<Packet>> = vec![None; G31_RESPONSE_TRANSITIONS];
    let mut challenge_packets: Vec<Option<Packet>> = vec![None; CHALLENGE_GROUPS];

    for group in (0..G31_RESPONSE_TRANSITIONS).rev() {
        let digit = response_digits[group];
        let magnitude = digit.unsigned_abs() as usize;
        assert!(magnitude < response_tables[group].len());
        let mut direct = direct_from_leaf(&response_tables[group][magnitude]);
        if digit < 0 {
            direct = direct.literal_negative();
        }
        let selected = selected_point(digit, &response_bases[group], &t, &p, &d);
        response_packets[group] = Some(chain.transition(selected, direct));
    }
    for group in (0..CHALLENGE_GROUPS).rev() {
        let digit = challenge_digits[group];
        let magnitude = digit.unsigned_abs() as usize;
        assert!(magnitude < challenge_tables[group].len());
        let mut direct = direct_from_leaf(&challenge_tables[group][magnitude]);
        if digit < 0 {
            direct = direct.literal_negative();
        }
        let selected = selected_point(digit, &challenge_bases[group], &t, &p, &d);
        challenge_packets[group] = Some(chain.transition(selected, direct));
    }
    assert_eq!(chain.transitions, G31_TRANSITIONS);

    let equation_point = add(
        &scalar_mul(response.clone(), &base, &p, &d),
        &negate(&scalar_mul(challenge.clone(), &public_key, &p, &d), &p),
        &p,
        &d,
    );
    assert_eq!(equation_point, nonce_point);
    assert_eq!(chain.current, shifted_nonce);
    assert_eq!(chain.current_m.u, shifted_nonce_m.u);
    assert_eq!(packed_field_bytes(&chain.current_m.u), rtilde);

    let response_packets = response_packets
        .into_iter()
        .map(|packet| packet.expect("every G31 response packet is populated"))
        .collect::<Vec<_>>();
    let challenge_packets = challenge_packets
        .into_iter()
        .map(|packet| packet.expect("every challenge packet is populated"))
        .collect::<Vec<_>>();
    let hybrid_states =
        audit_hybrid_transition_states(&response_packets, &challenge_packets, &initial_direct, &p);
    let final_hybrid_state = hybrid_states
        .last()
        .expect("the final challenge transition returns a hybrid state");
    let final_hybrid_u = hybrid_state_u(final_hybrid_state, &p);
    assert_eq!(final_hybrid_u, shifted_nonce_m.u);
    // This is the exact packed value copied into BLAKE3 before the final
    // transition. Once its decoder has produced this certified state, the
    // original eight packed items have no remaining algebraic consumer.
    assert_eq!(packed_field_bytes(&final_hybrid_u), rtilde);
    let all_packets = response_packets
        .iter()
        .chain(challenge_packets.iter())
        .collect::<Vec<_>>();
    assert_eq!(all_packets.len(), G31_TRANSITIONS);
    assert!(all_packets
        .iter()
        .all(|packet| packet.hints == packet.audit.hints()));

    let mut witness = Vec::with_capacity(G31_ENTRY_ITEMS);
    for packet in &challenge_packets {
        witness.extend(qfree_packet_items(packet));
    }
    for packet in &response_packets {
        witness.extend(qfree_packet_items(packet));
    }
    let scalar_items = qfree_scalar_items(&scalar_payload);
    assert_eq!(scalar_items.len(), QFREE_SCALAR_ITEMS);
    witness.extend(scalar_items);
    assert_eq!(witness.len(), G31_ENTRY_ITEMS);
    assert!(witness.iter().all(|item| item.len() <= 5));

    let serialized_witness = serialize(&Witness::from_slice(&witness));
    let exact_witness_bytes = serialized_witness.len();
    assert_eq!(exact_witness_bytes, serialized_item_vector_bytes(&witness));
    let exact_trace_vector_bytes = serialized_item_vector_bytes(&witness[..G31_TRACE_ITEMS]);
    let exact_scalar_vector_bytes = serialized_item_vector_bytes(&witness[G31_TRACE_ITEMS..]);
    let witness_hash = blake3::hash(&serialized_witness);
    assert_eq!(exact_witness_bytes, EXPECTED_G31_ARGUMENT_WITNESS_BYTES);
    assert_eq!(exact_trace_vector_bytes, EXPECTED_G31_TRACE_VECTOR_BYTES);
    assert_eq!(exact_scalar_vector_bytes, EXPECTED_G31_SCALAR_VECTOR_BYTES);
    assert_eq!(
        witness_hash.to_string(),
        EXPECTED_G31_ARGUMENT_WITNESS_BLAKE3
    );

    let curve_quotient_min = all_packets
        .iter()
        .map(|packet| packet.audit.curve.quotient)
        .min()
        .unwrap();
    let curve_quotient_max = all_packets
        .iter()
        .map(|packet| packet.audit.curve.quotient)
        .max()
        .unwrap();
    let curve_carry_min = all_packets
        .iter()
        .map(|packet| packet.audit.curve.reverse_carry_min)
        .min()
        .unwrap();
    let curve_carry_max = all_packets
        .iter()
        .map(|packet| packet.audit.curve.reverse_carry_max)
        .max()
        .unwrap();
    let continuity_quotient_min = all_packets
        .iter()
        .map(|packet| packet.audit.continuity.quotient)
        .min()
        .unwrap();
    let continuity_quotient_max = all_packets
        .iter()
        .map(|packet| packet.audit.continuity.quotient)
        .max()
        .unwrap();
    let continuity_carry_min = all_packets
        .iter()
        .map(|packet| packet.audit.continuity.reverse_carry_min)
        .min()
        .unwrap();
    let continuity_carry_max = all_packets
        .iter()
        .map(|packet| packet.audit.continuity.reverse_carry_max)
        .max()
        .unwrap();
    let first = response_packets
        .last()
        .expect("p29 is the first executed G31 response packet");
    let chained_packets = response_packets[..G31_RESPONSE_TRANSITIONS - 1]
        .iter()
        .chain(challenge_packets.iter())
        .collect::<Vec<_>>();
    assert_eq!(chained_packets.len(), G31_TRANSITIONS - 1);
    let chained_continuity_quotient_min = chained_packets
        .iter()
        .map(|packet| packet.audit.continuity.quotient)
        .min()
        .unwrap();
    let chained_continuity_quotient_max = chained_packets
        .iter()
        .map(|packet| packet.audit.continuity.quotient)
        .max()
        .unwrap();
    let chained_continuity_carry_min = chained_packets
        .iter()
        .map(|packet| packet.audit.continuity.reverse_carry_min)
        .min()
        .unwrap();
    let chained_continuity_carry_max = chained_packets
        .iter()
        .map(|packet| packet.audit.continuity.reverse_carry_max)
        .max()
        .unwrap();
    assert_eq!(
        (curve_quotient_min, curve_quotient_max),
        EXPECTED_G31_CURVE_QUOTIENT_INTERVAL
    );
    assert_eq!(
        (curve_carry_min, curve_carry_max),
        EXPECTED_G31_CURVE_CARRY_INTERVAL
    );
    assert_eq!(
        first.audit.continuity.quotient,
        EXPECTED_G31_FIRST_CONTINUITY_QUOTIENT
    );
    assert_eq!(
        (
            first.audit.continuity.reverse_carry_min,
            first.audit.continuity.reverse_carry_max,
        ),
        EXPECTED_G31_FIRST_CONTINUITY_CARRY_INTERVAL
    );
    assert_eq!(
        (
            chained_continuity_quotient_min,
            chained_continuity_quotient_max,
        ),
        EXPECTED_G31_CHAINED_CONTINUITY_QUOTIENT_INTERVAL
    );
    assert_eq!(
        (chained_continuity_carry_min, chained_continuity_carry_max),
        EXPECTED_G31_CHAINED_CONTINUITY_CARRY_INTERVAL
    );

    assert_eq!(compact_size_bytes(G31_ENTRY_ITEMS), 3);
    assert_eq!(compact_size_bytes(G31_ENTRY_ITEMS + 2), 3);
    let exact_complete_witness_constant =
        exact_witness_bytes + LEAF_COMPACT_SIZE_BYTES + SERIALIZED_CONTROL_BLOCK_BYTES;
    let exact_target_weight_constant =
        TARGET_STRIPPED_WEIGHT + WITNESS_MARKER_FLAG_BYTES + exact_complete_witness_constant;
    let exact_minimum_block_weight_constant =
        exact_target_weight_constant + MINIMUM_OTHER_BLOCK_WEIGHT;
    assert_eq!(
        exact_complete_witness_constant,
        EXPECTED_G31_COMPLETE_WITNESS_CONSTANT
    );
    assert_eq!(
        exact_target_weight_constant,
        EXPECTED_G31_TARGET_WEIGHT_CONSTANT
    );
    assert_eq!(
        exact_minimum_block_weight_constant,
        EXPECTED_G31_MINIMUM_BLOCK_WEIGHT_CONSTANT
    );
    let exact_complete_witness_bytes =
        G31_PROJECTED_LINKED_SCRIPT_BYTES + exact_complete_witness_constant;
    let exact_target_weight = G31_PROJECTED_LINKED_SCRIPT_BYTES + exact_target_weight_constant;
    let exact_minimum_block_weight =
        G31_PROJECTED_LINKED_SCRIPT_BYTES + exact_minimum_block_weight_constant;
    assert_eq!(exact_complete_witness_bytes, 3_857_605);
    assert_eq!(exact_target_weight, 3_857_983);
    assert_eq!(exact_minimum_block_weight, 3_858_751);
    let exact_headroom = 4_000_000 - exact_minimum_block_weight;
    assert_eq!(exact_headroom, 141_249);

    let conservative_argument_witness_bytes = compact_size_bytes(G31_ENTRY_ITEMS)
        + G31_TRACE_ITEMS * (1 + 5)
        + QFREE_SCALAR_ITEMS * (1 + 5);
    assert_eq!(conservative_argument_witness_bytes, 4_467);
    let conservative_target_weight_constant = TARGET_STRIPPED_WEIGHT
        + WITNESS_MARKER_FLAG_BYTES
        + conservative_argument_witness_bytes
        + LEAF_COMPACT_SIZE_BYTES
        + SERIALIZED_CONTROL_BLOCK_BYTES;
    let conservative_minimum_block_weight_constant =
        conservative_target_weight_constant + MINIMUM_OTHER_BLOCK_WEIGHT;
    assert_eq!(conservative_target_weight_constant, 4_884);
    assert_eq!(conservative_minimum_block_weight_constant, 5_652);
    let conservative_target_weight =
        G31_PROJECTED_LINKED_SCRIPT_BYTES + conservative_target_weight_constant;
    let conservative_minimum_block_weight =
        G31_PROJECTED_LINKED_SCRIPT_BYTES + conservative_minimum_block_weight_constant;
    assert_eq!(conservative_target_weight, 3_858_729);
    assert_eq!(conservative_minimum_block_weight, 3_859_497);
    let conservative_headroom = 4_000_000 - conservative_minimum_block_weight;
    assert_eq!(conservative_headroom, 140_503);

    println!("model=ed25519_montgomery_h16_g31_qfree_honest_witness");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=host-generation-and-witness-serialization");
    println!("execution_class=unclassified");
    println!("whole_script_generated=false");
    println!("whole_script_executed=false");
    println!("long_scalar_blake_or_field_script_execution=false");
    println!("response_schedule=G31");
    println!("response_width9_lower_positions=20,21,22,23,26");
    println!("response_other_lower_width=8");
    println!("response_top_width=8");
    println!("response_total_bits={SCALAR_BITS}");
    println!("response_groups={G31_RESPONSE_GROUPS}");
    println!("challenge_groups={CHALLENGE_GROUPS}");
    println!("transitions={G31_TRANSITIONS}");
    println!("deterministic_private_scalar={PUBLIC_KEY_SCALAR}");
    println!("benchmark_private_scalar_disclosed=true");
    println!("production_table_generator_secret_scalar_inputs=0");
    println!("deterministic_nonce={nonce}");
    println!("domain_separator={}", hex(&domain));
    println!("public_key_rfc8032={}", hex(&public_key_encoding));
    println!("fixed_message={}", hex(&message));
    println!("rtilde_packed_field={}", hex(&rtilde));
    println!("challenge_le128={challenge}");
    println!("response_s={response}");
    println!("response_payload_C_plus_s={scalar_payload}");
    println!("response_payload_z32={}", hex(&z));
    println!("signature_Rtilde_plus_z={}", hex(&signature));
    println!("signature_equation_sB_minus_hA_equals_R=true");
    println!("host_endpoint_minus_U_plus_sB_minus_hA_matches_Rtilde=true");
    println!("table_leaf_direct_limb_reconstruction_checked_for_all_47_selections=true");
    println!("derived_transition_pairs_host_verified={G31_TRANSITIONS}");
    println!(
        "derived_scalar_relations_host_verified={}",
        2 * G31_TRANSITIONS
    );
    println!("derived_relation_checks=exact_divisibility_plus_forward_and_reverse_radix32_carries");
    println!("hybrid_state_host_audited_for_all_46_transition_outputs=true");
    println!("hybrid_state_items=92");
    println!("hybrid_state_layout_bottom_to_top=b9|a16|lambda51_biased_decoder_digits|u16_centered_limbs");
    println!("hybrid_state_reuses_exact_decoder_and_table_representatives=true");
    println!("final_packed_r_has_no_consumer_after_certified_hybrid_state=true");
    println!("entry_layout=challenge16_trace_only_then_response30_trace_only_then_scalar8");
    println!("trace_data_items={G31_TRACE_ITEMS}");
    println!("scalar_word_items={QFREE_SCALAR_ITEMS}");
    println!("incremental_hint_items_per_transition=0");
    println!("quotient_hint_items=0");
    println!("complete_entry_items={G31_ENTRY_ITEMS}");
    println!("all_736_trace_and_8_scalar_items_coexist_at_entry=true");
    println!("quotients_materialized_on_host_for_audit_only=true");
    println!("quotients_are_verifier_derived_not_witness_supplied=true");
    println!("curve_quotient_actual_interval=[{curve_quotient_min},{curve_quotient_max}]");
    println!("curve_reverse_carry_actual_interval=[{curve_carry_min},{curve_carry_max}]");
    println!(
        "first_continuity_quotient_actual={}",
        first.audit.continuity.quotient
    );
    println!(
        "first_continuity_reverse_carry_actual_interval=[{},{}]",
        first.audit.continuity.reverse_carry_min, first.audit.continuity.reverse_carry_max
    );
    println!("chained_continuity_quotient_actual_interval=[{chained_continuity_quotient_min},{chained_continuity_quotient_max}]");
    println!("chained_continuity_reverse_carry_actual_interval=[{chained_continuity_carry_min},{chained_continuity_carry_max}]");
    println!(
        "continuity_quotient_actual_interval=[{continuity_quotient_min},{continuity_quotient_max}]"
    );
    println!(
        "continuity_reverse_carry_actual_interval=[{continuity_carry_min},{continuity_carry_max}]"
    );
    println!("exact_736_trace_item_vector_bytes={exact_trace_vector_bytes}");
    println!("exact_8_scalar_item_vector_bytes={exact_scalar_vector_bytes}");
    println!("exact_744_argument_witness_bytes={exact_witness_bytes}");
    println!("serialized_argument_witness_blake3={witness_hash}");
    println!("exact_746_item_complete_witness_bytes_formula=S+{exact_complete_witness_constant}");
    println!("exact_fixture_target_weight_formula=S+{exact_target_weight_constant}");
    println!("exact_fixture_minimum_block_weight_formula=S+{exact_minimum_block_weight_constant}");
    println!("linked_script_bytes_for_envelope={G31_PROJECTED_LINKED_SCRIPT_BYTES}");
    println!("linked_script_metric_status=projected_pending_exact_generation");
    println!("projected_exact_complete_witness_bytes={exact_complete_witness_bytes}");
    println!("projected_exact_target_weight={exact_target_weight}");
    println!("projected_exact_minimum_block_weight={exact_minimum_block_weight}");
    println!("projected_exact_headroom_below_4000000={exact_headroom}");
    println!("conservative_744_argument_witness_bytes={conservative_argument_witness_bytes}");
    println!("conservative_target_weight_formula=S+{conservative_target_weight_constant}");
    println!(
        "conservative_minimum_block_weight_formula=S+{conservative_minimum_block_weight_constant}"
    );
    println!("projected_conservative_target_weight={conservative_target_weight}");
    println!("projected_conservative_minimum_block_weight={conservative_minimum_block_weight}");
    println!("projected_conservative_headroom_below_4000000={conservative_headroom}");
    println!("includes=complete 744-item G31 argument witness only: 736 canonical packed trace-data items and eight canonical compressed-u32 scalar words; zero quotient hints; exact table representatives and all 92 derived relation identities checked on host; projected leaf size used only for envelope arithmetic; leaf generation/execution, control block, transaction, and Bitcoin Core validation excluded");
}

fn run_g32_qfree_honest_fixture(canonical_u5_final_r: bool) {
    assert_eq!(G32_RESPONSE_TRANSITIONS, 31);
    assert_eq!(G32_TRANSITIONS, 47);
    assert_eq!(G32_TRACE_ITEMS, 752);
    assert_eq!(G32_ENTRY_ITEMS, 760);
    assert_eq!(G32_U5_FINAL_PACKET_ITEMS, 59);
    assert_eq!(G32_U5_TRACE_ITEMS, 795);
    assert_eq!(G32_U5_ENTRY_ITEMS, 803);

    let response_widths = table_model::montgomery_direct_h16_qfree_g32_response_widths();
    assert_eq!(response_widths, g32_response_widths());
    let p = u5_balanced_table::modulus();
    let d = edwards_d();
    let sqrt_minus_one = BigUint::parse_bytes(
        b"19681161376707505956807079304988542015446066515923890162744021073123829784752",
        10,
    )
    .expect("sqrt(-1) parses");
    assert_eq!(
        mul_mod(&sqrt_minus_one, &sqrt_minus_one, &p),
        &p - BigUint::one()
    );
    let v_scale = sqrt_mod(&(&p - BigUint::from(486_664u32)), &p, &sqrt_minus_one);
    assert_eq!(v_scale.to_str_radix(10), EXPECTED_V_SCALE);
    let base_constants = basepoint_constants();
    let base = EdwardsPoint {
        x: base_constants.a,
        y: base_constants.b,
    };
    let t = EdwardsPoint {
        x: BigUint::zero(),
        y: &p - BigUint::one(),
    };
    let u = EdwardsPoint {
        x: sqrt_minus_one,
        y: BigUint::zero(),
    };
    assert_eq!(add(&u, &u, &p, &d), t);

    let private_scalar = BigUint::from(PUBLIC_KEY_SCALAR);
    let public_key = scalar_mul(private_scalar.clone(), &base, &p, &d);
    let public_key_encoding = standard_edwards_encoding(&public_key);
    assert_eq!(public_key_encoding, EXPECTED_PUBLIC_KEY);

    let nonce =
        BigUint::parse_bytes(b"123456789012345678901234567890123456789", 10).expect("nonce parses");
    assert!(nonce < scalar_order());
    let nonce_point = scalar_mul(nonce.clone(), &base, &p, &d);
    let shifted_nonce = add(&negate(&u, &p), &nonce_point, &p, &d);
    let shifted_nonce_m = to_montgomery(&shifted_nonce, &p, &v_scale);
    let rtilde = packed_field_bytes(&shifted_nonce_m.u);
    let domain = *blake3::hash(b"bitcoin-lab/custom-ed25519-blake3-slope-v1").as_bytes();
    let message: [u8; 32] = std::array::from_fn(|index| (index as u8).wrapping_mul(7));
    assert_eq!(hex(&domain), EXPECTED_DOMAIN_HEX);
    assert_eq!(hex(&message), EXPECTED_MESSAGE_HEX);
    assert_eq!(hex(&rtilde), EXPECTED_RTILDE_HEX);
    let digest = blake3::hash(
        &[
            domain.as_slice(),
            public_key_encoding.as_slice(),
            rtilde.as_slice(),
            message.as_slice(),
        ]
        .concat(),
    );
    let challenge = BigUint::from_bytes_le(&digest.as_bytes()[..16]);
    assert!(challenge.bits() <= 128);
    assert_eq!(challenge.to_str_radix(10), EXPECTED_CHALLENGE);
    let response = (&nonce + &challenge * &private_scalar) % scalar_order();
    assert_eq!(response.to_str_radix(10), EXPECTED_RESPONSE);
    let scalar_payload = response_encoding_offset(&response_widths) + &response;
    assert!(scalar_payload.bits() <= SCALAR_BITS as u64);
    let z = fixed_32_le(&scalar_payload);
    assert_eq!(hex(&z), EXPECTED_G32_Z_HEX);

    let response_digits = centered_digits(response.clone(), &response_widths);
    let challenge_widths = vec![8usize; CHALLENGE_GROUPS];
    let challenge_digits = independent_challenge_digits(&challenge);
    let mut payload_position = 0usize;
    for (group, width) in response_widths.iter().copied().enumerate() {
        let code = ((&scalar_payload >> payload_position) & BigUint::from((1u32 << width) - 1))
            .to_i32()
            .expect("response payload code fits i32");
        let expected = if group + 1 == G32_RESPONSE_GROUPS {
            response_digits[group]
        } else {
            response_digits[group] + (1i32 << (width - 1))
        };
        assert_eq!(code, expected, "G32 C+s code at group {group}");
        payload_position += width;
    }
    assert_eq!(payload_position, SCALAR_BITS);
    let response_bases = position_bases(&response_widths, &base, &p, &d);
    let negative_public_key = negate(&public_key, &p);
    let challenge_bases = position_bases(&challenge_widths, &negative_public_key, &p, &d);

    let table_model::MontgomeryDirectH16HostTables {
        response_low_to_high: response_tables,
        challenge_low_to_high: challenge_tables,
        public_key_compressed: table_public_key,
    } = table_model::montgomery_direct_h16_qfree_g32_host_tables_for_public_key(
        EXPECTED_PUBLIC_KEY,
    )
    .expect("the fixed external public-key boundary accepts the benchmark key");
    assert_eq!(table_public_key, public_key_encoding);
    assert_eq!(response_tables.len(), G32_RESPONSE_GROUPS);
    assert_eq!(challenge_tables.len(), CHALLENGE_GROUPS);

    let top_digit = response_digits[G32_RESPONSE_GROUPS - 1];
    assert!(top_digit >= 0);
    let top_digit = top_digit as usize;
    assert!(top_digit < response_tables[G32_RESPONSE_GROUPS - 1].len());
    let initial_direct = direct_from_leaf(&response_tables[G32_RESPONSE_GROUPS - 1][top_digit]);
    let top_contribution = scalar_mul(
        BigUint::from(top_digit as u32),
        &response_bases[G32_RESPONSE_GROUPS - 1],
        &p,
        &d,
    );
    let response_initializer_shift = negate(
        &scalar_mul(
            table_model::h16_independent_challenge_bias_scalar(),
            &public_key,
            &p,
            &d,
        ),
        &p,
    );
    let initial = add(
        &u,
        &add(&response_initializer_shift, &top_contribution, &p, &d),
        &p,
        &d,
    );
    let initial_m = to_montgomery(&initial, &p, &v_scale);
    assert_eq!(direct_coordinates(&initial_direct, &p), initial_m);

    let mut chain = ChainBuilder {
        p: p.clone(),
        d: d.clone(),
        v_scale: v_scale.clone(),
        current: initial,
        current_m: initial_m,
        initial_direct,
        previous_direct: None,
        previous_lambda: None,
        transitions: 0,
        symmetric_square_audit: true,
    };
    let mut response_packets: Vec<Option<Packet>> = vec![None; G32_RESPONSE_TRANSITIONS];
    let mut challenge_packets: Vec<Option<Packet>> = vec![None; CHALLENGE_GROUPS];

    for group in (0..G32_RESPONSE_TRANSITIONS).rev() {
        let digit = response_digits[group];
        let magnitude = digit.unsigned_abs() as usize;
        assert!(magnitude < response_tables[group].len());
        let mut direct = direct_from_leaf(&response_tables[group][magnitude]);
        if digit < 0 {
            direct = direct.literal_negative();
        }
        let selected = selected_point(digit, &response_bases[group], &t, &p, &d);
        response_packets[group] = Some(chain.transition(selected, direct));
    }
    for group in (0..CHALLENGE_GROUPS).rev() {
        let digit = challenge_digits[group];
        let magnitude = digit.unsigned_abs() as usize;
        assert!(magnitude < challenge_tables[group].len());
        let mut direct = direct_from_leaf(&challenge_tables[group][magnitude]);
        if digit < 0 {
            direct = direct.literal_negative();
        }
        let selected = selected_point(digit, &challenge_bases[group], &t, &p, &d);
        challenge_packets[group] = Some(chain.transition(selected, direct));
    }
    assert_eq!(chain.transitions, G32_TRANSITIONS);

    let equation_point = add(
        &scalar_mul(response.clone(), &base, &p, &d),
        &negate(&scalar_mul(challenge.clone(), &public_key, &p, &d), &p),
        &p,
        &d,
    );
    assert_eq!(equation_point, nonce_point);
    assert_eq!(chain.current, shifted_nonce);
    assert_eq!(chain.current_m.u, shifted_nonce_m.u);
    assert_eq!(packed_field_bytes(&chain.current_m.u), rtilde);

    let response_packets = response_packets
        .into_iter()
        .map(|packet| packet.expect("every G32 response packet is populated"))
        .collect::<Vec<_>>();
    let challenge_packets = challenge_packets
        .into_iter()
        .map(|packet| packet.expect("every challenge packet is populated"))
        .collect::<Vec<_>>();
    // Challenge packets are stored low-to-high at entry and executed
    // high-to-low, so packet zero is both the lowest physical packet and the
    // final transition. Its u_next is exactly the transcript Rtilde.
    assert_eq!(challenge_packets[0].u_next, shifted_nonce_m.u);
    let hybrid_states =
        audit_hybrid_transition_states(&response_packets, &challenge_packets, &initial_direct, &p);
    assert_eq!(hybrid_states.len(), G32_TRANSITIONS);
    let final_hybrid_u = hybrid_state_u(
        hybrid_states
            .last()
            .expect("the final challenge transition returns a hybrid state"),
        &p,
    );
    assert_eq!(final_hybrid_u, shifted_nonce_m.u);
    assert_eq!(packed_field_bytes(&final_hybrid_u), rtilde);

    let all_packets = response_packets
        .iter()
        .chain(challenge_packets.iter())
        .collect::<Vec<_>>();
    assert_eq!(all_packets.len(), G32_TRANSITIONS);
    assert!(all_packets
        .iter()
        .all(|packet| packet.hints == packet.audit.hints()));
    let audit_hash = transition_audit_hash(&response_packets, &challenge_packets);
    assert_eq!(audit_hash.to_string(), EXPECTED_G32_TRANSITION_AUDIT_BLAKE3);

    let expected_trace_items = if canonical_u5_final_r {
        G32_U5_TRACE_ITEMS
    } else {
        G32_TRACE_ITEMS
    };
    let expected_entry_items = if canonical_u5_final_r {
        G32_U5_ENTRY_ITEMS
    } else {
        G32_ENTRY_ITEMS
    };
    let mut witness = Vec::with_capacity(expected_entry_items);
    for (group, packet) in challenge_packets.iter().enumerate() {
        if canonical_u5_final_r && group == 0 {
            witness.extend(qfree_u5_final_packet_items(packet));
        } else {
            witness.extend(qfree_packet_items(packet));
        }
    }
    for packet in &response_packets {
        witness.extend(qfree_packet_items(packet));
    }
    let scalar_items = qfree_scalar_items(&scalar_payload);
    assert_eq!(scalar_items.len(), QFREE_SCALAR_ITEMS);
    witness.extend(scalar_items);
    assert_eq!(witness.len(), expected_entry_items);
    assert!(witness.iter().all(|item| item.len() <= 5));

    let serialized_witness = serialize(&Witness::from_slice(&witness));
    let exact_witness_bytes = serialized_witness.len();
    assert_eq!(exact_witness_bytes, serialized_item_vector_bytes(&witness));
    let exact_trace_vector_bytes = serialized_item_vector_bytes(&witness[..expected_trace_items]);
    let exact_scalar_vector_bytes = serialized_item_vector_bytes(&witness[expected_trace_items..]);
    let witness_hash = blake3::hash(&serialized_witness);
    assert_eq!(exact_scalar_vector_bytes, EXPECTED_G32_SCALAR_VECTOR_BYTES);
    if !canonical_u5_final_r {
        assert_eq!(exact_witness_bytes, EXPECTED_G32_ARGUMENT_WITNESS_BYTES);
        assert_eq!(exact_trace_vector_bytes, EXPECTED_G32_TRACE_VECTOR_BYTES);
        assert_eq!(
            witness_hash.to_string(),
            EXPECTED_G32_ARGUMENT_WITNESS_BLAKE3
        );
    } else {
        assert_eq!(exact_witness_bytes, EXPECTED_G32_U5_ARGUMENT_WITNESS_BYTES);
        assert_eq!(exact_trace_vector_bytes, EXPECTED_G32_U5_TRACE_VECTOR_BYTES);
        assert_eq!(
            witness_hash.to_string(),
            EXPECTED_G32_U5_ARGUMENT_WITNESS_BLAKE3
        );
    }

    let curve_quotient_min = all_packets
        .iter()
        .map(|packet| packet.audit.curve.quotient)
        .min()
        .unwrap();
    let curve_quotient_max = all_packets
        .iter()
        .map(|packet| packet.audit.curve.quotient)
        .max()
        .unwrap();
    let curve_carry_min = all_packets
        .iter()
        .map(|packet| packet.audit.curve.reverse_carry_min)
        .min()
        .unwrap();
    let curve_carry_max = all_packets
        .iter()
        .map(|packet| packet.audit.curve.reverse_carry_max)
        .max()
        .unwrap();
    let first = response_packets
        .last()
        .expect("p30 is the first executed G32 response packet");
    let chained_packets = response_packets[..G32_RESPONSE_TRANSITIONS - 1]
        .iter()
        .chain(challenge_packets.iter())
        .collect::<Vec<_>>();
    assert_eq!(chained_packets.len(), G32_TRANSITIONS - 1);
    let chained_continuity_quotient_min = chained_packets
        .iter()
        .map(|packet| packet.audit.continuity.quotient)
        .min()
        .unwrap();
    let chained_continuity_quotient_max = chained_packets
        .iter()
        .map(|packet| packet.audit.continuity.quotient)
        .max()
        .unwrap();
    let chained_continuity_carry_min = chained_packets
        .iter()
        .map(|packet| packet.audit.continuity.reverse_carry_min)
        .min()
        .unwrap();
    let chained_continuity_carry_max = chained_packets
        .iter()
        .map(|packet| packet.audit.continuity.reverse_carry_max)
        .max()
        .unwrap();
    assert_eq!(
        (curve_quotient_min, curve_quotient_max),
        EXPECTED_G32_CURVE_QUOTIENT_INTERVAL
    );
    assert_eq!(
        (curve_carry_min, curve_carry_max),
        EXPECTED_G32_CURVE_CARRY_INTERVAL
    );
    assert_eq!(
        first.audit.continuity.quotient,
        EXPECTED_G32_FIRST_CONTINUITY_QUOTIENT
    );
    assert_eq!(
        (
            first.audit.continuity.reverse_carry_min,
            first.audit.continuity.reverse_carry_max,
        ),
        EXPECTED_G32_FIRST_CONTINUITY_CARRY_INTERVAL
    );
    assert_eq!(
        (
            chained_continuity_quotient_min,
            chained_continuity_quotient_max,
        ),
        EXPECTED_G32_CHAINED_CONTINUITY_QUOTIENT_INTERVAL
    );
    assert_eq!(
        (chained_continuity_carry_min, chained_continuity_carry_max),
        EXPECTED_G32_CHAINED_CONTINUITY_CARRY_INTERVAL
    );

    let exact_complete_witness_constant =
        exact_witness_bytes + LEAF_COMPACT_SIZE_BYTES + SERIALIZED_CONTROL_BLOCK_BYTES;
    let exact_target_weight_constant =
        TARGET_STRIPPED_WEIGHT + WITNESS_MARKER_FLAG_BYTES + exact_complete_witness_constant;
    let exact_minimum_block_weight_constant =
        exact_target_weight_constant + MINIMUM_OTHER_BLOCK_WEIGHT;
    // Every ordinary packed word is at most five payload bytes. Canonical u5
    // digits are in 0..=31 and therefore need at most one payload byte.
    let packed_trace_and_scalar_items = if canonical_u5_final_r {
        G32_U5_TRACE_ITEMS - 51 + QFREE_SCALAR_ITEMS
    } else {
        G32_ENTRY_ITEMS
    };
    let canonical_u5_items = usize::from(canonical_u5_final_r) * 51;
    let conservative_argument_witness_bytes = compact_size_bytes(expected_entry_items)
        + packed_trace_and_scalar_items * (1 + 5)
        + canonical_u5_items * (1 + 1);
    let conservative_target_weight_constant = TARGET_STRIPPED_WEIGHT
        + WITNESS_MARKER_FLAG_BYTES
        + conservative_argument_witness_bytes
        + LEAF_COMPACT_SIZE_BYTES
        + SERIALIZED_CONTROL_BLOCK_BYTES;
    let conservative_minimum_block_weight_constant =
        conservative_target_weight_constant + MINIMUM_OTHER_BLOCK_WEIGHT;
    if canonical_u5_final_r {
        assert_eq!(compact_size_bytes(G32_U5_ENTRY_ITEMS), 3);
        assert_eq!(compact_size_bytes(G32_U5_ENTRY_ITEMS + 2), 3);
        assert_eq!(
            exact_complete_witness_constant,
            EXPECTED_G32_U5_COMPLETE_WITNESS_CONSTANT
        );
        assert_eq!(
            exact_target_weight_constant,
            EXPECTED_G32_U5_TARGET_WEIGHT_CONSTANT
        );
        assert_eq!(
            exact_minimum_block_weight_constant,
            EXPECTED_G32_U5_MINIMUM_BLOCK_WEIGHT_CONSTANT
        );
        assert_eq!(
            conservative_argument_witness_bytes,
            EXPECTED_G32_U5_CONSERVATIVE_ARGUMENT_WITNESS_BYTES
        );
        assert_eq!(
            conservative_target_weight_constant,
            EXPECTED_G32_U5_CONSERVATIVE_TARGET_WEIGHT_CONSTANT
        );
        assert_eq!(
            conservative_minimum_block_weight_constant,
            EXPECTED_G32_U5_CONSERVATIVE_MINIMUM_BLOCK_WEIGHT_CONSTANT
        );
    }

    let model = if canonical_u5_final_r {
        "ed25519_montgomery_h16_g32_hybrid_u5_honest_witness"
    } else {
        "ed25519_montgomery_h16_g32_qfree_honest_witness"
    };

    println!("model={model}");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=host-generation-and-witness-serialization");
    println!("execution_class=unclassified");
    println!("whole_script_generated=false");
    println!("whole_script_executed=false");
    println!("long_scalar_blake_or_field_script_execution=false");
    println!("response_schedule=G32_candidate");
    println!("response_width7_lower_positions=21,25,29");
    println!("response_other_lower_width=8");
    println!("response_top_width=8");
    println!("response_total_bits={SCALAR_BITS}");
    println!("response_groups={G32_RESPONSE_GROUPS}");
    println!("challenge_groups={CHALLENGE_GROUPS}");
    println!("transitions={G32_TRANSITIONS}");
    println!("deterministic_private_scalar={PUBLIC_KEY_SCALAR}");
    println!("benchmark_private_scalar_disclosed=true");
    println!("production_table_generator_secret_scalar_inputs=0");
    println!("deterministic_nonce={nonce}");
    println!("domain_separator={}", hex(&domain));
    println!("public_key_rfc8032={}", hex(&public_key_encoding));
    println!("fixed_message={}", hex(&message));
    println!("rtilde_packed_field={}", hex(&rtilde));
    println!("challenge_le128={challenge}");
    println!("response_s={response}");
    println!("response_payload_C_plus_s={scalar_payload}");
    println!("response_payload_z32={}", hex(&z));
    println!("signature_equation_sB_minus_hA_equals_R=true");
    println!("table_leaf_direct_limb_reconstruction_checked_for_all_48_selections=true");
    println!("derived_transition_pairs_host_verified={G32_TRANSITIONS}");
    println!(
        "derived_scalar_relations_host_verified={}",
        2 * G32_TRANSITIONS
    );
    println!("transition_audit_blake3={audit_hash}");
    println!("hybrid_state_host_audited_for_all_47_transition_outputs=true");
    println!("hybrid_state_items=92");
    println!("hybrid_state_layout_bottom_to_top=b9|a16|lambda51_biased_decoder_digits|u16_centered_limbs");
    println!("entry_layout=challenge16_trace_only_then_response31_trace_only_then_scalar8");
    println!(
        "final_challenge_packet_u_representation={}",
        if canonical_u5_final_r {
            "51_canonical_biased_radix32_digits"
        } else {
            "8_canonical_packed_u32_words"
        }
    );
    println!(
        "final_challenge_packet_items={}",
        if canonical_u5_final_r {
            G32_U5_FINAL_PACKET_ITEMS
        } else {
            TRACE_ITEMS_PER_PACKET
        }
    );
    println!("trace_data_items={expected_trace_items}");
    println!("scalar_word_items={QFREE_SCALAR_ITEMS}");
    println!("incremental_hint_items_per_transition=0");
    println!("quotient_hint_items=0");
    println!("complete_entry_items={expected_entry_items}");
    println!("all_trace_and_scalar_items_coexist_at_entry=true");
    if canonical_u5_final_r {
        println!("all_803_argument_items_coexist_at_script_entry=true");
        println!("final_r_u5_digits_host_canonical_and_reconstruct_rtilde=true");
        println!("final_r_u5_originals_bound_by_hash_certifier_and_terminal_relation=true");
    } else {
        println!("all_760_argument_items_coexist_at_script_entry=true");
        println!("final_r_packed_words_host_canonical_and_reconstruct_rtilde=true");
    }
    println!("curve_quotient_actual_interval=[{curve_quotient_min},{curve_quotient_max}]");
    println!("curve_reverse_carry_actual_interval=[{curve_carry_min},{curve_carry_max}]");
    println!(
        "first_continuity_quotient_actual={}",
        first.audit.continuity.quotient
    );
    println!(
        "first_continuity_reverse_carry_actual_interval=[{},{}]",
        first.audit.continuity.reverse_carry_min, first.audit.continuity.reverse_carry_max
    );
    println!("chained_continuity_quotient_actual_interval=[{chained_continuity_quotient_min},{chained_continuity_quotient_max}]");
    println!("chained_continuity_reverse_carry_actual_interval=[{chained_continuity_carry_min},{chained_continuity_carry_max}]");
    println!("exact_trace_item_vector_bytes={exact_trace_vector_bytes}");
    println!("exact_8_scalar_item_vector_bytes={exact_scalar_vector_bytes}");
    println!("exact_argument_witness_bytes={exact_witness_bytes}");
    if canonical_u5_final_r {
        println!("exact_795_trace_item_vector_bytes={exact_trace_vector_bytes}");
        println!("exact_803_argument_witness_bytes={exact_witness_bytes}");
    } else {
        println!("exact_752_trace_item_vector_bytes={exact_trace_vector_bytes}");
        println!("exact_760_argument_witness_bytes={exact_witness_bytes}");
    }
    println!("serialized_argument_witness_blake3={witness_hash}");
    println!("envelope_symbol_S=policy_produced_revealed_leaf_bytes");
    println!("exact_complete_witness_bytes_formula=S+{exact_complete_witness_constant}");
    println!(
        "exact_{}_item_complete_witness_bytes_formula=S+{exact_complete_witness_constant}",
        expected_entry_items + 2
    );
    println!("exact_fixture_target_weight_formula=S+{exact_target_weight_constant}");
    println!("exact_fixture_minimum_block_weight_formula=S+{exact_minimum_block_weight_constant}");
    println!("conservative_argument_witness_bytes={conservative_argument_witness_bytes}");
    println!("conservative_target_weight_formula=S+{conservative_target_weight_constant}");
    println!(
        "conservative_minimum_block_weight_formula=S+{conservative_minimum_block_weight_constant}"
    );
    if canonical_u5_final_r {
        let projected_exact_complete_witness =
            G32_HYBRID_U5_LINKED_SCRIPT_BYTES + exact_complete_witness_constant;
        let projected_exact_target_weight =
            G32_HYBRID_U5_LINKED_SCRIPT_BYTES + exact_target_weight_constant;
        let projected_exact_minimum_block_weight =
            G32_HYBRID_U5_LINKED_SCRIPT_BYTES + exact_minimum_block_weight_constant;
        assert_eq!(projected_exact_complete_witness, 3_003_885);
        assert_eq!(projected_exact_target_weight, 3_004_263);
        assert_eq!(projected_exact_minimum_block_weight, 3_005_031);
        assert_eq!(4_000_000 - projected_exact_minimum_block_weight, 994_969);
        println!("linked_script_bytes_for_envelope={G32_HYBRID_U5_LINKED_SCRIPT_BYTES}");
        println!("linked_script_static_non_push_opcodes={G32_HYBRID_U5_LINKED_SCRIPT_STATIC_NON_PUSH_OPCODES}");
        println!("linked_script_metric_status=locally_reproduced_generation_only_serialization");
        println!("projected_exact_complete_witness_bytes={projected_exact_complete_witness}");
        println!("projected_exact_target_weight={projected_exact_target_weight}");
        println!("projected_exact_minimum_block_weight={projected_exact_minimum_block_weight}");
        println!(
            "projected_exact_headroom_below_4000000={}",
            4_000_000usize - projected_exact_minimum_block_weight
        );
        println!("includes=complete 803-item G32 hybrid-u5 argument witness only: 795 trace-data items (the final packet is 51 canonical biased radix-32 Rtilde digits plus eight packed lambda words; every other packet is 16 packed words) and eight canonical compressed-u32 scalar words; zero quotient hints; exact table representatives, all 94 relation identities, canonical final-R reconstruction, and hybrid-state reuse checked on host; projected leaf size is used only for envelope arithmetic; leaf generation/execution, transaction construction, and Bitcoin Core validation excluded");
    } else {
        println!("linked_script_metric_status=historical_packed_r_mode");
        println!("transaction_envelope_status=historical_packed_r_mode");
        println!("includes=complete 760-item G32 candidate argument witness only: 752 canonical packed trace-data items and eight canonical compressed-u32 scalar words; zero quotient hints; exact table representatives, all 94 relation identities, and hybrid-state reuse checked on host; leaf generation/execution, envelope, transaction, and Bitcoin Core validation excluded");
    }
}

#[allow(dead_code)]
pub(crate) fn run_qfree_honest_witness_probe() {
    run_honest_fixture(true);
}

#[allow(dead_code)]
pub(crate) fn run_g31_qfree_honest_witness_probe() {
    run_g31_qfree_honest_fixture();
}

#[allow(dead_code)]
pub(crate) fn run_g32_qfree_honest_witness_probe() {
    run_g32_qfree_honest_fixture(false);
}

#[allow(dead_code)]
pub(crate) fn run_g32_hybrid_u5_honest_witness_probe() {
    run_g32_qfree_honest_fixture(true);
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("--g31-hybrid-audit") => run_g31_qfree_honest_fixture(),
        Some("--g32-hybrid-audit") => run_g32_qfree_honest_fixture(false),
        Some("--g32-hybrid-u5-audit") => run_g32_qfree_honest_fixture(true),
        _ => run_honest_fixture(false),
    }
}
