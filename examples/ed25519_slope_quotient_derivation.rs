//! Derive an Ed25519 relation quotient from the accumulator itself.
//!
//! For `H = sum(h_i * 32^i)` and `p = 32^51 - 19`, an accepted relation
//! has `H = q*p`.  Since every slope quotient is in a signed 22- or 23-bit
//! interval, its fixed-width residue is unique and
//!
//! `q = signed_w(1_324_517 * (H mod 2^w) mod 2^w)`.
//!
//! Only `h_0..h_4` contribute when `w <= 23`.  This focused probe derives
//! `q` without witness hints, then feeds it to the existing full reverse
//! carry verifier.  It does not execute a slope transition or the full leaf.

#[allow(dead_code)]
#[path = "ed25519_slope_carrier_codec.rs"]
mod carrier_codec;

use bitcoin_lab::{
    curves::ed25519::{
        absorb_relation_quotient,
        montgomery_slope::{
            CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
            CHAINED_CONTINUITY_QUOTIENT_ABS_MAX as CHAINED_CONTINUITY_ABS_MAX,
            CURVE_LOW_COEFFICIENT_ABS_MAX, CURVE_QUOTIENT_MAX as CURVE_MAX,
            CURVE_QUOTIENT_MIN as CURVE_MIN, FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
            FIRST_CONTINUITY_QUOTIENT_ABS_MAX as FIRST_CONTINUITY_ABS_MAX,
        },
        verify_streamed_relation, verify_streamed_relation_absorbed,
    },
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
    },
};

const RADIX_BITS: usize = 5;
const COEFFICIENTS: usize = 51;
const NEGATIVE_NINETEEN_INVERSE: u32 = 1_324_517;

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

/// Reduce one four-byte Script integer to a signed congruent remainder.
///
/// The input may be negative.  Taking the absolute value first avoids adding
/// a large normalization constant near the ScriptNum limit.  The caller's
/// coefficient bounds exclude `-2^31`.
fn signed_low_remainder(width: usize, max_abs: i64) -> Script {
    assert!((1..=30).contains(&width));
    let input_bits = i64::BITS as usize - max_abs.leading_zeros() as usize;
    assert!(input_bits <= 31);
    script! {
        OP_DUP 0 OP_LESSTHAN
        OP_DUP OP_TOALTSTACK
        OP_IF OP_NEGATE OP_ENDIF

        for bit in (width..input_bits).rev() {
            { 1u32 << bit } OP_2DUP OP_GREATERTHANOREQUAL
            OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
        }

        OP_FROMALTSTACK OP_IF OP_NEGATE OP_ENDIF
    }
}

/// Reduce a signed value of magnitude below `2^(width+3)` modulo `2^width`.
fn reduce_signed_five_term_sum(width: usize) -> Script {
    script! {
        OP_DUP 0 OP_LESSTHAN
        OP_DUP OP_TOALTSTACK
        OP_IF OP_NEGATE OP_ENDIF
        for bit in (width..=width + 2).rev() {
            { 1u32 << bit } OP_2DUP OP_GREATERTHANOREQUAL
            OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
        }
        OP_FROMALTSTACK
        OP_IF
            // `-0 mod 2^width` is zero, not the modulus.
            OP_DUP OP_NOT OP_NOT OP_IF
                { 1u32 << width } OP_SWAP OP_SUB
            OP_ENDIF
        OP_ENDIF
    }
}

/// Reduce a known nonnegative value below `2^(width+1)` modulo `2^width`.
fn reduce_once(width: usize) -> Script {
    script! {
        { 1u32 << width } OP_2DUP OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
    }
}

/// Multiply the top residue by `NEGATIVE_NINETEEN_INVERSE` modulo `2^width`.
/// The original residue is retained below a Horner accumulator and discarded
/// at the end, so every arithmetic intermediate stays below `2^(width+1)`.
fn multiply_inverse_mod_power_of_two(width: usize) -> Script {
    // Non-adjacent form has eight nonzero digits versus eleven set bits.
    let mut remaining = NEGATIVE_NINETEEN_INVERSE;
    let mut naf_low_to_high = Vec::new();
    while remaining != 0 {
        let digit = if remaining & 1 == 0 {
            0i8
        } else {
            2 - (remaining & 3) as i8
        };
        naf_low_to_high.push(digit);
        remaining = ((i64::from(remaining) - i64::from(digit)) / 2) as u32;
    }
    let naf_high_to_low = naf_low_to_high.into_iter().rev().collect::<Vec<_>>();
    assert_eq!(naf_high_to_low[0], 1);
    assert_eq!(
        naf_high_to_low.iter().filter(|digit| **digit != 0).count(),
        8
    );

    script! {
        // `x | accumulator=x`, then process all lower constant bits.
        OP_DUP
        for digit in naf_high_to_low.into_iter().skip(1) {
            OP_DUP OP_ADD
            { reduce_once(width) }
            if digit == 1 {
                1 OP_PICK OP_ADD
                { reduce_once(width) }
            } else if digit == -1 {
                1 OP_PICK OP_SUB
                OP_DUP 0 OP_LESSTHAN
                OP_IF { 1u32 << width } OP_ADD OP_ENDIF
            }
        }
        OP_NIP
    }
}

/// Input/output: `h[50..0] -> h[50..0] | q`, with `h0` nearest the top on
/// entry and the derived quotient nearest the top on exit.
///
/// The accumulator is preserved byte-for-byte.  Five copied low coefficients
/// are reduced one at a time and held transiently on altstack.
fn derive_relation_quotient(width: usize, low_coefficient_abs_max: [i64; 5]) -> Script {
    assert!(width == 22 || width == 23);
    let low_coefficients = width.div_ceil(RADIX_BITS);
    assert_eq!(low_coefficients, 5);

    script! {
        for coefficient in 0..low_coefficients {
            { coefficient as u32 } OP_PICK
            { signed_low_remainder(
                width - RADIX_BITS * coefficient,
                low_coefficient_abs_max[coefficient],
            ) }
            OP_TOALTSTACK
        }

        // Recompose H mod 2^width.  Each shifted term is below 2^width,
        // hence their five-term sum is below 5*2^width < 2^(width+3).
        OP_FROMALTSTACK
        for _coefficient in (0..low_coefficients - 1).rev() {
            for _ in 0..RADIX_BITS { OP_DUP OP_ADD }
            OP_FROMALTSTACK OP_ADD
        }
        { reduce_signed_five_term_sum(width) }
        { multiply_inverse_mod_power_of_two(width) }

        // Interpret the unique width-bit residue as two's complement.
        OP_DUP { 1u32 << (width - 1) } OP_GREATERTHANOREQUAL
        OP_IF { 1u32 << width } OP_SUB OP_ENDIF

    }
}

/// Close a relation with its quotient above, rather than below, the 51
/// coefficients. Pulling each high coefficient directly costs less than a
/// full 51-item block rotation before the ordinary closer.
fn verify_streamed_relation_top_quotient() -> Script {
    script! {
        // Retain the original q below the reverse-carry recurrence.
        OP_DUP
        for coefficient in (1..COEFFICIENTS).rev() {
            { (coefficient + 2) as u32 } OP_ROLL
            OP_SWAP
            for _ in 0..RADIX_BITS { OP_DUP OP_ADD }
            OP_SWAP OP_SUB
        }

        // h0 + 19*q == 32*carry.
        OP_TOALTSTACK
        OP_DUP
        // 19*q = 16*q + 2*q + q.
        OP_DUP OP_DUP OP_ADD
        OP_SWAP
        for _ in 0..4 { OP_DUP OP_ADD }
        OP_ADD OP_ADD
        OP_ADD
        OP_FROMALTSTACK
        for _ in 0..RADIX_BITS { OP_DUP OP_ADD }
        OP_NUMEQUALVERIFY
    }
}

fn derive_and_verify(width: usize, low_coefficient_abs_max: [i64; 5]) -> Script {
    script! {
        { derive_relation_quotient(width, low_coefficient_abs_max) }
        { verify_streamed_relation_top_quotient() }
    }
}

fn relation_coefficients(q: i32) -> [i64; COEFFICIENTS] {
    let mut h = [0i64; COEFFICIENTS];
    h[0] = -19 * i64::from(q);
    h[COEFFICIENTS - 1] = 32 * i64::from(q);
    h
}

/// Change the radix-32 coefficient representation without changing H.
fn add_carry_noise(h: &mut [i64; COEFFICIENTS]) {
    for (coefficient, carry) in [17i64, -29, 41, -53, 67].into_iter().enumerate() {
        h[coefficient] += 32 * carry;
        h[coefficient + 1] -= carry;
    }
}

fn coefficient_witness(h: &[i64; COEFFICIENTS]) -> Vec<Vec<u8>> {
    h.iter().rev().map(|value| scriptnum_item(*value)).collect()
}

fn execute_accept(fragment: &Script, width: usize, q: i32, noisy: bool) -> usize {
    let mut h = relation_coefficients(q);
    if noisy {
        add_carry_noise(&mut h);
    }
    let executable = script! {
        { fragment.clone() }
        OP_1
    }
    .compile_with_policy();
    let execution =
        execute_raw_script_with_inputs_strict(executable.to_bytes(), coefficient_witness(&h));
    assert!(
        execution.error.is_none(),
        "valid width-{width} q={q} relation failed: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);
    execution.stats.max_nb_stack_items
}

fn execute_reject(fragment: &Script, width: usize, h: &[i64; COEFFICIENTS], label: &str) {
    let executable = script! {
        { fragment.clone() }
        OP_1
    }
    .compile_with_policy();
    let execution =
        execute_raw_script_with_inputs_strict(executable.to_bytes(), coefficient_witness(h));
    assert!(
        execution.error.is_some(),
        "invalid width-{width} relation accepted: {label}"
    );
}

fn raw_fragment_len(fragment: Script) -> usize {
    let copies = MAX_OPTIMIZER_INPUT_BYTES.div_ceil(fragment.len()) + 1;
    let repeated = script! {
        for _ in 0..copies { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % copies, 0);
    repeated.len() / copies
}

fn main() {
    assert_eq!((19u64 * 7_064_091) % (1 << 23), 1);
    assert_eq!(
        (19u64 * u64::from(NEGATIVE_NINETEEN_INVERSE)) % (1 << 23),
        (1 << 23) - 1
    );

    let first_continuity_fragment = derive_and_verify(22, FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX);
    let curve_fragment = derive_and_verify(23, CURVE_LOW_COEFFICIENT_ABS_MAX);
    let chained_continuity_fragment =
        derive_and_verify(23, CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX);
    let derive_first_continuity =
        derive_relation_quotient(22, FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX);
    let derive_curve = derive_relation_quotient(23, CURVE_LOW_COEFFICIENT_ABS_MAX);
    let derive_chained_continuity =
        derive_relation_quotient(23, CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX);

    let mut peak22 = 0usize;
    for q in [
        -FIRST_CONTINUITY_ABS_MAX,
        -704_897,
        0,
        569_493,
        FIRST_CONTINUITY_ABS_MAX,
    ] {
        peak22 = peak22.max(execute_accept(&first_continuity_fragment, 22, q, true));
    }

    let mut peak23 = 0usize;
    for q in [
        CHAINED_CONTINUITY_ABS_MAX.checked_neg().unwrap(),
        CURVE_MIN,
        -704_897,
        0,
        643_853,
        CURVE_MAX,
        CHAINED_CONTINUITY_ABS_MAX,
    ] {
        peak23 = peak23.max(execute_accept(&curve_fragment, 23, q, true));
        peak23 = peak23.max(execute_accept(&chained_continuity_fragment, 23, q, true));
    }

    // The low residue still derives the same q, but the full recurrence must
    // reject a nonzero coefficient at radix position five.
    let mut malformed = relation_coefficients(643_853);
    add_carry_noise(&mut malformed);
    malformed[5] += 1;
    execute_reject(&curve_fragment, 23, &malformed, "non-divisible H");

    // q and q+2^w have the same low residue.  The signed-width derivation
    // chooses q, and the full relation check rejects the out-of-domain lift.
    let lifted_q = i64::from(643_853) + (1 << 23);
    let mut lifted = [0i64; COEFFICIENTS];
    lifted[0] = -19 * lifted_q;
    lifted[COEFFICIENTS - 1] = 32 * lifted_q;
    execute_reject(&curve_fragment, 23, &lifted, "q plus 2^23 alias");

    let derive_first_continuity_raw = raw_fragment_len(derive_first_continuity.clone());
    let derive_curve_raw = raw_fragment_len(derive_curve.clone());
    let derive_chained_continuity_raw = raw_fragment_len(derive_chained_continuity.clone());
    let first_continuity_fragment_raw = raw_fragment_len(first_continuity_fragment.clone());
    let curve_fragment_raw = raw_fragment_len(curve_fragment.clone());
    let chained_continuity_fragment_raw = raw_fragment_len(chained_continuity_fragment.clone());
    let ordinary_close = verify_streamed_relation(false);
    let top_quotient_close = verify_streamed_relation_top_quotient();
    let absorb = absorb_relation_quotient();
    let absorbed_close = verify_streamed_relation_absorbed();
    let ordinary_close_raw = raw_fragment_len(ordinary_close.clone());
    let top_quotient_close_raw = raw_fragment_len(top_quotient_close.clone());
    let absorb_raw = raw_fragment_len(absorb.clone());
    let absorbed_close_raw = raw_fragment_len(absorbed_close.clone());
    let first_response_decoder = carrier_codec::decode_pair_to_chunk_semantic(23, 22, 2);
    let padded_response_decoder = carrier_codec::decode_pair_to_chunk_semantic(23, 23, 2);
    let regular_response_decoder = carrier_codec::decode_pair_to_chunk_semantic(23, 23, 0);
    let challenge_carrier_decoder = carrier_codec::decode_carrier_compact_semantic(23);
    let first_response_decoder_raw = raw_fragment_len(first_response_decoder.clone());
    let padded_response_decoder_raw = raw_fragment_len(padded_response_decoder.clone());
    let regular_response_decoder_raw = raw_fragment_len(regular_response_decoder.clone());
    let challenge_carrier_decoder_raw = raw_fragment_len(challenge_carrier_decoder.clone());
    let derive_first_continuity_policy = derive_first_continuity.compile_with_policy().len();
    let derive_curve_policy = derive_curve.compile_with_policy().len();
    let derive_chained_continuity_policy = derive_chained_continuity.compile_with_policy().len();
    let first_continuity_fragment_policy = first_continuity_fragment.compile_with_policy().len();
    let curve_fragment_policy = curve_fragment.compile_with_policy().len();
    let chained_continuity_fragment_policy =
        chained_continuity_fragment.compile_with_policy().len();

    println!("model=ed25519_slope_quotient_derivation");
    println!("relation_radix=32");
    println!("modulus=2^255-19");
    println!("negative_19_inverse_mod_2pow22_and_2pow23={NEGATIVE_NINETEEN_INVERSE}");
    println!("low_coefficients_read=5");
    println!("incremental_hint_items=0");
    println!("logical_quotient_items_eliminated_per_relation=1");
    println!("derive_first_continuity_raw_bytes={derive_first_continuity_raw}");
    println!("derive_first_continuity_policy_bytes={derive_first_continuity_policy}");
    println!("derive_curve_raw_bytes={derive_curve_raw}");
    println!("derive_curve_policy_bytes={derive_curve_policy}");
    println!("derive_chained_continuity_raw_bytes={derive_chained_continuity_raw}");
    println!("derive_chained_continuity_policy_bytes={derive_chained_continuity_policy}");
    println!("derive_and_verify_first_continuity_raw_bytes={first_continuity_fragment_raw}");
    println!("derive_and_verify_first_continuity_policy_bytes={first_continuity_fragment_policy}");
    println!("derive_and_verify_curve_raw_bytes={curve_fragment_raw}");
    println!("derive_and_verify_curve_policy_bytes={curve_fragment_policy}");
    println!("derive_and_verify_chained_continuity_raw_bytes={chained_continuity_fragment_raw}");
    println!(
        "derive_and_verify_chained_continuity_policy_bytes={chained_continuity_fragment_policy}"
    );
    println!("ordinary_relation_close_raw_bytes={ordinary_close_raw}");
    println!(
        "ordinary_relation_close_policy_bytes={}",
        ordinary_close.compile_with_policy().len()
    );
    println!("top_quotient_relation_close_raw_bytes={top_quotient_close_raw}");
    println!(
        "top_quotient_relation_close_policy_bytes={}",
        top_quotient_close.compile_with_policy().len()
    );
    println!("quotient_absorb_raw_bytes={absorb_raw}");
    println!(
        "quotient_absorb_policy_bytes={}",
        absorb.compile_with_policy().len()
    );
    println!("absorbed_relation_close_raw_bytes={absorbed_close_raw}");
    println!(
        "absorbed_relation_close_policy_bytes={}",
        absorbed_close.compile_with_policy().len()
    );
    println!("first_response_pair_decoder_raw_bytes={first_response_decoder_raw}");
    println!(
        "first_response_pair_decoder_policy_bytes={}",
        first_response_decoder.compile_with_policy().len()
    );
    println!("padded_response_pair_decoder_raw_bytes={padded_response_decoder_raw}");
    println!(
        "padded_response_pair_decoder_policy_bytes={}",
        padded_response_decoder.compile_with_policy().len()
    );
    println!("regular_response_pair_decoder_raw_bytes={regular_response_decoder_raw}");
    println!(
        "regular_response_pair_decoder_policy_bytes={}",
        regular_response_decoder.compile_with_policy().len()
    );
    println!("challenge_carrier_decoder_raw_bytes={challenge_carrier_decoder_raw}");
    println!(
        "challenge_carrier_decoder_policy_bytes={}",
        challenge_carrier_decoder.compile_with_policy().len()
    );
    println!("strict_local_peak22={peak22}");
    println!("strict_local_peak23={peak23}");
    println!("curve_exact_bounds_tested=[{CURVE_MIN},{CURVE_MAX}]");
    println!("first_continuity_exact_bounds_tested=[-{FIRST_CONTINUITY_ABS_MAX},{FIRST_CONTINUITY_ABS_MAX}]");
    println!("chained_continuity_exact_bounds_tested=[-{CHAINED_CONTINUITY_ABS_MAX},{CHAINED_CONTINUITY_ABS_MAX}]");
    println!("carry_equivalent_low_coefficients_tested=true");
    println!("non_divisible_relation_rejected=true");
    println!("q_plus_modulus_alias_rejected=true");
    println!("whole_transition_or_leaf_executed=false");
}
