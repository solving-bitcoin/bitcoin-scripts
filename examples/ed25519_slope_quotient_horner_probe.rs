//! Bounded no-hint quotient experiment: reduce during low-coefficient Horner
//! composition rather than materializing and then normalizing five residues.
//! Every input coefficient is certified by the enclosing accumulator's bound.
//! The complete local input is 51 coefficient data items; auxiliary hints: 0.
//! Pool cases additionally model 4 or 16 authenticated Script-authored powers
//! at the fragment boundary (55 or 67 total local items), counted in peaks.
//! The probe runs strict local fragments only, never a full scalar or leaf.

use bitcoin_lab::{
    arithmetic::scriptint,
    curves::ed25519::{
        derive_streamed_relation_quotient,
        montgomery_slope::{
            CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX, FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
            SYMMETRIC_CURVE_LOW_COEFFICIENT_ABS_MAX,
        },
        verify_streamed_relation_top_quotient,
    },
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
    },
};

fn item(value: i64) -> Vec<u8> {
    let mut buffer = [0; 8];
    let length = bitcoin::script::write_scriptint(&mut buffer, value);
    buffer[..length].to_vec()
}

fn power(bit: usize, above: usize, pool: &[usize]) -> Script {
    if let Some(index) = pool.iter().position(|candidate| *candidate == bit) {
        script! { { (above + pool.len() - 1 - index) as u32 } OP_PICK }
    } else {
        script! { { 1u32 << bit } }
    }
}

fn subtract_power(bit: usize, above: usize, pool: &[usize]) -> Script {
    script! {
        { power(bit, above, pool) } OP_2DUP OP_GREATERTHANOREQUAL
        OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
    }
}

fn signed_remainder_legacy(width: usize, bound: i64, pool: &[usize]) -> Script {
    assert!(bound > 0 && bound <= i64::from(i32::MAX));
    let bits = i64::BITS as usize - bound.leading_zeros() as usize;
    script! {
        OP_DUP 0 OP_LESSTHAN OP_DUP OP_TOALTSTACK
        OP_IF OP_NEGATE OP_ENDIF
        for bit in (width..bits).rev() { { subtract_power(bit, 1, pool) } }
        OP_FROMALTSTACK OP_IF OP_NEGATE OP_ENDIF
    }
}

fn signed_remainder(width: usize, bound: i64, pool: &[usize]) -> Script {
    assert!(bound > 0 && bound <= i64::from(i32::MAX));
    let bits = i64::BITS as usize - bound.leading_zeros() as usize;
    script! {
        OP_DUP OP_ABS
        for bit in (width..bits).rev() { { subtract_power(bit, 2, pool) } }
        OP_SWAP 0 OP_LESSTHAN OP_IF OP_NEGATE OP_ENDIF
    }
}

fn reduce_factor(width: usize, factor: u32, above: usize, pool: &[usize]) -> Script {
    let bits = (u32::BITS - (factor - 1).leading_zeros()) as usize;
    script! {
        for bit in (width..width + bits).rev() { { subtract_power(bit, above, pool) } }
    }
}

fn inverse(width: usize, pool: &[usize]) -> Script {
    script! {
        OP_DUP
        { scriptint::mul_by_constant(233) }
        { reduce_factor(width, 233, 2, pool) }
        { scriptint::mul_by_constant(196) }
        1 OP_PICK { scriptint::mul_by_constant(5) } OP_ADD
        { reduce_factor(width, 201, 2, pool) }
        OP_NIP { scriptint::mul_by_constant(29) }
        { reduce_factor(width, 29, 1, pool) }
    }
}

/// `h[50..0] | pool -> h[50..0] | pool | q`.
/// At stage i, t = h_i + 32*r_(i+1), with |r_(i+1)| < 2^(w-5(i+1)).
/// Therefore |t| <= bound_i + 32*(2^(w-5(i+1))-1). The explicit assertions
/// certify every input to the reducer fits a four-byte ScriptNum.
fn fused_derive(width: usize, bounds: [i64; 5], pool: &[usize]) -> Script {
    let stage_bounds = core::array::from_fn::<_, 5, _>(|i| {
        bounds[i]
            + if i == 4 {
                0
            } else {
                32 * ((1i64 << (width - 5 * (i + 1))) - 1)
            }
    });
    assert!(stage_bounds
        .iter()
        .all(|bound| *bound <= i64::from(i32::MAX)));
    script! {
        { (4 + pool.len()) as u32 } OP_PICK
        { signed_remainder(width - 20, stage_bounds[4], pool) }
        for i in (0..4).rev() {
            for _ in 0..5 { OP_DUP OP_ADD }
            { (i + pool.len() + 1) as u32 } OP_PICK OP_ADD
            { signed_remainder(width - 5 * i, stage_bounds[i], pool) }
        }
        OP_DUP 0 OP_LESSTHAN
        OP_IF { power(width, 1, pool) } OP_ADD OP_ENDIF
        { inverse(width, pool) }
        OP_DUP { power(width - 1, 2, pool) } OP_GREATERTHANOREQUAL
        OP_IF { power(width, 1, pool) } OP_SUB OP_ENDIF
    }
}

fn independent_derive(width: usize, bounds: [i64; 5], pool: &[usize]) -> Script {
    script! {
        for i in 0..5 {
            { (i + pool.len()) as u32 } OP_PICK
            { signed_remainder_legacy(width - 5 * i, bounds[i], pool) }
            OP_TOALTSTACK
        }
        OP_FROMALTSTACK
        for _ in 0..4 {
            for _ in 0..5 { OP_DUP OP_ADD }
            OP_FROMALTSTACK OP_ADD
        }
        OP_DUP 0 OP_LESSTHAN OP_DUP OP_TOALTSTACK
        OP_IF OP_NEGATE OP_ENDIF
        for bit in (width..=width + 2).rev() { { subtract_power(bit, 1, pool) } }
        OP_FROMALTSTACK OP_IF
            OP_DUP OP_NOT OP_NOT OP_IF
                { power(width, 1, pool) } OP_SWAP OP_SUB
            OP_ENDIF
        OP_ENDIF
        { inverse(width, pool) }
        OP_DUP { power(width - 1, 2, pool) } OP_GREATERTHANOREQUAL
        OP_IF { power(width, 1, pool) } OP_SUB OP_ENDIF
    }
}

fn raw_len(fragment: Script) -> usize {
    let copies = MAX_OPTIMIZER_INPUT_BYTES.div_ceil(fragment.len()) + 1;
    let bytes = script! { for _ in 0..copies { { fragment.clone() } } }.compile_with_policy();
    assert!(bytes.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(bytes.len() % copies, 0);
    bytes.len() / copies
}

fn close_with_pool(pool_count: usize, negative_carry: bool) -> Script {
    script! {
        if negative_carry { OP_NEGATE }
        OP_DUP
        for coefficient in (1..51).rev() {
            { (coefficient + 2 + pool_count) as u32 } OP_ROLL
            OP_SWAP { scriptint::mul_by_constant(32) }
            if negative_carry { OP_ADD } else { OP_SWAP OP_SUB }
        }
        OP_TOALTSTACK OP_DUP { scriptint::mul_by_constant(19) }
        { (pool_count + 2) as u32 } OP_ROLL
        if negative_carry { OP_SUB } else { OP_ADD }
        OP_FROMALTSTACK { scriptint::mul_by_constant(32) } OP_NUMEQUALVERIFY OP_DROP
    }
}

fn reference_q(coefficients: &[i64; 51], width: usize) -> i64 {
    let modulus = 1i64 << width;
    let residue = (0..5)
        .map(|i| coefficients[i].rem_euclid(modulus) * (1 << (5 * i)))
        .sum::<i64>()
        .rem_euclid(modulus);
    let q = (residue * 1_324_517).rem_euclid(modulus);
    if q >= modulus / 2 {
        q - modulus
    } else {
        q
    }
}

fn main() {
    if std::env::args().any(|arg| arg == "--first-pool-frontier") {
        let mut candidates = vec![vec![23, 24, 25, 26]];
        for length in 12..=16 {
            for end in 27..=30 {
                candidates.push((end + 1 - length..=end).collect());
            }
        }
        for powers in candidates {
            let count = powers.len();
            let pair = script! {
                { 1u32 << powers[0] }
                for pair in powers.windows(2) {
                    if pair[1] == pair[0] + 1 { OP_DUP OP_DUP OP_ADD }
                    else { { 1u32 << pair[1] } }
                }
                { fused_derive(23, SYMMETRIC_CURVE_LOW_COEFFICIENT_ABS_MAX, &powers) }
                { close_with_pool(count, true) }
                for _ in 0..count { OP_TOALTSTACK }
                for _ in 0..count { OP_FROMALTSTACK }
                { fused_derive(22, FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX, &powers) }
                { close_with_pool(count, true) }
                for _ in 0..count / 2 { OP_2DROP }
                if count % 2 == 1 { OP_DROP }
            };
            println!(
                "first_pool={powers:?} count={count} two_relation_raw_bytes={} hints=0",
                raw_len(pair)
            );
        }
        return;
    }
    let first_pool = [23, 24, 25, 26];
    let pool = [
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
    ];
    for (label, width, bounds) in [
        (
            "first_continuity",
            22,
            FIRST_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
        ),
        ("curve", 23, SYMMETRIC_CURVE_LOW_COEFFICIENT_ABS_MAX),
        (
            "chained_continuity",
            23,
            CHAINED_CONTINUITY_LOW_COEFFICIENT_ABS_MAX,
        ),
    ] {
        for powers in [&[][..], &first_pool[..], &pool[..]] {
            let candidate = fused_derive(width, bounds, powers);
            let baseline = independent_derive(width, bounds, powers);
            if powers.is_empty() {
                assert_eq!(
                    candidate.clone().compile_with_policy(),
                    derive_streamed_relation_quotient(width, &bounds).compile_with_policy()
                );
            }
            let candidate_bytes = candidate.clone().compile_with_policy();
            for i in 0..5 {
                // Confirm the central small-fragment optimizer does not
                // already perform this sign-carrier layout transformation.
                assert!(
                    signed_remainder(width - 5 * i, bounds[i], powers)
                        .compile_with_policy()
                        .len()
                        < signed_remainder_legacy(width - 5 * i, bounds[i], powers)
                            .compile_with_policy()
                            .len()
                );
            }
            let mut peak = 0;
            let baseline_bytes = baseline.clone().compile_with_policy();
            let mut baseline_peak = 0;
            let mut seed = 0xface_b00c_9876_5432u64;
            for sample in 0..48 {
                let mut coefficients = [0i64; 51];
                for i in 0..5 {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    coefficients[i] = match sample {
                        0 => 0,
                        1 => bounds[i],
                        2 => -bounds[i],
                        3 => {
                            if i % 2 == 0 {
                                bounds[i]
                            } else {
                                -bounds[i]
                            }
                        }
                        4 => {
                            if i % 2 != 0 {
                                bounds[i]
                            } else {
                                -bounds[i]
                            }
                        }
                        _ => (seed % (2 * bounds[i] as u64 + 1)) as i64 - bounds[i],
                    };
                }
                let mut witness = coefficients
                    .iter()
                    .rev()
                    .map(|value| item(*value))
                    .collect::<Vec<_>>();
                witness.extend(powers.iter().map(|bit| item(1 << bit)));
                let execution = execute_raw_script_with_inputs_strict(
                    candidate_bytes.to_bytes(),
                    witness.clone(),
                );
                assert!(
                    execution.error.is_none(),
                    "{label} sample{sample}: {execution}"
                );
                assert_eq!(execution.final_stack.len(), witness.len() + 1);
                for (i, value) in witness.iter().enumerate() {
                    assert_eq!(execution.final_stack.get(i), *value);
                }
                assert_eq!(
                    execution.final_stack.get(witness.len()),
                    item(reference_q(&coefficients, width))
                );
                peak = peak.max(execution.stats.max_nb_stack_items);
                let execution =
                    execute_raw_script_with_inputs_strict(baseline_bytes.to_bytes(), witness);
                assert!(execution.error.is_none());
                baseline_peak = baseline_peak.max(execution.stats.max_nb_stack_items);
            }
            let old_close = close_with_pool(powers.len(), false);
            let new_close = close_with_pool(powers.len(), true);
            let close_bytes =
                script! { { candidate.clone() } { new_close.clone() } }.compile_with_policy();
            let q_max = if width == 22 { 1_843_466i64 } else { 3_686_931 };
            for q in [-q_max, -17, 0, 17, q_max] {
                let mut h = [0; 51];
                h[0] = -19 * q;
                h[50] = 32 * q;
                for (i, carry) in [173, -239, 541, -877, 1234].into_iter().enumerate() {
                    h[i] += 32 * carry;
                    h[i + 1] -= carry;
                }
                let mut inputs = h.iter().rev().map(|value| item(*value)).collect::<Vec<_>>();
                inputs.extend(powers.iter().map(|bit| item(1 << bit)));
                let execution =
                    execute_raw_script_with_inputs_strict(close_bytes.to_bytes(), inputs.clone());
                assert!(execution.error.is_none(), "{label} q={q}: {execution}");
                assert_eq!(execution.final_stack.len(), powers.len());
                for (i, bit) in powers.iter().enumerate() {
                    assert_eq!(execution.final_stack.get(i), item(1 << bit));
                }
                inputs[45] = item(h[5] + 1);
                let execution =
                    execute_raw_script_with_inputs_strict(close_bytes.to_bytes(), inputs);
                assert!(execution.error.is_some());
            }
            for q_alias in [1i64 << width, -(1i64 << width)] {
                let mut h = [0; 51];
                h[0] = -19 * q_alias;
                h[50] = 32 * q_alias;
                let mut inputs = h.iter().rev().map(|value| item(*value)).collect::<Vec<_>>();
                inputs.extend(powers.iter().map(|bit| item(1 << bit)));
                let execution =
                    execute_raw_script_with_inputs_strict(close_bytes.to_bytes(), inputs);
                assert!(
                    execution.error.is_some(),
                    "out-of-width quotient alias accepted"
                );
            }
            println!("profile={label} pool_items={} baseline_raw={} fused_raw={} saving={} fused_policy={} baseline_strict_peak={baseline_peak} strict_peak={peak} close_raw_saving={} hints=0", powers.len(), raw_len(baseline.clone()), raw_len(candidate.clone()), raw_len(baseline)-raw_len(candidate), candidate_bytes.len(), raw_len(old_close)-raw_len(new_close));
        }
        let close = script! { { fused_derive(width, bounds, &[]) } { verify_streamed_relation_top_quotient() } OP_1 }.compile_with_policy();
        for q in [-1_843_466i64, -17, 0, 17, 1_843_466] {
            let mut h = [0; 51];
            h[0] = -19 * q;
            h[50] = 32 * q;
            for (i, carry) in [173, -239, 541, -877, 1234].into_iter().enumerate() {
                h[i] += 32 * carry;
                h[i + 1] -= carry;
            }
            let inputs = h.iter().rev().map(|value| item(*value)).collect();
            let execution = execute_raw_script_with_inputs_strict(close.to_bytes(), inputs);
            assert!(execution.error.is_none(), "{label} q={q}: {execution}");
            assert_eq!(execution.final_stack.len(), 1);
            h[5] += 1;
            let execution = execute_raw_script_with_inputs_strict(
                close.to_bytes(),
                h.iter().rev().map(|value| item(*value)).collect(),
            );
            assert!(execution.error.is_some());
        }
    }
    println!("evidence=locally-reproduced evidence_boundary=strict-local-fragments execution_class=unclassified complete_input_data_items=51 auxiliary_hint_items_per_relation=0 auxiliary_hint_items_94_relations=0");
}
