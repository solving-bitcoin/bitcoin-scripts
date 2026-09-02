//! Carry-optimized prime RNS for hinted 256-bit modular multiplication.
//!
//! Once a witness provides one exact relation carry per coordinate, dense
//! multiplication tables are unnecessary. This basis therefore uses modulus
//! 2 plus 41 target-aware primes below the four-byte Script-number square-root
//! limit. Their product is larger than `2^512`, while every exact coordinate
//! product remains at most `32_717^2 < 2^31`.
//!
//! This module's compact 42-prime verifier has an external global-binding
//! precondition. [`bound`] is the self-contained alternative: it derives every
//! coordinate from shared bounded limbs and closes RNS wraparound locally.

use std::{cmp::Reverse, collections::BinaryHeap, sync::OnceLock};

use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};

use crate::{
    arithmetic::{scriptint, u31::U31_LOOKUP_STACK_LIMIT},
    support::script::*,
};

pub mod bound;
pub mod composable;

/// Carry-optimized prime basis in stack-coordinate order.
pub const MODULI: [u32; 42] = [
    2, 53, 101, 233, 251, 467, 827, 1_019, 1_487, 1_759, 1_847, 1_867, 1_949, 1_987, 3_331, 3_851,
    3_919, 6_373, 7_057, 7_351, 7_411, 7_867, 8_111, 10_501, 13_441, 15_331, 15_649, 16_333,
    24_919, 25_033, 26_701, 27_541, 28_099, 28_607, 30_697, 30_707, 30_817, 30_851, 31_771, 31_963,
    32_707, 32_717,
];

/// Number of residues in one carry-optimized value.
pub const RESIDUE_COUNT: u32 = MODULI.len() as u32;

/// Coordinates used to bind the partial remainder-complement representation.
/// Their product is greater than `2^257`.
pub const COMPLEMENT_INDICES: [usize; 18] = [
    16, 17, 18, 23, 24, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
];

/// Number of complement residues supplied by the optimized witness.
pub const COMPLEMENT_RESIDUE_COUNT: u32 = COMPLEMENT_INDICES.len() as u32;

/// Measured peak for [`mul_mod_hinted`] with no unrelated live items.
pub const HINTED_MUL_STACK_ITEMS: u32 = 231;

fn checks_complement(index: usize) -> bool {
    COMPLEMENT_INDICES.binary_search(&index).is_ok()
}

fn center(residue: u32, modulus: u32) -> i32 {
    if residue > modulus / 2 {
        residue as i32 - modulus as i32
    } else {
        residue as i32
    }
}

/// Return the product of the carry-optimized prime basis.
pub fn modulus() -> BigUint {
    MODULI
        .iter()
        .fold(BigUint::one(), |product, modulus| product * modulus)
}

/// Return the canonical carry-basis encoding of an unsigned integer.
pub fn encode(value: &BigUint) -> [u32; MODULI.len()] {
    std::array::from_fn(|index| {
        (value % MODULI[index])
            .to_u32()
            .expect("a residue must fit u32")
    })
}

/// Push canonical residues, with the modulus-2 coordinate on top.
pub fn push_residues(residues: &[u32; MODULI.len()]) -> Script {
    script! {
        for residue in residues.iter().rev() {
            { *residue }
        }
    }
}

/// Push the canonical carry-basis encoding of `value`.
pub fn push_value(value: &BigUint) -> Script {
    push_residues(&encode(value))
}

fn drop_items(items: u32) -> Script {
    script! {
        for _ in 0..items / 2 {
            OP_2DROP
        }
        if items % 2 != 0 {
            OP_DROP
        }
    }
}

/// Drop one carry-basis value from the main stack.
pub fn drop_value() -> Script {
    drop_items(RESIDUE_COUNT)
}

/// Consume and equality-check the top two carry-basis values.
pub fn equalverify() -> Script {
    script! {
        for index in 0..RESIDUE_COUNT {
            { RESIDUE_COUNT - index } OP_ROLL
            OP_EQUALVERIFY
        }
    }
}

fn from_altstack() -> Script {
    script! {
        for _ in 0..RESIDUE_COUNT {
            OP_FROMALTSTACK
        }
    }
}

fn canonical_add_reduce(modulus: u32) -> Script {
    let compare_limit = script! {
        OP_DUP { modulus - 1 } OP_GREATERTHAN
        OP_IF
            { modulus } OP_SUB
        OP_ENDIF
    };
    let hold_modulus = script! {
        { modulus } OP_2DUP OP_GREATERTHANOREQUAL
        OP_IF
            OP_SUB
        OP_ELSE
            OP_DROP
        OP_ENDIF
    };
    if hold_modulus.clone().compile().len() < compare_limit.clone().compile().len() {
        hold_modulus
    } else {
        compare_limit
    }
}

fn exact_centered_multiplier_mul(modulus: u32) -> Script {
    let half = modulus / 2;
    let highest_power = 1u32 << (31 - half.leading_zeros());
    let powers = (0..32 - highest_power.leading_zeros())
        .rev()
        .map(|shift| 1u32 << shift)
        .collect::<Vec<_>>();

    script! {
        // Replace y by center(y); changing the exact product by a multiple of
        // p is absorbed by the relation carry.
        { modulus } OP_OVER OP_SUB
        OP_2DUP OP_GREATERTHAN OP_TOALTSTACK
        OP_MIN

        // Layout is `x | remaining_abs_y | accumulator`.
        0
        for (iteration, power) in powers.into_iter().enumerate() {
            if iteration != 0 {
                OP_DUP OP_ADD
            }

            if power == 1 {
                // Consume the final 0/1 remainder as the condition and
                // collapse directly to `x | exact_product`.
                OP_SWAP
                OP_IF
                    OP_OVER OP_ADD
                OP_ENDIF
                OP_NIP
            } else if iteration == 0 {
                // The zero accumulator makes the leading selected-bit branch
                // just `x | (y-power) | x`.
                OP_OVER { power - 1 } OP_GREATERTHAN
                OP_IF
                    OP_DROP { power } OP_SUB OP_OVER
                OP_ENDIF
            } else {
                OP_OVER
                { power - 1 } OP_GREATERTHAN
                OP_IF
                    OP_SWAP { power } OP_SUB OP_SWAP
                    2 OP_PICK OP_ADD
                OP_ENDIF
            }
        }
        OP_FROMALTSTACK
        OP_IF
            OP_NEGATE
        OP_ENDIF
    }
}

fn exact_naf_mul(coefficient: i32) -> Script {
    let negative = coefficient < 0;
    let mut remaining = coefficient.unsigned_abs();
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
            if negative {
                OP_NEGATE
            }
        }
    }
}

// Every generated accumulator coefficient stays in this interval. With the
// largest basis residue as input, the resulting Script number remains within
// the four-byte arithmetic domain; the test below locks that bound down.
const EXACT_CHAIN_BOUND: i32 = 1 << 16;

#[derive(Clone, Copy, Debug)]
enum ExactChainOp {
    Double,
    DoublePlusInput,
    DoubleMinusInput,
    AddInput,
    SubtractInput,
    Negate,
    InputMinus,
    Triple,
    TriplePlusInput,
    TripleMinusInput,
    Quintuple,
}

impl ExactChainOp {
    const ALL: [Self; 11] = [
        Self::Double,
        Self::DoublePlusInput,
        Self::DoubleMinusInput,
        Self::AddInput,
        Self::SubtractInput,
        Self::Negate,
        Self::InputMinus,
        Self::Triple,
        Self::TriplePlusInput,
        Self::TripleMinusInput,
        Self::Quintuple,
    ];

    fn next(self, coefficient: i32) -> i32 {
        match self {
            Self::Double => 2 * coefficient,
            Self::DoublePlusInput => 2 * coefficient + 1,
            Self::DoubleMinusInput => 2 * coefficient - 1,
            Self::AddInput => coefficient + 1,
            Self::SubtractInput => coefficient - 1,
            Self::Negate => -coefficient,
            Self::InputMinus => 1 - coefficient,
            Self::Triple => 3 * coefficient,
            Self::TriplePlusInput => 3 * coefficient + 1,
            Self::TripleMinusInput => 3 * coefficient - 1,
            Self::Quintuple => 5 * coefficient,
        }
    }

    fn byte_len(self) -> usize {
        match self {
            Self::Negate => 1,
            Self::Double | Self::AddInput | Self::SubtractInput => 2,
            Self::DoublePlusInput | Self::DoubleMinusInput | Self::InputMinus => 3,
            Self::Triple => 4,
            Self::TriplePlusInput | Self::TripleMinusInput => 5,
            Self::Quintuple => 6,
        }
    }

    fn script(self) -> Script {
        match self {
            Self::Double => script! { OP_DUP OP_ADD },
            // `x | kx -> x | (2k+1)x` and `x | (2k-1)x` in three bytes.
            Self::DoublePlusInput => script! { OP_2DUP OP_ADD OP_ADD },
            Self::DoubleMinusInput => script! { OP_2DUP OP_SUB OP_SUB },
            Self::AddInput => script! { OP_OVER OP_ADD },
            Self::SubtractInput => script! { OP_OVER OP_SUB },
            Self::Negate => script! { OP_NEGATE },
            Self::InputMinus => script! { OP_OVER OP_SWAP OP_SUB },
            Self::Triple => script! { OP_DUP OP_DUP OP_ADD OP_ADD },
            Self::TriplePlusInput => script! {
                OP_2DUP OP_ADD OP_OVER OP_ADD OP_ADD
            },
            Self::TripleMinusInput => script! {
                OP_2DUP OP_SUB OP_OVER OP_SUB OP_SUB
            },
            Self::Quintuple => script! {
                OP_DUP OP_DUP OP_ADD OP_DUP OP_ADD OP_ADD
            },
        }
    }
}

fn exact_chain_index(coefficient: i32) -> usize {
    (coefficient + EXACT_CHAIN_BOUND) as usize
}

fn exact_chain_predecessors() -> &'static [Option<(i32, ExactChainOp)>] {
    // Script generation reuses one byte-optimal path tree rooted at x. Edge
    // weights are the exact serialized opcode lengths of their transitions.
    static PREDECESSORS: OnceLock<Vec<Option<(i32, ExactChainOp)>>> = OnceLock::new();
    PREDECESSORS.get_or_init(|| {
        let state_count = (2 * EXACT_CHAIN_BOUND + 1) as usize;
        let mut distances = vec![usize::MAX; state_count];
        let mut predecessors = vec![None; state_count];
        let mut frontier = BinaryHeap::new();
        distances[exact_chain_index(1)] = 0;
        frontier.push((Reverse(0usize), 1i32));

        while let Some((Reverse(distance), coefficient)) = frontier.pop() {
            if distance != distances[exact_chain_index(coefficient)] {
                continue;
            }
            for operation in ExactChainOp::ALL {
                let next = operation.next(coefficient);
                if !(-EXACT_CHAIN_BOUND..=EXACT_CHAIN_BOUND).contains(&next) {
                    continue;
                }
                let next_distance = distance + operation.byte_len();
                let next_index = exact_chain_index(next);
                if next_distance < distances[next_index] {
                    distances[next_index] = next_distance;
                    predecessors[next_index] = Some((coefficient, operation));
                    frontier.push((Reverse(next_distance), next));
                }
            }
        }
        predecessors
    })
}

fn exact_chain_mul(coefficient: i32) -> Script {
    assert!(
        (-EXACT_CHAIN_BOUND..=EXACT_CHAIN_BOUND).contains(&coefficient),
        "exact multiplication coefficient exceeds the chain table"
    );
    if coefficient == 0 {
        return script! { OP_DROP 0 };
    }
    if coefficient == 1 {
        return script! {};
    }
    if coefficient == -1 {
        return script! { OP_NEGATE };
    }

    let predecessors = exact_chain_predecessors();
    let mut coefficient = coefficient;
    let mut operations = Vec::new();
    while coefficient != 1 {
        let (previous, operation) = predecessors[exact_chain_index(coefficient)]
            .expect("every exact multiplication coefficient must be reachable");
        operations.push(operation);
        coefficient = previous;
    }
    operations.reverse();

    script! {
        OP_DUP
        for operation in operations {
            { operation.script() }
        }
        OP_NIP
    }
}

fn exact_constant_mul(coefficient: i32) -> Script {
    let binary = script! {
        { scriptint::mul_by_constant(coefficient.unsigned_abs()) }
        if coefficient < 0 {
            OP_NEGATE
        }
    };
    let naf = exact_naf_mul(coefficient);
    let chain = exact_chain_mul(coefficient);
    [binary, naf, chain]
        .into_iter()
        .min_by_key(|candidate| candidate.clone().compile().len())
        .expect("constant multiplication has candidates")
}

/// Derive the exact signed carries consumed by [`mul_mod_hinted`].
pub fn relation_carries(
    lhs: &BigUint,
    rhs: &BigUint,
    quotient: &BigUint,
    remainder: &BigUint,
    target_modulus: &BigUint,
) -> [i32; MODULI.len()] {
    assert!(!target_modulus.is_zero(), "target modulus must be positive");
    assert!(
        target_modulus.bits() <= 256,
        "target modulus must fit in 256 bits"
    );
    assert!(lhs < target_modulus, "lhs must be below target modulus");
    assert!(rhs < target_modulus, "rhs must be below target modulus");
    assert!(quotient.bits() <= 256, "quotient must fit in 256 bits");
    assert!(
        remainder < target_modulus,
        "remainder must be below target modulus"
    );
    assert_eq!(
        lhs * rhs,
        quotient * target_modulus + remainder,
        "quotient and remainder must satisfy the integer product equation"
    );

    let lhs = encode(lhs);
    let rhs = encode(rhs);
    let quotient = encode(quotient);
    let remainder = encode(remainder);
    let target = encode(target_modulus);

    std::array::from_fn(|index| {
        let modulus = i64::from(MODULI[index]);
        let rhs = i64::from(center(rhs[index], MODULI[index]));
        let target = i64::from(center(target[index], MODULI[index]));
        let numerator = i64::from(lhs[index]) * rhs
            - i64::from(quotient[index]) * target
            - i64::from(remainder[index]);
        assert_eq!(
            numerator % modulus,
            0,
            "hinted multiplication values must satisfy every RNS congruence"
        );
        i32::try_from(numerator / modulus).expect("an RNS relation carry must fit i32")
    })
}

/// Push a complete coordinate-interleaved carry-hinted witness.
///
/// Groups are pushed in reverse [`MODULI`] order. Every group contains
/// `lhs_i | rhs_i | quotient_i | remainder_i`, followed by `complement_i` only
/// for [`COMPLEMENT_INDICES`], then `carry_i`. The modulus-2 carry is on top.
pub fn push_hinted_witness(
    lhs: &BigUint,
    rhs: &BigUint,
    quotient: &BigUint,
    remainder: &BigUint,
    remainder_complement: &BigUint,
    carries: &[i32; MODULI.len()],
) -> Script {
    let lhs = encode(lhs);
    let rhs = encode(rhs);
    let quotient = encode(quotient);
    let remainder = encode(remainder);
    let complement = encode(remainder_complement);

    push_hinted_residues(&lhs, &rhs, &quotient, &remainder, &complement, carries)
}

/// Push already encoded coordinate-interleaved inputs for [`mul_mod_hinted`].
pub fn push_hinted_residues(
    lhs: &[u32; MODULI.len()],
    rhs: &[u32; MODULI.len()],
    quotient: &[u32; MODULI.len()],
    remainder: &[u32; MODULI.len()],
    remainder_complement: &[u32; MODULI.len()],
    carries: &[i32; MODULI.len()],
) -> Script {
    script! {
        for index in (0..MODULI.len()).rev() {
            { lhs[index] }
            { rhs[index] }
            { quotient[index] }
            { remainder[index] }
            if checks_complement(index) {
                { remainder_complement[index] }
            }
            { carries[index] }
        }
    }
}

fn calculated_peak(preserved_items: u32) -> u64 {
    u64::from(preserved_items)
        + 5 * u64::from(RESIDUE_COUNT)
        + u64::from(COMPLEMENT_RESIDUE_COUNT)
        + 3
}

/// Verify a carry-hinted modular multiplication and return its remainder.
///
/// The input uses the coordinate-interleaved layout produced by
/// [`push_hinted_witness`]. The fragment validates quotient, remainder, and
/// complement coordinates; proves `remainder + complement = target - 1` over
/// the 258-bit complement subbasis; and verifies one exact signed carry
/// equation per product-basis prime. Operand-coordinate checks, terminal
/// predicates, and global integer bindings are excluded.
///
/// Soundness requires every coordinate group for `lhs`, `rhs`, `quotient`,
/// `remainder`, and the partial complement to be externally bound to the
/// canonical residue encoding of one unsigned integer below `2^256`, with
/// `lhs,rhs < target_modulus`. A range claim that is not tied to the supplied
/// coordinates is insufficient. Under those bindings, the 513-bit basis turns
/// all checked congruences into the required exact integer equality.
pub fn mul_mod_hinted(target_modulus: &BigUint, preserved_items: u32) -> Script {
    assert!(!target_modulus.is_zero(), "target modulus must be positive");
    assert!(
        target_modulus.bits() <= 256,
        "target modulus must fit in 256 bits"
    );
    assert!(
        calculated_peak(preserved_items) <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "carry-optimized prime RNS multiplication exceeds Bitcoin Script's stack limit"
    );

    let target = encode(target_modulus);
    let centered_target: [i32; MODULI.len()] =
        std::array::from_fn(|index| center(target[index], MODULI[index]));
    let complement_sum = target_modulus - BigUint::one();
    let complement_sum = encode(&complement_sum);
    let coordinates = MODULI
        .iter()
        .copied()
        .enumerate()
        .map(|(index, modulus)| {
            let target = centered_target[index];
            let validate = script! {
                OP_DUP 0 { modulus } OP_WITHIN OP_VERIFY
            };
            let validate_remainder_bound = if checks_complement(index) {
                script! {
                    { validate.clone() }
                    // Check r_i beneath c_i, then retain r_i on the main
                    // stack while consuming c_i in their complement sum.
                    OP_OVER 0 { modulus } OP_WITHIN OP_VERIFY
                    OP_OVER OP_ADD
                    { canonical_add_reduce(modulus) }
                    { complement_sum[index] } OP_EQUALVERIFY
                }
            } else {
                validate.clone()
            };
            let multiply = if modulus == 2 {
                script! { OP_BOOLAND }
            } else {
                exact_centered_multiplier_mul(modulus)
            };

            script! {
                // Packed group suffix is q_i | r_i | [c_i] | carry_i.
                OP_TOALTSTACK
                { validate_remainder_bound }

                // Keep r_i on the main stack as the eventual output. Park q_i
                // above the carry while multiplying the two operands.
                OP_SWAP
                { validate }
                OP_TOALTSTACK
                OP_ROT OP_ROT
                { multiply }

                OP_FROMALTSTACK
                { exact_constant_mul(target) }
                OP_SUB
                OP_OVER OP_SUB
                OP_FROMALTSTACK
                { exact_constant_mul(modulus as i32) }
                OP_EQUALVERIFY

                // Stream the retained canonical remainder to the altstack so
                // the next packed coordinate remains accessible.
                OP_TOALTSTACK
            }
        })
        .collect::<Vec<_>>();

    script! {
        for coordinate in coordinates {
            { coordinate }
        }
        { from_altstack() }
    }
}

/// Return the exact byte attribution for [`mul_mod_hinted`].
///
/// This profile is table-free, so every generated byte is attributed to
/// computation, validation, routing, or output handling.
pub fn mul_mod_hinted_cost_breakdown(target_modulus: &BigUint) -> super::ScriptCostBreakdown {
    super::ScriptCostBreakdown {
        table_push: 0,
        table_drop: 0,
        computation: mul_mod_hinted(target_modulus, 0).compile().len(),
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::{BigUint, RandBigInt};
    use num_traits::{One, Zero};
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    fn is_prime(value: u32) -> bool {
        value >= 2 && (2..=((value as f64).sqrt() as u32)).all(|d| value % d != 0)
    }

    fn secp256k1_modulus() -> BigUint {
        BigUint::parse_bytes(
            b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            16,
        )
        .unwrap()
    }

    #[test]
    fn exact_chain_operations_match_their_affine_transitions() {
        for operation in ExactChainOp::ALL {
            assert_eq!(operation.script().compile().len(), operation.byte_len());
            for coefficient in [-257, -1, 0, 1, 257] {
                let input = 1_234i64;
                let next = operation.next(coefficient);
                let result = crate::support::execution::execute_script(script! {
                    { input }
                    { input * i64::from(coefficient) }
                    { operation.script() }
                    { input * i64::from(next) } OP_EQUALVERIFY
                    { input } OP_EQUAL
                });
                assert!(
                    result.success,
                    "operation {operation:?} at coefficient {coefficient}: {result}"
                );
            }
        }
    }

    #[test]
    fn exact_chain_table_covers_every_coordinate_coefficient_safely() {
        let predecessors = exact_chain_predecessors();
        let largest_modulus = *MODULI.last().unwrap() as i32;
        assert!(
            i64::from(EXACT_CHAIN_BOUND) * i64::from(largest_modulus - 1)
                <= i64::from(scriptint::MAX_SCRIPTNUM)
        );

        for target in -largest_modulus..=largest_modulus {
            if (-1..=1).contains(&target) {
                continue;
            }
            let mut coefficient = target;
            let mut operation_count = 0usize;
            while coefficient != 1 {
                let (previous, operation) = predecessors[exact_chain_index(coefficient)]
                    .expect("coordinate coefficient must be reachable");
                assert_eq!(operation.next(previous), coefficient);
                coefficient = previous;
                operation_count += 1;
                assert!(operation_count < 100, "chain for {target} contains a cycle");
            }
        }
    }

    #[test]
    fn exact_centered_multiplier_scan_matches_reference() {
        for modulus in MODULI.into_iter().skip(1) {
            let multipliers = if modulus <= 251 {
                (0..modulus).collect::<Vec<_>>()
            } else {
                vec![
                    0,
                    1,
                    2,
                    modulus / 2,
                    modulus / 2 + 1,
                    modulus - 2,
                    modulus - 1,
                ]
            };
            let multiplicands = [0, 1, modulus / 2, modulus - 1];
            let operation = exact_centered_multiplier_mul(modulus);
            for multiplier in multipliers {
                for multiplicand in multiplicands {
                    let expected = i64::from(multiplicand) * i64::from(center(multiplier, modulus));
                    let result = crate::support::execution::execute_script(script! {
                        { multiplicand }
                        { multiplier }
                        { operation.clone() }
                        { expected }
                        OP_EQUAL
                    });
                    assert!(
                        result.success,
                        "{multiplicand} * center({multiplier}) mod coordinate {modulus}: {result}"
                    );
                }
            }
        }
    }

    fn execute_product(
        lhs: &BigUint,
        rhs: &BigUint,
        target: &BigUint,
        operation: Script,
    ) -> crate::support::execution::ExecuteInfo {
        let product = lhs * rhs;
        let quotient = &product / target;
        let remainder = &product % target;
        let complement = target - BigUint::one() - &remainder;
        let carries = relation_carries(lhs, rhs, &quotient, &remainder, target);

        crate::support::execution::execute_script(script! {
            { push_hinted_witness(lhs, rhs, &quotient, &remainder, &complement, &carries) }
            { operation }
            { push_value(&remainder) }
            { equalverify() }
            OP_TRUE
        })
    }

    #[test]
    fn basis_has_exact_unsigned_256_bit_product_capacity() {
        assert_eq!(MODULI.len(), 42);
        assert!(MODULI.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(MODULI.iter().all(|modulus| is_prime(*modulus)));

        let max = (BigUint::one() << 256usize) - BigUint::one();
        assert!(modulus() > &max * &max);
        assert_eq!(modulus().bits(), 513);
        assert!(MODULI
            .iter()
            .all(|modulus| u64::from(*modulus) * u64::from(*modulus) <= 0x7fff_ffff));

        let complement_modulus = COMPLEMENT_INDICES
            .iter()
            .fold(BigUint::one(), |product, index| product * MODULI[*index]);
        assert!(complement_modulus > (BigUint::one() << 257usize));
        assert_eq!(complement_modulus.bits(), 258);
    }

    #[test]
    fn hinted_modular_multiplication_is_correct() {
        let target = secp256k1_modulus();
        let operation = mul_mod_hinted(&target, 0);
        let mut rng = StdRng::seed_from_u64(0x4341_5252_595f_3334);
        let mut pairs = vec![
            (BigUint::zero(), BigUint::zero()),
            (BigUint::zero(), &target - BigUint::one()),
            (BigUint::one(), &target - BigUint::one()),
            (&target - BigUint::one(), &target - BigUint::one()),
        ];
        for _ in 0..6 {
            pairs.push((
                rng.gen_biguint_below(&target),
                rng.gen_biguint_below(&target),
            ));
        }

        for (lhs, rhs) in pairs {
            let result = execute_product(&lhs, &rhs, &target, operation.clone());
            assert!(result.success, "{lhs} * {rhs} mod target: {result}");
        }
    }

    #[test]
    fn supports_boundary_target_moduli() {
        let targets = [
            BigUint::one(),
            BigUint::from(2u32),
            BigUint::from(MODULI[5]),
            BigUint::one() << 255usize,
            (BigUint::one() << 256usize) - BigUint::one(),
        ];

        for target in targets {
            let lhs = if target > BigUint::one() {
                &target - BigUint::one()
            } else {
                BigUint::zero()
            };
            let result = execute_product(&lhs, &lhs, &target, mul_mod_hinted(&target, 0));
            assert!(result.success, "target {target}: {result}");
        }
    }

    #[test]
    fn rejects_adversarial_hints_and_malformed_coordinates() {
        let target = secp256k1_modulus();
        let lhs = BigUint::from(123_456_789u64);
        let rhs = (&target >> 1usize) + BigUint::from(17u32);
        let product = &lhs * &rhs;
        let quotient = &product / &target;
        let remainder = &product % &target;
        let complement = &target - BigUint::one() - &remainder;
        let carries = relation_carries(&lhs, &rhs, &quotient, &remainder, &target);
        let operation = mul_mod_hinted(&target, 0);

        let bad_quotient = &quotient + BigUint::one();
        let result = crate::support::execution::execute_script(script! {
            { push_hinted_witness(&lhs, &rhs, &bad_quotient, &remainder, &complement, &carries) }
            { operation.clone() }
            OP_TRUE
        });
        assert!(!result.success);

        let bad_remainder = &remainder + BigUint::one();
        let bad_complement = &complement - BigUint::one();
        let result = crate::support::execution::execute_script(script! {
            { push_hinted_witness(
                &lhs,
                &rhs,
                &quotient,
                &bad_remainder,
                &bad_complement,
                &carries,
            ) }
            { operation.clone() }
            OP_TRUE
        });
        assert!(!result.success);

        for (index, offset) in [(0, 1), (MODULI.len() / 2, -1), (MODULI.len() - 1, 1)] {
            let mut bad_carries = carries;
            bad_carries[index] += offset;
            let result = crate::support::execution::execute_script(script! {
                { push_hinted_witness(
                    &lhs,
                    &rhs,
                    &quotient,
                    &remainder,
                    &complement,
                    &bad_carries,
                ) }
                { operation.clone() }
                OP_TRUE
            });
            assert!(!result.success, "carry {index} offset {offset} accepted");
        }

        let lhs_residues = encode(&lhs);
        let rhs_residues = encode(&rhs);
        let mut quotient_residues = encode(&quotient);
        let remainder_residues = encode(&remainder);
        let complement_residues = encode(&complement);
        quotient_residues[MODULI.len() - 1] = MODULI[MODULI.len() - 1];
        let result = crate::support::execution::execute_script(script! {
            { push_hinted_residues(
                &lhs_residues,
                &rhs_residues,
                &quotient_residues,
                &remainder_residues,
                &complement_residues,
                &carries,
            ) }
            { operation }
            OP_TRUE
        });
        assert!(!result.success);
    }

    #[test]
    fn preserves_unrelated_items_and_matches_stack_guard() {
        let target = secp256k1_modulus();
        let lhs = &target - BigUint::one();
        let rhs = lhs.clone();
        let product = &lhs * &rhs;
        let quotient = &product / &target;
        let remainder = &product % &target;
        let complement = &target - BigUint::one() - &remainder;
        let carries = relation_carries(&lhs, &rhs, &quotient, &remainder, &target);

        assert_eq!(calculated_peak(0), u64::from(HINTED_MUL_STACK_ITEMS));
        let result = crate::support::execution::execute_script(script! {
            { push_hinted_witness(
                &lhs,
                &rhs,
                &quotient,
                &remainder,
                &complement,
                &carries,
            ) }
            { mul_mod_hinted(&target, 0) }
            { drop_value() }
            OP_TRUE
        });
        assert!(result.success, "strict peak execution failed: {result}");
        assert_eq!(
            result.stats.max_nb_stack_items,
            HINTED_MUL_STACK_ITEMS as usize
        );

        let result = crate::support::execution::execute_script(script! {
            101 OP_TOALTSTACK
            102
            { push_hinted_witness(
                &lhs,
                &rhs,
                &quotient,
                &remainder,
                &complement,
                &carries,
            ) }
            { mul_mod_hinted(&target, 2) }
            { push_value(&remainder) }
            { equalverify() }
            102 OP_EQUALVERIFY
            OP_FROMALTSTACK 101 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "preserved-state execution failed: {result}");

        let preserved = U31_LOOKUP_STACK_LIMIT - HINTED_MUL_STACK_ITEMS;
        let result = crate::support::execution::execute_script(script! {
            for _ in 0..preserved {
                0
            }
            { push_hinted_witness(
                &lhs,
                &rhs,
                &quotient,
                &remainder,
                &complement,
                &carries,
            ) }
            { mul_mod_hinted(&target, preserved) }
            { drop_value() }
            { drop_items(preserved) }
            OP_TRUE
        });
        assert!(result.success, "1,000-item execution failed: {result}");
        assert_eq!(result.stats.max_nb_stack_items, 1_000);
    }

    #[test]
    fn cost_breakdown_is_table_free() {
        let cost = mul_mod_hinted_cost_breakdown(&secp256k1_modulus());
        assert_eq!(cost.table_push, 0);
        assert_eq!(cost.table_drop, 0);
        assert_eq!(cost.computation, 10_952);
        assert_eq!(cost.total(), 10_952);
    }

    #[test]
    #[should_panic(
        expected = "carry-optimized prime RNS multiplication exceeds Bitcoin Script's stack limit"
    )]
    fn rejects_excess_preserved_depth() {
        let target = secp256k1_modulus();
        let _ = mul_mod_hinted(&target, U31_LOOKUP_STACK_LIMIT - HINTED_MUL_STACK_ITEMS + 1);
    }

    #[test]
    #[should_panic(expected = "target modulus must be positive")]
    fn rejects_zero_target() {
        let _ = mul_mod_hinted(&BigUint::zero(), 0);
    }

    #[test]
    #[should_panic(expected = "target modulus must fit in 256 bits")]
    fn rejects_oversized_target() {
        let _ = mul_mod_hinted(&(BigUint::one() << 256usize), 0);
    }
}
