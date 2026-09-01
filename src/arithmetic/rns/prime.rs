//! Prime-only RNS arithmetic sized for exact 256-bit products.
//!
//! The basis contains `2` and every odd prime through `383` except `47`.
//! Its product is slightly larger than `2^512`, so every product of two
//! unsigned 256-bit integers has a unique (unwrapped) representation. Each
//! value occupies 75 stack items.
//!
//! Addition and subtraction keep canonical residues (`0..p-1`) and use one
//! conditional correction per odd coordinate. Multiplication streams one
//! coordinate table at a time. Tiny coordinates have specialized formulas;
//! small odd primes use full canonical log/exp tables; larger primes use a
//! signed projective magnitude-log table and only half an exponent table.
//! The latter exploits `g^(e + (p - 1) / 2) = -g^e`.
//!
//! [`mul_mod_hinted`] additionally verifies a quotient/remainder witness for a
//! fixed modulus, subject to its documented global 256-bit binding precondition.
//!
//! Arithmetic fragments do not range-check witness residues. Callers must
//! establish canonical (or centered) coordinate ranges before a residue is
//! used as an `OP_PICK` index. [`verify_canonical`] and [`verify_centered`]
//! provide reusable validation fragments.

use num_bigint::{BigInt, BigUint};
use num_traits::{One, ToPrimitive, Zero};

use crate::{arithmetic::u31::U31_LOOKUP_STACK_LIMIT, support::script::*};

/// Prime moduli in stack-coordinate order.
///
/// This is `2` followed by every odd prime through `383`, except `47`. The
/// missing prime is the byte-cost optimum found by the fixed-basis search for
/// the exact unsigned 256-by-256-bit product bound.
pub const MODULI: [u32; 75] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383,
];

/// Primitive roots aligned with [`MODULI`].
///
/// The modulus-2 entry is unused; the table-free modulus-3 strategy also does
/// not consult its conventional root. Projective-channel roots minimize
/// serialized signed-log plus half-exponent tables. Full canonical table size
/// is root-independent.
pub const GENERATORS: [u32; MODULI.len()] = [
    0, 2, 2, 3, 2, 2, 3, 3, 5, 2, 21, 5, 11, 20, 27, 43, 2, 41, 52, 5, 3, 42, 19, 14, 35, 11, 6,
    57, 66, 106, 31, 12, 73, 126, 89, 70, 12, 78, 154, 120, 41, 83, 22, 5, 120, 141, 75, 2, 29, 5,
    206, 56, 42, 54, 171, 42, 48, 143, 15, 18, 20, 270, 285, 276, 5, 250, 171, 139, 175, 228, 77,
    263, 5, 261, 37,
];

/// Affine biases for projective-log coordinates, aligned with [`MODULI`].
///
/// Biasing `L` to `(L+c) mod h` changes only generated table literals; the
/// multiplication query is unchanged. These values jointly minimize the
/// serialized signed-log and shifted half-exponent entries.
pub const LOG_BIASES: [u32; MODULI.len()] = [
    0, 0, 0, 0, 2, 0, 6, 0, 3, 3, 1, 2, 3, 4, 10, 14, 0, 0, 8, 0, 11, 14, 5, 1, 21, 20, 4, 20, 5,
    22, 6, 12, 55, 17, 16, 74, 17, 8, 33, 26, 36, 28, 51, 45, 16, 9, 64, 2, 22, 20, 26, 3, 9, 10,
    16, 46, 4, 69, 6, 14, 12, 27, 44, 84, 54, 68, 59, 81, 34, 20, 31, 163, 48, 38, 182,
];

/// Number of residues in one encoded value.
pub const RESIDUE_COUNT: u32 = MODULI.len() as u32;

/// Measured peak for [`mul`] with two operands and no unrelated live items.
pub const MUL_STACK_ITEMS: u32 = 462;

/// Measured peak for [`add`] or [`sub`] with two operands.
pub const ADD_SUB_STACK_ITEMS: u32 = 151;

/// Measured peak for [`mul_mod_hinted`] with no unrelated live items.
pub const HINTED_MUL_STACK_ITEMS: u32 = 612;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MulStrategy {
    Binary,
    Ternary,
    CanonicalFull,
    ProjectiveCanonical,
    ProjectiveCentered,
}

fn strategy(modulus: u32) -> MulStrategy {
    match modulus {
        2 => MulStrategy::Binary,
        3 => MulStrategy::Ternary,
        5..=19 => MulStrategy::CanonicalFull,
        23..=151 => MulStrategy::ProjectiveCanonical,
        _ => MulStrategy::ProjectiveCentered,
    }
}

fn pow_mod(base: u32, mut exponent: u32, modulus: u32) -> u32 {
    let mut result = 1u64;
    let modulus = u64::from(modulus);
    let mut base = u64::from(base);
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = result * base % modulus;
        }
        base = base * base % modulus;
        exponent >>= 1;
    }
    result as u32
}

fn discrete_logs(modulus: u32, generator: u32) -> Vec<u32> {
    let mut logs = vec![u32::MAX; modulus as usize];
    for exponent in 0..modulus - 1 {
        logs[pow_mod(generator, exponent, modulus) as usize] = exponent;
    }
    assert!(
        logs[1..].iter().all(|log| *log != u32::MAX),
        "prime RNS generator must be primitive"
    );
    logs
}

fn center(residue: u32, modulus: u32) -> i32 {
    let half = modulus / 2;
    if residue > half {
        residue as i32 - modulus as i32
    } else {
        residue as i32
    }
}

/// Return the product of all [`MODULI`].
pub fn modulus() -> BigUint {
    MODULI
        .iter()
        .fold(BigUint::one(), |product, modulus| product * modulus)
}

/// Return the canonical RNS encoding of an unsigned integer.
pub fn encode(value: &BigUint) -> [u32; MODULI.len()] {
    std::array::from_fn(|index| {
        (value % MODULI[index])
            .to_u32()
            .expect("a residue must fit u32")
    })
}

/// Return the canonical RNS encoding of a possibly negative integer.
pub fn encode_signed(value: &BigInt) -> [u32; MODULI.len()] {
    std::array::from_fn(|index| {
        let modulus = BigInt::from(MODULI[index]);
        let mut residue = (value % &modulus).to_i32().expect("a residue must fit i32");
        if residue < 0 {
            residue += MODULI[index] as i32;
        }
        residue as u32
    })
}

/// Return the centered RNS encoding of a possibly negative integer.
///
/// The binary coordinate remains canonical (`0` or `1`); every odd-prime
/// coordinate lies in `[-(p-1)/2, (p-1)/2]`.
pub fn encode_centered(value: &BigInt) -> [i32; MODULI.len()] {
    let canonical = encode_signed(value);
    std::array::from_fn(|index| {
        if MODULI[index] == 2 {
            canonical[index] as i32
        } else {
            center(canonical[index], MODULI[index])
        }
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

/// Push centered residues, with the modulus-2 coordinate on top.
pub fn push_centered_residues(residues: &[i32; MODULI.len()]) -> Script {
    script! {
        for residue in residues.iter().rev() {
            { *residue }
        }
    }
}

/// Push the canonical RNS encoding of `value`.
pub fn push_value(value: &BigUint) -> Script {
    push_residues(&encode(value))
}

/// Push the centered RNS encoding of `value`.
pub fn push_centered_value(value: &BigInt) -> Script {
    push_centered_residues(&encode_centered(value))
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

fn full_table_entries(index: usize) -> Vec<i32> {
    let modulus = MODULI[index];
    let generator = GENERATORS[index];
    let logs = discrete_logs(modulus, generator);
    let mut entries = Vec::with_capacity((2 * (modulus - 1)) as usize);
    for exponent in (0..modulus - 1).rev() {
        entries.push(pow_mod(generator, exponent, modulus) as i32);
    }
    for residue in (1..modulus).rev() {
        entries.push(logs[residue as usize] as i32);
    }
    entries
}

fn projective_table_entries(index: usize, centered_exponents: bool) -> Vec<i32> {
    let modulus = MODULI[index];
    let generator = GENERATORS[index];
    let half = (modulus - 1) / 2;
    let order = modulus - 1;
    let bias = LOG_BIASES[index];
    let logs = discrete_logs(modulus, generator);
    let mut entries = Vec::with_capacity((modulus - 1) as usize);

    for exponent in (0..half).rev() {
        let shifted_exponent = (exponent + order - (2 * bias) % order) % order;
        let residue = pow_mod(generator, shifted_exponent, modulus);
        entries.push(if centered_exponents {
            center(residue, modulus)
        } else {
            residue as i32
        });
    }

    // For positive magnitude m, e=log_g(m)=k+b*h. Affinely bias k and absorb
    // its wrap bit into b. Selected biases keep the unique zero token positive.
    for magnitude in (1..=half).rev() {
        let exponent = logs[magnitude as usize];
        let lower = exponent % half;
        let shifted = lower + bias;
        let shifted_lower = shifted % half;
        let shifted_upper = (exponent >= half) ^ (shifted >= half);
        assert!(
            shifted_lower != 0 || !shifted_upper,
            "projective log bias must not create negative zero"
        );
        entries.push(if shifted_upper {
            -(shifted_lower as i32)
        } else {
            shifted_lower as i32
        });
    }
    entries
}

fn push_table_entries(entries: &[i32]) -> Script {
    script! {
        for entry in entries {
            { *entry }
        }
    }
}

fn canonical_full_coordinate_mul(modulus: u32) -> Script {
    let order = modulus - 1;
    script! {
        OP_PICK
        // This is the final log lookup, so remove its table entry.
        OP_SWAP OP_ROLL
        OP_ADD
        OP_DUP { modulus - 2 } OP_GREATERTHAN
        OP_IF
            { order } OP_SUB
        OP_ENDIF
        // One log entry is gone; exponent zero is now at depth order-1.
        { order - 1 } OP_ADD OP_ROLL
    }
}

fn reduce_projective_sum(half: u32) -> Script {
    let held_half = script! {
        { half } OP_2DUP OP_GREATERTHANOREQUAL
        OP_IF
            OP_SUB
            OP_FROMALTSTACK OP_NOT OP_TOALTSTACK
        OP_ELSE
            OP_DROP
        OP_ENDIF
    };
    let threshold = script! {
        OP_DUP { half - 1 } OP_GREATERTHAN
        OP_IF
            { half } OP_SUB
            OP_FROMALTSTACK OP_NOT OP_TOALTSTACK
        OP_ENDIF
    };
    if threshold.clone().compile().len() < held_half.clone().compile().len() {
        threshold
    } else {
        held_half
    }
}

fn projective_coordinate_mul(modulus: u32, centered_exponents: bool) -> Script {
    let half = (modulus - 1) / 2;
    script! {
        // Produce min(x,p-x) while recording which canonical half x used.
        { modulus } OP_OVER OP_SUB
        OP_2DUP OP_GREATERTHAN OP_TOALTSTACK
        OP_MIN OP_PICK
        OP_SWAP
        { modulus } OP_OVER OP_SUB
        OP_2DUP OP_GREATERTHAN
        OP_FROMALTSTACK OP_NUMNOTEQUAL OP_TOALTSTACK
        // This is the final log lookup, so remove its table entry.
        OP_MIN OP_ROLL

        // Fold token signs into the input parity and add lower exponents.
        OP_2DUP
        0 OP_LESSTHAN
        OP_SWAP
        0 OP_LESSTHAN
        OP_NUMNOTEQUAL
        OP_FROMALTSTACK OP_NUMNOTEQUAL OP_TOALTSTACK
        OP_ABS OP_SWAP OP_ABS OP_ADD

        // Reduce modulo h and retain the carry as an omitted-half bit.
        { reduce_projective_sum(half) }

        // One log entry is gone, so exponent zero is at depth h-1. This is
        // also the final exponent lookup and can be destructive.
        { half - 1 } OP_ADD OP_ROLL
        OP_FROMALTSTACK

        if centered_exponents {
            OP_IF
                OP_NEGATE
            OP_ENDIF
            OP_DUP 0 OP_LESSTHAN
            OP_IF
                { modulus } OP_ADD
            OP_ENDIF
        } else {
            OP_IF
                { modulus } OP_SWAP OP_SUB
            OP_ENDIF
        }
    }
}

fn ternary_coordinate_mul() -> Script {
    script! {
        OP_2DUP OP_BOOLAND
        OP_IF
            OP_NUMNOTEQUAL OP_1ADD
        OP_ELSE
            OP_BOOLAND
        OP_ENDIF
    }
}

fn table_items(modulus: u32, strategy: MulStrategy) -> u32 {
    match strategy {
        MulStrategy::Binary | MulStrategy::Ternary => 0,
        MulStrategy::CanonicalFull => 2 * (modulus - 1),
        MulStrategy::ProjectiveCanonical | MulStrategy::ProjectiveCentered => modulus - 1,
    }
}

fn cleanup_items(modulus: u32, strategy: MulStrategy) -> u32 {
    table_items(modulus, strategy).saturating_sub(2)
}

fn streamed_table_coordinate(
    lhs_depth: u32,
    entries: &[i32],
    query: Script,
    cleanup: u32,
) -> Script {
    script! {
        { lhs_depth } OP_ROLL
        OP_2DUP OP_BOOLAND
        OP_IF
            OP_TOALTSTACK OP_TOALTSTACK
            { push_table_entries(entries) }
            OP_FROMALTSTACK OP_FROMALTSTACK
            { query }
            OP_TOALTSTACK
            { drop_items(cleanup) }
        OP_ELSE
            OP_BOOLAND OP_TOALTSTACK
        OP_ENDIF
    }
}

fn calculated_mul_peak(preserved_items: u32) -> u64 {
    MODULI
        .iter()
        .enumerate()
        .map(|(index, modulus)| {
            let strategy = strategy(*modulus);
            let live = 2 * u64::from(RESIDUE_COUNT) - index as u64;
            let table = u64::from(table_items(*modulus, strategy));
            let transient = match strategy {
                MulStrategy::Binary => 0,
                MulStrategy::Ternary | MulStrategy::CanonicalFull => 2,
                MulStrategy::ProjectiveCanonical | MulStrategy::ProjectiveCentered => 4,
            };
            u64::from(preserved_items) + live + table + transient
        })
        .max()
        .unwrap_or(u64::from(preserved_items))
}

/// Multiply two canonical RNS values with per-coordinate streamed tables.
///
/// Input layout: `preserved | lhs | rhs`, where `preserved_items` counts all
/// unrelated live main- and altstack items. Both operands are consumed. The
/// canonical output residues are left on the altstack, and no table remains.
pub fn mul(preserved_items: u32) -> Script {
    assert!(
        calculated_mul_peak(preserved_items) <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "prime RNS multiplication exceeds Bitcoin Script's stack limit"
    );

    let coordinates = MODULI
        .iter()
        .copied()
        .enumerate()
        .map(|(index, modulus)| {
            let lhs_depth = RESIDUE_COUNT - index as u32;
            match strategy(modulus) {
                MulStrategy::Binary => script! {
                    { lhs_depth } OP_ROLL OP_BOOLAND OP_TOALTSTACK
                },
                MulStrategy::Ternary => script! {
                    { lhs_depth } OP_ROLL
                    { ternary_coordinate_mul() }
                    OP_TOALTSTACK
                },
                strategy @ MulStrategy::CanonicalFull => {
                    let entries = full_table_entries(index);
                    streamed_table_coordinate(
                        lhs_depth,
                        &entries,
                        canonical_full_coordinate_mul(modulus),
                        cleanup_items(modulus, strategy),
                    )
                }
                strategy @ MulStrategy::ProjectiveCanonical => {
                    let entries = projective_table_entries(index, false);
                    streamed_table_coordinate(
                        lhs_depth,
                        &entries,
                        projective_coordinate_mul(modulus, false),
                        cleanup_items(modulus, strategy),
                    )
                }
                strategy @ MulStrategy::ProjectiveCentered => {
                    let entries = projective_table_entries(index, true);
                    streamed_table_coordinate(
                        lhs_depth,
                        &entries,
                        projective_coordinate_mul(modulus, true),
                        cleanup_items(modulus, strategy),
                    )
                }
            }
        })
        .collect::<Vec<_>>();

    script! {
        for coordinate in coordinates {
            { coordinate }
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

fn mul_by_constant_addition_chain(constant: u32, modulus: u32) -> Script {
    let constant = constant % modulus;
    let negative = constant > modulus / 2;
    let magnitude = if negative {
        modulus - constant
    } else {
        constant
    };

    script! {
        if magnitude == 0 {
            OP_DROP 0
        } else {
            OP_DUP
            for _ in 1..magnitude {
                OP_OVER OP_ADD
                { canonical_add_reduce(modulus) }
            }
            OP_NIP

            if negative {
                OP_DUP OP_0NOTEQUAL
                OP_IF
                    { modulus } OP_SWAP OP_SUB
                OP_ENDIF
            }
        }
    }
}

fn mul_by_constant_direct_table(constant: u32, modulus: u32, centered: bool) -> Script {
    let entries = (0..modulus)
        .rev()
        .map(|value| {
            let residue = value * constant % modulus;
            if centered {
                center(residue, modulus)
            } else {
                residue as i32
            }
        })
        .collect::<Vec<_>>();

    script! {
        OP_TOALTSTACK
        { push_table_entries(&entries) }
        OP_FROMALTSTACK OP_ROLL
        OP_TOALTSTACK
        { drop_items(modulus - 1) }
        OP_FROMALTSTACK

        if centered {
            OP_DUP 0 OP_LESSTHAN
            OP_IF
                { modulus } OP_ADD
            OP_ENDIF
        }
    }
}

/// Multiply one canonical coordinate by a fixed constant.
///
/// Script generation selects the shortest of a centered addition chain and
/// canonical/centered direct lookup tables. Direct tables are streamed and
/// destructively queried, so only one coordinate table is live at a time.
fn mul_by_constant_mod(constant: u32, modulus: u32) -> Script {
    let candidates = [
        mul_by_constant_addition_chain(constant, modulus),
        mul_by_constant_direct_table(constant, modulus, false),
        mul_by_constant_direct_table(constant, modulus, true),
    ];
    candidates
        .into_iter()
        .min_by_key(|candidate| candidate.clone().compile().len())
        .expect("constant multiplication has candidates")
}

fn verify_sum_to_constant(constant: &[u32; MODULI.len()]) -> Script {
    script! {
        for (index, modulus) in MODULI.iter().copied().enumerate() {
            // Layout is `value | complement`; preserve both while checking
            // one coordinate of value + complement = constant.
            { RESIDUE_COUNT + index as u32 } OP_PICK
            { index as u32 + 1 } OP_PICK
            OP_ADD
            { canonical_add_reduce(modulus) }
            { constant[index] } OP_EQUALVERIFY
        }
    }
}

fn calculated_hinted_reduction_peak(preserved_items: u32) -> u64 {
    let multiplication = calculated_mul_peak(preserved_items + 2 * RESIDUE_COUNT);
    let relation = u64::from(preserved_items + 3 * RESIDUE_COUNT + MODULI[MODULI.len() - 1] + 3);
    let input_validation = u64::from(preserved_items + 5 * RESIDUE_COUNT + 3);
    multiplication.max(relation).max(input_validation)
}

/// Verify a witness-hinted modular multiplication and return its remainder.
///
/// `target_modulus` is fixed in the locking script and must fit in 256 bits.
/// Input layout is
/// `preserved | lhs | rhs | quotient | remainder | remainder_complement`,
/// with every value in canonical [`MODULI`] order. The fragment consumes all
/// five values except `remainder`, which it returns on the main stack.
///
/// The quotient, remainder, and complement are hostile witness hints. This
/// fragment verifies their coordinate ranges, `remainder + complement =
/// target_modulus - 1`, and `lhs * rhs = quotient * target_modulus +
/// remainder` in every RNS channel. Callers must additionally bind all five
/// vectors to unsigned integers below `2^256`, and must establish `lhs,
/// rhs < target_modulus`. Those global range properties are not coordinatewise
/// and are deliberately outside this fragment.
///
/// Under those preconditions, both sides of the product equation are below
/// `2^512`, while [`modulus`] is greater than `2^512`; the coordinate checks
/// therefore prove integer equality rather than equality only modulo the RNS
/// dynamic range. The complement equation proves a canonical remainder.
pub fn mul_mod_hinted(target_modulus: &BigUint, preserved_items: u32) -> Script {
    assert!(!target_modulus.is_zero(), "target modulus must be positive");
    assert!(
        target_modulus.bits() <= 256,
        "target modulus must fit in 256 bits"
    );
    assert!(
        calculated_hinted_reduction_peak(preserved_items) <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "prime RNS hinted modular multiplication exceeds Bitcoin Script's stack limit"
    );

    let target_residues = encode(target_modulus);
    let complement_sum = target_modulus - BigUint::one();
    let complement_sum_residues = encode(&complement_sum);
    let relation_checks = MODULI
        .iter()
        .copied()
        .enumerate()
        .map(|(index, modulus)| {
            let index = index as u32;
            script! {
                // Layout is `product | quotient | remainder`. Copy one
                // coordinate from each vector without disturbing the output.
                { 2 * RESIDUE_COUNT + index } OP_PICK
                { RESIDUE_COUNT + index + 1 } OP_PICK
                { index + 2 } OP_PICK

                OP_TOALTSTACK
                { mul_by_constant_mod(target_residues[index as usize], modulus) }
                OP_FROMALTSTACK
                OP_ADD
                { canonical_add_reduce(modulus) }
                OP_EQUALVERIFY
            }
        })
        .collect::<Vec<_>>();

    script! {
        // Validate and bind r' = target - 1 - r before any hint can be used as
        // a lookup index. Both vectors remain live for the equality checks.
        { verify_canonical() }
        { verify_sum_to_constant(&complement_sum_residues) }
        { drop_value() }
        { verify_canonical() }

        // Preserve r and validate q before multiplication.
        { to_altstack() }
        { verify_canonical() }
        { to_altstack() }

        // q and r coexist below all temporary multiplication state.
        { mul(preserved_items + 2 * RESIDUE_COUNT) }
        { from_altstack() }
        { from_altstack() }
        { from_altstack() }

        for check in relation_checks {
            { check }
        }

        // Preserve only the verified canonical remainder.
        { to_altstack() }
        { drop_items(2 * RESIDUE_COUNT) }
        { from_altstack() }
    }
}

fn centered_reduce(modulus: u32) -> Script {
    let half = (modulus - 1) / 2;
    let two_bounds = script! {
        OP_DUP { half } OP_GREATERTHAN
        OP_IF
            { modulus } OP_SUB
        OP_ELSE
            OP_DUP { -(half as i32) } OP_LESSTHAN
            OP_IF
                { modulus } OP_ADD
            OP_ENDIF
        OP_ENDIF
    };
    let absolute_bound = script! {
        OP_DUP OP_ABS { half } OP_GREATERTHAN
        OP_IF
            OP_DUP 0 OP_LESSTHAN
            OP_IF
                { modulus }
            OP_ELSE
                { -(modulus as i32) }
            OP_ENDIF
            OP_ADD
        OP_ENDIF
    };
    if absolute_bound.clone().compile().len() < two_bounds.clone().compile().len() {
        absolute_bound
    } else {
        two_bounds
    }
}

fn canonical_binary_op(subtract: bool) -> Script {
    script! {
        for (index, modulus) in MODULI.iter().copied().enumerate() {
            { RESIDUE_COUNT - index as u32 } OP_ROLL
            if modulus == 2 {
                OP_NUMNOTEQUAL
            } else if subtract {
                OP_SWAP OP_SUB
                OP_DUP 0 OP_LESSTHAN
                OP_IF
                    { modulus } OP_ADD
                OP_ENDIF
            } else {
                OP_ADD
                { canonical_add_reduce(modulus) }
            }
            OP_TOALTSTACK
        }
    }
}

fn centered_binary_op(subtract: bool) -> Script {
    script! {
        for (index, modulus) in MODULI.iter().copied().enumerate() {
            { RESIDUE_COUNT - index as u32 } OP_ROLL
            if modulus == 2 {
                OP_NUMNOTEQUAL
            } else {
                if subtract {
                    OP_SWAP OP_SUB
                } else {
                    OP_ADD
                }
                { centered_reduce(modulus) }
            }
            OP_TOALTSTACK
        }
    }
}

/// Add two canonical RNS values without lookup tables.
pub fn add() -> Script {
    canonical_binary_op(false)
}

/// Subtract the top canonical RNS value from the one beneath it.
pub fn sub() -> Script {
    canonical_binary_op(true)
}

/// Add two centered RNS values without lookup tables.
pub fn add_centered() -> Script {
    centered_binary_op(false)
}

/// Subtract the top centered RNS value from the one beneath it.
pub fn sub_centered() -> Script {
    centered_binary_op(true)
}

/// Verify that the top RNS value uses canonical coordinate ranges.
pub fn verify_canonical() -> Script {
    script! {
        for (index, modulus) in MODULI.iter().copied().enumerate() {
            if index == 0 {
                OP_DUP
            } else {
                { index as u32 } OP_PICK
            }
            0 { modulus } OP_WITHIN OP_VERIFY
        }
    }
}

/// Verify the mixed centered encoding used by [`encode_centered`].
pub fn verify_centered() -> Script {
    script! {
        for (index, modulus) in MODULI.iter().copied().enumerate() {
            if index == 0 {
                OP_DUP
            } else {
                { index as u32 } OP_PICK
            }
            if modulus == 2 {
                0 2 OP_WITHIN OP_VERIFY
            } else {
                { -((modulus as i32 - 1) / 2) }
                { (modulus + 1) / 2 }
                OP_WITHIN OP_VERIFY
            }
        }
    }
}

/// Move one RNS value from the altstack to the main stack.
pub fn from_altstack() -> Script {
    script! {
        for _ in 0..RESIDUE_COUNT {
            OP_FROMALTSTACK
        }
    }
}

/// Move one RNS value from the main stack to the altstack.
pub fn to_altstack() -> Script {
    script! {
        for _ in 0..RESIDUE_COUNT {
            OP_TOALTSTACK
        }
    }
}

/// Drop one RNS value from the main stack.
pub fn drop_value() -> Script {
    drop_items(RESIDUE_COUNT)
}

/// Consume and equality-check the top two RNS values.
pub fn equalverify() -> Script {
    script! {
        for index in 0..RESIDUE_COUNT {
            { RESIDUE_COUNT - index } OP_ROLL
            OP_EQUALVERIFY
        }
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::{BigInt, BigUint, RandBigInt};
    use num_traits::{One, Zero};
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    fn is_prime(value: u32) -> bool {
        value >= 2 && (2..=((value as f64).sqrt() as u32)).all(|d| value % d != 0)
    }

    fn is_primitive_root(modulus: u32, generator: u32) -> bool {
        let mut factors = Vec::new();
        let mut remaining = modulus - 1;
        let mut factor = 2;
        while factor * factor <= remaining {
            if remaining % factor == 0 {
                factors.push(factor);
                while remaining % factor == 0 {
                    remaining /= factor;
                }
            }
            factor += 1;
        }
        if remaining > 1 {
            factors.push(remaining);
        }
        factors
            .iter()
            .all(|factor| pow_mod(generator, (modulus - 1) / factor, modulus) != 1)
    }

    fn modular_sub(lhs: &BigUint, rhs: &BigUint, modulus: &BigUint) -> BigUint {
        if lhs >= rhs {
            lhs - rhs
        } else {
            modulus - (rhs - lhs)
        }
    }

    fn run_canonical_binary(lhs: &BigUint, rhs: &BigUint, expected: &BigUint, op: Script) {
        crate::support::execution::run(script! {
            { push_value(lhs) }
            { push_value(rhs) }
            { op }
            { push_value(expected) }
            { from_altstack() }
            { equalverify() }
            OP_TRUE
        });
    }

    fn run_centered_binary(lhs: &BigInt, rhs: &BigInt, expected: &BigInt, op: Script) {
        crate::support::execution::run(script! {
            { push_centered_value(lhs) }
            { push_centered_value(rhs) }
            { op }
            { push_centered_value(expected) }
            { from_altstack() }
            { equalverify() }
            OP_TRUE
        });
    }

    fn secp256k1_modulus() -> BigUint {
        BigUint::parse_bytes(
            b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            16,
        )
        .unwrap()
    }

    fn run_hinted_modular_product(
        lhs: &BigUint,
        rhs: &BigUint,
        target: &BigUint,
        operation: Script,
    ) -> crate::support::execution::ExecuteInfo {
        let product = lhs * rhs;
        let quotient = &product / target;
        let remainder = &product % target;
        let complement = target - BigUint::one() - &remainder;
        crate::support::execution::execute_script(script! {
            { push_value(lhs) }
            { push_value(rhs) }
            { push_value(&quotient) }
            { push_value(&remainder) }
            { push_value(&complement) }
            { operation }
            { push_value(&remainder) }
            { equalverify() }
            OP_TRUE
        })
    }

    #[test]
    fn basis_has_exact_unsigned_256_bit_product_capacity() {
        assert_eq!(MODULI.len(), 75);
        assert!(MODULI.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(MODULI.iter().all(|modulus| is_prime(*modulus)));
        assert!(!MODULI.contains(&47));

        let max = (BigUint::one() << 256usize) - BigUint::one();
        let target = &max * &max;
        let combined = modulus();
        assert!(combined > target);
        assert_eq!(combined.bits(), 513);

        for index in 1..MODULI.len() {
            assert!(is_primitive_root(MODULI[index], GENERATORS[index]));
            if matches!(
                strategy(MODULI[index]),
                MulStrategy::ProjectiveCanonical | MulStrategy::ProjectiveCentered
            ) {
                assert!(LOG_BIASES[index] < (MODULI[index] - 1) / 2);
            }
        }
    }

    #[test]
    fn affine_projective_tables_model_every_coordinate_product() {
        for index in 8..MODULI.len() {
            let modulus = MODULI[index];
            let half = (modulus - 1) / 2;
            let order = modulus - 1;
            let bias = LOG_BIASES[index];
            let logs = discrete_logs(modulus, GENERATORS[index]);
            let tokens = (1..=half)
                .map(|magnitude| {
                    let exponent = logs[magnitude as usize];
                    let lower = exponent % half;
                    let shifted = lower + bias;
                    let shifted_lower = shifted % half;
                    let shifted_upper = (exponent >= half) ^ (shifted >= half);
                    assert!(shifted_lower != 0 || !shifted_upper);
                    if shifted_upper {
                        -(shifted_lower as i32)
                    } else {
                        shifted_lower as i32
                    }
                })
                .collect::<Vec<_>>();
            assert_eq!(tokens.iter().filter(|token| **token == 0).count(), 1);
            assert_eq!(
                projective_table_entries(
                    index,
                    strategy(modulus) == MulStrategy::ProjectiveCentered,
                )
                .len(),
                (modulus - 1) as usize
            );

            for lhs in 0..modulus {
                for rhs in 0..modulus {
                    let actual = if lhs == 0 || rhs == 0 {
                        0
                    } else {
                        let lhs_token = tokens[lhs.min(modulus - lhs) as usize - 1];
                        let rhs_token = tokens[rhs.min(modulus - rhs) as usize - 1];
                        let sum = lhs_token.unsigned_abs() + rhs_token.unsigned_abs();
                        let carry = sum >= half;
                        let exponent = (sum % half + order - (2 * bias) % order) % order;
                        let mut residue = pow_mod(GENERATORS[index], exponent, modulus);
                        let negate =
                            (lhs > half) ^ (rhs > half) ^ (lhs_token < 0) ^ (rhs_token < 0) ^ carry;
                        if negate {
                            residue = modulus - residue;
                        }
                        residue
                    };
                    assert_eq!(actual, lhs * rhs % modulus, "modulus {modulus}");
                }
            }
        }
    }

    #[test]
    fn addition_and_subtraction_are_correct() {
        let combined = modulus();
        let mut rng = StdRng::seed_from_u64(0x3235_365f_5052_4e53);
        let maximum = &combined - BigUint::one();
        let mut pairs = vec![
            (BigUint::zero(), BigUint::zero()),
            (BigUint::zero(), BigUint::one()),
            (maximum.clone(), maximum.clone()),
            (maximum.clone(), BigUint::one()),
            (
                (BigUint::one() << 256usize) - BigUint::one(),
                BigUint::one(),
            ),
        ];
        for _ in 0..5 {
            pairs.push((
                rng.gen_biguint_below(&combined),
                rng.gen_biguint_below(&combined),
            ));
        }

        for (lhs, rhs) in pairs {
            run_canonical_binary(&lhs, &rhs, &((&lhs + &rhs) % &combined), add());
            run_canonical_binary(&lhs, &rhs, &modular_sub(&lhs, &rhs, &combined), sub());

            let offset = BigInt::from(&combined >> 1usize);
            let lhs_signed = BigInt::from(lhs) - &offset;
            let rhs_signed = BigInt::from(rhs) - &offset;
            run_centered_binary(
                &lhs_signed,
                &rhs_signed,
                &(&lhs_signed + &rhs_signed),
                add_centered(),
            );
            run_centered_binary(
                &lhs_signed,
                &rhs_signed,
                &(&lhs_signed - &rhs_signed),
                sub_centered(),
            );
        }
    }

    #[test]
    fn multiplication_is_correct_for_256_bit_values() {
        let combined = modulus();
        let max = (BigUint::one() << 256usize) - BigUint::one();
        let mut rng = StdRng::seed_from_u64(0x4d55_4c5f_3235_3652);
        let mut pairs = vec![
            (BigUint::zero(), max.clone()),
            (max.clone(), BigUint::zero()),
            (BigUint::one(), max.clone()),
            (max.clone(), max.clone()),
        ];
        for modulus in [3u32, 5, 19, 23, 151, 157, 383] {
            pairs.push((BigUint::from(modulus), BigUint::from(modulus + 1)));
        }
        for _ in 0..3 {
            pairs.push((rng.gen_biguint(256), rng.gen_biguint(256)));
        }

        let operation = mul(0);
        for (lhs, rhs) in pairs {
            let expected = (&lhs * &rhs) % &combined;
            run_canonical_binary(&lhs, &rhs, &expected, operation.clone());
        }
    }

    #[test]
    fn multiplication_preserves_unrelated_items() {
        let lhs = BigUint::from(123_456_789u64);
        let rhs = (BigUint::one() << 255usize) + BigUint::from(17u32);
        let expected = &lhs * &rhs;
        crate::support::execution::run(script! {
            101 OP_TOALTSTACK
            102
            { push_value(&lhs) }
            { push_value(&rhs) }
            { mul(2) }
            { push_value(&expected) }
            { from_altstack() }
            { equalverify() }
            102 OP_EQUALVERIFY
            OP_FROMALTSTACK 101 OP_EQUALVERIFY
            OP_TRUE
        });
    }

    #[test]
    fn hinted_modular_multiplication_is_correct() {
        let target = secp256k1_modulus();
        let operation = mul_mod_hinted(&target, 0);
        let mut rng = StdRng::seed_from_u64(0x4849_4e54_5f4d_4f44);
        let mut pairs = vec![
            (BigUint::zero(), BigUint::zero()),
            (BigUint::zero(), &target - BigUint::one()),
            (BigUint::one(), &target - BigUint::one()),
            (&target - BigUint::one(), &target - BigUint::one()),
        ];
        for _ in 0..2 {
            pairs.push((
                rng.gen_biguint_below(&target),
                rng.gen_biguint_below(&target),
            ));
        }

        for (lhs, rhs) in pairs {
            let result = run_hinted_modular_product(&lhs, &rhs, &target, operation.clone());
            assert!(result.success, "{lhs} * {rhs} mod target: {result}");
        }
    }

    #[test]
    fn hinted_modular_multiplication_rejects_adversarial_hints() {
        let target = secp256k1_modulus();
        let lhs = BigUint::from(123_456_789u64);
        let rhs = (&target >> 1usize) + BigUint::from(17u32);
        let product = &lhs * &rhs;
        let quotient = &product / &target;
        let remainder = &product % &target;
        let complement = &target - BigUint::one() - &remainder;
        let operation = mul_mod_hinted(&target, 0);

        for (bad_quotient, bad_remainder, bad_complement) in [
            (
                &quotient + BigUint::one(),
                remainder.clone(),
                complement.clone(),
            ),
            (
                quotient.clone(),
                &remainder + BigUint::one(),
                &complement - BigUint::one(),
            ),
            (
                quotient.clone(),
                remainder.clone(),
                &complement + BigUint::one(),
            ),
        ] {
            let result = crate::support::execution::execute_script(script! {
                { push_value(&lhs) }
                { push_value(&rhs) }
                { push_value(&bad_quotient) }
                { push_value(&bad_remainder) }
                { push_value(&bad_complement) }
                { operation.clone() }
                OP_TRUE
            });
            assert!(!result.success);
        }

        let mut malformed_quotient = encode(&quotient);
        malformed_quotient[MODULI.len() - 1] = MODULI[MODULI.len() - 1];
        let result = crate::support::execution::execute_script(script! {
            { push_value(&lhs) }
            { push_value(&rhs) }
            { push_residues(&malformed_quotient) }
            { push_value(&remainder) }
            { push_value(&complement) }
            { operation.clone() }
            OP_TRUE
        });
        assert!(!result.success);

        let mut malformed_complement = encode(&complement);
        malformed_complement[MODULI.len() - 1] = MODULI[MODULI.len() - 1];
        let result = crate::support::execution::execute_script(script! {
            { push_value(&lhs) }
            { push_value(&rhs) }
            { push_value(&quotient) }
            { push_value(&remainder) }
            { push_residues(&malformed_complement) }
            { operation }
            OP_TRUE
        });
        assert!(!result.success);
    }

    #[test]
    fn hinted_modular_multiplication_preserves_unrelated_items() {
        let target = secp256k1_modulus();
        let lhs = BigUint::from(123_456_789u64);
        let rhs = BigUint::from(987_654_321u64);
        let product = &lhs * &rhs;
        let quotient = &product / &target;
        let remainder = &product % &target;
        let complement = &target - BigUint::one() - &remainder;
        let result = crate::support::execution::execute_script(script! {
            101 OP_TOALTSTACK
            102
            { push_value(&lhs) }
            { push_value(&rhs) }
            { push_value(&quotient) }
            { push_value(&remainder) }
            { push_value(&complement) }
            { mul_mod_hinted(&target, 2) }
            { push_value(&remainder) }
            { equalverify() }
            102 OP_EQUALVERIFY
            OP_FROMALTSTACK 101 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "preserved-state execution failed: {result}");
    }

    #[test]
    fn range_verifiers_accept_boundaries_and_reject_malformed_coordinates() {
        let combined = modulus();
        crate::support::execution::run(script! {
            { push_value(&(&combined - BigUint::one())) }
            { verify_canonical() }
            { drop_value() }
            OP_TRUE
        });

        let centered = encode_centered(&(-BigInt::from(123_456u32)));
        crate::support::execution::run(script! {
            { push_centered_residues(&centered) }
            { verify_centered() }
            { drop_value() }
            OP_TRUE
        });

        let mut malformed = [0u32; MODULI.len()];
        malformed[MODULI.len() - 1] = *MODULI.last().unwrap();
        let result = crate::support::execution::execute_script(script! {
            { push_residues(&malformed) }
            { verify_canonical() }
            { drop_value() }
            OP_TRUE
        });
        assert!(!result.success);

        let mut malformed_centered = [0i32; MODULI.len()];
        malformed_centered[MODULI.len() - 1] = (*MODULI.last().unwrap() as i32 + 1) / 2;
        let result = crate::support::execution::execute_script(script! {
            { push_centered_residues(&malformed_centered) }
            { verify_centered() }
            { drop_value() }
            OP_TRUE
        });
        assert!(!result.success);
    }

    #[test]
    fn stack_peak_matches_the_guard() {
        assert_eq!(calculated_mul_peak(0), u64::from(MUL_STACK_ITEMS));
        let max = (BigUint::one() << 256usize) - BigUint::one();
        let result = crate::support::execution::execute_script(script! {
            { push_value(&max) }
            { push_value(&(&max - BigUint::one())) }
            { mul(0) }
            { from_altstack() }
            { drop_value() }
            OP_TRUE
        });
        assert!(result.success, "peak execution failed: {result}");
        assert_eq!(result.stats.max_nb_stack_items, MUL_STACK_ITEMS as usize);

        let preserved = U31_LOOKUP_STACK_LIMIT - MUL_STACK_ITEMS;
        let result = crate::support::execution::execute_script(script! {
            for _ in 0..preserved {
                0
            }
            { push_value(&max) }
            { push_value(&(&max - BigUint::one())) }
            { mul(preserved) }
            { from_altstack() }
            { drop_value() }
            { drop_items(preserved) }
            OP_TRUE
        });
        assert!(result.success, "stack-limit execution failed: {result}");
        assert_eq!(result.stats.max_nb_stack_items, 1_000);

        let target = secp256k1_modulus();
        let lhs = &target - BigUint::one();
        let rhs = lhs.clone();
        let product = &lhs * &rhs;
        let quotient = &product / &target;
        let remainder = &product % &target;
        let complement = &target - BigUint::one() - &remainder;
        assert_eq!(
            calculated_hinted_reduction_peak(0),
            u64::from(HINTED_MUL_STACK_ITEMS)
        );
        let result = crate::support::execution::execute_script(script! {
            { push_value(&lhs) }
            { push_value(&rhs) }
            { push_value(&quotient) }
            { push_value(&remainder) }
            { push_value(&complement) }
            { mul_mod_hinted(&target, 0) }
            { drop_value() }
            OP_TRUE
        });
        assert!(result.success, "hinted peak execution failed: {result}");
        assert_eq!(
            result.stats.max_nb_stack_items,
            HINTED_MUL_STACK_ITEMS as usize
        );
    }

    #[test]
    #[should_panic(expected = "prime RNS multiplication exceeds Bitcoin Script's stack limit")]
    fn multiplication_rejects_excess_preserved_depth() {
        let _ = mul(U31_LOOKUP_STACK_LIMIT - MUL_STACK_ITEMS + 1);
    }

    #[test]
    #[should_panic(
        expected = "prime RNS hinted modular multiplication exceeds Bitcoin Script's stack limit"
    )]
    fn hinted_multiplication_rejects_excess_preserved_depth() {
        let target = secp256k1_modulus();
        let _ = mul_mod_hinted(&target, U31_LOOKUP_STACK_LIMIT - HINTED_MUL_STACK_ITEMS + 1);
    }

    #[test]
    #[should_panic(expected = "target modulus must be positive")]
    fn hinted_multiplication_rejects_zero_target() {
        let _ = mul_mod_hinted(&BigUint::zero(), 0);
    }

    #[test]
    #[should_panic(expected = "target modulus must fit in 256 bits")]
    fn hinted_multiplication_rejects_oversized_target() {
        let _ = mul_mod_hinted(&(BigUint::one() << 256usize), 0);
    }
}
