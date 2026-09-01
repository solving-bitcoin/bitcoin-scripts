//! Arithmetic for prime fields whose canonical elements fit in 31 bits.
//!
//! The implementation uses two representations of the same residue:
//! `u31(x) = x` and `v31(x) = x - p`. Switching between them keeps every
//! arithmetic intermediate inside Bitcoin Script's signed 32-bit numeric
//! range. Multiplication decomposes one operand into bits and evaluates two
//! bits per window.
//!
//! Ported from BitVM's `rust-bitcoin-m31-or-babybear` at commit
//! `1015e3393c7310f0f30f0b73ff4a7f2bc1a5173e`.

use bitcoin::ScriptBuf;

use crate::support::script::*;

mod extension;
mod karatsuba;
mod lookup;

pub use extension::*;
pub use karatsuba::*;
pub use lookup::*;

/// Configuration for a field with a modulus strictly below `2^31`.
pub trait U31Config {
    const MODULUS: u32;
}

/// The Mersenne prime field with modulus `2^31 - 1`.
pub struct M31;

impl U31Config for M31 {
    const MODULUS: u32 = (1 << 31) - 1;
}

/// The BabyBear field with modulus `15 * 2^27 + 1`.
pub struct BabyBear;

impl U31Config for BabyBear {
    const MODULUS: u32 = 15 * (1 << 27) + 1;
}

/// Convert canonical `x` into the negative representative `x - p`.
pub fn u31_to_v31<C: U31Config>() -> Script {
    script! {
        { C::MODULUS }
        OP_SUB
    }
}

/// Convert the negative representative `x - p` back into canonical `x`.
pub fn v31_to_u31<C: U31Config>() -> Script {
    script! {
        { C::MODULUS }
        OP_ADD
    }
}

/// Add a canonical element to a negative representative and return canonical.
pub fn u31_add_v31<C: U31Config>() -> Script {
    script! {
        OP_ADD
        { u31_adjust::<C>() }
    }
}

/// Add a negative representative to a canonical element and return negative.
pub fn v31_add_u31<C: U31Config>() -> Script {
    script! {
        OP_ADD
        { v31_adjust::<C>() }
    }
}

fn u31_adjust<C: U31Config>() -> Script {
    script! {
        OP_DUP
        0
        OP_LESSTHAN
        OP_IF
            { C::MODULUS }
            OP_ADD
        OP_ENDIF
    }
}

fn v31_adjust<C: U31Config>() -> Script {
    script! {
        OP_DUP
        0
        OP_GREATERTHANOREQUAL
        OP_IF
            { C::MODULUS }
            OP_SUB
        OP_ENDIF
    }
}

/// Add two canonical field elements.
pub fn u31_add<C: U31Config>() -> Script {
    script! {
        { u31_to_v31::<C>() }
        { u31_add_v31::<C>() }
    }
}

/// Add two negative representatives and return a negative representative.
pub fn v31_add<C: U31Config>() -> Script {
    script! {
        { v31_to_u31::<C>() }
        { v31_add_u31::<C>() }
    }
}

/// Double a canonical field element.
pub fn u31_double<C: U31Config>() -> Script {
    script! {
        OP_DUP
        { u31_add::<C>() }
    }
}

/// Double a negative representative.
pub fn v31_double<C: U31Config>() -> Script {
    script! {
        OP_DUP
        { v31_add::<C>() }
    }
}

/// Subtract the top canonical element from the one below it.
pub fn u31_sub<C: U31Config>() -> Script {
    script! {
        OP_SUB
        { u31_adjust::<C>() }
    }
}

/// Subtract the top negative representative from the one below it.
pub fn v31_sub<C: U31Config>() -> Script {
    script! {
        OP_SUB
        { v31_adjust::<C>() }
    }
}

/// Negate a canonical field element and keep zero canonical.
pub fn u31_neg<C: U31Config>() -> Script {
    script! {
        OP_DUP 0 OP_EQUAL
        OP_IF
            OP_DROP 0
        OP_ELSE
            { C::MODULUS }
            OP_SWAP
            OP_SUB
        OP_ENDIF
    }
}

/// Negate a negative representative and keep zero represented as `-p`.
pub fn v31_neg<C: U31Config>() -> Script {
    script! {
        OP_DUP { -(C::MODULUS as i64) } OP_EQUAL
        OP_IF
            OP_DROP { -(C::MODULUS as i64) }
        OP_ELSE
            { -(C::MODULUS as i64) }
            OP_SWAP
            OP_SUB
        OP_ENDIF
    }
}

/// Decompose a canonical element into 31 bits, with the least-significant bit
/// on top and the most-significant bit deepest.
pub fn u31_to_bits() -> Script {
    u31_to_bits_with_width(31)
}

/// Decompose a canonical element into exactly `bit_width` bits.
///
/// The least-significant bit is left on top. The caller must ensure that the
/// input is smaller than `2^bit_width`; field multiplication should normally
/// use [`u31_mul_compact`], which derives the safe width from the modulus.
pub fn u31_to_bits_with_width(bit_width: u32) -> Script {
    assert!(
        (1..=31).contains(&bit_width),
        "u31 bit width must be in 1..=31"
    );

    script! {
        for bit in (1..bit_width).rev() {
            OP_DUP
            { (1u32 << bit) - 1 }
            OP_GREATERTHAN
            OP_SWAP
            OP_OVER
            OP_IF
                { 1u32 << bit }
                OP_SUB
            OP_ENDIF
        }
    }
}

fn u31_mul_common_with_window_pairs<C: U31Config>(window_pairs: u32) -> Script {
    script! {
        0
        OP_SWAP
        { u31_to_v31::<C>() }
        OP_DUP
        { v31_double::<C>() }
        OP_2DUP
        { v31_add::<C>() }
        0
        OP_FROMALTSTACK
        OP_IF
            3 OP_PICK
            { u31_add_v31::<C>() }
        OP_ENDIF
        if window_pairs > 0 {
            { u31_double::<C>() }
            { u31_double::<C>() }
            for pair in 0..window_pairs {
                OP_FROMALTSTACK
                OP_DUP OP_ADD
                OP_FROMALTSTACK OP_ADD
                4 OP_SWAP OP_SUB OP_PICK
                { u31_add_v31::<C>() }
                if pair + 1 < window_pairs {
                    { u31_double::<C>() }
                    { u31_double::<C>() }
                }
            }
        }
        OP_TOALTSTACK
        OP_2DROP OP_2DROP
        OP_FROMALTSTACK
    }
}

fn u31_mul_common_with_even_window_pairs<C: U31Config>(window_pairs: u32) -> Script {
    assert!(window_pairs > 0, "even-width multiplication needs one pair");

    script! {
        0
        OP_SWAP
        { u31_to_v31::<C>() }
        OP_DUP
        { v31_double::<C>() }
        OP_2DUP
        { v31_add::<C>() }
        0
        for pair in 0..window_pairs {
            OP_FROMALTSTACK
            OP_DUP OP_ADD
            OP_FROMALTSTACK OP_ADD
            4 OP_SWAP OP_SUB OP_PICK
            { u31_add_v31::<C>() }
            if pair + 1 < window_pairs {
                { u31_double::<C>() }
                { u31_double::<C>() }
            }
        }
        OP_TOALTSTACK
        OP_2DROP OP_2DROP
        OP_FROMALTSTACK
    }
}

pub(crate) fn u31_mul_common<C: U31Config>() -> Script {
    u31_mul_common_with_window_pairs::<C>(15)
}

/// Multiply two canonical field elements.
pub fn u31_mul<C: U31Config>() -> Script {
    script! {
        { u31_to_bits() }
        for _ in 0..31 {
            OP_TOALTSTACK
        }
        { u31_mul_common::<C>() }
    }
}

/// Multiply two canonical field elements using the modulus' minimum safe bit
/// width instead of always decomposing the right operand into 31 bits.
///
/// This is identical in size to [`u31_mul`] for 31-bit fields, but is much
/// smaller for fields with narrow canonical representations.
pub fn u31_mul_compact<C: U31Config>() -> Script {
    assert!(
        (2..(1 << 31)).contains(&C::MODULUS),
        "u31 modulus must be in 2..2^31"
    );
    let bit_width = 32 - (C::MODULUS - 1).leading_zeros();

    script! {
        { u31_to_bits_with_width(bit_width) }
        for _ in 0..bit_width {
            OP_TOALTSTACK
        }
        if bit_width % 2 == 0 {
            { u31_mul_common_with_even_window_pairs::<C>(bit_width / 2) }
        } else {
            { u31_mul_common_with_window_pairs::<C>((bit_width - 1) / 2) }
        }
    }
}

/// Emit the signed addition chain used by the public constant multipliers.
fn u31_mul_by_signed_constant<C: U31Config>(constant: u32, negative: bool) -> Script {
    let mut naf = ark_ff::biginteger::arithmetic::find_naf(&[constant as u64]);

    if naf.len() > 3 {
        let len = naf.len();
        if naf[len - 2] == 0 && naf[len - 3] == -1 {
            naf[len - 3] = 1;
            naf[len - 2] = 1;
            naf.resize(len - 1, 0);
        }
    }

    if negative {
        for digit in &mut naf {
            *digit = -*digit;
        }
    }

    let double = u31_double::<C>();
    let mut output = script! {};
    let mut cursor = 0usize;

    while cursor < naf.len() && naf[cursor] == 0 {
        output = script! { { output } { double.clone() } };
        cursor += 1;
    }

    if cursor == naf.len() {
        return script! {
            { output }
            OP_DROP
            0
        };
    }

    match naf[cursor] {
        1 => {
            output = script! {
                { output }
                OP_DUP
                { double.clone() }
            };
        }
        -1 => {
            output = script! {
                { output }
                OP_DUP
                { u31_neg::<C>() }
                OP_SWAP
                { double.clone() }
            };
        }
        _ => unreachable!(),
    }
    cursor += 1;

    while cursor < naf.len() {
        output = match naf[cursor] {
            0 => script! {
                { output }
                { double.clone() }
            },
            1 => script! {
                { output }
                OP_SWAP OP_OVER
                { u31_add::<C>() }
                OP_SWAP
                if cursor != naf.len() - 1 {
                    { double.clone() }
                }
            },
            -1 => script! {
                { output }
                OP_SWAP OP_OVER
                { u31_sub::<C>() }
                OP_SWAP
                if cursor != naf.len() - 1 {
                    { double.clone() }
                }
            },
            _ => unreachable!(),
        };
        cursor += 1;
    }

    // Keep the same raw-fragment behavior as the upstream generator while
    // returning this repository's StructuredScript type.
    let compiled = script! { { output } OP_DROP }.compile();
    Script::new("u31 multiplication by constant")
        .push_script(ScriptBuf::from_bytes(compiled.to_bytes()))
}

/// Multiply a canonical field element by a generation-time constant.
///
/// A relaxed non-adjacent form minimizes the emitted sequence of doubles,
/// additions, and subtractions. The resulting script size depends on the
/// constant.
pub fn u31_mul_by_constant<C: U31Config>(constant: u32) -> Script {
    u31_mul_by_signed_constant::<C>(constant, false)
}

/// Multiply by the shorter of `constant mod p` and its negation.
///
/// The choice is made at generation time from the actual serialized sizes.
/// Special cases for `0`, `1`, and `-1` avoid the addition-chain setup
/// entirely. The input and output are canonical field elements.
pub fn u31_mul_by_constant_centered<C: U31Config>(constant: u32) -> Script {
    assert!(
        (2..(1 << 31)).contains(&C::MODULUS),
        "u31 modulus must be in 2..2^31"
    );
    let reduced = (constant as u64 % C::MODULUS as u64) as u32;

    match reduced {
        0 => script! { OP_DROP 0 },
        1 => script! {},
        value if value == C::MODULUS - 1 => u31_neg::<C>(),
        value => {
            let positive = u31_mul_by_signed_constant::<C>(value, false);
            let negative = u31_mul_by_signed_constant::<C>(C::MODULUS - value, true);

            if negative.clone().compile().len() < positive.clone().compile().len() {
                negative
            } else {
                positive
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;
    use crate::support::{execution::execute_script, script::script};

    struct TestField257;

    impl U31Config for TestField257 {
        const MODULUS: u32 = 257;
    }

    struct TestField12289;

    impl U31Config for TestField12289 {
        const MODULUS: u32 = 12_289;
    }

    fn add_mod(a: u32, b: u32, modulus: u32) -> u32 {
        ((a as u64 + b as u64) % modulus as u64) as u32
    }

    fn sub_mod(a: u32, b: u32, modulus: u32) -> u32 {
        (a as i64 - b as i64).rem_euclid(modulus as i64) as u32
    }

    fn mul_mod(a: u32, b: u32, modulus: u32) -> u32 {
        (a as u64 * b as u64 % modulus as u64) as u32
    }

    fn boundary_values(modulus: u32) -> [u32; 6] {
        [0, 1, 2, modulus / 2, modulus - 2, modulus - 1]
    }

    fn assert_binary<C: U31Config>(a: u32, b: u32, expected: u32, operation: Script) {
        let result = execute_script(script! {
            { a }
            { b }
            { operation }
            { expected }
            OP_EQUAL
        });
        assert!(
            result.success,
            "field operation failed for a={a}, b={b}, expected={expected}: {result}"
        );
    }

    fn test_base_field<C: U31Config>() {
        for a in boundary_values(C::MODULUS) {
            for b in boundary_values(C::MODULUS) {
                assert_binary::<C>(a, b, add_mod(a, b, C::MODULUS), u31_add::<C>());
                assert_binary::<C>(a, b, sub_mod(a, b, C::MODULUS), u31_sub::<C>());
                assert_binary::<C>(a, b, mul_mod(a, b, C::MODULUS), u31_mul::<C>());
            }
        }

        let mut rng = StdRng::seed_from_u64(C::MODULUS as u64);
        for _ in 0..40 {
            let a = rng.gen_range(0..C::MODULUS);
            let b = rng.gen_range(0..C::MODULUS);
            assert_binary::<C>(a, b, add_mod(a, b, C::MODULUS), u31_add::<C>());
            assert_binary::<C>(a, b, sub_mod(a, b, C::MODULUS), u31_sub::<C>());
            assert_binary::<C>(a, b, mul_mod(a, b, C::MODULUS), u31_mul::<C>());
        }
    }

    #[test]
    fn test_m31_base_field() {
        test_base_field::<M31>();
    }

    #[test]
    fn test_babybear_base_field() {
        test_base_field::<BabyBear>();
    }

    #[test]
    fn test_u31_bit_decomposition() {
        for value in boundary_values(M31::MODULUS) {
            let bits = (0..31).map(|i| (value >> i) & 1).collect::<Vec<_>>();
            let result = execute_script(script! {
                { value }
                { u31_to_bits() }
                for bit in bits {
                    { bit }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            });
            assert!(
                result.success,
                "bit decomposition failed for {value}: {result}"
            );
        }
    }

    fn test_constant_mul<C: U31Config>() {
        let constants = [0, 1, 2, 3, 5, C::MODULUS / 3, C::MODULUS - 1, u32::MAX];
        for value in boundary_values(C::MODULUS) {
            for constant in constants {
                let expected = mul_mod(value, constant, C::MODULUS);
                for (name, operation) in [
                    ("naf", u31_mul_by_constant::<C>(constant)),
                    ("centered", u31_mul_by_constant_centered::<C>(constant)),
                ] {
                    let result = execute_script(script! {
                        { value }
                        { operation }
                        { expected }
                        OP_EQUAL
                    });
                    assert!(
                        result.success,
                        "{name} constant multiplication failed for value={value}, constant={constant}, expected={expected}: {result}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_m31_constant_multiplication() {
        test_constant_mul::<M31>();
    }

    #[test]
    fn test_babybear_constant_multiplication() {
        test_constant_mul::<BabyBear>();
    }

    fn test_compact_mul<C: U31Config>() {
        for a in boundary_values(C::MODULUS) {
            for b in boundary_values(C::MODULUS) {
                assert_binary::<C>(a, b, mul_mod(a, b, C::MODULUS), u31_mul_compact::<C>());
            }
        }

        let mut rng = StdRng::seed_from_u64(C::MODULUS as u64 ^ 0x0043_4f4d_5041_4354);
        for _ in 0..100 {
            let a = rng.gen_range(0..C::MODULUS);
            let b = rng.gen_range(0..C::MODULUS);
            assert_binary::<C>(a, b, mul_mod(a, b, C::MODULUS), u31_mul_compact::<C>());
        }
    }

    #[test]
    fn test_small_field_compact_multiplication() {
        test_compact_mul::<TestField257>();
        test_compact_mul::<TestField12289>();
    }

    #[test]
    fn test_small_field_bit_decomposition() {
        for value in boundary_values(TestField257::MODULUS) {
            let bits = (0..9).map(|i| (value >> i) & 1).collect::<Vec<_>>();
            let result = execute_script(script! {
                { value }
                { u31_to_bits_with_width(9) }
                for bit in bits {
                    { bit }
                    OP_EQUALVERIFY
                }
                OP_TRUE
            });
            assert!(result.success, "9-bit decomposition failed: {result}");
        }
    }

    #[test]
    fn test_small_field_centered_constant_multiplication() {
        test_constant_mul::<TestField257>();
        test_constant_mul::<TestField12289>();
    }

    #[test]
    fn test_small_field_multiplication_metrics_are_stable() {
        let constant = 173;
        let baseline = (1..TestField257::MODULUS)
            .map(|value| u31_mul_by_constant::<TestField257>(value).compile().len())
            .sum::<usize>();
        let centered = (1..TestField257::MODULUS)
            .map(|value| {
                u31_mul_by_constant_centered::<TestField257>(value)
                    .compile()
                    .len()
            })
            .sum::<usize>();
        assert!(
            centered < baseline,
            "signed centering must improve the mean"
        );

        let fragments = [
            ("test257_dynamic", u31_mul::<TestField257>(), 1_238),
            ("test257_compact", u31_mul_compact::<TestField257>(), 345),
            (
                "test257_constant",
                u31_mul_by_constant::<TestField257>(constant),
                167,
            ),
            (
                "test257_centered_constant",
                u31_mul_by_constant_centered::<TestField257>(constant),
                132,
            ),
            (
                "test257_full_lookup_8",
                u31_mul_by_constant_lookup_batch::<TestField257>(constant, 8),
                809,
            ),
            (
                "test257_half_lookup_8",
                u31_mul_by_constant_half_lookup_batch::<TestField257>(constant, 8),
                573,
            ),
            (
                "test12289_compact",
                u31_mul_compact::<TestField12289>(),
                517,
            ),
        ];
        for (name, fragment, expected_size) in fragments {
            assert_eq!(
                fragment.compile().len(),
                expected_size,
                "{name} size changed"
            );
        }

        assert_eq!(
            u31_push_mul_by_constant_table::<TestField257>(constant)
                .compile()
                .len(),
            626
        );
        assert_eq!(
            u31_drop_mul_by_constant_table::<TestField257>()
                .compile()
                .len(),
            129
        );
        assert_eq!(
            u31_push_half_mul_by_constant_table::<TestField257>(constant)
                .compile()
                .len(),
            248
        );
        assert_eq!(
            u31_drop_half_mul_by_constant_table::<TestField257>()
                .compile()
                .len(),
            65
        );
        for (name, operation, value, expected_stack) in [
            (
                "test257_compact",
                u31_mul_compact::<TestField257>(),
                256,
                15,
            ),
            (
                "test12289_compact",
                u31_mul_compact::<TestField12289>(),
                12_288,
                20,
            ),
            (
                "test257_centered",
                u31_mul_by_constant_centered::<TestField257>(constant),
                256,
                4,
            ),
        ] {
            let result = execute_script(script! {
                { value }
                if name.contains("compact") {
                    { value }
                }
                { operation }
                OP_DROP
                OP_TRUE
            });
            assert!(result.success, "{name} metric execution failed: {result}");
            assert_eq!(
                result.stats.max_nb_stack_items, expected_stack,
                "{name} stack changed"
            );
        }
    }

    #[test]
    fn test_u31_representations_and_negation() {
        for value in boundary_values(M31::MODULUS) {
            let negative_representation = value as i64 - M31::MODULUS as i64;
            let negated = if value == 0 { 0 } else { M31::MODULUS - value };
            let negated_v31 = if value == 0 {
                -(M31::MODULUS as i64)
            } else {
                -(value as i64)
            };

            for script in [
                script! {
                    { value }
                    { u31_to_v31::<M31>() }
                    { negative_representation }
                    OP_EQUAL
                },
                script! {
                    { value }
                    { u31_to_v31::<M31>() }
                    { v31_to_u31::<M31>() }
                    { value }
                    OP_EQUAL
                },
                script! {
                    { value }
                    { u31_neg::<M31>() }
                    { negated }
                    OP_EQUAL
                },
                script! {
                    { negative_representation }
                    { v31_neg::<M31>() }
                    { negated_v31 }
                    OP_EQUAL
                },
            ] {
                let result = execute_script(script);
                assert!(
                    result.success,
                    "representation test failed for {value}: {result}"
                );
            }
        }
    }

    fn push_ext(value: [u32; 4]) -> Script {
        script! {
            for coefficient in value.iter().rev() {
                { *coefficient }
            }
        }
    }

    fn verify_ext_only(expected: [u32; 4]) -> Script {
        script! {
            for coefficient in expected {
                { coefficient }
                OP_EQUALVERIFY
            }
        }
    }

    fn verify_ext(expected: [u32; 4]) -> Script {
        script! {
            { verify_ext_only(expected) }
            OP_TRUE
        }
    }

    fn ext_add(a: [u32; 4], b: [u32; 4], modulus: u32) -> [u32; 4] {
        std::array::from_fn(|i| add_mod(a[i], b[i], modulus))
    }

    fn ext_sub(a: [u32; 4], b: [u32; 4], modulus: u32) -> [u32; 4] {
        std::array::from_fn(|i| sub_mod(a[i], b[i], modulus))
    }

    fn ext_scale(a: [u32; 4], b: u32, modulus: u32) -> [u32; 4] {
        a.map(|coefficient| mul_mod(coefficient, b, modulus))
    }

    fn babybear4_mul(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
        let modulus = BabyBear::MODULUS;
        let mut product = [0u32; 7];
        for i in 0..4 {
            for j in 0..4 {
                product[i + j] = add_mod(product[i + j], mul_mod(a[i], b[j], modulus), modulus);
            }
        }
        [
            sub_mod(product[0], mul_mod(11, product[4], modulus), modulus),
            sub_mod(product[1], mul_mod(11, product[5], modulus), modulus),
            sub_mod(product[2], mul_mod(11, product[6], modulus), modulus),
            product[3],
        ]
    }

    fn complex_mul(a: [u32; 2], b: [u32; 2], modulus: u32) -> [u32; 2] {
        [
            sub_mod(
                mul_mod(a[0], b[0], modulus),
                mul_mod(a[1], b[1], modulus),
                modulus,
            ),
            add_mod(
                mul_mod(a[0], b[1], modulus),
                mul_mod(a[1], b[0], modulus),
                modulus,
            ),
        ]
    }

    fn qm31_mul(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
        let modulus = M31::MODULUS;
        let a0 = [a[0], a[1]];
        let a1 = [a[2], a[3]];
        let b0 = [b[0], b[1]];
        let b1 = [b[2], b[3]];
        let low = complex_mul(a0, b0, modulus);
        let high = complex_mul(a1, b1, modulus);
        let cross_left = complex_mul(a0, b1, modulus);
        let cross_right = complex_mul(a1, b0, modulus);
        let cross = [
            add_mod(cross_left[0], cross_right[0], modulus),
            add_mod(cross_left[1], cross_right[1], modulus),
        ];

        // y² = 2 + i, so (2 + i)(r + s*i) = (2r - s) + (r + 2s)i.
        let reduced_high = [
            sub_mod(add_mod(high[0], high[0], modulus), high[1], modulus),
            add_mod(high[0], add_mod(high[1], high[1], modulus), modulus),
        ];

        [
            add_mod(low[0], reduced_high[0], modulus),
            add_mod(low[1], reduced_high[1], modulus),
            cross[0],
            cross[1],
        ]
    }

    fn random_ext(rng: &mut StdRng, modulus: u32) -> [u32; 4] {
        std::array::from_fn(|_| rng.gen_range(0..modulus))
    }

    fn assert_ext_binary<C: U31ExtConfig>(
        a: [u32; 4],
        b: [u32; 4],
        expected: [u32; 4],
        operation: Script,
    ) {
        let result = execute_script(script! {
            { push_ext(a) }
            { push_ext(b) }
            { operation }
            { verify_ext(expected) }
        });
        assert!(result.success, "extension operation failed: {result}");
    }

    fn test_extension<C: U31ExtConfig>(reference_mul: fn([u32; 4], [u32; 4]) -> [u32; 4]) {
        let modulus = C::BaseFieldConfig::MODULUS;
        let mut rng = StdRng::seed_from_u64(modulus as u64 ^ 0x455854);

        let zero = [0; 4];
        let max = [modulus - 1; 4];
        for (a, b) in [(zero, zero), (zero, max), (max, max)] {
            assert_ext_binary::<C>(a, b, ext_add(a, b, modulus), u31ext_add::<C>());
            assert_ext_binary::<C>(a, b, ext_sub(a, b, modulus), u31ext_sub::<C>());
            assert_ext_binary::<C>(a, b, reference_mul(a, b), u31ext_mul::<C>());
        }

        for scalar in [0, 1, modulus - 1] {
            let expected = ext_scale(max, scalar, modulus);
            let supplied = execute_script(script! {
                { push_ext(max) }
                { scalar }
                { u31ext_mul_u31::<C>() }
                { verify_ext(expected) }
            });
            assert!(
                supplied.success,
                "boundary extension/base multiplication failed: {supplied}"
            );

            let constant = execute_script(script! {
                { push_ext(max) }
                { u31ext_mul_u31_by_constant::<C>(scalar) }
                { verify_ext(expected) }
            });
            assert!(
                constant.success,
                "boundary extension/constant multiplication failed: {constant}"
            );
        }

        for _ in 0..8 {
            let a = random_ext(&mut rng, modulus);
            let b = random_ext(&mut rng, modulus);
            assert_ext_binary::<C>(a, b, ext_add(a, b, modulus), u31ext_add::<C>());
            assert_ext_binary::<C>(a, b, ext_sub(a, b, modulus), u31ext_sub::<C>());
            assert_ext_binary::<C>(a, b, reference_mul(a, b), u31ext_mul::<C>());

            let scalar = rng.gen_range(0..modulus);
            let expected = ext_scale(a, scalar, modulus);
            let supplied = execute_script(script! {
                { push_ext(a) }
                { scalar }
                { u31ext_mul_u31::<C>() }
                { verify_ext(expected) }
            });
            assert!(
                supplied.success,
                "extension/base multiplication failed: {supplied}"
            );

            let constant = execute_script(script! {
                { push_ext(a) }
                { u31ext_mul_u31_by_constant::<C>(scalar) }
                { verify_ext(expected) }
            });
            assert!(
                constant.success,
                "extension/constant multiplication failed: {constant}"
            );
        }
    }

    #[test]
    fn test_qm31_extension() {
        test_extension::<QM31>(qm31_mul);
    }

    #[test]
    fn test_babybear4_extension() {
        test_extension::<BabyBear4>(babybear4_mul);
    }

    #[test]
    fn test_extension_stack_helpers() {
        let a = [1, 2, 3, 4];
        let b = [5, 6, 7, 8];

        let copy = execute_script(script! {
            { push_ext(a) }
            { push_ext(b) }
            { u31ext_copy::<QM31>(1) }
            { verify_ext_only(a) }
            { verify_ext_only(b) }
            { verify_ext_only(a) }
            OP_TRUE
        });
        assert!(copy.success, "extension copy failed: {copy}");

        let roll = execute_script(script! {
            { push_ext(a) }
            { push_ext(b) }
            { u31ext_roll::<QM31>(1) }
            { verify_ext_only(a) }
            { verify_ext_only(b) }
            OP_TRUE
        });
        assert!(roll.success, "extension roll failed: {roll}");

        let altstack = execute_script(script! {
            { push_ext(a) }
            { u31ext_toaltstack::<QM31>() }
            { u31ext_fromaltstack::<QM31>() }
            { verify_ext(a) }
        });
        assert!(
            altstack.success,
            "extension altstack round trip failed: {altstack}"
        );

        let equal = execute_script(script! {
            { push_ext(a) }
            { push_ext(a) }
            { u31ext_equalverify::<QM31>() }
            OP_TRUE
        });
        assert!(equal.success, "extension equality failed: {equal}");
    }

    #[test]
    fn test_u31_metrics_are_stable() {
        let representative_constant = 0x1234_5678;
        let fragments = [
            ("add", u31_add::<M31>(), 18),
            ("sub", u31_sub::<M31>(), 12),
            ("mul", u31_mul::<M31>(), 1400),
            (
                "mul_constant",
                u31_mul_by_constant::<M31>(representative_constant),
                736,
            ),
            ("qm31_add", u31ext_add::<QM31>(), 84),
            ("qm31_sub", u31ext_sub::<QM31>(), 63),
            ("qm31_mul", u31ext_mul::<QM31>(), 13_186),
            ("babybear4_mul", u31ext_mul::<BabyBear4>(), 13_441),
            ("qm31_mul_base", u31ext_mul_u31::<QM31>(), 4_642),
            (
                "qm31_mul_constant",
                u31ext_mul_u31_by_constant::<QM31>(representative_constant),
                2_950,
            ),
        ];

        for (name, fragment, expected_size) in fragments {
            assert_eq!(
                fragment.compile().len(),
                expected_size,
                "{name} size changed"
            );
        }

        let base_max = M31::MODULUS - 1;
        let extension_max = [base_max; 4];
        let executions = [
            (
                "add",
                script! { { base_max } { base_max } { u31_add::<M31>() } OP_DROP OP_TRUE },
                3,
            ),
            (
                "sub",
                script! { { base_max } { base_max } { u31_sub::<M31>() } OP_DROP OP_TRUE },
                3,
            ),
            (
                "mul",
                script! { { base_max } { base_max } { u31_mul::<M31>() } OP_DROP OP_TRUE },
                37,
            ),
            (
                "mul_constant",
                script! {
                    { base_max }
                    { u31_mul_by_constant::<M31>(representative_constant) }
                    OP_DROP OP_TRUE
                },
                4,
            ),
            (
                "qm31_add",
                script! {
                    { push_ext(extension_max) }
                    { push_ext(extension_max) }
                    { u31ext_add::<QM31>() }
                    OP_2DROP OP_2DROP OP_TRUE
                },
                9,
            ),
            (
                "qm31_mul",
                script! {
                    { push_ext(extension_max) }
                    { push_ext(extension_max) }
                    { u31ext_mul::<QM31>() }
                    OP_2DROP OP_2DROP OP_TRUE
                },
                52,
            ),
            (
                "babybear4_mul",
                script! {
                    { push_ext([BabyBear::MODULUS - 1; 4]) }
                    { push_ext([BabyBear::MODULUS - 1; 4]) }
                    { u31ext_mul::<BabyBear4>() }
                    OP_2DROP OP_2DROP OP_TRUE
                },
                53,
            ),
            (
                "qm31_mul_base",
                script! {
                    { push_ext(extension_max) }
                    { base_max }
                    { u31ext_mul_u31::<QM31>() }
                    OP_2DROP OP_2DROP OP_TRUE
                },
                133,
            ),
            (
                "qm31_mul_constant",
                script! {
                    { push_ext(extension_max) }
                    { u31ext_mul_u31_by_constant::<QM31>(representative_constant) }
                    OP_2DROP OP_2DROP OP_TRUE
                },
                7,
            ),
        ];

        for (name, execution, expected_depth) in executions {
            let result = execute_script(execution);
            assert!(
                result.success,
                "metric execution failed for {name}: {result}"
            );
            assert_eq!(
                result.stats.max_nb_stack_items, expected_depth,
                "{name} maximum stack depth changed"
            );
        }
    }
}
