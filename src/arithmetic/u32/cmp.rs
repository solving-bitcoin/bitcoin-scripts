use crate::support::script::*;

fn u32_cmp(comparison: Script) -> Script {
    script! {
        4
        OP_ROLL
        OP_SWAP
        { comparison.clone() }
        OP_SWAP

        4
        OP_ROLL
        OP_2DUP
        OP_EQUAL
        3
        OP_ROLL
        OP_BOOLAND
        OP_SWAP
        OP_ROT
        { comparison.clone() }
        OP_BOOLOR
        OP_SWAP

        3
        OP_ROLL
        OP_2DUP
        OP_EQUAL
        3
        OP_ROLL
        OP_BOOLAND
        OP_SWAP
        OP_ROT
        { comparison.clone() }
        OP_BOOLOR
        OP_SWAP

        OP_ROT
        OP_2DUP
        OP_EQUAL
        3
        OP_ROLL
        OP_BOOLAND
        OP_SWAP
        OP_ROT
        { comparison }
        OP_BOOLOR
    }
}

fn u32_cmp_or_equal(comparison: Script) -> Script {
    script! {
        OP_2OVER
        OP_2OVER
        8
        OP_PICK
        OP_EQUAL
        OP_SWAP
        9
        OP_PICK
        OP_EQUAL
        OP_BOOLAND
        OP_SWAP
        9
        OP_PICK
        OP_EQUAL
        OP_BOOLAND
        OP_SWAP
        9
        OP_PICK
        OP_EQUAL
        OP_BOOLAND
        OP_TOALTSTACK
        { u32_cmp(comparison) }
        OP_FROMALTSTACK
        OP_BOOLOR
    }
}

/// Unsigned less-than comparison of the top two u32 values.
pub fn u32_lessthan() -> Script {
    u32_cmp(script! { OP_LESSTHAN })
}

/// Signed two's-complement less-than comparison of the top two u32 values.
///
/// The four byte limbs must already be canonical values in `0..=255`. The
/// words are interpreted as i32 values without changing their stack encoding.
pub fn u32_signed_lessthan() -> Script {
    script! {
        // Save the sign bit of the lower (left) word, then the top (right) word.
        7 OP_PICK
        128 OP_GREATERTHANOREQUAL
        OP_TOALTSTACK
        3 OP_PICK
        128 OP_GREATERTHANOREQUAL
        OP_TOALTSTACK

        { u32_lessthan() }
        OP_TOALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK

        // Different signs decide the result; equal signs use unsigned order.
        OP_SWAP
        OP_2DUP
        OP_EQUAL
        OP_NOT
        OP_IF
            OP_DROP
            OP_SWAP
            OP_DROP
        OP_ELSE
            OP_2DROP
        OP_ENDIF
    }
}

/// Unsigned greater-than comparison of the top two u32 values.
pub fn u32_greaterthan() -> Script {
    u32_cmp(script! { OP_GREATERTHAN })
}

/// Unsigned less-than-or-equal comparison of the top two u32 values.
pub fn u32_lessthanorequal() -> Script {
    u32_cmp_or_equal(script! { OP_LESSTHAN })
}

/// Unsigned greater-than-or-equal comparison of the top two u32 values.
pub fn u32_greaterthanorequal() -> Script {
    u32_cmp_or_equal(script! { OP_GREATERTHAN })
}

fn certify_compressed_word() -> Script {
    script! {
        OP_SIZE
        5
        OP_NUMEQUAL
        OP_IF
            OP_DUP
            -2147483648
            OP_EQUALVERIFY
        OP_ELSE
            OP_DUP
            OP_DUP
            0
            OP_ADD
            OP_EQUALVERIFY
        OP_ENDIF
        OP_DROP
    }
}

fn normalize_compressed_word() -> Script {
    script! {
        OP_SIZE 5 OP_NUMEQUAL
        OP_IF
            { -2_147_483_648i64 } OP_EQUALVERIFY
            1 0
        OP_ELSE
            OP_DUP
            0
            OP_LESSTHAN
            OP_IF
                { 0x7fff_ffffu32 } OP_ADD OP_1ADD
                1 OP_SWAP
            OP_ELSE
                0 OP_SWAP
            OP_ENDIF
        OP_ENDIF
    }
}

/// Unsigned less-than comparison of two canonical compressed u32 ScriptNums.
pub fn u32_compressed_lessthan() -> Script {
    script! {
        OP_DUP
        { certify_compressed_word() }
        OP_TOALTSTACK
        OP_DUP
        { certify_compressed_word() }
        OP_FROMALTSTACK
        OP_SWAP
        { normalize_compressed_word() }
        OP_SWAP
        OP_TOALTSTACK
        OP_SWAP
        OP_TOALTSTACK
        OP_FROMALTSTACK
        { normalize_compressed_word() }
        OP_SWAP
        OP_TOALTSTACK
        OP_LESSTHAN
        OP_FROMALTSTACK
        OP_FROMALTSTACK

        // The normalized values are ordered within each sign half. Across
        // halves, nonnegative values are always below negative values.
        OP_IF
            OP_IF
            OP_ELSE
                OP_DROP
                OP_0
            OP_ENDIF
        OP_ELSE
            OP_IF
                OP_DROP
                OP_1
            OP_ENDIF
        OP_ENDIF
    }
}

/// Compare one canonical compressed u32 ScriptNum with an embedded threshold.
///
/// The witness value is the left operand and `value` is the right operand.
/// Values with the high bit set are embedded as their signed ScriptNum
/// representation, matching the compressed-u32 wire format.
pub fn u32_compressed_lessthan_constant(value: u32) -> Script {
    let constant = i64::from(value as i32);
    script! {
        { constant }
        { u32_compressed_lessthan() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::u32::stack::u32_push;
    use crate::support::execution::{execute_script, execute_script_with_inputs_strict, run};
    use rand::Rng;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const SIGNED_COMPARISON_SEED: u64 = 0x5532_434f_4d50_0001;
    const SIGNED_COMPARISON_RANDOM_CASES: usize = 256;

    #[test]
    fn test_u32_comparisons() {
        let boundaries = [
            0,
            1,
            0xff,
            0x100,
            0x7fff_ffff,
            0x8000_0000,
            0xffff_fffe,
            u32::MAX,
        ];

        for &a in &boundaries {
            for &b in &boundaries {
                check_comparisons(a, b);
            }
        }

        let mut rng = rand::thread_rng();
        for _ in 0..256 {
            check_comparisons(rng.gen(), rng.gen());
        }
    }

    #[test]
    fn test_u32_signed_less_than() {
        let boundaries = [0, 1, 0x7fff_ffff, 0x8000_0000, 0x8000_0001, 0xffff_ffff];

        for &a in &boundaries {
            for &b in &boundaries {
                check_signed_less_than(a, b);
            }
        }

        let mut rng = ChaCha20Rng::seed_from_u64(SIGNED_COMPARISON_SEED);
        for _ in 0..SIGNED_COMPARISON_RANDOM_CASES {
            check_signed_less_than(rng.gen(), rng.gen());
        }
    }

    fn check_signed_less_than(a: u32, b: u32) {
        let script = script! {
            { u32_push(a) }
            { u32_push(b) }
            { u32_signed_lessthan() }
            { ((a as i32) < (b as i32)) as u32 }
            OP_EQUAL
        };
        run(script);
    }

    fn scriptnum(value: u32) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value as i32));
        bytes[..length].to_vec()
    }

    fn check_compressed_lessthan(a: u32, b: u32) {
        let result = execute_script_with_inputs_strict(
            script! {
                { u32_compressed_lessthan() }
                { (a < b) as u32 }
                OP_EQUAL
            },
            vec![scriptnum(a), scriptnum(b)],
        );
        assert!(
            result.success,
            "compressed less-than failed for {a:08x} < {b:08x}: {result}"
        );
    }

    #[test]
    fn test_u32_compressed_lessthan_boundaries_and_random_values() {
        let boundaries = [
            0,
            1,
            0xff,
            0x100,
            0x7fff_ffff,
            0x8000_0000,
            0xffff_fffe,
            u32::MAX,
        ];
        for &a in &boundaries {
            for &b in &boundaries {
                check_compressed_lessthan(a, b);
            }
        }

        let mut rng = ChaCha20Rng::seed_from_u64(0x4330_4c54);
        for _ in 0..256 {
            check_compressed_lessthan(rng.gen(), rng.gen());
        }
    }

    #[test]
    fn test_u32_compressed_lessthan_rejects_noncanonical_inputs() {
        for inputs in [
            vec![vec![1, 0], scriptnum(1)],
            vec![vec![0, 0, 0, 0x80], scriptnum(0)],
            vec![vec![1, 0, 0, 0, 0], scriptnum(0)],
        ] {
            let result = execute_script_with_inputs_strict(
                script! { { u32_compressed_lessthan() } },
                inputs,
            );
            assert!(
                result.error.is_some(),
                "accepted malformed compressed input: {result}"
            );
        }
    }

    #[test]
    fn test_u32_compressed_lessthan_constant_boundaries() {
        let boundaries = [
            0,
            1,
            0xff,
            0x100,
            0x7fff_ffff,
            0x8000_0000,
            0xffff_fffe,
            u32::MAX,
        ];
        for &input in &boundaries {
            for &threshold in &boundaries {
                let result = execute_script_with_inputs_strict(
                    script! {
                        { u32_compressed_lessthan_constant(threshold) }
                        { (input < threshold) as u32 }
                        OP_EQUAL
                    },
                    vec![scriptnum(input)],
                );
                assert!(
                    result.success,
                    "constant compressed less-than failed for {input:08x} < {threshold:08x}: {result}"
                );
            }
        }
    }

    #[test]
    fn test_u32_compressed_lessthan_constant_rejects_malformed_input() {
        for raw in [vec![1, 0], vec![0, 0, 0, 0x80], vec![1, 0, 0, 0, 0]] {
            let result = execute_script_with_inputs_strict(
                script! { { u32_compressed_lessthan_constant(0x1234_5678) } },
                vec![raw],
            );
            assert!(
                result.error.is_some(),
                "accepted malformed compressed input: {result}"
            );
        }
    }

    #[test]
    fn test_u32_compressed_lessthan_constant_preserves_surrounding_state() {
        let input = i64::from(0x1234_5678u32 as i32);
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            { input }
            { u32_compressed_lessthan_constant(0x8000_0000) }
            OP_1 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "constant compressed less-than changed surrounding state: {result}"
        );
    }

    fn check_comparisons(a: u32, b: u32) {
        let cases = [
            (u32_lessthan(), a < b),
            (u32_greaterthan(), a > b),
            (u32_lessthanorequal(), a <= b),
            (u32_greaterthanorequal(), a >= b),
        ];

        for (comparison, expected) in cases {
            let script = script! {
                { u32_push(a) }
                { u32_push(b) }
                { comparison }
                { expected as u32 }
                OP_EQUAL
            };
            run(script);
        }
    }
}
