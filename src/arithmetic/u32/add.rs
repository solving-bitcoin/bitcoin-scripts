use crate::arithmetic::u32::stack::{u32_compress, u32_uncompress};
use crate::arithmetic::u32::zip::{u32_copy_zip, u32_zip};
use crate::support::script::*;

/// Addition of two u8 elements at the top of the stack, pushing the carry after the sum
pub fn u8_add_carry() -> Script {
    script! {
        OP_ADD
        256
        OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_SUB
            1
        OP_ELSE
            OP_DROP
            0
        OP_ENDIF
    }
}

/// Addition of two u8 elements at the top of the stack, without minding the carry
pub fn u8_add() -> Script {
    script! {
        OP_ADD
        256
        OP_2DUP
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_SUB
            OP_0
        OP_ENDIF
        OP_DROP
    }
}

/// Modulo 2^32 addition of a-th and b-th u32 values, keeps the a-th element at stack
pub fn u32_add(a: u32, b: u32) -> Script {
    assert_ne!(a, b);
    script! {
        {u32_copy_zip(a, b)}

        // A0 + B0
        u8_add_carry
        OP_SWAP
        OP_TOALTSTACK

        // A1 + B1 + carry_0
        OP_ADD
        u8_add_carry
        OP_SWAP
        OP_TOALTSTACK

        // A2 + B2 + carry_1
        OP_ADD
        u8_add_carry
        OP_SWAP
        OP_TOALTSTACK

        // A3 + B3 + carry_2
        OP_ADD
        u8_add

        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK

        // Now there's the result C_3 C_2 C_1 C_0 on the stack
    }
}

/// Modulo 2^32 addition of a-th and b-th u32 values
pub fn u32_add_drop(a: u32, b: u32) -> Script {
    assert_ne!(a, b);
    script! {
        {u32_zip(a, b)}

        // A0 + B0
        u8_add_carry
        OP_SWAP
        OP_TOALTSTACK

        // A1 + B1 + carry_0
        OP_ADD
        u8_add_carry
        OP_SWAP
        OP_TOALTSTACK

        // A2 + B2 + carry_1
        OP_ADD
        u8_add_carry
        OP_SWAP
        OP_TOALTSTACK

        // A3 + B3 + carry_2
        OP_ADD
        u8_add

        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK

        // Now there's the result C_3 C_2 C_1 C_0 on the stack
    }
}

fn certify_compressed_word() -> Script {
    script! {
        OP_DUP
        OP_SIZE
        5
        OP_EQUAL
        OP_IF
            -2147483648
            OP_EQUALVERIFY
        OP_ELSE
            OP_DUP
            0
            OP_ADD
            OP_EQUALVERIFY
        OP_ENDIF
    }
}

/// Adds two canonical compressed u32 ScriptNums modulo `2^32`.
///
/// The top compressed word is added to the compressed word below it. Both
/// inputs are consumed and one canonical compressed result is returned.
pub fn u32_compressed_add() -> Script {
    script! {
        { certify_compressed_word() }
        OP_TOALTSTACK
        { certify_compressed_word() }
        { u32_uncompress() }
        OP_FROMALTSTACK
        { u32_uncompress() }
        { u32_add_drop(0, 1) }
        { u32_compress() }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::arithmetic::u32::stack::{u32_equal, u32_equalverify, u32_push};
    use crate::support::execution::{execute_script_with_inputs_strict, run};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn scriptnum(value: u32) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value as i32));
        bytes[..length].to_vec()
    }

    fn check_compressed_add(a: u32, b: u32) {
        let expected = a.wrapping_add(b);
        let result = execute_script_with_inputs_strict(
            script! {
                { u32_compressed_add() }
                { i64::from(expected as i32) }
                OP_EQUAL
            },
            vec![scriptnum(b), scriptnum(a)],
        );
        assert!(
            result.success,
            "compressed add failed for {a:08x}+{b:08x}: {result}"
        );
    }

    #[test]
    fn test_u32_add() {
        println!("u32_len: {}", u32_add_drop(1, 0).len());
        let mut rng = ChaCha20Rng::seed_from_u64(0x4330_4144);
        for _ in 0..1000 {
            let x = rng.gen();
            let y = rng.gen_range(0..=u32::MAX - x);
            let script_add_drop = script! {
                { u32_push(x) }
                { u32_push(y) }
                { u32_add_drop(1, 0) }
                { u32_push(x + y) }
                { u32_equal() }
            };
            let script_add = script! {
                { u32_push(x) }
                { u32_push(y) }
                { u32_add(1, 0) }
                { u32_push(x + y) }
                { u32_equalverify() }
                { u32_push(x) }
                { u32_equal() }
            };
            run(script_add_drop);
            run(script_add);
        }
    }
    #[test]
    fn test_u8_adds_exhaustive() {
        for a in 0..256 {
            for b in 0..256 {
                let script_without_carry = script! {
                  { a }
                  { b }
                  { u8_add() }
                  { (a + b) % 256 }
                  OP_EQUAL
                };
                let script_with_carry = script! {
                    { a }
                    { b }
                    { u8_add_carry() }
                    { ((a + b) >= 256) as u32 }
                    OP_EQUAL
                    OP_TOALTSTACK
                    { (a + b) % 256 }
                    OP_EQUAL
                    OP_FROMALTSTACK
                    OP_BOOLAND
                };
                run(script_without_carry);
                run(script_with_carry);
            }
        }
    }

    #[test]
    fn test_compressed_add_boundaries_and_random_values() {
        for &(a, b) in &[
            (0, 0),
            (1, 1),
            (0x7fff_ffff, 1),
            (0x8000_0000, 0x8000_0000),
            (u32::MAX, 1),
            (0xffff_fffe, 3),
        ] {
            check_compressed_add(a, b);
        }

        let mut rng = rand::thread_rng();
        for _ in 0..64 {
            check_compressed_add(rng.gen(), rng.gen());
        }
    }

    #[test]
    fn test_compressed_add_rejects_noncanonical_inputs() {
        let cases = [
            vec![vec![1, 0], scriptnum(2)],
            vec![vec![0, 0, 0, 0x80], scriptnum(2)],
            vec![vec![1, 0, 0, 0, 0], scriptnum(2)],
            vec![scriptnum(1), vec![2, 0]],
        ];
        for witness in cases {
            let result = execute_script_with_inputs_strict(
                script! {
                    { u32_compressed_add() }
                    OP_1
                },
                witness,
            );
            assert!(!result.success, "noncanonical input was accepted: {result}");
        }
    }
}
