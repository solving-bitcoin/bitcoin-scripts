use crate::support::script::*;

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

fn divide_magnitude_by_power(shift: u32) -> Script {
    assert!((1..=31).contains(&shift));
    script! {
        0 OP_TOALTSTACK
        if shift < 31 {
            for bit in (0..=(30 - shift)).rev() {
                OP_DUP
                { 1u32 << (shift + bit) }
                OP_GREATERTHANOREQUAL
                OP_IF
                    { 1u32 << (shift + bit) }
                    OP_SUB
                    OP_FROMALTSTACK
                    { 1u32 << bit }
                    OP_ADD
                    OP_TOALTSTACK
                OP_ENDIF
            }
        }
        OP_DROP
        OP_FROMALTSTACK
    }
}

/// Logical right shift of one canonical compressed u32 ScriptNum.
pub fn u32_compressed_rshift(shift: u32) -> Script {
    assert!((1..=31).contains(&shift));
    script! {
        OP_DUP
        { certify_compressed_word() }
        { normalize_compressed_word() }
        OP_SWAP
        OP_TOALTSTACK
        { divide_magnitude_by_power(shift) }
        OP_FROMALTSTACK
        OP_IF
            { 1u32 << (31 - shift) }
            OP_ADD
        OP_ENDIF
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::execute_script_with_inputs_strict;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn scriptnum(value: u32) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value as i32));
        bytes[..length].to_vec()
    }

    #[test]
    fn test_u32_compressed_rshift_boundaries_and_random_values() {
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
        let mut rng = ChaCha20Rng::seed_from_u64(0x5253_4846);
        for shift in 1..=31 {
            for &value in &boundaries {
                check_shift(value, shift);
            }
            for _ in 0..64 {
                check_shift(rng.gen(), shift);
            }
        }
    }

    #[test]
    fn test_u32_compressed_rshift_rejects_noncanonical_inputs() {
        for input in [vec![1, 0], vec![0, 0, 0, 0x80], vec![1, 0, 0, 0, 0]] {
            let result = execute_script_with_inputs_strict(
                script! { { u32_compressed_rshift(8) } },
                vec![input],
            );
            assert!(result.error.is_some(), "accepted malformed input: {result}");
        }
    }

    fn check_shift(value: u32, shift: u32) {
        let result = execute_script_with_inputs_strict(
            script! {
                { u32_compressed_rshift(shift) }
                { (value >> shift) as i64 }
                OP_EQUAL
            },
            vec![scriptnum(value)],
        );
        assert!(
            result.success,
            "compressed right shift failed for {value:08x} >> {shift}: {result}"
        );
    }
}
