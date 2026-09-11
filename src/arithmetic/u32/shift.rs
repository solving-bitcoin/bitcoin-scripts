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

fn double_magnitude() -> Script {
    script! {
        OP_DUP
        { 0x4000_0000u32 }
        OP_GREATERTHANOREQUAL
        OP_IF
            { 0x4000_0000u32 }
            OP_SUB
            OP_DUP
            OP_ADD
            { 0x7fff_ffffu32 }
            OP_SUB
            OP_1SUB
        OP_ELSE
            OP_DUP
            OP_ADD
        OP_ENDIF
    }
}

/// Logical left shift of one canonical compressed u32 ScriptNum.
pub fn u32_compressed_lshift(shift: u32) -> Script {
    assert!((1..=31).contains(&shift));
    script! {
        OP_DUP
        { certify_compressed_word() }
        { normalize_compressed_word() }
        OP_SWAP
        OP_DROP
        for index in 0..shift {
            { double_magnitude() }
            if index + 1 < shift {
                { normalize_compressed_word() }
                OP_SWAP
                OP_DROP
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::execute_raw_script_with_inputs_strict;
    use crate::support::script::ScriptCompilation;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn scriptnum(value: u32) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value as i32));
        bytes[..length].to_vec()
    }

    #[test]
    fn test_u32_compressed_lshift_boundaries_and_random_values() {
        let boundaries = [
            0,
            1,
            0xff,
            0x100,
            0x4000_0000,
            0x7fff_ffff,
            0x8000_0000,
            0xffff_fffe,
            u32::MAX,
        ];
        let mut rng = ChaCha20Rng::seed_from_u64(0x4c53_4846);
        for shift in 1..=31 {
            let script = script! {
                { u32_compressed_lshift(shift) }
            }
            .compile_with_policy()
            .to_bytes();
            for &value in &boundaries {
                check_shift(&script, value, shift);
            }
            if matches!(shift, 1 | 2 | 7 | 8 | 15 | 16 | 23 | 31) {
                for _ in 0..16 {
                    check_shift(&script, rng.gen(), shift);
                }
            }
        }
    }

    #[test]
    fn test_u32_compressed_lshift_rejects_noncanonical_inputs() {
        for input in [vec![1, 0], vec![0, 0, 0, 0x80], vec![1, 0, 0, 0, 0]] {
            let result = execute_raw_script_with_inputs_strict(
                script! { { u32_compressed_lshift(8) } }
                    .compile_with_policy()
                    .to_bytes(),
                vec![input],
            );
            assert!(result.error.is_some(), "accepted malformed input: {result}");
        }
    }

    fn check_shift(script: &[u8], value: u32, shift: u32) {
        let result = execute_raw_script_with_inputs_strict(script.to_vec(), vec![scriptnum(value)]);
        assert!(
            result.error.is_none(),
            "compressed left shift failed for {value:08x} << {shift}: {result}"
        );
        assert_eq!(
            result.final_stack.get(0),
            scriptnum((value << shift) as u32),
            "wrong compressed output for {value:08x} << {shift}: {result}"
        );
    }
}
