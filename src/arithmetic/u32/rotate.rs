use super::stack::verify_canonical_byte;
use crate::support::script::*;

/// Right rotation of an u32 element by 16 bits
pub fn u32_rrot16() -> Script {
    script! {
      OP_2SWAP
    }
}

/// Checked right rotation of a four-byte u32 word by sixteen bits.
pub fn u32_rrot16_checked() -> Script {
    script! {
        for _ in 0..4 {
            { verify_canonical_byte() }
            OP_TOALTSTACK
        }
        for _ in 0..4 {
            OP_FROMALTSTACK
        }
        { u32_rrot16() }
    }
}

/// Right rotation of an u32 element by 8 bits
pub fn u32_rrot8() -> Script {
    script! {
      OP_2SWAP
      3 OP_ROLL
    }
}

/// Checked right rotation of a four-byte u32 word by eight bits.
pub fn u32_rrot8_checked() -> Script {
    script! {
        for _ in 0..4 {
            { verify_canonical_byte() }
            OP_TOALTSTACK
        }
        for _ in 0..4 {
            OP_FROMALTSTACK
        }
        { u32_rrot8() }
    }
}

/// Right rotation of a u32 word by the fixed seven-bit SHA-256 rotation.
pub fn u8_rrot7(i: u32) -> Script {
    let roll_script = match i {
        0 => script! {},
        1 => script! { OP_SWAP },
        2 => script! { OP_ROT },
        _ => script! { {i} OP_ROLL },
    };
    script! {
        { roll_script }
        128
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

/// Right rotation of an u32 element by 7 bits
pub fn u32_rrot7() -> Script {
    script! {
        // First Byte
        {u8_rrot7(0)}

        // Second byte
        {u8_rrot7(2)}

        OP_TOALTSTACK
        OP_DUP
        OP_ADD
        OP_ADD
        OP_FROMALTSTACK

        // Third byte
        {u8_rrot7(3)}

        OP_TOALTSTACK
        OP_DUP
        OP_ADD
        OP_ADD
        OP_FROMALTSTACK

        // Fourth byte
        {u8_rrot7(4)}

        OP_TOALTSTACK
        OP_DUP
        OP_ADD
        OP_ADD
        OP_FROMALTSTACK

        // Close the circle
        4 OP_ROLL
        OP_DUP
        OP_ADD
        OP_ADD

        OP_SWAP
        OP_2SWAP
        OP_SWAP
    }
}

/// Checked right rotation of a four-byte u32 word by seven bits.
pub fn u32_rrot7_checked() -> Script {
    script! {
        for _ in 0..4 {
            { verify_canonical_byte() }
            OP_TOALTSTACK
        }
        for _ in 0..4 {
            OP_FROMALTSTACK
        }
        { u32_rrot7() }
    }
}

/// Extracts (puts it at the top of the stack) the most significant bit of the u8 number and multiplies it by 2 modulo 256
pub fn u8_extract_1bit() -> Script {
    script! {
        OP_DUP
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

/// Extracts (puts them at the top of the stack as the sum) the h most significant bits of the u8 number and multiplies it by 2^h modulo 256
pub fn u8_extract_hbit(hbit: usize) -> Script {
    assert!((1..8).contains(&hbit));
    if hbit == 1 {
        return u8_extract_1bit();
    }
    let x: u32 = 1 << (hbit - 1);
    script! {
        0
        OP_TOALTSTACK

        for i in 0..hbit
        {
            128
            OP_2DUP
            OP_GREATERTHANOREQUAL
            OP_IF
                OP_SUB
                OP_FROMALTSTACK
                { x >> i }
                OP_ADD
                OP_TOALTSTACK
                OP_DUP
            OP_ENDIF
            OP_DROP
            OP_DUP
            OP_ADD
        }

        OP_FROMALTSTACK
    }
}

/// Checked form of [`u8_extract_hbit`].
pub fn u8_extract_hbit_checked(hbit: usize) -> Script {
    script! {
        OP_DUP 0 256 OP_WITHIN OP_VERIFY
        { u8_extract_hbit(hbit) }
    }
}
/// Reorders (reverse and rotate) the bytes of an u32 number, assuming the starting order is 1 2 3 4 (4 being at the top):
/// if offset is 0, then reorder is 4 3 2 1
/// if offset is 1, then reorder is 1 4 3 2
/// if offset is 2, then reorder is 2 1 4 3
/// if offset is 3, then reorder is 3 2 1 4
pub fn byte_reorder(offset: usize) -> Script {
    assert!((0..4).contains(&offset));
    if offset == 0 {
        script! {
            OP_SWAP
            OP_2SWAP
            OP_SWAP
        }
    } else if offset == 1 {
        return script! {
            OP_SWAP
            OP_ROT
        };
    } else if offset == 2 {
        return script! {
            OP_SWAP
            OP_2SWAP
            OP_SWAP
            OP_2SWAP
        };
    } else
    /* if offset == 3 */
    {
        return script! {
            OP_SWAP
            OP_ROT
            OP_2SWAP
        };
    }
}

/// Rotates the bits of a u32 number by rot_num
pub fn u32_rrot(rot_num: usize) -> Script {
    assert!((0..32).contains(&rot_num));
    let specific_optimize: Option<Script> = match rot_num {
        0 => script! {}.into(),            // 0
        7 => script! {u32_rrot7}.into(),   // 76
        8 => script! {u32_rrot8}.into(),   // 3
        16 => script! {u32_rrot16}.into(), // 1
        23 => script! {u32_rrot16 u32_rrot7}.into(),
        24 => script! {3 OP_ROLL}.into(), // 2
        _ => None,
    };

    if let Some(res) = specific_optimize {
        return res;
    }

    let remainder: usize = rot_num % 8;

    let hbit: usize = 8 - remainder;
    let offset: usize = (rot_num - remainder) / 8;

    script! {
        {u8_extract_hbit(hbit)}
        OP_ROT {u8_extract_hbit(hbit)}
        4 OP_ROLL {u8_extract_hbit(hbit)}
        6 OP_ROLL {u8_extract_hbit(hbit)}

        7 OP_ROLL
        OP_ADD
        OP_TOALTSTACK

        OP_ADD
        OP_TOALTSTACK

        OP_ADD
        OP_TOALTSTACK

        OP_ADD
        OP_TOALTSTACK

        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        {byte_reorder(offset)}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::test_helpers::{run_with_witness, word_witness};
    use crate::arithmetic::u32::stack::*;
    use crate::support::execution::run;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    fn rrot(x: u32, n: usize) -> u32 {
        if n == 0 {
            return x;
        }
        (x >> n) | (x << (32 - n))
    }

    #[test]
    fn test_rrot() {
        let scripts: Vec<_> = (0..32)
            .map(|i| {
                println!("u32_rrot({}): {} bytes", i, u32_rrot(i).len());
                script! {
                    { u32_rrot(i) }
                    { u32_equal() }
                }
                .compile_with_policy()
                .to_bytes()
            })
            .collect();
        let mut rng = StdRng::seed_from_u64(0x7533325f726f74);
        for _ in 0..1000 {
            let x: u32 = rng.gen();
            for (i, script) in scripts.iter().enumerate() {
                run_with_witness(script, word_witness(rrot(x, i)).chain(word_witness(x)));
            }
        }
    }

    #[test]
    fn fixed_byte_rotations_match_reference() {
        for (fragment, expected) in [
            (u32_rrot8(), 0x4411_2233),
            (u32_rrot16(), 0x3344_1122),
            (u32_rrot(24), 0x2233_4411),
        ] {
            let result = crate::support::execution::execute_script_with_inputs_strict(
                script! {
                    99 OP_TOALTSTACK
                    { fragment }
                    { u32_push(expected) }
                    { u32_equalverify() }
                    OP_FROMALTSTACK 99 OP_EQUAL
                },
                vec![vec![0x11], vec![0x22], vec![0x33], vec![0x44]],
            );
            assert!(result.success, "fixed rotation failed: {result}");
        }
    }

    #[test]
    fn fixed_rotation7_matches_reference_boundaries() {
        for value in [0, 1, 0x80, 0x1122_3344, 0x8000_0000, u32::MAX] {
            let expected = rrot(value, 7);
            run(script! {
                { u32_push(value) }
                { u32_rrot7() }
                { u32_push(expected) }
                { u32_equal() }
                OP_VERIFY OP_TRUE
            });
        }
    }

    #[test]
    fn fixed_rotation7_preserves_runtime_stack_state() {
        let result = crate::support::execution::execute_script_with_inputs_strict(
            script! {
                99 OP_TOALTSTACK
                { u32_rrot7() }
                { u32_push(0x8822_4466) }
                { u32_equalverify() }
                OP_FROMALTSTACK 99 OP_EQUAL
            },
            vec![vec![0x11], vec![0x22], vec![0x33], vec![0x44]],
        );
        assert!(
            result.success,
            "rotation or stack preservation failed: {result}"
        );
    }

    #[test]
    fn fixed_rotation7_rejects_a_short_word_with_an_execution_error() {
        let result = crate::support::execution::execute_script_with_inputs_strict(
            script! { { u32_rrot7() } },
            vec![vec![1u8]; 3],
        );
        assert!(!result.success);
        assert!(matches!(
            result.error,
            Some(bitcoin_scriptexec::ExecError::InvalidStackOperation)
        ));
    }

    #[test]
    fn test_canonical_rrot8() {
        let script = script! {
            { u32_rrot8_checked() }
            { u32_equal() }
        }
        .compile_with_policy()
        .to_bytes();
        for x in [0, 1, 0x0102_0304, 0x8000_0000, u32::MAX] {
            run_with_witness(&script, word_witness(rrot(x, 8)).chain(word_witness(x)));
        }
    }

    #[test]
    fn test_canonical_rrot8_rejects_malformed_bytes() {
        let script = script! {
            { u32_rrot8_checked() }
            OP_2DROP OP_2DROP
            OP_TRUE
        };
        for position in 0..4 {
            for replacement in [vec![1, 0], vec![0, 1], vec![0x80]] {
                let mut witness = vec![vec![1]; 4];
                witness[position] = replacement;
                let result =
                    crate::support::execution::execute_script_with_inputs(script.clone(), witness);
                assert!(
                    !result.success,
                    "accepted malformed byte at {position}: {result}"
                );
            }
        }
    }

    #[test]
    fn test_canonical_rrot8_preserves_surrounding_stacks() {
        let result = crate::support::execution::execute_script_with_inputs_strict(
            script! {
                99 OP_TOALTSTACK
                { u32_rrot8_checked() }
                OP_2DROP OP_2DROP
                77 OP_EQUALVERIFY
                OP_FROMALTSTACK 99 OP_EQUALVERIFY
                OP_TRUE
            },
            vec![vec![77], vec![1], vec![2], vec![3], vec![4]],
        );
        assert!(result.success, "stack preservation failed: {result}");
    }
    #[test]
    fn test_canonical_rrot16() {
        let script = script! {
            { u32_rrot16_checked() }
            { u32_equal() }
        }
        .compile_with_policy()
        .to_bytes();
        for x in [0, 1, 0x0102_0304, 0x8000_0000, u32::MAX] {
            run_with_witness(&script, word_witness(rrot(x, 16)).chain(word_witness(x)));
        }
    }

    #[test]
    fn test_canonical_rrot16_rejects_malformed_bytes() {
        let script = script! {
            { u32_rrot16_checked() }
            OP_2DROP OP_2DROP
            OP_TRUE
        };
        for position in 0..4 {
            for replacement in [vec![1, 0], vec![0, 1], vec![0x80]] {
                let mut witness = vec![vec![1]; 4];
                witness[position] = replacement;
                let result =
                    crate::support::execution::execute_script_with_inputs(script.clone(), witness);
                assert!(
                    !result.success,
                    "accepted malformed byte at {position}: {result}"
                );
            }
        }
    }

    #[test]
    fn test_canonical_rrot16_preserves_surrounding_stacks() {
        let result = crate::support::execution::execute_script_with_inputs_strict(
            script! {
                99 OP_TOALTSTACK
                { u32_rrot16_checked() }
                OP_2DROP OP_2DROP
                77 OP_EQUALVERIFY
                OP_FROMALTSTACK 99 OP_EQUALVERIFY
                OP_TRUE
            },
            vec![vec![77], vec![1], vec![2], vec![3], vec![4]],
        );
        assert!(result.success, "stack preservation failed: {result}");
    }

    #[test]
    fn test_extract_hbit() {
        let scripts: Vec<_> = (1..8)
            .map(|h| {
                script! {
                    { u8_extract_hbit(h) }
                    OP_ROT OP_EQUALVERIFY
                    OP_EQUAL
                }
                .compile_with_policy()
                .to_bytes()
            })
            .collect();
        for x in 0..256 {
            for (i, script) in scripts.iter().enumerate() {
                let h = i + 1;
                run_with_witness(script, [(x << h) % 256, x >> (8 - h), x]);
            }
        }
    }

    #[test]
    fn test_checked_extract_hbit_rejects_non_bytes() {
        for h in [1, 4, 7] {
            for x in 0..=255 {
                let result = crate::support::execution::execute_script(script! {
                    { x }
                    { u8_extract_hbit_checked(h) }
                    { x >> (8 - h) } OP_EQUALVERIFY
                    { (x << h) % 256 } OP_EQUAL
                });
                assert!(result.success, "failed for x={x}, h={h}: {result}");
            }
            for x in [-1, 256, 512] {
                let result = crate::support::execution::execute_script(script! {
                    { x }
                    { u8_extract_hbit_checked(h) }
                });
                assert!(!result.success, "accepted non-byte x={x}, h={h}");
            }
        }
    }

    #[test]
    fn test_checked_rrot7() {
        let script = script! {
            { u32_rrot7_checked() }
            { u32_equal() }
        }
        .compile_with_policy()
        .to_bytes();
        let mut rng = StdRng::seed_from_u64(0x7533325f726f745f);
        for _ in 0..1000 {
            let x: u32 = rng.gen();
            run_with_witness(&script, word_witness(rrot(x, 7)).chain(word_witness(x)));
        }
    }

    #[test]
    fn test_checked_rrot7_rejects_malformed_bytes() {
        let script = script! {
            { u32_rrot7_checked() }
            for _ in 0..4 { OP_DROP }
            OP_TRUE
        };
        for position in 0..4 {
            for replacement in [vec![1, 0], vec![0, 1], vec![0x80]] {
                let mut witness = vec![vec![1]; 4];
                witness[position] = replacement.clone();
                let result =
                    crate::support::execution::execute_script_with_inputs(script.clone(), witness);
                assert!(
                    !result.success,
                    "accepted malformed byte at {position} ({replacement:?}): {result}"
                );
            }
        }
    }

    #[test]
    fn test_checked_rrot7_preserves_surrounding_stacks() {
        let result = crate::support::execution::execute_script_with_inputs_strict(
            script! {
                99 OP_TOALTSTACK
                { u32_rrot7_checked() }
                for _ in 0..4 { OP_DROP }
                77 OP_EQUALVERIFY
                OP_FROMALTSTACK 99 OP_EQUALVERIFY
                OP_TRUE
            },
            vec![vec![77], vec![1], vec![2], vec![3], vec![4]],
        );
        assert!(result.success, "{result}");
    }
    #[test]
    fn byte_reorder_covers_all_offsets() {
        for (offset, expected) in [
            (0, 0x4433_2211),
            (1, 0x1144_3322),
            (2, 0x2211_4433),
            (3, 0x3322_1144),
        ] {
            let result = crate::support::execution::execute_script(script! {
                { u32_push(0x1122_3344) }
                { byte_reorder(offset) }
                { u32_push(expected) }
                { u32_equal() }
                OP_VERIFY
                OP_TRUE
            });
            assert!(result.success, "offset {offset} failed: {result}");
        }
    }

    #[test]
    fn byte_reorder_rejects_invalid_offsets() {
        assert!(std::panic::catch_unwind(|| byte_reorder(4)).is_err());
    }
}
