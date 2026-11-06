//! Extended Hamming (8,4) decoding over canonical ScriptNum bytes.

use crate::{
    arithmetic::{
        scriptint::mul_by_constant, u31::u31_to_bits_with_width, u32::stack::verify_canonical_byte,
    },
    support::script::*,
};

fn xor_into(positions: &[u32], above: u32) -> Script {
    script! {
        for &position in positions {
            {position - 1 + above} OP_PICK OP_NUMNOTEQUAL
        }
    }
}

fn parity(positions: &[u32], above: u32) -> Script {
    let (first, remaining) = positions.split_first().unwrap();
    script! {
        {first - 1 + above} OP_PICK
        {xor_into(remaining, above + 1)}
    }
}

/// Decode the unique extended-Hamming codeword within distance one.
///
/// A canonical numeric byte becomes its canonical data nibble. Bit positions
/// are numbered from the least significant bit starting at one. Positions
/// 3, 5, 6, and 7 carry data, low bit first, and position 8 is overall parity.
/// Rejects words outside all distance-one balls. No hints are required.
pub fn decode_hamming84() -> Script {
    script! {
        {verify_canonical_byte()} {u31_to_bits_with_width(8)}
        {parity(&[1, 3, 5, 7], 0)}
        // Reuse s1 as the first half of overall parity.
        OP_DUP {xor_into(&[2, 4, 6, 8], 2)} OP_TOALTSTACK
        {parity(&[2, 3, 6, 7], 1)}
        {parity(&[4, 5, 6, 7], 2)}
        {mul_by_constant(4)} OP_SWAP {mul_by_constant(2)} OP_ADD OP_ADD
        OP_FROMALTSTACK
        OP_NOTIF OP_DUP 0 OP_NUMEQUALVERIFY OP_ENDIF

        // Accumulate corrected data bits from most to least significant.
        0
        for position in [7u32, 6, 5, 3] {
            OP_DUP OP_ADD
            {position + 1} OP_PICK
            2 OP_PICK {position} OP_NUMEQUAL OP_NUMNOTEQUAL OP_ADD
        }
        OP_TOALTSTACK
        for _ in 0..9 {OP_DROP}
        OP_FROMALTSTACK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::test_helpers::{assert_clean_true, run_tapscript, scriptnum},
        support::tapscript::TapscriptProfile,
    };
    use bitcoin::ScriptBuf;
    use bitcoin_scriptexec::ExecError;

    mod baseline {
        use crate::{arithmetic::u32::stack::verify_canonical_byte, support::script::*};
        include!("../../../research/extended-hamming-decoder/baseline.rs");
    }

    const PROFILE: TapscriptProfile = TapscriptProfile::Consensus;

    fn leaf(fragment: Script, expected: u8) -> ScriptBuf {
        script! {{fragment} {u32::from(expected)} OP_EQUALVERIFY OP_TRUE}.compile_with_policy()
    }

    #[test]
    fn both_schedules_match_unique_nearest_codeword_for_every_byte() {
        let generators = [
            decode_hamming84 as fn() -> Script,
            baseline::decode_with_table,
        ];
        let mut accepted = 0;
        for byte in 0..=255u8 {
            let expected = baseline::nearest(byte);
            accepted += usize::from(expected.is_some());
            let input = vec![scriptnum(i64::from(byte))];
            for (generate, expected_error) in generators
                .into_iter()
                .zip([ExecError::NumEqualVerify, ExecError::Verify])
            {
                let fragment = generate();
                if let Some(nibble) = expected {
                    assert_clean_true(&run_tapscript(
                        leaf(fragment, nibble),
                        input.clone(),
                        PROFILE,
                    ));
                } else {
                    let script = script! {{fragment} OP_DROP OP_TRUE}.compile_with_policy();
                    let result = run_tapscript(script, input.clone(), PROFILE);
                    assert_eq!(result.error, Some(expected_error), "byte {byte:02x}");
                }
            }
        }
        assert_eq!(accepted, 144);
    }

    #[test]
    fn single_and_double_error_domains_and_three_bit_alias() {
        for value in 0..16 {
            let codeword = baseline::encode(value);
            for i in 0..8 {
                let single = codeword ^ (1 << i);
                assert_eq!(baseline::nearest(single), Some(value));
                for j in i + 1..8 {
                    assert_eq!(baseline::nearest(single ^ (1 << j)), None);
                }
            }
        }
        // Three bit flips from the zero codeword lie one bit from 0x87.
        assert_eq!(baseline::encode(0), 0);
        assert_eq!(baseline::encode(1), 0x87);
        assert_clean_true(&run_tapscript(
            leaf(decode_hamming84(), 1),
            vec![scriptnum(0x07)],
            PROFILE,
        ));
    }

    #[test]
    fn rejects_noncanonical_and_oversized_numeric_bytes() {
        for fragment in [decode_hamming84(), baseline::decode_with_table()] {
            let script = leaf(fragment, 0);
            for (bad, error) in [
                (scriptnum(-1), ExecError::Verify),
                (scriptnum(256), ExecError::Verify),
                (vec![0], ExecError::EqualVerify),
                (vec![0x80], ExecError::EqualVerify),
                (vec![0, 0], ExecError::EqualVerify),
                (vec![0; 5], ExecError::ScriptIntNumericOverflow),
                (vec![0; 521], ExecError::PushSize),
            ] {
                let result = run_tapscript(script.clone(), vec![bad], PROFILE);
                assert_eq!(result.error, Some(error));
            }
            assert!(!run_tapscript(script.clone(), vec![], PROFILE).success);
            assert!(!run_tapscript(script, vec![vec![], vec![]], PROFILE).success);
        }
    }

    #[test]
    fn preserves_both_caller_stacks_at_exact_limit() {
        let script = script! {
            OP_TOALTSTACK {decode_hamming84()} OP_FROMALTSTACK
        }
        .compile_with_policy();
        let prefix = vec![vec![0x91, 0x36]; 986];
        let alt = vec![0x82, 0x42];
        let mut input = prefix.clone();
        input.extend([scriptnum(0x83), alt.clone()]);
        let result = run_tapscript(script.clone(), input.clone(), PROFILE);
        assert_eq!(result.error, None);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        let actual: Vec<_> = (0..result.final_stack.len())
            .map(|i| result.final_stack.get(i))
            .collect();
        assert_eq!(actual, [prefix, vec![scriptnum(1), alt]].concat());
        input.insert(0, vec![]);
        assert_eq!(
            run_tapscript(script, input, PROFILE).error,
            Some(ExecError::StackSize)
        );
    }

    #[test]
    fn batched_table_keeps_output_order_and_rejects_a_bad_item() {
        let checked = script! {
            {baseline::decode_batch_with_table(8)}
            for value in (0..8).rev() {{value} OP_EQUALVERIFY}
            OP_TRUE
        }
        .compile_with_policy();
        let mut input: Vec<_> = (0..8)
            .map(|value| scriptnum(i64::from(baseline::encode(value) ^ (1 << value))))
            .collect();
        assert_clean_true(&run_tapscript(checked.clone(), input.clone(), PROFILE));
        input[3] = scriptnum(0x03);
        assert_eq!(
            run_tapscript(checked, input, PROFILE).error,
            Some(ExecError::Verify)
        );
    }
}
