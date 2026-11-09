//! Convert canonical byte-valued ScriptNums to one raw byte.

use crate::{arithmetic::u32::stack::verify_canonical_byte, support::script::*};

/// Consume a canonical nonnegative ScriptNum in 0..=255 and return its
/// exact one-byte vector. The result is raw data, including for 0 and 128.
/// Both caller stacks are preserved for the exact one-item suffix. No hints
/// are required and peak combined stack use is four plus caller state.
pub fn numeric_to_raw_byte() -> Script {
    script! {
        {verify_canonical_byte()}
        OP_DUP 128 OP_LESSTHAN
        OP_IF
            {vec![0u8]}
        OP_ELSE
            // Negative values -1..=-127 serialize as 0x81..=0xff.
            128 OP_SWAP OP_SUB
            {vec![0x80u8]}
        OP_ENDIF
        // Replace either encoding's zero with its exact raw byte.
        OP_OVER OP_0NOTEQUAL
        OP_IF OP_DROP OP_ELSE OP_NIP OP_ENDIF
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::test_helpers::{assert_clean_true, run_tapscript, scriptnum},
        support::tapscript::TapscriptProfile,
    };
    use bitcoin::{
        hashes::{sha256, Hash},
        ScriptBuf,
    };
    use bitcoin_scriptexec::ExecError;

    mod baseline {
        use crate::{arithmetic::u32::stack::verify_canonical_byte, support::script::*};
        include!("../../../research/raw-scriptnum-byte-adapter/baseline.rs");
    }

    const GENERATORS: [fn() -> Script; 2] =
        [numeric_to_raw_byte, baseline::convert_with_high_table];

    fn checked(fragment: Script, expected: u8) -> ScriptBuf {
        script! {{fragment} {vec![expected]} OP_EQUALVERIFY OP_TRUE}.compile_with_policy()
    }

    fn hash_leaf(fragment: Script, byte: u8) -> ScriptBuf {
        let digest = sha256::Hash::hash(&[byte]).to_byte_array().to_vec();
        script! {{fragment} OP_SHA256 {digest} OP_EQUALVERIFY OP_TRUE}.compile_with_policy()
    }

    #[test]
    fn exact_bytes_and_native_hashes_for_all_256_inputs() {
        for byte in 0..=255u8 {
            for generate in GENERATORS {
                let input = vec![scriptnum(i64::from(byte))];
                let exact = checked(generate(), byte);
                let hashed = hash_leaf(generate(), byte);
                for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
                    assert_clean_true(&run_tapscript(exact.clone(), input.clone(), profile));
                    assert_clean_true(&run_tapscript(hashed.clone(), input.clone(), profile));
                }
            }
        }
    }

    #[test]
    fn rejects_malformed_numeric_bytes_even_when_output_would_match() {
        for generate in GENERATORS {
            let script = checked(generate(), 0);
            for (bad, error) in [
                (scriptnum(-1), ExecError::Verify),
                (scriptnum(256), ExecError::Verify),
                (vec![0], ExecError::EqualVerify),
                (vec![0x80], ExecError::EqualVerify),
                (vec![0, 0], ExecError::EqualVerify),
                (vec![0; 5], ExecError::ScriptIntNumericOverflow),
                (vec![0; 521], ExecError::PushSize),
            ] {
                let result = run_tapscript(script.clone(), vec![bad], TapscriptProfile::Consensus);
                assert_eq!(result.error, Some(error));
            }
            assert!(!run_tapscript(script.clone(), vec![], TapscriptProfile::Consensus).success);
            assert!(
                !run_tapscript(script, vec![vec![], vec![]], TapscriptProfile::Consensus).success
            );
        }
    }

    #[test]
    fn numeric_hashing_has_the_wrong_bytes_at_zero_and_above_127() {
        for byte in [0, 128, 255] {
            let direct = hash_leaf(verify_canonical_byte(), byte);
            let witness = vec![scriptnum(i64::from(byte))];
            assert_eq!(
                run_tapscript(direct, witness.clone(), TapscriptProfile::Consensus).error,
                Some(ExecError::EqualVerify)
            );
            assert_clean_true(&run_tapscript(
                hash_leaf(numeric_to_raw_byte(), byte),
                witness,
                TapscriptProfile::Consensus,
            ));
        }
    }

    #[test]
    fn preserves_both_caller_stacks_at_exact_limit() {
        let script = script! {
            OP_TOALTSTACK {numeric_to_raw_byte()} OP_FROMALTSTACK
        }
        .compile_with_policy();
        let prefix = vec![vec![0x91, 0x36]; 995];
        let alt = vec![0x82, 0x42];
        let mut input = prefix.clone();
        input.extend([scriptnum(128), alt.clone()]);
        let result = run_tapscript(script.clone(), input.clone(), TapscriptProfile::Consensus);
        assert_eq!(result.error, None);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        let actual: Vec<_> = (0..result.final_stack.len())
            .map(|i| result.final_stack.get(i))
            .collect();
        assert_eq!(actual, [prefix, vec![vec![0x80], alt]].concat());
        input.insert(0, vec![]);
        assert_eq!(
            run_tapscript(script, input, TapscriptProfile::Consensus).error,
            Some(ExecError::StackSize)
        );
    }
}
