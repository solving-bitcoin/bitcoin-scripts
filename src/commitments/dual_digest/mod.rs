//! Verify two native digests of one raw preimage.

use crate::support::script::*;

/// Consume one preimage and check its HASH160 and HASH256 digests.
///
/// The two digest constants are raw bytes in hash output order. Both caller
/// stacks are preserved for the exact one-item suffix. No hints are required.
pub fn verify_hash160_hash256(hash160: [u8; 20], hash256: [u8; 32]) -> Script {
    script! {
        OP_SHA256 OP_DUP
        OP_RIPEMD160 {hash160.to_vec()} OP_EQUALVERIFY
        OP_SHA256 {hash256.to_vec()} OP_EQUALVERIFY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{
        execution::ExecuteInfo,
        tapscript::{
            execute_tapscript, TapscriptOutcome, TapscriptPolicyRejection, TapscriptProfile,
        },
    };
    use bitcoin::{
        hashes::{hash160, sha256, sha256d, Hash},
        ScriptBuf,
    };
    use bitcoin_scriptexec::ExecError;

    mod baseline {
        use crate::support::script::*;
        include!("../../../research/shared-digest-preimage/baseline.rs");
    }

    type Generator = fn([u8; 20], [u8; 32]) -> Script;
    const GENERATORS: [Generator; 2] = [verify_hash160_hash256, baseline::verify_separate_hashes];
    const PROFILE: TapscriptProfile = TapscriptProfile::Consensus;

    fn digests(bytes: &[u8]) -> ([u8; 20], [u8; 32]) {
        (
            hash160::Hash::hash(bytes).to_byte_array(),
            sha256d::Hash::hash(bytes).to_byte_array(),
        )
    }

    fn complete(fragment: Script) -> ScriptBuf {
        script! {{fragment} OP_TRUE}.compile_with_policy()
    }

    fn run(script: ScriptBuf, witness: Vec<Vec<u8>>) -> ExecuteInfo {
        match execute_tapscript(script, witness, PROFILE).outcome {
            TapscriptOutcome::Executed(result) => result,
            outcome => panic!("expected execution: {outcome:?}"),
        }
    }

    fn clean(result: ExecuteInfo) {
        assert!(result.success && result.stack_limit_enforced, "{result}");
        assert_eq!(result.final_stack.len(), 1);
        assert_eq!(result.final_stack.get(0), vec![1]);
    }

    #[test]
    fn matches_independent_digests_at_padding_and_element_boundaries() {
        for length in [0, 1, 31, 32, 55, 56, 63, 64, 80, 81, 119, 120, 519, 520] {
            let preimage: Vec<_> = (0..length).map(|i| ((i * 17 + 5) % 251) as u8).collect();
            let (short, long) = digests(&preimage);
            for generate in GENERATORS {
                let leaf = complete(generate(short, long));
                clean(run(leaf.clone(), vec![preimage.clone()]));
                if length > 80 {
                    let result =
                        execute_tapscript(leaf, vec![preimage.clone()], TapscriptProfile::Policy);
                    assert!(matches!(
                        result.outcome,
                        TapscriptOutcome::PolicyRejected(
                            TapscriptPolicyRejection::WitnessStackItemSize {index: 0, size}
                        ) if size == length
                    ));
                }
            }
        }
    }

    #[test]
    fn independently_binds_both_digests_and_rejects_adversarial_openings() {
        let preimage = vec![0x80, 0, 0xff, 0x7f];
        let other = vec![0x80, 0, 0xfe, 0x7f];
        let intermediate = sha256::Hash::hash(&preimage).to_byte_array().to_vec();
        let (short, long) = digests(&preimage);
        let (other_short, other_long) = digests(&other);
        for generate in GENERATORS {
            for (short, long) in [(other_short, long), (short, other_long)] {
                assert_eq!(
                    run(complete(generate(short, long)), vec![preimage.clone()]).error,
                    Some(ExecError::EqualVerify)
                );
            }
            let leaf = complete(generate(short, long));
            for bad in [other.clone(), intermediate.clone()] {
                assert_eq!(
                    run(leaf.clone(), vec![bad]).error,
                    Some(ExecError::EqualVerify)
                );
            }
            assert!(!run(leaf.clone(), vec![]).success);
            assert!(!run(leaf, vec![vec![0xaa], preimage.clone()]).success);
            let oversized = vec![0x42; 521];
            let (short, long) = digests(&oversized);
            assert_eq!(
                run(complete(generate(short, long)), vec![oversized]).error,
                Some(ExecError::PushSize)
            );
        }
    }

    #[test]
    fn preserves_caller_stacks_and_observes_combined_limit() {
        let preimage = vec![0x36, 0x91];
        let (short, long) = digests(&preimage);
        for generate in GENERATORS {
            let fragment = generate(short, long);
            let script = script! {
                OP_TOALTSTACK {fragment} OP_FROMALTSTACK
            }
            .compile_with_policy();
            let caller = vec![vec![0x71, 0x42]; 996];
            let alt = vec![0x80, 0x19];
            let mut input = caller.clone();
            input.extend([preimage.clone(), alt.clone()]);
            let result = run(script.clone(), input.clone());
            assert_eq!(result.error, None, "{result}");
            assert_eq!(result.stats.max_nb_stack_items, 1000);
            let actual: Vec<_> = (0..result.final_stack.len())
                .map(|index| result.final_stack.get(index))
                .collect();
            assert_eq!(actual, [caller, vec![alt]].concat());
            input.insert(0, vec![]);
            assert_eq!(run(script, input).error, Some(ExecError::StackSize));
        }
    }
}
