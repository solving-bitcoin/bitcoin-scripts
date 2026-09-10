//! Exact-byte fixtures for the supported local tapscript consensus/policy subset.
//! These checks do not establish transaction-level consensus or relay validity.

use bitcoin::{Opcode, ScriptBuf};
use bitcoin_lab::support::tapscript::{
    execute_tapscript, TapscriptOutcome, TapscriptPolicyRejection, TapscriptProfile,
    TapscriptResult,
};
use bitcoin_scriptexec::ExecError;

const PROFILES: [TapscriptProfile; 2] = [TapscriptProfile::Consensus, TapscriptProfile::Policy];

fn run(bytes: &[u8], witness: Vec<Vec<u8>>, profile: TapscriptProfile) -> TapscriptResult {
    let result = execute_tapscript(ScriptBuf::from_bytes(bytes.to_vec()), witness, profile);
    assert_eq!(result.profile, profile);
    result
}

fn assert_executed(result: &TapscriptResult, accepted: bool, error: Option<ExecError>) {
    assert_eq!(result.accepted(), Some(accepted));
    let execution = result.execution().expect("ordinary interpreter execution");
    assert!(execution.stack_limit_enforced);
    assert_eq!(execution.success, accepted);
    assert_eq!(execution.error, error, "{execution}");
    if accepted {
        assert_eq!(execution.final_stack.len(), 1, "{execution}");
        assert_eq!(execution.final_stack.get(0), vec![1], "{execution}");
    }
}

fn assert_success_bypass(result: &TapscriptResult, byte: u8) {
    assert_eq!(result.accepted(), Some(true));
    assert!(
        result.execution().is_none(),
        "OP_SUCCESS must not invent execution statistics"
    );
    assert!(
        matches!(result.outcome, TapscriptOutcome::OpSuccess(opcode) if opcode == Opcode::from(byte))
    );
}

fn assert_discouraged_success(result: &TapscriptResult, byte: u8) {
    assert_eq!(result.accepted(), Some(false));
    assert!(result.execution().is_none());
    assert!(matches!(
        result.outcome,
        TapscriptOutcome::PolicyRejected(TapscriptPolicyRejection::DiscourageOpSuccess(opcode))
            if opcode == Opcode::from(byte)
    ));
}

fn is_op_success(byte: u8) -> bool {
    // BIP342's complete opcode set; payload bytes are not opcodes.
    matches!(byte, 80 | 98 | 126..=129 | 131..=134 | 137..=138 | 141..=142 | 149..=153 | 187..=254)
}

#[test]
fn profile_metadata_distinguishes_executed_success_and_false() {
    for profile in PROFILES {
        assert_executed(&run(&[0x51], vec![], profile), true, None);
        assert_executed(&run(&[0x00], vec![], profile), false, None);
    }
}

#[test]
fn nonminimal_numeric_witness_aliases_are_consensus_valid_and_policy_invalid() {
    for (alias, expected) in [(vec![1, 0], 0x51), (vec![0x80], 0x00), (vec![0], 0x00)] {
        // The script compares numeric values, without raw-byte canonicalization.
        let bytes = [expected, 0x9c]; // expected OP_NUMEQUAL
        assert_executed(
            &run(&bytes, vec![alias.clone()], TapscriptProfile::Consensus),
            true,
            None,
        );
        assert_executed(
            &run(&bytes, vec![alias], TapscriptProfile::Policy),
            false,
            Some(ExecError::MinimalData),
        );
    }
}

#[test]
fn minimaldata_applies_to_executed_pushes_but_not_skipped_pushes() {
    // OP_PUSHDATA1 for one byte is nonminimal; use 17 so the numeric encoding is minimal.
    let executed = [0x4c, 0x01, 0x11, 0x75, 0x51];
    assert_executed(
        &run(&executed, vec![], TapscriptProfile::Consensus),
        true,
        None,
    );
    assert_executed(
        &run(&executed, vec![], TapscriptProfile::Policy),
        false,
        Some(ExecError::MinimalData),
    );
    let skipped = [0x00, 0x63, 0x4c, 0x01, 0x11, 0x68, 0x51];
    for profile in PROFILES {
        assert_executed(&run(&skipped, vec![], profile), true, None);
    }
}

#[test]
fn minimalif_remains_mandatory_under_both_profiles() {
    for conditional in [0x63, 0x64] {
        // IF and NOTIF
        let bytes = [conditional, 0x51, 0x67, 0x51, 0x68];
        for profile in PROFILES {
            for condition in [vec![], vec![1]] {
                assert_executed(&run(&bytes, vec![condition], profile), true, None);
            }
            for condition in [vec![0], vec![2], vec![0x80], vec![0x81], vec![1, 0]] {
                assert_executed(
                    &run(&bytes, vec![condition], profile),
                    false,
                    Some(ExecError::TapscriptMinimalIf),
                );
            }
        }
    }
}

#[test]
fn policy_witness_item_limit_has_an_exact_eighty_byte_boundary() {
    for size in [80, 81] {
        let witness = vec![vec![0x42; size]];
        assert_executed(
            &run(&[0x75, 0x51], witness.clone(), TapscriptProfile::Consensus),
            true,
            None,
        );
        let policy = run(&[0x75, 0x51], witness, TapscriptProfile::Policy);
        if size == 80 {
            assert_executed(&policy, true, None);
        } else {
            assert_eq!(policy.accepted(), Some(false));
            assert!(policy.execution().is_none());
            assert!(matches!(
                policy.outcome,
                TapscriptOutcome::PolicyRejected(TapscriptPolicyRejection::WitnessStackItemSize {
                    index: 0,
                    size: 81
                })
            ));
        }
    }
}

#[test]
fn complete_op_success_set_bypasses_execution_and_is_discouraged_by_policy() {
    for byte in 0u8..=255 {
        let consensus = run(&[byte], vec![], TapscriptProfile::Consensus);
        let policy = run(&[byte], vec![], TapscriptProfile::Policy);
        if is_op_success(byte) {
            assert_success_bypass(&consensus, byte);
            assert_discouraged_success(&policy, byte);
        } else {
            assert!(
                !matches!(consensus.outcome, TapscriptOutcome::OpSuccess(_)),
                "opcode {byte}"
            );
            assert!(
                !matches!(
                    policy.outcome,
                    TapscriptOutcome::PolicyRejected(
                        TapscriptPolicyRejection::DiscourageOpSuccess(_)
                    )
                ),
                "opcode {byte}"
            );
        }
    }
}

#[test]
fn op_success_bytes_inside_push_payloads_do_not_bypass_execution() {
    for byte in (0u8..=255).filter(|byte| is_op_success(*byte)) {
        // Two-byte payloads remain minimal even when the first byte is 0x81.
        let bytes = [0x02, byte, 0x42, 0x75, 0x51];
        for profile in PROFILES {
            assert_executed(&run(&bytes, vec![], profile), true, None);
        }
    }
    // Every length-prefix format must mask payload bytes, including nonminimal pushes.
    for prefix in [
        vec![0x01],
        vec![0x4c, 1],
        vec![0x4d, 1, 0],
        vec![0x4e, 1, 0, 0, 0],
    ] {
        let mut bytes = prefix;
        bytes.extend([0x50, 0x75, 0x51]);
        assert_executed(
            &run(&bytes, vec![], TapscriptProfile::Consensus),
            true,
            None,
        );
    }
}

#[test]
fn malformed_push_before_op_success_rejects_and_after_op_success_is_bypassed() {
    for prefix in [vec![0x4c, 2], vec![0x4d, 2, 0], vec![0x4e, 2, 0, 0, 0]] {
        let mut malformed = prefix;
        malformed.push(0x50); // A truncated payload, not an OP_SUCCESS opcode.
        for profile in PROFILES {
            let result = run(&malformed, vec![], profile);
            assert_eq!(result.accepted(), Some(false));
            assert!(result.execution().is_none());
            assert!(matches!(result.outcome, TapscriptOutcome::InvalidScript(_)));
        }
    }
    let bytes = [0x50, 0x4c];
    assert_success_bypass(&run(&bytes, vec![], TapscriptProfile::Consensus), 0x50);
    assert_discouraged_success(&run(&bytes, vec![], TapscriptProfile::Policy), 0x50);
}

#[test]
fn op_success_in_dead_branches_overrides_unbalanced_conditionals() {
    let bytes = [0x00, 0x63, 0x50]; // No ENDIF: the sequential scan still succeeds.
    assert_success_bypass(&run(&bytes, vec![], TapscriptProfile::Consensus), 0x50);
    assert_discouraged_success(&run(&bytes, vec![], TapscriptProfile::Policy), 0x50);
}

#[test]
fn op_success_overrides_earlier_execution_failures_and_unsupported_opcodes() {
    for earlier in [0x6a, 0x75, 0xac, 0xb1, 0xff] {
        // RETURN, DROP, CHECKSIG, CLTV, invalid opcode
        let bytes = [earlier, 0x50];
        assert_success_bypass(&run(&bytes, vec![], TapscriptProfile::Consensus), 0x50);
        assert_discouraged_success(&run(&bytes, vec![], TapscriptProfile::Policy), 0x50);
    }
}

#[test]
fn op_success_bypasses_consensus_entry_stack_limits() {
    for witness in [vec![vec![]; 1001], vec![vec![0x42; 521]]] {
        assert_success_bypass(&run(&[0x50], witness, TapscriptProfile::Consensus), 0x50);
    }
    assert_discouraged_success(
        &run(&[0x50], vec![vec![]; 1001], TapscriptProfile::Policy),
        0x50,
    );
}

#[test]
fn policy_witness_limit_precedes_op_success_and_script_parsing() {
    for bytes in [vec![0x50], vec![0x4c]] {
        let result = run(
            &bytes,
            vec![vec![], vec![0x42; 81]],
            TapscriptProfile::Policy,
        );
        assert_eq!(result.accepted(), Some(false));
        assert!(result.execution().is_none());
        assert!(matches!(
            result.outcome,
            TapscriptOutcome::PolicyRejected(TapscriptPolicyRejection::WitnessStackItemSize {
                index: 1,
                size: 81
            })
        ));
    }
}

#[test]
fn consensus_entry_limits_still_reject_without_op_success() {
    for (witness, error) in [
        (vec![vec![]; 1001], ExecError::StackSize),
        (vec![vec![0x42; 521]], ExecError::PushSize),
    ] {
        assert_executed(
            &run(&[0x75, 0x51], witness, TapscriptProfile::Consensus),
            false,
            Some(error),
        );
    }
}

#[test]
fn signature_and_timelock_contexts_are_explicitly_unsupported() {
    for byte in [0xab, 0xac, 0xad, 0xae, 0xaf, 0xb1, 0xb2, 0xba] {
        for bytes in [vec![byte], vec![0x00, 0x63, byte, 0x68, 0x51]] {
            for profile in PROFILES {
                let result = run(&bytes, vec![], profile);
                assert_eq!(result.accepted(), None, "opcode {byte}");
                assert!(result.execution().is_none());
                assert!(
                    matches!(result.outcome, TapscriptOutcome::UnsupportedOpcode(opcode) if opcode == Opcode::from(byte))
                );
            }
        }
    }
}

#[test]
fn upgradable_nops_are_consensus_valid_but_outside_the_policy_subset() {
    for byte in [0xb0, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9] {
        for bytes in [vec![byte, 0x51], vec![0x00, 0x63, byte, 0x68, 0x51]] {
            assert_executed(
                &run(&bytes, vec![], TapscriptProfile::Consensus),
                true,
                None,
            );
            let policy = run(&bytes, vec![], TapscriptProfile::Policy);
            assert_eq!(policy.accepted(), None);
            assert!(policy.execution().is_none());
            assert!(
                matches!(policy.outcome, TapscriptOutcome::UnsupportedOpcode(opcode) if opcode == Opcode::from(byte))
            );
        }
    }
}
