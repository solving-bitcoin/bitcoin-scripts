//! Explicit local consensus/policy profiles for context-free tapscript fragments.
//!
//! These profiles do not validate a Taproot commitment, transaction, signature
//! budget, annex or complete relay policy. An accepted local fragment therefore
//! has deployment `unclassified`. Existing experimental research helpers remain
//! in [`super::execution`].

use bitcoin::{script::Instruction, Opcode, ScriptBuf};
use bitcoin_scriptexec::{Experimental, Options};

use super::execution::{execute_script_buf_with_options, ExecuteInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapscriptProfile {
    /// Consensus numeric encoding and OP_SUCCESS semantics, with resource checks.
    Consensus,
    /// Additionally enforce minimal pushes/numbers, 80-byte witness data items,
    /// and DISCOURAGE_OP_SUCCESS. This is a subset of full transaction policy.
    Policy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapscriptPolicyRejection {
    WitnessStackItemSize { index: usize, size: usize },
    DiscourageOpSuccess(Opcode),
}

#[derive(Debug)]
pub enum TapscriptOutcome {
    Executed(ExecuteInfo),
    /// The BIP342 pre-scan succeeds without executing the script or checking
    /// entry resources. There are deliberately no fabricated execution stats.
    OpSuccess(Opcode),
    PolicyRejected(TapscriptPolicyRejection),
    InvalidScript(bitcoin::script::Error),
    /// No verdict: this fragment API lacks the needed transaction context or
    /// policy flag. It conservatively refuses these opcodes even in dead code.
    UnsupportedOpcode(Opcode),
    InitializationError(bitcoin_scriptexec::Error),
}

#[derive(Debug)]
pub struct TapscriptResult {
    pub profile: TapscriptProfile,
    pub outcome: TapscriptOutcome,
}

impl TapscriptResult {
    /// A local fragment verdict, not a complete consensus/policy classification.
    /// `None` explicitly means that this API could not evaluate the script.
    pub fn accepted(&self) -> Option<bool> {
        match &self.outcome {
            TapscriptOutcome::Executed(result) => Some(result.success),
            TapscriptOutcome::OpSuccess(_) => Some(true),
            TapscriptOutcome::PolicyRejected(_) | TapscriptOutcome::InvalidScript(_) => Some(false),
            TapscriptOutcome::UnsupportedOpcode(_) | TapscriptOutcome::InitializationError(_) => {
                None
            }
        }
    }

    pub fn execution(&self) -> Option<&ExecuteInfo> {
        match &self.outcome {
            TapscriptOutcome::Executed(result) => Some(result),
            _ => None,
        }
    }
}

fn is_op_success(opcode: Opcode) -> bool {
    // Bitcoin Core v30.3, script/script.cpp::IsOpSuccess; BIP342.
    matches!(opcode.to_u8(), 80 | 98 | 126..=129 | 131..=134 | 137..=138
        | 141..=142 | 149..=153 | 187..=254)
}

fn needs_unsupported_context(opcode: Opcode, profile: TapscriptProfile) -> bool {
    // Signature checks, CODESEPARATOR and locktime checks need proper context;
    // CHECKMULTISIG variants are unimplemented in the dependency. Policy also
    // discourages executable upgradeable NOPs,
    // which the dependency does not expose as an option. A conservative refusal
    // is preferable to claiming rejection/acceptance for an unchecked rule.
    matches!(opcode.to_u8(), 0xab..=0xaf | 0xba | 0xb1 | 0xb2)
        || (profile == TapscriptProfile::Policy && matches!(opcode.to_u8(), 0xb0 | 0xb3..=0xb9))
}

/// Execute exact bytecode under an explicit local tapscript profile.
///
/// Compile generated scripts with `ScriptCompilation::compile_with_policy()`
/// before calling this function. Data witness items must exclude the script,
/// control block and annex. All data and hints coexist at entry.
///
/// Policy's witness-item check precedes script parsing, as in Core's
/// IsWitnessStandard. The consensus OP_SUCCESS scan precedes entry limits and
/// all execution: a malformed prefix rejects, a malformed suffix after the
/// first OP_SUCCESS is irrelevant, and push payload bytes are never opcodes.
pub fn execute_tapscript(
    script: ScriptBuf,
    witness: Vec<Vec<u8>>,
    profile: TapscriptProfile,
) -> TapscriptResult {
    let result = |outcome| TapscriptResult { profile, outcome };
    if profile == TapscriptProfile::Policy {
        if let Some((index, item)) = witness.iter().enumerate().find(|(_, item)| item.len() > 80) {
            return result(TapscriptOutcome::PolicyRejected(
                TapscriptPolicyRejection::WitnessStackItemSize {
                    index,
                    size: item.len(),
                },
            ));
        }
    }

    let mut unsupported = None;
    for instruction in script.instructions() {
        match instruction {
            Err(error) => return result(TapscriptOutcome::InvalidScript(error)),
            Ok(Instruction::Op(opcode)) if is_op_success(opcode) => {
                return result(if profile == TapscriptProfile::Consensus {
                    TapscriptOutcome::OpSuccess(opcode)
                } else {
                    TapscriptOutcome::PolicyRejected(TapscriptPolicyRejection::DiscourageOpSuccess(
                        opcode,
                    ))
                });
            }
            Ok(Instruction::Op(opcode)) if needs_unsupported_context(opcode, profile) => {
                unsupported.get_or_insert(opcode);
            }
            _ => {}
        }
    }
    if let Some(opcode) = unsupported {
        return result(TapscriptOutcome::UnsupportedOpcode(opcode));
    }

    let options = Options {
        require_minimal: profile == TapscriptProfile::Policy,
        verify_cltv: true,
        verify_csv: true,
        verify_minimal_if: true,
        enforce_stack_limit: true,
        experimental: Experimental { op_cat: false },
    };
    result(
        match execute_script_buf_with_options(script, witness, options) {
            Ok(execution) => TapscriptOutcome::Executed(execution),
            Err(error) => TapscriptOutcome::InitializationError(error),
        },
    )
}
