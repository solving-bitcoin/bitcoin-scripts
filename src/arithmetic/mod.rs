//! Modulus-agnostic integer, residue, and finite-field arithmetic backends.

pub mod bigint;
pub mod checksums;
pub mod rns;
pub mod scriptint;
pub mod signed_window;
pub mod u31;
pub mod u32;
pub mod u4;

#[cfg(test)]
mod test_helpers {
    use crate::support::{
        execution::{execute_raw_script_with_inputs_strict, ExecuteInfo},
        tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
    };

    /// Minimal ScriptNum encoding of `value`, for canonical witness controls.
    pub(super) fn scriptnum(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let length = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..length].to_vec()
    }

    /// Execute exact policy-compiled bytecode under an explicit local
    /// tapscript profile. `Consensus` disables global numeric minimality
    /// (`require_minimal: false`), so raw-witness numeric aliases reach the
    /// fragment; `Policy` enforces it. Both enforce the combined 1,000-item
    /// stack limit. This is local fragment execution, not Bitcoin Core or
    /// complete-spend validation.
    pub(super) fn run_tapscript(
        script: bitcoin::ScriptBuf,
        witness: Vec<Vec<u8>>,
        profile: TapscriptProfile,
    ) -> ExecuteInfo {
        match execute_tapscript(script, witness, profile).outcome {
            TapscriptOutcome::Executed(result) => result,
            outcome => panic!("expected local {profile:?}-profile execution: {outcome:?}"),
        }
    }

    /// Assert that a complete leaf succeeded with the stack limit enforced and
    /// left exactly one `OP_TRUE` item.
    pub(super) fn assert_clean_true(result: &ExecuteInfo) {
        assert!(result.stack_limit_enforced, "stack limit was not enforced");
        assert!(
            result.error.is_none(),
            "unexpected execution error: {result}"
        );
        assert!(result.success, "complete script failed: {result}");
        assert_eq!(
            result.final_stack.len(),
            1,
            "script did not leave a clean stack: {result}"
        );
        assert_eq!(
            result.final_stack.get(0),
            vec![1],
            "script result is not OP_TRUE: {result}"
        );
    }

    /// Supply canonical ScriptNums to a fixed, policy-compiled test script.
    /// These are strict local tapscript checks, not consensus validation.
    pub(super) fn run_with_witness(script: &[u8], values: impl IntoIterator<Item = i64>) {
        let values: Vec<_> = values.into_iter().collect();
        let witness = values
            .iter()
            .map(|&value| {
                let mut bytes = [0u8; 8];
                let len = bitcoin::script::write_scriptint(&mut bytes, value);
                bytes[..len].to_vec()
            })
            .collect();
        let result = execute_raw_script_with_inputs_strict(script.to_vec(), witness);
        assert!(result.success, "witness {values:?}: {result}");
        assert!(result.stack_limit_enforced);
        assert_eq!(result.final_stack.len(), 1);
        assert_eq!(result.final_stack.get(0), vec![1]);
        assert!(result.stats.max_nb_stack_items <= 1000);
    }

    pub(super) fn word_witness(value: u32) -> impl Iterator<Item = i64> {
        value.to_be_bytes().into_iter().map(i64::from)
    }

    pub(super) fn nibble_witness(value: u32) -> impl Iterator<Item = i64> {
        (0..8)
            .rev()
            .map(move |i| i64::from((value >> (i * 4)) & 0xf))
    }
}
