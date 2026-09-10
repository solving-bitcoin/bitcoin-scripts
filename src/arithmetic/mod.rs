//! Modulus-agnostic integer, residue, and finite-field arithmetic backends.

pub mod bigint;
pub mod rns;
pub mod scriptint;
pub mod u31;
pub mod u32;
pub mod u4;

#[cfg(test)]
mod test_helpers {
    use crate::support::execution::execute_raw_script_with_inputs_strict;

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
