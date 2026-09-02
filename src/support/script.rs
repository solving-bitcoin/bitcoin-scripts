//! Script construction types and the repository-wide compilation policy.

use bitcoin::ScriptBuf;
use bitcoin_script::CompileOptions;
pub use bitcoin_script::{script, Script};

/// Largest generated script sent through the general Tapscript optimizer.
///
/// Larger scripts remain byte-for-byte as generated because the optimizer's
/// fixpoint passes are prohibitively expensive at those sizes.
pub const MAX_OPTIMIZER_INPUT_BYTES: usize = 64 * 1024;

/// Apply the repository-wide compilation policy to a generated script.
pub trait ScriptCompilation {
    /// Optimize scripts up to [`MAX_OPTIMIZER_INPUT_BYTES`] with every upstream
    /// pass; compile larger scripts without optimizer rewrites.
    fn compile_with_policy(self) -> ScriptBuf;
}

impl ScriptCompilation for Script {
    fn compile_with_policy(self) -> ScriptBuf {
        let raw = self.clone().compile_with_options(CompileOptions::NONE);
        if raw.len() > MAX_OPTIMIZER_INPUT_BYTES {
            raw
        } else {
            self.compile_with_options(CompileOptions::ALL)
        }
    }
}

/// Attribute whole-script optimizer effects to one byte-cost category.
///
/// Cost breakdowns measure meaningful fragments independently, but the final
/// optimizer may fuse instructions across those fragment boundaries. The
/// selected category absorbs that usually small delta so its reported total
/// still equals the serialized final script.
pub fn attribute_compilation_delta(
    category: &mut usize,
    independently_compiled_total: usize,
    final_script_bytes: usize,
) {
    if final_script_bytes >= independently_compiled_total {
        *category += final_script_bytes - independently_compiled_total;
    } else {
        *category = category
            .checked_sub(independently_compiled_total - final_script_bytes)
            .expect("optimizer delta exceeds the selected byte-cost category");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compilation_policy_optimizes_small_scripts() {
        let compiled = script! {
            OP_1
            OP_ADD
        }
        .compile_with_policy();

        assert_eq!(compiled.to_bytes(), vec![0x8b]); // OP_1ADD
    }

    #[test]
    fn compilation_policy_skips_scripts_above_cutoff() {
        let compiled = script! {
            for _ in 0..=MAX_OPTIMIZER_INPUT_BYTES {
                OP_NOP
            }
        }
        .compile_with_policy();

        assert_eq!(compiled.len(), MAX_OPTIMIZER_INPUT_BYTES + 1);
        assert!(compiled.to_bytes().iter().all(|byte| *byte == 0x61)); // OP_NOP
    }
}
