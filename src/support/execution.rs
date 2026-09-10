//! Local tapscript execution, with explicit resource-limit enforcement.
//!
//! "Strict" helpers enforce entry and per-step stack limits; they are not
//! full consensus or policy validators. See the colocated README for the
//! pinned interpreter's remaining limitations.

use core::fmt;

use crate::support::script::{self, ScriptCompilation};
use bitcoin::{
    hashes::Hash,
    hex::DisplayHex,
    taproot::{LeafVersion, TAPROOT_ANNEX_PREFIX},
    Opcode, Script, ScriptBuf, TapLeafHash, Transaction, TxOut,
};
use bitcoin_scriptexec::{Exec, ExecCtx, ExecError, ExecStats, Options, Stack, TxTemplate};

pub struct FmtStack(pub Stack);
impl fmt::Display for FmtStack {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.0.iter_str().enumerate().peekable();
        write!(f, "\n0:\t\t ")?;
        while let Some((index, mut item)) = iter.next() {
            if item.is_empty() {
                write!(f, "    []    ")?;
            } else {
                item.reverse();
                write!(f, "0x{:8}", item.as_hex())?;
            }
            if iter.peek().is_some() {
                if (index + 1) % f.width().unwrap_or(4) == 0 {
                    write!(f, "\n{}:\t\t", index + 1)?;
                }
                write!(f, " ")?;
            }
        }
        Ok(())
    }
}

impl FmtStack {
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn get(&self, index: usize) -> Vec<u8> {
        self.0.get(index)
    }
}

impl fmt::Debug for FmtStack {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ExecuteInfo {
    /// Whether the combined main/alt-stack item limit was enforced, both at
    /// entry and after every instruction. All helpers use a tapscript context.
    /// False means `research-unlimited`; true alone does not establish
    /// consensus or policy validity.
    pub stack_limit_enforced: bool,
    pub success: bool,
    pub error: Option<ExecError>,
    pub final_stack: FmtStack,
    pub remaining_script: String,
    pub last_opcode: Option<Opcode>,
    pub stats: ExecStats,
}

impl fmt::Display for ExecuteInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.stack_limit_enforced {
            writeln!(
                f,
                "Execution: tapscript, stack limit enforced; deployment unclassified."
            )?;
        } else {
            writeln!(
                f,
                "Execution: tapscript, research-unlimited (stack limit disabled)."
            )?;
        }
        if self.success {
            writeln!(f, "Script execution successful.")?;
        } else {
            writeln!(f, "Script execution failed!")?;
        }
        if let Some(ref error) = self.error {
            writeln!(f, "Error: {:?}", error)?;
        }
        if !self.remaining_script.is_empty() {
            if self.remaining_script.len() < 500 {
                writeln!(f, "Remaining Script: {}", self.remaining_script)?;
            } else {
                let mut string = self.remaining_script.clone();
                string.truncate(500);
                writeln!(f, "Remaining Script: {}...", string)?;
            }
        }
        if !self.final_stack.is_empty() {
            match f.width() {
                None => writeln!(f, "Final Stack: {:4}", self.final_stack)?,
                Some(width) => {
                    writeln!(f, "Final Stack: {:width$}", self.final_stack, width = width)?
                }
            }
        }
        if let Some(ref opcode) = self.last_opcode {
            writeln!(f, "Last Opcode: {:?}", opcode)?;
        }
        writeln!(f, "Stats: {:?}", self.stats)?;
        Ok(())
    }
}

pub fn execute_script(script: script::Script) -> ExecuteInfo {
    execute_script_buf_optional_stack_limit(script.compile_with_policy(), true)
}

pub fn execute_script_buf(script: bitcoin::ScriptBuf) -> ExecuteInfo {
    execute_script_buf_optional_stack_limit(script, true)
}

pub fn execute_script_without_stack_limit(script: script::Script) -> ExecuteInfo {
    execute_script_buf_optional_stack_limit(script.compile_with_policy(), false)
}

pub fn execute_script_buf_without_stack_limit(script: bitcoin::ScriptBuf) -> ExecuteInfo {
    execute_script_buf_optional_stack_limit(script, false)
}

fn execute_script_buf_optional_stack_limit(
    script: bitcoin::ScriptBuf,
    stack_limit: bool,
) -> ExecuteInfo {
    execute_script_buf_with_inputs_optional_stack_limit(script, vec![], stack_limit)
}

/// Execute in the research-unlimited tapscript context: the stack item count
/// is unlimited, but witness elements must still fit in 520 bytes.
pub fn execute_raw_script_with_inputs(script: Vec<u8>, witness: Vec<Vec<u8>>) -> ExecuteInfo {
    execute_raw_script_with_inputs_optional_stack_limit(script, witness, false)
}

/// Execute a tapscript with an explicit witness while enforcing Bitcoin's
/// combined 1,000-item main/alt-stack limit at entry and after each instruction,
/// including data pushes. Witness items must fit in 520 bytes. This is not a
/// complete consensus validator.
pub fn execute_raw_script_with_inputs_strict(
    script: Vec<u8>,
    witness: Vec<Vec<u8>>,
) -> ExecuteInfo {
    execute_raw_script_with_inputs_optional_stack_limit(script, witness, true)
}

fn execute_raw_script_with_inputs_optional_stack_limit(
    script: Vec<u8>,
    witness: Vec<Vec<u8>>,
    stack_limit: bool,
) -> ExecuteInfo {
    execute_script_buf_with_inputs_optional_stack_limit(
        ScriptBuf::from_bytes(script),
        witness,
        stack_limit,
    )
}

fn execute_script_buf_with_inputs_optional_stack_limit(
    script: ScriptBuf,
    witness: Vec<Vec<u8>>,
    stack_limit: bool,
) -> ExecuteInfo {
    let opts = Options {
        enforce_stack_limit: stack_limit,
        ..Default::default()
    };

    execute_script_buf_with_options(script, witness, opts).expect("error creating exec")
}

pub(crate) fn execute_script_buf_with_options(
    script: ScriptBuf,
    witness: Vec<Vec<u8>>,
    opts: Options,
) -> Result<ExecuteInfo, bitcoin_scriptexec::Error> {
    let stack_limit = opts.enforce_stack_limit;

    let exec = Exec::new(
        ExecCtx::Tapscript,
        opts,
        TxTemplate {
            tx: Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            prevouts: vec![],
            input_idx: 0,
            taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
        },
        script,
        witness,
    )?;

    Ok(run_exec(exec, stack_limit))
}

/// The repaired pinned interpreter checks entry resources and every executed
/// instruction, including data pushes. Keep one driver for all research and
/// explicit-profile entry points so the same upstream checks are exercised.
fn run_exec(mut exec: Exec, stack_limit: bool) -> ExecuteInfo {
    while exec.exec_next().is_ok() {}
    execution_snapshot(&exec, stack_limit)
}

fn execution_snapshot(exec: &Exec, stack_limit: bool) -> ExecuteInfo {
    let res = exec.result();
    let mut stats = exec.stats().clone();
    // Upstream can fail before updating statistics. Include the failing
    // instruction's live stack as well as all successfully executed steps.
    stats.max_nb_stack_items = stats
        .max_nb_stack_items
        .max(exec.stack().len() + exec.altstack().len());

    ExecuteInfo {
        stack_limit_enforced: stack_limit,
        success: res.is_some_and(|result| result.success),
        error: res.and_then(|result| result.error.clone()),
        last_opcode: res.and_then(|result| result.opcode),
        final_stack: FmtStack(exec.stack().clone()),
        remaining_script: exec.remaining_script().to_owned().to_asm_string(),
        stats,
    }
}

pub fn execute_script_with_inputs(script: script::Script, witness: Vec<Vec<u8>>) -> ExecuteInfo {
    execute_raw_script_with_inputs(script.compile_with_policy().to_bytes(), witness)
}

/// Compile with the repository policy and execute an explicit tapscript
/// witness with the combined stack limit enabled.
pub fn execute_script_with_inputs_strict(
    script: script::Script,
    witness: Vec<Vec<u8>>,
) -> ExecuteInfo {
    execute_raw_script_with_inputs_strict(script.compile_with_policy().to_bytes(), witness)
}

pub fn dry_run_taproot_input(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
) -> ExecuteInfo {
    let script = tx.input[input_index].witness.tapscript().unwrap();
    let stack = {
        let witness_items = tx.input[input_index].witness.to_vec();
        let last = witness_items.last().unwrap();
        let script_index =
            if witness_items.len() >= 3 && last.first() == Some(&TAPROOT_ANNEX_PREFIX) {
                witness_items.len() - 3
            } else {
                witness_items.len() - 2
            };
        witness_items[0..script_index].to_vec()
    };

    let leaf_hash = TapLeafHash::from_script(
        Script::from_bytes(script.as_bytes()),
        LeafVersion::TapScript,
    );

    let exec = Exec::new(
        ExecCtx::Tapscript,
        Options::default(),
        TxTemplate {
            tx: tx.clone(),
            prevouts: prevouts.into(),
            input_idx: input_index,
            taproot_annex_scriptleaf: Some((leaf_hash, None)),
        },
        ScriptBuf::from_bytes(script.to_bytes()),
        stack,
    )
    .expect("error creating exec");

    run_exec(exec, true)
}

pub fn run(script: script::Script) {
    let exec_result = execute_script(script);
    if !exec_result.success {
        println!(
            "ERROR: {:?} <--- \n STACK: {:4} ",
            exec_result.last_opcode, exec_result.final_stack
        );
    }
    assert!(exec_result.success);
}
