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
    pub success: bool,
    pub error: Option<ExecError>,
    pub final_stack: FmtStack,
    pub remaining_script: String,
    pub last_opcode: Option<Opcode>,
    pub stats: ExecStats,
}

impl fmt::Display for ExecuteInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    let opts = Options {
        enforce_stack_limit: stack_limit,
        ..Default::default()
    };
    let mut exec = Exec::new(
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
        vec![],
    )
    .expect("error creating exec");

    loop {
        if exec.exec_next().is_err() {
            break;
        }
    }

    let res = exec.result().unwrap();
    ExecuteInfo {
        success: res.success,
        error: res.error.clone(),
        last_opcode: res.opcode,
        final_stack: FmtStack(exec.stack().clone()),
        remaining_script: exec.remaining_script().to_asm_string(),
        stats: exec.stats().clone(),
    }
}

pub fn execute_raw_script_with_inputs(script: Vec<u8>, witness: Vec<Vec<u8>>) -> ExecuteInfo {
    let opts = Options {
        enforce_stack_limit: false,
        ..Default::default()
    };

    let mut exec = Exec::new(
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
        ScriptBuf::from_bytes(script),
        witness,
    )
    .expect("error creating exec");

    loop {
        match exec.exec_next() {
            Ok(()) => (),
            Err(_) => break,
        }
    }

    let res = exec.result().unwrap();
    ExecuteInfo {
        success: res.success,
        error: res.error.clone(),
        last_opcode: res.opcode,
        final_stack: FmtStack(exec.stack().clone()),
        remaining_script: exec.remaining_script().to_owned().to_asm_string(),
        stats: exec.stats().clone(),
    }
}

pub fn execute_script_with_inputs(script: script::Script, witness: Vec<Vec<u8>>) -> ExecuteInfo {
    execute_raw_script_with_inputs(script.compile_with_policy().to_bytes(), witness)
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

    let mut exec = Exec::new(
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

    loop {
        if exec.exec_next().is_err() {
            break;
        }
    }
    let res = exec.result().unwrap();
    ExecuteInfo {
        success: res.success,
        error: res.error.clone(),
        last_opcode: res.opcode,
        final_stack: FmtStack(exec.stack().clone()),
        remaining_script: exec.remaining_script().to_asm_string(),
        stats: exec.stats().clone(),
    }
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
