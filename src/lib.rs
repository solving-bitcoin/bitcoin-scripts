//! Bitcoin Script cryptographic and arithmetic primitives.

pub mod arithmetic;
pub mod ciphers;
pub mod commitments;
pub mod curves;
pub mod hashes;
pub mod signatures;
pub mod support;

// Keep the established public paths working while the source tree uses
// domain-oriented names.
pub use arithmetic::{bigint, rns, scriptint, u31, u32, u4};
pub use ciphers as cipher;
pub use curves::bn254;
pub use hashes as hash;
pub use support::execution::{
    dry_run_taproot_input, execute_raw_script_with_inputs, execute_script, execute_script_buf,
    execute_script_buf_without_stack_limit, execute_script_with_inputs,
    execute_script_without_stack_limit, run, ExecuteInfo, FmtStack,
};
pub use support::script_ops as pseudo;

#[allow(dead_code)]
pub mod script {
    pub use bitcoin_script::{script, Script};

    pub use crate::{execute_script, execute_script_without_stack_limit, run};
}
