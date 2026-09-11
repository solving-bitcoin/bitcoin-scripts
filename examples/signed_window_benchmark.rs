//! Compare the shared signed-radix-32 lookup table with branch extraction.
//!
//! Run with:
//! `cargo run --locked --release --example signed_window_benchmark`

use bitcoin::{consensus::encode::serialize, script::Instruction, Witness};
use bitcoin_lab::{
    arithmetic::signed_window,
    support::{execution::execute_script_with_inputs_strict, script::ScriptCompilation},
};
use bitcoin_script::script;

fn scriptnum(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let len = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..len].to_vec()
}

fn branch_digit_to_altstack() -> bitcoin_script::Script {
    script! {
        OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
        OP_DUP 0 OP_LESSTHAN
        OP_SWAP OP_ABS OP_SWAP OP_TOALTSTACK
        for bit in (0..5).rev() {
            OP_DUP { 1i64 << bit } OP_GREATERTHANOREQUAL
            OP_IF
                { 1i64 << bit } OP_SUB OP_1
            OP_ELSE
                OP_0
            OP_ENDIF
            OP_TOALTSTACK
        }
        OP_DROP
    }
}

fn finish_batch(fragment: bitcoin_script::Script, count: u32) -> bitcoin_script::Script {
    script! {
        { fragment }
        for _ in 0..6 * count { OP_FROMALTSTACK OP_DROP }
        OP_TRUE
    }
}

fn static_non_push_opcodes(script: bitcoin_script::Script) -> usize {
    script
        .compile_with_policy()
        .instructions()
        .map(|instruction| instruction.expect("generated script must parse"))
        .filter(
            |instruction| matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() > 0x60),
        )
        .count()
}

fn main() {
    println!("digits table_bytes branch_bytes table_delta table_stack branch_stack table_non_push branch_non_push witness_bytes");
    for count in [1, 2, 4, 8, 16, 32, 64, 128, 140] {
        let count = count as u32;
        let table = finish_batch(signed_window::digits_to_altstack(count, true), count);
        let branch = finish_batch(
            script! {
                for _ in 0..count { { branch_digit_to_altstack() } }
            },
            count,
        );
        let witness = vec![scriptnum(31); count as usize];
        let table_result = execute_script_with_inputs_strict(table.clone(), witness.clone());
        let branch_result = execute_script_with_inputs_strict(branch.clone(), witness.clone());
        assert!(table_result.success, "table failed: {table_result}");
        assert!(branch_result.success, "branch failed: {branch_result}");
        let witness_bytes = serialize(&Witness::from_slice(&witness)).len();
        let table_bytes = table.clone().compile_with_policy().len();
        let branch_bytes = branch.clone().compile_with_policy().len();
        let table_non_push = static_non_push_opcodes(table.clone());
        let branch_non_push = static_non_push_opcodes(branch.clone());
        println!(
            "{count} {table_bytes} {branch_bytes} {} {} {} {} {} {witness_bytes}",
            branch_bytes as isize - table_bytes as isize,
            table_result.stats.max_nb_stack_items,
            branch_result.stats.max_nb_stack_items,
            table_non_push,
            branch_non_push,
        );
    }
}
