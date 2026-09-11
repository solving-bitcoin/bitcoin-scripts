//! Compare the one-item compressed u32 right shift with the four-byte wire.

use bitcoin::consensus::encode::serialize;
use bitcoin::{script::Instruction, Witness};
use bitcoin_lab::{
    arithmetic::u32::{rshift::*, stack::*},
    support::{execution::execute_script_with_inputs_strict, script::ScriptCompilation},
};
use bitcoin_script::script;

fn scriptnum(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let len = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..len].to_vec()
}

fn compressed_witness(value: u32) -> Vec<Vec<u8>> {
    vec![scriptnum(i64::from(value as i32))]
}

fn byte_witness(value: u32) -> Vec<Vec<u8>> {
    [
        value >> 24,
        (value >> 16) & 0xff,
        (value >> 8) & 0xff,
        value & 0xff,
    ]
    .into_iter()
    .map(|byte| scriptnum(i64::from(byte)))
    .collect()
}

fn witness_bytes(items: &[Vec<u8>]) -> usize {
    serialize(&Witness::from_slice(items)).len()
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
    let value = 0xa5c3_19e7;
    println!("shift compressed_bytes byte_bytes compressed_witness byte_witness compressed_stack byte_stack compressed_static_ops byte_static_ops");
    for shift in [1, 3, 7, 8, 15, 16, 23, 24, 31] {
        let compressed = script! {
            { u32_compressed_rshift(shift) }
            OP_DROP
            OP_TRUE
        };
        let bytes = script! {
            { u32_bytes_rshift(shift) }
            { u32_drop() }
            OP_TRUE
        };
        let compressed_input = compressed_witness(value);
        let byte_input = byte_witness(value);
        let compressed_result =
            execute_script_with_inputs_strict(compressed.clone(), compressed_input.clone());
        let byte_result = execute_script_with_inputs_strict(bytes.clone(), byte_input.clone());
        assert!(compressed_result.success, "compressed shift {shift} failed");
        assert!(byte_result.success, "byte shift {shift} failed");
        println!(
            "{shift} {} {} {} {} {} {} {} {}",
            compressed.clone().compile_with_policy().len(),
            bytes.clone().compile_with_policy().len(),
            witness_bytes(&compressed_input),
            witness_bytes(&byte_input),
            compressed_result.stats.max_nb_stack_items,
            byte_result.stats.max_nb_stack_items,
            static_non_push_opcodes(compressed),
            static_non_push_opcodes(bytes),
        );
    }
}
