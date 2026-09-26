use bitcoin::consensus::encode::serialize;
use bitcoin::script::Instruction;
use bitcoin::Witness;
use bitcoin_lab::arithmetic::u32::shift::u32_compressed_rshift;
use bitcoin_lab::arithmetic::u32::stack::{u32_compress, u32_uncompress};
use bitcoin_lab::support::execution::execute_raw_script_with_inputs_strict;
use bitcoin_lab::support::script::{Script, ScriptCompilation};
use bitcoin_script::script;

fn scriptnum(value: u32) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value as i32));
    bytes[..length].to_vec()
}

fn byte_shift8() -> Script {
    script! {
        OP_TOALTSTACK
        OP_TOALTSTACK
        OP_TOALTSTACK
        OP_TOALTSTACK
        0
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_DROP
    }
}

fn measure(name: &str, script: Script, witness: Vec<Vec<u8>>) {
    let leaf = script! {
        { script }
        OP_VERIFY
        OP_TRUE
    }
    .compile_with_policy();
    let result = execute_raw_script_with_inputs_strict(leaf.to_bytes(), witness);
    assert!(result.success, "{name} failed: {result}");
    let static_non_push_opcodes = leaf
        .instructions()
        .map(|instruction| instruction.expect("generated benchmark script must parse"))
        .filter(|instruction| !matches!(instruction, Instruction::PushBytes(_)))
        .count();
    println!("{name}_script_bytes={}", leaf.len());
    println!(
        "{name}_witness_bytes={}",
        serialize(&Witness::from_slice(&[scriptnum(0x89ab_cdef)])).len()
    );
    println!("{name}_witness_data_items=1");
    println!("{name}_hint_items=0");
    println!("{name}_stack_peak={}", result.stats.max_nb_stack_items);
    println!("{name}_executed_opcodes=0");
    println!("{name}_static_non_push_opcodes={static_non_push_opcodes}");
    println!(
        "{name}_validation_weight_delta={}",
        result.stats.validation_weight
    );
}

fn main() {
    const VALUE: u32 = 0x89ab_cdef;
    let witness = vec![scriptnum(VALUE)];
    measure("compressed", u32_compressed_rshift(8), witness.clone());
    measure(
        "decode_shift_encode_baseline",
        script! { { u32_uncompress() } { byte_shift8() } { u32_compress() } },
        witness,
    );
    println!("context=tapscript stack_limit=1000");
}
