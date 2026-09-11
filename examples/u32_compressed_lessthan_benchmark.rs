use bitcoin::consensus::encode::serialize;
use bitcoin::{script::Instruction, Witness};
use bitcoin_lab::{
    arithmetic::u32::cmp::{u32_compressed_lessthan, u32_lessthan},
    support::{execution::execute_script_with_inputs_strict, script::ScriptCompilation},
};
use bitcoin_script::script;

fn scriptnum(value: u32) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value as i32));
    bytes[..length].to_vec()
}

fn byte_word(value: u32) -> [Vec<u8>; 4] {
    [
        scriptnum(value >> 24),
        scriptnum((value >> 16) & 0xff),
        scriptnum((value >> 8) & 0xff),
        scriptnum(value & 0xff),
    ]
}

fn static_non_push(script: &bitcoin_script::Script) -> usize {
    script
        .clone()
        .compile_with_policy()
        .instructions()
        .map(|instruction| instruction.expect("generated fragment must parse"))
        .filter(
            |instruction| matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() > 0x60),
        )
        .count()
}

fn main() {
    let a = 0x0102_0304;
    let b = 0x0506_0708;
    let compressed = u32_compressed_lessthan();
    let byte_baseline = u32_lessthan();
    let compressed_witness = vec![scriptnum(a), scriptnum(b)];
    let byte_witness = byte_word(a)
        .into_iter()
        .chain(byte_word(b))
        .collect::<Vec<_>>();
    let compressed_leaf = script! {
        { compressed.clone() }
        OP_VERIFY
        OP_TRUE
    };
    let byte_leaf = script! {
        { byte_baseline.clone() }
        OP_VERIFY
        OP_TRUE
    };
    let compressed_result =
        execute_script_with_inputs_strict(compressed_leaf, compressed_witness.clone());
    let byte_result = execute_script_with_inputs_strict(byte_leaf, byte_witness.clone());
    assert!(
        compressed_result.success,
        "compressed less-than failed: {compressed_result}"
    );
    assert!(byte_result.success, "byte less-than failed: {byte_result}");

    for (name, fragment, witness, result) in [
        (
            "compressed",
            compressed,
            compressed_witness,
            compressed_result,
        ),
        ("byte_baseline", byte_baseline, byte_witness, byte_result),
    ] {
        let compiled = fragment.clone().compile_with_policy();
        println!("{name}_script_bytes={}", compiled.len());
        println!(
            "{name}_witness_bytes={}",
            serialize(&Witness::from_slice(&witness)).len()
        );
        println!("{name}_witness_data_items={}", witness.len());
        println!("{name}_hint_items=0");
        println!("{name}_stack_peak={}", result.stats.max_nb_stack_items);
        println!("{name}_executed_opcodes={}", result.stats.opcode_count);
        println!(
            "{name}_static_non_push_opcodes={}",
            static_non_push(&fragment)
        );
        println!(
            "{name}_validation_weight_delta={}",
            result.stats.start_validation_weight - result.stats.validation_weight
        );
    }
    println!("context=tapscript stack_limit=1000");
}
