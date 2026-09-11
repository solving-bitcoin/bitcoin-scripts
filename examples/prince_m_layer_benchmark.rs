use bitcoin::consensus::encode::serialize;
use bitcoin::{script::Instruction, Witness};
use bitcoin_lab::{
    ciphers::prince::prince_m_layer,
    support::{execution::execute_script_with_inputs_strict, script::ScriptCompilation},
};
use bitcoin_script::script;

fn main() {
    let fragment = prince_m_layer();
    let compiled = fragment.clone().compile_with_policy();
    let witness: Vec<Vec<u8>> = [
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
    ]
    .into_iter()
    .rev()
    .map(|nibble| if nibble == 0 { vec![] } else { vec![nibble] })
    .collect();
    let execution_leaf = script! {
        { fragment }
        for _ in 0..8 { OP_2DROP }
        OP_TRUE
    };
    let result = execute_script_with_inputs_strict(execution_leaf, witness.clone());
    assert!(result.success, "benchmark vector failed: {result}");

    let static_non_push = compiled
        .instructions()
        .map(|instruction| instruction.expect("generated fragment must parse"))
        .filter(
            |instruction| matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() > 0x60),
        )
        .count();
    println!("script_bytes={}", compiled.len());
    println!(
        "witness_bytes={}",
        serialize(&Witness::from_slice(&witness)).len()
    );
    println!("witness_data_items={}", witness.len());
    println!("hint_items=0");
    println!("stack_peak={}", result.stats.max_nb_stack_items);
    println!("executed_opcodes={}", result.stats.opcode_count);
    println!("static_non_push_opcodes={static_non_push}");
    println!(
        "validation_weight_delta={}",
        result.stats.start_validation_weight - result.stats.validation_weight
    );
    println!("context=tapscript stack_limit=1000");
}
