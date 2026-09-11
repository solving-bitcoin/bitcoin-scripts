use bitcoin::consensus::encode::serialize;
use bitcoin::Witness;
use bitcoin_lab::hashes::shake256::shake256_prefix;
use bitcoin_lab::support::execution::execute_script_with_inputs_strict;
use bitcoin_lab::support::script::{script, ScriptCompilation};

fn main() {
    let witness = vec![vec![0x42]; 32];
    let prefix = shake256_prefix(32, 32);
    let measured = script! {
        { prefix.clone() }
        for _ in 0..16 { OP_2DROP }
        OP_TRUE
    };
    let execution = execute_script_with_inputs_strict(measured, witness.clone());
    assert!(execution.success, "benchmark fixture failed: {execution}");

    println!("primitive=shake256_prefix");
    println!("message_bytes=32");
    println!("output_bytes=32");
    println!("script_bytes={}", prefix.compile_with_policy().len());
    println!(
        "witness_bytes={}",
        serialize(&Witness::from_slice(&witness)).len()
    );
    println!("witness_items={}", witness.len());
    println!("hint_items=0");
    println!("stack_peak={}", execution.stats.max_nb_stack_items);
    println!("executed_opcodes={}", execution.stats.opcode_count);
    println!("execution_class=unclassified");
}
