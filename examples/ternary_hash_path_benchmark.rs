use bitcoin::consensus::encode::serialize;
use bitcoin::Witness;
use bitcoin_lab::commitments::{
    ternary_hash_path_integer_commitment, ternary_hash_path_integer_witness,
    verify_ternary_hash_path_to_integer,
};
use bitcoin_lab::support::execution::execute_script_with_inputs_strict;
use bitcoin_lab::support::script::ScriptCompilation;

fn main() {
    let preimage = [0x42; 32];
    let value = 0x1234_5678;
    let commitment = ternary_hash_path_integer_commitment(&preimage, value, 31);
    let witness = ternary_hash_path_integer_witness(&preimage, value, 31);
    let verifier = verify_ternary_hash_path_to_integer(31, commitment);
    let execution = execute_script_with_inputs_strict(verifier.clone(), witness.clone());
    assert!(execution.success, "benchmark fixture failed: {execution}");
    let script_bytes = verifier.compile_with_policy().len();

    println!("primitive=ternary_hash_path_integer");
    println!("bit_width=31");
    println!("trit_count=20");
    println!("script_bytes={script_bytes}");
    println!(
        "witness_bytes={}",
        serialize(&Witness::from_slice(&witness)).len()
    );
    println!("witness_items={}", witness.len());
    println!("hint_items=0");
    println!("executed_opcodes={}", execution.stats.opcode_count);
    println!("commitment_bytes={}", commitment.len());
}
