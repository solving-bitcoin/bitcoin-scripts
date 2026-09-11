use bitcoin::consensus::encode::serialize;
use bitcoin::script::Instruction;
use bitcoin::Witness;
use bitcoin_lab::hashes::sha256::sha2_u32::sha256;
use bitcoin_lab::support::script::ScriptCompilation;

fn main() {
    let script = sha256(64).compile_with_policy();
    let static_non_push_opcodes = script
        .instructions()
        .map(Result::unwrap)
        .filter(
            |instruction| matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() > 0x60),
        )
        .count();
    let witness = Witness::from_slice(&vec![vec![1u8]; 64]);
    let witness_bytes = serialize(&witness).len();
    assert_eq!(script.len(), 1_060_200);
    assert_eq!(static_non_push_opcodes, 770_481);
    assert_eq!(witness_bytes, 129);
    println!(
        "sha256_64_bytes={} witness_max={} static_non_push_opcodes={}",
        script.len(),
        witness_bytes,
        static_non_push_opcodes
    );
}
