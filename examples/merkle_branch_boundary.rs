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
    let fixture_witness = Witness::from_slice(&vec![vec![1u8]; 64]);
    let maximum_witness = Witness::from_slice(&vec![vec![0xff, 0x00]; 64]);
    let fixture_witness_bytes = serialize(&fixture_witness).len();
    let maximum_witness_bytes = serialize(&maximum_witness).len();
    assert_eq!(script.len(), 1_060_200);
    assert_eq!(static_non_push_opcodes, 770_481);
    assert_eq!(fixture_witness_bytes, 129);
    assert_eq!(maximum_witness_bytes, 193);
    println!(
        "sha256_64_bytes_unoptimized={} witness_fixture_bytes={} witness_max_bytes={} data_items=64 hints=0 static_non_push_opcodes={}",
        script.len(),
        fixture_witness_bytes,
        maximum_witness_bytes,
        static_non_push_opcodes
    );
}
