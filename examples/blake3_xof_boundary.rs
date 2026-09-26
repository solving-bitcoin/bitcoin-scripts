use bitcoin_lab::hashes::blake3::blake3_compute_script;
use bitcoin_lab::support::script::ScriptCompilation;

fn main() {
    let message: Vec<u8> = (0..32).collect();
    let mut xof = blake3::Hasher::new().update(&message).finalize_xof();
    let mut output = [0u8; 64];
    xof.fill(&mut output);
    assert_eq!(&output[..32], blake3::hash(&message).as_bytes());
    println!(
        "message_bytes=32 reference_xof_bytes={} current_output_contract_bytes=32 current_compute_script_bytes={}",
        output.len(),
        blake3_compute_script(32).compile_with_policy().len()
    );
}
