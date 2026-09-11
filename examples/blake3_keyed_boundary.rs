use bitcoin_lab::hashes::blake3::blake3_short_compute_script;

fn main() {
    let message: Vec<u8> = (0..32).collect();
    let key = [0x42u8; 32];
    let unkeyed = blake3::hash(&message);
    let mut keyed_hasher = blake3::Hasher::new_keyed(&key);
    keyed_hasher.update(&message);
    let keyed = keyed_hasher.finalize();

    assert_ne!(unkeyed, keyed);
    println!(
        "message_bytes={} key_bytes={} keyed_output_bytes={} current_mode=unkeyed current_compute_script_bytes={}",
        message.len(),
        key.len(),
        keyed.as_bytes().len(),
        blake3_short_compute_script(message.len()).len()
    );
}
