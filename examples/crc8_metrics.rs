#[path = "../research/crc8-nibble-feedback/measure.rs"]
mod measure;
fn main() {
    let revision = std::env::args().nth(1).expect("source revision required");
    assert_eq!(revision.len(), 40);
    assert!(revision.bytes().all(|b| b.is_ascii_hexdigit()));
    println!(
        "{}",
        serde_json::to_string_pretty(&measure::report(&revision)).unwrap()
    );
}
