#[path = "../research/integer-root-bounds/measure.rs"]
mod measure;
fn main() {
    let rev = std::env::args().nth(1).expect("source revision required");
    assert_eq!(rev.len(), 40);
    assert!(rev.bytes().all(|b| b.is_ascii_hexdigit()));
    println!(
        "{}",
        serde_json::to_string_pretty(&measure::report(&rev)).unwrap()
    )
}
