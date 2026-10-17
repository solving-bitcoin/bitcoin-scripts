//! Reproduce the canonical Adler-state comparison and artifact bindings.
#[path = "../research/adler32-delayed-reduction/measure.rs"]
mod measure;
fn main() {
    let revision = std::env::args()
        .nth(1)
        .expect("pass the measured source commit");
    println!(
        "{}",
        serde_json::to_string_pretty(&measure::report(&revision)).unwrap()
    );
}
