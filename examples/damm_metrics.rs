#[path = "../research/damm-finite-state/measure.rs"]
mod measure;
fn main() {
    let rev = std::env::args()
        .nth(1)
        .expect("source revision argument required");
    println!(
        "{}",
        serde_json::to_string_pretty(&measure::report(&rev)).unwrap()
    );
}
