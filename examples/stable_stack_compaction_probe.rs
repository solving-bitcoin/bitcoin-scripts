//! Reproduce stable-compaction costs, native/explicit comparisons and bindings.
#[path = "../research/stable-stack-compaction/measure.rs"]
mod measure;
fn main() {
    let revision = std::env::args()
        .nth(1)
        .expect("pass measured source commit");
    println!(
        "{}",
        serde_json::to_string_pretty(&measure::report(&revision)).unwrap()
    );
}
