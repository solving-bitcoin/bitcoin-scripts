//! Anchor and first short check share scriptCode; short checks stay distinct.
//! Placeholder full-size serialization, not a complete extraction theorem.
#[allow(dead_code)]
#[path = "pointlock_anchored_typed_size_probe.rs"]
mod typed;

fn main() {
    typed::run(true);
}
