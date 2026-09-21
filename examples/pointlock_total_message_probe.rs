//! Compose scalar-to-membership, per-pool rank and total garbled message decoding.
//! All secrets are public test fixtures; public malicious-setup binding is absent.
#[allow(dead_code)]
#[path = "pointlock_complement_translation_probe.rs"]
mod complement;

fn main() {
    complement::composed::run();
}
