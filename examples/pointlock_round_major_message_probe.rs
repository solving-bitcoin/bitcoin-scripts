//! Compose the exact native 95-pool fixture with its total 2048-bit garbled decoder.
//! Honest setup only: public malicious-setup binding and general extraction remain open.
#[allow(dead_code)]
#[path = "pointlock_decoders/round_major_complement.rs"]
mod complement;

fn main() {
    complement::composed::run();
}
