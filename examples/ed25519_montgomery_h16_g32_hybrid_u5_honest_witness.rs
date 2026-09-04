//! Deterministic host-only honest argument for the 803-item G32 hybrid-u5
//! custom BLAKE3-128 slope leaf.
//!
//! This replaces only the final challenge packet's eight packed Rtilde words
//! with 51 canonical biased radix-32 digits. It builds or executes no Script.

#[path = "ed25519_montgomery_h16_honest_witness.rs"]
mod honest_witness;

fn main() {
    honest_witness::run_g32_hybrid_u5_honest_witness_probe();
}
