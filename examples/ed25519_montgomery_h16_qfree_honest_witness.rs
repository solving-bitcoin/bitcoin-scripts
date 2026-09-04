//! Deterministic honest witness for the quotient-derived custom BLAKE3-128
//! Ed25519 Montgomery-slope verifier.
//!
//! This focused host probe emits exactly 712 entry items in q-free scheduler
//! order: 16 challenge trace packets, 28 response trace packets, and eight
//! scalar words. It supplies zero quotient hints. The shared honest fixture
//! still reconstructs and audits all 44 curve/continuity relation pairs so
//! the verifier-derived quotients and both carry directions are checked here
//! without generating or executing the multi-megabyte leaf.

#[allow(dead_code)]
#[path = "ed25519_montgomery_h16_honest_witness.rs"]
mod honest_witness;

fn main() {
    honest_witness::run_qfree_honest_witness_probe();
}
