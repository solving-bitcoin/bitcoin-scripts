//! Deterministic honest witness for the G31 quotient-derived custom
//! BLAKE3-128 Ed25519 Montgomery-slope verifier.
//!
//! This host-only probe emits `challenge16 trace | response30 trace | scalar8`:
//! 744 coexisting entry items and zero quotient hints. It audits every exact
//! quotient/carry relation and the signature equation without generating or
//! executing the multi-megabyte leaf.

#[allow(dead_code)]
#[path = "ed25519_montgomery_h16_honest_witness.rs"]
mod honest_witness;

fn main() {
    honest_witness::run_g31_qfree_honest_witness_probe();
}
