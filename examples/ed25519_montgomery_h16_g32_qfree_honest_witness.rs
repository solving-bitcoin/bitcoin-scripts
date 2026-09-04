//! Deterministic host-only honest witness for the G32 quotient-derived
//! Montgomery-slope candidate.
//!
//! This keeps G29 and G31 fixtures untouched. It serializes
//! `challenge16 trace | response31 trace | scalar8`, audits all 47 transition
//! pairs, and deliberately does not construct or execute a multi-megabyte
//! Script. Linked size and transaction envelope remain pending selection of
//! the hybrid-kernel schedule.

#[allow(dead_code)]
#[path = "ed25519_montgomery_h16_honest_witness.rs"]
mod honest_witness;

fn main() {
    honest_witness::run_g32_qfree_honest_witness_probe();
}
