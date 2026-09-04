//! Exact table-only cost probe for the direct-limb 45-group Montgomery
//! torsion-coset slope-chain schedule.
//!
//! This generates no field-arithmetic kernel and executes no long-running
//! scalar multiplication. It measures policy-produced raw bytecode for 29
//! response tables and sixteen byte-aligned 128-bit challenge tables. Every
//! selected point is emitted directly as 16 `u`/`a` limbs and nine `v`/`b`
//! limbs, matching the transition kernel and requiring zero witness hints.
//!
//! Run with:
//! `cargo run --locked --release --example ed25519_montgomery_direct_fixed_table_probe`.

#[allow(dead_code)]
#[path = "ed25519_fixed_table_actual_model.rs"]
mod table_model;

fn main() {
    table_model::report_montgomery_direct_torsion_coset_tables();
}
