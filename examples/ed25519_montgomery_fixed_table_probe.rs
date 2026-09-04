//! Exact table-only cost probe for the 43-group Montgomery torsion-coset
//! slope-chain schedule.
//!
//! This generates no field-arithmetic kernel and executes no long-running
//! scalar-multiplication test. It measures policy-produced raw table bytecode:
//! 29 response groups (one P0 initializer plus 28 additions) and 14 additions
//! for a custom 128-bit challenge. The table constants live in the locking
//! script and require exactly zero witness-hint items.

#[allow(dead_code)]
#[path = "ed25519_fixed_table_actual_model.rs"]
mod table_model;

fn main() {
    table_model::report_montgomery_torsion_coset_tables();
}
