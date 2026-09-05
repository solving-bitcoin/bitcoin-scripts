//! The Ed25519 base field `GF(2^255 - 19)`.

pub mod bigint9;
/// Radix-16 backend with balanced 20-bit left limbs.
pub mod u4_balanced_table;
/// Radix-16 backend with operand-specific multiplication tables.
pub mod u4_table;
/// Centered radix-32 backend with balanced 20-bit left limbs.
pub mod u5_balanced_table;
/// Eight-item packed wires for the centered radix-32 backend.
pub mod u5_packed;
/// Packed-word decoding directly to centered 20/15-bit grouped limbs.
pub mod u5_packed_grouped;
/// Radix-32 backend with 5-bit operand tables.
pub mod u5_table;
