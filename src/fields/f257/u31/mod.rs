//! F257 configuration for the generic 31-bit field backend.

use crate::arithmetic::u31::U31Config;

/// The prime field with modulus `257`.
pub struct F257;

impl U31Config for F257 {
    const MODULUS: u32 = 257;
}
