//! M31 configuration for the generic 31-bit field backend.

use crate::arithmetic::u31::U31Config;

/// The Mersenne prime field with modulus `2^31 - 1`.
pub struct M31;

impl U31Config for M31 {
    const MODULUS: u32 = (1 << 31) - 1;
}
