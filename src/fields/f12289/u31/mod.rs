//! F12289 configuration for the generic 31-bit field backend.

use crate::arithmetic::u31::U31Config;

/// The prime field with modulus `12,289`.
pub struct F12289;

impl U31Config for F12289 {
    const MODULUS: u32 = 12_289;
}
