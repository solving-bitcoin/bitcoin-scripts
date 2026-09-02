//! BabyBear configuration for the generic 31-bit field backend.

use crate::arithmetic::u31::U31Config;

/// The BabyBear field with modulus `15 * 2^27 + 1`.
pub struct BabyBear;

impl U31Config for BabyBear {
    const MODULUS: u32 = 15 * (1 << 27) + 1;
}
