use super::{mul_by_constant, script, verify_canonical_nibble, Script};

// Bound seed minus each product for canonical nibbles.
pub(super) fn bounds(seed: i32, weights: &[i32]) -> (i32, i32) {
    weights
        .iter()
        .fold((seed, seed), |(lower, upper), &weight| {
            (lower - 15 * weight.max(0), upper - 15 * weight.min(0))
        })
}

pub(super) fn reduce_mod17(lower: i32, upper: i32) -> Script {
    let bias = -17 * lower.div_euclid(17);
    let steps = u32::BITS - (((upper + bias) as u32) / 17).leading_zeros();
    let thresholds = (0..steps).rev().map(|shift| 17i32 << shift);
    script! {
        if bias != 0 { { bias } OP_ADD }
        for threshold in thresholds {
            OP_DUP { threshold } OP_GREATERTHANOREQUAL
            OP_IF { threshold } OP_SUB OP_ENDIF
        }
    }
}

// Keep the ordinary residual on main and the weighted residual on alt.
pub(super) fn scan(erased: usize, sum: u8, seed: i32, weights: &[i32]) -> Script {
    script! {
        { sum } { seed } OP_TOALTSTACK
        for (index, &weight) in weights.iter().enumerate().rev() {
            if index != erased {
                OP_SWAP { verify_canonical_nibble() }
                if weight == 0 {
                    OP_SUB
                } else {
                    OP_TUCK OP_SUB OP_SWAP
                    { mul_by_constant(weight.unsigned_abs()) }
                    OP_FROMALTSTACK OP_SWAP
                    if weight < 0 { OP_ADD } else { OP_SUB }
                    OP_TOALTSTACK
                }
            }
        }
    }
}

pub(super) fn recover_digit(width: usize, sum: u8) -> Script {
    let upper = i32::from(sum);
    script! {
        { reduce_mod17(upper - 15 * (width as i32 - 1), upper) }
        OP_DUP 16 OP_LESSTHAN OP_VERIFY
    }
}
