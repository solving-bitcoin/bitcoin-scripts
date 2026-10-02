//! Exact products of canonical nibble pairs through quarter-square lookup.
use super::stack::{u4_drop, verify_canonical_nibble};
use crate::support::script::*;

/// Resident entries for Q(x)=floor(x*x/4), x=0..30.
pub const U4_QUARTER_SQUARE_TABLE_ITEMS: u32 = 31;
/// Maximum pair count before accounting for caller live main/alt state.
pub const U4_QUARTER_SQUARE_MAX_PAIRS: u32 = 483;

fn table() -> Script {
    script! { for x in (0..U4_QUARTER_SQUARE_TABLE_ITEMS).rev() { { x*x/4 } } }
}
fn product() -> Script {
    script! {
        { verify_canonical_nibble() }
        OP_SWAP { verify_canonical_nibble() } OP_SWAP
        OP_2DUP OP_SUB OP_ABS OP_TOALTSTACK
        OP_ADD OP_PICK
        OP_FROMALTSTACK 1 OP_ADD OP_PICK
        OP_SUB
    }
}

/// Consume `a[0] b[0] ... a[n-1] b[n-1]` and return ordered exact products.
///
/// Inputs are canonical ScriptNums in 0..15; outputs are canonical ScriptNums
/// in 0..225 (not necessarily one raw byte). Both caller stacks are preserved.
/// Setup, routing and cleanup are included. Requires
/// `2*n + 34 + preserved_items <= 1000`. No hints or terminal predicate.
pub fn u4_pairwise_mul_exact(pair_count: u32) -> Script {
    assert!((1..=U4_QUARTER_SQUARE_MAX_PAIRS).contains(&pair_count));
    script! {
        { table() }
        for _ in 0..pair_count {
            { U4_QUARTER_SQUARE_TABLE_ITEMS } OP_ROLL
            { U4_QUARTER_SQUARE_TABLE_ITEMS + 1 } OP_ROLL
            OP_SWAP
            { product() }
            OP_TOALTSTACK
        }
        { u4_drop(U4_QUARTER_SQUARE_TABLE_ITEMS) }
        for _ in 0..pair_count { OP_FROMALTSTACK }
    }
}
