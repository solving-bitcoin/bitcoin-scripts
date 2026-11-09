//! Stable selection of opaque stack items using sparse indices.

use super::script::*;
use crate::arithmetic::scriptint::verify_canonical;

/// Consume `payload[0] ... payload[n-1] depth[k-1] ... depth[0]` and leave
/// the selected payloads in their original order, followed by the count.
///
/// Depths are canonical ScriptNums relative to the original payload block
/// (zero is the top payload) and must strictly increase in consumption order.
/// Both caller stacks are preserved for an exact input suffix. The caller is
/// responsible for binding the suffix shape, selection meaning and outputs.
/// The fragment needs no hints. The combined peak is at most `n + k + 4`
/// items in addition to preserved caller state.
pub fn compact_indexed_items(n: u32, k: u32) -> Script {
    assert!(
        (1..996).contains(&n) && (1..=n).contains(&k) && k <= 996 - n,
        "indexed selection requires 1 <= k <= n and n + k <= 996"
    );
    script! {
        -1
        for j in 0..k {
            OP_SWAP
            { verify_canonical() }
            OP_2DUP OP_LESSTHAN OP_VERIFY
            OP_NIP
            OP_DUP { n } OP_LESSTHAN OP_VERIFY

            // j shallower payloads have moved. The retained depth and
            // k-j-1 unread selectors still sit above the remaining payloads.
            OP_DUP { k as i32 - 2 * j as i32 } OP_ADD
            OP_ROLL OP_TOALTSTACK
        }
        OP_DROP
        for _ in k..n {
            OP_DROP
        }
        for _ in 0..k {
            OP_FROMALTSTACK
        }
        { k }
    }
}
