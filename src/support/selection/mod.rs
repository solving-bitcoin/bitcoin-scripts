//! Stable selection of opaque stack items with binary flags or sparse indices.
use super::script::*;
use crate::arithmetic::scriptint::verify_canonical;

pub const MAX_PAIRS: u32 = 499;

/// Consume `data[0] flag[0] ... data[n-1] flag[n-1]` and return the retained
/// payloads in their original order, followed by their canonical numeric count.
/// Both caller stacks are preserved. There are no hints or resident tables.
///
/// Tapscript MINIMALIF validates every flag as exactly empty or `[1]`. This
/// canonical flag contract does not hold in legacy truthy-IF contexts. Payloads
/// are opaque, including empty and nonnumeric strings, subject to entry element
/// limits. The caller must bind selector meaning, outputs/count, and a terminal
/// predicate; selection itself does not authenticate or certify payloads.
///
/// Combined peak excluding preserved caller state: 1 for n=0; at most 4 for
/// n=1 (3 if discarded); 2n+1 for n>=2. Require the total to be at most 1000.
pub fn compact_selected_items(pair_count: u32) -> Script {
    assert!(
        pair_count <= MAX_PAIRS,
        "stable selection supports 0..=499 pairs"
    );
    script! {
        0
        for _ in 0..pair_count {
            OP_SWAP OP_IF
                OP_SWAP OP_TOALTSTACK OP_1ADD
            OP_ELSE OP_SWAP OP_DROP OP_ENDIF
        }
        for i in 0..pair_count {
            OP_DUP {i} OP_GREATERTHAN
            OP_IF OP_FROMALTSTACK OP_SWAP OP_ENDIF
        }
    }
}

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
