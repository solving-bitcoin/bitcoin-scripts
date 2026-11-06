//! Stable selection of opaque stack items with native tapscript binary flags.
use super::script::*;

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
