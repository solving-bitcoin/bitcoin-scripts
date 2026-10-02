//! Canonical modulo-16 prefix sums in original order.
use super::stack::verify_canonical_nibble;
use crate::support::script::*;

/// Standalone maximum; unrelated main/alt items reduce this allowance.
pub const U4_PREFIX_SUM_MAX_BATCH: u32 = 997;

/// `preserved | x[0] ... x[n-1] -> preserved | s[0] ... s[n-1]`,
/// where `s[i] = sum(x[0..=i]) mod 16`. Checks canonical nibble encodings,
/// preserves caller altstack, and requires `n + 3 + preserved_items <= 1000`.
/// This fragment retains all outputs; the caller supplies terminal predicates.
pub fn u4_nibbles_to_prefix_sum(n: u32) -> Script {
    assert!(n > 0 && n <= U4_PREFIX_SUM_MAX_BATCH);
    script! {
        for _ in 0..n {OP_TOALTSTACK}
        OP_FROMALTSTACK {verify_canonical_nibble()}
        for _ in 1..n {
            OP_FROMALTSTACK {verify_canonical_nibble()}
            OP_OVER OP_ADD
            OP_DUP 16 OP_GREATERTHANOREQUAL
            OP_IF 16 OP_SUB OP_ENDIF
        }
    }
}
