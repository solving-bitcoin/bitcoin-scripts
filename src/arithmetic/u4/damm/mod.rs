//! Numeric decimal Damm checksum with a resident transition table.
use super::stack::u4_drop;
use crate::{arithmetic::scriptint::mul_by_constant, support::script::*};

/// Largest standalone batch; all surrounding main/alt state reduces capacity.
pub const DAMM_MAX_DIGITS: u32 = 896;

// Fixed table from CheckDigits.Net 734afa2d3596862ef4c3bb3ec404b512b96b8965.
// Original source and MIT license: research/damm-finite-state/reference/.
const Q: [[u8; 10]; 10] = [
    [0, 3, 1, 7, 5, 9, 8, 6, 4, 2],
    [7, 0, 9, 2, 1, 5, 4, 8, 6, 3],
    [4, 2, 0, 6, 8, 7, 1, 3, 5, 9],
    [1, 7, 5, 0, 9, 8, 3, 4, 2, 6],
    [6, 1, 2, 3, 0, 4, 5, 9, 7, 8],
    [3, 6, 7, 4, 2, 0, 9, 5, 8, 1],
    [5, 8, 6, 9, 7, 2, 0, 1, 3, 4],
    [8, 9, 4, 5, 3, 6, 2, 0, 1, 7],
    [9, 4, 3, 8, 6, 1, 7, 2, 0, 5],
    [2, 5, 8, 1, 4, 3, 6, 7, 9, 0],
];

/// Consume bottom-to-top numeric decimal digits in left-to-right order and
/// return the canonical Damm state, initially zero. Both caller stacks survive.
///
/// Every hostile digit is checked as an at-most-four-byte ScriptNum in 0..=9;
/// numeric aliases are allowed when the execution profile permits them. The
/// fixed table is installed once and removed before returning; there are no
/// hints. Empty input returns zero. This is error detection, not authentication:
/// the caller binds message meaning, result and a terminal predicate.
///
/// Combined peak excluding caller state: 1 if empty, otherwise digit_count+104.
/// Add both caller stacks and require the total to be at most 1,000.
pub fn u4_decimal_digits_to_damm(digit_count: u32) -> Script {
    assert!(
        digit_count <= DAMM_MAX_DIGITS,
        "Damm batch supports 0..=896 digits"
    );
    if digit_count == 0 {
        return script! {0};
    }
    script! {
        for a in (0..10).rev() {for b in (0..10).rev() {{Q[a][b]}}}
        0
        for i in 0..digit_count {
            {100+digit_count-i} OP_ROLL
            OP_DUP 0 10 OP_WITHIN OP_VERIFY
            OP_SWAP {mul_by_constant(10)} OP_ADD OP_PICK
        }
        OP_TOALTSTACK {u4_drop(100)} OP_FROMALTSTACK
    }
}
