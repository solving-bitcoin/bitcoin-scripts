//! Matched research schedules, with no public adoption of their higher caps.
use bitcoin_lab::{
    arithmetic::{scriptint::mul_by_constant, u4::stack::u4_drop},
    support::script::*,
};
// Numeric table from the pinned MIT-licensed reference; see reference/LICENSE.txt.
pub const Q: [[u8; 10]; 10] = [
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
pub fn guard() -> Script {
    script! {OP_DUP 0 10 OP_WITHIN OP_VERIFY}
}
fn table() -> Script {
    script! {for a in (0..10).rev(){for b in (0..10).rev(){{Q[a][b]}}}}
}
fn map(lo: u32, hi: u32) -> Script {
    if hi - lo == 1 {
        return script! {OP_DROP{Q[lo as usize/10][lo as usize%10]}};
    }
    let mid = (lo + hi) / 2;
    script! {OP_DUP{mid}OP_LESSTHAN OP_IF{map(lo,mid)}OP_ELSE{map(mid,hi)}OP_ENDIF}
}
fn row_map(lo: u32, hi: u32) -> Script {
    if hi - lo == 1 {
        return script! {OP_DROP for d in (0..10).rev(){{Q[lo as usize][d]}}};
    }
    let mid = (lo + hi) / 2;
    script! {OP_DUP{mid}OP_LESSTHAN OP_IF{row_map(lo,mid)}OP_ELSE{row_map(mid,hi)}OP_ENDIF}
}
pub fn row_table(n: u32) -> Script {
    assert!(n <= 1000);
    if n == 0 {
        return script! {0};
    }
    script! {
        // Initial state zero selects the first row directly. Later rows are
        // runtime-selected; their ephemeral table contains ten live entries.
        {n-1}OP_ROLL{guard()}OP_TOALTSTACK
        for d in (0..10).rev(){{Q[0][d]}}
        OP_FROMALTSTACK OP_PICK
        OP_TOALTSTACK{u4_drop(10)}OP_FROMALTSTACK
        for i in 1..n {
            {n-i}OP_ROLL{guard()}OP_TOALTSTACK
            {row_map(0,10)} OP_FROMALTSTACK OP_PICK
            OP_TOALTSTACK{u4_drop(10)}OP_FROMALTSTACK
        }
    }
}
pub fn resident_unbounded(n: u32) -> Script {
    assert!(n <= 1000);
    if n == 0 {
        return script! {0};
    }
    script! {{table()}0 for i in 0..n{{100+n-i}OP_ROLL{guard()}OP_SWAP{mul_by_constant(10)}OP_ADD OP_PICK}OP_TOALTSTACK{u4_drop(100)}OP_FROMALTSTACK}
}
pub fn dispatch(n: u32) -> Script {
    assert!(n <= 1000);
    if n == 0 {
        return script! {0};
    }
    script! {{n-1}OP_ROLL{guard()}{map(0,10)}for i in 1..n{{n-i}OP_ROLL{guard()}OP_SWAP{mul_by_constant(10)}OP_ADD{map(0,100)}}}
}
pub fn warmup(n: u32) -> Script {
    assert!(n <= 1000);
    if n <= 1 {
        return dispatch(n);
    }
    script! {{n-1}OP_ROLL{guard()}{map(0,10)}OP_TOALTSTACK{table()}OP_FROMALTSTACK for i in 1..n{{100+n-i}OP_ROLL{guard()}OP_SWAP{mul_by_constant(10)}OP_ADD OP_PICK}OP_TOALTSTACK{u4_drop(100)}OP_FROMALTSTACK}
}
