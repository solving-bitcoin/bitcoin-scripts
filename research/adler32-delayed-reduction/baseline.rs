//! Research-only schedules with the same canonical byte/two-residue boundary.
use bitcoin_lab::{arithmetic::u32::stack::verify_canonical_byte, support::script::*};
const P: u32 = 65_521;
fn reduce(bound: u32) -> Script {
    let mut multiples = Vec::new();
    let mut multiple = P;
    while multiple <= bound {
        multiples.push(multiple);
        multiple *= 2;
    }
    script! {for multiple in multiples.into_iter().rev(){
        OP_DUP {multiple} OP_GREATERTHANOREQUAL
        OP_IF {multiple} OP_SUB OP_ENDIF
    }}
}
/// Normalizes each state per byte, omitting unreachable prefix reductions.
pub fn bounded_streaming(n: u32) -> Script {
    streaming(n, true)
}
/// Naive per-byte bounds retained to demonstrate a fragment/leaf policy split.
pub fn naive_streaming(n: u32) -> Script {
    streaming(n, false)
}
fn streaming(n: u32, prefix_bounds: bool) -> Script {
    assert!(n <= 1000);
    script! {
        for _ in 0..n{{verify_canonical_byte()} OP_TOALTSTACK}
        1 0
        for i in 0..n {
            OP_FROMALTSTACK OP_ROT OP_ADD
            {reduce(if prefix_bounds{(1+255*i).min(P-1)+255}else{P-1+255})}
            OP_DUP OP_ROT OP_ADD
            {reduce(if prefix_bounds{
                (i+255*i*(i+1)/2).min(P-1)+(1+255*(i+1)).min(P-1)
            }else{2*(P-1)})}
        }
    }
}
/// Initial schedule: validation overlaps the two accumulators, peaking at n+5.
pub fn interleaved(n: u32) -> Script {
    assert!(n <= 1000);
    script! {
        for _ in 0..n{OP_TOALTSTACK}
        1 0
        for _ in 0..n{
            OP_FROMALTSTACK{verify_canonical_byte()}OP_ROT OP_ADD OP_DUP OP_ROT OP_ADD
        }
        OP_SWAP {reduce(1+255*n)} OP_SWAP {reduce(n+255*n*(n+1)/2)}
    }
}
