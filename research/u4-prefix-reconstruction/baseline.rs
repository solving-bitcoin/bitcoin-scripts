//! Same canonical prefix-vector boundary with a 31-item lookup table.
use bitcoin_lab::{
    arithmetic::u4::stack::{u4_drop, verify_canonical_nibble},
    support::script::*,
};
pub fn table(n: u32) -> Script {
    assert!(n > 0 && n <= 966);
    if n == 1 {
        return script! {{verify_canonical_nibble()}};
    }
    script! {
        for _ in 0..n {OP_TOALTSTACK}
        for value in (0..31u32).rev() {{value%16}}
        OP_FROMALTSTACK {verify_canonical_nibble()}
        for index in 1..n {
            OP_FROMALTSTACK {verify_canonical_nibble()}
            OP_OVER OP_ADD
            {index} OP_ADD OP_PICK
        }
        for _ in 0..n {OP_TOALTSTACK}
        {u4_drop(31)}
        for _ in 0..n {OP_FROMALTSTACK}
    }
}

pub fn roundtrip(n: u32) -> Script {
    assert!((2..=499).contains(&n));
    script! {
        for i in 0..n{{n-1-i}OP_PICK{verify_canonical_nibble()}OP_DROP}
        {n-1}OP_PICK OP_TOALTSTACK
        {bitcoin_lab::arithmetic::u4::adjacent_delta::u4_nibbles_to_adjacent_delta(n)}
        OP_FROMALTSTACK
        for _ in 0..n-1{{n-1}OP_ROLL}
        {bitcoin_lab::arithmetic::u4::prefix_sum::u4_nibbles_to_prefix_sum(n)}
    }
}
