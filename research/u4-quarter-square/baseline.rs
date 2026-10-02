//! Retained same-semantics table comparisons and modulo negative-result probe.
#![allow(dead_code)]
use bitcoin_lab::{
    arithmetic::{
        scriptint,
        u4::{
            mul,
            stack::{u4_drop, verify_canonical_nibble},
        },
    },
    support::script::*,
};
fn canonical_pair() -> Script {
    script! {{scriptint::verify_canonical()}OP_SWAP{scriptint::verify_canonical()}OP_SWAP}
}
fn quarter_setup() -> Script {
    script! { for x in (0u32..31).rev() { { (x*x/4)%16 } } }
}
fn quarter_query() -> Script {
    script! {
        {verify_canonical_nibble()} OP_SWAP {verify_canonical_nibble()} OP_SWAP
        OP_2DUP OP_SUB OP_ABS OP_TOALTSTACK
        OP_ADD OP_PICK
        OP_FROMALTSTACK 1 OP_ADD OP_PICK
        OP_SUB
        OP_DUP 0 OP_LESSTHAN OP_IF 16 OP_ADD OP_ENDIF
    }
}
fn full_setup(exact: bool) -> Script {
    if !exact {
        return mul::u4_push_full_product_table();
    }
    script! {for a in (0u32..16).rev(){for b in (0u32..16).rev(){{a*b}}}}
}
fn full_query(exact: bool) -> Script {
    if !exact {
        return script! {{canonical_pair()}{mul::u4_mul_mod16()}};
    }
    script! {
        {verify_canonical_nibble()} OP_SWAP {verify_canonical_nibble()} OP_SWAP
        OP_SWAP {scriptint::mul_by_constant(16)} OP_ADD OP_PICK
    }
}
pub fn batch(n: u32, quarter: bool, exact: bool) -> Script {
    if quarter && exact {
        return bitcoin_lab::arithmetic::u4::quarter_square::u4_pairwise_mul_exact(n);
    }
    assert!((1..=if quarter { 483 } else { 370 }).contains(&n));
    let items = if quarter { 31 } else { 256 };
    let setup = if quarter {
        quarter_setup()
    } else {
        full_setup(exact)
    };
    let query = if quarter {
        quarter_query()
    } else {
        full_query(exact)
    };
    script! {
        {setup}
        for _ in 0..n{
            {items}OP_ROLL {items+1}OP_ROLL OP_SWAP
            {query.clone()} OP_TOALTSTACK
        }
        {u4_drop(items)}
        for _ in 0..n{OP_FROMALTSTACK}
    }
}

pub fn full_exact(n: u32) -> Script {
    batch(n, false, true)
}
pub fn full_mod(n: u32) -> Script {
    batch(n, false, false)
}
pub fn quarter_mod(n: u32) -> Script {
    batch(n, true, false)
}
pub fn full_numeric_mod(n: u32) -> Script {
    assert!((1..=370).contains(&n));
    script! {
        {mul::u4_push_full_product_table()}
        for _ in 0..n{256 OP_ROLL 257 OP_ROLL OP_SWAP{mul::u4_mul_mod16()}OP_TOALTSTACK}
        {u4_drop(256)}
        for _ in 0..n{OP_FROMALTSTACK}
    }
}
