//! Comparison schedules copied from the immutable initial prototype.
use bitcoin_lab::{arithmetic::scriptint::mul_by_constant, support::script::*};
pub fn max(bits: u32) -> u32 {
    assert!((1..=31).contains(&bits));
    (1u32 << bits) - 1
}
pub fn guard(bits: u32) -> Script {
    script! {OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY OP_DUP {max(bits)} OP_LESSTHANOREQUAL OP_VERIFY}
}
#[cfg(test)]
pub fn restoring(bits: u32) -> Script {
    let root_bits = (bits + 1) / 2;
    script! {
        {guard(bits)} 0
        for bit in (0..root_bits).rev() {
            // Main: residual, root. Candidate square difference fits ScriptNum.
            OP_DUP {mul_by_constant(2*(1u32<<bit))} {(1u32<<bit).pow(2)} OP_ADD
            2 OP_PICK OP_OVER OP_GREATERTHANOREQUAL
            OP_IF
                OP_ROT OP_SWAP OP_SUB OP_SWAP {1u32<<bit} OP_ADD
            OP_ELSE OP_DROP OP_ENDIF
        }
        OP_NIP
    }
}
pub fn host_root(x: u32) -> u32 {
    let (mut lo, mut hi) = (0u32, 65536u32);
    while lo + 1 < hi {
        let m = (lo + hi) / 2;
        if u64::from(m) * u64::from(m) <= u64::from(x) {
            lo = m
        } else {
            hi = m
        }
    }
    lo
}
fn threshold_map(lo: u32, hi: u32) -> Script {
    if lo == hi {
        return script! {OP_DROP{lo}};
    }
    let mid = (lo + hi + 1) / 2;
    script! {OP_DUP {mid*mid} OP_LESSTHAN OP_IF {threshold_map(lo,mid-1)} OP_ELSE {threshold_map(mid,hi)} OP_ENDIF}
}
pub fn thresholds(bits: u32) -> Script {
    script! {{guard(bits)}{threshold_map(0,host_root(max(bits)))}}
}
