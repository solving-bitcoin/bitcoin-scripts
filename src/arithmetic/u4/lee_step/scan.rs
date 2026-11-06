use super::{script, verify_canonical_nibble, Script};

/// The measure maps a signed difference to a one-item comparable value.
pub(super) fn scan_with(n: u32, measure: Script, decode: Script) -> Script {
    script! {
        {verify_canonical_nibble()} OP_SWAP {verify_canonical_nibble()}
        OP_2DUP OP_SUB {measure.clone()}
        OP_ROT OP_DROP OP_TOALTSTACK
        for _ in 2..n {
            OP_SWAP {verify_canonical_nibble()}
            OP_TUCK OP_SUB {measure.clone()}
            OP_FROMALTSTACK OP_TUCK OP_NUMEQUALVERIFY OP_TOALTSTACK
        }
        OP_DROP OP_FROMALTSTACK {decode}
    }
}
