mod ops {
    include!("../../src/arithmetic/u32/dual_residue/ops.rs");
}

/// Check byte encodings once, then reduce with independent centered weights.
pub fn separate_residues() -> Script {
    script! {
        {ops::verify_word()} {OP_4DUP()}
        {ops::weighted_sum(2, -3)} 770 OP_ADD
        {ops::reduce_nonnegative(7, 1790)} OP_TOALTSTACK
        {ops::weighted_sum(-2, 4)} 513 OP_ADD
        {ops::reduce_nonnegative(9, 2043)}
        OP_FROMALTSTACK OP_SWAP
    }
}
