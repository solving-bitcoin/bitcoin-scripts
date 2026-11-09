pub fn recomputed_depth(pair_count: u32) -> Script {
    script! {
        0
        for i in 0..pair_count {
            OP_DUP { 2 * (pair_count - i) } OP_ADD OP_ROLL
            OP_OVER { 2 * (pair_count - i) } OP_ADD OP_ROLL
            OP_IF
                OP_TOALTSTACK
            OP_ELSE
                OP_SWAP OP_1ADD
            OP_ENDIF
        }
    }
}
