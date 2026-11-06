pub fn multiply_first(width: u32) -> Script {
    script! {
        { schedule::verify_bit() }
        for position in 1..width {
            OP_SWAP { schedule::verify_bit() } OP_SWAP
            if position == 31 {
                OP_DUP { 1 << 30 } OP_NUMEQUAL OP_IF
                    OP_DROP 1 OP_EQUALVERIFY { -2_147_483_647i64 }
                OP_ELSE
                    OP_DUP { 1 << 30 } OP_LESSTHAN OP_VERIFY
                    OP_DUP OP_ADD OP_SUB
                OP_ENDIF
            } else {
                OP_DUP OP_ADD OP_SUB
            }
        }
    }
}
