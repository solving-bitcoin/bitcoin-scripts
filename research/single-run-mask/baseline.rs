/// Decode the interval with a separate closed flag alongside start and length.
pub fn decode_with_closed_flag(n: u32) -> Script {
    script! {
        OP_IF 0 1 OP_ELSE 1 0 OP_ENDIF 0
        for _ in 1..n {
            3 OP_ROLL
            OP_IF
                OP_DUP OP_NOT OP_VERIFY
                OP_SWAP OP_1ADD OP_SWAP
            OP_ELSE
                OP_OVER OP_0NOTEQUAL
                OP_IF OP_DROP 1
                OP_ELSE OP_ROT OP_1ADD OP_ROT OP_ROT
                OP_ENDIF
            OP_ENDIF
        }
        OP_DROP OP_DUP OP_VERIFY
    }
}
