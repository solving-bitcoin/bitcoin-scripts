pub fn dense_mask(width: u32) -> Script {
    script! {
        for _ in 0..width { OP_EQUAL OP_TOALTSTACK }
        0
        for index in 0..width {
            OP_FROMALTSTACK OP_NOTIF
                0 OP_EQUALVERIFY { index + 1 }
            OP_ENDIF
        }
        OP_DUP OP_VERIFY OP_1SUB
    }
}
