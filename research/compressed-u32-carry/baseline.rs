pub fn complement_comparison() -> Script {
    script! {
        OP_SIZE 5 OP_LESSTHAN OP_IF
            OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
            OP_NEGATE OP_1SUB
        OP_ELSE
            { -2_147_483_648i64 } OP_EQUALVERIFY
            { 2_147_483_647i64 }
        OP_ENDIF
        OP_SWAP { u32_compressed_lessthan() }
    }
}

pub fn expanded_ripple() -> Script {
    script! {
        { u32_uncompress_canonical() } { u32_toaltstack() }
        { u32_uncompress_canonical() } { u32_fromaltstack() }
        { u32_zip(0, 1) }
        OP_ADD 256 OP_GREATERTHANOREQUAL
        for _ in 0..3 { OP_ADD OP_ADD 256 OP_GREATERTHANOREQUAL }
    }
}
