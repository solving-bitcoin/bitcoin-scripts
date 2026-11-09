pub fn branch_phase(width: u32) -> Script {
    script! {
        { schedule::start() }
        for _ in 0..width - 2 {
            { schedule::strict_ascent() }
            OP_IF
                OP_FROMALTSTACK OP_1ADD OP_TOALTSTACK
            OP_ELSE
                OP_FROMALTSTACK 0 OP_EQUALVERIFY 0 OP_TOALTSTACK
            OP_ENDIF
        }
        { schedule::finish() }
    }
}
