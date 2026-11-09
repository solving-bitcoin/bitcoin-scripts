pub fn explicit_parity() -> Script {
    script! {
        OP_TOALTSTACK
        { schedule::prepare() } OP_ADD
        OP_FROMALTSTACK OP_IF
            { schedule::push_odd_candidate() }
        OP_ELSE
            OP_OVER OP_DUP OP_ADD
        OP_ENDIF
        OP_EQUALVERIFY
    }
}
