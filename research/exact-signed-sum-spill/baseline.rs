pub fn precheck_headroom() -> Script {
    script! {
        OP_SIZE 4 OP_LESSTHANOREQUAL OP_VERIFY
        OP_SWAP OP_SIZE 4 OP_LESSTHANOREQUAL OP_VERIFY OP_SWAP
        OP_DUP 0 OP_LESSTHAN OP_IF
            OP_DUP { -BOUND } OP_SWAP OP_SUB
            2 OP_PICK OP_GREATERTHAN OP_IF
                { BOUND } OP_ADD OP_ADD -1
            OP_ELSE OP_ADD 0 OP_ENDIF
        OP_ELSE
            OP_DUP { BOUND } OP_SWAP OP_SUB
            2 OP_PICK OP_LESSTHAN OP_IF
                { BOUND } OP_SUB OP_ADD 1
            OP_ELSE OP_ADD 0 OP_ENDIF
        OP_ENDIF
    }
}
