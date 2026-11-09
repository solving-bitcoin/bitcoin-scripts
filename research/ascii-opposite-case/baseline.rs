pub fn raw_mate() -> Script {
    script! {
        OP_SIZE 1 OP_EQUALVERIFY
        OP_DUP 97 OP_GREATERTHANOREQUAL OP_IF
            32 OP_SUB
            OP_DUP 65 91 OP_WITHIN OP_VERIFY
        OP_ELSE
            OP_DUP 65 91 OP_WITHIN OP_VERIFY
            32 OP_ADD
        OP_ENDIF
        OP_EQUALVERIFY
    }
}

fn fold_with_case() -> Script {
    script! {
        OP_SIZE 1 OP_EQUALVERIFY
        OP_DUP 97 OP_GREATERTHANOREQUAL
        OP_TUCK OP_IF 32 OP_SUB OP_ENDIF
        OP_DUP 65 91 OP_WITHIN OP_VERIFY
    }
}

pub fn independent_fold() -> Script {
    script! {
        { fold_with_case() } OP_ROT
        { fold_with_case() } OP_ROT OP_NUMEQUALVERIFY
        OP_NUMNOTEQUAL OP_VERIFY
    }
}
