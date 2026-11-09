pub fn cross_sums(count: u32) -> Script {
    script! {
        OP_SIZE 4 OP_LESSTHANOREQUAL OP_VERIFY
        OP_SWAP OP_SIZE 4 OP_LESSTHANOREQUAL OP_VERIFY OP_SWAP
        for _ in 0..count - 2 {
            OP_ROT OP_SIZE 4 OP_LESSTHANOREQUAL OP_VERIFY
            OP_TUCK OP_ADD
            2 OP_PICK OP_DUP OP_ADD
            OP_EQUALVERIFY OP_SWAP
        }
        OP_2DROP
    }
}
