pub fn verify_separate_hashes(hash160: [u8; 20], hash256: [u8; 32]) -> Script {
    script! {
        OP_DUP
        OP_HASH160 {hash160.to_vec()} OP_EQUALVERIFY
        OP_HASH256 {hash256.to_vec()} OP_EQUALVERIFY
    }
}
