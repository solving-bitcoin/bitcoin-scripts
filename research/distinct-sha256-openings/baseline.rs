mod routing {
    include!("../../src/commitments/sha256_pool/routing.rs");
}

use routing::{check_rank, push_digests};

pub fn fixed_indices(digests: &[[u8; 32]]) -> Script {
    let n = digests.len();
    script! {
        {push_digests(digests)}
        {n} OP_ROLL {check_rank(n)}
        OP_DUP OP_TOALTSTACK
        OP_PICK {n+1} OP_ROLL OP_SHA256 OP_EQUALVERIFY
        {n} OP_ROLL {check_rank(n)}
        OP_DUP OP_FROMALTSTACK OP_NUMNOTEQUAL OP_VERIFY
        OP_PICK {n+1} OP_ROLL OP_SHA256 OP_EQUALVERIFY
        for _ in 0..n {OP_DROP}
    }
}

pub fn scan(digests: &[[u8; 32]]) -> Script {
    script! {
        OP_SHA256 OP_SWAP OP_SHA256
        OP_2DUP OP_EQUAL OP_NOT OP_VERIFY
        0
        for digest in digests {
            // Each constant is compared with both hashes. The public pool is unique.
            {digest.to_vec()} OP_DUP 4 OP_PICK OP_EQUAL
            OP_SWAP 3 OP_PICK OP_EQUAL
            OP_ADD OP_ADD
        }
        2 OP_NUMEQUALVERIFY OP_2DROP
    }
}
