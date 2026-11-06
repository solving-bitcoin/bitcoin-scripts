/// Consume the same split vectors, counting the live prefix from left to right.
pub fn forward_prefix(n: u32) -> Script {
    script! {
        0 1
        for remaining in (1..=n).rev() {
            {remaining + 1} OP_ROLL
            {2 * remaining + 1} OP_ROLL
            OP_EQUAL OP_BOOLAND
            OP_TUCK OP_ADD OP_SWAP
        }
        OP_DROP
    }
}
