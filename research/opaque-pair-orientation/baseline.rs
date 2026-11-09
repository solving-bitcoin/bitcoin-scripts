pub fn eager(width: u32) -> Script {
    schedule::batch(
        width,
        script! {
            // Duplicate the quartet for the straight flag.
            OP_2OVER OP_2OVER
            OP_ROT OP_EQUAL OP_TOALTSTACK OP_EQUAL OP_FROMALTSTACK OP_BOOLAND
            OP_TOALTSTACK
            // Consume the remaining quartet for the reversed flag.
            OP_SWAP OP_ROT OP_EQUAL OP_TOALTSTACK OP_EQUAL OP_FROMALTSTACK OP_BOOLAND
            // Verify exactly one flag and retain the reversed flag.
            OP_FROMALTSTACK OP_OVER OP_NUMNOTEQUAL OP_VERIFY
        },
    )
}
