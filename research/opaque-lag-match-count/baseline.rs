pub fn eager_destructive(width: u32, lag: u32) -> Script {
    script! {
        0
        for _ in 0..width - lag {
            { lag + 1 } OP_PICK OP_ROT OP_EQUAL OP_ADD
        }
        OP_TOALTSTACK
        for _ in 0..lag { OP_DROP }
        OP_FROMALTSTACK
    }
}

pub fn nondestructive(width: u32, lag: u32) -> Script {
    script! {
        0
        for index in 0..width - lag {
            { width - index } OP_PICK
            { width - index - lag + 1 } OP_PICK
            OP_EQUAL OP_ADD
        }
        OP_TOALTSTACK
        for _ in 0..width { OP_DROP }
        OP_FROMALTSTACK
    }
}
