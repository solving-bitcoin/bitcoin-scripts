mod routing {
    include!("../../src/support/rotation/routing.rs");
}

pub fn copy(n: u32) -> Script {
    script! {
        {routing::initial_depth(n)}
        for _ in 0..n {
            {routing::wrap_depth(n)}
            OP_DUP OP_1ADD OP_PICK OP_TOALTSTACK
            OP_1ADD
        }
        OP_DROP
        for _ in 0..n {OP_DROP}
        for _ in 0..n {OP_FROMALTSTACK}
    }
}
