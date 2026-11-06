pub fn streaming(width: u32) -> Script {
    script! {
        if width == 1 {
            { schedule::verify_input() } OP_DUP
        } else {
            { schedule::order_pair() }
            for _ in 2..width { { schedule::update_single() } }
        }
    }
}
