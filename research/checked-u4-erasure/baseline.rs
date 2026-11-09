pub fn direct(width: usize, erased: usize, sum: u8, weighted: u8) -> Script {
    let weights: Vec<_> = (0..width as i32).collect();
    let seed = i32::from(weighted);
    let (lower, upper) = schedule::bounds(seed, &weights);
    script! {
        { schedule::scan(erased, sum, seed, &weights) }
        { schedule::recover_digit(width, sum) }
        if erased == 0 {
            OP_FROMALTSTACK
        } else {
            OP_DUP { mul_by_constant(erased as u32) }
            OP_FROMALTSTACK OP_SWAP OP_SUB
        }
        { schedule::reduce_mod17(lower, upper) }
        0 OP_EQUALVERIFY
    }
}
