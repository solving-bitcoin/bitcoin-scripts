mod scan {
    include!("../../src/arithmetic/u4/lee_step/scan.rs");
}

pub fn direct(n: u32) -> Script {
    scan::scan_with(
        n,
        script! {OP_ABS OP_DUP 16 OP_SWAP OP_SUB OP_MIN},
        script! {},
    )
}
