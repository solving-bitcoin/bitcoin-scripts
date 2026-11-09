mod schedule {
    include!("../../src/support/witness_data_size/schedule.rs");
}

pub fn conditional(items: u32, cap: u32) -> Script {
    use schedule::{check_with, LONG_COMPACTSIZE};

    check_with(
        items,
        cap,
        script! {
            OP_DUP {LONG_COMPACTSIZE} OP_GREATERTHANOREQUAL
            OP_IF 2 OP_ADD OP_ENDIF
        },
    )
}
