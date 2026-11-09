mod mod3_table {
    include!("../../src/arithmetic/u4/mod3/table.rs");
}

use mod3_table::{mod3_to_altstack, push_mod3_table};

mod schedule {
    include!("../../src/arithmetic/u4/sliding_mod3/schedule.rs");
}

pub fn rescan(n: u32, window: u32) -> Script {
    let windows = n - window + 1;
    script! {
        {schedule::project_for_windows(n)}
        for remaining in (window..=n).rev() {
            {schedule::sum_top_window(window)}
            {remaining} OP_ADD OP_PICK
            OP_TOALTSTACK OP_DROP
        }
        {u4_drop(U4_MOD3_TABLE_ITEMS + window - 1)}
        for _ in 0..windows {OP_FROMALTSTACK}
    }
}
