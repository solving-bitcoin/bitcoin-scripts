mod table {
    include!("../../src/arithmetic/u4/one_hot/table.rs");
}
use table::push_one_hot_table;

mod fold {
    include!("../../src/arithmetic/u4/distinct_mask/fold.rs");
}

pub fn pairwise_mask(n: u32) -> Script {
    script! {
        for a in 0..n {
            for b in a+1..n {
                {a} OP_PICK {b+1} OP_PICK OP_EQUAL OP_NOT OP_VERIFY
            }
        }
        {fold::sum_one_hot(n)}
    }
}
