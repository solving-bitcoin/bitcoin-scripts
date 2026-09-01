use super::u4_std::u4_drop;
use crate::script::*;

pub fn u4_push_lshift_tables() -> Script {
    script! {
        OP_8
        OP_0
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_12
        OP_8
        OP_4
        OP_0
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_14
        OP_12
        OP_10
        OP_8
        OP_6
        OP_4
        OP_2
        OP_0
        OP_14
        OP_12
        OP_10
        OP_8
        OP_6
        OP_4
        OP_2
        OP_0
    }
}

pub fn u4_drop_lshift_tables() -> Script {
    u4_drop(16 * 3)
}

pub fn u4_push_rshift_tables() -> Script {
    script! {
        OP_3
        OP_DUP
        OP_2DUP
        OP_2
        OP_DUP
        OP_2DUP
        OP_1
        OP_DUP
        OP_2DUP
        OP_0
        OP_DUP
        OP_2DUP

        OP_7
        OP_DUP
        OP_6
        OP_DUP
        OP_5
        OP_DUP
        OP_4
        OP_DUP
        OP_3
        OP_DUP
        OP_2
        OP_DUP
        OP_1
        OP_DUP
        OP_0
        OP_DUP
    }
}

pub fn u4_drop_rshift_tables() -> Script {
    u4_drop(16 * 2)
}

pub fn u4_push_2_nib_rshift_tables() -> Script {
    script! {
       { u4_push_lshift_tables() }
       { u4_push_rshift_tables() }
    }
}

pub fn u4_drop_2_nib_rshift_tables() -> Script {
    script! {
       { u4_drop_rshift_tables() }
       { u4_drop_lshift_tables() }
    }
}

pub fn u4_lshift(n: u32, lshift_offset: u32) -> Script {
    assert!((1..4).contains(&n));
    script! {
        { lshift_offset + (16 * (n - 1)) }
        OP_ADD
        OP_PICK
    }
}

pub fn u4_rshift(n: u32, rshift_offset: u32) -> Script {
    assert!((1..4).contains(&n));
    script! {
        if n == 3 {
            8
            OP_GREATERTHANOREQUAL
        } else {
            { rshift_offset + (16 * (n - 1)) }
            OP_ADD
            OP_PICK
        }
    }
}

pub fn u4_2_nib_rshift_n(n: u32, tables_offset: u32) -> Script {
    assert!((1..4).contains(&n));
    script! {
        { u4_lshift(4 - n, tables_offset + (16 * 2) + 1)  }
        OP_SWAP
        { u4_rshift(n, tables_offset + 1)  }
        OP_ADD
    }
}
