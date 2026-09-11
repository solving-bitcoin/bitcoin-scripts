use super::stack::u4_drop;
use crate::arithmetic::u4::add::u4_arrange_nibbles;
use crate::support::script::*;

pub fn u4_push_full_xor_table() -> Script {
    script! {
        for i in (0..16).rev() {
            for j in (0..16).rev() {
                {i ^ j}
            }
        }
    }
}

pub fn u4_drop_full_logic_table() -> Script {
    u4_drop(16 * 16)
}

pub fn u4_push_full_lookup() -> Script {
    script! {
        for i in (0..=256).rev().step_by(16) {
            { i }
        }
    }
}

pub fn u4_drop_full_lookup() -> Script {
    u4_drop(17)
}

pub fn u4_push_half_xor_table() -> Script {
    script! {
        for i in (0..16).rev() {
            for j in (i..16).rev() {
                {i ^ j}
            }
        }
    }
}

pub fn u4_push_half_and_table() -> Script {
    script! {
        OP_15
        OP_14
        OP_DUP
        OP_13
        OP_12
        OP_2DUP
        OP_DUP
        OP_2DUP
        OP_11
        OP_10
        OP_9
        OP_8
        OP_11
        OP_10
        OP_DUP
        OP_8
        OP_DUP
        OP_10
        OP_DUP
        OP_9
        OP_8
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_7
        OP_6
        OP_5
        OP_4
        OP_3
        OP_2
        OP_1
        OP_0
        OP_7
        OP_6
        OP_DUP
        OP_4
        OP_DUP
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_6
        OP_DUP
        OP_5
        OP_4
        OP_2DUP
        OP_1
        OP_0
        OP_2DUP
        OP_5
        OP_4
        OP_2DUP
        OP_DUP
        OP_2DUP
        OP_0
        OP_DUP
        OP_2DUP
        OP_4
        OP_DUP
        OP_2DUP
        OP_3
        OP_2
        OP_1
        OP_0
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_2OVER
        OP_3
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_2
        OP_DUP
        OP_0
        OP_DUP
        OP_2
        OP_DUP
        OP_1
        OP_0
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_2DUP
        OP_DUP
        OP_2DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
        OP_3DUP
    }
}

pub fn u4_drop_half_table() -> Script {
    u4_drop(136)
}

pub fn u4_push_half_lookup() -> Script {
    script! {
        136
        135
        133
        130
        126
        121
        115
        108
        100
        91
        81
        70
        58
        45
        31
        16
    }
}

pub fn u4_drop_half_lookup() -> Script {
    u4_drop(16)
}

pub fn u4_sort() -> Script {
    script! {
        OP_2DUP
        OP_MIN
        OP_TOALTSTACK
        OP_MAX
        OP_FROMALTSTACK
    }
}

pub fn u4_half_table_operation(lookup: u32) -> Script {
    script! {
        { u4_sort() }
        { lookup - 1 }
        OP_ADD
        OP_PICK
        { lookup - 2 }
        OP_ADD
        OP_ADD
        OP_PICK
    }
}

pub fn u4_full_table_operation(lookup: u32, table: u32) -> Script {
    script! {
        { lookup }
        OP_ADD
        OP_PICK
        { table }
        OP_ADD
        OP_ADD
        OP_PICK
    }
}

pub fn u4_xor_with_half_and_table(lookup: u32) -> Script {
    script! {
        OP_2DUP
        { u4_half_table_operation(lookup + 2) }
        OP_DUP
        OP_ADD
        OP_SUB
        OP_ADD
    }
}

pub fn u4_logic_nibs(
    nibble_count: u32,
    mut bases: Vec<u32>,
    offset: u32,
    do_xor_with_half_and_table: bool,
) -> Script {
    let numbers = bases.len() as u32;
    bases.sort();
    script! {
        { u4_arrange_nibbles(nibble_count, bases) }
        for nib in 0..nibble_count {
            for i in 0..numbers-1 {
                if do_xor_with_half_and_table {
                    { u4_xor_with_half_and_table( offset - i - nib * numbers ) }
                } else {
                    { u4_half_table_operation( offset - i - nib * numbers ) }
                }
            }
            OP_TOALTSTACK
        }
    }
}

pub fn u4_xor_u32(bases: Vec<u32>, offset: u32, do_xor_with_and: bool) -> Script {
    u4_logic_nibs(8, bases, offset, do_xor_with_and)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::execute_script;

    fn assert_table(values: &[u32], push: Script) {
        let result = execute_script(script! {
            { push }
            for value in values {
                { *value }
                OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(result.success, "lookup table mismatch: {result}");
    }

    #[test]
    fn lookup_tables_preserve_their_index_schedule() {
        assert_table(
            &[
                16, 31, 45, 58, 70, 81, 91, 100, 108, 115, 121, 126, 130, 133, 135, 136,
            ],
            u4_push_half_lookup(),
        );
        assert_table(
            &[
                0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256,
            ],
            u4_push_full_lookup(),
        );
    }

    #[test]
    fn lookup_cleanup_requires_the_matching_table_width() {
        let result = execute_script(script! {
            { u4_push_half_lookup() }
            { u4_drop_full_lookup() }
            OP_TRUE
        });
        assert!(!result.success, "full cleanup accepted a half table");

        let result = execute_script(script! {
            { u4_push_half_lookup() }
            { u4_drop_half_lookup() }
            OP_TRUE
        });
        assert!(
            result.success,
            "matching half-table cleanup failed: {result}"
        );
    }
}
