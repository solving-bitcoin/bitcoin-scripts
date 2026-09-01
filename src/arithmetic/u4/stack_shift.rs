use super::shift::u4_push_lshift_tables;
use bitcoin_script::Script;
use bitcoin_script_stack::stack::{script, StackTracker, StackVariable};

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

        for i in (0..16).rev() {
            { i }
            OP_DUP
        }
    }
}

pub fn u4_push_shift_tables_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(
        16 * 6,
        script! { {u4_push_lshift_tables()} {u4_push_rshift_tables()}},
        "shift_tables",
    )
}

pub fn u4_rshift_stack(stack: &mut StackTracker, tables: StackVariable, n: u32) -> StackVariable {
    assert!((1..4).contains(&n));
    if n == 3 {
        stack.number(8);
        return stack.op_greaterthanorequal();
    }
    stack.get_value_from_table(tables, Some(32 * (n - 1)))
}

pub fn u4_lshift_stack(stack: &mut StackTracker, tables: StackVariable, n: u32) -> StackVariable {
    assert!((1..4).contains(&n));
    stack.get_value_from_table(tables, Some(16 * 3 + 16 * (n - 1)))
}

pub fn u4_push_shift_for_blake(stack: &mut StackTracker) -> StackVariable {
    stack.custom(
        script! {
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
        },
        0,
        false,
        0,
        "",
    );
    stack.define(16, "lshift1")
}

pub fn u4_2_nib_shift_stack(
    stack: &mut StackTracker,
    tables: StackVariable,
    n: u32,
) -> StackVariable {
    assert!((1..4).contains(&n));
    u4_lshift_stack(stack, tables, 4 - n);
    stack.op_swap();
    u4_rshift_stack(stack, tables, n);
    stack.op_add()
}

pub fn u4_2_nib_shift_blake(stack: &mut StackTracker, tables: StackVariable) -> StackVariable {
    stack.number(8);
    stack.op_greaterthanorequal();
    stack.op_swap();
    stack.get_value_from_table(tables, None);
    stack.op_add()
}
