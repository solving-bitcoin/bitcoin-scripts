use crate::script::*;
use bitcoin_script_stack::stack::{StackTracker, StackVariable};

use crate::u4::u4_logic::u4_sort;

use super::{
    u4_logic::{
        u4_push_full_lookup, u4_push_full_xor_table, u4_push_half_and_table, u4_push_half_xor_table,
    },
    u4_shift_stack::u4_rshift_stack,
};

pub fn u4_push_half_and_table_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(136, u4_push_half_and_table(), "and_table")
}

pub fn u4_push_half_xor_table_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(136, u4_push_half_xor_table(), "xor_half_table")
}

pub fn u4_push_full_xor_table_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(256, u4_push_full_xor_table(), "xor_full_table")
}

pub fn u4_push_half_lookup_0_based() -> Script {
    script! {
        120
        119
        117
        114
        110
        105
        99
        92
        84
        75
        65
        54
        42
        29
        15
        0
    }
}

pub fn u4_push_from_depth_full_lookup(stack: &mut StackTracker, delta: i32) -> StackVariable {
    for i in (0..16).rev() {
        stack.numberi((i + 1) * -16 + delta);
    }
    let lookup = stack.join_count(&mut stack.get_var_from_stack(15), 15);
    stack.rename(lookup, "lookup");
    lookup
}

pub fn u4_push_from_depth_half_lookup(stack: &mut StackTracker, delta: i32) -> StackVariable {
    for i in (1..17).rev() {
        let diff = ((16 - i) * (16 - i + 1)) / 2;
        let value = -diff + delta;
        stack.numberi(value);
    }
    let lookup = stack.join_count(&mut stack.get_var_from_stack(15), 15);
    stack.rename(lookup, "lookup");
    lookup
}

pub fn u4_push_half_lookup_table_0_based_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(16, u4_push_half_lookup_0_based(), "lookup_table")
}

pub fn u4_push_full_lookup_table_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(17, u4_push_full_lookup(), "full_lookup_table")
}

pub fn u4_logic_with_table_stack(
    stack: &mut StackTracker,
    lookup_table: StackVariable,
    logic_table: StackVariable,
) -> StackVariable {
    let use_full_table = logic_table.size() > 136;
    if !use_full_table {
        stack.custom(u4_sort(), 0, false, 0, "sort");
    }
    stack.get_value_from_table(lookup_table, None);
    stack.op_add();
    stack.get_value_from_table(logic_table, None)
}

pub fn u4_and_with_xor_stack(
    stack: &mut StackTracker,
    lookup_table: StackVariable,
    logic_table: StackVariable,
    shift_table: StackVariable,
) -> StackVariable {
    stack.op_2dup();
    u4_logic_with_table_stack(stack, lookup_table, logic_table);
    stack.op_sub();
    stack.op_add();
    u4_rshift_stack(stack, shift_table, 1)
}
