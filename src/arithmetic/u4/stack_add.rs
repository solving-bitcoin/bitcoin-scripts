use crate::support::script::*;
use bitcoin_script_stack::stack::{StackTracker, StackVariable};

use super::add::{u4_push_modulo_table_5, u4_push_quotient_table_5};

pub fn u4_push_quotient_table_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(80, u4_push_quotient_table_5(), "quotient_table")
}

pub fn u4_push_modulo_table_stack(stack: &mut StackTracker) -> StackVariable {
    stack.var(80, u4_push_modulo_table_5(), "modulo_table")
}

pub fn u4_push_modulo_for_blake(stack: &mut StackTracker) -> StackVariable {
    stack.custom(
        script! {
            for i in (0..48).rev() {
                { i % 16 }
            }
        },
        0,
        false,
        0,
        "",
    );
    stack.define(48, "modulo")
}

pub fn u4_push_quotient_for_blake(stack: &mut StackTracker) -> StackVariable {
    stack.custom(
        script! {
            for i in (0..=2).rev() {
                { i }
                OP_DUP
                OP_2DUP
                OP_3DUP
                OP_3DUP
                OP_3DUP
                OP_3DUP
            }
        },
        0,
        false,
        0,
        "",
    );
    stack.define(48, "quotient")
}

pub fn u4_arrange_nibbles_stack(
    nibble_count: u32,
    stack: &mut StackTracker,
    to_copy: Vec<StackVariable>,
    mut to_move: Vec<&mut StackVariable>,
    constants: Vec<u32>,
) {
    let mut constant_parts: Vec<Vec<u32>> = Vec::new();

    for n in constants {
        let parts = (0..8).rev().map(|i| (n >> (i * 4)) & 0xF).collect();
        constant_parts.push(parts);
    }

    for i in 0..nibble_count {
        for var in to_copy.iter() {
            stack.copy_var_sub_n(*var, i);
        }

        for var in to_move.iter_mut() {
            stack.move_var_sub_n(var, 0);
        }

        for parts in constant_parts.iter() {
            stack.number(parts[i as usize]);
        }
    }
}

pub fn u4_add_internal_stack(
    stack: &mut StackTracker,
    nibble_count: u32,
    number_count: u32,
    quotient_table: StackVariable,
    modulo_table: StackVariable,
) {
    for i in 0..nibble_count {
        if i > 0 {
            stack.op_add();
        }

        for _ in 0..number_count - 1 {
            stack.op_add();
        }

        if i < nibble_count - 1 {
            stack.op_dup();
        }

        let modulo = stack.get_value_from_table(modulo_table, None);
        stack.rename(modulo, &format!("modulo[{}]", i).to_string());
        stack.to_altstack();

        if i < nibble_count - 1 {
            let carry = stack.get_value_from_table(quotient_table, None);
            stack.rename(carry, "carry");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::u4::stack::verify_n;

    #[test]
    fn test_add_for_blake() {
        let mut stack = StackTracker::new();

        let modulo = u4_push_modulo_for_blake(&mut stack);
        let quotient = u4_push_quotient_for_blake(&mut stack);

        let mut x = stack.number_u32(0x00112233);
        let y = stack.number_u32(0x99887766);
        u4_arrange_nibbles_stack(8, &mut stack, vec![y], vec![&mut x], vec![0xaabbccdd]);

        u4_add_internal_stack(&mut stack, 8, 3, quotient, modulo);

        let mut vars = stack.from_altstack_count(8);
        stack.join_count(&mut vars[0], 7);

        stack.number_u32(0x44556676);
        stack.custom(verify_n(8), 2, false, 0, "verify");
        stack.drop(y);
        stack.drop(quotient);
        stack.drop(modulo);
        stack.op_true();

        let res = stack.run();
        assert!(res.success);
    }
}
