use crate::arithmetic::u4::{stack_add::*, stack_logic::*, stack_shift::*};
pub use bitcoin_script::builder::StructuredScript as Script;
use bitcoin_script_stack::stack::{StackTracker, StackVariable};
use std::collections::HashMap;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_PERMUTATION: [u8; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[derive(Clone, Debug, Copy)]
pub(crate) struct TablesVars {
    modulo: StackVariable,
    quotient: StackVariable,
    shift_tables: StackVariable,
    xor_table: StackVariable,
    depth_lookup: StackVariable,
    use_full_tables: bool,
}

impl TablesVars {
    pub(crate) fn new(stack: &mut StackTracker, use_full_tables: bool) -> Self {
        let depth_lookup = if !use_full_tables {
            u4_push_from_depth_half_lookup(stack, -18)
        } else {
            u4_push_from_depth_full_lookup(stack, -17)
        };
        let xor_table = if !use_full_tables {
            u4_push_half_xor_table_stack(stack)
        } else {
            u4_push_full_xor_table_stack(stack)
        };
        let shift_tables = u4_push_shift_for_blake(stack);
        let modulo = u4_push_modulo_for_blake(stack);
        let quotient = u4_push_quotient_for_blake(stack);
        TablesVars {
            modulo,
            quotient,
            shift_tables,
            xor_table,
            depth_lookup,
            use_full_tables,
        }
    }

    pub(crate) fn drop(&self, stack: &mut StackTracker) {
        stack.drop(self.quotient);
        stack.drop(self.modulo);
        stack.drop(self.shift_tables);
        stack.drop(self.xor_table);
        stack.drop(self.depth_lookup);
    }
}

fn xor_and_rotate_right_by_multiple_of_4(
    stack: &mut StackTracker,
    var_map: &mut HashMap<u8, StackVariable>,
    x: u8,
    y: u8,
    rotation: u8,
    use_full_tables: bool,
) -> StackVariable {
    let pos_shift = 8 - rotation / 4;
    let y = var_map[&y];
    let x = var_map.get_mut(&x).unwrap();
    for i in pos_shift..(pos_shift + 8) {
        let n = i % 8;
        let mut z = 0;
        if i < 8 {
            z = pos_shift;
        }
        xor_2_nibbles(stack, x, y, z, n, use_full_tables);
    }
    stack.join_count(&mut stack.get_var_from_stack(7), 7)
}

fn xor_2_nibbles(
    stack: &mut StackTracker,
    x: &mut StackVariable,
    y: StackVariable,
    nibble_x: u8,
    nibble_y: u8,
    use_full_tables: bool,
) -> StackVariable {
    if !use_full_tables {
        stack.op_depth();
        stack.op_dup();
        stack.copy_var_sub_n(y, nibble_y as u32);
        stack.move_var_sub_n(x, nibble_x as u32);
        stack.op_2dup();
        stack.op_min();
        stack.to_altstack();
        stack.op_max();
        stack.op_sub();
        stack.op_1sub();
        stack.op_pick();
        stack.op_add();
        stack.from_altstack();
        stack.op_sub();
        stack.op_pick()
    } else {
        stack.op_depth();
        stack.op_dup();
        stack.copy_var_sub_n(y, nibble_y as u32);
        stack.op_sub();
        stack.op_pick();
        stack.op_add();
        stack.move_var_sub_n(x, nibble_x as u32);
        stack.op_add();
        stack.op_pick()
    }
}

fn xor_and_rotate_right_by_7(
    stack: &mut StackTracker,
    var_map: &mut HashMap<u8, StackVariable>,
    x: u8,
    y: u8,
    tables: &TablesVars,
) -> StackVariable {
    let y = var_map[&y];
    let x = var_map.get_mut(&x).unwrap();

    let z6 = xor_2_nibbles(stack, x, y, 6, 6, tables.use_full_tables);
    stack.rename(z6, "z6");

    stack.copy_var(z6);
    stack.to_altstack();

    let z7 = xor_2_nibbles(stack, x, y, 6, 7, tables.use_full_tables);
    stack.rename(z7, "z7");
    stack.copy_var(z7);
    stack.to_altstack();

    let mut w0 = u4_2_nib_shift_blake(stack, tables.shift_tables);
    stack.rename(w0, "w0");

    for i in 0..6 {
        stack.from_altstack();
        let r0 = xor_2_nibbles(stack, x, y, 0, i, tables.use_full_tables);
        stack.rename(r0, &format!("z{}", i));
        stack.copy_var(r0);
        stack.to_altstack();
        let w1 = u4_2_nib_shift_blake(stack, tables.shift_tables);
        stack.rename(w1, &format!("w{}", i + 1));
    }

    stack.from_altstack();
    stack.from_altstack();

    let w7 = u4_2_nib_shift_blake(stack, tables.shift_tables);
    stack.rename(w7, "w7");

    stack.join_count(&mut w0, 7)
}

fn u4_add_direct(
    stack: &mut StackTracker,
    to_copy: Vec<StackVariable>,
    mut to_move: Vec<&mut StackVariable>,
    tables: &TablesVars,
) {
    let nibble_count = 8;
    let number_count = to_copy.len() + to_move.len();

    for i in (0..nibble_count).rev() {
        for x in to_copy.iter() {
            stack.copy_var_sub_n(*x, i);
        }

        for x in to_move.iter_mut() {
            stack.move_var_sub_n(x, i);
        }

        for _ in 0..number_count - 1 {
            stack.op_add();
        }

        if i < nibble_count - 1 {
            stack.op_add();
        }

        if i > 0 {
            stack.op_dup();
        }

        let modulo = stack.get_value_from_table(tables.modulo, None);
        stack.rename(modulo, &format!("modulo[{}]", i).to_string());
        stack.to_altstack();

        if i > 0 {
            let carry = stack.get_value_from_table(tables.quotient, None);
            stack.rename(carry, "carry");
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn g(
    stack: &mut StackTracker,
    var_map: &mut HashMap<u8, StackVariable>,
    a: u8,
    b: u8,
    c: u8,
    d: u8,
    mut m_two_i: StackVariable,
    mut m_two_i_plus_one: StackVariable,
    tables: &TablesVars,
    last_round: bool,
) {
    let vb = var_map[&b];
    let mut va = var_map.get_mut(&a).unwrap();

    if last_round {
        u4_add_direct(stack, vec![vb], vec![&mut va, &mut m_two_i], tables);
    } else {
        u4_add_direct(stack, vec![vb, m_two_i], vec![&mut va], tables);
    }

    *va = stack.from_altstack_joined(8, &format!("state_{}", a));

    let ret =
        xor_and_rotate_right_by_multiple_of_4(stack, var_map, d, a, 16, tables.use_full_tables);
    var_map.insert(d, ret);

    let vd = var_map[&d];
    let mut vc = var_map.get_mut(&c).unwrap();
    u4_add_direct(stack, vec![vd], vec![&mut vc], tables);
    *vc = stack.from_altstack_joined(8, &format!("state_{}", c));

    let ret =
        xor_and_rotate_right_by_multiple_of_4(stack, var_map, b, c, 12, tables.use_full_tables);
    var_map.insert(b, ret);

    let vb = var_map[&b];
    let mut va = var_map.get_mut(&a).unwrap();
    if last_round {
        u4_add_direct(
            stack,
            vec![vb],
            vec![&mut va, &mut m_two_i_plus_one],
            tables,
        );
    } else {
        u4_add_direct(stack, vec![vb, m_two_i_plus_one], vec![&mut va], tables);
    }

    *va = stack.from_altstack_joined(8, &format!("state_{}", a));

    let ret =
        xor_and_rotate_right_by_multiple_of_4(stack, var_map, d, a, 8, tables.use_full_tables);
    var_map.insert(d, ret);
    stack.rename(ret, &format!("state_{}", d));

    let vd = var_map[&d];
    let mut vc = var_map.get_mut(&c).unwrap();
    u4_add_direct(stack, vec![vd], vec![&mut vc], tables);
    *vc = stack.from_altstack_joined(8, &format!("state_{}", c));

    let ret = xor_and_rotate_right_by_7(stack, var_map, b, c, tables);
    var_map.insert(b, ret);
    stack.rename(ret, &format!("state_{}", b));
}

fn round(
    stack: &mut StackTracker,
    state_var_map: &mut HashMap<u8, StackVariable>,
    message_var_map: &HashMap<u8, StackVariable>,
    tables: &TablesVars,
    last_round: bool,
) {
    g(
        stack,
        state_var_map,
        0,
        4,
        8,
        12,
        message_var_map[&0],
        message_var_map[&1],
        tables,
        last_round,
    );
    g(
        stack,
        state_var_map,
        1,
        5,
        9,
        13,
        message_var_map[&2],
        message_var_map[&3],
        tables,
        last_round,
    );
    g(
        stack,
        state_var_map,
        2,
        6,
        10,
        14,
        message_var_map[&4],
        message_var_map[&5],
        tables,
        last_round,
    );
    g(
        stack,
        state_var_map,
        3,
        7,
        11,
        15,
        message_var_map[&6],
        message_var_map[&7],
        tables,
        last_round,
    );
    g(
        stack,
        state_var_map,
        0,
        5,
        10,
        15,
        message_var_map[&8],
        message_var_map[&9],
        tables,
        last_round,
    );
    g(
        stack,
        state_var_map,
        1,
        6,
        11,
        12,
        message_var_map[&10],
        message_var_map[&11],
        tables,
        last_round,
    );
    g(
        stack,
        state_var_map,
        2,
        7,
        8,
        13,
        message_var_map[&12],
        message_var_map[&13],
        tables,
        last_round,
    );
    g(
        stack,
        state_var_map,
        3,
        4,
        9,
        14,
        message_var_map[&14],
        message_var_map[&15],
        tables,
        last_round,
    );
}

fn permutate(message_var_map: &HashMap<u8, StackVariable>) -> HashMap<u8, StackVariable> {
    let mut ret = HashMap::new();
    for i in 0..16_u8 {
        ret.insert(i, message_var_map[&MSG_PERMUTATION[i as usize]]);
    }
    ret
}

fn init_state(
    stack: &mut StackTracker,
    chaining: bool,
    counter: u32,
    block_len: u32,
    flags: u32,
) -> HashMap<u8, StackVariable> {
    let mut state = Vec::new();

    if chaining {
        for i in 0..8 {
            state.push(stack.from_altstack_joined(8, &format!("prev-hash[{}]", i)));
        }
    } else {
        for u32 in IV {
            state.push(stack.number_u32(u32));
        }
    }
    for u32 in &IV[0..4] {
        state.push(stack.number_u32(*u32));
    }
    state.push(stack.number_u32(counter));
    state.push(stack.number_u32(0));
    state.push(stack.number_u32(block_len));
    state.push(stack.number_u32(flags));

    let mut state_map = HashMap::new();
    for (i, s) in state.iter().enumerate() {
        state_map.insert(i as u8, *s);
        stack.rename(*s, &format!("state_{}", i));
    }
    state_map
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compress(
    stack: &mut StackTracker,
    chaining: bool,
    counter: u32,
    block_len: u32,
    flags: u32,
    mut message: HashMap<u8, StackVariable>,
    tables: &TablesVars,
    final_rounds: u8,
    last_round: bool,
) {
    assert_eq!(final_rounds, 8);

    let mut state = init_state(stack, chaining, counter, block_len, flags);

    for _ in 0..6 {
        round(stack, &mut state, &message, tables, false);
        message = permutate(&message);
    }
    round(stack, &mut state, &message, tables, true);

    for i in (0..final_rounds).rev() {
        let mut tmp = Vec::new();

        for n in 0..8 {
            let v2 = *state.get(&(i + 8)).unwrap();
            let v1 = state.get_mut(&i).unwrap();
            tmp.push(xor_2_nibbles(stack, v1, v2, 0, n, tables.use_full_tables));

            if last_round && n % 2 == 1 {
                stack.to_altstack();
                stack.to_altstack();
            }
        }
        if !last_round {
            for _ in 0..8 {
                stack.to_altstack();
            }
        }
    }
}

pub(crate) fn get_flags_for_block(i: u32, num_blocks: u32) -> u32 {
    if num_blocks == 1 {
        return 0b00001011;
    }
    if i == 0 {
        return 0b00000001;
    }
    if i == num_blocks - 1 {
        return 0b00001010;
    }
    0
}
