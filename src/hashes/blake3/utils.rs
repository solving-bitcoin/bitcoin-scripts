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

fn split_addition(stack: &mut StackTracker, tables: &TablesVars, nibble_index: u8) {
    if nibble_index > 0 {
        // The 48-entry quotient table sits immediately above modulo. Retain
        // one absolute quotient depth, fetch modulo 48 entries plus the
        // retained-depth item below it, then reuse the depth for carry.
        let quotient_offset = stack.get_offset(tables.quotient) - 1;
        stack.number(quotient_offset);
        stack.op_add();
        stack.op_dup();
        stack.number(49);
        stack.op_add();
        let modulo = stack.op_pick();
        stack.rename(modulo, &format!("modulo[{nibble_index}]"));
        stack.to_altstack();
        let carry = stack.op_pick();
        stack.rename(carry, "carry");
    } else {
        let modulo = stack.get_value_from_table(tables.modulo, None);
        stack.rename(modulo, "modulo[0]");
        stack.to_altstack();
    }
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

        split_addition(stack, tables, i as u8);
    }
}

fn constant_nibble(value: u32, index: u8) -> u32 {
    (value >> ((7 - index) * 4)) & 0x0f
}

fn u4_add_constant_and_dynamic(
    stack: &mut StackTracker,
    constant: u32,
    dynamic: &mut StackVariable,
    tables: &TablesVars,
) -> StackVariable {
    for i in (0..8_u8).rev() {
        stack.copy_var_sub_n(*dynamic, u32::from(i));
        stack.number(constant_nibble(constant, i));
        stack.op_add();

        if i < 7 {
            stack.op_add();
        }
        split_addition(stack, tables, i);
    }
    stack.from_altstack_joined(8, "constant-plus-dynamic")
}

fn xor_constant_and_rotate_right_by_multiple_of_4(
    stack: &mut StackTracker,
    constant: u32,
    dynamic: StackVariable,
    rotation: u8,
    tables: &TablesVars,
) -> StackVariable {
    let pos_shift = 8 - rotation / 4;
    let mut outputs = Vec::with_capacity(8);
    for i in pos_shift..(pos_shift + 8) {
        let dynamic_nibble = i % 8;
        let constant_nibble = constant_nibble(constant, dynamic_nibble);

        if constant_nibble == 0 {
            outputs.push(stack.copy_var_sub_n(dynamic, u32::from(dynamic_nibble)));
            continue;
        }
        if constant_nibble == 15 {
            stack.number(15);
            stack.copy_var_sub_n(dynamic, u32::from(dynamic_nibble));
            outputs.push(stack.op_sub());
            continue;
        }

        stack.copy_var_sub_n(dynamic, u32::from(dynamic_nibble));
        outputs.push(stack.get_value_from_table(tables.xor_table, Some(16 * constant_nibble)));
    }
    stack.join_count(&mut outputs[0], 7)
}

fn constant_g(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> [u32; 4] {
    a = a.wrapping_add(b);
    d = (d ^ a).rotate_right(16);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_right(12);
    a = a.wrapping_add(b);
    d = (d ^ a).rotate_right(8);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_right(7);
    [a, b, c, d]
}

#[allow(clippy::too_many_arguments)]
fn first_column_g(
    stack: &mut StackTracker,
    initial_a: u32,
    initial_b: u32,
    initial_c: u32,
    initial_d: u32,
    mut m0: StackVariable,
    mut m1: Option<StackVariable>,
    tables: &TablesVars,
) -> [StackVariable; 4] {
    let mut a =
        u4_add_constant_and_dynamic(stack, initial_a.wrapping_add(initial_b), &mut m0, tables);
    let d = xor_constant_and_rotate_right_by_multiple_of_4(stack, initial_d, a, 16, tables);
    let mut dynamic_d = d;
    let c = u4_add_constant_and_dynamic(stack, initial_c, &mut dynamic_d, tables);
    let b = xor_constant_and_rotate_right_by_multiple_of_4(stack, initial_b, c, 12, tables);

    if let Some(message) = m1.as_mut() {
        u4_add_direct(stack, vec![b, *message], vec![&mut a], tables);
    } else {
        u4_add_direct(stack, vec![b], vec![&mut a], tables);
    }
    a = stack.from_altstack_joined(8, "first-column-a");

    let mut state = HashMap::from([(0, a), (1, b), (2, c), (3, d)]);
    let rotated_d = xor_and_rotate_right_by_multiple_of_4(stack, &mut state, 3, 0, 8, true);
    state.insert(3, rotated_d);
    let d = state[&3];
    let c = state.get_mut(&2).unwrap();
    u4_add_direct(stack, vec![d], vec![c], tables);
    *c = stack.from_altstack_joined(8, "first-column-c");
    let rotated_b = xor_and_rotate_right_by_7(stack, &mut state, 1, 2, tables);
    state.insert(1, rotated_b);

    [state[&0], state[&1], state[&2], state[&3]]
}

fn first_round_columns(
    stack: &mut StackTracker,
    counter: u32,
    block_len: u32,
    flags: u32,
    message: &HashMap<u8, StackVariable>,
    tables: &TablesVars,
) -> HashMap<u8, StackVariable> {
    let initial = [
        IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7], IV[0], IV[1], IV[2], IV[3],
        counter, 0, block_len, flags,
    ];
    let mut state = HashMap::new();
    let column_order = match block_len {
        0..=8 => [0_usize, 1, 3, 2],
        9..=16 => [1_usize, 0, 3, 2],
        17..=28 => [2_usize, 0, 1, 3],
        32 => [0_usize, 1, 2, 3],
        _ => [3_usize, 1, 2, 0],
    };
    for index in column_order {
        let (a, b, c, d) = (index, index + 4, index + 8, index + 12);
        let m0 = message.get(&(index as u8 * 2)).copied();
        let m1 = message.get(&(index as u8 * 2 + 1)).copied();
        let words = match (m0, m1) {
            (None, None) => constant_g(initial[a], initial[b], initial[c], initial[d])
                .map(|value| stack.number_u32(value)),
            (Some(m0), m1) => first_column_g(
                stack, initial[a], initial[b], initial[c], initial[d], m0, m1, tables,
            ),
            (None, Some(_)) => unreachable!("message words form a dense prefix"),
        };
        for (lane, word) in [(a, words[0]), (b, words[1]), (c, words[2]), (d, words[3])] {
            state.insert(lane as u8, word);
        }
    }
    state
}

#[allow(clippy::too_many_arguments)]
fn g(
    stack: &mut StackTracker,
    var_map: &mut HashMap<u8, StackVariable>,
    a: u8,
    b: u8,
    c: u8,
    d: u8,
    mut m_two_i: Option<StackVariable>,
    mut m_two_i_plus_one: Option<StackVariable>,
    tables: &TablesVars,
    last_round: bool,
) {
    let vb = var_map[&b];
    let mut va = var_map.get_mut(&a).unwrap();

    match (last_round, m_two_i.as_mut()) {
        (true, Some(message)) => u4_add_direct(stack, vec![vb], vec![&mut va, message], tables),
        (false, Some(message)) => u4_add_direct(stack, vec![vb, *message], vec![&mut va], tables),
        (_, None) => u4_add_direct(stack, vec![vb], vec![&mut va], tables),
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
    match (last_round, m_two_i_plus_one.as_mut()) {
        (true, Some(message)) => u4_add_direct(stack, vec![vb], vec![&mut va, message], tables),
        (false, Some(message)) => u4_add_direct(stack, vec![vb, *message], vec![&mut va], tables),
        (_, None) => u4_add_direct(stack, vec![vb], vec![&mut va], tables),
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
    round_index: u8,
    block_len: u32,
    skipped_columns: [bool; 4],
) {
    const COLUMN_STEPS: [(u8, u8, u8, u8, u8, u8); 4] = [
        (0, 4, 8, 12, 0, 1),
        (1, 5, 9, 13, 2, 3),
        (2, 6, 10, 14, 4, 5),
        (3, 7, 11, 15, 6, 7),
    ];
    const DIAGONAL_STEPS: [(u8, u8, u8, u8, u8, u8); 4] = [
        (0, 5, 10, 15, 8, 9),
        (1, 6, 11, 12, 10, 11),
        (2, 7, 8, 13, 12, 13),
        (3, 4, 9, 14, 14, 15),
    ];

    // Calls within each phase touch disjoint lanes, so their order does not
    // affect BLAKE3 semantics. Exhaustive host-time searches selected the
    // short-message orders below for each active-word class.
    let orders = if message_var_map.len() < 16 {
        match (round_index, block_len) {
            (0, 9..=16) => [([3, 1, 2, 0]), ([3, 2, 1, 0])],
            (0, 25..=28 | 32) => [([3, 1, 2, 0]), ([2, 1, 3, 0])],
            (0, _) => [([3, 1, 2, 0]), ([3, 1, 2, 0])],
            (6, 0..=8) => [([1, 2, 0, 3]), ([2, 0, 3, 1])],
            (6, 9..=12) => [([1, 0, 3, 2]), ([1, 0, 3, 2])],
            (6, 13..=28) => [([1, 0, 2, 3]), ([2, 1, 0, 3])],
            _ => [([1, 2, 3, 0]), ([3, 2, 1, 0])],
        }
    } else {
        [([3, 0, 2, 1]), ([0, 3, 1, 2])]
    };

    for (phase, (steps, order)) in [(&COLUMN_STEPS, orders[0]), (&DIAGONAL_STEPS, orders[1])]
        .into_iter()
        .enumerate()
    {
        for index in order {
            if phase == 0 && skipped_columns[index] {
                continue;
            }
            let (a, b, c, d, m0, m1) = steps[index];
            g(
                stack,
                state_var_map,
                a,
                b,
                c,
                d,
                message_var_map.get(&m0).copied(),
                message_var_map.get(&m1).copied(),
                tables,
                last_round,
            );
        }
    }
}

fn permutate(message_var_map: &HashMap<u8, StackVariable>) -> HashMap<u8, StackVariable> {
    let mut ret = HashMap::new();
    for i in 0..16_u8 {
        if let Some(message) = message_var_map.get(&MSG_PERMUTATION[i as usize]) {
            ret.insert(i, *message);
        }
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
        for value in IV {
            state.push(stack.number_u32(value));
        }
    }
    for value in &IV[0..4] {
        state.push(stack.number_u32(*value));
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

    let (mut state, first_full_round) = if chaining {
        (init_state(stack, true, counter, block_len, flags), 0)
    } else {
        let mut state = first_round_columns(stack, counter, block_len, flags, &message, tables);
        round(
            stack, &mut state, &message, tables, false, 0, block_len, [true; 4],
        );
        message = permutate(&message);
        (state, 1)
    };

    for round_index in first_full_round..6 {
        round(
            stack,
            &mut state,
            &message,
            tables,
            false,
            round_index,
            block_len,
            [false; 4],
        );
        message = permutate(&message);
    }
    round(
        stack, &mut state, &message, tables, true, 6, block_len, [false; 4],
    );

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
