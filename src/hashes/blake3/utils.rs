use crate::arithmetic::u4::{stack_add::u4_push_modulo_for_blake, stack_logic::*, stack_shift::*};
pub use bitcoin_script::builder::StructuredScript as Script;
use bitcoin_script::script;
use bitcoin_script_stack::stack::{StackTracker, StackVariable};
use std::collections::HashMap;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_PERMUTATION: [u8; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[derive(Clone, Debug, Copy)]
pub(crate) struct TablesVars {
    modulo_last: StackVariable,
    add_interleaved: StackVariable,
    shift_tables: StackVariable,
    xor_table: StackVariable,
    depth_lookup: StackVariable,
    use_full_tables: bool,
    late_tables: bool,
}

impl TablesVars {
    pub(crate) fn new(stack: &mut StackTracker, use_full_tables: bool) -> Self {
        Self::build(stack, use_full_tables, false)
    }

    pub(crate) fn new_late(stack: &mut StackTracker) -> Self {
        Self::build(stack, true, true)
    }

    fn build(stack: &mut StackTracker, use_full_tables: bool, late_tables: bool) -> Self {
        let depth_lookup = if !use_full_tables {
            u4_push_from_depth_half_lookup(stack, -18)
        } else {
            push_packed_full_depth_lookup(stack)
        };
        let xor_table = if !use_full_tables {
            u4_push_half_xor_table_stack(stack)
        } else {
            push_packed_full_xor_table(stack)
        };
        let shift_tables = if late_tables {
            StackVariable::null()
        } else {
            u4_push_shift_for_blake(stack)
        };
        let modulo_last = if use_full_tables {
            StackVariable::null()
        } else {
            u4_push_modulo_for_blake(stack)
        };
        let add_interleaved = if late_tables {
            StackVariable::null()
        } else {
            push_interleaved_add_table(stack)
        };
        TablesVars {
            modulo_last,
            add_interleaved,
            shift_tables,
            xor_table,
            depth_lookup,
            use_full_tables,
            late_tables,
        }
    }

    pub(crate) fn push_late_tables(&mut self, stack: &mut StackTracker) {
        assert!(self.late_tables);
        assert!(self.shift_tables.is_null());
        assert!(self.add_interleaved.is_null());
        self.shift_tables = u4_push_shift_for_blake(stack);
        self.add_interleaved = push_interleaved_add_table(stack);
        self.late_tables = false;
    }

    pub(crate) fn drop(&self, stack: &mut StackTracker) {
        stack.drop(self.add_interleaved);
        if !self.use_full_tables {
            stack.drop(self.modulo_last);
        }
        stack.drop(self.shift_tables);
        stack.drop(self.xor_table);
        stack.drop(self.depth_lookup);
    }

    pub(crate) fn drop_after_destructive_xor_query(&self, stack: &mut StackTracker) {
        assert!(self.use_full_tables);
        // The final OP_ROLL removes one item from the 331-item table memory.
        // Model the four tracked table variables as one 330-item runtime drop.
        stack.custom(
            script! {
                for _ in 0..165 {
                    OP_2DROP
                }
            },
            4,
            false,
            0,
            "drop tables after final destructive XOR query",
        );
    }
}

fn push_interleaved_add_table(stack: &mut StackTracker) -> StackVariable {
    stack.custom(
        script! {
            for sum in (0..48).rev() {
                { sum / 16 }
                { sum % 16 }
            }
        },
        0,
        false,
        0,
        "interleaved quotient/modulo addition table",
    );
    stack.define(96, "add_interleaved")
}

// Consecutive fixed-orientation XOR rows overlap by 8, 4, 2, or 1 items.
// This bit-reversal order attains the 171-item shortest common superstring.
const PACKED_FULL_XOR_ROW_ORDER: [u32; 16] = [15, 7, 11, 3, 13, 5, 9, 1, 14, 6, 10, 2, 12, 4, 8, 0];
const PACKED_FULL_XOR_ROW_STARTS: [u32; 16] = [
    155, 70, 113, 28, 135, 50, 93, 8, 147, 62, 105, 20, 127, 42, 85, 0,
];
const PACKED_FULL_XOR_SCS_ITEMS: u32 = 171;
// Two extra copies of row zero extend its existing 16 entries into a
// 48-entry modulo-16 table. Addition sums are bounded by 47.
const PACKED_FULL_XOR_SUFFIX_ITEMS: u32 = 32;
const PACKED_FULL_XOR_ITEMS: u32 = PACKED_FULL_XOR_SCS_ITEMS + PACKED_FULL_XOR_SUFFIX_ITEMS;

fn packed_full_xor_overlap(left_row: u32, right_row: u32) -> usize {
    match left_row ^ right_row {
        8 => 8,
        12 => 4,
        14 => 2,
        15 => 1,
        _ => 0,
    }
}

fn packed_full_xor_values() -> Vec<u32> {
    let mut values = Vec::with_capacity(PACKED_FULL_XOR_ITEMS as usize);
    for (position, row) in PACKED_FULL_XOR_ROW_ORDER.into_iter().enumerate() {
        let overlap = if position == 0 {
            0
        } else {
            packed_full_xor_overlap(PACKED_FULL_XOR_ROW_ORDER[position - 1], row)
        };
        debug_assert_eq!(
            (values.len() - overlap) as u32,
            PACKED_FULL_XOR_ROW_STARTS[row as usize]
        );
        values.extend((0..16 - overlap).rev().map(|column| row ^ column as u32));
    }
    for _ in 0..2 {
        values.extend((0..16).rev());
    }
    debug_assert_eq!(values.len(), PACKED_FULL_XOR_ITEMS as usize);
    values
}

fn push_packed_full_depth_lookup(stack: &mut StackTracker) -> StackVariable {
    // Each dynamic row lookup uses its packed start rather than `16*y`.
    let values = PACKED_FULL_XOR_ROW_STARTS.map(|start| -33_i32 - start as i32);
    stack.custom(
        script! {
            for value in values {
                { value }
            }
        },
        0,
        false,
        0,
        "packed full-XOR depth lookup",
    );
    stack.define(16, "lookup")
}

fn push_packed_full_xor_table(stack: &mut StackTracker) -> StackVariable {
    let values = packed_full_xor_values();
    stack.custom(
        script! {
            for value in values {
                { value }
            }
        },
        0,
        false,
        0,
        "packed full XOR table",
    );
    stack.define(PACKED_FULL_XOR_ITEMS, "xor_full_table")
}

fn packed_full_xor_row_offset(semantic_row: u32) -> u32 {
    PACKED_FULL_XOR_ITEMS - 16 - PACKED_FULL_XOR_ROW_STARTS[semantic_row as usize]
}

fn packed_full_modulo_offset() -> u32 {
    PACKED_FULL_XOR_ITEMS - 48 - PACKED_FULL_XOR_ROW_STARTS[0]
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
        // Top-relative depths 2*s and 2*s+1 contain s%16 and s/16. Retaining
        // the absolute index during the first PICK shifts that lookup by one;
        // consuming the same index during the second PICK selects carry.
        stack.op_dup();
        stack.op_add();
        let interleaved_offset = stack.get_offset(tables.add_interleaved);
        stack.number(interleaved_offset);
        stack.op_add();
        stack.op_dup();
        let modulo = stack.op_pick();
        stack.rename(modulo, &format!("modulo[{nibble_index}]"));
        stack.to_altstack();
        let carry = stack.op_pick();
        stack.rename(carry, "carry");
    } else {
        let modulo = if tables.use_full_tables {
            // Row zero is extended to three consecutive copies, so indexing
            // it with any possible raw sum directly returns sum modulo 16.
            stack.get_value_from_table(tables.xor_table, Some(packed_full_modulo_offset()))
        } else {
            stack.get_value_from_table(tables.modulo_last, None)
        };
        stack.rename(modulo, "modulo[0]");
        stack.to_altstack();
    }
}

fn u4_add_direct(
    stack: &mut StackTracker,
    to_copy: Vec<StackVariable>,
    to_move: Vec<&mut StackVariable>,
    tables: &TablesVars,
) {
    u4_add_direct_ordered(stack, to_copy, to_move, tables, false);
}

fn u4_add_direct_ordered(
    stack: &mut StackTracker,
    to_copy: Vec<StackVariable>,
    mut to_move: Vec<&mut StackVariable>,
    tables: &TablesVars,
    move_before_copy: bool,
) {
    let nibble_count = 8;
    let number_count = to_copy.len() + to_move.len();

    for i in (0..nibble_count).rev() {
        if move_before_copy {
            for x in to_move.iter_mut().rev() {
                stack.move_var_sub_n(x, i);
            }
            for x in &to_copy {
                stack.copy_var_sub_n(*x, i);
            }
        } else {
            for x in &to_copy {
                stack.copy_var_sub_n(*x, i);
            }
            for x in &mut to_move {
                stack.move_var_sub_n(x, i);
            }
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
        if i < 7 {
            stack.op_add();
        }
        // Fold the known nibble into the absolute interleaved-table address:
        // 2*(dynamic + carry + constant) = 2*(dynamic + carry) + 2*constant.
        stack.op_dup();
        stack.op_add();
        let retained_index_adjustment = u32::from(i > 0);
        let offset = stack.get_offset(tables.add_interleaved) - 1
            + retained_index_adjustment
            + 2 * constant_nibble(constant, i);
        stack.number(offset);
        stack.op_add();
        if i > 0 {
            stack.op_dup();
            stack.op_pick();
            stack.to_altstack();
            stack.op_pick();
        } else {
            stack.op_pick();
            stack.to_altstack();
        }
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
        outputs.push(stack.get_value_from_table(
            tables.xor_table,
            Some(packed_full_xor_row_offset(constant_nibble)),
        ));
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
    move_message_first: bool,
) {
    let vb = var_map[&b];
    let mut va = var_map.get_mut(&a).unwrap();

    match (last_round, m_two_i.as_mut()) {
        (true, Some(message)) => u4_add_direct_ordered(
            stack,
            vec![vb],
            vec![&mut va, message],
            tables,
            move_message_first,
        ),
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
        (true, Some(message)) => u4_add_direct_ordered(
            stack,
            vec![vb],
            vec![&mut va, message],
            tables,
            move_message_first,
        ),
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
    direct_short_layout: bool,
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
                last_round && direct_short_layout && block_len == 32,
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
    direct_short_layout: bool,
) {
    assert_eq!(final_rounds, 8);

    let (mut state, first_full_round) = if chaining {
        (init_state(stack, true, counter, block_len, flags), 0)
    } else {
        let mut state = first_round_columns(stack, counter, block_len, flags, &message, tables);
        round(
            stack,
            &mut state,
            &message,
            tables,
            false,
            0,
            block_len,
            [true; 4],
            direct_short_layout,
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
            direct_short_layout,
        );
        message = permutate(&message);
    }
    round(
        stack,
        &mut state,
        &message,
        tables,
        true,
        6,
        block_len,
        [false; 4],
        direct_short_layout,
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

const DIGIT_R16_ORDER: [usize; 8] = [3, 1, 2, 0, 4, 5, 6, 7];
const DIGIT_R12_ORDER: [usize; 8] = [2, 0, 1, 6, 4, 5, 3, 7];
const DIGIT_R8_ORDER: [usize; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

// Short inputs with eight live words keep each nibble as an independent
// tracked register. That lets the generator choose physical emission order
// without normalizing a word after every rotation; semantic indices in
// `digits` remain canonical.
#[derive(Clone, Debug, Copy)]
pub(crate) struct DigitWord {
    digits: [StackVariable; 8],
}

impl DigitWord {
    pub(crate) fn from_physical_slice(digits: &[StackVariable], order: &[usize; 8]) -> Self {
        let mut semantic = [StackVariable::null(); 8];
        for (physical, semantic_index) in order.iter().copied().enumerate() {
            semantic[semantic_index] = digits[physical];
        }
        Self { digits: semantic }
    }

    fn from_slice(digits: &[StackVariable]) -> Self {
        Self {
            digits: digits.try_into().unwrap(),
        }
    }

    fn copy_digit(&self, stack: &mut StackTracker, index: usize) -> StackVariable {
        stack.copy_var_sub_n(self.digits[index], 0)
    }

    fn move_digit(&mut self, stack: &mut StackTracker, index: usize) -> StackVariable {
        stack.move_var_sub_n(&mut self.digits[index], 0)
    }

    fn from_altstack(stack: &mut StackTracker, name: &str) -> Self {
        let values = stack.from_altstack_count(8);
        for (index, value) in values.iter().enumerate() {
            stack.rename(*value, &format!("{name}[{index}]"));
        }
        Self::from_slice(&values)
    }

    fn join(self, stack: &mut StackTracker) -> StackVariable {
        let mut first = self.digits[0];
        stack.join_count(&mut first, 7)
    }
}

fn digit_add(
    stack: &mut StackTracker,
    copies: &[DigitWord],
    moves: &mut [&mut DigitWord],
    tables: &TablesVars,
    move_before_copy: bool,
) -> DigitWord {
    let operand_count = copies.len() + moves.len();
    for index in (0..8).rev() {
        if move_before_copy {
            for word in moves.iter_mut().rev() {
                word.move_digit(stack, index);
            }
            for word in copies {
                word.copy_digit(stack, index);
            }
        } else {
            for word in copies {
                word.copy_digit(stack, index);
            }
            for word in moves.iter_mut() {
                word.move_digit(stack, index);
            }
        }
        for _ in 1..operand_count {
            stack.op_add();
        }
        if index < 7 {
            stack.op_add();
        }
        split_addition(stack, tables, index as u8);
    }
    DigitWord::from_altstack(stack, "digit-add")
}

fn digit_add_constant(
    stack: &mut StackTracker,
    constant: u32,
    dynamic: &DigitWord,
    tables: &TablesVars,
) -> DigitWord {
    for index in (0..8).rev() {
        dynamic.copy_digit(stack, index);
        if index < 7 {
            stack.op_add();
        }
        stack.op_dup();
        stack.op_add();
        let retained_adjustment = u32::from(index > 0);
        let offset = stack.get_offset(tables.add_interleaved) - 1
            + retained_adjustment
            + 2 * constant_nibble(constant, index as u8);
        stack.number(offset);
        stack.op_add();
        if index > 0 {
            stack.op_dup();
            stack.op_pick();
            stack.to_altstack();
            stack.op_pick();
        } else {
            stack.op_pick();
            stack.to_altstack();
        }
    }
    DigitWord::from_altstack(stack, "digit-constant-add")
}

fn digit_xor(
    stack: &mut StackTracker,
    x: &mut DigitWord,
    x_index: usize,
    y: &DigitWord,
    y_index: usize,
) -> StackVariable {
    stack.op_depth();
    stack.op_dup();
    y.copy_digit(stack, y_index);
    stack.op_sub();
    stack.op_pick();
    stack.op_add();
    x.move_digit(stack, x_index);
    stack.op_add();
    stack.op_pick()
}

fn digit_xor_final_query(
    stack: &mut StackTracker,
    x: &mut DigitWord,
    x_index: usize,
    y: &DigitWord,
    y_index: usize,
) -> StackVariable {
    stack.op_depth();
    stack.op_dup();
    y.copy_digit(stack, y_index);
    stack.op_sub();
    stack.op_pick();
    stack.op_add();
    x.move_digit(stack, x_index);
    stack.op_add();
    // Runtime destructively consumes the selected table item. The tracker
    // intentionally models this as a PICK-shaped result; cleanup reconciles
    // the one-item difference once no later table lookup can observe it.
    stack
        .custom(
            script! { OP_ROLL },
            1,
            true,
            0,
            "final destructive XOR lookup",
        )
        .unwrap()
}

fn digit_rotation_order(rotation: usize) -> &'static [usize; 8] {
    // Exhaustive host-time searches selected these orders for the fixed
    // eight-word message layout. They affect routing only, not word semantics.
    match rotation {
        16 => &DIGIT_R16_ORDER,
        12 => &DIGIT_R12_ORDER,
        8 => &DIGIT_R8_ORDER,
        _ => unreachable!(),
    }
}

fn digit_xor_rotate_multiple_of_four(
    stack: &mut StackTracker,
    x: &mut DigitWord,
    y: &DigitWord,
    rotation: usize,
) -> DigitWord {
    let shift = 8 - rotation / 4;
    let mut values = [StackVariable::null(); 8];
    for output in digit_rotation_order(rotation) {
        let source = (output + shift) % 8;
        values[*output] = digit_xor(stack, x, source, y, source);
    }
    DigitWord { digits: values }
}

fn digit_xor_constant_rotate_multiple_of_four(
    stack: &mut StackTracker,
    constant: u32,
    dynamic: &DigitWord,
    rotation: usize,
    tables: &TablesVars,
) -> DigitWord {
    let shift = 8 - rotation / 4;
    let mut values = [StackVariable::null(); 8];
    for output in digit_rotation_order(rotation) {
        let source = (output + shift) % 8;
        let nibble = constant_nibble(constant, source as u8);
        values[*output] = if nibble == 0 {
            dynamic.copy_digit(stack, source)
        } else if nibble == 15 {
            stack.number(15);
            dynamic.copy_digit(stack, source);
            stack.op_sub()
        } else {
            dynamic.copy_digit(stack, source);
            stack.get_value_from_table(tables.xor_table, Some(packed_full_xor_row_offset(nibble)))
        };
    }
    DigitWord { digits: values }
}

fn digit_xor_rotate_seven(
    stack: &mut StackTracker,
    x: &mut DigitWord,
    y: &DigitWord,
    tables: &TablesVars,
    call: usize,
) -> DigitWord {
    // A bounded coordinate search over all eight starts for every G call.
    const STARTS: [usize; 56] = [
        1, 4, 1, 0, 1, 1, 4, 0, 4, 1, 1, 0, 4, 1, 1, 0, 4, 1, 1, 0, 4, 1, 1, 0, 4, 1, 1, 0, 4, 1,
        1, 0, 4, 1, 1, 0, 4, 1, 1, 0, 4, 1, 1, 0, 4, 1, 1, 1, 1, 4, 1, 1, 1, 1, 1, 1,
    ];
    let start = STARTS[call];
    let first_source = (start + 6) % 8;
    let second_source = (start + 7) % 8;
    let first = digit_xor(stack, x, first_source, y, first_source);
    stack.copy_var(first);
    stack.to_altstack();
    let second = digit_xor(stack, x, second_source, y, second_source);
    stack.copy_var(second);
    stack.to_altstack();
    let mut outputs = [StackVariable::null(); 8];
    outputs[start] = u4_2_nib_shift_blake(stack, tables.shift_tables);
    for offset in 0..6 {
        stack.from_altstack();
        let source = (start + offset) % 8;
        let z = digit_xor(stack, x, source, y, source);
        stack.copy_var(z);
        stack.to_altstack();
        outputs[(start + offset + 1) % 8] = u4_2_nib_shift_blake(stack, tables.shift_tables);
    }
    stack.from_altstack();
    stack.from_altstack();
    outputs[(start + 7) % 8] = u4_2_nib_shift_blake(stack, tables.shift_tables);
    DigitWord { digits: outputs }
}

#[allow(clippy::too_many_arguments)]
fn digit_first_g(
    stack: &mut StackTracker,
    initial_a: u32,
    initial_b: u32,
    initial_c: u32,
    initial_d: u32,
    m0: &DigitWord,
    m1: &DigitWord,
    tables: &TablesVars,
    call: usize,
) -> [DigitWord; 4] {
    let mut a = digit_add_constant(stack, initial_a.wrapping_add(initial_b), m0, tables);
    let d = digit_xor_constant_rotate_multiple_of_four(stack, initial_d, &a, 16, tables);
    let c = digit_add_constant(stack, initial_c, &d, tables);
    let b = digit_xor_constant_rotate_multiple_of_four(stack, initial_b, &c, 12, tables);
    a = digit_add(stack, &[b, *m1], &mut [&mut a], tables, false);
    let mut d_tail = d;
    d_tail = digit_xor_rotate_multiple_of_four(stack, &mut d_tail, &a, 8);
    let mut c_tail = c;
    c_tail = digit_add(stack, &[d_tail], &mut [&mut c_tail], tables, false);
    let mut b_tail = b;
    b_tail = digit_xor_rotate_seven(stack, &mut b_tail, &c_tail, tables, call);
    [a, b_tail, c_tail, d_tail]
}

#[allow(clippy::too_many_arguments)]
fn digit_g(
    stack: &mut StackTracker,
    state: &mut HashMap<u8, DigitWord>,
    a: u8,
    b: u8,
    c: u8,
    d: u8,
    m0: Option<DigitWord>,
    m1: Option<DigitWord>,
    tables: &TablesVars,
    last_round: bool,
    call: usize,
) {
    let b_value = state[&b];
    let a_value = state.get_mut(&a).unwrap();
    *a_value = match (last_round, m0) {
        (true, Some(mut message)) => digit_add(
            stack,
            &[b_value],
            &mut [a_value, &mut message],
            tables,
            true,
        ),
        (false, Some(message)) => {
            digit_add(stack, &[b_value, message], &mut [a_value], tables, false)
        }
        (_, None) => digit_add(stack, &[b_value], &mut [a_value], tables, false),
    };
    let a_value = state[&a];
    let d_value = state.get_mut(&d).unwrap();
    *d_value = digit_xor_rotate_multiple_of_four(stack, d_value, &a_value, 16);
    let d_value = state[&d];
    let c_value = state.get_mut(&c).unwrap();
    *c_value = digit_add(stack, &[d_value], &mut [c_value], tables, false);
    let c_value = state[&c];
    let b_value = state.get_mut(&b).unwrap();
    *b_value = digit_xor_rotate_multiple_of_four(stack, b_value, &c_value, 12);
    let b_value = state[&b];
    let a_value = state.get_mut(&a).unwrap();
    *a_value = match (last_round, m1) {
        (true, Some(mut message)) => digit_add(
            stack,
            &[b_value],
            &mut [a_value, &mut message],
            tables,
            true,
        ),
        (false, Some(message)) => {
            digit_add(stack, &[b_value, message], &mut [a_value], tables, false)
        }
        (_, None) => digit_add(stack, &[b_value], &mut [a_value], tables, false),
    };
    let a_value = state[&a];
    let d_value = state.get_mut(&d).unwrap();
    *d_value = digit_xor_rotate_multiple_of_four(stack, d_value, &a_value, 8);
    let d_value = state[&d];
    let c_value = state.get_mut(&c).unwrap();
    *c_value = digit_add(stack, &[d_value], &mut [c_value], tables, false);
    let c_value = state[&c];
    let b_value = state.get_mut(&b).unwrap();
    *b_value = digit_xor_rotate_seven(stack, b_value, &c_value, tables, call);
}

fn digit_permute(message: &HashMap<u8, DigitWord>) -> HashMap<u8, DigitWord> {
    (0..16_u8)
        .filter_map(|index| {
            message
                .get(&MSG_PERMUTATION[index as usize])
                .copied()
                .map(|word| (index, word))
        })
        .collect()
}

pub(crate) fn compress_short_digits(
    stack: &mut StackTracker,
    block_len: u32,
    mut message: HashMap<u8, DigitWord>,
    tables: &TablesVars,
) {
    // This backend is called only for a single root block with eight live
    // message words (29..=32 bytes).
    let initial = [
        IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7], IV[0], IV[1], IV[2], IV[3], 0, 0,
        block_len, 0b1011,
    ];
    let mut state = HashMap::new();
    for index in 0..4_usize {
        let words = digit_first_g(
            stack,
            initial[index],
            initial[index + 4],
            initial[index + 8],
            initial[index + 12],
            &message[&(index as u8 * 2)],
            &message[&(index as u8 * 2 + 1)],
            tables,
            index,
        );
        for (lane, word) in [
            (index, words[0]),
            (index + 4, words[1]),
            (index + 8, words[2]),
            (index + 12, words[3]),
        ] {
            state.insert(lane as u8, word);
        }
    }

    const COLUMNS: [(u8, u8, u8, u8, u8, u8); 4] = [
        (0, 4, 8, 12, 0, 1),
        (1, 5, 9, 13, 2, 3),
        (2, 6, 10, 14, 4, 5),
        (3, 7, 11, 15, 6, 7),
    ];
    const DIAGONALS: [(u8, u8, u8, u8, u8, u8); 4] = [
        (0, 5, 10, 15, 8, 9),
        (1, 6, 11, 12, 10, 11),
        (2, 7, 8, 13, 12, 13),
        (3, 4, 9, 14, 14, 15),
    ];

    for (position, index) in [2, 1, 3, 0].into_iter().enumerate() {
        let (a, b, c, d, m0, m1) = DIAGONALS[index];
        digit_g(
            stack,
            &mut state,
            a,
            b,
            c,
            d,
            message.get(&m0).copied(),
            message.get(&m1).copied(),
            tables,
            false,
            4 + position,
        );
    }
    message = digit_permute(&message);

    let mut call = 8;
    for round in 1..=6 {
        let diagonal_order = if round == 6 {
            [3, 0, 2, 1]
        } else {
            [3, 2, 1, 0]
        };
        for (steps, order) in [(&COLUMNS, [1, 2, 3, 0]), (&DIAGONALS, diagonal_order)] {
            for index in order {
                let (a, b, c, d, m0, m1) = steps[index];
                digit_g(
                    stack,
                    &mut state,
                    a,
                    b,
                    c,
                    d,
                    message.get(&m0).copied(),
                    message.get(&m1).copied(),
                    tables,
                    round == 6,
                    call,
                );
                call += 1;
            }
        }
        if round < 6 {
            message = digit_permute(&message);
        }
    }

    for word in (0..8_u8).rev() {
        for digit in 0..8 {
            let y = state[&(word + 8)];
            let x = state.get_mut(&word).unwrap();
            if block_len == 32 && word == 0 && digit == 7 {
                digit_xor_final_query(stack, x, digit, &y, digit);
            } else {
                digit_xor(stack, x, digit, &y, digit);
            }
            if digit % 2 == 1 {
                stack.to_altstack();
                stack.to_altstack();
            }
        }
    }
    for word in 8..16_u8 {
        state[&word].join(stack);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::execute_script;
    use crate::support::script::ScriptCompilation;

    #[test]
    fn packed_table_lifecycle_metrics() {
        let mut stack = StackTracker::new();
        let tables = TablesVars::new(&mut stack, true);
        let setup_bytes = stack.get_script().compile_with_policy().len();
        tables.drop(&mut stack);
        assert_eq!(setup_bytes, 353);
        assert_eq!(
            stack.get_script().compile_with_policy().len() - setup_bytes,
            166
        );

        let mut stack = StackTracker::new();
        let mut tables = TablesVars::new_late(&mut stack);
        let initial_setup_bytes = stack.get_script().compile_with_policy().len();
        tables.push_late_tables(&mut stack);
        let complete_setup_bytes = stack.get_script().compile_with_policy().len();
        tables.drop(&mut stack);
        assert_eq!(initial_setup_bytes, 241);
        assert_eq!(complete_setup_bytes - initial_setup_bytes, 112);
        assert_eq!(
            stack.get_script().compile_with_policy().len() - complete_setup_bytes,
            166
        );
    }

    #[test]
    fn destructive_final_xor_query_cleanup_matches_runtime_shape() {
        let mut stack = StackTracker::new();
        let mut tables = TablesVars::new_late(&mut stack);
        tables.push_late_tables(&mut stack);
        stack.number(stack.get_offset(tables.xor_table));
        let result = stack
            .custom(script! { OP_ROLL }, 1, true, 0, "destructive table probe")
            .unwrap();
        stack.drop(result);
        tables.drop_after_destructive_xor_query(&mut stack);
        stack.op_depth();
        stack.number(0);
        stack.op_equalverify();
        stack.op_true();
        assert!(execute_script(stack.get_script()).success);
    }

    #[test]
    fn interleaved_addition_table_covers_every_sum() {
        for sum in 0..48_u32 {
            let mut stack = StackTracker::new();
            let tables = TablesVars::new(&mut stack, true);

            stack.number(sum);
            split_addition(&mut stack, &tables, 1);
            stack.from_altstack();
            stack.number(sum % 16);
            stack.op_equalverify();
            stack.number(sum / 16);
            stack.op_equalverify();
            tables.drop(&mut stack);
            stack.op_true();
            assert!(execute_script(stack.get_script()).success, "sum {sum}");

            let mut stack = StackTracker::new();
            let tables = TablesVars::new(&mut stack, true);
            stack.number(sum);
            split_addition(&mut stack, &tables, 0);
            stack.from_altstack();
            stack.number(sum % 16);
            stack.op_equalverify();
            tables.drop(&mut stack);
            stack.op_true();
            assert!(
                execute_script(stack.get_script()).success,
                "final sum {sum}"
            );
        }
    }

    #[test]
    fn packed_xor_table_covers_every_pair() {
        for x in 0..16_u32 {
            for y in 0..16_u32 {
                let mut stack = StackTracker::new();
                let tables = TablesVars::new(&mut stack, true);
                let mut x_var = stack.number(x);
                let y_var = stack.number(y);
                xor_2_nibbles(&mut stack, &mut x_var, y_var, 0, 0, true);
                stack.number(x ^ y);
                stack.op_equalverify();
                stack.drop(y_var);
                tables.drop(&mut stack);
                stack.op_true();
                assert!(execute_script(stack.get_script()).success, "x={x} y={y}");
            }
        }
    }

    #[test]
    fn packed_xor_table_has_minimum_fixed_row_length() {
        const ROWS: usize = 16;
        let mut best_overlap = vec![0_u8; (1 << ROWS) * ROWS];
        for mask in 1_usize..(1 << ROWS) {
            if mask.is_power_of_two() {
                continue;
            }
            for last in 0..ROWS {
                if mask & (1 << last) == 0 {
                    continue;
                }
                let preceding_mask = mask ^ (1 << last);
                best_overlap[mask * ROWS + last] = (0..ROWS)
                    .filter(|preceding| preceding_mask & (1 << preceding) != 0)
                    .map(|preceding| {
                        best_overlap[preceding_mask * ROWS + preceding]
                            + packed_full_xor_overlap(preceding as u32, last as u32) as u8
                    })
                    .max()
                    .unwrap();
            }
        }
        let full_mask = (1 << ROWS) - 1;
        let maximum_overlap = (0..ROWS)
            .map(|last| best_overlap[full_mask * ROWS + last])
            .max()
            .unwrap();
        assert_eq!(maximum_overlap, 85);
        assert_eq!(ROWS * ROWS - maximum_overlap as usize, 171);
    }
}
