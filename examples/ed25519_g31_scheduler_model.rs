//! Executable stack scheduler for the 31-group fixed-base Ed25519 model.
//!
//! This composes the real direct scalar stream and the 61-item asymmetric-R0
//! quotient decoder with short transition stubs having the measured local
//! input/output/peak interfaces of the arithmetic kernels. It deliberately
//! does not execute thirty ~100 kB arithmetic kernels. The result proves item
//! scheduling and the combined-stack frontier, not affine algebra.
//!
//! Run with:
//! `cargo run --locked --release --example ed25519_g31_scheduler_model`.

use bitcoin_lab::support::{
    execution::execute_raw_script_with_inputs_strict,
    script::{script, Script, ScriptCompilation},
};
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};

const TRANSITIONS: usize = 30;
const TRACE_ITEMS_PER_TRANSITION: usize = 24;
const TRACE_ITEMS: usize = TRANSITIONS * TRACE_ITEMS_PER_TRANSITION;
const PAIR_ITEMS_PER_TRANSITION: usize = 2;
const PAIR_ITEMS: usize = TRANSITIONS * PAIR_ITEMS_PER_TRANSITION;
const Q_HIGH_ITEMS: usize = 1;
const QUOTIENT_HINT_ITEMS: usize = PAIR_ITEMS + Q_HIGH_ITEMS;
const SCALAR_ITEMS: usize = 8;
const COMPLETE_ENTRY_ITEMS: usize = TRACE_ITEMS + QUOTIENT_HINT_ITEMS + SCALAR_ITEMS;
const LEGACY_Q_HINT_ITEMS: usize = 63;
const LEGACY_COMPLETE_ENTRY_ITEMS: usize = TRACE_ITEMS + LEGACY_Q_HINT_ITEMS + SCALAR_ITEMS;
const MIXED_Q_HINT_ITEMS: usize = 65;
const MIXED_COMPLETE_ENTRY_ITEMS: usize = TRACE_ITEMS + MIXED_Q_HINT_ITEMS + SCALAR_ITEMS;
const HYBRID_TABLE_BYTES: usize = 861_360;
const MIXED_HYBRID_TABLE_BYTES: usize = 849_844;
const SCALAR_VALIDATOR_BYTES: usize = 774;
const SCALAR_STREAM_BYTES: usize = 4_893;
const QUOTIENT_DECODER_BYTES: usize = 27_236;
const MIXED_FIRST_SEQUENTIAL_BYTES: usize = 179_408;
const MIXED_FIRST_SEQUENTIAL_PEAK: usize = 233;
const MIXED_CHAINED_SHARED_BYTES: usize = 110_180;
const MIXED_CHAINED_SHARED_PEAK: usize = 256;
const MIXED_DIRECT_CONSTANTS_BYTES: usize = 100_546;
const MIXED_DIRECT_CONSTANTS_PEAK: usize = 329;

const PACKED_POINT_ITEMS: usize = 16;
const EXPANDED_POINT_ITEMS: usize = 102;
const EARLY_CONSTANT_ITEMS: usize = 29;
const LATE_CONSTANT_ITEMS: usize = 115;
const TOP_WORD_BITS: usize = 29;
const PACKED_WORDS: usize = 8;
const Q0_WIDTH: usize = 23;
const Q_RELATION_WIDTH: usize = 21;
const Q_HIGH_BITS: usize = 30;
const Q_MIN: [i32; 3] = [-3_499_801, -584_302, -565_752];
const Q_MAX: [i32; 3] = [3_299_033, 565_752, 584_302];

// These interfaces are measured by ed25519_packed_affine_transition_benchmark.
// They are intentionally kept next to the scheduler arithmetic so a changed
// kernel metric cannot silently alter the composition claim.
const FIRST_SEQUENTIAL: Kernel = Kernel {
    name: "first_sequential_direct_k",
    input: 72,
    output: EXPANDED_POINT_ITEMS,
    local_peak: 237,
    bytes: 165_536,
};
const FIRST_SHARED: Kernel = Kernel {
    name: "first_shared_direct_k",
    input: 72,
    output: EXPANDED_POINT_ITEMS,
    local_peak: 285,
    bytes: 123_264,
};
const CHAINED_SEQUENTIAL: Kernel = Kernel {
    name: "chained_sequential_direct_k",
    input: 158,
    output: EXPANDED_POINT_ITEMS,
    local_peak: 242,
    bytes: 156_031,
};
const CHAINED_SHARED: Kernel = Kernel {
    name: "chained_shared_direct_k",
    input: 158,
    output: EXPANDED_POINT_ITEMS,
    local_peak: 256,
    bytes: 113_262,
};
const DIRECT_CONSTANTS_SEQUENTIAL: Kernel = Kernel {
    name: "chained_sequential_direct_constants",
    input: 244,
    output: EXPANDED_POINT_ITEMS,
    local_peak: 329,
    bytes: 139_705,
};
const DIRECT_CONSTANTS_SHARED: Kernel = Kernel {
    name: "chained_shared_direct_constants",
    input: 244,
    output: EXPANDED_POINT_ITEMS,
    local_peak: 329,
    bytes: 103_628,
};

#[derive(Clone, Copy)]
struct Kernel {
    name: &'static str,
    input: usize,
    output: usize,
    local_peak: usize,
    bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Block {
    Trace(usize),
    Pair(usize),
    QuotientHigh,
    Scalar,
    Current,
    Constants,
    Quotients,
}

#[derive(Clone)]
struct Layout {
    blocks: Vec<(Block, usize)>,
}

impl Layout {
    fn entry() -> Self {
        let mut blocks = (0..TRANSITIONS)
            .rev()
            .map(|transition| (Block::Trace(transition), TRACE_ITEMS_PER_TRANSITION))
            .collect::<Vec<_>>();
        blocks.extend(
            (0..TRANSITIONS)
                .rev()
                .map(|transition| (Block::Pair(transition), PAIR_ITEMS_PER_TRANSITION)),
        );
        blocks.extend([
            (Block::QuotientHigh, Q_HIGH_ITEMS),
            (Block::Scalar, SCALAR_ITEMS),
        ]);
        let result = Self { blocks };
        assert_eq!(result.items(), COMPLETE_ENTRY_ITEMS);
        result
    }

    fn items(&self) -> usize {
        self.blocks.iter().map(|(_, items)| *items).sum()
    }

    fn index(&self, block: Block) -> usize {
        self.blocks
            .iter()
            .position(|(candidate, _)| *candidate == block)
            .unwrap_or_else(|| panic!("missing scheduler block {block:?}"))
    }

    fn size(&self, block: Block) -> usize {
        self.blocks[self.index(block)].1
    }

    fn move_to_top(&mut self, block: Block) -> Script {
        let index = self.index(block);
        let block_items = self.blocks[index].1;
        let items_above = self.blocks[index + 1..]
            .iter()
            .map(|(_, items)| *items)
            .sum();
        let entry = self.blocks.remove(index);
        self.blocks.push(entry);
        move_block_to_top(block_items, items_above)
    }

    fn push(&mut self, block: Block, items: usize) {
        assert!(!self.blocks.iter().any(|(candidate, _)| *candidate == block));
        self.blocks.push((block, items));
    }

    fn set_size(&mut self, block: Block, items: usize) {
        let index = self.index(block);
        if items == 0 {
            self.blocks.remove(index);
        } else {
            self.blocks[index].1 = items;
        }
    }

    fn replace_suffix(&mut self, expected: &[(Block, usize)], replacement: &[(Block, usize)]) {
        assert!(
            self.blocks.ends_with(expected),
            "bad scheduler suffix: live={:?}, expected={expected:?}",
            self.blocks
        );
        self.blocks.truncate(self.blocks.len() - expected.len());
        self.blocks.extend_from_slice(replacement);
    }
}

fn move_block_to_top(block_items: usize, items_above: usize) -> Script {
    if items_above == 0 || block_items == 0 {
        return Script::new("block already at top");
    }
    let depth = block_items + items_above - 1;
    script! { for _ in 0..block_items { { depth as u32 } OP_ROLL } }
}

fn drop_top_items(items: usize) -> Script {
    script! {
        for _ in 0..items / 2 { OP_2DROP }
        if items % 2 != 0 { OP_DROP }
    }
}

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn compressed_word_scriptnum(word: u32) -> i64 {
    i64::from(word as i32)
}

fn widths_high_to_low() -> Vec<usize> {
    [vec![9], vec![9; 4], vec![8; 26]].concat()
}

fn scalar_items_after_callbacks() -> Vec<usize> {
    let mut chunks = vec![TOP_WORD_BITS];
    chunks.extend(std::iter::repeat_n(32, PACKED_WORDS - 1));
    let mut chunk = 0usize;
    let mut remaining = chunks[0];
    let mut result = Vec::with_capacity(TRANSITIONS);
    for width in widths_high_to_low() {
        let mut needed = width;
        while needed >= remaining {
            needed -= remaining;
            chunk += 1;
            if needed == 0 {
                remaining = chunks.get(chunk).copied().unwrap_or(0);
                break;
            }
            remaining = chunks[chunk];
        }
        if needed != 0 {
            remaining -= needed;
        }
        result.push(chunks.len() - chunk);
    }
    assert_eq!(result.len(), TRANSITIONS + 1);
    assert_eq!(result[0], SCALAR_ITEMS);
    result.remove(0); // Top table selection is not an affine transition.
    assert_eq!(result.len(), TRANSITIONS);
    assert_eq!(*result.last().expect("thirty callbacks"), 0);
    result
}

fn scalar_words_for_all_one_digits() -> [u32; PACKED_WORDS] {
    let mut payload = BigUint::zero();
    let mut offset = 0usize;
    let mut low_to_high = vec![8; 26];
    low_to_high.extend([9; 4]);
    low_to_high.push(9);
    for (index, width) in low_to_high.iter().enumerate() {
        let encoded = if index + 1 == low_to_high.len() {
            1u32
        } else {
            1u32 + (1u32 << (width - 1))
        };
        payload |= BigUint::from(encoded) << offset;
        offset += width;
    }
    assert_eq!(offset, 253);
    std::array::from_fn(|index| {
        ((&payload >> (32 * index)) & BigUint::from(u32::MAX))
            .to_u32()
            .expect("masked scalar word")
    })
}

fn scalar_witness_items() -> Vec<Vec<u8>> {
    scalar_words_for_all_one_digits()
        .into_iter()
        .map(|word| scriptnum_item(compressed_word_scriptnum(word)))
        .collect()
}

fn bits_from_altstack_to_number(width: usize) -> Script {
    assert!(width > 0);
    script! {
        OP_FROMALTSTACK
        for _ in 1..width {
            OP_DUP OP_ADD OP_FROMALTSTACK OP_ADD
        }
    }
}

fn split_number(total_bits: usize, high_bits: usize) -> Script {
    assert!(high_bits > 0 && high_bits < total_bits && total_bits <= 31);
    let low_bits = total_bits - high_bits;
    script! {
        for bit in (low_bits..total_bits).rev() {
            OP_DUP { (1u32 << bit) - 1 } OP_GREATERTHAN
            OP_SWAP OP_OVER
            OP_IF { 1u32 << bit } OP_SUB OP_ENDIF
        }
        OP_TOALTSTACK
        for _ in 0..high_bits { OP_TOALTSTACK }
        { bits_from_altstack_to_number(high_bits) }
        OP_FROMALTSTACK
    }
}

fn compressed_word_to_low31_and_sign() -> Script {
    script! {
        OP_DUP 0 OP_LESSTHAN
        OP_IF
            { i32::MAX } OP_ADD OP_1ADD 1
        OP_ELSE
            0
        OP_ENDIF
    }
}

fn finish_partial(total_bits: usize, partial_bits: usize, take: usize) -> Script {
    assert!(partial_bits > 0 && take > 0 && take < total_bits);
    script! {
        OP_SWAP
        { split_number(total_bits, take) }
        OP_TOALTSTACK OP_SWAP
        for _ in 0..take { OP_DUP OP_ADD }
        OP_ADD
        OP_FROMALTSTACK OP_SWAP
    }
}

fn park_current(items: usize) -> Script {
    script! { for _ in 0..items { OP_TOALTSTACK } }
}

fn restore_current(items: usize) -> Script {
    script! {
        for _ in 0..items { OP_FROMALTSTACK }
        { items as u32 } OP_ROLL
    }
}

fn certify_exact_compressed_word() -> Script {
    script! {
        OP_SIZE 5 OP_NUMEQUAL
        OP_IF
            OP_DUP { -2_147_483_648i64 } OP_EQUALVERIFY
        OP_ELSE
            OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
        OP_ENDIF
    }
}

fn certify_q_high_word() -> Script {
    script! {
        OP_SIZE 5 OP_LESSTHAN OP_VERIFY
        OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
        OP_DUP 0 { 1u32 << Q_HIGH_BITS } OP_WITHIN OP_VERIFY
    }
}

fn exact_word_to_low31_and_sign() -> Script {
    script! {
        { certify_exact_compressed_word() }
        { compressed_word_to_low31_and_sign() }
    }
}

fn finish_twos_complement(width: usize) -> Script {
    script! {
        OP_DUP { 1u32 << (width - 1) } OP_GREATERTHANOREQUAL
        OP_IF { 1u32 << width } OP_SUB OP_ENDIF
    }
}

// This is the measured codec's exact local decoder, kept inline so the whole
// scheduler exercises hostile-word certification and real tuple routing.
fn decode_quotient_tuple() -> Script {
    script! {
        // Entry is high32 | low32 | q0_bit22.
        OP_TOALTSTACK
        { exact_word_to_low31_and_sign() }
        OP_TOALTSTACK
        // low31 -> q+ low10 | q-.
        for bit in (21..31).rev() {
            OP_DUP { (1u32 << bit) - 1 } OP_GREATERTHAN
            OP_SWAP OP_OVER
            OP_IF { 1u32 << bit } OP_SUB OP_ENDIF
        }
        OP_TOALTSTACK
        for _ in 0..10 { OP_TOALTSTACK }
        { bits_from_altstack_to_number(10) }
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_TOALTSTACK OP_SWAP OP_FROMALTSTACK
        for _ in 0..10 { OP_DUP OP_ADD }
        OP_ADD

        2 OP_ROLL
        { exact_word_to_low31_and_sign() }
        OP_TOALTSTACK
        // high31 -> q0 low21 | q+ high10.
        for bit in (10..31).rev() {
            OP_DUP { (1u32 << bit) - 1 } OP_GREATERTHAN
            OP_SWAP OP_OVER
            OP_IF { 1u32 << bit } OP_SUB OP_ENDIF
        }
        OP_TOALTSTACK
        for _ in 0..21 { OP_TOALTSTACK }
        { bits_from_altstack_to_number(21) }
        OP_FROMALTSTACK

        2 OP_ROLL OP_SWAP
        for _ in 0..11 { OP_DUP OP_ADD }
        OP_ADD
        OP_SWAP OP_FROMALTSTACK
        for _ in 0..21 { OP_DUP OP_ADD }
        OP_ADD
        OP_FROMALTSTACK
        for _ in 0..22 { OP_DUP OP_ADD }
        OP_ADD

        OP_ROT OP_ROT OP_SWAP
        { finish_twos_complement(Q_RELATION_WIDTH) }
        OP_SWAP { finish_twos_complement(Q_RELATION_WIDTH) } OP_SWAP
        2 OP_ROLL { finish_twos_complement(Q0_WIDTH) }
        OP_ROT OP_ROT

        2 OP_PICK { Q_MIN[0] } { Q_MAX[0] + 1 } OP_WITHIN OP_VERIFY
        1 OP_PICK { Q_MIN[1] } { Q_MAX[1] + 1 } OP_WITHIN OP_VERIFY
        OP_DUP { Q_MIN[2] } { Q_MAX[2] + 1 } OP_WITHIN OP_VERIFY
    }
}

fn decode_next_quotients(remaining_bits: usize, first: bool) -> Script {
    script! {
        if first { { certify_q_high_word() } }
        if remaining_bits == 1 {
            OP_TOALTSTACK OP_SWAP
        } else {
            { split_number(remaining_bits, 1) }
            OP_SWAP OP_TOALTSTACK
            1 OP_ROLL 2 OP_ROLL
        }
        OP_FROMALTSTACK
        { decode_quotient_tuple() }
    }
}

fn all_zero_quotient_witness() -> Vec<Vec<u8>> {
    vec![Vec::new(); QUOTIENT_HINT_ITEMS]
}

fn selected_constants(digit: i32, constants: usize) -> Script {
    assert_ne!(digit, 0);
    script! {
        OP_DUP { digit } OP_NUMEQUALVERIFY
        // One sign marker survives magnitude selection.
        OP_DUP 0 OP_LESSTHAN
        OP_IF OP_NEGATE 1 OP_ELSE 0 OP_ENDIF
        OP_SWAP

        // Stand in for the table leaf: consume magnitude, then return the
        // authenticated constants followed by its nonzero branch marker.
        OP_DROP
        for _ in 0..constants { 0 }
        1
        OP_IF OP_ENDIF

        // Sign and table branch markers coexist only until this routing point.
        { constants as u32 } OP_ROLL
        OP_IF OP_ELSE OP_ENDIF
    }
}

fn kernel_stub(kernel: Kernel) -> Script {
    assert!(kernel.local_peak >= kernel.input);
    let growth = kernel.local_peak - kernel.input;
    script! {
        for _ in 0..growth { 0 }
        { drop_top_items(growth + kernel.input) }
        for _ in 0..kernel.output { 0 }
    }
}

fn route_high_remainder_below_scalar(layout: &mut Layout, transition: usize) -> Script {
    if transition + 1 == TRANSITIONS {
        return Script::new("global q-high word was consumed");
    }
    script! {
        { layout.move_to_top(Block::Scalar) }
        { layout.move_to_top(Block::Current) }
        { layout.move_to_top(Block::Constants) }
        { layout.move_to_top(Block::Trace(transition)) }
        { layout.move_to_top(Block::Quotients) }
    }
}

#[derive(Clone)]
struct Row {
    transition: usize,
    width: usize,
    scalar_items: usize,
    constants: usize,
    boundary: usize,
    preserved: usize,
    kernel: Kernel,
    combined_peak: usize,
}

fn callback(
    layout: &mut Layout,
    transition: usize,
    width: usize,
    scalar_items: usize,
    kernel: Kernel,
    rows: &mut Vec<Row>,
) -> Script {
    layout.set_size(Block::Scalar, scalar_items);
    layout.push(Block::Constants, 0); // placeholder replaced after digit selection
    layout.set_size(
        Block::Constants,
        if width == 9 {
            EARLY_CONSTANT_ITEMS
        } else {
            LATE_CONSTANT_ITEMS
        },
    );
    let constants = layout.size(Block::Constants);

    let select = script! {
        { 1u32 << (width - 1) } OP_SUB
        { selected_constants(1, constants) }
    };
    let route_trace = layout.move_to_top(Block::Trace(transition));
    let route_pair = layout.move_to_top(Block::Pair(transition));
    let route_high = layout.move_to_top(Block::QuotientHigh);
    layout.replace_suffix(
        &[
            (Block::Pair(transition), PAIR_ITEMS_PER_TRANSITION),
            (Block::QuotientHigh, Q_HIGH_ITEMS),
        ],
        if transition + 1 == TRANSITIONS {
            &[(Block::Quotients, 3)][..]
        } else {
            &[(Block::QuotientHigh, 1), (Block::Quotients, 3)][..]
        },
    );
    let decode = decode_next_quotients(Q_HIGH_BITS - transition, transition == 0);
    let restore_high = route_high_remainder_below_scalar(layout, transition);

    let expected_suffix = [
        (
            Block::Current,
            if transition == 0 {
                PACKED_POINT_ITEMS
            } else {
                EXPANDED_POINT_ITEMS
            },
        ),
        (Block::Constants, constants),
        (Block::Trace(transition), TRACE_ITEMS_PER_TRANSITION),
        (Block::Quotients, 3),
    ];
    assert!(layout.blocks.ends_with(&expected_suffix));
    assert_eq!(
        expected_suffix
            .iter()
            .map(|(_, items)| *items)
            .sum::<usize>(),
        kernel.input
    );
    let boundary = layout.items();
    let preserved = boundary - kernel.input;
    let combined_peak = preserved + kernel.local_peak;
    rows.push(Row {
        transition,
        width,
        scalar_items,
        constants,
        boundary,
        preserved,
        kernel,
        combined_peak,
    });
    layout.replace_suffix(&expected_suffix, &[(Block::Current, kernel.output)]);

    script! {
        { select }
        { route_trace }
        { route_pair }
        { route_high }
        { decode }
        { restore_high }
        { kernel_stub(kernel) }
    }
}

fn build_schedule(kernels: &[Kernel; TRANSITIONS]) -> (Script, Vec<Row>, Layout) {
    let scalar_after = scalar_items_after_callbacks();
    let mut layout = Layout::entry();
    let mut rows = Vec::with_capacity(TRANSITIONS);
    let mut steps = Vec::new();

    // The independent scalar validator preserves all eight words and has
    // measured +7 combined-stack growth at this exact 789-item entry.
    steps.push(script! { for _ in 0..7 { 0 } for _ in 0..7 { OP_DROP } });

    // Top width-9 digit. The table consumes it and returns packed x/y (16
    // items), including the top-zero identity without a lower-table K.
    steps.push(script! {
        { split_number(TOP_WORD_BITS, 9) }
        OP_SWAP 1 OP_NUMEQUALVERIFY
        for _ in 0..PACKED_POINT_ITEMS { 0 }
    });
    layout.push(Block::Current, PACKED_POINT_ITEMS);

    let target_widths = widths_high_to_low();
    let mut transition = 0usize;
    let mut remainder_bits = TOP_WORD_BITS - target_widths[0];
    while remainder_bits >= target_widths[transition + 1] {
        let width = target_widths[transition + 1];
        let current_items = layout.size(Block::Current);
        steps.push(park_current(current_items));
        if remainder_bits == width {
            steps.push(restore_current(current_items));
            remainder_bits = 0;
        } else {
            steps.push(script! {
                { split_number(remainder_bits, width) } OP_SWAP
                { restore_current(current_items) }
            });
            remainder_bits -= width;
        }
        steps.push(callback(
            &mut layout,
            transition,
            width,
            scalar_after[transition],
            kernels[transition],
            &mut rows,
        ));
        transition += 1;
    }
    let mut partial_bits = remainder_bits;

    for _word in (0..PACKED_WORDS - 1).rev() {
        let current_items = layout.size(Block::Current);
        steps.push(park_current(current_items));
        if partial_bits != 0 {
            steps.push(script! { 1 OP_ROLL });
        }
        steps.push(compressed_word_to_low31_and_sign());
        if partial_bits == 0 {
            partial_bits = 1;
        } else {
            steps.push(script! {
                OP_TOALTSTACK OP_SWAP
                OP_DUP OP_ADD OP_FROMALTSTACK OP_ADD
            });
            partial_bits += 1;
        }

        let width = target_widths[transition + 1];
        let needed = width - partial_bits;
        if needed == 0 {
            steps.push(restore_current(current_items));
        } else {
            steps.push(script! {
                { finish_partial(31, partial_bits, needed) }
                { restore_current(current_items) }
            });
        }
        steps.push(callback(
            &mut layout,
            transition,
            width,
            scalar_after[transition],
            kernels[transition],
            &mut rows,
        ));
        transition += 1;
        remainder_bits = 31 - needed;

        while transition < TRANSITIONS && remainder_bits >= target_widths[transition + 1] {
            let width = target_widths[transition + 1];
            let current_items = layout.size(Block::Current);
            steps.push(park_current(current_items));
            if remainder_bits == width {
                steps.push(restore_current(current_items));
                remainder_bits = 0;
            } else {
                steps.push(script! {
                    { split_number(remainder_bits, width) } OP_SWAP
                    { restore_current(current_items) }
                });
                remainder_bits -= width;
            }
            steps.push(callback(
                &mut layout,
                transition,
                width,
                scalar_after[transition],
                kernels[transition],
                &mut rows,
            ));
            transition += 1;
        }
        partial_bits = remainder_bits;
    }
    assert_eq!(transition, TRANSITIONS);
    assert_eq!(partial_bits, 0);
    assert_eq!(layout.blocks, vec![(Block::Current, EXPANDED_POINT_ITEMS)]);
    (script! { for step in steps { { step } } }, rows, layout)
}

fn selected_kernels() -> [Kernel; TRANSITIONS] {
    std::array::from_fn(|transition| match transition {
        0 => FIRST_SEQUENTIAL,
        1..=3 => CHAINED_SHARED,
        _ => DIRECT_CONSTANTS_SHARED,
    })
}

fn entry_witness() -> Vec<Vec<u8>> {
    let mut witness = vec![Vec::new(); TRACE_ITEMS];
    witness.extend(all_zero_quotient_witness());
    witness.extend(scalar_witness_items());
    assert_eq!(witness.len(), COMPLETE_ENTRY_ITEMS);
    witness
}

fn marker_lifetime_checks() {
    for digit in [-1, 1] {
        let script = script! {
            { digit }
            { selected_constants(digit, EARLY_CONSTANT_ITEMS) }
            { drop_top_items(EARLY_CONSTANT_ITEMS) }
            OP_1
        }
        .compile_with_policy();
        let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), vec![]);
        assert!(
            execution.error.is_none(),
            "signed marker route failed: {execution}"
        );
    }
    // Identity table leaf: sign=0 and the table's sole zero marker coexist,
    // then both are consumed. The actual tau=0/current=next proof is outside
    // this item-only stub and remains a required integration boundary.
    let zero = script! {
        0
        OP_DUP 0 OP_LESSTHAN
        OP_IF OP_NEGATE 1 OP_ELSE 0 OP_ENDIF
        OP_SWAP OP_DROP
        0
        OP_NOTIF 0 OP_NUMEQUALVERIFY OP_ENDIF
        OP_1
    }
    .compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(zero.to_bytes(), vec![]);
    assert!(
        execution.error.is_none(),
        "zero marker route failed: {execution}"
    );
}

fn main() {
    assert_eq!(COMPLETE_ENTRY_ITEMS, 789);
    assert_eq!(LEGACY_COMPLETE_ENTRY_ITEMS, 791);
    assert_eq!(MIXED_COMPLETE_ENTRY_ITEMS, 793);
    assert!(
        FIRST_SEQUENTIAL.local_peak != 0,
        "fill measured first sequential peak"
    );
    assert!(
        CHAINED_SEQUENTIAL.local_peak != 0,
        "fill measured chained sequential peak"
    );
    assert!(
        DIRECT_CONSTANTS_SHARED.local_peak != 0,
        "fill measured direct-constant peak"
    );
    marker_lifetime_checks();

    let (schedule, rows, _) = build_schedule(&selected_kernels());
    let executable = script! {
        { schedule }
        { drop_top_items(EXPANDED_POINT_ITEMS) }
        OP_1
    }
    .compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(executable.to_bytes(), entry_witness());
    assert!(
        execution.error.is_none(),
        "G31 scheduler failed: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);

    println!("model=ed25519_g31_integration_scheduler");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=item-schedule");
    println!("execution_class=unclassified");
    println!("transition_arithmetic=measured-interface-stubs");
    println!("trace_items={TRACE_ITEMS}");
    println!("quotient_hint_items={QUOTIENT_HINT_ITEMS}");
    println!("scalar_data_items={SCALAR_ITEMS}");
    println!("all_trace_data_quotient_hints_and_scalar_coexist_at_entry=true");
    println!("complete_entry_items={COMPLETE_ENTRY_ITEMS}");
    println!("legacy_63q_complete_entry_items={LEGACY_COMPLETE_ENTRY_ITEMS}");
    println!("mixed_65q_complete_entry_items={MIXED_COMPLETE_ENTRY_ITEMS}");
    println!("top_selected_items={PACKED_POINT_ITEMS}");
    println!("early_w9_transitions=4");
    println!("early_nonzero_selected_items_including_branch_marker=30");
    println!("late_w8_transitions=26");
    println!("late_nonzero_selected_items_including_branch_marker=116");
    println!("maximum_sign_markers_live=1");
    println!("maximum_table_branch_markers_live=1");
    println!("maximum_sign_plus_branch_markers_live=2");
    println!("markers_consumed_before_relation_kernel=true");
    println!("zero_branch_arithmetic_stubbed=true");
    println!("scheduler_stub_script_bytes={}", executable.len());
    println!(
        "strict_combined_main_alt_stack_peak={}",
        execution.stats.max_nb_stack_items
    );
    println!("sequential_transition_count=1");
    println!("shared_transition_count=29");
    for row in &rows {
        println!(
            "transition={:02},width={},scalar={},constants={},boundary={},local_input={},preserved={},kernel={},local_peak={},combined_peak={},allowance={},fits={}",
            row.transition,
            row.width,
            row.scalar_items,
            row.constants,
            row.boundary,
            row.kernel.input,
            row.preserved,
            row.kernel.name,
            row.kernel.local_peak,
            row.combined_peak,
            1_000usize.saturating_sub(row.preserved),
            row.combined_peak <= 1_000,
        );
    }
    println!(
        "first_shared_counterfactual_peak={}",
        rows[0].preserved + FIRST_SHARED.local_peak
    );
    println!(
        "second_shared_counterfactual_peak={}",
        rows[1].preserved + CHAINED_SHARED.local_peak
    );
    println!(
        "third_shared_peak={}",
        rows[2].preserved + CHAINED_SHARED.local_peak
    );
    println!("only_first_transition_requires_sequential_mode=true");
    println!("kernel_bytes_first_sequential={}", FIRST_SEQUENTIAL.bytes);
    println!(
        "kernel_bytes_chained_sequential={}",
        CHAINED_SEQUENTIAL.bytes
    );
    println!("kernel_bytes_chained_shared={}", CHAINED_SHARED.bytes);
    println!(
        "kernel_bytes_direct_constants_shared={}",
        DIRECT_CONSTANTS_SHARED.bytes
    );
    println!("unused_first_shared_bytes={}", FIRST_SHARED.bytes);
    println!(
        "unused_direct_constants_sequential_bytes={}",
        DIRECT_CONSTANTS_SEQUENTIAL.bytes
    );
    let transition_bytes =
        FIRST_SEQUENTIAL.bytes + 3 * CHAINED_SHARED.bytes + 26 * DIRECT_CONSTANTS_SHARED.bytes;
    let incomplete_positive_subtotal = HYBRID_TABLE_BYTES
        + transition_bytes
        + SCALAR_VALIDATOR_BYTES
        + SCALAR_STREAM_BYTES
        + QUOTIENT_DECODER_BYTES;
    println!("hybrid_table_bytes={HYBRID_TABLE_BYTES}");
    println!("transition_kernel_bytes={transition_bytes}");
    println!("scalar_validator_bytes={SCALAR_VALIDATOR_BYTES}");
    println!("scalar_stream_bytes={SCALAR_STREAM_BYTES}");
    println!("quotient_decoder_bytes={QUOTIENT_DECODER_BYTES}");
    println!("incomplete_positive_subtotal_bytes={incomplete_positive_subtotal}");
    println!(
        "incomplete_positive_subtotal_excess_over_4m={}",
        incomplete_positive_subtotal.saturating_sub(4_000_000)
    );
    // The separate compact-table mixed kernel recovers the four extra stack
    // items used by its 65-item quotient encoding, but its byte budget is
    // already exhausted before adding that quotient decoder.
    let mixed_transition_bytes = MIXED_FIRST_SEQUENTIAL_BYTES
        + 3 * MIXED_CHAINED_SHARED_BYTES
        + 26 * MIXED_DIRECT_CONSTANTS_BYTES;
    let mixed_pre_quotient_subtotal = MIXED_HYBRID_TABLE_BYTES
        + mixed_transition_bytes
        + SCALAR_VALIDATOR_BYTES
        + SCALAR_STREAM_BYTES;
    println!(
        "mixed_t0_peak={}",
        rows[0].preserved + 4 + MIXED_FIRST_SEQUENTIAL_PEAK
    );
    println!(
        "mixed_t1_peak={}",
        rows[1].preserved + 4 + MIXED_CHAINED_SHARED_PEAK
    );
    println!(
        "mixed_first_w8_peak={}",
        rows[4].preserved + 4 + MIXED_DIRECT_CONSTANTS_PEAK
    );
    println!("mixed_hybrid_table_bytes={MIXED_HYBRID_TABLE_BYTES}");
    println!("mixed_transition_kernel_bytes={mixed_transition_bytes}");
    println!("mixed_pre_quotient_subtotal_bytes={mixed_pre_quotient_subtotal}");
    println!(
        "mixed_quotient_decoder_budget_below_4m={}",
        4_000_000usize.saturating_sub(mixed_pre_quotient_subtotal)
    );
}
