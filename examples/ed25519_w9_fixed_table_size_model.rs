//! Raw locking-script size model for the proposed width-9 Ed25519 fixed-base table.
//!
//! This is deliberately only a table-shape prototype. It does not implement
//! scalar recoding, point addition, or the generalized field-relation gate.
//! Every packed `u32` is represented by the exceptional five-byte ScriptNum
//! accepted by `arithmetic::u32::stack::u32_uncompress`, so every modeled
//! constant push takes the conservative maximum of six serialized bytes. The
//! lower-table zero entry also retains three dummy fields even though the
//! identity branch can eventually omit them. The reported total is therefore
//! a conservative table-only upper bound, not an optimized realized table.
//!
//! Run with:
//! `cargo run --locked --release --example ed25519_w9_fixed_table_size_model`.

use bitcoin_lab::support::script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES};

const WINDOW_BITS: usize = 9;
const POSITION_GROUPS: usize = 29;
const ADDITION_GROUPS: usize = POSITION_GROUPS - 1;
const MAGNITUDE_ENTRIES: usize = (1 << (WINDOW_BITS - 1)) + 1;

// A canonical Ed25519 scalar has at most 253 bits. Its source bit 252 and the
// carry out of the lower 28 centered radix-512 digits make the top recoded
// digit one of 0, 1, or 2.
const TOP_ENTRIES: usize = 3;

const PACKED_U32S_PER_FIELD: usize = 8;
const TOP_FIELDS_PER_ENTRY: usize = 2; // selected initial affine x and y
const ADD_FIELDS_PER_ENTRY: usize = 3; // c_plus, c_minus, and k^{-1}

const TOP_OUTPUT_ITEMS: usize = TOP_FIELDS_PER_ENTRY * PACKED_U32S_PER_FIELD;
const ADD_OUTPUT_ITEMS: usize = ADD_FIELDS_PER_ENTRY * PACKED_U32S_PER_FIELD;

// +2^31 is the sole five-byte ScriptNum used by the existing u32 decoder as
// an unambiguous sentinel for the otherwise unrepresentable u32 bit pattern.
// Its script serialization is one direct-push length byte plus five payload
// bytes. Modeling every word this way is conservative and data-independent.
const WORST_PACKED_U32: i64 = 1_i64 << 31;
const WORST_PACKED_U32_PUSH_BYTES: usize = 6;

fn selector_push_bytes(value: usize) -> usize {
    match value {
        0..=16 => 1,
        17..=127 => 2,
        128..=32_767 => 3,
        _ => panic!("model selector exceeds two-byte ScriptNum payload"),
    }
}

/// Exact raw control-flow bytes emitted by [`decision_tree`].
fn decision_tree_control_bytes(low: usize, high: usize) -> usize {
    assert!(low < high);
    if high - low == 1 {
        // The selected magnitude is consumed at the leaf.
        1 // OP_DROP
    } else {
        let middle = low + (high - low) / 2;
        // OP_DUP, minimally encoded pivot, OP_LESSTHAN, OP_IF, OP_ELSE,
        // OP_ENDIF, then both child subtrees.
        5 + selector_push_bytes(middle)
            + decision_tree_control_bytes(low, middle)
            + decision_tree_control_bytes(middle, high)
    }
}

fn decision_tree(low: usize, high: usize, output_items: usize) -> Script {
    assert!(low < high);
    if high - low == 1 {
        script! {
            OP_DROP
            for _ in 0..output_items { { WORST_PACKED_U32 } }
        }
    } else {
        let middle = low + (high - low) / 2;
        script! {
            OP_DUP { middle as u32 } OP_LESSTHAN
            OP_IF
                { decision_tree(low, middle, output_items) }
            OP_ELSE
                { decision_tree(middle, high, output_items) }
            OP_ENDIF
        }
    }
}

fn table_payload_bytes(entries: usize, output_items: usize) -> usize {
    entries * output_items * WORST_PACKED_U32_PUSH_BYTES
}

fn main() {
    let top_control = decision_tree_control_bytes(0, TOP_ENTRIES);
    let add_control = decision_tree_control_bytes(0, MAGNITUDE_ENTRIES);
    let nonzero_add_control = decision_tree_control_bytes(0, MAGNITUDE_ENTRIES - 1);
    let top_payload = table_payload_bytes(TOP_ENTRIES, TOP_OUTPUT_ITEMS);
    let add_payload = table_payload_bytes(MAGNITUDE_ENTRIES, ADD_OUTPUT_ITEMS);
    let nonzero_add_payload = table_payload_bytes(MAGNITUDE_ENTRIES - 1, ADD_OUTPUT_ITEMS);

    let top_table = decision_tree(0, TOP_ENTRIES, TOP_OUTPUT_ITEMS);
    let add_table = decision_tree(0, MAGNITUDE_ENTRIES, ADD_OUTPUT_ITEMS);
    let all_tables = script! {
        { top_table }
        for _ in 0..ADDITION_GROUPS { { add_table.clone() } }
    };
    let compiled = all_tables.compile_with_policy();

    let total_control = top_control + ADDITION_GROUPS * add_control;
    let total_payload = top_payload + ADDITION_GROUPS * add_payload;
    let modeled_total = total_control + total_payload;
    assert!(
        modeled_total > MAX_OPTIMIZER_INPUT_BYTES,
        "the whole model must exercise the policy's raw-script path"
    );
    assert_eq!(compiled.len(), modeled_total);

    println!("model=ed25519_width9_fixed_base_table_only");
    println!("bound=conservative_upper");
    println!("compilation=policy-produced-unoptimized");
    println!("position_groups={POSITION_GROUPS}");
    println!("addition_groups={ADDITION_GROUPS}");
    println!("top_table_entries={TOP_ENTRIES}");
    println!("entries_per_addition_table={MAGNITUDE_ENTRIES}");
    println!(
        "embedded_logical_entries={}",
        TOP_ENTRIES + ADDITION_GROUPS * MAGNITUDE_ENTRIES
    );
    println!("top_table_control_bytes={top_control}");
    println!("top_table_payload_bytes={top_payload}");
    println!("one_add_table_control_bytes={add_control}");
    println!("one_add_table_payload_bytes={add_payload}");
    println!("one_nonzero_only_add_table_control_bytes={nonzero_add_control}");
    println!("one_nonzero_only_add_table_payload_bytes={nonzero_add_payload}");
    println!(
        "one_nonzero_only_add_table_bytes={}",
        nonzero_add_control + nonzero_add_payload
    );
    println!("all_tables_control_bytes={total_control}");
    println!("all_tables_payload_bytes={total_payload}");
    println!("all_tables_locking_script_bytes={}", compiled.len());
    println!("top_selected_runtime_items={TOP_OUTPUT_ITEMS}");
    println!("addition_selected_runtime_items={ADD_OUTPUT_ITEMS}");
    println!(
        "selected_items_if_all_outputs_coexist={}",
        TOP_OUTPUT_ITEMS + ADDITION_GROUPS * ADD_OUTPUT_ITEMS
    );
    println!("hint_items=0");
    println!("assumption_packed_u32_push_bytes={WORST_PACKED_U32_PUSH_BYTES}");
    println!("assumption_zero_entry_retains_dummy_fields=true");
    println!("execution_class=unclassified");
}
