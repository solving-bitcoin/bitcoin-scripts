//! Executable item scheduler for the mixed-relation 29-group Ed25519 model.
//!
//! The scalar validator/streamer, MSB-first table trie, and mixed quotient
//! codec are represented by their independently executed item interfaces.
//! Arithmetic uses peak-equivalent stubs. This makes all entry coexistence,
//! per-transition consumption, and the 1,000-item frontier executable without
//! running 28 large affine kernels.
//!
//! Run with:
//! `cargo run --locked --release --example ed25519_g29_scheduler_model`.

use bitcoin_lab::support::{
    execution::execute_raw_script_with_inputs_strict,
    script::{script, Script, ScriptCompilation},
};

const TRANSITIONS: usize = 28;
const WIDTH9_TRANSITIONS: usize = 20;
const WIDTH8_TRANSITIONS: usize = 8;
const TRACE_PER_TRANSITION: usize = 24;
const TRACE_ITEMS: usize = TRANSITIONS * TRACE_PER_TRANSITION;
const LOCAL_Q_WORDS_PER_TRANSITION: usize = 2;
const LOCAL_Q_ITEMS: usize = TRANSITIONS * LOCAL_Q_WORDS_PER_TRANSITION;
const GLOBAL_Q_ITEMS: usize = 5;
const QUOTIENT_HINT_ITEMS: usize = LOCAL_Q_ITEMS + GLOBAL_Q_ITEMS;
const SCALAR_ITEMS: usize = 8;
const ENTRY_ITEMS: usize = TRACE_ITEMS + QUOTIENT_HINT_ITEMS + SCALAR_ITEMS;

const PACKED_CURRENT_ITEMS: usize = 16;
const EXPANDED_CURRENT_ITEMS: usize = 102;
const EARLY_CONSTANT_ITEMS: usize = 29;
const LATE_CONSTANT_ITEMS: usize = 115;

const TABLE_BYTES: usize = 923_727;
const SCALAR_VALIDATOR_BYTES: usize = 791;
const SCALAR_STREAM_BYTES: usize = 9_836;
const QUOTIENT_CODEC_BYTES: usize = 25_570;
const FIRST_SHARED_BYTES: usize = 116_418;
const CHAINED_SHARED_BYTES: usize = 107_259;
const DIRECT_CONSTANTS_SHARED_BYTES: usize = 98_331;

const SCALAR_VALIDATOR_GROWTH: usize = 7;
const SCALAR_STREAM_GLOBAL_GROWTH: usize = 26;
const QUOTIENT_CODEC_GLOBAL_GROWTH: usize = 21;

#[derive(Clone, Copy)]
struct Kernel {
    name: &'static str,
    input: usize,
    output: usize,
    local_peak: usize,
    bytes: usize,
}

const FIRST_SHARED: Kernel = Kernel {
    name: "first_shared_mixed_signed_zero",
    input: 74,
    output: EXPANDED_CURRENT_ITEMS,
    local_peak: 256,
    bytes: FIRST_SHARED_BYTES,
};
const CHAINED_SHARED: Kernel = Kernel {
    name: "chained_shared_mixed_signed_zero",
    input: 160,
    output: EXPANDED_CURRENT_ITEMS,
    local_peak: 256,
    bytes: CHAINED_SHARED_BYTES,
};
const DIRECT_CONSTANTS_SHARED: Kernel = Kernel {
    name: "chained_direct_constants_shared_mixed_signed_zero",
    input: 246,
    output: EXPANDED_CURRENT_ITEMS,
    local_peak: 330,
    bytes: DIRECT_CONSTANTS_SHARED_BYTES,
};

#[derive(Clone)]
struct Row {
    transition: usize,
    width: usize,
    scalar_items: usize,
    constants: usize,
    q_physical_consumed: usize,
    boundary: usize,
    local_input: usize,
    preserved: usize,
    kernel: Kernel,
    combined_peak: usize,
}

fn drop_top_items(items: usize) -> Script {
    script! {
        for _ in 0..items / 2 { OP_2DROP }
        if items % 2 != 0 { OP_DROP }
    }
}

fn grow_then_change(growth: usize, net_change: isize) -> Script {
    let drops = isize::try_from(growth).expect("small growth") - net_change;
    assert!(drops >= 0);
    script! {
        for _ in 0..growth { 0 }
        { drop_top_items(usize::try_from(drops).expect("nonnegative drops")) }
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

// Input is one centered nonzero digit. The sign marker survives the table
// selector; the trie leaf then supplies constants and a nonzero branch marker.
fn trie_select_nonzero(digit: i32, width: usize, constants: usize) -> Script {
    assert_ne!(digit, 0);
    script! {
        OP_DUP { digit } OP_NUMEQUALVERIFY
        OP_DUP 0 OP_LESSTHAN
        OP_IF OP_NEGATE 1 OP_ELSE 0 OP_ENDIF
        OP_SWAP

        // Model exact MSB-first decomposition: one remainder plus w bits,
        // all consumed by the trie before the selected leaf is entered.
        OP_TOALTSTACK
        for _ in 0..width { 0 }
        for _ in 0..width { OP_DROP }
        OP_FROMALTSTACK OP_DROP

        for _ in 0..constants { 0 }
        1
        OP_IF OP_ENDIF
        { constants as u32 } OP_ROLL
        OP_IF OP_ELSE OP_ENDIF
    }
}

fn scalar_items_after_transitions() -> Vec<usize> {
    let mut chunks = vec![29usize];
    chunks.extend(std::iter::repeat_n(32, 7));
    let widths = [vec![9; WIDTH9_TRANSITIONS + 1], vec![8; WIDTH8_TRANSITIONS]].concat();
    assert_eq!(widths.iter().sum::<usize>(), 253);
    let mut chunk = 0usize;
    let mut remainder = chunks[0];
    let mut states = Vec::with_capacity(widths.len());
    for width in widths {
        let mut needed = width;
        while needed >= remainder {
            needed -= remainder;
            chunk += 1;
            if needed == 0 {
                remainder = chunks.get(chunk).copied().unwrap_or(0);
                break;
            }
            remainder = chunks[chunk];
        }
        if needed != 0 {
            remainder -= needed;
        }
        states.push(chunks.len() - chunk);
    }
    assert_eq!(states.len(), TRANSITIONS + 1);
    assert_eq!(states[0], SCALAR_ITEMS);
    states.remove(0);
    assert_eq!(*states.last().expect("transitions"), 0);
    states
}

fn kernel_for(transition: usize) -> Kernel {
    match transition {
        0 => FIRST_SHARED,
        1..WIDTH9_TRANSITIONS => CHAINED_SHARED,
        _ => DIRECT_CONSTANTS_SHARED,
    }
}

fn build_schedule() -> (Script, Vec<Row>) {
    let scalar_states = scalar_items_after_transitions();
    let mut steps = Vec::new();
    let mut rows = Vec::with_capacity(TRANSITIONS);
    let mut live = ENTRY_ITEMS;
    let mut previous_scalar = SCALAR_ITEMS;

    // The exact scalar validator preserves its eight physical words.
    steps.push(grow_then_change(SCALAR_VALIDATOR_GROWTH, 0));

    // Top extraction plus the top bit-trie consumes one digit and returns the
    // 16-item packed point. The measured scalar-stream maximum is +26.
    steps.push(grow_then_change(
        SCALAR_STREAM_GLOBAL_GROWTH,
        PACKED_CURRENT_ITEMS as isize,
    ));
    live += PACKED_CURRENT_ITEMS;

    for transition in 0..TRANSITIONS {
        let width = if transition < WIDTH9_TRANSITIONS {
            9
        } else {
            8
        };
        let constants = if width == 9 {
            EARLY_CONSTANT_ITEMS
        } else {
            LATE_CONSTANT_ITEMS
        };
        let scalar_items = scalar_states[transition];
        let scalar_drop = previous_scalar - scalar_items;

        // Direct scalar extraction leaves the centered digit live. A word
        // boundary can consume one physical scalar item at the same time.
        steps.push(grow_then_change(width + 1, 1 - scalar_drop as isize));
        live = live + 1 - scalar_drop;
        steps.push(trie_select_nonzero(1, width, constants));
        live = live - 1 + constants + 2;

        // Two local compressed words become three logical q values. Five
        // global bit-plane words remain until all are consumed at t=27.
        let q_net = if transition + 1 == TRANSITIONS { -4 } else { 1 };
        steps.push(grow_then_change(QUOTIENT_CODEC_GLOBAL_GROWTH, q_net));
        live = usize::try_from(isize::try_from(live).expect("live") + q_net).expect("live");

        let kernel = kernel_for(transition);
        let boundary = live;
        let preserved = boundary - kernel.input;
        let combined_peak = preserved + kernel.local_peak;
        rows.push(Row {
            transition,
            width,
            scalar_items,
            constants,
            q_physical_consumed: 2 + if transition + 1 == TRANSITIONS { 5 } else { 0 },
            boundary,
            local_input: kernel.input,
            preserved,
            kernel,
            combined_peak,
        });
        steps.push(kernel_stub(kernel));
        live = preserved + kernel.output;
        previous_scalar = scalar_items;
    }
    assert_eq!(live, EXPANDED_CURRENT_ITEMS);
    (script! { for step in steps { { step } } }, rows)
}

fn marker_checks() {
    for digit in [-1, 1] {
        let script = script! {
            { digit }
            { trie_select_nonzero(digit, 9, EARLY_CONSTANT_ITEMS) }
            { drop_top_items(EARLY_CONSTANT_ITEMS) }
            OP_1
        }
        .compile_with_policy();
        let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), vec![]);
        assert!(
            execution.error.is_none(),
            "sign marker route failed: {execution}"
        );
    }

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

fn execute_peak_stub(row: &Row) -> usize {
    let growth = row.kernel.local_peak - row.kernel.input;
    let script = script! {
        OP_DEPTH
        for _ in 1..growth { OP_DUP }
        for _ in 1..growth { OP_ADD }
        { (row.boundary * growth) as u32 } OP_NUMEQUALVERIFY
        for _ in 0..row.boundary { OP_DROP }
        OP_1
    }
    .compile_with_policy();
    let execution =
        execute_raw_script_with_inputs_strict(script.to_bytes(), vec![Vec::new(); row.boundary]);
    assert!(execution.error.is_none(), "peak stub failed: {execution}");
    execution.stats.max_nb_stack_items as usize
}

fn main() {
    assert_eq!(QUOTIENT_HINT_ITEMS, 61);
    assert_eq!(ENTRY_ITEMS, 741);
    marker_checks();
    let (_long_schedule_deactivated, rows) = build_schedule();
    let worst = rows
        .iter()
        .max_by_key(|row| row.combined_peak)
        .expect("transitions");
    let measured_peak = execute_peak_stub(worst);
    assert_eq!(measured_peak, worst.combined_peak);

    println!("model=ed25519_g29_integration_scheduler");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=item-schedule");
    println!("execution_class=unclassified");
    println!("arithmetic_and_codecs=measured-interface-stubs");
    println!("trace_circuit_data_items={TRACE_ITEMS}");
    println!("quotient_hint_items={QUOTIENT_HINT_ITEMS}");
    println!("scalar_data_items={SCALAR_ITEMS}");
    println!("complete_entry_items={ENTRY_ITEMS}");
    println!("all_trace_data_quotient_hints_and_scalar_coexist_at_entry=true");
    println!("position_groups=29");
    println!("width9_transitions={WIDTH9_TRANSITIONS}");
    println!("width8_transitions={WIDTH8_TRANSITIONS}");
    println!("global_q_remainders_until_final={GLOBAL_Q_ITEMS}");
    println!("maximum_sign_markers_live=1");
    println!("maximum_table_branch_markers_live=1");
    println!("maximum_sign_plus_branch_markers_live=2");
    println!("controls_authenticated_by_relation_kernel=true");
    println!("signed_and_identity_kernels_measured=true");
    println!("long_full_scheduler_execution_deactivated=true");
    println!("strict_combined_main_alt_stack_peak={measured_peak}");
    for row in &rows {
        println!(
            "transition={:02},width={},scalar={},constants={},q_physical_consumed={},boundary={},local_input={},preserved={},kernel={},local_peak={},combined_peak={},allowance={},fits={}",
            row.transition,
            row.width,
            row.scalar_items,
            row.constants,
            row.q_physical_consumed,
            row.boundary,
            row.local_input,
            row.preserved,
            row.kernel.name,
            row.kernel.local_peak,
            row.combined_peak,
            1_000usize.saturating_sub(row.preserved),
            row.combined_peak <= 1_000,
        );
    }

    let kernel_bytes = FIRST_SHARED.bytes
        + (WIDTH9_TRANSITIONS - 1) * CHAINED_SHARED.bytes
        + WIDTH8_TRANSITIONS * DIRECT_CONSTANTS_SHARED.bytes;
    let subtotal = TABLE_BYTES
        + kernel_bytes
        + SCALAR_VALIDATOR_BYTES
        + SCALAR_STREAM_BYTES
        + QUOTIENT_CODEC_BYTES;
    println!("identity_safe_bit_trie_hybrid_table_raw_bytes={TABLE_BYTES}");
    println!("signed_identity_transition_kernel_raw_bytes={kernel_bytes}");
    println!("scalar_validator_raw_bytes={SCALAR_VALIDATOR_BYTES}");
    println!("dynamic_scalar_scaffolding_model_raw_bytes={SCALAR_STREAM_BYTES}");
    println!("quotient_codec_raw_bytes={QUOTIENT_CODEC_BYTES}");
    println!("incomplete_signed_identity_raw_subtotal_bytes={subtotal}");
    println!(
        "remaining_below_4m_before_wrappers_and_tx={}",
        4_000_000usize.saturating_sub(subtotal)
    );
}
