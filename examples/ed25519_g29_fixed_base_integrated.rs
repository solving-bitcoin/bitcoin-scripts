//! Integrated bytecode and stack model for G29 fixed-base Ed25519 `[s]B`.
//!
//! Byte mode measures the real G29 scalar validator/stream, authenticated
//! MSB-first table tries, routing, and all 28 real signed/identity affine
//! relation kernels. Each signed kernel first policy-compiles its smaller
//! semantic steps; since the full fragment is above 32 KiB, its final pass
//! applies no further rewrites and its size is exactly the sum of those
//! independently serialized insertion points. Stack mode replaces only the
//! large arithmetic bodies with peak-equivalent stubs, allowing the
//! complete 29-step schedule (including real scalar and table control) to
//! execute quickly under the strict 1,000-item harness.
//!
//! The arithmetic form is a composable primitive fragment: it consumes the
//! scalar, trace, and quotient witness and returns a certified expanded affine
//! point.  A useful caller still has to consume/compare that point and enforce
//! its own terminal clean-stack predicate.
//!
//! Run the fast stack check (the default) with:
//! `cargo run --locked --release --example ed25519_g29_fixed_base_integrated -- --check-stack`.
//! Run the opt-in full kernel-input routing probes with `--check-routing`.
//! Run the separate exact byte accounting with `--measure-bytes`.

#[allow(dead_code)]
#[path = "ed25519_fixed_table_actual_model.rs"]
mod table_model;

#[allow(dead_code)]
#[path = "ed25519_g31_scalar_word_validator.rs"]
mod scalar_validation;

use bitcoin_lab::{
    curves::ed25519::{
        verify_packed_signed_transition_chained_direct_constants_shared_tau_mixed,
        verify_packed_signed_transition_chained_direct_k_shared_tau_mixed,
        verify_packed_signed_transition_expanded_direct_k_shared_tau_mixed,
    },
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
    },
};
use num_bigint::BigUint;
use num_traits::{One, Zero};

const TRANSITIONS: usize = 28;
const WIDTH9_TRANSITIONS: usize = 20;
const WIDTH8_TRANSITIONS: usize = 8;
const PACKED_WORDS: usize = 8;
const PACKED_POINT_ITEMS: usize = 16;
const EXPANDED_POINT_ITEMS: usize = 102;
const TRACE_ITEMS_PER_TRANSITION: usize = 24;
const QUOTIENT_ITEMS_PER_TRANSITION: usize = 3;
const PACKET_ITEMS: usize = TRACE_ITEMS_PER_TRANSITION + QUOTIENT_ITEMS_PER_TRANSITION;
const TRACE_ITEMS: usize = TRANSITIONS * TRACE_ITEMS_PER_TRANSITION;
const QUOTIENT_HINT_ITEMS: usize = TRANSITIONS * QUOTIENT_ITEMS_PER_TRANSITION;
const PRESERVED_BELOW_SCALAR: usize = TRACE_ITEMS + QUOTIENT_HINT_ITEMS;
const COMPLETE_ENTRY_ITEMS: usize = PRESERVED_BELOW_SCALAR + PACKED_WORDS;

const NEXT_PACKED_ITEMS: usize = 16;
const TAU_PACKED_ITEMS: usize = 8;
const K_LIMBS: usize = 13;
const CONTROL_ITEMS: usize = 2;

#[derive(Clone, Copy, Debug)]
struct KernelShape {
    name: &'static str,
    current_items: usize,
    field_items: usize,
    input_items: usize,
    local_peak: usize,
}

const FIRST_PACKED: KernelShape = KernelShape {
    name: "first_packed_signed_shared_mixed",
    current_items: PACKED_POINT_ITEMS,
    field_items: PACKED_WORDS,
    input_items: 74,
    local_peak: 256,
};

const CHAINED_PACKED: KernelShape = KernelShape {
    name: "chained_packed_signed_shared_mixed",
    current_items: EXPANDED_POINT_ITEMS,
    field_items: PACKED_WORDS,
    input_items: 160,
    local_peak: 256,
};

const CHAINED_DIRECT: KernelShape = KernelShape {
    name: "chained_direct_signed_shared_mixed",
    current_items: EXPANDED_POINT_ITEMS,
    field_items: 51,
    input_items: 246,
    local_peak: 330,
};

#[derive(Clone, Debug)]
struct StackRow {
    transition: usize,
    width: usize,
    scalar_items: usize,
    preserved_items: usize,
    kernel: KernelShape,
    combined_peak: usize,
}

fn widths_low_to_high() -> Vec<usize> {
    let mut widths = vec![8; WIDTH8_TRANSITIONS];
    widths.extend(std::iter::repeat_n(9, WIDTH9_TRANSITIONS));
    widths.push(9);
    assert_eq!(widths.iter().sum::<usize>(), 253);
    widths
}

/// Scalar item population after each of the 28 lower-window callbacks.
/// One numeric remainder or cross-word partial replaces the physical word it
/// came from, so this count is independent of the scalar value.
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
    assert_eq!(states.remove(0), PACKED_WORDS);
    assert_eq!(*states.last().expect("lower windows"), 0);
    states
}

fn shape_for_transition(transition: usize) -> KernelShape {
    match transition {
        0 => FIRST_PACKED,
        1..WIDTH9_TRANSITIONS => CHAINED_PACKED,
        _ => CHAINED_DIRECT,
    }
}

fn drop_top_items(items: usize) -> Script {
    script! {
        for _ in 0..items / 2 { OP_2DROP }
        if items % 2 != 0 { OP_DROP }
    }
}

/// Move a contiguous block across `items_above` while retaining its order.
fn move_block_to_top(block_items: usize, items_above: usize) -> Script {
    if items_above == 0 || block_items == 0 {
        return Script::new("no-op block move");
    }
    let depth = block_items + items_above - 1;
    script! {
        for _ in 0..block_items { { depth as u32 } OP_ROLL }
    }
}

fn swap_equal_blocks(items: usize) -> Script {
    script! {
        for _ in 0..items { { (2 * items - 1) as u32 } OP_ROLL }
    }
}

/// The table stores positive-point `Cp | Cm | K | z`.  The affine wrapper
/// consumes `selected Cm | selected Cp | K | ... | nonzero | negative`:
/// positive digits therefore swap the two field blocks, while negative digits
/// keep them in table order.  The authenticated `z` marker is preserved.
fn orient_table_constants(field_items: usize) -> Script {
    script! {
        OP_SWAP OP_TOALTSTACK
        OP_NOTIF
            for _ in 0..K_LIMBS { OP_TOALTSTACK }
            { swap_equal_blocks(field_items) }
            for _ in 0..K_LIMBS { OP_FROMALTSTACK }
        OP_ENDIF
        OP_FROMALTSTACK
    }
}

/// Input is a biased lower-window code; output is `magnitude | negative`.
fn decode_lower_code(width: usize) -> Script {
    assert!(width == 8 || width == 9);
    script! {
        { 1u32 << (width - 1) } OP_SUB
        OP_DUP 0 OP_LESSTHAN
        OP_IF OP_NEGATE 1 OP_ELSE 0 OP_ENDIF
    }
}

fn park_current(items: usize) -> Script {
    script! { for _ in 0..items { OP_TOALTSTACK } }
}

fn restore_current(items: usize) -> Script {
    script! { for _ in 0..items { OP_FROMALTSTACK } }
}

fn bits_from_altstack_to_number(width: usize) -> Script {
    script! {
        OP_FROMALTSTACK
        for _ in 1..width {
            OP_DUP OP_ADD OP_FROMALTSTACK OP_ADD
        }
    }
}

/// Split a nonnegative at-most-31-bit number into `high | low`.
fn split_high(total_bits: usize, high_bits: usize) -> Script {
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
        OP_IF { i32::MAX } OP_ADD OP_1ADD 1 OP_ELSE 0 OP_ENDIF
    }
}

fn finish_partial(total_bits: usize, partial_bits: usize, take: usize) -> Script {
    assert!(partial_bits > 0 && take > 0 && take < total_bits);
    script! {
        OP_SWAP
        { split_high(total_bits, take) }
        OP_TOALTSTACK
        OP_SWAP
        for _ in 0..take { OP_DUP OP_ADD }
        OP_ADD
        OP_FROMALTSTACK OP_SWAP
    }
}

/// Stream the certified eight-word scalar into the 29 callbacks.  At every
/// lower callback the current point is parked on altstack; the callback must
/// restore and consume it, and must return the next 102-item current point
/// with an empty altstack.
fn direct_scalar_stream(top_callback: Script, lower_callbacks: &[Script]) -> Script {
    assert_eq!(lower_callbacks.len(), TRANSITIONS);
    let target_widths = widths_low_to_high().into_iter().rev().collect::<Vec<_>>();
    let mut steps = Vec::new();
    let mut target = 0usize;

    let first_width = target_widths[target];
    steps.push(script! {
        { split_high(29, first_width) }
        OP_SWAP
        { top_callback }
    });
    target += 1;
    let mut remainder_bits = 29 - first_width;

    while remainder_bits >= target_widths[target] {
        let width = target_widths[target];
        let current_items = if target == 1 {
            PACKED_POINT_ITEMS
        } else {
            EXPANDED_POINT_ITEMS
        };
        steps.push(park_current(current_items));
        if remainder_bits != width {
            steps.push(script! { { split_high(remainder_bits, width) } OP_SWAP });
            remainder_bits -= width;
        } else {
            remainder_bits = 0;
        }
        steps.push(lower_callbacks[target - 1].clone());
        target += 1;
    }
    let mut partial_bits = remainder_bits;

    for _word in (0..PACKED_WORDS - 1).rev() {
        steps.push(park_current(EXPANDED_POINT_ITEMS));
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

        let width = target_widths[target];
        let needed = width - partial_bits;
        if needed != 0 {
            steps.push(finish_partial(31, partial_bits, needed));
        }
        steps.push(lower_callbacks[target - 1].clone());
        target += 1;
        remainder_bits = 31 - needed;

        while target < target_widths.len() && remainder_bits >= target_widths[target] {
            let width = target_widths[target];
            steps.push(park_current(EXPANDED_POINT_ITEMS));
            if remainder_bits != width {
                steps.push(script! { { split_high(remainder_bits, width) } OP_SWAP });
                remainder_bits -= width;
            } else {
                remainder_bits = 0;
            }
            steps.push(lower_callbacks[target - 1].clone());
            target += 1;
        }
        partial_bits = remainder_bits;
    }

    assert_eq!(target, target_widths.len());
    assert_eq!(partial_bits, 0);
    script! { for step in steps { { step } } }
}

fn kernel_stub(shape: KernelShape) -> Script {
    assert!(shape.local_peak >= shape.input_items);
    let growth = shape.local_peak - shape.input_items;
    script! {
        // The real signed wrapper requires `nonzero | negative` at the top.
        // Preserve both booleans while enforcing negative => nonzero. A
        // swapped positive-leaf pair (`0 | 1`) fails here.
        OP_DUP OP_IF OP_OVER OP_VERIFY OP_ENDIF
        for _ in 0..growth { 0 }
        { drop_top_items(growth + shape.input_items) }
        for _ in 0..EXPANDED_POINT_ITEMS { 0 }
    }
}

fn probe_values(first: i64, items: usize) -> Vec<i64> {
    (0..items)
        .map(|offset| first + i64::try_from(offset).expect("probe offset fits i64"))
        .collect()
}

fn push_probe_values(values: &[i64]) -> Script {
    let pushes = values
        .iter()
        .copied()
        .map(|value| script! { { value } })
        .collect::<Vec<_>>();
    script! { for push in pushes { { push } } }
}

fn verify_probe_values(values_bottom_to_top: &[i64]) -> Script {
    let checks = values_bottom_to_top
        .iter()
        .rev()
        .copied()
        .map(|value| script! { { value } OP_NUMEQUALVERIFY })
        .collect::<Vec<_>>();
    script! { for check in checks { { check } } }
}

/// Execute one synthetic callback whose values are unique by block.  The
/// probe kernel checks all 74/160/246 routed inputs rather than merely their
/// population, so a q/tau/next/current/constants block swap cannot hide behind
/// the peak-equivalent arithmetic stub.
fn run_transition_routing_probe(transition: usize, negative: bool) {
    let shape = shape_for_transition(transition);
    let field_items = shape.field_items;
    let current_field_items = shape.current_items / 2;
    let scalar_items = 3;

    let x_next = probe_values(1_000, PACKED_WORDS);
    let y_next = probe_values(1_100, PACKED_WORDS);
    let cp_from_table = probe_values(1_200, field_items);
    let cm_from_table = probe_values(1_300, field_items);
    let tau = probe_values(1_400, PACKED_WORDS);
    let k = probe_values(1_500, K_LIMBS);
    let q = probe_values(1_600, QUOTIENT_ITEMS_PER_TRANSITION);
    let y_current = probe_values(1_700, current_field_items);
    let x_current = probe_values(1_800, current_field_items);
    let scalar = probe_values(1_900, scalar_items);
    let output = probe_values(2_000, EXPANDED_POINT_ITEMS);

    // Table leaves are stored Cp | Cm | K | nonzero.  The callback must
    // present selected Cm | selected Cp to the affine wrapper, swapping the
    // two blocks only for a positive digit.
    let table = script! {
        1 OP_NUMEQUALVERIFY
        { push_probe_values(&cp_from_table) }
        { push_probe_values(&cm_from_table) }
        { push_probe_values(&k) }
        1
    };

    let (selected_cm, selected_cp) = if negative {
        (&cp_from_table, &cm_from_table)
    } else {
        (&cm_from_table, &cp_from_table)
    };
    let mut expected_kernel_input = Vec::with_capacity(shape.input_items);
    expected_kernel_input.extend_from_slice(&x_next);
    expected_kernel_input.extend_from_slice(&y_next);
    expected_kernel_input.extend_from_slice(selected_cm);
    expected_kernel_input.extend_from_slice(selected_cp);
    expected_kernel_input.extend_from_slice(&tau);
    expected_kernel_input.extend_from_slice(&k);
    expected_kernel_input.extend_from_slice(&q);
    expected_kernel_input.extend_from_slice(&y_current);
    expected_kernel_input.extend_from_slice(&x_current);
    expected_kernel_input.push(1); // authenticated nonzero
    expected_kernel_input.push(i64::from(negative));
    assert_eq!(expected_kernel_input.len(), shape.input_items);

    let kernel = script! {
        { verify_probe_values(&expected_kernel_input) }
        { push_probe_values(&output) }
    };
    let width = if transition < WIDTH9_TRANSITIONS {
        9
    } else {
        8
    };
    let encoded_digit = (1i64 << (width - 1)) + if negative { -1 } else { 1 };
    let current = [y_current, x_current].concat();
    let executable = script! {
        { push_probe_values(&current) }
        { park_current(shape.current_items) }
        { push_probe_values(&q) }
        { push_probe_values(&tau) }
        { push_probe_values(&x_next) }
        { push_probe_values(&y_next) }
        { push_probe_values(&scalar) }
        { encoded_digit }
        { transition_callback(transition, scalar_items, table, kernel) }
        { verify_probe_values(&output) }
        { verify_probe_values(&scalar) }
        OP_1
    }
    .compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(executable.to_bytes(), vec![]);
    assert!(
        execution.error.is_none(),
        "{} routing probe failed: {execution}",
        shape.name
    );
    assert_eq!(execution.final_stack.len(), 1, "{} probe", shape.name);
}

fn run_transition_routing_probes() {
    run_transition_routing_probe(0, false);
    run_transition_routing_probe(1, true);
    run_transition_routing_probe(WIDTH9_TRANSITIONS, false);
    println!("model=ed25519_g29_fixed_base_routing_probe");
    println!("mode=check-routing");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=item-order");
    println!("execution_class=unclassified");
    println!("verified_kernel_input_items=74,160,246");
    println!("verified_sign_cases=positive,negative");
}

#[derive(Clone, Copy)]
enum CallbackBody {
    Empty,
    Stub,
}

/// Compose one lower-table selection with its exact packet/current routing.
///
/// Before (main): `later_packets | q,tau,next | scalar | encoded_digit`.
/// Before (alt): `current`.  The packet order is deliberately q first and
/// next-point last, allowing each block to be lifted exactly when the affine
/// wrapper needs it.  After: `later_packets | scalar | next_current` with an
/// empty altstack.
fn transition_callback(
    transition: usize,
    scalar_items: usize,
    table: Script,
    kernel: Script,
) -> Script {
    let shape = shape_for_transition(transition);
    let width = if transition < WIDTH9_TRANSITIONS {
        9
    } else {
        8
    };
    let fields = 2 * shape.field_items;

    // Lift x'/y' while the encoded scalar digit is still above the packet,
    // then put that digit back on top for sign/magnitude decoding.
    let lift_next = move_block_to_top(NEXT_PACKED_ITEMS, scalar_items + 1);
    let lift_tau = move_block_to_top(TAU_PACKED_ITEMS, scalar_items + NEXT_PACKED_ITEMS + fields);
    let tail_after_tau = K_LIMBS + CONTROL_ITEMS;
    let lift_q = move_block_to_top(
        QUOTIENT_ITEMS_PER_TRANSITION,
        scalar_items + NEXT_PACKED_ITEMS + fields + TAU_PACKED_ITEMS + tail_after_tau,
    );

    script! {
        { lift_next }
        { NEXT_PACKED_ITEMS as u32 } OP_ROLL
        { decode_lower_code(width) }

        // Keep two sign copies above the parked current: one orients C-/C+,
        // while the other is passed to the signed affine kernel.
        OP_DUP OP_TOALTSTACK OP_TOALTSTACK
        { table }
        OP_FROMALTSTACK
        { orient_table_constants(shape.field_items) }
        OP_FROMALTSTACK

        // K and the temporary z/negative controls must follow tau. Park that
        // 15-item tail, lift tau from the packet, and restore the tail.
        for _ in 0..tail_after_tau { OP_TOALTSTACK }
        { lift_tau }
        for _ in 0..tail_after_tau { OP_FROMALTSTACK }

        { lift_q }
        { restore_current(shape.current_items) }
        // Signed wrappers immediately park these topmost controls. Move the
        // authenticated `z | negative` pair past q and the restored current.
        { move_block_to_top(CONTROL_ITEMS, QUOTIENT_ITEMS_PER_TRANSITION + shape.current_items) }
        { kernel }
    }
}

fn raw_fragment_len(fragment: Script) -> usize {
    const COPIES: usize = 48;
    let repeated = script! {
        for _ in 0..COPIES { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % COPIES, 0);
    repeated.len() / COPIES
}

fn scalar_words(scalar: &BigUint) -> Vec<Vec<u8>> {
    let payload =
        scalar_validation::centered_payload_for_scalar_with_widths(scalar, &widths_low_to_high());
    scalar_validation::words_from_payload(&payload)
        .into_iter()
        .map(|word| scalar_validation::scriptnum_item(i64::from(word as i32)))
        .collect()
}

fn scalar_stream_probe() -> Script {
    let top = script! {
        0 OP_NUMEQUALVERIFY
        for _ in 0..PACKED_POINT_ITEMS { 0 }
    };
    let callbacks = (0..TRANSITIONS)
        .map(|transition| {
            let shape = shape_for_transition(transition);
            let width = if transition < WIDTH9_TRANSITIONS {
                9
            } else {
                8
            };
            script! {
                { restore_current(shape.current_items) }
                { shape.current_items as u32 } OP_ROLL
                { 1u32 << (width - 1) } OP_NUMEQUALVERIFY
                if transition == 0 {
                    { drop_top_items(PACKED_POINT_ITEMS) }
                    for _ in 0..EXPANDED_POINT_ITEMS { 0 }
                }
            }
        })
        .collect::<Vec<_>>();
    direct_scalar_stream(top, &callbacks)
}

fn build_callbacks(
    tables_low_to_high: &[Script],
    body: CallbackBody,
) -> (Script, Vec<Script>, Vec<StackRow>) {
    assert_eq!(tables_low_to_high.len(), TRANSITIONS + 1);
    let scalar_states = scalar_items_after_transitions();
    let top = tables_low_to_high[TRANSITIONS].clone();
    let mut callbacks = Vec::with_capacity(TRANSITIONS);
    let mut rows = Vec::with_capacity(TRANSITIONS);

    for transition in 0..TRANSITIONS {
        let shape = shape_for_transition(transition);
        let scalar_items = scalar_states[transition];
        let preserved_items = (TRANSITIONS - transition - 1) * PACKET_ITEMS + scalar_items;
        let combined_peak = preserved_items + shape.local_peak;
        let kernel = match body {
            CallbackBody::Empty => Script::new("byte-attribution boundary"),
            CallbackBody::Stub => kernel_stub(shape),
        };
        let table_position = TRANSITIONS - transition - 1;
        callbacks.push(transition_callback(
            transition,
            scalar_items,
            tables_low_to_high[table_position].clone(),
            kernel,
        ));
        rows.push(StackRow {
            transition,
            width: if transition < WIDTH9_TRANSITIONS {
                9
            } else {
                8
            },
            scalar_items,
            preserved_items,
            kernel: shape,
            combined_peak,
        });
    }
    (top, callbacks, rows)
}

fn run_scalar_probe() {
    let scalar_probe = script! {
        for word in scalar_words(&BigUint::zero()) { { word } }
        { scalar_stream_probe() }
        { drop_top_items(EXPANDED_POINT_ITEMS) }
        OP_1
    }
    .compile_with_policy();
    let scalar_probe_execution =
        execute_raw_script_with_inputs_strict(scalar_probe.to_bytes(), vec![]);
    assert!(
        scalar_probe_execution.error.is_none(),
        "zero scalar stream probe failed: {scalar_probe_execution}"
    );
}

fn scalar_validator() -> Script {
    scalar_validation::validate_scalar_words_for_widths_preserving(
        &widths_low_to_high(),
        PRESERVED_BELOW_SCALAR,
    )
}

fn run_check_stack(tables: &[Script]) {
    run_scalar_probe();
    let (stub_top, stub_callbacks, rows) = build_callbacks(tables, CallbackBody::Stub);
    let executable = script! {
        { scalar_validator() }
        { direct_scalar_stream(stub_top, &stub_callbacks) }
        { drop_top_items(EXPANDED_POINT_ITEMS) }
        OP_1
    }
    .compile_with_policy();
    let run_stub = |scalar: &BigUint, label: &str| {
        let mut witness = vec![Vec::new(); PRESERVED_BELOW_SCALAR];
        witness.extend(scalar_words(scalar));
        assert_eq!(witness.len(), COMPLETE_ENTRY_ITEMS);
        let execution = execute_raw_script_with_inputs_strict(executable.to_bytes(), witness);
        assert!(
            execution.error.is_none(),
            "{label} schedule failed: {execution}"
        );
        assert_eq!(execution.final_stack.len(), 1, "{label}");
        execution.stats.max_nb_stack_items
    };
    let zero_peak = run_stub(&BigUint::zero(), "zero scalar");
    let one_peak = run_stub(&BigUint::one(), "one scalar");
    let high_peak = run_stub(
        &(scalar_validation::scalar_order() - BigUint::one()),
        "l-1 scalar",
    );
    let strict_peak = zero_peak.max(one_peak).max(high_peak);

    println!("model=ed25519_g29_fixed_base_integrated_stack");
    println!("mode=check-stack");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=item-schedule");
    println!("execution_class=unclassified");
    println!("arithmetic=measured-interface-stubs");
    println!("scalar_validator_table_trie_and_routing=real");
    println!("full_kernel_input_order_probes=separate-check-routing-mode");
    println!("trace_data_items={TRACE_ITEMS}");
    println!("quotient_hint_items_per_transition={QUOTIENT_ITEMS_PER_TRANSITION}");
    println!("quotient_hint_items_total={QUOTIENT_HINT_ITEMS}");
    println!("scalar_data_items={PACKED_WORDS}");
    println!("complete_entry_items={COMPLETE_ENTRY_ITEMS}");
    println!("all_trace_data_quotient_hints_and_scalar_coexist_at_entry=true");
    println!("stubbed_schedule_raw_script_bytes={}", executable.len());
    println!("stubbed_zero_scalar_strict_peak={zero_peak}");
    println!("stubbed_one_scalar_strict_peak={one_peak}");
    println!("stubbed_l_minus_1_strict_peak={high_peak}");
    println!("strict_combined_main_alt_stack_peak={strict_peak}");
    for row in rows {
        println!(
            "transition={:02},width={},scalar_items={},preserved_items={},kernel={},local_input={},local_peak={},combined_peak={},fits={}",
            row.transition,
            row.width,
            row.scalar_items,
            row.preserved_items,
            row.kernel.name,
            row.kernel.input_items,
            row.kernel.local_peak,
            row.combined_peak,
            row.combined_peak <= 1_000,
        );
    }
}

fn run_measure_bytes(tables: &[Script]) {
    let table_script = script! { for table in tables { { table.clone() } } }.compile_with_policy();
    assert!(table_script.len() > MAX_OPTIMIZER_INPUT_BYTES);
    let validator_raw_bytes = raw_fragment_len(scalar_validator());

    // Above the 32-KiB cutoff the central policy applies no optimizer passes,
    // so serialization is exactly additive. Measure scalar extraction and
    // packet/sign routing with empty table/kernel insertion points; fill them
    // with independently measured raw table and kernel bytes below.
    let empty_tables = (0..=TRANSITIONS)
        .map(|_| Script::new("byte-attribution boundary"))
        .collect::<Vec<_>>();
    let (empty_top, routing_callbacks, _) = build_callbacks(&empty_tables, CallbackBody::Empty);
    let scalar_and_routing_raw_bytes =
        raw_fragment_len(direct_scalar_stream(empty_top, &routing_callbacks));

    let first_kernel = verify_packed_signed_transition_expanded_direct_k_shared_tau_mixed(0)
        .compile_with_policy()
        .len();
    let chained_packed_kernel =
        verify_packed_signed_transition_chained_direct_k_shared_tau_mixed(0)
            .compile_with_policy()
            .len();
    let chained_direct_kernel =
        verify_packed_signed_transition_chained_direct_constants_shared_tau_mixed(0)
            .compile_with_policy()
            .len();
    assert_eq!(first_kernel, 116_418);
    assert_eq!(chained_packed_kernel, 107_259);
    assert_eq!(chained_direct_kernel, 98_331);
    let kernel_bytes = first_kernel
        + (WIDTH9_TRANSITIONS - 1) * chained_packed_kernel
        + WIDTH8_TRANSITIONS * chained_direct_kernel;
    let actual_fragment_bytes =
        validator_raw_bytes + scalar_and_routing_raw_bytes + table_script.len() + kernel_bytes;
    assert!(actual_fragment_bytes > MAX_OPTIMIZER_INPUT_BYTES);

    // Conservative upper bound for an honest, minimally encoded witness:
    // packed trace/scalar words need at most five payload bytes and every
    // signed-23-bit quotient needs at most three. Add CompactSize prefixes,
    // the leaf itself, and a depth-zero 33-byte control block.
    let witness_stack_items = COMPLETE_ENTRY_ITEMS + 2;
    let witness_count_prefix_bytes = 3; // 766 > 252
    let argument_bytes =
        TRACE_ITEMS * (1 + 5) + QUOTIENT_HINT_ITEMS * (1 + 3) + PACKED_WORDS * (1 + 5);
    let leaf_bytes = 5 + actual_fragment_bytes;
    let control_block_bytes = 1 + 33;
    let conservative_honest_witness_bytes =
        witness_count_prefix_bytes + argument_bytes + leaf_bytes + control_block_bytes;
    // Version, counts, one empty-scriptSig input, one P2TR output, locktime.
    let stripped_transaction_bytes = 94;
    let segwit_marker_and_flag_bytes = 2;
    let conservative_transaction_weight = 4 * stripped_transaction_bytes
        + segwit_marker_and_flag_bytes
        + conservative_honest_witness_bytes;

    println!("model=ed25519_g29_fixed_base_integrated");
    println!("mode=measure-bytes");
    println!("evidence=locally-reproduced");
    println!("execution_class=unclassified");
    println!(
        "measurement_method=exact-additive-serialization-with-policy-precompiled-kernel-steps"
    );
    println!("boundary=fragment-only: scalar validation, scalar streaming, authenticated tables, sign/identity routing, trace and direct quotient consumption, and 28 affine kernels included; terminal point consumer and witness serialization excluded");
    println!("compilation=whole-fragment-none-with-policy-precompiled-kernel-steps");
    println!("position_groups=29");
    println!("transitions={TRANSITIONS}");
    println!("width9_transitions={WIDTH9_TRANSITIONS}");
    println!("width8_transitions={WIDTH8_TRANSITIONS}");
    println!("trace_data_items={TRACE_ITEMS}");
    println!("quotient_hint_items_per_transition={QUOTIENT_ITEMS_PER_TRANSITION}");
    println!("quotient_hint_items_total={QUOTIENT_HINT_ITEMS}");
    println!("quotient_honest_signed_slot_bits=23");
    println!("quotient_honest_payload_bytes_at_most=3");
    println!("scalar_data_items={PACKED_WORDS}");
    println!("complete_entry_items={COMPLETE_ENTRY_ITEMS}");
    println!("all_trace_data_quotient_hints_and_scalar_coexist_at_entry=true");
    println!("output_items={EXPANDED_POINT_ITEMS}");
    println!("table_raw_script_bytes={}", table_script.len());
    println!("first_signed_kernel_raw_script_bytes={first_kernel}");
    println!("chained_packed_signed_kernel_raw_script_bytes={chained_packed_kernel}");
    println!("chained_direct_signed_kernel_raw_script_bytes={chained_direct_kernel}");
    println!("all_transition_kernel_raw_script_bytes={kernel_bytes}");
    println!("scalar_validator_raw_script_bytes={validator_raw_bytes}");
    println!("scalar_stream_and_routing_raw_script_bytes={scalar_and_routing_raw_bytes}");
    println!("cross_component_optimizer_delta_bytes=0");
    println!(
        "actual_integrated_fragment_raw_script_bytes={}",
        actual_fragment_bytes
    );
    println!(
        "remaining_below_4_000_000_script_bytes={}",
        4_000_000usize.saturating_sub(actual_fragment_bytes)
    );
    println!("projected_taproot_witness_items_before_terminal_consumer={witness_stack_items}");
    println!("conservative_honest_argument_serialization_bytes={argument_bytes}");
    println!("projected_honest_witness_bytes_before_terminal_consumer={conservative_honest_witness_bytes}");
    println!("minimal_one_input_one_p2tr_output_stripped_bytes={stripped_transaction_bytes}");
    println!(
        "projected_transaction_weight_before_terminal_consumer={conservative_transaction_weight}"
    );
    println!(
        "remaining_below_4_000_000_block_weight={}",
        4_000_000usize.saturating_sub(conservative_transaction_weight)
    );
    println!("default_policy_400_000_weight_compatible=false");
    println!("block_header_coinbase_and_terminal_consumer_not_included=true");
    println!("compressed_point_encoding_and_eddsa_equation_not_included=true");
    println!("full_arithmetic_schedule_executed=false");
    println!("full_arithmetic_execution_skipped=explicit_long-test-policy");
}

fn main() {
    assert_eq!(TRACE_ITEMS, 672);
    assert_eq!(QUOTIENT_HINT_ITEMS, 84);
    assert_eq!(PRESERVED_BELOW_SCALAR, 756);
    assert_eq!(COMPLETE_ENTRY_ITEMS, 764);

    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "--check-stack".to_owned());
    match mode.as_str() {
        "--check-stack" => {
            let tables = table_model::g29_hybrid_bit_table_fragments();
            run_check_stack(&tables);
        }
        "--check-routing" => run_transition_routing_probes(),
        "--measure-bytes" => {
            let tables = table_model::g29_hybrid_bit_table_fragments();
            run_measure_bytes(&tables);
        }
        _ => panic!("use --check-stack, --check-routing, or --measure-bytes"),
    }
}
