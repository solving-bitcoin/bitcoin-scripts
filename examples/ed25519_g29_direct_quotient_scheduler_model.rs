//! Direct-quotient Pareto model for the mixed-relation G29 Ed25519 schedule.
//!
//! The 84 host-bounded signed 23-bit relation quotients remain one hostile
//! ScriptNum each. The size-winning mode adds no precheck: the exact integer
//! identity `H = q*p` uniquely binds q, while the first arithmetic use rejects
//! inputs above Bitcoin's four-byte numeric domain. A nonminimal four-byte
//! encoding can only alias the same integer. Explicit canonical-only and
//! canonical-plus-range variants are measured as optional hardening. Direct
//! items spend 23 more entry slots than the 61-item packed codec but remove its
//! large decoder from the 4-MB leaf.
//!
//! Arithmetic is represented by measured input/output/peak stubs.  Only the
//! small quotient validator and the independently bounded worst stack phases
//! execute here; the 28 large relation kernels deliberately do not.

use bitcoin::{consensus::encode::serialize, Witness};
use bitcoin_lab::{
    curves::ed25519::{absorb_relation_quotient, verify_streamed_relation_absorbed},
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
    },
};

const TRANSITIONS: usize = 28;
const WIDTH9_TRANSITIONS: usize = 20;
const WIDTH8_TRANSITIONS: usize = 8;
const TRACE_PER_TRANSITION: usize = 24;
const TRACE_ITEMS: usize = TRANSITIONS * TRACE_PER_TRANSITION;
const QUOTIENTS_PER_TRANSITION: usize = 3;
const QUOTIENT_HINT_ITEMS: usize = TRANSITIONS * QUOTIENTS_PER_TRANSITION;
const SCALAR_ITEMS: usize = 8;
const NON_QUOTIENT_ENTRY_ITEMS: usize = TRACE_ITEMS + SCALAR_ITEMS;
const ENTRY_ITEMS: usize = NON_QUOTIENT_ENTRY_ITEMS + QUOTIENT_HINT_ITEMS;

const PACKED_CURRENT_ITEMS: usize = 16;
const EXPANDED_CURRENT_ITEMS: usize = 102;
const EARLY_CONSTANT_ITEMS: usize = 29;
const LATE_CONSTANT_ITEMS: usize = 115;

const Q_WIDTH: usize = 23;
const Q_MIN: i32 = -(1 << (Q_WIDTH - 1));
const Q_MAX: i32 = (1 << (Q_WIDTH - 1)) - 1;

// Exact mixed-relation measurements including authenticated sign and nonzero
// controls and the positive, negative, and identity branches.
const FIRST_SHARED_BYTES: usize = 116_418;
const CHAINED_SHARED_BYTES: usize = 107_259;
const DIRECT_CONSTANTS_SHARED_BYTES: usize = 98_331;
const SHARED_PACKED_LOCAL_PEAK: usize = 256;
const SHARED_DIRECT_LOCAL_PEAK: usize = 330;

const TABLE_BYTES: usize = 923_727;
const SCALAR_VALIDATOR_RAW_BYTES: usize = 791;
const SCALAR_STREAM_RAW_BYTES: usize = 9_836;

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
    local_peak: SHARED_PACKED_LOCAL_PEAK,
    bytes: FIRST_SHARED_BYTES,
};
const CHAINED_SHARED: Kernel = Kernel {
    name: "chained_shared_mixed_signed_zero",
    input: 160,
    output: EXPANDED_CURRENT_ITEMS,
    local_peak: SHARED_PACKED_LOCAL_PEAK,
    bytes: CHAINED_SHARED_BYTES,
};
const DIRECT_CONSTANTS_SHARED: Kernel = Kernel {
    name: "chained_direct_constants_shared_mixed_signed_zero",
    input: 246,
    output: EXPANDED_CURRENT_ITEMS,
    local_peak: SHARED_DIRECT_LOCAL_PEAK,
    bytes: DIRECT_CONSTANTS_SHARED_BYTES,
};

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

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

/// Input/output: q. The byte-equality no-op binds canonical ScriptNum encoding;
/// OP_WITHIN then enforces the exact signed-23-bit interval.
fn certify_signed_q23_preserving() -> Script {
    script! {
        OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
        OP_DUP { Q_MIN } { i64::from(Q_MAX) + 1 } OP_WITHIN OP_VERIFY
    }
}

/// Input/output: q. Explicitly bind only canonical ScriptNum encoding without
/// imposing the conservative 23-bit host bound.
fn certify_canonical_scriptnum_preserving() -> Script {
    script! { OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY }
}

/// Input/output: q0 | q+ | q-. All three are restored in the same order, and
/// the callback boundary has an empty altstack.
fn certify_triplet_preserving() -> Script {
    script! {
        { certify_signed_q23_preserving() } OP_TOALTSTACK
        { certify_signed_q23_preserving() } OP_TOALTSTACK
        { certify_signed_q23_preserving() }
        OP_FROMALTSTACK OP_FROMALTSTACK
    }
}

fn certify_all_and_consume() -> Script {
    script! {
        for _ in 0..TRANSITIONS {
            { certify_triplet_preserving() }
            OP_2DROP OP_DROP
        }
    }
}

fn certify_canonical_triplet_preserving() -> Script {
    script! {
        { certify_canonical_scriptnum_preserving() } OP_TOALTSTACK
        { certify_canonical_scriptnum_preserving() } OP_TOALTSTACK
        { certify_canonical_scriptnum_preserving() }
        OP_FROMALTSTACK OP_FROMALTSTACK
    }
}

fn certify_all_canonical_and_consume() -> Script {
    script! {
        for _ in 0..TRANSITIONS {
            { certify_canonical_triplet_preserving() }
            OP_2DROP OP_DROP
        }
    }
}

fn raw_fragment_len(fragment: Script) -> usize {
    const COPIES: usize = 64;
    let repeated = script! {
        for _ in 0..COPIES { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % COPIES, 0);
    repeated.len() / COPIES
}

fn q_witness() -> Vec<Vec<u8>> {
    let mut result = Vec::with_capacity(QUOTIENT_HINT_ITEMS);
    // Reverse transition order so transition zero's q0,q+,q- tuple is on top.
    for transition in (0..TRANSITIONS).rev() {
        for relation in 0..QUOTIENTS_PER_TRANSITION {
            let value = if (transition + relation) % 2 == 0 {
                Q_MIN
            } else {
                Q_MAX
            };
            result.push(scriptnum_item(i64::from(value)));
        }
    }
    result
}

fn execute_q_rejection(item: Vec<u8>, description: &str) {
    let script = script! {
        { certify_signed_q23_preserving() }
        OP_DROP OP_1
    }
    .compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), vec![item]);
    assert!(
        execution.error.is_some(),
        "invalid direct quotient accepted: {description}"
    );
}

/// Exercise the real zero-accumulator relation close with no precheck. This is
/// a focused parse/binding probe, not a replacement for the integer proof that
/// `H = q*p` has a unique quotient.
fn no_precheck_zero_relation_probe(item: Vec<u8>, should_accept: bool, description: &str) {
    let script = script! {
        { absorb_relation_quotient() }
        { verify_streamed_relation_absorbed() }
        OP_1
    }
    .compile_with_policy();
    let mut witness = vec![item];
    witness.extend(vec![Vec::new(); 51]);
    let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), witness);
    assert_eq!(
        execution.error.is_none(),
        should_accept,
        "unexpected no-precheck relation result ({description}): {execution}"
    );
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
    states.remove(0); // top table selection is not a relation transition
    assert_eq!(states.len(), TRANSITIONS);
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

fn schedule_rows() -> Vec<Row> {
    let scalar_states = scalar_items_after_transitions();
    let mut previous_scalar = SCALAR_ITEMS;
    let mut live = ENTRY_ITEMS + PACKED_CURRENT_ITEMS;
    let mut rows = Vec::with_capacity(TRANSITIONS);
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
        live -= previous_scalar - scalar_items;
        // The table keeps one sign and one nonzero control for authentication
        // by the signed/identity-capable transition kernel.
        live += constants + 2;
        let kernel = kernel_for(transition);
        let boundary = live;
        let preserved = boundary - kernel.input;
        rows.push(Row {
            transition,
            width,
            scalar_items,
            constants,
            boundary,
            preserved,
            kernel,
            combined_peak: preserved + kernel.local_peak,
        });
        live = preserved + kernel.output;
        previous_scalar = scalar_items;
    }
    assert_eq!(live, EXPANDED_CURRENT_ITEMS);
    rows
}

/// Execute only the maximum arithmetic frontier, rather than all 28 kernels.
fn execute_peak_stub(row: &Row) -> usize {
    let growth = row.kernel.local_peak - row.kernel.input;
    let script = script! {
        // OP_DEPTH is witness-dependent, preventing the policy optimizer from
        // deleting the peak-equivalent work. Duplicates reach exactly the
        // measured local transient and are then bound to the entry depth.
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
    assert_eq!(TRACE_ITEMS, 672);
    assert_eq!(QUOTIENT_HINT_ITEMS, 84);
    assert_eq!(ENTRY_ITEMS, 764);

    let q_validator_fragment = certify_all_and_consume();
    let q_validator_raw_bytes = raw_fragment_len(q_validator_fragment.clone());
    let q_validator = q_validator_fragment.compile_with_policy();
    let canonical_validator_fragment = certify_all_canonical_and_consume();
    let canonical_validator_raw_bytes = raw_fragment_len(canonical_validator_fragment.clone());
    let canonical_validator = canonical_validator_fragment.compile_with_policy();
    let hints = q_witness();
    let executable = script! {
        { certify_all_and_consume() }
        for _ in 0..NON_QUOTIENT_ENTRY_ITEMS { OP_DROP }
        OP_1
    }
    .compile_with_policy();
    let mut complete = vec![Vec::new(); NON_QUOTIENT_ENTRY_ITEMS];
    complete.extend(hints.clone());
    let q_execution =
        execute_raw_script_with_inputs_strict(executable.to_bytes(), complete.clone());
    assert!(
        q_execution.error.is_none(),
        "direct q checks failed: {q_execution}"
    );
    let canonical_executable = script! {
        { certify_all_canonical_and_consume() }
        for _ in 0..NON_QUOTIENT_ENTRY_ITEMS { OP_DROP }
        OP_1
    }
    .compile_with_policy();
    let canonical_execution =
        execute_raw_script_with_inputs_strict(canonical_executable.to_bytes(), complete.clone());
    assert!(
        canonical_execution.error.is_none(),
        "canonical-only q checks failed: {canonical_execution}"
    );

    for accepted in [Q_MIN, -1, 0, 1, Q_MAX] {
        let check = script! {
            { certify_signed_q23_preserving() }
            { accepted } OP_NUMEQUALVERIFY OP_1
        }
        .compile_with_policy();
        let execution = execute_raw_script_with_inputs_strict(
            check.to_bytes(),
            vec![scriptnum_item(i64::from(accepted))],
        );
        assert!(execution.error.is_none(), "valid q rejected: {accepted}");
    }
    execute_q_rejection(scriptnum_item(i64::from(Q_MIN) - 1), "below minimum");
    execute_q_rejection(scriptnum_item(i64::from(Q_MAX) + 1), "above maximum");
    execute_q_rejection(vec![0x80], "negative zero");
    execute_q_rejection(vec![0x01, 0x00], "redundant positive sign byte");
    execute_q_rejection(vec![0xff; 5], "five-byte numeric payload");
    no_precheck_zero_relation_probe(Vec::new(), true, "q=0 for H=0");
    no_precheck_zero_relation_probe(scriptnum_item(1), false, "wrong q=1 for H=0");
    no_precheck_zero_relation_probe(
        scriptnum_item(i64::from(Q_MAX) + 1),
        false,
        "out-of-host-bound q for H=0",
    );
    no_precheck_zero_relation_probe(vec![0xff; 5], false, "five-byte quotient");
    no_precheck_zero_relation_probe(vec![0x80], false, "strict nonminimal zero");

    let rows = schedule_rows();
    let worst = rows
        .iter()
        .max_by_key(|row| row.combined_peak)
        .expect("transitions");
    let measured_peak = execute_peak_stub(worst);
    assert_eq!(measured_peak, worst.combined_peak);
    assert!(measured_peak <= 1_000);

    let kernel_bytes = FIRST_SHARED.bytes
        + (WIDTH9_TRANSITIONS - 1) * CHAINED_SHARED.bytes
        + WIDTH8_TRANSITIONS * DIRECT_CONSTANTS_SHARED.bytes;
    let zero_check_subtotal =
        TABLE_BYTES + kernel_bytes + SCALAR_VALIDATOR_RAW_BYTES + SCALAR_STREAM_RAW_BYTES;
    let canonical_only_subtotal = zero_check_subtotal + canonical_validator_raw_bytes;
    let full_check_subtotal = zero_check_subtotal + q_validator_raw_bytes;

    println!("model=ed25519_g29_direct_quotient_scheduler");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=item-schedule");
    println!("execution_class=unclassified");
    println!("relation_kernel_scope=mixed_signed_and_identity");
    println!("trace_circuit_data_items={TRACE_ITEMS}");
    println!("direct_quotient_hint_items={QUOTIENT_HINT_ITEMS}");
    println!("logical_quotients={QUOTIENT_HINT_ITEMS}");
    println!("scalar_data_items={SCALAR_ITEMS}");
    println!("complete_entry_items={ENTRY_ITEMS}");
    println!("all_trace_data_quotient_hints_and_scalar_coexist_at_entry=true");
    println!("direct_q_policy_bytes={}", q_validator.len());
    println!("direct_q_full_check_standalone_raw_bytes={q_validator_raw_bytes}");
    println!(
        "direct_q_optimizer_delta_bytes={}",
        q_validator_raw_bytes - q_validator.len()
    );
    println!(
        "direct_q_hint_witness_bytes={}",
        serialize(&Witness::from_slice(&hints)).len()
    );
    println!(
        "direct_q_strict_complete_entry_peak={}",
        q_execution.stats.max_nb_stack_items
    );
    println!(
        "canonical_only_q_policy_bytes={}",
        canonical_validator.len()
    );
    println!("canonical_only_q_raw_bytes={canonical_validator_raw_bytes}");
    println!(
        "canonical_only_q_strict_complete_entry_peak={}",
        canonical_execution.stats.max_nb_stack_items
    );
    println!("zero_explicit_q_checks_bytes=0");
    println!("no_precheck_real_relation_probe=pass");
    println!("maximum_logical_quotients_live=3");
    println!("callback_altstack_items=0");
    println!("maximum_sign_markers_live=1");
    println!("maximum_nonzero_branch_markers_live=1");
    println!("sign_and_nonzero_controls_authenticated_by_kernel=true");
    for row in &rows {
        println!(
            "transition={:02},width={},scalar={},constants={},q_consumed=3,trace_consumed=24,boundary={},local_input={},preserved={},kernel={},local_peak={},combined_peak={},fits={}",
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
            row.combined_peak <= 1_000,
        );
    }
    println!("strict_measured_peak_stub_items={measured_peak}");
    println!("identity_safe_bit_trie_hybrid_table_raw_bytes={TABLE_BYTES}");
    println!("transition_kernel_raw_bytes={kernel_bytes}");
    println!("scalar_validator_raw_bytes={SCALAR_VALIDATOR_RAW_BYTES}");
    println!("dynamic_scalar_scaffolding_model_raw_bytes={SCALAR_STREAM_RAW_BYTES}");
    println!("direct_q_full_validation_raw_bytes={q_validator_raw_bytes}");
    println!("direct_q_canonical_only_raw_bytes={canonical_validator_raw_bytes}");
    println!("zero_check_incomplete_raw_subtotal_bytes={zero_check_subtotal}");
    println!("canonical_only_incomplete_raw_subtotal_bytes={canonical_only_subtotal}");
    println!("full_check_incomplete_raw_subtotal_bytes={full_check_subtotal}");
    println!(
        "zero_check_remaining_below_4m_before_routing_final_and_tx={}",
        4_000_000usize.saturating_sub(zero_check_subtotal)
    );
    println!(
        "canonical_only_remaining_below_4m_before_routing_final_and_tx={}",
        4_000_000usize.saturating_sub(canonical_only_subtotal)
    );
    println!(
        "full_check_remaining_below_4m_before_routing_final_and_tx={}",
        4_000_000usize.saturating_sub(full_check_subtotal)
    );
}
