//! Focused signed-leaf and identity-leaf glue model for the Ed25519 G31
//! fixed-base schedule.
//!
//! This example deliberately excludes table traversal and the affine kernel.
//! It measures only the glue left between a lower-window scalar code and the
//! selected affine constants:
//!
//! 1. decode the biased centered code to `(magnitude, negative)`;
//! 2. reuse that one sign bit to negate the 17-limb magnitude `tau`;
//! 3. swap the selected `Cp`/`Cm` blocks for a negative digit while leaving
//!    the 13 `K` limbs unchanged; and
//! 4. synthesize the authenticated identity leaf (`Cp=Cm=K=1, z=0`).
//!
//! Both live constant shapes are covered: packed `8+8+13+z` and direct
//! `51+51+13+z`.  Every fragment has zero auxiliary witness hint items.
//! Run with:
//! `cargo run --locked --release --example ed25519_signed_identity_glue_benchmark`.

use bitcoin::{consensus::encode::serialize, Witness};
use bitcoin_lab::{
    fields::ed25519::{u5_balanced_table, u5_packed},
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
    },
};
use num_bigint::BigUint;
use num_traits::One;

const TAU_LIMBS: usize = 17;
const K_LIMBS: usize = 13;
const PACKED_FIELD_ITEMS: usize = 8;
const DIRECT_FIELD_ITEMS: usize = 51;
const HINT_ITEMS: usize = 0;

// The asymmetric R0 layout groups 51 centered radix-32 digits as twelve
// four-digit limbs followed by one three-digit limb.
const K_LIMB_DIGITS: [usize; K_LIMBS] = [4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 3];

#[derive(Clone, Copy, Debug)]
enum Shape {
    Packed,
    Direct,
}

impl Shape {
    fn name(self) -> &'static str {
        match self {
            Self::Packed => "packed_8_8_13",
            Self::Direct => "direct_51_51_13",
        }
    }

    fn field_items(self) -> usize {
        match self {
            Self::Packed => PACKED_FIELD_ITEMS,
            Self::Direct => DIRECT_FIELD_ITEMS,
        }
    }

    fn selected_items(self) -> usize {
        2 * self.field_items() + K_LIMBS + 1 // Cp | Cm | K | z
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SelectedValues {
    cp: Vec<i64>,
    cm: Vec<i64>,
    k: Vec<i64>,
    z: i64,
}

impl SelectedValues {
    fn assert_shape(&self, shape: Shape) {
        assert_eq!(self.cp.len(), shape.field_items());
        assert_eq!(self.cm.len(), shape.field_items());
        assert_eq!(self.k.len(), K_LIMBS);
        assert!(self.z == 0 || self.z == 1);
    }

    fn routed(&self, negative: bool) -> Self {
        if negative {
            Self {
                cp: self.cm.clone(),
                cm: self.cp.clone(),
                k: self.k.clone(),
                z: self.z,
            }
        } else {
            self.clone()
        }
    }

    fn stack_values(&self) -> Vec<i64> {
        self.cp
            .iter()
            .chain(&self.cm)
            .chain(&self.k)
            .copied()
            .chain(std::iter::once(self.z))
            .collect()
    }
}

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn witness(values: impl IntoIterator<Item = i64>) -> Vec<Vec<u8>> {
    values.into_iter().map(scriptnum_item).collect()
}

fn pushed_values(values: &[i64]) -> Script {
    script! {
        for value in values { { *value } }
    }
}

/// Before: `encoded`; after: `magnitude | negative`.
///
/// Lower window codes are biased by half the radix.  Zero therefore decodes
/// deterministically to `(0, 0)`, which is important because OP_IF accepts
/// only the empty vector or `1` under minimal-if tapscript execution.
fn decode_lower_code(width: usize) -> Script {
    assert!(width == 8 || width == 9);
    let bias = 1u32 << (width - 1);
    script! {
        { bias } OP_SUB
        OP_DUP 0 OP_LESSTHAN
        OP_IF
            OP_NEGATE 1
        OP_ELSE
            0
        OP_ENDIF
    }
}

/// Before: `tau[17] | negative`; after: `signed_tau[17]`.
///
/// Pulling the bottom limb to the top 17 times preserves limb order.  The
/// branch is skipped for positive and identity digits.
fn conditionally_negate_tau() -> Script {
    script! {
        OP_IF
            for _ in 0..TAU_LIMBS {
                { (TAU_LIMBS - 1) as u32 } OP_ROLL OP_NEGATE
            }
        OP_ENDIF
    }
}

/// Swap two adjacent equal-length stack blocks while preserving the order
/// within each block.
fn swap_equal_blocks(items: usize) -> Script {
    script! {
        for _ in 0..items {
            { (2 * items - 1) as u32 } OP_ROLL
        }
    }
}

/// Before: `Cp[n] | Cm[n] | K[13] | z | negative`;
/// after: `(Cp,Cm if positive; Cm,Cp if negative) | K[13] | z`.
///
/// `z` is parked unconditionally.  `K` is parked only inside the negative
/// branch, allowing the two field blocks to become adjacent.  Sign is a
/// magnitude convention: K is invariant; the separate tau fragment negates
/// tau.  Total main-plus-alt population never increases except for the
/// transient numeric depth used by OP_ROLL.
fn route_selected_constants(shape: Shape) -> Script {
    let field_items = shape.field_items();
    script! {
        OP_SWAP OP_TOALTSTACK // park z; expose negative
        OP_IF
            for _ in 0..K_LIMBS { OP_TOALTSTACK }
            { swap_equal_blocks(field_items) }
            for _ in 0..K_LIMBS { OP_FROMALTSTACK }
        OP_ENDIF
        OP_FROMALTSTACK // restore z
    }
}

fn packed_identity_field() -> Vec<i64> {
    u5_packed::packed_words_from_digits(&u5_balanced_table::field_digits(&BigUint::one()))
        .iter()
        .rev()
        .map(|word| i64::from(*word as i32))
        .collect()
}

fn direct_identity_field() -> Vec<i64> {
    u5_balanced_table::field_digits(&BigUint::one())
        .iter()
        .map(|digit| i64::from(*digit))
        .collect()
}

fn grouped_k_from_stored_digits(stored_digits: &[i64]) -> Vec<i64> {
    assert_eq!(stored_digits.len(), DIRECT_FIELD_ITEMS);
    let mut cursor = 0usize;
    K_LIMB_DIGITS
        .iter()
        .map(|digit_count| {
            let start = cursor;
            cursor += digit_count;
            stored_digits[start..cursor]
                .iter()
                .rev()
                .fold(0i64, |limb, digit| limb * 32 + (*digit - 16))
        })
        .collect()
}

fn identity_values(shape: Shape) -> SelectedValues {
    let direct_one = direct_identity_field();
    let field_one = match shape {
        Shape::Packed => packed_identity_field(),
        Shape::Direct => direct_one.clone(),
    };
    let result = SelectedValues {
        cp: field_one.clone(),
        cm: field_one,
        k: grouped_k_from_stored_digits(&direct_one),
        z: 0,
    };
    result.assert_shape(shape);
    // Cp=Cm=K=1 in their exact live representations.
    assert_eq!(result.k[0], 1);
    assert!(result.k[1..].iter().all(|limb| *limb == 0));
    result
}

fn nonzero_probe_values(shape: Shape) -> SelectedValues {
    let n = shape.field_items();
    let result = SelectedValues {
        cp: (0..n).map(|index| 101 + index as i64).collect(),
        cm: (0..n).map(|index| 501 + index as i64).collect(),
        k: (0..K_LIMBS).map(|index| 1_001 + index as i64).collect(),
        z: 1,
    };
    result.assert_shape(shape);
    result
}

fn push_selected(values: &SelectedValues) -> Script {
    let stack = values.stack_values();
    pushed_values(&stack)
}

/// Executable composition around a modeled selector leaf.
///
/// Before: `tau[17] | encoded`; after:
/// `signed_tau[17] | routed Cp | routed Cm | K[13] | z`.
/// The selected values are script constants only so the example can execute
/// without implementing a second decision tree.  Their independently
/// measured push bytes are reported separately from the glue control bytes.
fn composed_glue(width: usize, shape: Shape, selected: &SelectedValues) -> Script {
    selected.assert_shape(shape);
    script! {
        { decode_lower_code(width) }

        // Copy negative for the post-selection Cp/Cm route.  Park magnitude
        // above it while tau consumes the original negative bit.
        OP_DUP OP_TOALTSTACK
        OP_SWAP OP_TOALTSTACK
        { conditionally_negate_tau() }
        OP_FROMALTSTACK

        // Model the table consuming magnitude, then emitting one authenticated
        // leaf. Table traversal and payload are intentionally out of scope.
        OP_DROP
        { push_selected(selected) }

        OP_FROMALTSTACK
        { route_selected_constants(shape) }
    }
}

/// Recover exact unoptimized bytes without bypassing the repository compile
/// policy: enough identical copies cross the 32-KiB cutoff, where policy
/// deliberately returns the unoptimized serialization.
fn raw_fragment_len(fragment: Script) -> usize {
    const COPIES: usize = 4_096;
    let repeated = script! {
        for _ in 0..COPIES { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % COPIES, 0);
    repeated.len() / COPIES
}

fn assert_execution(label: &str, fragment: Script, input: Vec<i64>, expected: Vec<i64>) -> usize {
    let policy = fragment.compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(policy.to_bytes(), witness(input));
    assert!(
        execution.error.is_none(),
        "{label} failed unexpectedly: {execution}"
    );
    assert_eq!(execution.final_stack.len(), expected.len(), "{label}");
    for (index, value) in expected.into_iter().enumerate() {
        assert_eq!(
            execution.final_stack.get(index),
            scriptnum_item(value),
            "{label} item {index}"
        );
    }
    execution.stats.max_nb_stack_items
}

fn decoder_checks(width: usize) -> usize {
    let bias = 1i64 << (width - 1);
    let fragment = decode_lower_code(width);
    let positive = assert_execution(
        "positive digit decode",
        fragment.clone(),
        vec![bias + 5],
        vec![5, 0],
    );
    let negative = assert_execution(
        "negative digit decode",
        fragment.clone(),
        vec![bias - 5],
        vec![5, 1],
    );
    let zero = assert_execution("zero digit decode", fragment, vec![bias], vec![0, 0]);
    positive.max(negative).max(zero)
}

fn tau_checks() -> usize {
    let tau = (1..=TAU_LIMBS as i64).collect::<Vec<_>>();
    let fragment = conditionally_negate_tau();
    let positive = assert_execution(
        "positive tau",
        fragment.clone(),
        tau.iter().copied().chain(std::iter::once(0)).collect(),
        tau.clone(),
    );
    let negative = assert_execution(
        "negative tau",
        fragment.clone(),
        tau.iter().copied().chain(std::iter::once(1)).collect(),
        tau.iter().map(|limb| -*limb).collect(),
    );
    let zero_tau = vec![0; TAU_LIMBS];
    let zero = assert_execution(
        "identity tau",
        fragment,
        zero_tau.iter().copied().chain(std::iter::once(0)).collect(),
        zero_tau,
    );
    positive.max(negative).max(zero)
}

fn route_checks(shape: Shape) -> usize {
    let selected = nonzero_probe_values(shape);
    let fragment = route_selected_constants(shape);
    let mut positive_input = selected.stack_values();
    positive_input.push(0);
    let positive = assert_execution(
        "positive constant route",
        fragment.clone(),
        positive_input,
        selected.stack_values(),
    );

    let mut negative_input = selected.stack_values();
    negative_input.push(1);
    let negative = assert_execution(
        "negative constant route",
        fragment.clone(),
        negative_input,
        selected.routed(true).stack_values(),
    );

    let identity = identity_values(shape);
    let mut zero_input = identity.stack_values();
    zero_input.push(0);
    let zero = assert_execution(
        "identity constant route",
        fragment,
        zero_input,
        identity.stack_values(),
    );
    positive.max(negative).max(zero)
}

fn composed_checks(width: usize, shape: Shape) -> (usize, usize, usize, usize) {
    let bias = 1i64 << (width - 1);
    let tau = (1..=TAU_LIMBS as i64).collect::<Vec<_>>();
    let selected = nonzero_probe_values(shape);

    let positive_fragment = composed_glue(width, shape, &selected);
    let mut positive_input = tau.clone();
    positive_input.push(bias + 5);
    let mut positive_expected = tau.clone();
    positive_expected.extend(selected.stack_values());
    let positive_peak = assert_execution(
        "positive composed glue",
        positive_fragment.clone(),
        positive_input,
        positive_expected,
    );

    let negative_fragment = composed_glue(width, shape, &selected);
    let mut negative_input = tau.clone();
    negative_input.push(bias - 5);
    let mut negative_expected = tau.iter().map(|limb| -*limb).collect::<Vec<_>>();
    negative_expected.extend(selected.routed(true).stack_values());
    let negative_peak = assert_execution(
        "negative composed glue",
        negative_fragment.clone(),
        negative_input,
        negative_expected,
    );

    let identity = identity_values(shape);
    let identity_fragment = composed_glue(width, shape, &identity);
    let mut identity_input = vec![0; TAU_LIMBS];
    identity_input.push(bias);
    let mut identity_expected = vec![0; TAU_LIMBS];
    identity_expected.extend(identity.stack_values());
    let identity_peak = assert_execution(
        "identity composed glue",
        identity_fragment.clone(),
        identity_input,
        identity_expected,
    );

    let selected_push_raw = raw_fragment_len(push_selected(&selected));
    let full_nonzero_raw = raw_fragment_len(negative_fragment);
    let control_raw = full_nonzero_raw
        .checked_sub(selected_push_raw)
        .expect("selected payload is part of full raw script");
    let identity_full_raw = raw_fragment_len(identity_fragment.clone());
    let identity_full_policy = identity_fragment.compile_with_policy().len();
    (
        positive_peak.max(negative_peak).max(identity_peak),
        control_raw,
        identity_full_raw,
        identity_full_policy,
    )
}

fn report_shape(shape: Shape, width: usize) -> (usize, usize) {
    let identity = identity_values(shape);
    let identity_fragment = push_selected(&identity);
    let identity_raw = raw_fragment_len(identity_fragment.clone());
    let identity_policy = identity_fragment.clone().compile_with_policy().len();
    let identity_peak = assert_execution(
        "identity synthesis",
        identity_fragment,
        vec![],
        identity.stack_values(),
    );

    let route = route_selected_constants(shape);
    let route_raw = raw_fragment_len(route.clone());
    let route_policy = route.compile_with_policy().len();
    let route_peak = route_checks(shape);

    let (composed_peak, control_raw, identity_full_raw, identity_full_policy) =
        composed_checks(width, shape);

    println!("shape={}", shape.name());
    println!("lower_window_width={width}");
    println!("route_input_items={}", shape.selected_items() + 1);
    println!("route_output_items={}", shape.selected_items());
    println!("route_raw_script_bytes={route_raw}");
    println!("route_policy_script_bytes={route_policy}");
    println!("route_strict_local_peak_items={route_peak}");
    println!("identity_synthesis_input_items=0");
    println!("identity_synthesis_output_items={}", shape.selected_items());
    println!("identity_synthesis_raw_script_bytes={identity_raw}");
    println!(
        "identity_constants_excluding_existing_z_raw_script_bytes={}",
        identity_raw - 1
    );
    println!("identity_synthesis_policy_script_bytes={identity_policy}");
    println!("identity_synthesis_strict_local_peak_items={identity_peak}");
    println!("composed_input_items={}", TAU_LIMBS + 1);
    println!(
        "composed_output_items={}",
        TAU_LIMBS + shape.selected_items()
    );
    println!("composed_control_raw_script_bytes={control_raw}");
    println!("composed_identity_raw_script_bytes={identity_full_raw}");
    println!("composed_identity_policy_script_bytes={identity_full_policy}");
    println!("composed_strict_local_peak_items={composed_peak}");
    println!("incremental_hint_items={HINT_ITEMS}");
    (control_raw, identity_raw - 1)
}

fn main() {
    let decode8 = decode_lower_code(8);
    let decode9 = decode_lower_code(9);
    let tau = conditionally_negate_tau();

    let decode8_raw = raw_fragment_len(decode8.clone());
    let decode9_raw = raw_fragment_len(decode9.clone());
    let tau_raw = raw_fragment_len(tau.clone());
    let decode8_policy = decode8.compile_with_policy().len();
    let decode9_policy = decode9.compile_with_policy().len();
    let tau_policy = tau.compile_with_policy().len();
    let decode8_peak = decoder_checks(8);
    let decode9_peak = decoder_checks(9);
    let tau_peak = tau_checks();

    println!("model=ed25519_signed_identity_glue");
    println!("deployment_class=unclassified");
    println!("execution_mode=strict_tapscript_fragment");
    println!("table_traversal_included=false");
    println!("affine_kernel_included=false");
    println!("digit_decode_input_items=1");
    println!("digit_decode_output_items=2");
    println!("digit_decode_w8_raw_script_bytes={decode8_raw}");
    println!("digit_decode_w8_policy_script_bytes={decode8_policy}");
    println!("digit_decode_w9_raw_script_bytes={decode9_raw}");
    println!("digit_decode_w9_policy_script_bytes={decode9_policy}");
    println!(
        "digit_decode_strict_local_peak_items={}",
        decode8_peak.max(decode9_peak)
    );
    println!("tau_sign_input_items={}", TAU_LIMBS + 1);
    println!("tau_sign_output_items={TAU_LIMBS}");
    println!("tau_sign_raw_script_bytes={tau_raw}");
    println!("tau_sign_policy_script_bytes={tau_policy}");
    println!("tau_sign_strict_local_peak_items={tau_peak}");
    println!("tau_sign_invariant=negative_negates_tau_K_unchanged");
    println!("incremental_hint_items={HINT_ITEMS}");

    // Early G31 tables use width nine and packed Cp/Cm.  Later tables use
    // width eight and direct Cp/Cm.
    let (packed_control, packed_identity_constants) = report_shape(Shape::Packed, 9);
    let (direct_control, direct_identity_constants) = report_shape(Shape::Direct, 8);

    // Raw schedule totals are additive because the production multi-megabyte
    // script is above the policy optimizer cutoff.  The table already emits
    // one authenticated z marker per leaf, so the incremental identity cost
    // excludes that existing one-byte marker.
    println!(
        "g31_30_transition_signed_control_raw_script_bytes={}",
        4 * packed_control + 26 * direct_control
    );
    println!(
        "g31_30_transition_identity_constants_raw_script_bytes={}",
        4 * packed_identity_constants + 26 * direct_identity_constants
    );
    println!(
        "g31_30_transition_total_residual_raw_script_bytes={}",
        4 * (packed_control + packed_identity_constants)
            + 26 * (direct_control + direct_identity_constants)
    );
    println!(
        "g29_28_transition_signed_control_raw_script_bytes={}",
        20 * packed_control + 8 * direct_control
    );
    println!(
        "g29_28_transition_identity_constants_raw_script_bytes={}",
        20 * packed_identity_constants + 8 * direct_identity_constants
    );
    println!(
        "g29_28_transition_total_residual_raw_script_bytes={}",
        20 * (packed_control + packed_identity_constants)
            + 8 * (direct_control + direct_identity_constants)
    );

    let representative_input =
        witness((1..=TAU_LIMBS as i64).chain(std::iter::once((1i64 << 8) - 5)));
    println!(
        "representative_composed_input_witness_bytes={}",
        serialize(&Witness::from_slice(&representative_input)).len()
    );
}
