use bitcoin_lab::{
    curves::ed25519::{
        affine_add, basepoint_constants, chained_signed_transition_direct_constants_witness_items,
        chained_signed_transition_direct_k_witness_items,
        controlled_shared_tau_mixed_transition_hints,
        packed_signed_transition_direct_k_witness_items,
        verify_packed_signed_transition_chained_direct_constants_shared_tau_mixed,
        verify_packed_signed_transition_chained_direct_k_shared_tau_mixed,
        verify_packed_signed_transition_expanded_direct_k_shared_tau_mixed,
        EXPANDED_CURRENT_SIGNED_DIRECT_CONSTANTS_INPUT_ITEM_COUNT,
        EXPANDED_CURRENT_SIGNED_DIRECT_K_INPUT_ITEM_COUNT, HINT_ITEM_COUNT,
        PACKED_SIGNED_DIRECT_K_INPUT_ITEM_COUNT,
    },
    fields::ed25519::u5_balanced_table::modulus,
    support::{execution::execute_raw_script_with_inputs_strict, script::ScriptCompilation},
};
use num_bigint::BigUint;
use num_traits::{One, Zero};

#[derive(Clone)]
struct Case {
    name: &'static str,
    tau: BigUint,
    x_next: BigUint,
    y_next: BigUint,
    k: BigUint,
    cp: BigUint,
    cm: BigUint,
    negative: bool,
    nonzero: bool,
}

fn main() {
    let fixed = basepoint_constants();
    let x = fixed.a.clone();
    let y = fixed.b.clone();
    let (positive_x, positive_y, positive_tau) = affine_add(&x, &y, &fixed);

    let p = modulus();
    let negative_fixed =
        bitcoin_lab::curves::ed25519::FixedPointConstants::new(&p - &fixed.a, fixed.b.clone());
    assert_eq!(negative_fixed.cp, fixed.cm);
    assert_eq!(negative_fixed.cm, fixed.cp);
    let (negative_x, negative_y, negative_tau_field) = affine_add(&x, &y, &negative_fixed);
    let negative_tau = if negative_tau_field.is_zero() {
        BigUint::zero()
    } else {
        &p - negative_tau_field
    };

    let cases = [
        Case {
            name: "positive",
            tau: positive_tau,
            x_next: positive_x,
            y_next: positive_y,
            k: fixed.k.clone(),
            cp: fixed.cp.clone(),
            cm: fixed.cm.clone(),
            negative: false,
            nonzero: true,
        },
        Case {
            name: "negative",
            tau: negative_tau,
            x_next: negative_x,
            y_next: negative_y,
            k: fixed.k.clone(),
            cp: fixed.cm.clone(),
            cm: fixed.cp.clone(),
            negative: true,
            nonzero: true,
        },
        Case {
            name: "identity",
            tau: BigUint::zero(),
            x_next: x.clone(),
            y_next: y.clone(),
            k: BigUint::one(),
            cp: BigUint::one(),
            cm: BigUint::one(),
            negative: false,
            nonzero: false,
        },
    ];

    let first =
        verify_packed_signed_transition_expanded_direct_k_shared_tau_mixed(0).compile_with_policy();
    let chained =
        verify_packed_signed_transition_chained_direct_k_shared_tau_mixed(0).compile_with_policy();
    let direct = verify_packed_signed_transition_chained_direct_constants_shared_tau_mixed(0)
        .compile_with_policy();
    assert_eq!(first.len(), 116_418);
    assert_eq!(chained.len(), 107_259);
    assert_eq!(direct.len(), 98_331);

    println!("execution_class=research-unlimited");
    println!("logical_hint_items={HINT_ITEM_COUNT}");
    println!("first_complete_input_items={PACKED_SIGNED_DIRECT_K_INPUT_ITEM_COUNT}");
    println!("first_script_bytes={}", first.len());
    println!("chained_complete_input_items={EXPANDED_CURRENT_SIGNED_DIRECT_K_INPUT_ITEM_COUNT}");
    println!("chained_script_bytes={}", chained.len());
    println!(
        "direct_constants_complete_input_items={EXPANDED_CURRENT_SIGNED_DIRECT_CONSTANTS_INPUT_ITEM_COUNT}"
    );
    println!("direct_constants_script_bytes={}", direct.len());

    if std::env::args().any(|argument| argument == "--measure-only") {
        println!("arithmetic_execution_skipped=true");
        println!("script_compilation=policy-precompiled-semantic-steps");
        return;
    }

    for case in cases {
        let hints = controlled_shared_tau_mixed_transition_hints(
            &x,
            &y,
            &case.tau,
            &case.x_next,
            &case.y_next,
            &case.k,
            &case.cp,
            &case.cm,
            case.negative,
            case.nonzero,
        );

        let first_execution = execute_raw_script_with_inputs_strict(
            first.to_bytes(),
            packed_signed_transition_direct_k_witness_items(
                &x,
                &y,
                &case.tau,
                &case.x_next,
                &case.y_next,
                &case.k,
                &case.cp,
                &case.cm,
                case.negative,
                case.nonzero,
                &hints,
            ),
        );
        assert!(
            first_execution.error.is_none(),
            "{} first signed transition failed: {first_execution}",
            case.name
        );
        println!(
            "{}_first_local_peak={}",
            case.name, first_execution.stats.max_nb_stack_items
        );

        let chained_execution = execute_raw_script_with_inputs_strict(
            chained.to_bytes(),
            chained_signed_transition_direct_k_witness_items(
                &x,
                &y,
                &case.tau,
                &case.x_next,
                &case.y_next,
                &case.k,
                &case.cp,
                &case.cm,
                case.negative,
                case.nonzero,
                &hints,
            ),
        );
        assert!(
            chained_execution.error.is_none(),
            "{} chained signed transition failed: {chained_execution}",
            case.name
        );
        println!(
            "{}_chained_local_peak={}",
            case.name, chained_execution.stats.max_nb_stack_items
        );

        let direct_execution = execute_raw_script_with_inputs_strict(
            direct.to_bytes(),
            chained_signed_transition_direct_constants_witness_items(
                &x,
                &y,
                &case.tau,
                &case.x_next,
                &case.y_next,
                &case.k,
                &case.cp,
                &case.cm,
                case.negative,
                case.nonzero,
                &hints,
            ),
        );
        assert!(
            direct_execution.error.is_none(),
            "{} direct-constant signed transition failed: {direct_execution}",
            case.name
        );
        println!(
            "{}_direct_constants_local_peak={}",
            case.name, direct_execution.stats.max_nb_stack_items
        );
    }

    println!("script_compilation=policy-precompiled-semantic-steps");
}
