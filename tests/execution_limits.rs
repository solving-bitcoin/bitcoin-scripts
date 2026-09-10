//! Exact bytecode fixtures exercise limits that an optimizer could erase.
//! These are local tapscript resource checks, not Bitcoin Core validation.

use bitcoin::ScriptBuf;
use bitcoin_lab::support::{
    execution::{
        dry_run_taproot_input, execute_raw_script_with_inputs,
        execute_raw_script_with_inputs_strict, execute_script_buf,
        execute_script_buf_without_stack_limit, execute_script_with_inputs_strict,
    },
    script::script,
};
use bitcoin_scriptexec::ExecError;

fn drop_items(count: usize) -> Vec<u8> {
    let mut bytes = vec![0x6d; count / 2]; // OP_2DROP
    if count % 2 != 0 {
        bytes.push(0x75); // OP_DROP
    }
    bytes.push(0x51); // OP_TRUE
    bytes
}

#[test]
fn initial_stack_limit_is_checked_before_cleanup() {
    for count in [1000, 1001] {
        let witness = vec![vec![]; count];
        let script = drop_items(count);
        let strict = execute_raw_script_with_inputs_strict(script.clone(), witness.clone());
        assert_eq!(strict.success, count == 1000);
        assert_eq!(strict.error, (count > 1000).then_some(ExecError::StackSize));
        assert_eq!(strict.stats.max_nb_stack_items, count);
        if count > 1000 {
            assert_eq!(
                strict.final_stack.len(),
                count,
                "must reject before OP_2DROP"
            );
        }
        let relaxed = execute_raw_script_with_inputs(script, witness);
        assert!(relaxed.success, "{relaxed}");
        assert_eq!(relaxed.stats.max_nb_stack_items, count);
    }
}

#[test]
fn witness_element_limit_is_checked_before_drop() {
    for size in [520, 521] {
        for strict in [false, true] {
            let execute = if strict {
                execute_raw_script_with_inputs_strict
            } else {
                execute_raw_script_with_inputs
            };
            let result = execute(drop_items(1), vec![vec![0x42; size]]);
            assert_eq!(result.success, size == 520, "size {size}, strict {strict}");
            assert_eq!(result.error, (size > 520).then_some(ExecError::PushSize));
        }
    }
}

#[test]
fn data_push_overflow_cannot_be_hidden_by_a_following_drop() {
    for count in [999, 1000] {
        // A minimal data push of 17 followed by OP_DROP; the general optimizer
        // would remove it, which would erase the resource-limit counterexample.
        let mut bytes = vec![0x01, 0x11, 0x75];
        bytes.extend(drop_items(count));
        let witness = vec![vec![]; count];
        let strict = execute_raw_script_with_inputs_strict(bytes.clone(), witness.clone());
        assert_eq!(strict.success, count == 999);
        assert_eq!(
            strict.error,
            (count == 1000).then_some(ExecError::StackSize)
        );
        assert_eq!(strict.stats.max_nb_stack_items, count + 1);
        assert!(execute_raw_script_with_inputs(bytes, witness).success);
    }
}

#[test]
fn altstack_items_count_during_data_pushes() {
    // Move one of 999 items to the altstack, then add two data items. Main
    // stack alone reaches 1000, but combined depth reaches 1001.
    let mut bytes = vec![0x6b, 0x01, 0x11, 0x01, 0x12, 0x6d, 0x6c];
    bytes.extend(drop_items(999));
    let witness = vec![vec![]; 999];
    let strict = execute_raw_script_with_inputs_strict(bytes.clone(), witness.clone());
    assert_eq!(strict.error, Some(ExecError::StackSize));
    assert_eq!(strict.final_stack.len(), 1000);
    assert_eq!(strict.stats.max_nb_stack_items, 1001);
    assert!(execute_raw_script_with_inputs(bytes, witness).success);
}

#[test]
fn no_witness_helper_checks_empty_data_pushes() {
    // OP_0 is decoded as a data push by rust-bitcoin.
    let mut bytes = vec![0x00; 1001];
    bytes.extend(drop_items(1001));
    let strict = execute_script_buf(ScriptBuf::from_bytes(bytes.clone()));
    assert_eq!(strict.error, Some(ExecError::StackSize));
    assert_eq!(strict.stats.max_nb_stack_items, 1001);
    assert!(execute_script_buf_without_stack_limit(ScriptBuf::from_bytes(bytes)).success);
}

#[test]
fn compiled_witness_helper_checks_initial_limits() {
    let result =
        execute_script_with_inputs_strict(script! { OP_DROP OP_TRUE }, vec![vec![0x42; 521]]);
    assert_eq!(result.error, Some(ExecError::PushSize));
}

#[test]
fn failing_numeric_push_is_included_in_peak() {
    let result = execute_raw_script_with_inputs_strict(vec![0x51], vec![vec![]; 1000]);
    assert_eq!(result.error, Some(ExecError::StackSize));
    assert_eq!(result.stats.max_nb_stack_items, 1001);
}

#[test]
fn skipped_push_does_not_increase_live_stack_depth() {
    // Starting with 1000 items, OP_IF consumes an empty condition. Dead
    // branch pushes do not change the remaining 999-item live stack.
    let mut bytes = vec![0x63, 0x01, 0x11, 0x01, 0x12, 0x68];
    bytes.extend(drop_items(999));
    let result = execute_raw_script_with_inputs_strict(bytes, vec![vec![]; 1000]);
    assert!(result.success, "{result}");
    assert_eq!(result.stats.max_nb_stack_items, 1000);
}

#[test]
fn execution_reports_stack_limit_choice() {
    let strict = execute_raw_script_with_inputs_strict(vec![0x51], vec![]);
    assert!(strict.stack_limit_enforced);
    assert!(strict.to_string().contains("deployment unclassified"));
    let relaxed = execute_raw_script_with_inputs(vec![0x51], vec![]);
    assert!(!relaxed.stack_limit_enforced);
    assert!(relaxed.to_string().contains("research-unlimited"));
}

#[test]
fn taproot_dry_run_uses_the_same_resource_checks() {
    // This helper only executes the leaf: the dummy control block is not a
    // Taproot commitment fixture and does not establish transaction validity.
    for (count, size, expected_error) in [
        (1, 520, None),
        (1, 521, Some(ExecError::PushSize)),
        (1001, 0, Some(ExecError::StackSize)),
    ] {
        let mut witness = vec![vec![0x42; size]; count];
        witness.push(drop_items(count));
        let mut control = vec![0; 33];
        control[0] = 0xc0;
        witness.push(control);
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                witness: bitcoin::Witness::from_slice(&witness),
                ..Default::default()
            }],
            output: vec![],
        };
        let result = dry_run_taproot_input(&tx, 0, &[]);
        assert_eq!(result.success, expected_error.is_none());
        assert_eq!(result.error, expected_error);
        assert!(result.stack_limit_enforced);
    }
}
