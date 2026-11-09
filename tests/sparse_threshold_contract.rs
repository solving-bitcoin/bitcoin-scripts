use bitcoin::Amount;
use bitcoin_lab::{
    signatures::sparse_threshold::verify_sparse_threshold,
    support::script::MAX_OPTIMIZER_INPUT_BYTES,
};
use bitcoin_scriptexec::ExecError;

#[path = "support/sparse_threshold.rs"]
mod support;
use support::{fixture, keypairs};

#[test]
fn checks_signed_exact_threshold_fixtures_and_full_witness_budget() {
    for (n, depths) in [
        (1, vec![0]),
        (8, vec![0, 7]),
        (16, vec![0, 4, 8, 15]),
        (64, vec![0, 63]),
    ] {
        for sparse in [false, true] {
            let built = fixture(n, &depths, sparse);
            let trace = built.trace(&built.tx);
            assert!(trace.success, "{:?}", trace.error);
            assert_eq!(trace.error, None);
            assert_eq!(
                trace.initial_budget,
                50 + built.tx.input[0].witness.size() as i64
            );
            assert_eq!(trace.charged, 50 * depths.len() as i64);
            assert!(trace.peak <= 1000);
            assert!(trace.executed > 0);
            assert!(built.raw_script_bytes <= MAX_OPTIMIZER_INPUT_BYTES);
        }
    }
}

#[test]
fn rejects_malformed_out_of_range_duplicate_and_descending_depths() {
    let built = fixture(8, &[0, 7], true);
    for (bad, error) in [
        (vec![8], ExecError::Verify),
        (vec![0x81], ExecError::Verify),
        (vec![0], ExecError::EqualVerify),
        (vec![0x80], ExecError::EqualVerify),
        (vec![0; 5], ExecError::ScriptIntNumericOverflow),
    ] {
        let mut data = built.data.clone();
        data[3] = bad;
        let trace = built.trace(&built.with_data(data));
        assert!(!trace.success);
        assert_eq!(trace.error, Some(error));
        assert_eq!(trace.charged, 0);
    }
    let mut duplicate = built.data.clone();
    duplicate[1] = duplicate[3].clone();
    duplicate[0] = duplicate[2].clone();
    let trace = built.trace(&built.with_data(duplicate));
    assert_eq!(trace.error, Some(ExecError::Verify));
    assert_eq!(trace.charged, 50);
    let descending = fixture(8, &[7, 0], true);
    let trace = descending.trace(&descending.tx);
    assert_eq!(trace.error, Some(ExecError::Verify));
    assert_eq!(trace.charged, 50);
}

#[test]
fn rejects_reassigned_signatures_empty_signatures_and_changed_transaction() {
    let built = fixture(8, &[0, 7], true);
    for depth in [1, 6] {
        let mut data = built.data.clone();
        data[3] = vec![depth];
        assert!(!built.trace(&built.with_data(data)).success);
    }
    let mut swapped = built.data.clone();
    swapped.swap(0, 2);
    assert!(!built.trace(&built.with_data(swapped)).success);
    let mut empty = built.data.clone();
    empty[2].clear();
    let trace = built.trace(&built.with_data(empty));
    assert!(!trace.success);
    assert_eq!(trace.charged, 0);

    let mut changed = built.tx.clone();
    changed.output[0].value = Amount::from_sat(89_999);
    assert!(!built.trace(&changed).success);
    let dense = fixture(8, &[0, 7], false);
    let mut wrong_leaf = built.data.clone();
    wrong_leaf[2] = dense.data[7].clone();
    assert!(!built.trace(&built.with_data(wrong_leaf)).success);
    let mut short = built.data.clone();
    short.remove(0);
    assert!(!built.trace(&built.with_data(short)).success);
    let mut extra = built.data.clone();
    extra.insert(0, vec![]);
    assert!(!built.trace(&built.with_data(extra)).success);
}

#[test]
fn observes_exact_stack_limit_and_rejects_invalid_key_sets() {
    let built = fixture(994, &[993], true);
    assert!(built.raw_script_bytes > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(built.script.len(), built.raw_script_bytes);
    assert_eq!(built.script.len(), 33_827);
    assert_eq!(built.tx.input[0].witness.size(), 33_933);
    let trace = built.trace(&built.tx);
    assert!(trace.success, "{:?}", trace.error);
    assert_eq!(trace.peak, 1000);
    assert_eq!(trace.executed, 1012);
    let mut extra = built.data.clone();
    extra.insert(0, vec![]);
    assert_eq!(
        built.trace(&built.with_data(extra)).error,
        Some(ExecError::StackSize)
    );

    let keys: Vec<_> = keypairs(2)
        .iter()
        .map(|pair| pair.x_only_public_key().0)
        .collect();
    for (keys, k) in [
        (keys.clone(), 0),
        (keys.clone(), 3),
        (vec![keys[0]; 2], 1),
        (vec![keys[0]; 995], 1),
    ] {
        assert!(std::panic::catch_unwind(|| verify_sparse_threshold(&keys, k)).is_err());
    }
}
