use bitcoin::Amount;
use bitcoin_lab::{
    signatures::quorum::{verify_weighted_quorum, MAX_KEYS},
    support::script::{script, MAX_OPTIMIZER_INPUT_BYTES},
};
use bitcoin_scriptexec::ExecError;

#[path = "support/weighted_quorum.rs"]
mod fixture;

use fixture::{groups, individual, keypairs, Spend};

#[test]
fn matches_every_subset_of_a_weighted_policy() {
    let pairs = keypairs(6);
    let keys: Vec<_> = pairs.iter().map(|key| key.x_only_public_key().0).collect();
    let spec = [(1, 2), (2, 2), (5, 2)];
    let policy = groups(&keys, &spec);
    let weights = [1, 1, 2, 2, 5, 5];
    let threshold = 7;
    for fragment in [
        verify_weighted_quorum(&policy, threshold),
        individual(&policy, threshold),
    ] {
        let spend = Spend::new(fragment, &pairs);
        assert!(spend.raw_script_bytes <= MAX_OPTIMIZER_INPUT_BYTES);
        for bits in 0..1 << weights.len() {
            let indices: Vec<_> = (0..weights.len())
                .filter(|&i| bits & (1 << i) != 0)
                .collect();
            let expected = indices.iter().map(|&i| weights[i]).sum::<u32>() >= threshold;
            let tx = spend.with_data(spend.data(&indices));
            let trace = spend.trace(&tx);
            assert_eq!(
                trace.success, expected,
                "slots {indices:?}: {:?}",
                trace.error
            );
            assert_eq!(trace.charged, 50 * indices.len() as i64);
            assert_eq!(trace.initial_budget, 50 + tx.input[0].witness.size() as i64);
            assert!(trace.executed > 0);
        }
    }
}

#[test]
fn rejects_malformed_or_replayed_signatures_even_after_quorum() {
    let pairs = keypairs(3);
    let keys: Vec<_> = pairs.iter().map(|key| key.x_only_public_key().0).collect();
    let policy = groups(&keys, &[(5, 1), (1, 2)]);
    let grouped = Spend::new(verify_weighted_quorum(&policy, 5), &pairs);
    let direct = Spend::new(individual(&policy, 5), &pairs);
    for spend in [&grouped, &direct] {
        let honest = spend.data(&[0]);
        let tx = spend.with_data(honest.clone());
        assert!(spend.trace(&tx).success);
        let mut changed = tx;
        changed.output[0].value = Amount::from_sat(89_999);
        assert!(!spend.trace(&changed).success);
        for bad in [
            vec![1],
            vec![0; 63],
            vec![0; 64],
            vec![0; 65],
            vec![0; 521],
            honest[2].clone(),
        ] {
            let mut data = honest.clone();
            data[1] = bad;
            assert!(!spend.trace(&spend.with_data(data)).success);
        }
        let mut short = honest.clone();
        short.remove(0);
        assert!(!spend.trace(&spend.with_data(short)).success);
        let mut long = honest;
        long.insert(0, vec![]);
        assert!(!spend.trace(&spend.with_data(long)).success);
    }
    assert!(!direct.trace(&direct.with_data(grouped.data(&[0]))).success);
}

#[test]
fn validates_policy_parameters_and_the_combined_frontier() {
    let pairs = keypairs(MAX_KEYS);
    let keys: Vec<_> = pairs.iter().map(|key| key.x_only_public_key().0).collect();
    let duplicated = [(1, &keys[..1]), (5, &keys[..1])];
    let empty = [(1, &keys[..0])];
    let zero = [(0, &keys[..1])];
    let oversized = [(17, &keys[..1])];
    let valid = [(1, &keys[..1])];
    for (groups, threshold) in [
        (&duplicated[..], 1),
        (&empty[..], 1),
        (&zero[..], 1),
        (&oversized[..], 1),
        (&valid[..], 0),
        (&valid[..], 2),
        (&[][..], 1),
    ] {
        assert!(std::panic::catch_unwind(|| verify_weighted_quorum(groups, threshold)).is_err());
    }
    let mut too_many = keys.clone();
    too_many.push(keys[0]);
    assert!(std::panic::catch_unwind(|| verify_weighted_quorum(&[(1, &too_many)], 1)).is_err());

    let policy = groups(&keys, &[(15, 1), (1, MAX_KEYS - 1)]);
    let spend = Spend::new(verify_weighted_quorum(&policy, 15), &pairs);
    assert!(spend.raw_script_bytes > MAX_OPTIMIZER_INPUT_BYTES);
    let data = spend.data(&[0]);
    let trace = spend.trace(&spend.with_data(data.clone()));
    assert!(trace.success, "{:?}", trace.error);
    assert_eq!(trace.peak, 1000);
    assert_eq!(trace.charged, 50);
    let mut extra = data;
    extra.insert(0, vec![]);
    assert_eq!(
        spend.trace(&spend.with_data(extra)).error,
        Some(ExecError::StackSize)
    );
}

#[test]
fn preserves_caller_stacks_at_the_maximum_single_key_weight() {
    let pairs = keypairs(1);
    let keys = [pairs[0].x_only_public_key().0];
    let policy = [(16, &keys[..])];
    let main = vec![1, 0];
    let alt = vec![0x80];
    let fragment = script! {
        OP_TOALTSTACK
        {verify_weighted_quorum(&policy,16)}
        OP_FROMALTSTACK {alt.clone()} OP_EQUALVERIFY
        {main.clone()} OP_EQUALVERIFY
    };
    let spend = Spend::new(fragment, &pairs);
    let data = [vec![main], spend.data(&[0]), vec![alt]].concat();
    let trace = spend.trace(&spend.with_data(data));
    assert!(trace.success, "{:?}", trace.error);
    assert_eq!(trace.charged, 50);
}
