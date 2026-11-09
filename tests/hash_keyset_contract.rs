use bitcoin::{consensus::serialize, secp256k1::XOnlyPublicKey, sighash::TapSighashType};
use bitcoin_lab::{signatures::hash_keyset::verify_hash160_keyset, support::script::*};

#[path = "support/hash_keyset.rs"]
mod fixtures;
use fixtures::{embedded_index, embedded_scan, identifier, keypairs, public_key, Spend};

#[test]
fn all_members_verify_under_each_exact_leaf_and_signature_budget() {
    let keys = keypairs(4);
    let public: Vec<_> = keys.iter().map(public_key).collect();
    let identifiers: Vec<_> = public.iter().map(|key| identifier(key)).collect();
    for (mode, fragment) in [
        verify_hash160_keyset(&identifiers),
        embedded_scan(&public),
        embedded_index(&public),
    ]
    .into_iter()
    .enumerate()
    {
        let spend = Spend::new(fragment);
        for (index, key) in keys.iter().enumerate() {
            for sighash in [TapSighashType::Default, TapSighashType::All] {
                let signature = spend.sign(key, sighash);
                let data = if mode == 2 {
                    let selector = if index == 0 {
                        vec![]
                    } else {
                        vec![index as u8]
                    };
                    vec![signature, selector]
                } else {
                    vec![signature, public[index].to_vec()]
                };
                let witness = spend.witness(data);
                let size = serialize(&witness).len();
                let trace = spend.trace(witness);
                assert!(trace.success);
                assert_eq!(trace.initial_budget, 50 + size as i64);
                assert_eq!(trace.charged, 50);
                assert!(trace.executed > 0 && trace.peak <= 6);
            }
        }
    }
}

#[test]
fn membership_signature_and_sighash_are_independently_bound() {
    let keys = keypairs(3);
    let public: Vec<_> = keys.iter().map(public_key).collect();
    let committed = [identifier(&public[0]), identifier(&public[1])];
    let spend = Spend::new(verify_hash160_keyset(&committed));
    let alternative = Spend::new(embedded_scan(&public[..2]));
    let signature = spend.sign(&keys[0], TapSighashType::Default);
    let mut invalid_sighash = signature.clone();
    invalid_sighash.push(0);

    let outsider = spend.trace(spend.witness(vec![
        spend.sign(&keys[2], TapSighashType::Default),
        public[2].to_vec(),
    ]));
    assert!(!outsider.success);
    assert_eq!(outsider.charged, 0);

    for data in [
        vec![signature.clone(), public[1].to_vec()],
        vec![vec![], public[0].to_vec()],
        vec![invalid_sighash, public[0].to_vec()],
        vec![
            alternative.sign(&keys[0], TapSighashType::Default),
            public[0].to_vec(),
        ],
        vec![signature.clone()],
        vec![vec![], signature, public[0].to_vec()],
    ] {
        assert!(!spend.trace(spend.witness(data)).success);
    }
}

#[test]
fn raw_key_size_guard_prevents_the_unknown_type_bypass() {
    let short = vec![2];
    let digest = identifier(&short);
    let guarded = Spend::new(verify_hash160_keyset(&[digest]));
    let unguarded = Spend::new(script! {
        OP_DUP OP_HASH160 { digest.to_vec() } OP_EQUALVERIFY OP_CHECKSIGVERIFY
    });
    let data = vec![vec![1], short];
    let trace = guarded.trace(guarded.witness(data.clone()));
    assert!(!trace.success);
    assert_eq!(trace.charged, 0);
    let trace = unguarded.trace(unguarded.witness(data));
    assert!(trace.success);
    assert_eq!(trace.charged, 50);

    let invalid = [0xff; 32];
    assert!(XOnlyPublicKey::from_slice(&invalid).is_err());
    let spend = Spend::new(verify_hash160_keyset(&[identifier(&invalid)]));
    let key = &keypairs(1)[0];
    let data = vec![spend.sign(key, TapSighashType::Default), invalid.to_vec()];
    assert!(!spend.trace(spend.witness(data)).success);
}

#[test]
fn maximum_list_and_caller_stack_boundaries_are_observable() {
    let key = &keypairs(1)[0];
    let public = public_key(key);
    let identifiers = vec![identifier(&public); 512];
    let spend = Spend::new(script! {
        OP_TOALTSTACK
        { verify_hash160_keyset(&identifiers) }
        OP_FROMALTSTACK 18 OP_EQUALVERIFY
        for _ in 0..992 { OP_DROP }
        17 OP_EQUALVERIFY
    });
    let mut data = vec![vec![17]];
    data.extend((0..992).map(|_| vec![]));
    data.extend([
        spend.sign(key, TapSighashType::Default),
        public.to_vec(),
        vec![18],
    ]);
    let trace = spend.trace(spend.witness(data.clone()));
    assert!(trace.success);
    assert_eq!(trace.peak, 1000);
    data.insert(0, vec![19]);
    let trace = spend.trace(spend.witness(data));
    assert!(!trace.success);
    assert_eq!(trace.charged, 0);
    for count in [0, 513] {
        let unsupported = vec![[0; 20]; count];
        assert!(std::panic::catch_unwind(|| verify_hash160_keyset(&unsupported)).is_err());
    }
}
