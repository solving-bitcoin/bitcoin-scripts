//! Checked PRINCEv2 complete leaves, with hostile witness encodings.
//! Local profiles enforce the combined stack limit; deployment is unclassified
//! here. The separate pinned-Core experiment establishes transaction evidence.
use bitcoin::{consensus::serialize, ScriptBuf, Witness};
use bitcoin_lab::{
    ciphers::prince::{prince_verify, u64_to_nibbles_msb},
    support::{
        script::ScriptCompilation,
        tapscript::{execute_tapscript, TapscriptProfile},
    },
};
use std::sync::LazyLock;

fn witness(plaintext: u64) -> Vec<Vec<u8>> {
    u64_to_nibbles_msb(plaintext)
        .into_iter()
        .rev()
        .map(|n| if n == 0 { vec![] } else { vec![n] })
        .collect()
}

fn c_vectors() -> Vec<(u128, u64, u64)> {
    let document: serde_json::Value =
        serde_json::from_str(include_str!("data/princev2_upstream_vectors.json")).unwrap();
    assert_eq!(
        document["commit"],
        "0c6172dcd85f1fe6a269519093a79c7350fe6e55"
    );
    document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                u128::from_str_radix(row["key"].as_str().unwrap(), 16).unwrap(),
                u64::from_str_radix(row["plaintext"].as_str().unwrap(), 16).unwrap(),
                u64::from_str_radix(row["ciphertext"].as_str().unwrap(), 16).unwrap(),
            )
        })
        .collect()
}

static ZERO: LazyLock<ScriptBuf> = LazyLock::new(|| {
    let (_, _, ciphertext) = c_vectors()
        .into_iter()
        .find(|(k, p, _)| *k == 0 && *p == 0)
        .unwrap();
    prince_verify(0, ciphertext).compile_with_policy()
});

fn assert_rejects(script: &ScriptBuf, data: Vec<Vec<u8>>) {
    for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
        let result = execute_tapscript(script.clone(), data.clone(), profile);
        assert_eq!(result.accepted(), Some(false), "{profile:?}: {data:?}");
        let execution = result
            .execution()
            .expect("ordinary supported script rejection");
        assert!(execution.error.is_some());
        assert!(execution.stack_limit_enforced);
    }
}

#[test]
fn checked_leaf_matches_independent_c_boundary_vectors() {
    let published_key = 0x0123456789abcdeffedcba9876543210;
    let vectors = c_vectors()
        .into_iter()
        .filter(|(key, _, _)| *key == 0 || *key == published_key)
        .collect::<Vec<_>>();
    assert!(vectors.iter().any(|(k, p, _)| *k == 0 && *p == 0));
    assert!(vectors.iter().any(|(k, p, _)| *k == 0 && *p == u64::MAX));
    assert!(vectors.iter().any(|(k, _, _)| *k == published_key));
    for (key, plaintext, ciphertext) in vectors {
        let script = prince_verify(key, ciphertext).compile_with_policy();
        let data = witness(plaintext);
        assert_eq!(data.len(), 16);
        for profile in [TapscriptProfile::Consensus, TapscriptProfile::Policy] {
            let result = execute_tapscript(script.clone(), data.clone(), profile);
            assert_eq!(
                result.accepted(),
                Some(true),
                "key={key:032x} plaintext={plaintext:016x}"
            );
            let execution = result.execution().unwrap();
            assert_eq!(execution.final_stack.len(), 1);
            assert_eq!(execution.final_stack.get(0), vec![1]);
            assert!(execution.stats.max_nb_stack_items <= 1000);
            assert!(execution.stack_limit_enforced);
        }
        println!("key={key:032x} plaintext={plaintext:016x} checked_leaf_bytes={} data_witness_bytes={} data_items=16 hint_items=0 complete_taproot_items=18", script.len(), serialize(&Witness::from_slice(&data)).len());
    }
}

#[test]
fn checked_leaf_rejects_invalid_nibbles_at_every_position_without_policy_help() {
    let invalid = [
        vec![0],
        vec![0x80],
        vec![0, 0],
        vec![1, 0],
        vec![0x81],
        vec![16],
        vec![127],
        vec![0xff],
        vec![0x80, 0],
        vec![0xff, 0xff, 0xff, 0x7f],
        vec![0xff, 0xff, 0xff, 0xff, 0],
    ];
    for position in 0..16 {
        for bytes in &invalid {
            let mut data = witness(0);
            data[position] = bytes.clone();
            assert_rejects(&ZERO, data);
        }
    }
}

#[test]
fn checked_leaf_rejects_missing_and_extra_inputs() {
    for count in [0, 1, 15, 17, 32] {
        assert_rejects(&ZERO, vec![vec![]; count]);
    }
}

#[test]
fn checked_leaf_rejects_wrong_ciphertext_and_plaintext() {
    let (_, _, ciphertext) = c_vectors()
        .into_iter()
        .find(|(k, p, _)| *k == 0 && *p == 0)
        .unwrap();
    let wrong = prince_verify(0, ciphertext ^ 1).compile_with_policy();
    assert_rejects(&wrong, witness(0));
    assert_rejects(&ZERO, witness(1));
}
