//! Legacy 1-of-N point-lock experiment with a shared two-CHECKSIG tail.
//! Fixed deterministic public test scalars; exact policy-produced bytecode.
//! Execute only redeem scripts <=520 bytes, with default Legacy interpreter
//! options. No funding/Core validation: deployment unclassified.
use bitcoin::{
    absolute,
    hashes::{hash160, Hash},
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_lab::{
    signatures::pointlocks::committed_two_check as lock,
    support::script::{script, Script, ScriptCompilation},
};
use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};

fn choose(leaves: &[Script]) -> Script {
    if leaves.len() == 1 {
        return leaves[0].clone();
    }
    let mid = leaves.len() / 2;
    let left = choose(&leaves[..mid]);
    let right = choose(&leaves[mid..]);
    script! { OP_IF { left } OP_ELSE { right } OP_ENDIF }
}

// First path decision on top, so recursive decisions are appended first.
fn selectors(count: usize, index: usize, items: &mut Vec<Vec<u8>>) {
    if count == 1 {
        return;
    }
    let mid = count / 2;
    if index < mid {
        selectors(mid, index, items);
        items.push(vec![1]);
    } else {
        selectors(count - mid, index - mid, items);
        items.push(vec![]);
    }
}

fn transaction() -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: (0..2)
            .map(|vout| TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::all_zeros(),
                    vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

fn execute(script: ScriptBuf, items: Vec<Vec<u8>>) -> (bool, usize) {
    let mut exec = Exec::new(
        ExecCtx::Legacy,
        Options::default(),
        TxTemplate {
            tx: transaction(),
            prevouts: vec![],
            input_idx: 1,
            taproot_annex_scriptleaf: None,
        },
        script,
        items,
    )
    .unwrap();
    while exec.exec_next().is_ok() {}
    (
        exec.result().unwrap().success,
        exec.stats().max_nb_stack_items,
    )
}

fn main() {
    let secp = Secp256k1::new();
    for hashed_keys in [false, true] {
        for count in [2usize, 4, 5, 6, 7, 8] {
            let mut leaves = Vec::new();
            let mut signatures = Vec::new();
            let mut keys = Vec::new();
            for i in 0..count {
                let secret = SecretKey::from_slice(&[7 + i as u8; 32]).unwrap();
                let t = PublicKey::from_secret_key(&secp, &secret);
                let q = lock::companion_key(t).unwrap();
                let signature = lock::sign(secret).unwrap();
                let h = lock::signature_commitment(&signature)
                    .to_byte_array()
                    .to_vec();
                let (t_bytes, q_bytes) = if hashed_keys {
                    (
                        hash160::Hash::hash(&t.serialize()).to_byte_array().to_vec(),
                        hash160::Hash::hash(&q.serialize()).to_byte_array().to_vec(),
                    )
                } else {
                    (t.serialize().to_vec(), q.serialize().to_vec())
                };
                leaves.push(script! { { t_bytes } { q_bytes } { h } });
                signatures.push(signature.to_vec());
                keys.push((t.serialize().to_vec(), q.serialize().to_vec()));
            }
            let selection = choose(&leaves);
            let authentication = if hashed_keys {
                script! {
                    // sigma T Q hash(T) hash(Q) h -> sigma T Q
                    5 OP_PICK OP_HASH160 OP_EQUALVERIFY
                    2 OP_PICK OP_HASH160 OP_EQUALVERIFY
                    2 OP_PICK OP_HASH160 OP_EQUALVERIFY
                }
            } else {
                script! { 3 OP_PICK OP_HASH160 OP_EQUALVERIFY }
            };
            let redeem = script! {
                { selection }
                { authentication }
                // sigma T Q -> T Q sigma
                OP_ROT OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
                OP_DUP OP_ROT OP_CHECKSIGVERIFY OP_SWAP OP_CHECKSIG
            }
            .compile_with_policy();
            let mut max_peak = 0;
            let mut max_selector_items = 0;
            if redeem.len() <= 520 {
                for i in 0..count {
                    let mut items = vec![signatures[i].clone()];
                    if hashed_keys {
                        items.extend([keys[i].0.clone(), keys[i].1.clone()]);
                    }
                    let data_count = items.len();
                    selectors(count, i, &mut items);
                    max_selector_items = max_selector_items.max(items.len() - data_count);
                    let (success, peak) = execute(redeem.clone(), items.clone());
                    assert!(success, "mode={hashed_keys} count={count} index={i}");
                    max_peak = max_peak.max(peak);
                    items[0] = signatures[(i + 1) % count].clone();
                    assert!(!execute(redeem.clone(), items).0);
                    if hashed_keys {
                        let mut mixed = vec![
                            signatures[i].clone(),
                            keys[i].0.clone(),
                            keys[(i + 1) % count].1.clone(),
                        ];
                        selectors(count, i, &mut mixed);
                        assert!(!execute(redeem.clone(), mixed).0);
                    }
                }
            }
            println!("hashed_keys={hashed_keys} choices={count} script_bytes={} fits_p2sh={} max_selector_items={max_selector_items} max_stack={max_peak}",redeem.len(),redeem.len()<=520);
        }
    }
}
