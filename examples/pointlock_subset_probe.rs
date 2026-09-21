//! Research-only t-of-n HASH160 point-lock subset, sharing one candidate table.
//! Sorted indices enforce distinct selections. No full transaction/Core proof.
use bitcoin::{
    absolute,
    hashes::{hash160, Hash},
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_lab::{
    signatures::pointlocks::committed_two_check as lock,
    support::script::{script, ScriptCompilation},
};
use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};

#[derive(Clone)]
struct Candidate {
    signature: Vec<u8>,
    target: Vec<u8>,
    companion: Vec<u8>,
}
fn candidates(n: usize) -> Vec<Candidate> {
    let secp = Secp256k1::new();
    (0..n)
        .map(|i| {
            let secret = SecretKey::from_slice(&[7 + i as u8; 32]).unwrap();
            let target = PublicKey::from_secret_key(&secp, &secret);
            Candidate {
                signature: lock::sign(secret).unwrap().to_vec(),
                target: target.serialize().to_vec(),
                companion: lock::companion_key(target).unwrap().serialize().to_vec(),
            }
        })
        .collect()
}
fn subset(c: &[Candidate], t: usize) -> ScriptBuf {
    assert!(t > 0 && t <= c.len());
    let n = c.len();
    script! {
        for row in c {
            { hash160::Hash::hash(&row.target).to_byte_array().to_vec() }
            { hash160::Hash::hash(&row.companion).to_byte_array().to_vec() }
            { hash160::Hash::hash(&row.signature).to_byte_array().to_vec() }
        }
        -1 OP_TOALTSTACK
        for _ in 0..t {
            // Move next (sigma,T,Q,index) from below the shared table.
            for _ in 0..4 { { 3*n+3 } OP_ROLL }
            // Strict ascending indices, with previous=-1 and index<n.
            OP_DUP { n } OP_LESSTHAN OP_VERIFY
            OP_DUP OP_FROMALTSTACK OP_GREATERTHAN OP_VERIFY
            OP_DUP OP_TOALTSTACK
            // Depth of h_sigma is 3*(n-index), with sigma,T,Q above table.
            { n } OP_SWAP OP_SUB OP_DUP OP_DUP OP_ADD OP_ADD
            OP_DUP OP_TOALTSTACK OP_PICK
            3 OP_PICK OP_HASH160 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1ADD OP_DUP OP_TOALTSTACK OP_PICK
            1 OP_PICK OP_HASH160 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1ADD OP_PICK
            2 OP_PICK OP_HASH160 OP_EQUALVERIFY
            // sigma T Q: original two checks, all key/hash openings bound.
            OP_ROT OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
            OP_DUP OP_ROT OP_CHECKSIGVERIFY OP_SWAP OP_CHECKSIGVERIFY
        }
        for _ in 0..3*n { OP_DROP }
        OP_FROMALTSTACK OP_DROP
        OP_TRUE
    }
    .compile_with_policy()
}
fn items(c: &[Candidate], selected: &[usize]) -> Vec<Vec<u8>> {
    selected
        .iter()
        .rev()
        .flat_map(|&i| {
            let row = &c[i];
            [
                row.signature.clone(),
                row.target.clone(),
                row.companion.clone(),
                if i == 0 { vec![] } else { vec![i as u8] },
            ]
        })
        .collect()
}
fn execute(script: ScriptBuf, items: Vec<Vec<u8>>) -> (bool, usize) {
    let tx = Transaction {
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
    };
    let mut exec = Exec::new(
        ExecCtx::Legacy,
        Options::default(),
        TxTemplate {
            tx,
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
        exec.result().unwrap().success && exec.stack().len() == 1,
        exec.stats().max_nb_stack_items,
    )
}
fn serialized_scriptsig(items: &[Vec<u8>], redeem: &ScriptBuf) -> ScriptBuf {
    let mut builder = bitcoin::script::Builder::new();
    for item in items {
        builder = if item.is_empty() {
            builder.push_int(0)
        } else if item.len() == 1 && (1..=16).contains(&item[0]) {
            builder.push_int(i64::from(item[0]))
        } else if item == &[0x81] {
            builder.push_int(-1)
        } else {
            builder.push_slice(bitcoin::script::PushBytesBuf::try_from(item.clone()).unwrap())
        };
    }
    builder
        .push_slice(bitcoin::script::PushBytesBuf::try_from(redeem.to_bytes()).unwrap())
        .into_script()
}
fn main() {
    for n in 2..=7 {
        let c = candidates(n);
        for t in 1..=3.min(n) {
            let redeem = subset(&c, t);
            let static_ops = redeem
                .instructions()
                .filter(|i| matches!(i,Ok(bitcoin::script::Instruction::Op(op)) if op.to_u8()>0x60))
                .count();
            let mut branches = 0;
            let mut max_peak = 0;
            let mut max_scriptsig = 0;
            if redeem.len() <= 520 {
                for mask in 0..(1usize << n) {
                    if mask.count_ones() as usize != t {
                        continue;
                    }
                    let selected: Vec<_> = (0..n).filter(|i| mask & (1 << i) != 0).collect();
                    let opening = items(&c, &selected);
                    let (success, peak) = execute(redeem.clone(), opening.clone());
                    assert!(success, "n={n} t={t} selected={selected:?}");
                    branches += 1;
                    max_peak = max_peak.max(peak);
                    max_scriptsig =
                        max_scriptsig.max(serialized_scriptsig(&opening, &redeem).len());
                    let mut bad = opening.clone();
                    bad[0] = c[(selected[t - 1] + 1) % n].signature.clone();
                    assert!(
                        !execute(redeem.clone(), bad).0,
                        "signature mismatch accepted"
                    );
                    let mut bad = opening.clone();
                    bad[1] = c[(selected[t - 1] + 1) % n].target.clone();
                    assert!(!execute(redeem.clone(), bad).0, "target mismatch accepted");
                    let mut bad = opening.clone();
                    bad[2] = c[(selected[t - 1] + 1) % n].companion.clone();
                    assert!(
                        !execute(redeem.clone(), bad).0,
                        "companion mismatch accepted"
                    );
                    for index in [vec![n as u8], vec![0x81]] {
                        let mut bad = opening.clone();
                        *bad.last_mut().unwrap() = index;
                        assert!(!execute(redeem.clone(), bad).0, "out-of-range accepted");
                    }
                    if t >= 2 {
                        let mut repeated = selected.clone();
                        repeated[1] = repeated[0];
                        assert!(
                            !execute(redeem.clone(), items(&c, &repeated)).0,
                            "duplicate accepted"
                        );
                        let mut reversed = selected.clone();
                        reversed.reverse();
                        assert!(
                            !execute(redeem.clone(), items(&c, &reversed)).0,
                            "descending accepted"
                        );
                    }
                }
            }
            println!("n={n} t={t} script_bytes={} static_ops={static_ops} fits_p2sh={} valid_subsets={branches} hint_items={t} input_items={} max_stack={max_peak} max_scriptsig_bytes={max_scriptsig}",redeem.len(),redeem.len()<=520,4*t);
        }
    }
}
