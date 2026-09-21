//! Compare equivalent CHECKSIG and exact-list CHECKMULTISIG subset verifiers.
//! Sorted indices enforce distinct selections. This generator measures bytes
//! and emits vectors; independent Core validation is recorded in
//! research/pointlocks-2026-09-17/multisig_core_check.json.
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
#[derive(Clone, Copy, Debug, PartialEq)]
enum Mode {
    Checksigs,
    ChecksigsOrdered,
    PairMultisig,
    PairOrdered,
    TwoBatches,
    OneBatch,
}

/// Assemble exact selected lists. The symbolic bookkeeping only chooses stack
/// depths; all signature/key validation happens in the generated Script.
fn batches(t: usize, mode: Mode) -> Script {
    let mut stack: Vec<String> = (0..t)
        .flat_map(|i| [format!("s{i}"), format!("T{i}"), format!("Q{i}")])
        .collect();
    let mut pieces: Vec<Script> = Vec::new();
    fn put(stack: &mut Vec<String>, parts: &mut Vec<Script>, value: usize) {
        parts.push(script! { { value } });
        stack.push("count-or-dummy".into());
    }
    fn get(stack: &mut Vec<String>, parts: &mut Vec<Script>, name: String, consume: bool) {
        let index = stack.iter().position(|v| v == &name).unwrap();
        let depth = stack.len() - index - 1;
        parts.push(if consume {
            script! {{ depth } OP_ROLL}
        } else {
            script! {{ depth } OP_PICK}
        });
        if consume {
            stack.remove(index);
        }
        stack.push("arranged".into());
    }
    match mode {
        Mode::OneBatch => {
            put(&mut stack, &mut pieces, 0);
            for i in 0..t {
                get(&mut stack, &mut pieces, format!("s{i}"), true);
                pieces.push(script! {OP_DUP});
                stack.push("duplicate".into());
            }
            put(&mut stack, &mut pieces, 2 * t);
            for i in 0..t {
                get(&mut stack, &mut pieces, format!("T{i}"), true);
                get(&mut stack, &mut pieces, format!("Q{i}"), true);
            }
            put(&mut stack, &mut pieces, 2 * t);
            pieces.push(script! {OP_CHECKMULTISIGVERIFY});
            stack.truncate(stack.len() - (4 * t + 3));
        }
        Mode::TwoBatches => {
            for key in ["T", "Q"] {
                put(&mut stack, &mut pieces, 0);
                for i in 0..t {
                    get(&mut stack, &mut pieces, format!("s{i}"), key == "Q");
                }
                put(&mut stack, &mut pieces, t);
                for i in 0..t {
                    get(&mut stack, &mut pieces, format!("{key}{i}"), true);
                }
                put(&mut stack, &mut pieces, t);
                pieces.push(script! {OP_CHECKMULTISIGVERIFY});
                stack.truncate(stack.len() - (2 * t + 3));
            }
        }
        _ => unreachable!(),
    }
    assert!(stack.is_empty());
    script! { for part in pieces { { part } } }
}
fn subset(c: &[Candidate], t: usize, mode: Mode) -> ScriptBuf {
    assert!(t > 0 && t <= c.len());
    let n = c.len();
    script! {
        for row in c {
            { hash160::Hash::hash(&row.target).to_byte_array().to_vec() }
            { hash160::Hash::hash(&row.companion).to_byte_array().to_vec() }
            { hash160::Hash::hash(&row.signature).to_byte_array().to_vec() }
        }
        -1 OP_TOALTSTACK
        for iteration in 0..t {
            // Move next (sigma,T,Q,index) from below the shared table.
            for _ in 0..4 { { 3*n+3+if matches!(mode,Mode::TwoBatches|Mode::OneBatch) {3*iteration} else {0} } OP_ROLL }
            // Strict ascending indices, with previous=-1 and index<n.
            OP_DUP { n } OP_LESSTHAN OP_VERIFY
            OP_DUP OP_FROMALTSTACK OP_GREATERTHAN OP_VERIFY
            OP_DUP OP_TOALTSTACK
            // Depth of h_sigma is 3*(n-index), with sigma,T,Q above table.
            { n } OP_SWAP OP_SUB OP_DUP OP_DUP OP_ADD OP_ADD
            if matches!(mode,Mode::TwoBatches|Mode::OneBatch) && iteration>0 { {3*iteration} OP_ADD }
            OP_DUP OP_TOALTSTACK OP_PICK
            { if matches!(mode, Mode::PairOrdered | Mode::ChecksigsOrdered) {1} else {3} } OP_PICK OP_HASH160 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1ADD OP_DUP OP_TOALTSTACK OP_PICK
            { if matches!(mode, Mode::PairOrdered | Mode::ChecksigsOrdered) {2} else {1} } OP_PICK OP_HASH160 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_1ADD OP_PICK
            { if matches!(mode, Mode::PairOrdered | Mode::ChecksigsOrdered) {3} else {2} } OP_PICK OP_HASH160 OP_EQUALVERIFY
            if matches!(mode, Mode::Checksigs | Mode::ChecksigsOrdered) {
                if !matches!(mode, Mode::PairOrdered | Mode::ChecksigsOrdered) { OP_ROT }
                OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
                OP_DUP OP_ROT OP_CHECKSIGVERIFY OP_SWAP OP_CHECKSIGVERIFY
            } else if matches!(mode,Mode::PairMultisig|Mode::PairOrdered) {
                // sigma T Q -> T Q sigma -> T Q dummy sigma sigma 2
                // -> dummy sigma sigma 2 T Q 2, an exact 2-of-2 check.
                if !matches!(mode, Mode::PairOrdered | Mode::ChecksigsOrdered) { OP_ROT }
                OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
                OP_0 OP_SWAP OP_DUP OP_2 OP_2ROT
                OP_2 OP_CHECKMULTISIGVERIFY
            } else {
                // Keep the authenticated tuple until all selected rows are ready.
                OP_2 OP_PICK OP_SIZE 57 OP_GREATERTHAN OP_VERIFY OP_DROP
            }
        }
        if matches!(mode,Mode::TwoBatches|Mode::OneBatch) {
            for _ in 0..3*t { OP_TOALTSTACK }
        }
        for _ in 0..3*n { OP_DROP }
        if matches!(mode,Mode::TwoBatches|Mode::OneBatch) {
            for _ in 0..3*t { OP_FROMALTSTACK }
            { batches(t,mode) }
        }
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
fn mode_items(c: &[Candidate], selected: &[usize], mode: Mode) -> Vec<Vec<u8>> {
    let mut result = items(c, selected);
    if matches!(mode, Mode::PairOrdered | Mode::ChecksigsOrdered) {
        for row in result.chunks_exact_mut(4) {
            row[..3].rotate_left(1);
        }
    }
    result
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
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|v| format!("{v:02x}")).collect()
}
fn main() {
    let compiler = bitcoin_lab::support::provenance::compiler().unwrap().commit;
    let interpreter = bitcoin_lab::support::provenance::interpreter()
        .unwrap()
        .commit;
    println!("compiler={compiler} interpreter={interpreter}");
    let mut vectors = Vec::new();
    for mode in [
        Mode::Checksigs,
        Mode::ChecksigsOrdered,
        Mode::PairMultisig,
        Mode::PairOrdered,
        Mode::TwoBatches,
        Mode::OneBatch,
    ] {
        for n in 2..=7 {
            let c = candidates(n);
            for t in 1..=3.min(n) {
                let redeem = subset(&c, t, mode);
                let static_ops = redeem
                    .instructions()
                    .filter(
                        |i| matches!(i,Ok(bitcoin::script::Instruction::Op(op)) if op.to_u8()>0x60),
                    )
                    .count();
                let mut branches = 0;
                let mut checked = 0;
                let mut max_peak = 0;
                let mut max_scriptsig = 0;
                let mut cases = Vec::new();
                for mask in 0..(1usize << n) {
                    if mask.count_ones() as usize != t {
                        continue;
                    }
                    let selected: Vec<_> = (0..n).filter(|i| mask & (1 << i) != 0).collect();
                    let opening = mode_items(&c, &selected, mode);
                    let scriptsig = serialized_scriptsig(&opening, &redeem);
                    branches += 1;
                    max_scriptsig = max_scriptsig.max(scriptsig.len());
                    let local = matches!(mode, Mode::Checksigs | Mode::ChecksigsOrdered)
                        && redeem.len() <= 520;
                    if local {
                        let (success, peak) = execute(redeem.clone(), opening.clone());
                        assert!(success, "n={n} t={t} selected={selected:?}");
                        checked += 1;
                        max_peak = max_peak.max(peak);
                    }
                    let mut add_case = |name: String, data: Vec<Vec<u8>>, expected: bool| {
                        if local {
                            assert_eq!(
                                execute(redeem.clone(), data.clone()).0,
                                expected,
                                "{mode:?} n={n} t={t} {name}"
                            );
                        }
                        cases.push(serde_json::json!({"name":name,"expected":expected,"items":data.iter().map(|v|hex_encode(v)).collect::<Vec<_>>(),"script_sig":hex_encode(serialized_scriptsig(&data,&redeem).as_bytes())}));
                    };
                    add_case(format!("subset-{selected:?}"), opening.clone(), true);
                    for (field, label) in [(0, "signature"), (1, "target"), (2, "companion")] {
                        let mut bad = opening.clone();
                        let field = if matches!(mode, Mode::PairOrdered | Mode::ChecksigsOrdered) {
                            (field + 2) % 3
                        } else {
                            field
                        };
                        let other = &c[(selected[t - 1] + 1) % n];
                        bad[field] = match label {
                            "signature" => other.signature.clone(),
                            "target" => other.target.clone(),
                            _ => other.companion.clone(),
                        };
                        add_case(format!("subset-{selected:?}-{label}-mismatch"), bad, false);
                    }
                    for (label, index) in
                        [("index-n", vec![n as u8]), ("index-negative", vec![0x81])]
                    {
                        let mut bad = opening.clone();
                        *bad.last_mut().unwrap() = index;
                        add_case(format!("subset-{selected:?}-{label}"), bad, false);
                    }
                    if t >= 2 {
                        let mut repeated = selected.clone();
                        repeated[1] = repeated[0];
                        add_case(
                            format!("subset-{selected:?}-duplicate"),
                            mode_items(&c, &repeated, mode),
                            false,
                        );
                        let mut reversed = selected.clone();
                        reversed.reverse();
                        add_case(
                            format!("subset-{selected:?}-descending"),
                            mode_items(&c, &reversed, mode),
                            false,
                        );
                    }
                }
                // Static opcode count excludes the CHECKMULTISIG public-key
                // surcharge. Every path here executes all multisig instructions.
                let charged_ops = static_ops
                    + if matches!(mode, Mode::Checksigs | Mode::ChecksigsOrdered) {
                        0
                    } else {
                        2 * t
                    };
                println!("mode={mode:?} n={n} t={t} script_bytes={} static_ops={static_ops} charged_ops={charged_ops} fits_p2sh={} subsets={branches} locally_checked_subsets={checked} hint_items={t} input_items={} local_max_stack={max_peak} max_scriptsig_bytes={max_scriptsig}",redeem.len(),redeem.len()<=520,4*t);
                vectors.push(serde_json::json!({"mode":format!("{mode:?}"),"n":n,"t":t,"redeem_script":hex_encode(redeem.as_bytes()),"script_bytes":redeem.len(),"static_ops":static_ops,"charged_ops":charged_ops,"fits_p2sh":redeem.len()<=520,"hint_items":t,"input_items":4*t,"max_scriptsig_bytes":max_scriptsig,"local_max_stack":if checked>0 {Some(max_peak)}else{None},"cases":cases}));
            }
        }
    }
    if let Some(path) = std::env::args().nth(1) {
        let output = serde_json::json!({"compiler":compiler,"interpreter":interpreter,"evidence":"locally-reproduced","deployment":"unclassified","note":"CHECKMULTISIG is unimplemented in the pinned local interpreter. Its variants are compiled vectors for independent validation. script_sig includes the redeem push; legacy inputs have no witness.","configurations":vectors});
        std::fs::write(path, serde_json::to_vec_pretty(&output).unwrap()).unwrap();
    }
}
