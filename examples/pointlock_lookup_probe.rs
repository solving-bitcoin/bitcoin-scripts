//! Research-only destructive lookup for t-of-n HASH160 point-lock subsets.
//! Removing a selected row enforces distinctness. No complete Core transaction validation.
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
fn subset(
    c: &[Candidate],
    t: usize,
    full_keys: bool,
    depth_hint: bool,
    alt_inputs: bool,
) -> ScriptBuf {
    assert!(t > 0 && t <= c.len());
    let n = c.len();
    script! {
        if alt_inputs {
            for _ in 0..(t * if full_keys {2} else {4}) { OP_TOALTSTACK }
        }
        for row in c {
            if full_keys {
                { row.target.clone() } { row.companion.clone() }
            } else {
                { hash160::Hash::hash(&row.target).to_byte_array().to_vec() }
                { hash160::Hash::hash(&row.companion).to_byte_array().to_vec() }
            }
            { hash160::Hash::hash(&row.signature).to_byte_array().to_vec() }
        }
        for j in 0..t {
            // Each successful selection removes exactly one complete row.
            for _ in 0..(if full_keys { 2 } else { 4 }) {
                if alt_inputs { OP_FROMALTSTACK } else {
                    { 3*(n-j) + if full_keys { 1 } else { 3 } } OP_ROLL
                }
            }
            if depth_hint {
                // Authentication of sigma makes only signature-hash slots usable.
                OP_DUP { if full_keys { 1 } else { 3 } }
                { 3*(n-j) + 1 - if full_keys { 2 } else { 0 } } OP_WITHIN OP_VERIFY
            } else {
                OP_DUP 0 { n-j } OP_WITHIN OP_VERIFY
                { n-j } OP_SWAP OP_SUB OP_DUP OP_DUP OP_ADD OP_ADD
                if full_keys { 2 OP_SUB }
            }
            OP_DUP OP_TOALTSTACK OP_ROLL
            { if full_keys { 1 } else { 3 } } OP_PICK OP_HASH160 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_ROLL
            if full_keys {
                OP_FROMALTSTACK OP_1ADD OP_ROLL
            } else {
                1 OP_PICK OP_HASH160 OP_EQUALVERIFY
                OP_FROMALTSTACK OP_ROLL
                2 OP_PICK OP_HASH160 OP_EQUALVERIFY
            }
            OP_ROT OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
            OP_DUP OP_ROT OP_CHECKSIGVERIFY OP_SWAP OP_CHECKSIGVERIFY
        }
        for _ in 0..3*(n-t) { OP_DROP }
        OP_TRUE
    }
    .compile_with_policy()
}
fn variable_subset(
    c: &[Candidate],
    t: usize,
    full_keys: bool,
    depth_hint: bool,
    alt_inputs: bool,
) -> ScriptBuf {
    assert!(t > 0 && t <= c.len());
    assert!(!full_keys && depth_hint && alt_inputs);
    let n = c.len();
    script! {
        if alt_inputs {
            for _ in 0..(t * if full_keys {2} else {4}) { OP_TOALTSTACK }
        }
        for row in c {
            if full_keys {
                { row.target.clone() } { row.companion.clone() }
            } else {
                { hash160::Hash::hash(&row.target).to_byte_array().to_vec() }
                { hash160::Hash::hash(&row.companion).to_byte_array().to_vec() }
            }
            { hash160::Hash::hash(&row.signature).to_byte_array().to_vec() }
        }
        for j in 0..t {
            // Each successful selection removes exactly one complete row.
            for _ in 0..(if full_keys { 2 } else { 4 }) {
                if alt_inputs { OP_FROMALTSTACK } else {
                    { 3*(n-j) + if full_keys { 1 } else { 3 } } OP_ROLL
                }
            }
            if j > 0 {
                // Sentinel zero skips this opening and discards an unused table row.
                OP_DUP OP_NOTIF
                    for _ in 0..7 { OP_DROP }
                OP_ELSE
            }
            if depth_hint {
                // Authentication of sigma makes only signature-hash slots usable.
                OP_DUP { if full_keys { 1 } else { 3 } }
                { 3*(n-j) + 1 - if full_keys { 2 } else { 0 } } OP_WITHIN OP_VERIFY
            } else {
                OP_DUP 0 { n-j } OP_WITHIN OP_VERIFY
                { n-j } OP_SWAP OP_SUB OP_DUP OP_DUP OP_ADD OP_ADD
                if full_keys { 2 OP_SUB }
            }
            OP_DUP OP_TOALTSTACK OP_ROLL
            { if full_keys { 1 } else { 3 } } OP_PICK OP_HASH160 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_ROLL
            if full_keys {
                OP_FROMALTSTACK OP_1ADD OP_ROLL
            } else {
                1 OP_PICK OP_HASH160 OP_EQUALVERIFY
                OP_FROMALTSTACK OP_ROLL
                2 OP_PICK OP_HASH160 OP_EQUALVERIFY
            }
            OP_ROT OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
            OP_DUP OP_ROT OP_CHECKSIGVERIFY OP_SWAP OP_CHECKSIGVERIFY
            if j > 0 { OP_ENDIF }
        }
        for _ in 0..3*(n-t) { OP_DROP }
        OP_TRUE
    }
    .compile_with_policy()
}
fn items(
    c: &[Candidate],
    selected: &[usize],
    full_keys: bool,
    depth_hint: bool,
    alt_inputs: bool,
) -> Vec<Vec<u8>> {
    let mut remaining: Vec<usize> = (0..c.len()).collect();
    let mut openings = Vec::new();
    for &i in selected {
        let residual = remaining
            .iter()
            .position(|&j| j == i)
            .expect("distinct selection");
        let index = if depth_hint {
            3 * (remaining.len() - residual) - if full_keys { 2 } else { 0 }
        } else {
            residual
        };
        remaining.remove(residual);
        let row = &c[i];
        let mut frame = vec![row.signature.clone()];
        if !full_keys {
            frame.extend([row.target.clone(), row.companion.clone()]);
        }
        frame.push(if index == 0 {
            vec![]
        } else {
            vec![index as u8]
        });
        openings.push(frame);
    }
    if alt_inputs {
        openings.into_iter().flatten().collect()
    } else {
        openings.into_iter().rev().flatten().collect()
    }
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
    write_vectors();
    probe_variable();
    write_variable_vectors();
    println!(
        "compiler={:?} interpreter={:?}",
        bitcoin_lab::support::provenance::compiler().unwrap(),
        bitcoin_lab::support::provenance::interpreter().unwrap()
    );
    for alt_inputs in [false, true] {
        for full_keys in [false, true] {
            for depth_hint in [false, true] {
                for n in 2..=7 {
                    let c = candidates(n);
                    for t in 1..=3.min(n) {
                        let redeem = subset(&c, t, full_keys, depth_hint, alt_inputs);
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
                                let selected: Vec<_> =
                                    (0..n).filter(|i| mask & (1 << i) != 0).collect();
                                let opening =
                                    items(&c, &selected, full_keys, depth_hint, alt_inputs);
                                let (success, peak) = execute(redeem.clone(), opening.clone());
                                assert!(success, "n={n} t={t} selected={selected:?}");
                                branches += 1;
                                max_peak = max_peak.max(peak);
                                max_scriptsig = max_scriptsig
                                    .max(serialized_scriptsig(&opening, &redeem).len());
                                let mut bad = opening.clone();
                                bad[0] = c[(selected[if alt_inputs { 0 } else { t - 1 }] + 1) % n]
                                    .signature
                                    .clone();
                                assert!(
                                    !execute(redeem.clone(), bad).0,
                                    "signature mismatch accepted"
                                );
                                if !full_keys {
                                    let mut bad = opening.clone();
                                    bad[1] = c
                                        [(selected[if alt_inputs { 0 } else { t - 1 }] + 1) % n]
                                        .target
                                        .clone();
                                    assert!(
                                        !execute(redeem.clone(), bad).0,
                                        "target mismatch accepted"
                                    );
                                    let mut bad = opening.clone();
                                    bad[2] = c
                                        [(selected[if alt_inputs { 0 } else { t - 1 }] + 1) % n]
                                        .companion
                                        .clone();
                                    assert!(
                                        !execute(redeem.clone(), bad).0,
                                        "companion mismatch accepted"
                                    );
                                }
                                for index in [vec![3 * n as u8 + 4], vec![0x81]] {
                                    let mut bad = opening.clone();
                                    *bad.last_mut().unwrap() = index;
                                    assert!(
                                        !execute(redeem.clone(), bad).0,
                                        "out-of-range accepted"
                                    );
                                }
                                if depth_hint {
                                    for index in 0..=3 * n + 3 {
                                        if index
                                            == *opening.last().unwrap().first().unwrap_or(&0)
                                                as usize
                                        {
                                            continue;
                                        }
                                        let mut bad = opening.clone();
                                        *bad.last_mut().unwrap() = if index == 0 {
                                            vec![]
                                        } else {
                                            vec![index as u8]
                                        };
                                        assert!(
                                            !execute(redeem.clone(), bad).0,
                                            "incorrect depth accepted"
                                        );
                                    }
                                }
                                if t >= 2 {
                                    // Replace the second opening's actual payload with the first.
                                    // The second index still addresses a different physical table row.
                                    let mut repeated = opening.clone();
                                    let width = if full_keys { 2 } else { 4 };
                                    for k in 0..width - 1 {
                                        repeated[(t - 2) * width + k] =
                                            repeated[(t - 1) * width + k].clone();
                                    }
                                    assert!(
                                        !execute(redeem.clone(), repeated).0,
                                        "duplicate accepted"
                                    );
                                    let mut reversed = selected.clone();
                                    reversed.reverse();
                                    assert!(
                                        execute(
                                            redeem.clone(),
                                            items(&c, &reversed, full_keys, depth_hint, alt_inputs)
                                        )
                                        .0,
                                        "order-independent subset failed"
                                    );
                                }
                            }
                        }
                        println!("alt_inputs={alt_inputs} full_keys={full_keys} depth_hint={depth_hint} n={n} t={t} script_bytes={} static_ops={static_ops} fits_p2sh={} valid_subsets={branches} hint_items={t} input_items={} max_stack={max_peak} max_scriptsig_bytes={max_scriptsig}",redeem.len(),redeem.len()<=520,if full_keys {2*t} else {4*t});
                    }
                }
            }
        }
    }
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|v| format!("{v:02x}")).collect()
}
fn write_vectors() {
    let mut cases = Vec::new();
    for (n, t, full_keys, depth_hint, alt_inputs) in [
        (6, 2, false, true, true),
        (6, 3, false, true, true),
        (5, 2, true, true, false),
        (6, 2, false, false, true),
    ] {
        let c = candidates(n);
        let redeem = subset(&c, t, full_keys, depth_hint, alt_inputs);
        let variant = format!("lookup-full-{full_keys}-depth-{depth_hint}-alt-{alt_inputs}");
        let static_ops = redeem
            .instructions()
            .filter(|i| matches!(i,Ok(bitcoin::script::Instruction::Op(op)) if op.to_u8()>0x60))
            .count();
        let mut add = |name: String, opening: Vec<Vec<u8>>, expected: bool| {
            assert_eq!(
                execute(redeem.clone(), opening.clone()).0,
                expected,
                "{variant} {name}"
            );
            cases.push(serde_json::json!({
                "name":format!("{variant}-{n}-{t}-{name}"), "variant":variant,"n":n,"t":t,
                "script_hex":hex_encode(redeem.as_bytes()),
                "items_hex":opening.iter().map(|v|hex_encode(v)).collect::<Vec<_>>(),
                "p2sh_script_sig_hex":hex_encode(serialized_scriptsig(&opening,&redeem).as_bytes()),
                "expected":expected,"expected_policy":expected,"hint_items":t,
                "compiler_static_ops":static_ops,"compiler_charged_ops":static_ops,
            }));
        };
        for mask in 0..1usize << n {
            if mask.count_ones() as usize != t {
                continue;
            }
            let selected: Vec<_> = (0..n).filter(|i| mask & (1 << i) != 0).collect();
            add(
                format!("subset-{selected:?}"),
                items(&c, &selected, full_keys, depth_hint, alt_inputs),
                true,
            );
        }
        let selected: Vec<_> = (0..t).collect();
        let opening = items(&c, &selected, full_keys, depth_hint, alt_inputs);
        let width = if full_keys { 2 } else { 4 };
        for field in 0..width - 1 {
            let mut bad = opening.clone();
            bad[field] = match field {
                0 => c[n - 1].signature.clone(),
                1 => c[n - 1].target.clone(),
                _ => c[n - 1].companion.clone(),
            };
            add(format!("mismatched-field-{field}"), bad, false);
        }
        let mut duplicate = opening.clone();
        for k in 0..width - 1 {
            duplicate[width + k] = duplicate[k].clone();
        }
        add("duplicate-opening".into(), duplicate, false);
        for index in 0..=3 * n + 3 {
            if index == *opening.last().unwrap().first().unwrap_or(&0) as usize {
                continue;
            }
            let mut bad = opening.clone();
            *bad.last_mut().unwrap() = if index == 0 {
                vec![]
            } else {
                vec![index as u8]
            };
            add(format!("wrong-index-{index}"), bad, false);
        }
    }
    let out = serde_json::json!({"compiler":bitcoin_lab::support::provenance::compiler().unwrap().commit,
        "interpreter":bitcoin_lab::support::provenance::interpreter().unwrap().commit,"cases":cases});
    std::fs::write(
        "research/pointlocks-2026-09-17/lookup-vectors.json",
        serde_json::to_string_pretty(&out).unwrap() + "\n",
    )
    .unwrap();
}

fn variable_items(c: &[Candidate], selected: &[usize], max_t: usize) -> Vec<Vec<u8>> {
    let mut opening = items(c, selected, false, true, true);
    for _ in selected.len()..max_t {
        opening.extend([vec![], vec![], vec![], vec![]]);
    }
    opening
}
fn probe_variable() {
    for n in 3..=6 {
        let c = candidates(n);
        for max_t in 2..=4.min(n) {
            let redeem = variable_subset(&c, max_t, false, true, true);
            let static_ops = redeem
                .instructions()
                .filter(|i| matches!(i,Ok(bitcoin::script::Instruction::Op(op)) if op.to_u8()>0x60))
                .count();
            if redeem.len() > 520 {
                println!("variable n={n} max_t={max_t} script_bytes={} static_ops={static_ops} fits_p2sh=false",redeem.len());
                continue;
            }
            for t in 1..=max_t {
                let mut peak = 0;
                let mut max_scriptsig = 0;
                let mut count = 0;
                for mask in 0..1usize << n {
                    if mask.count_ones() as usize != t {
                        continue;
                    }
                    let selected: Vec<_> = (0..n).filter(|i| mask & (1 << i) != 0).collect();
                    let opening = variable_items(&c, &selected, max_t);
                    let (ok, p) = execute(redeem.clone(), opening.clone());
                    assert!(ok, "variable {n} {max_t} {selected:?}");
                    peak = peak.max(p);
                    max_scriptsig =
                        max_scriptsig.max(serialized_scriptsig(&opening, &redeem).len());
                    count += 1;
                    let mut bad = opening.clone();
                    bad[0] = c[(selected[0] + 1) % n].signature.clone();
                    assert!(
                        !execute(redeem.clone(), bad).0,
                        "variable mismatched signature"
                    );
                    if t > 1 {
                        let mut bad = opening.clone();
                        for k in 0..3 {
                            bad[4 + k] = bad[k].clone();
                        }
                        assert!(
                            !execute(redeem.clone(), bad).0,
                            "variable duplicate opening"
                        );
                    }
                }
                println!("variable n={n} max_t={max_t} t={t} script_bytes={} static_ops={static_ops} valid_subsets={count} hint_items={max_t} input_items={} max_stack={peak} max_scriptsig_bytes={max_scriptsig}",redeem.len(),4*max_t);
            }
            assert!(
                !execute(redeem.clone(), variable_items(&c, &[], max_t)).0,
                "variable empty subset accepted"
            );
        }
    }
}

fn write_variable_vectors() {
    let mut cases = Vec::new();
    for (n, max_t) in [(5, 3), (5, 4), (6, 2)] {
        let c = candidates(n);
        let redeem = variable_subset(&c, max_t, false, true, true);
        let static_ops = redeem
            .instructions()
            .filter(|i| matches!(i,Ok(bitcoin::script::Instruction::Op(op)) if op.to_u8()>0x60))
            .count();
        let mut add = |name: String, opening: Vec<Vec<u8>>, expected: bool| {
            assert_eq!(
                execute(redeem.clone(), opening.clone()).0,
                expected,
                "variable-vector {name}"
            );
            cases.push(serde_json::json!({
                "name":format!("variable-lookup-{n}-{max_t}-{name}"), "variant":"variable-lookup","n":n,"t":max_t,
                "script_hex":hex_encode(redeem.as_bytes()),"items_hex":opening.iter().map(|v|hex_encode(v)).collect::<Vec<_>>(),
                "p2sh_script_sig_hex":hex_encode(serialized_scriptsig(&opening,&redeem).as_bytes()),
                "expected":expected,"expected_policy":expected,"hint_items":max_t,
                "compiler_static_ops":static_ops,"compiler_charged_ops":static_ops,
            }));
        };
        for t in 1..=max_t {
            for mask in 0..1usize << n {
                if mask.count_ones() as usize != t {
                    continue;
                }
                let selected: Vec<_> = (0..n).filter(|i| mask & (1 << i) != 0).collect();
                add(
                    format!("subset-{selected:?}"),
                    variable_items(&c, &selected, max_t),
                    true,
                );
            }
        }
        add("empty-subset".into(), variable_items(&c, &[], max_t), false);
        let opening = variable_items(&c, &[0, 1], max_t);
        let mut duplicate = opening.clone();
        for k in 0..3 {
            duplicate[4 + k] = duplicate[k].clone();
        }
        add("duplicate-opening".into(), duplicate, false);
        for field in 0..3 {
            let mut bad = opening.clone();
            bad[field] = match field {
                0 => c[n - 1].signature.clone(),
                1 => c[n - 1].target.clone(),
                _ => c[n - 1].companion.clone(),
            };
            add(format!("mismatched-field-{field}"), bad, false);
        }
        for index in 0..=3 * n + 3 {
            if index == opening[3][0] as usize {
                continue;
            }
            let mut bad = opening.clone();
            bad[3] = if index == 0 {
                vec![]
            } else {
                vec![index as u8]
            };
            add(format!("wrong-index-{index}"), bad, false);
        }
    }
    let out = serde_json::json!({"compiler":bitcoin_lab::support::provenance::compiler().unwrap().commit,
        "interpreter":bitcoin_lab::support::provenance::interpreter().unwrap().commit,"cases":cases});
    std::fs::write(
        "research/pointlocks-2026-09-17/lookup-variable-vectors.json",
        serde_json::to_string_pretty(&out).unwrap() + "\n",
    )
    .unwrap();
}
