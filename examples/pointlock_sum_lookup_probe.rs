//! Common-key sum locks with a destructive table of HASH160(P) commitments.
use bitcoin::{
    absolute,
    hashes::{hash160, Hash},
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    transaction, Amount, EcdsaSighashType, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};
use bitcoin_lab::{
    signatures::pointlocks,
    support::{
        provenance,
        script::{script, ScriptCompilation},
    },
};
use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};
use num_bigint::BigUint;
use serde_json::json;
#[derive(Clone)]
pub(crate) struct Candidate {
    pub(crate) signature: Vec<u8>,
    pub(crate) key: Vec<u8>,
}
fn bytes(v: &BigUint) -> [u8; 32] {
    let v = v.to_bytes_be();
    let mut b = [0; 32];
    b[32 - v.len()..].copy_from_slice(&v);
    b
}
pub(crate) fn candidates(n: usize) -> (Vec<Candidate>, Vec<u8>) {
    let secp = Secp256k1::new();
    let order = BigUint::parse_bytes(
        b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .unwrap();
    let one = SecretKey::from_slice(&bytes(&BigUint::from(1u8))).unwrap();
    let g = PublicKey::from_secret_key(&secp, &one);
    let digest = pointlocks::sighash_single_bug_message();
    let z = BigUint::from_bytes_be(&digest);
    let mut out = vec![];
    let mut counter = 1u64;
    while out.len() < n {
        // Public deterministic research fixtures. Production nonces must be independent and secret.
        let nonce = SecretKey::from_slice(
            &bitcoin::hashes::sha256::Hash::hash(&counter.to_be_bytes()).to_byte_array(),
        )
        .unwrap();
        counter += 1;
        let sig =
            pointlocks::sign_with_nonce(digest, one, nonce, EcdsaSighashType::Single).unwrap();
        if sig.to_vec().len() != 71 {
            continue;
        }
        let r = BigUint::from_bytes_be(&sig.signature.serialize_compact()[..32]);
        let t = (&order
            - BigUint::from(2u8) * &z * r.modpow(&(&order - BigUint::from(2u8)), &order) % &order)
            % &order;
        let target = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&bytes(&t)).unwrap());
        let key = target.combine(&g.negate(&secp)).unwrap();
        assert_ne!(key, g);
        secp.verify_ecdsa(
            &bitcoin::secp256k1::Message::from_digest(digest),
            &sig.signature,
            &key,
        )
        .unwrap();
        out.push(Candidate {
            signature: sig.to_vec(),
            key: key.serialize().to_vec(),
        });
    }
    (out, g.serialize().to_vec())
}
pub(crate) fn redeem(c: &[Candidate], t: usize, g: &[u8]) -> ScriptBuf {
    validate_pool(c, t, g);
    script! {
     for _ in 0..3*t {OP_TOALTSTACK}
     {g.to_vec()}
     for row in c {{hash160::Hash::hash(&row.key).to_byte_array().to_vec()}}
     for j in 0..t {
      OP_FROMALTSTACK OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
      OP_FROMALTSTACK OP_FROMALTSTACK
      OP_DUP 2 {c.len()-j+2} OP_WITHIN OP_VERIFY
      OP_ROLL OP_OVER OP_HASH160 OP_EQUALVERIFY
      OP_OVER {c.len()-j+2} OP_PICK OP_CHECKSIGVERIFY OP_CHECKSIGVERIFY
     }
     for _ in 0..(c.len()-t+1) {OP_DROP}
     OP_TRUE
    }
    .compile_with_policy()
}
pub(crate) fn variable_redeem(c: &[Candidate], t: usize, g: &[u8]) -> ScriptBuf {
    validate_pool(c, t, g);
    script! {
     for _ in 0..3*t {OP_TOALTSTACK}
     {g.to_vec()}
     for row in c {{hash160::Hash::hash(&row.key).to_byte_array().to_vec()}}
     for j in 0..t {
      OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
      if j>0 {OP_DUP OP_NOTIF OP_2DROP OP_2DROP OP_ELSE}
      OP_DUP 2 {c.len()-j+2} OP_WITHIN OP_VERIFY
      OP_ROLL OP_OVER OP_HASH160 OP_EQUALVERIFY
      OP_OVER OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
      {c.len()-j+2} OP_PICK OP_CHECKSIGVERIFY OP_CHECKSIGVERIFY
      if j>0 {OP_ENDIF}
     }
     for _ in 0..(c.len()-t+1) {OP_DROP}
     OP_TRUE
    }
    .compile_with_policy()
}
fn validate_pool(c: &[Candidate], t: usize, g: &[u8]) {
    assert!(t > 0 && t <= c.len());
    let generator = PublicKey::from_slice(g).unwrap();
    let mut hashes = std::collections::HashSet::new();
    for candidate in c {
        let key = PublicKey::from_slice(&candidate.key).unwrap();
        pointlocks::sum_key::target_point(key, generator).expect("nondegenerate sum lock");
        assert!(
            hashes.insert(hash160::Hash::hash(&candidate.key)),
            "duplicate table commitment"
        );
    }
}
pub(crate) fn items(c: &[Candidate], selected: &[usize]) -> Vec<Vec<u8>> {
    let mut remaining: Vec<_> = (0..c.len()).collect();
    let mut out = vec![];
    for &i in selected {
        let position = remaining.iter().position(|v| *v == i).unwrap();
        let depth = remaining.len() + 1 - position;
        remaining.remove(position);
        out.extend([c[i].signature.clone(), c[i].key.clone(), vec![depth as u8]]);
    }
    out
}
fn execute(s: &ScriptBuf, items: Vec<Vec<u8>>) -> (bool, usize) {
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
    let mut e = Exec::new(
        ExecCtx::Legacy,
        Options::default(),
        TxTemplate {
            tx,
            prevouts: vec![],
            input_idx: 1,
            taproot_annex_scriptleaf: None,
        },
        s.clone(),
        items,
    )
    .unwrap();
    while e.exec_next().is_ok() {}
    (
        e.result().unwrap().success && e.stack().len() == 1,
        e.stats().max_nb_stack_items,
    )
}
fn push_script(items: &[Vec<u8>], script: &ScriptBuf) -> ScriptBuf {
    let mut b = bitcoin::script::Builder::new();
    for item in items {
        b = if item.is_empty() {
            b.push_int(0)
        } else if item.len() == 1 && (1..=16).contains(&item[0]) {
            b.push_int(item[0] as i64)
        } else {
            b.push_slice(bitcoin::script::PushBytesBuf::try_from(item.clone()).unwrap())
        };
    }
    b.push_slice(bitcoin::script::PushBytesBuf::try_from(script.to_bytes()).unwrap())
        .into_script()
}
fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    let (all, g) = candidates(22);
    let mut metrics = vec![];
    let mut cases = vec![];
    let mut variable_metrics = vec![];
    for n in 2..=22 {
        for t in 1..=7.min(n) {
            let c = &all[..n];
            let s = redeem(c, t, &g);
            let ops = s
                .instructions()
                .filter(|v| matches!(v,Ok(bitcoin::script::Instruction::Op(op)) if op.to_u8()>0x60))
                .count();
            if s.len() > 520 || ops > 201 {
                continue;
            }
            let sel: Vec<_> = (0..t).collect();
            let opening = items(c, &sel);
            let (ok, peak) = execute(&s, opening.clone());
            assert!(ok, "n={n} t={t}");
            metrics.push(json!({"n":n,"t":t,"script_bytes":s.len(),"script_sig_bytes":push_script(&opening,&s).len(),"static_non_push_ops":ops,"accurate_sigops":2*t,"hint_items":t,"entry_items":3*t,"combined_stack_peak":peak,"signature_bytes":71}));
            if (n, t) == (17, 4) || (n, t) == (18, 3) || (n, t) == (16, 4) {
                // First, last, interleaved selections and malformed data, deterministically.
                let selections = vec![sel, (n - t..n).collect(), (0..t).map(|i| 2 * i).collect()];
                for selected in selections {
                    let opening = items(c, &selected);
                    assert!(execute(&s, opening.clone()).0);
                    let mut variants = vec![("valid", opening.clone(), true)];
                    let mut bad = opening.clone();
                    bad[0][0] ^= 1;
                    variants.push(("malformed-signature", bad, false));
                    let mut bad = opening.clone();
                    bad[0] = vec![1; 57];
                    variants.push(("short-signature", bad, false));
                    let mut bad = opening.clone();
                    bad[1] = all[n].key.clone();
                    variants.push(("uncommitted-key", bad, false));
                    let mut bad = opening.clone();
                    bad[2] = vec![1];
                    variants.push(("wrong-depth", bad, false));
                    let mut bad = opening.clone();
                    bad[2] = vec![255, 0];
                    variants.push(("out-of-range", bad, false));
                    let mut bad = opening.clone();
                    bad[3] = opening[0].clone();
                    bad[4] = opening[1].clone();
                    variants.push(("duplicate-selection", bad, false));
                    for (name, opening, expected) in variants {
                        assert_eq!(
                            execute(&s, opening.clone()).0,
                            expected,
                            "{n}/{t}/{selected:?}/{name}"
                        );
                        cases.push(json!({"name":format!("sum-lookup-{t}-of-{n}-{selected:?}-{name}"),"variant":"sum-key-hash160-lookup","n":n,"t":t,"expected":expected,"expected_policy":expected,"script_hex":hex(s.as_bytes()),"items_hex":opening.iter().map(|v|hex(v)).collect::<Vec<_>>(),"p2sh_script_sig_hex":hex(push_script(&opening,&s).as_bytes()),"hint_items":t}));
                    }
                }
            }
        }
    }
    for n in 5..=19 {
        for max_t in 2..=5.min(n) {
            let c = &all[..n];
            let s = variable_redeem(c, max_t, &g);
            let ops = s
                .instructions()
                .filter(|v| matches!(v,Ok(bitcoin::script::Instruction::Op(op)) if op.to_u8()>0x60))
                .count();
            if s.len() > 520 || ops > 201 {
                continue;
            }
            let mut sizes = vec![];
            let mut peak = 0;
            for t in 1..=max_t {
                let sel: Vec<_> = (0..t).collect();
                let mut opening = items(c, &sel);
                opening.resize(3 * max_t, vec![]);
                let (ok, actual_peak) = execute(&s, opening.clone());
                assert!(ok, "variable{n}/{max_t}/{t}");
                peak = peak.max(actual_peak);
                sizes.push(push_script(&opening, &s).len());
                if n >= 14 && max_t >= 3 {
                    let mut variants = vec![("valid", opening.clone(), true)];
                    let mut bad = opening.clone();
                    bad[0][0] ^= 1;
                    variants.push(("malformed-signature", bad, false));
                    let mut bad = opening.clone();
                    bad[0] = vec![1; 57];
                    variants.push(("short-signature", bad, false));
                    let mut bad = opening.clone();
                    bad[1] = all[n].key.clone();
                    variants.push(("uncommitted-key", bad, false));
                    let mut bad = opening.clone();
                    bad[2] = vec![1];
                    variants.push(("wrong-depth", bad, false));
                    variants.push(("all-empty", vec![vec![]; 3 * max_t], false));
                    if t > 1 {
                        let mut bad = opening.clone();
                        bad[3] = opening[0].clone();
                        bad[4] = opening[1].clone();
                        variants.push(("duplicate-selection", bad, false));
                    }
                    for (name, opening, expected) in variants {
                        assert_eq!(
                            execute(&s, opening.clone()).0,
                            expected,
                            "variable{n}/{max_t}/{t}/{name}"
                        );
                        cases.push(json!({"name":format!("sum-lookup-variable-{max_t}-of-{n}-t{t}-{name}"),"variant":"sum-key-hash160-lookup-variable","n":n,"t":t,"max_t":max_t,"expected":expected,"expected_policy":expected,"script_hex":hex(s.as_bytes()),"items_hex":opening.iter().map(|v|hex(v)).collect::<Vec<_>>(),"p2sh_script_sig_hex":hex(push_script(&opening,&s).as_bytes()),"hint_items":max_t}));
                    }
                }
            }
            variable_metrics.push(json!({"n":n,"max_t":max_t,"script_bytes":s.len(),"script_sig_bytes_by_t":sizes,"static_non_push_ops":ops,"accurate_sigops":2*max_t,"hint_items":max_t,"entry_items":3*max_t,"combined_stack_peak":peak,"signature_bytes":71}));
        }
    }
    let out = json!({"compiler":provenance::compiler().unwrap().commit,"interpreter":provenance::interpreter().unwrap().commit,"evidence":"locally-reproduced","deployment":"unclassified","signature_generation":"Independent public test nonces, retry for exactly71B low-S signatures","metrics":metrics,"variable_metrics":variable_metrics,"cases":cases});
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
