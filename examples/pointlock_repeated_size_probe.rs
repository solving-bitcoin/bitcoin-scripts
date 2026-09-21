//! Size-only probe for repeated capped ECDSA checks on publicly scaled keys.
//! Cryptographic amplification is a separate, unproven assumption.
use bitcoin::{
    absolute,
    consensus::serialize,
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    transaction, Amount, EcdsaSighashType, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};
use bitcoin_lab::{
    signatures::pointlocks,
    support::script::{script, ScriptCompilation},
};
use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};
use num_bigint::BigUint;
use serde_json::json;

fn key(i: usize) -> Vec<u8> {
    let mut a = [0; 32];
    a[24..].copy_from_slice(&(i as u64 + 1).to_be_bytes());
    PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&a).unwrap())
        .serialize()
        .to_vec()
}
fn choose(n: usize, t: usize) -> BigUint {
    let mut a = BigUint::from(1u8);
    for j in 0..t {
        a = a * BigUint::from(n - j) / BigUint::from(j + 1);
    }
    a
}
fn count(radix: &BigUint) -> usize {
    let mut a = BigUint::from(1u8);
    let target = BigUint::from(1u8) << 2048;
    let mut n = 0;
    while a < target {
        a *= radix;
        n += 1;
    }
    n
}
fn number(mut n: usize) -> Vec<u8> {
    let mut a = vec![];
    while n > 0 {
        a.push((n & 255) as u8);
        n >>= 8;
    }
    if a.last().map(|v| v & 128 != 0).unwrap_or(false) {
        a.push(0);
    }
    a
}
fn redeem(n: usize, t: usize, d: usize) -> ScriptBuf {
    script! {
        for _ in 0..t*(d+1){OP_TOALTSTACK}
        for i in 0..n*d{{key(i)}}
        for _ in 0..t{
            OP_FROMALTSTACK
            if d==3{OP_DUP OP_DUP OP_ADD OP_ADD}else{OP_DUP OP_ADD OP_DUP OP_ADD}
            2 OP_ADD
            for _ in 0..d{
                OP_FROMALTSTACK OP_SIZE 60 OP_LESSTHANOREQUAL OP_VERIFY
                OP_OVER OP_ROLL OP_CHECKSIGVERIFY
            }
            OP_DROP
        }
        for _ in 0..d*(n-t){OP_DROP}
        OP_TRUE
    }
    .compile_with_policy()
}
fn tx(input: Vec<TxIn>, output: Vec<TxOut>) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input,
        output,
    }
}
fn input(i: usize, witness: Witness) -> TxIn {
    TxIn {
        previous_output: OutPoint::null(),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::from_consensus(i as u32),
        witness,
    }
}
fn layout_check(n: usize, t: usize, d: usize) -> usize {
    let half = SecretKey::from_slice(&hex_bytes(
        "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1",
    ))
    .unwrap();
    let mut items = vec![];
    for row in 0..t {
        items.push(number(n - row - 1));
        for j in (0..d).rev() {
            let mut a = [0; 32];
            a[24..].copy_from_slice(&((row * d + j + 1) as u64).to_be_bytes());
            items.push(
                pointlocks::sign_with_nonce(
                    pointlocks::sighash_single_bug_message(),
                    SecretKey::from_slice(&a).unwrap(),
                    half,
                    EcdsaSighashType::Single,
                )
                .unwrap()
                .to_vec(),
            );
        }
    }
    let transaction = tx(
        vec![input(0, Witness::new()), input(1, Witness::new())],
        vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        }],
    );
    let mut e = Exec::new(
        ExecCtx::Legacy,
        Options::default(),
        TxTemplate {
            tx: transaction,
            prevouts: vec![],
            input_idx: 1,
            taproot_annex_scriptleaf: None,
        },
        redeem(n, t, d),
        items,
    )
    .unwrap();
    while e.exec_next().is_ok() {}
    assert!(e.result().unwrap().success);
    assert_eq!(e.stack().len(), 1);
    e.stats().max_nb_stack_items
}
fn hex_bytes(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}
fn pair(s: &ScriptBuf, t: usize, d: usize, n: usize, m: usize) -> (usize, usize, usize) {
    let helper = TxOut {
        value: Amount::from_sat(10000),
        script_pubkey: script! {OP_1 {key(0)[1..].to_vec()}}.compile_with_policy(),
    };
    let funding = tx(
        vec![input(0, Witness::from_slice(&[vec![0; 64]]))],
        std::iter::once(helper.clone())
            .chain((0..m).map(|_| TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: s.to_p2wsh(),
            }))
            .collect(),
    );
    let mut data = vec![];
    for j in 0..t {
        data.push(number(n - j - 1));
        data.extend(vec![vec![0x30; 60]; d]);
    }
    data.push(s.to_bytes());
    let w = Witness::from_slice(&data);
    let spending = tx(
        std::iter::once(input(0, Witness::from_slice(&[vec![0; 64]])))
            .chain((0..m).map(|i| input(i + 1, w.clone())))
            .collect(),
        vec![helper],
    );
    (funding.vsize(), spending.vsize(), serialize(&w).len())
}
fn main() {
    let layout_peaks = vec![
        json!({"n":19,"t":5,"replicas":3,"legacy_combined_stack_peak":layout_check(19,5,3)}),
        json!({"n":15,"t":4,"replicas":4,"legacy_combined_stack_peak":layout_check(15,4,4)}),
    ];
    let mut rows = vec![];
    for d in [3usize, 4] {
        for n in 4..=35 {
            for t in 1..n.min(8) {
                let s = redeem(n, t, d);
                let ops = s
                    .instructions()
                    .filter(
                        |v| matches!(v,Ok(bitcoin::script::Instruction::Op(op))if op.to_u8()>0x60),
                    )
                    .count();
                if s.len() > 3600 || ops > 201 || t * (d + 1) > 100 {
                    continue;
                }
                let radix = choose(n, t);
                let m = count(&radix);
                let (fv, sv, wb) = pair(&s, t, d, n, m);
                rows.push(json!({"replicas":d,"n":n,"t":t,"pools":m,"script_bytes":s.len(),"witness_bytes":wb,"charged_ops":ops,"sigops":d*t,"hint_items":t,"entry_items":t*(d+1),"combined_stack_upper_bound":n*d+t*(d+1)+4,"funding_vbytes":fv,"spending_vbytes":sv,"combined_vbytes":fv+sv}));
            }
        }
    }
    rows.sort_by_key(|v| v["combined_vbytes"].as_u64().unwrap());
    println!("{}",serde_json::to_string_pretty(&json!({"scope":"Compilation and serialization only; placeholder60-byte signatures, no amplification claim. Funding firstP2TR plusP2WSH pools; spendhelper+allpools intooneP2TR output.","evidence":"locally-reproduced","deployment":"unclassified","rows":rows,"legacy_layout_checks":layout_peaks})).unwrap());
}
