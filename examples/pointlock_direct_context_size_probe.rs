//! Direct target-key checks at distinct native CODESEPARATOR contexts.
//! Sizing only: placeholder signatures do not establish extraction or validity.
use bitcoin::{
    absolute,
    consensus::serialize,
    hashes::{hash160, Hash},
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_lab::support::{
    provenance,
    script::{script, ScriptCompilation},
};
use num_bigint::BigUint;
use serde_json::json;

pub(crate) fn key(i: usize) -> Vec<u8> {
    let mut b = [0; 32];
    b[24..].copy_from_slice(&(i as u64 + 1).to_be_bytes());
    PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&b).unwrap())
        .serialize()
        .to_vec()
}
pub(crate) fn redeem(
    keys: &[Vec<u8>],
    t: usize,
    rounds: usize,
    hashed: bool,
    clamped: bool,
) -> ScriptBuf {
    let n = keys.len();
    assert!(t > 0 && t <= n && rounds > 0);
    script! {
        {key(0)} OP_CHECKSIGVERIFY
        for p in keys {
            if hashed {{hash160::Hash::hash(p).to_byte_array().to_vec()}}
            else {{p.clone()}}
        }
        for j in 0..t {
            if hashed {
                {n-j} OP_ROLL {n-j+1} OP_ROLL
                if clamped {{n-j} OP_MIN}
                else {OP_DUP 1 {n-j+1} OP_WITHIN OP_VERIFY}
                OP_ROLL OP_OVER OP_HASH160 OP_EQUALVERIFY
            } else {
                {n-j} OP_ROLL OP_DUP 0 {n-j} OP_WITHIN OP_VERIFY OP_ROLL
            }
            for _ in 0..rounds {
                {n-j} OP_ROLL OP_SIZE 60 OP_EQUALVERIFY
                OP_OVER OP_CODESEPARATOR OP_CHECKSIGVERIFY
            }
            OP_DROP
        }
        for _ in 0..n-t {OP_DROP}
        OP_TRUE
    }
    .compile_with_policy()
}
fn number(mut n: usize) -> Vec<u8> {
    let mut b = vec![];
    while n > 0 {
        b.push((n & 255) as u8);
        n >>= 8;
    }
    if b.last().is_some_and(|v| v & 128 != 0) {
        b.push(0);
    }
    b
}
fn choose(n: usize, t: usize) -> BigUint {
    (0..t).fold(BigUint::from(1u8), |v, j| {
        v * BigUint::from(n - j) / BigUint::from(j + 1)
    })
}
fn input(i: usize, witness: Witness) -> TxIn {
    let mut outpoint = OutPoint::null();
    outpoint.vout = i as u32;
    TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness,
    }
}
fn tx(input: Vec<TxIn>, output: Vec<TxOut>) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input,
        output,
    }
}
fn main() {
    let keys: Vec<_> = (1..=180).map(key).collect();
    let helper = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: script! {OP_1 {key(0)[1..].to_vec()}}.compile_with_policy(),
    };
    let mut best = vec![];
    let mut feasible = 0;
    for rounds in 3..=16 {
        let mut rows = vec![];
        for (hashed, clamped) in [(true, false), (true, true), (false, false)] {
            for n in 3..=180 {
                for t in 1..=10.min(n - 1) {
                    let entry = 1 + t * (rounds + if hashed { 2 } else { 1 });
                    if entry > 100 || (6 * rounds + 5) * t + (n - t) / 2 + 1 > 201 {
                        continue;
                    }
                    let code = redeem(&keys[..n], t, rounds, hashed, clamped);
                    let ops=code.instructions().filter(|i|matches!(i,Ok(bitcoin::script::Instruction::Op(op))if op.to_u8()>0x60)).count();
                    if ops > 201 || code.len() > 3600 {
                        continue;
                    }
                    let radix = choose(n, t);
                    let mut capacity = BigUint::from(1u8);
                    let mut pools = 0;
                    while capacity < (BigUint::from(1u8) << 2048) {
                        capacity *= &radix;
                        pools += 1;
                    }
                    let mut items = vec![];
                    for j in 0..t {
                        if hashed {
                            items.push(keys[j].clone());
                        }
                        items.push(number(n - j - if hashed { 0 } else { 1 }));
                        items.extend((0..rounds).map(|_| vec![0x30; 60]));
                    }
                    items.reverse();
                    items.push(vec![0x30; 72]);
                    items.push(code.to_bytes());
                    let witness = Witness::from_slice(&items);
                    let funding = tx(
                        vec![input(0, Witness::from_slice(&[vec![0; 64]]))],
                        std::iter::once(helper.clone())
                            .chain((0..pools).map(|_| TxOut {
                                value: Amount::from_sat(100_000),
                                script_pubkey: code.to_p2wsh(),
                            }))
                            .collect(),
                    );
                    let spending = tx(
                        std::iter::once(input(0, Witness::from_slice(&[vec![0; 64]])))
                            .chain((0..pools).map(|i| input(i + 1, witness.clone())))
                            .collect(),
                        vec![helper.clone()],
                    );
                    rows.push(json!({"rounds":rounds,"table":if hashed{"hash160-key"}else{"embedded-key"},"clamped_index":clamped,
                "n":n,"t":t,"pools":pools,"script_bytes":code.len(),"charged_ops":ops,
                "hint_items":t,"total_hint_items":pools*t,"entry_items":entry,"total_entry_items":pools*entry,
                "complete_witness_items":items.len(),"serialized_witness_bytes":serialize(&witness).len(),
                "combined_stack_upper_bound":n+entry+6,
                "funding_vbytes":funding.vsize(),"spending_vbytes":spending.vsize(),"combined_vbytes":funding.vsize()+spending.vsize(),
                "spending_weight":spending.weight().to_wu(),"spending_within_policy_weight":spending.weight().to_wu()<=400_000}));
                }
            }
        }
        feasible += rows.len();
        rows.sort_by_key(|r| r["combined_vbytes"].as_u64().unwrap());
        best.push(rows.into_iter().next().unwrap());
    }
    println!("{}",serde_json::to_string_pretty(&json!({
        "scope":"Bounded homogeneous-profile scan n=3..180,t=1..10,rounds=3..16, direct embedded/HASH160 target key. Exact scripts and full creation/spending serialization with placeholder short/authorization signatures. Every required output, helper and per-pool authorization included. No native validation or general extraction bound.",
        "evidence":"locally-reproduced","deployment":"unclassified","compiler_commit":provenance::compiler().unwrap().commit,
        "feasible_rows":feasible,"best_by_rounds":best})).unwrap());
}
