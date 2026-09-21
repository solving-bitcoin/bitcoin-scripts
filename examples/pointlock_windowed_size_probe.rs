//! Serialization probe for conditional, windowed small-r ECDSA point locks.
//! This example measures scripts and complete transaction framing. Its signatures
//! are placeholders: it does not claim to have performed the production grind.
use bitcoin::{
    absolute,
    consensus::serialize,
    hashes::{hash160, Hash},
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_lab::support::script::{script, ScriptCompilation};
use num_bigint::BigUint;
use serde_json::json;

pub(crate) fn lookup_redeem(keys: &[Vec<u8>], t: usize, cap: usize) -> ScriptBuf {
    assert!(t > 0 && t <= keys.len());
    script! {
        for _ in 0..3*t {OP_TOALTSTACK}
        for key in keys {{hash160::Hash::hash(key).to_byte_array().to_vec()}}
        for j in 0..t {
            OP_FROMALTSTACK OP_SIZE {cap} OP_LESSTHANOREQUAL OP_VERIFY
            OP_FROMALTSTACK OP_FROMALTSTACK
            OP_DUP 2 {keys.len()-j+2} OP_WITHIN OP_VERIFY
            OP_ROLL OP_OVER OP_HASH160 OP_EQUALVERIFY OP_CHECKSIGVERIFY
        }
        for _ in 0..keys.len()-t {OP_DROP}
        OP_TRUE
    }
    .compile_with_policy()
}
pub(crate) fn multisig_redeem(keys: &[Vec<u8>], t: usize, cap: usize) -> ScriptBuf {
    assert!(t > 0 && t <= keys.len() && keys.len() <= 20);
    script! {
        for _ in 0..t {OP_SIZE {cap} OP_LESSTHANOREQUAL OP_VERIFY OP_TOALTSTACK}
        for _ in 0..t {OP_FROMALTSTACK}
        {t}
        for key in keys {{key.clone()}}
        {keys.len()} OP_CHECKMULTISIG
    }
    .compile_with_policy()
}
pub(crate) fn compact_lookup_redeem(keys: &[Vec<u8>], t: usize, cap: usize) -> ScriptBuf {
    assert!(t > 0 && t <= keys.len() && cap > 20);
    script! {
        for _ in 0..3*t {OP_TOALTSTACK}
        for key in keys {{hash160::Hash::hash(key).to_byte_array().to_vec()}}
        for _ in 0..t {
            OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
            OP_ROLL OP_OVER OP_HASH160 OP_EQUALVERIFY
            OP_OVER OP_SIZE {cap} OP_EQUALVERIFY OP_DROP OP_CHECKSIGVERIFY
        }
        for _ in 0..keys.len()-t {OP_DROP}
        OP_TRUE
    }
    .compile_with_policy()
}
pub(crate) fn batched_multisig_redeem(blocks: &[(Vec<Vec<u8>>, usize)], cap: usize) -> ScriptBuf {
    script! {
        for (keys,t) in blocks {
            for _ in 0..*t {OP_SIZE {cap} OP_LESSTHANOREQUAL OP_VERIFY OP_TOALTSTACK}
            for _ in 0..*t {OP_FROMALTSTACK}
            {*t}
            for key in keys {{key.clone()}}
            {keys.len()} OP_CHECKMULTISIGVERIFY
        }
        OP_TRUE
    }
    .compile_with_policy()
}
fn script_num(mut v: usize) -> Vec<u8> {
    if v == 0 {
        return vec![];
    }
    let mut out = vec![];
    while v > 0 {
        out.push((v & 255) as u8);
        v >>= 8;
    }
    if out.last().unwrap() & 0x80 != 0 {
        out.push(0);
    }
    out
}
pub(crate) fn lookup_items(
    signatures: &[Vec<u8>],
    keys: &[Vec<u8>],
    selected: &[usize],
) -> Vec<Vec<u8>> {
    let mut remaining: Vec<_> = (0..keys.len()).collect();
    let mut out = vec![];
    for &index in selected {
        let position = remaining.iter().position(|&v| v == index).unwrap();
        let depth = remaining.len() + 1 - position;
        remaining.remove(position);
        out.extend([
            signatures[index].clone(),
            keys[index].clone(),
            script_num(depth),
        ]);
    }
    out
}
fn keys(n: usize) -> Vec<Vec<u8>> {
    let secp = Secp256k1::new();
    (1..=n)
        .map(|i| {
            let mut s = [0; 32];
            s[24..].copy_from_slice(&(i as u64).to_be_bytes());
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&s).unwrap())
                .serialize()
                .to_vec()
        })
        .collect()
}
fn choose(n: usize, t: usize) -> BigUint {
    let mut out = BigUint::from(1u8);
    for i in 0..t {
        out = out * BigUint::from(n - i) / BigUint::from(i + 1);
    }
    out
}
fn bits(v: &BigUint) -> f64 {
    let b = v.bits();
    if b < 53 {
        return (v.to_u64_digits()[0] as f64).log2();
    }
    let high = (v >> (b - 53)).to_u64_digits()[0];
    (high as f64).log2() + (b - 53) as f64
}
fn pools(radix: &BigUint) -> usize {
    let target = BigUint::from(1u8) << 2048;
    let mut capacity = BigUint::from(1u8);
    let mut count = 0;
    while capacity < target {
        capacity *= radix;
        count += 1;
    }
    count
}
fn tx(input: Vec<TxIn>, output: Vec<TxOut>) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input,
        output,
    }
}
fn input(vout: usize, witness: Witness) -> TxIn {
    TxIn {
        previous_output: OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: vout as u32,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness,
    }
}
fn pair(script: &ScriptBuf, items: &[Vec<u8>], count: usize) -> (usize, usize, u64, u64) {
    let helper_script = script! {OP_1 {keys(1)[0][1..].to_vec()}}.compile_with_policy();
    let helper_output = TxOut {
        value: Amount::from_sat(10000),
        script_pubkey: helper_script,
    };
    let funding = tx(
        vec![input(0, Witness::from_slice(&[vec![0; 64]]))],
        std::iter::once(helper_output.clone())
            .chain((0..count).map(|_| TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: script.to_p2wsh(),
            }))
            .collect(),
    );
    let mut data = items.to_vec();
    data.push(script.to_bytes());
    let spending = tx(
        std::iter::once(input(0, Witness::from_slice(&[vec![0; 64]])))
            .chain((0..count).map(|i| input(i + 1, Witness::from_slice(&data))))
            .collect(),
        std::iter::once(helper_output)
            .chain((0..count).map(|i| TxOut {
                value: Amount::ZERO,
                script_pubkey:
                    script! {OP_RETURN {(i as u64).to_le_bytes().to_vec()}}.compile_with_policy(),
            }))
            .collect(),
    );
    (
        funding.vsize(),
        spending.vsize(),
        funding.weight().to_wu(),
        spending.weight().to_wu(),
    )
}
fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let batch_only = std::env::args().any(|a| a == "--batch-only");
    let all = keys(170);
    let mut metrics = vec![];
    for cap in [53usize, 54] {
        for family in ["multisig", "hash160-lookup", "compact-exact-lookup"] {
            if batch_only {
                continue;
            }
            for n in 2..=if family == "multisig" { 20 } else { 170 } {
                if quick
                    && family != "multisig"
                    && ![32, 48, 64, 80, 96, 112, 128, 144, 152, 160, 168].contains(&n)
                {
                    continue;
                }
                for t in 1..=if family == "multisig" {
                    n - 1
                } else {
                    (n - 1).min(20)
                } {
                    let estimated_ops = if family == "multisig" {
                        5 * t + 1 + n
                    } else if family == "hash160-lookup" {
                        17 * t + (n - t + 1) / 2
                    } else {
                        13 * t + (n - t + 1) / 2
                    };
                    if estimated_ops > 201 {
                        continue;
                    }
                    let s = if family == "multisig" {
                        multisig_redeem(&all[..n], t, cap)
                    } else if family == "hash160-lookup" {
                        lookup_redeem(&all[..n], t, cap)
                    } else {
                        compact_lookup_redeem(&all[..n], t, cap)
                    };
                    let ops=s.instructions().filter(|v|matches!(v,Ok(bitcoin::script::Instruction::Op(op)) if op.to_u8()>0x60)).count();
                    let charged = ops + if family == "multisig" { n } else { 0 };
                    let entry = if family == "multisig" { t + 1 } else { 3 * t };
                    if s.len() > 3600 || charged > 201 || entry > 100 {
                        continue;
                    }
                    let signatures = vec![vec![0x30; cap]; n];
                    let selected = (0..t).collect::<Vec<_>>();
                    let items = if family == "multisig" {
                        std::iter::once(vec![])
                            .chain(signatures[..t].iter().cloned())
                            .collect()
                    } else {
                        lookup_items(&signatures, &all[..n], &selected)
                    };
                    let mut data = items.clone();
                    data.push(s.to_bytes());
                    let wit = Witness::from_slice(&data);
                    let witness_bytes = serialize(&wit).len();
                    let radix = choose(n, t);
                    let count = pools(&radix);
                    let (fv, sv, fw, sw) = pair(&s, &items, count);
                    let prefix = 116 + if s.len() < 253 { 1 } else { 3 } + s.len();
                    let inner = (prefix % 64 + 40 + 9 + 63) / 64;
                    metrics.push(json!({"family":family,"cap":cap,"n":n,"t":t,"script_bytes":s.len(),"witness_bytes":witness_bytes,"hint_items":if family=="multisig"{0}else{t},"entry_items":entry,"combined_stack_upper_bound":if family=="multisig"{n+2*t+4}else{n+3*t+4},"static_non_push_ops":ops,"charged_ops":charged,"sigops":if family=="multisig"{if n>16{20}else{n}}else{t},"bits_per_pool":bits(&radix),"pools":count,"funding_vbytes":fv,"spending_vbytes":sv,"combined_vbytes":fv+sv,"funding_weight":fw,"spending_weight":sw,"nonce_output_bytes":19,"sha256_compressions_per_trial":3+inner}));
                }
            }
        }
    }
    for cap in [53usize, 54] {
        for blocks in 2..=5 {
            for n in 10..=20 {
                if quick && ![16, 18, 19, 20].contains(&n) {
                    continue;
                }
                for t in 1..n {
                    if blocks * (n + 5 * t - 2) > 201 || blocks * (t + 1) > 100 {
                        continue;
                    }
                    let spec = (0..blocks)
                        .map(|b| (all[b * n..(b + 1) * n].to_vec(), t))
                        .collect::<Vec<_>>();
                    let s = batched_multisig_redeem(&spec, cap);
                    let ops=s.instructions().filter(|v|matches!(v,Ok(bitcoin::script::Instruction::Op(op)) if op.to_u8()>0x60)).count();
                    let charged = ops + blocks * n;
                    if s.len() > 3600 || charged > 201 {
                        continue;
                    }
                    let mut items = vec![];
                    for _ in 0..blocks {
                        items.push(vec![]);
                        items.extend(vec![vec![0x30; cap]; t]);
                    }
                    let mut data = items.clone();
                    data.push(s.to_bytes());
                    let wit = Witness::from_slice(&data);
                    let radix = choose(n, t).pow(blocks as u32);
                    let count = pools(&radix);
                    let (fv, sv, fw, sw) = pair(&s, &items, count);
                    let prefix = 116 + if s.len() < 253 { 1 } else { 3 } + s.len();
                    let inner = (prefix % 64 + 40 + 9 + 63) / 64;
                    metrics.push(json!({"family":"batched-multisig","cap":cap,"blocks":blocks,"n":n,"t":t,"script_bytes":s.len(),"witness_bytes":serialize(&wit).len(),"hint_items":0,"entry_items":items.len(),"combined_stack_upper_bound":items.len()+n+5,"static_non_push_ops":ops,"charged_ops":charged,"sigops":blocks*if n>16{20}else{n},"bits_per_pool":bits(&radix),"pools":count,"funding_vbytes":fv,"spending_vbytes":sv,"combined_vbytes":fv+sv,"funding_weight":fw,"spending_weight":sw,"nonce_output_bytes":19,"sha256_compressions_per_trial":3+inner}));
                }
            }
        }
    }
    metrics.sort_by_key(|v| v["combined_vbytes"].as_u64().unwrap());
    println!("{}",serde_json::to_string_pretty(&json!({"evidence":"locally-reproduced","deployment":"unclassified","scope":"Compiled serialization only; hypothetical signatures, production grind not executed. Includes funding and per-input eight-byte OP_RETURN nonce outputs.","metrics":metrics})).unwrap());
}
