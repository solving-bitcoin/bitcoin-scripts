//! Complete bare-legacy 7-of-48 sum-key publication fixtures.
//! Deterministic public test secrets only; never use this fixture with real funds.
#[allow(dead_code)]
#[path = "pointlock_sum_lookup_probe.rs"]
mod layout;

use bitcoin::{
    absolute,
    consensus::serialize,
    hashes::{hash160, Hash},
    script::{Builder, Instruction, PushBytesBuf},
    secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache},
    transaction, Amount, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut,
    Witness,
};
use bitcoin_lab::support::{
    provenance,
    script::{script, ScriptCompilation},
};
use num_bigint::BigUint;
use serde_json::{json, Value};
use std::{collections::BTreeSet, str::FromStr};

const N: usize = 48;
const T: usize = 7;
const POOLS: usize = 79;

fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
fn one() -> SecretKey {
    let mut b = [0; 32];
    b[31] = 1;
    SecretKey::from_slice(&b).unwrap()
}
fn p2tr() -> ScriptBuf {
    let p = PublicKey::from_secret_key(&Secp256k1::new(), &one())
        .x_only_public_key()
        .0;
    Builder::new()
        .push_int(1)
        .push_slice(p.serialize())
        .into_script()
}
fn input(txid: bitcoin::Txid, vout: u32) -> TxIn {
    TxIn {
        previous_output: OutPoint { txid, vout },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }
}
fn sign_helper(tx: &mut Transaction, prevouts: &[TxOut], index: usize) {
    let hash = SighashCache::new(&*tx)
        .taproot_key_spend_signature_hash(index, &Prevouts::All(prevouts), TapSighashType::Default)
        .unwrap();
    let secp = Secp256k1::new();
    let sig = secp.sign_schnorr_no_aux_rand(
        &Message::from_digest(hash.to_byte_array()),
        &Keypair::from_secret_key(&secp, &one()),
    );
    tx.input[index].witness = Witness::from_slice(&[sig.as_ref()]);
}
fn info(tx: &Transaction) -> Value {
    json!({"hex":hex(&serialize(tx)),"txid":tx.compute_txid().to_string(),
        "weight":tx.weight().to_wu(),"vbytes":tx.vsize(),"size":serialize(tx).len()})
}
fn choose(n: usize, k: usize) -> usize {
    if k > n {
        return 0;
    }
    (0..k.min(n - k)).fold(1, |a, i| a * (n - i) / (i + 1))
}
fn unrank(mut rank: usize) -> Vec<usize> {
    assert!(rank < choose(N, T));
    let mut out = vec![];
    let mut low = 0;
    for slot in 0..T {
        for i in low..N {
            let count = choose(N - i - 1, T - slot - 1);
            if rank < count {
                out.push(i);
                low = i + 1;
                break;
            }
            rank -= count;
        }
    }
    assert_eq!(out.len(), T);
    out
}
fn rank(selected: &[usize]) -> usize {
    assert_eq!(selected.len(), T);
    let mut value = 0;
    let mut low = 0;
    for (slot, &i) in selected.iter().enumerate() {
        assert!(i >= low && i < N);
        for j in low..i {
            value += choose(N - j - 1, T - slot - 1);
        }
        low = i + 1;
    }
    value
}
fn selections(payload: &[u8]) -> Vec<Vec<usize>> {
    assert_eq!(payload.len(), 256);
    let mut v = BigUint::from_bytes_be(payload);
    let radix = BigUint::from(choose(N, T));
    let mut out = vec![vec![]; POOLS];
    for slot in out.iter_mut().rev() {
        let words = (&v % &radix).to_u64_digits();
        *slot = unrank(words.first().copied().unwrap_or(0) as usize);
        v /= &radix;
    }
    assert_eq!(v, BigUint::from(0u8));
    out
}
fn bare(c: &[layout::Candidate], g: &[u8]) -> ScriptBuf {
    assert_eq!(c.len(), N);
    script! {
        for _ in 0..3*T { OP_TOALTSTACK }
        {g.to_vec()}
        for row in c { {hash160::Hash::hash(&row.key).to_byte_array().to_vec()} }
        for j in 0..T {
            OP_FROMALTSTACK OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
            OP_FROMALTSTACK OP_FROMALTSTACK
            OP_DUP 2 {N-j+2} OP_WITHIN OP_VERIFY
            OP_ROLL OP_OVER OP_HASH160 OP_EQUALVERIFY
            OP_OVER {N-j+2} OP_PICK OP_CHECKSIGVERIFY OP_CHECKSIGVERIFY
        }
        // Bare legacy consensus permits the unselected table entries to remain.
        OP_TRUE
    }
    .compile_with_policy()
}
fn pushes(items: &[Vec<u8>]) -> ScriptBuf {
    let mut b = Builder::new();
    for item in items {
        b = if item.is_empty() {
            b.push_int(0)
        } else if item.len() == 1 && (1..=16).contains(&item[0]) {
            b.push_int(item[0] as i64)
        } else if item == &[0x81] {
            b.push_int(-1)
        } else {
            b.push_slice(PushBytesBuf::try_from(item.clone()).unwrap())
        };
    }
    b.into_script()
}
fn spend(
    funding: &Transaction,
    candidates: &[layout::Candidate],
    selected: &[Vec<usize>],
) -> Transaction {
    let mut tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: (0..=POOLS)
            .map(|i| input(funding.compute_txid(), i as u32))
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(
                funding.output.iter().map(|o| o.value.to_sat()).sum::<u64>() - 200_000,
            ),
            script_pubkey: p2tr(),
        }],
    };
    for i in 0..POOLS {
        tx.input[i + 1].script_sig = pushes(&layout::items(
            &candidates[i * N..(i + 1) * N],
            &selected[i],
        ));
    }
    sign_helper(&mut tx, &funding.output, 0);
    tx
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let arg = |name: &str| args[args.iter().position(|a| a == name).unwrap() + 1].clone();
    let (candidates, g) = layout::candidates(POOLS * N);
    assert_eq!(
        candidates
            .iter()
            .map(|c| c.key.clone())
            .collect::<BTreeSet<_>>()
            .len(),
        POOLS * N
    );
    assert_eq!(
        candidates
            .iter()
            .map(|c| hash160::Hash::hash(&c.key))
            .collect::<BTreeSet<_>>()
            .len(),
        POOLS * N
    );
    let scripts: Vec<_> = candidates.chunks(N).map(|c| bare(c, &g)).collect();
    assert!(scripts.iter().all(|s| s.len() == 1232));
    let ops = scripts[0]
        .instructions()
        .filter(|v| matches!(v,Ok(Instruction::Op(op)) if op.to_u8()>0x60))
        .count();
    assert_eq!(ops, 140);
    let amount: u64 = arg("--funding-amount").parse().unwrap();
    let mut funding = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input(
            bitcoin::Txid::from_str(&arg("--funding-txid")).unwrap(),
            0,
        )],
        output: vec![TxOut {
            value: Amount::from_sat(amount - POOLS as u64 * 10_000 - 200_000),
            script_pubkey: p2tr(),
        }],
    };
    funding
        .output
        .extend(scripts.iter().cloned().map(|s| TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: s,
        }));
    sign_helper(
        &mut funding,
        &[TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: p2tr(),
        }],
        0,
    );
    let payload: Vec<u8> = (0..=255).collect();
    let selected = selections(&payload);
    let base = spend(&funding, &candidates, &selected);
    let first = layout::items(&candidates[..N], &selected[0]);
    let mut cases = vec![];
    for (name, data) in [
        ("message-00-through-ff", payload.clone()),
        ("message-zero", vec![0; 256]),
        ("message-ff", vec![255; 256]),
    ] {
        let chosen = selections(&data);
        let tx = spend(&funding, &candidates, &chosen);
        cases.push(
            json!({"name":name,"expected":true,"payload_hex":hex(&data),"transaction":info(&tx)}),
        );
    }
    for name in [
        "reversed-selection-order",
        "four-byte-hints",
        "extra-lower-item",
        "nonpush-scriptsig",
        "high-s",
        "undefined-single-flag",
        "short-signature",
        "mutated-s",
        "wrong-key",
        "zero-hint",
        "one-hint",
        "upper-bound-hint",
        "negative-hint",
        "five-byte-hint",
        "missing-hint",
        "deleted-frame",
        "duplicate-selection",
        "wrong-sighash",
        "two-outputs",
        "pointlock-index-zero",
        "invalid-helper",
    ] {
        let mut tx = base.clone();
        let mut items = first.clone();
        let expected = matches!(
            name,
            "reversed-selection-order"
                | "four-byte-hints"
                | "extra-lower-item"
                | "nonpush-scriptsig"
                | "high-s"
                | "undefined-single-flag"
        );
        match name {
            "reversed-selection-order" => {
                let mut order = selected[0].clone();
                order.reverse();
                items = layout::items(&candidates[..N], &order);
            }
            "four-byte-hints" => {
                for i in (2..items.len()).step_by(3) {
                    items[i].resize(4, 0);
                }
            }
            "extra-lower-item" => items.insert(0, vec![7]),
            "nonpush-scriptsig" => {}
            "high-s" => {
                let low =
                    bitcoin::secp256k1::ecdsa::Signature::from_der(&items[0][..items[0].len() - 1])
                        .unwrap();
                let mut compact = low.serialize_compact();
                let modulus = BigUint::parse_bytes(
                    b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
                    16,
                )
                .unwrap();
                let high = modulus - BigUint::from_bytes_be(&compact[32..]);
                compact[32..].copy_from_slice(&high.to_bytes_be());
                items[0] = bitcoin::secp256k1::ecdsa::Signature::from_compact(&compact)
                    .unwrap()
                    .serialize_der()
                    .to_vec();
                items[0].push(3);
            }
            "undefined-single-flag" => *items[0].last_mut().unwrap() = 0x23,
            "short-signature" => items[0] = vec![0; 57],
            "mutated-s" => {
                let last = items[0].len() - 2;
                items[0][last] ^= 1;
            }
            "wrong-key" => items[1] = candidates[N].key.clone(),
            "zero-hint" => items[2] = vec![],
            "one-hint" => items[2] = vec![1],
            "upper-bound-hint" => items[2] = vec![(N + 2) as u8],
            "negative-hint" => items[2] = vec![0x81],
            "five-byte-hint" => items[2].resize(5, 0),
            "missing-hint" => {
                items.pop();
            }
            "deleted-frame" => {
                items.truncate(items.len() - 3);
            }
            "duplicate-selection" => {
                items[3] = items[0].clone();
                items[4] = items[1].clone();
            }
            "wrong-sighash" => *items[0].last_mut().unwrap() = 1,
            "two-outputs" | "pointlock-index-zero" | "invalid-helper" => {}
            _ => unreachable!(),
        }
        tx.input[1].script_sig = pushes(&items);
        if name == "nonpush-scriptsig" {
            let mut code = tx.input[1].script_sig.to_bytes();
            code.extend([0x76, 0x75]);
            tx.input[1].script_sig = ScriptBuf::from_bytes(code);
        }
        if name == "two-outputs" {
            tx.output[0].value = Amount::from_sat(tx.output[0].value.to_sat() - 10_000);
            tx.output.push(TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: p2tr(),
            });
            sign_helper(&mut tx, &funding.output, 0);
        }
        if name == "pointlock-index-zero" {
            tx.input.swap(0, 1);
            let mut prevouts = funding.output.clone();
            prevouts.swap(0, 1);
            sign_helper(&mut tx, &prevouts, 1);
        }
        if name == "invalid-helper" {
            let mut signature = tx.input[0].witness.iter().next().unwrap().to_vec();
            signature[0] ^= 1;
            tx.input[0].witness = Witness::from_slice(&[signature]);
        }
        cases.push(json!({"name":name,"expected":expected,"payload_hex":hex(&payload),"transaction":info(&tx)}));
    }
    // The byte-sized publication codec cannot assign every surplus codeword.
    let unused = spend(&funding, &candidates, &vec![(N - T..N).collect(); POOLS]);
    cases.push(json!({"name":"unused-codeword","expected":true,"payload_hex":null,"transaction":info(&unused)}));
    // Native pool scripts do not require every other pool to participate.
    let mut partial = base.clone();
    partial.input.truncate(2);
    partial.output[0].value = Amount::from_sat(funding.output[0].value.to_sat() + 10_000 - 200_000);
    sign_helper(&mut partial, &funding.output[..2], 0);
    cases.push(json!({"name":"partial-one-pool","expected":true,"payload_hex":null,"transaction":info(&partial)}));
    println!("{}",serde_json::to_string_pretty(&json!({"compiler":provenance::compiler().unwrap().commit,
        "profile":{"n":N,"t":T,"pools":POOLS,"candidate_points":N*POOLS,"scalar_openings":T*POOLS,
          "script_bytes":1232,"static_non_push_ops":ops,"hint_items_per_pool":T,"entry_items_per_pool":3*T},
        "funding":info(&funding),"cases":cases,
        "pool_commitments":candidates.chunks(N).enumerate().map(|(i,c)|json!({"pool":i,
          "script_hex":hex(scripts[i].as_bytes()),"keys":c.iter().map(|r|hex(&r.key)).collect::<Vec<_>>()})).collect::<Vec<_>>()
    })).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bare_codec_boundaries() {
        let radix = choose(N, T);
        for value in [0, 1, radix / 2, radix - 2, radix - 1] {
            assert_eq!(rank(&unrank(value)), value);
        }
        for data in [vec![0; 256], vec![255; 256], (0..=255).collect()] {
            let mut rank_value = BigUint::from(0u8);
            for chosen in selections(&data) {
                rank_value = rank_value * radix + rank(&chosen);
            }
            assert_eq!(rank_value, BigUint::from_bytes_be(&data));
        }
        assert!(BigUint::from(radix).pow(79) >= BigUint::from(1u8) << 2048);
        assert!(BigUint::from(radix).pow(78) < BigUint::from(1u8) << 2048);
    }
}
