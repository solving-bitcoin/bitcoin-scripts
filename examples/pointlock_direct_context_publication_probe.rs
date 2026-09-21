//! Full honest publication for the conditional direct-key CODESEPARATOR candidate.
//! Neither this generator nor successful transactions prove general extraction.
//! All scalar secrets below are deterministic public test fixtures.
#[allow(dead_code)]
#[path = "pointlock_direct_context_size_probe.rs"]
mod layout;

use bitcoin::{
    absolute,
    consensus::serialize,
    hashes::{hash160, sha256, Hash},
    opcodes::all::{OP_CHECKSIGVERIFY, OP_CODESEPARATOR},
    script::Instruction,
    secp256k1::{ecdsa::Signature, Keypair, Message, PublicKey, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache},
    transaction, Amount, EcdsaSighashType, OutPoint, ScriptBuf, Sequence, TapSighashType,
    Transaction, TxIn, TxOut, Witness,
};
use bitcoin_lab::{
    signatures::pointlocks,
    support::{
        provenance,
        script::{script, ScriptCompilation},
    },
};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use serde_json::{json, Value};
use std::{collections::BTreeSet, str::FromStr, time::Instant};

const POOLS: usize = 115;
const N: usize = 50;
const THRESHOLD: usize = 4;
const ROUNDS: usize = 6;
const LOCK_VALUE: u64 = 100_000;

fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
fn scalar(v: &BigUint) -> SecretKey {
    let mut bytes = [0u8; 32];
    let b = v.to_bytes_be();
    bytes[32 - b.len()..].copy_from_slice(&b);
    SecretKey::from_slice(&bytes).unwrap()
}
fn one() -> SecretKey {
    scalar(&BigUint::from(1u8))
}
fn owner_key() -> Vec<u8> {
    PublicKey::from_secret_key(&Secp256k1::new(), &one())
        .serialize()
        .to_vec()
}
fn p2tr() -> ScriptBuf {
    script! {OP_1 {owner_key()[1..].to_vec()}}.compile_with_policy()
}
fn number(mut v: usize) -> Vec<u8> {
    let mut b = vec![];
    while v > 0 {
        b.push((v & 255) as u8);
        v >>= 8;
    }
    if b.last().is_some_and(|x| x & 128 != 0) {
        b.push(0);
    }
    b
}
fn input(previous_output: OutPoint) -> TxIn {
    TxIn {
        previous_output,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }
}
fn info(tx: &Transaction) -> Value {
    json!({"hex":hex(&serialize(tx)),"txid":tx.compute_txid().to_string(),
        "wtxid":tx.compute_wtxid().to_string(),"weight":tx.weight().to_wu(),"vbytes":tx.vsize()})
}
fn sign_helper(tx: &mut Transaction, prevouts: &[TxOut]) {
    let hash = SighashCache::new(&*tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(prevouts), TapSighashType::Default)
        .unwrap();
    let secp = Secp256k1::new();
    let sig = secp.sign_schnorr_no_aux_rand(
        &Message::from_digest(hash.to_byte_array()),
        &Keypair::from_secret_key(&secp, &one()),
    );
    tx.input[0].witness = Witness::from_slice(&[sig.as_ref()]);
}
fn digest(tx: &Transaction, index: usize, code: &ScriptBuf, flag: EcdsaSighashType) -> [u8; 32] {
    SighashCache::new(tx)
        .p2wsh_signature_hash(index, code, Amount::from_sat(LOCK_VALUE), flag)
        .unwrap()
        .to_byte_array()
}
fn choose(n: usize, t: usize) -> u64 {
    (0..t.min(n - t)).fold(1u64, |v, j| v * (n - j) as u64 / (j + 1) as u64)
}
fn unrank(mut rank: u64, n: usize, t: usize) -> Vec<usize> {
    let mut selected = vec![];
    let mut start = 0;
    for j in 0..t {
        for i in start..n {
            let c = choose(n - i - 1, t - j - 1);
            if rank < c {
                selected.push(i);
                start = i + 1;
                break;
            }
            rank -= c;
        }
    }
    assert_eq!(selected.len(), t);
    assert_eq!(rank, 0);
    selected
}
fn encode_payload(payload: &[u8]) -> Vec<Vec<usize>> {
    assert_eq!(payload.len(), 256);
    let radix = choose(N, THRESHOLD);
    assert!(BigUint::from(radix).pow(POOLS as u32) >= (BigUint::from(1u8) << 2048));
    let mut value = BigUint::from_bytes_be(payload);
    let mut selections = vec![];
    for _ in 0..POOLS {
        let rank = (&value % radix).to_u64().unwrap();
        value /= radix;
        selections.push(unrank(rank, N, THRESHOLD));
    }
    assert_eq!(value, BigUint::from(0u8));
    selections
}

struct Candidate {
    secret: SecretKey,
    target: Vec<u8>,
}
struct Pool {
    candidates: Vec<Candidate>,
    code: ScriptBuf,
    checks: Vec<ScriptBuf>,
}
fn authorized_code(keys: &[Vec<u8>]) -> ScriptBuf {
    layout::redeem(keys, THRESHOLD, ROUNDS, true, true)
}
fn contexts(code: &ScriptBuf) -> Vec<ScriptBuf> {
    let mut start = 0;
    let mut out = vec![];
    for item in code.instruction_indices() {
        match item.unwrap() {
            (offset, Instruction::Op(op)) if op == OP_CODESEPARATOR => start = offset + 1,
            (_, Instruction::Op(op)) if op == OP_CHECKSIGVERIFY => {
                out.push(ScriptBuf::from_bytes(code.as_bytes()[start..].to_vec()))
            }
            _ => {}
        }
    }
    assert_eq!(out.len(), 1 + THRESHOLD * ROUNDS);
    out
}
fn setup_range(worker: usize, workers: usize) -> (Vec<(usize, Pool)>, usize) {
    let secp = Secp256k1::new();
    let mut attempts = 0;
    let mut pools = vec![];
    for i in (worker..POOLS).step_by(workers) {
        let mut candidates = vec![];
        for j in 0..N {
            let mut attempt = 0;
            let candidate = loop {
                let b = sha256::Hash::hash(
                    format!("anchored-publication-v1-{i}-{j}-{attempt}").as_bytes(),
                )
                .to_byte_array();
                attempt += 1;
                attempts += 1;
                let secret = SecretKey::from_slice(&b).unwrap();
                let point = PublicKey::from_secret_key(&secp, &secret);
                let target = point.serialize().to_vec();
                if target[1] == 0 || target[1] >= 128 {
                    continue;
                }
                break Candidate { secret, target };
            };
            candidates.push(candidate);
        }
        let keys: Vec<_> = candidates.iter().map(|c| c.target.clone()).collect();
        let code = authorized_code(&keys);
        let checks = contexts(&code);
        pools.push((
            i,
            Pool {
                candidates,
                code,
                checks,
            },
        ));
    }
    (pools, attempts)
}
fn setup(workers: usize) -> (Vec<Pool>, usize) {
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|worker| scope.spawn(move || setup_range(worker, workers)))
            .collect();
        let mut indexed = vec![];
        let mut attempts = 0;
        for handle in handles {
            let (mut pools, count) = handle.join().unwrap();
            indexed.append(&mut pools);
            attempts += count;
        }
        indexed.sort_by_key(|(index, _)| *index);
        (
            indexed.into_iter().map(|(_, pool)| pool).collect(),
            attempts,
        )
    })
}
fn verify_setup(pools: &[Pool], workers: usize) {
    // This global duplicate check is deliberately included in public verification.
    let mut hashes = BTreeSet::new();
    for pool in pools {
        for candidate in &pool.candidates {
            assert!(hashes.insert(hash160::Hash::hash(&candidate.target).to_byte_array()));
        }
    }
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|worker| {
                scope.spawn(move || {
                    for pool in pools.iter().skip(worker).step_by(workers) {
                        for candidate in &pool.candidates {
                            let target = PublicKey::from_slice(&candidate.target)
                                .unwrap()
                                .serialize();
                            assert!(target[1] != 0 && target[1] < 128);
                            assert_eq!(target.as_slice(), candidate.target.as_slice());
                        }
                        let keys: Vec<_> =
                            pool.candidates.iter().map(|c| c.target.clone()).collect();
                        assert_eq!(authorized_code(&keys), pool.code);
                        assert_eq!(contexts(&pool.code), pool.checks);
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    });
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let arg = |name: &str| {
        args.iter()
            .position(|v| v == name)
            .map(|i| args[i + 1].clone())
    };
    let workers = arg("--workers")
        .map(|v| v.parse::<usize>().unwrap())
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, usize::from))
        .clamp(1, POOLS);
    if let Some(samples) = arg("--benchmark") {
        let samples: usize = samples.parse().unwrap();
        let mut rows = vec![];
        for _ in 0..samples {
            let start = Instant::now();
            let (pools, attempts) = setup(workers);
            let generated = start.elapsed();
            let start = Instant::now();
            verify_setup(&pools, workers);
            let checked = start.elapsed();
            rows.push(json!({"generation_ms":generated.as_secs_f64()*1000.,"verification_ms":checked.as_secs_f64()*1000.,
                "combined_ms":(generated+checked).as_secs_f64()*1000.,"target_curve_multiplications":attempts}));
        }
        println!("{}",serde_json::to_string_pretty(&json!({"scope":"Direct point-label generation, key-table generation, policy compilation and public checking for the entire115pool instance. Excludes garbling/VSS, transaction funding, opening generation, process startup and compilation of this executable.",
            "pools":POOLS,"candidates":POOLS*N,"workers":workers,
            "compiler_commit":provenance::compiler().unwrap().commit,
            "build_profile":if cfg!(debug_assertions){"debug"}else{"release"},"samples":rows})).unwrap());
        return;
    }
    let setup_start = Instant::now();
    let (pools, setup_attempts) = setup(workers);
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1000.;
    let verify_start = Instant::now();
    verify_setup(&pools, workers);
    let verification_ms = verify_start.elapsed().as_secs_f64() * 1000.;
    let amount = arg("--funding-amount")
        .unwrap_or_else(|| "100000000".into())
        .parse::<u64>()
        .unwrap();
    let previous = TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: p2tr(),
    };
    let funding_txid =
        bitcoin::Txid::from_str(&arg("--funding-txid").unwrap_or_else(|| "00".repeat(32))).unwrap();
    let mut funding = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input(OutPoint {
            txid: funding_txid,
            vout: arg("--funding-vout")
                .unwrap_or_else(|| "0".into())
                .parse()
                .unwrap(),
        })],
        output: vec![TxOut {
            value: Amount::from_sat(amount - 50_000 - POOLS as u64 * LOCK_VALUE),
            script_pubkey: p2tr(),
        }],
    };
    funding.output.extend(pools.iter().map(|p| TxOut {
        value: Amount::from_sat(LOCK_VALUE),
        script_pubkey: p.code.to_p2wsh(),
    }));
    sign_helper(&mut funding, &[previous]);
    let mut spending = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: (0..POOLS + 1)
            .map(|vout| {
                input(OutPoint {
                    txid: funding.compute_txid(),
                    vout: vout as u32,
                })
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(amount - 150_000),
            script_pubkey: p2tr(),
        }],
    };
    let payload: Vec<u8> = if let Some(value) = arg("--payload-hex") {
        assert!(
            value.is_ascii() && value.len() == 512,
            "payload must be exactly256bytes of hex"
        );
        (0..512)
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
            .collect()
    } else {
        (0..256).map(|v| v as u8).collect()
    };
    let radix = choose(N, THRESHOLD);
    let selections = encode_payload(&payload);
    let order = BigUint::parse_bytes(
        b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .unwrap();
    let half = (&order + BigUint::from(1u8)) / 2u8;
    let half_key = scalar(&half);
    let rh = BigUint::from_bytes_be(&pointlocks::G_HALF_R);
    let inv_rh = rh.modpow(&(&order - 2u8), &order);
    let secp = Secp256k1::new();
    let flags = [
        EcdsaSighashType::All,
        EcdsaSighashType::None,
        EcdsaSighashType::Single,
        EcdsaSighashType::AllPlusAnyoneCanPay,
        EcdsaSighashType::NonePlusAnyoneCanPay,
        EcdsaSighashType::SinglePlusAnyoneCanPay,
    ];
    let opening_start = Instant::now();
    let mut sign_attempts = 0;
    let mut opening_attempts = 0u32;
    let records = 'opening: loop {
        // A retry changes only the helper's sequence, which the ALL
        // short-signature contexts commit to. Output destinations, amounts and selected labels stay
        // fixed. The disable-relative-locktime bit remains set throughout.
        assert!(
            opening_attempts < 0x8000_0000,
            "exhausted helper-sequence retry space"
        );
        spending.input[0].sequence = Sequence::from_consensus(u32::MAX - opening_attempts);
        opening_attempts += 1;
        let mut records = vec![];
        for (i, pool) in pools.iter().enumerate() {
            let index = i + 1;
            let mut remaining: Vec<_> = (0..N).collect();
            let mut consumption = vec![];
            let mut frames = vec![];
            for (slot, &selected) in selections[i].iter().enumerate() {
                let candidate = &pool.candidates[selected];
                let c = 1 + slot * ROUNDS;
                let t = BigUint::from_bytes_be(&candidate.secret.secret_bytes());
                let secret = candidate.secret;
                let key = PublicKey::from_slice(&candidate.target).unwrap();
                let pos = remaining.iter().position(|&v| v == selected).unwrap();
                let depth = remaining.len() - pos;
                remaining.remove(pos);
                consumption.extend([key.serialize().to_vec(), number(depth)]);
                let mut checks = vec![];
                for round in 0..ROUNDS {
                    let code = &pool.checks[c + round];
                    let opening = flags.iter().find_map(|&flag| {
                        sign_attempts += 1;
                        let msg = digest(&spending, index, code, flag);
                        let sigma = pointlocks::sign_with_nonce(msg, secret, half_key, flag)
                            .ok()?
                            .to_vec();
                        (sigma.len() == 60).then_some((sigma, flag, msg))
                    });
                    let Some((sigma, flag, msg)) = opening else {
                        continue 'opening;
                    };
                    let parsed = Signature::from_der(&sigma[..59]).unwrap();
                    secp.verify_ecdsa(&Message::from_digest(msg), &parsed, &key)
                        .unwrap();
                    let s = BigUint::from_bytes_be(&parsed.serialize_compact()[32..]);
                    let z = BigUint::from_bytes_be(&msg) % &order;
                    assert!([half.clone(), &order - &half].iter().any(|k| {
                        let pp = ((&s * k + &order - &z) * &inv_rh) % &order;
                        pp == t
                    }));
                    checks.push(json!({"flag":flag as u32,"digest":hex(&msg)}));
                    consumption.push(sigma);
                }
                frames.push(json!({"selected":selected,"depth":depth,"target":hex(&candidate.target),
                "target_scalar_fixture":hex(&candidate.secret.secret_bytes()),"short_checks":checks}));
            }
            consumption.reverse();
            let auth_digest = digest(&spending, index, &pool.code, EcdsaSighashType::All);
            let mut auth = secp
                .sign_ecdsa(&Message::from_digest(auth_digest), &one())
                .serialize_der()
                .to_vec();
            auth.push(1);
            let auth_bytes = auth.len();
            consumption.push(auth);
            consumption.push(pool.code.to_bytes());
            spending.input[index].witness = Witness::from_slice(&consumption);
            let ops = pool
                .code
                .instructions()
                .filter(|v| matches!(v,Ok(Instruction::Op(op))if op.to_u8()>0x60))
                .count();
            assert!(ops <= 201 && pool.code.len() <= 3600 && consumption.len() - 1 <= 100);
            records.push(json!({"pool":i,"input_index":index,"n":N,"t":THRESHOLD,"rounds":ROUNDS,
            "selected":selections[i],"frames":frames,"script_hex":hex(pool.code.as_bytes()),"script_bytes":pool.code.len(),
            "targets":pool.candidates.iter().map(|c|hex(&c.target)).collect::<Vec<_>>(),
            "serialized_witness_bytes":serialize(&spending.input[index].witness).len(),"charged_ops":ops,
            "hint_items":THRESHOLD,"entry_items":consumption.len()-1,"complete_witness_items":consumption.len(),
            "combined_stack_upper_bound":N+consumption.len()+5,"auth_signature_bytes":auth_bytes}));
        }
        break records;
    };
    sign_helper(&mut spending, &funding.output);
    let opening_ms = opening_start.elapsed().as_secs_f64() * 1000.;
    assert!(funding.vsize() + spending.vsize() < 100_000);
    assert!(spending.weight().to_wu() <= 400_000);
    let mut negative = vec![];
    let mut changed = spending.clone();
    let mut w: Vec<Vec<u8>> = changed.input[1]
        .witness
        .iter()
        .map(|v| v.to_vec())
        .collect();
    let auth_index = w.len() - 2;
    w[auth_index][0] ^= 1;
    changed.input[1].witness = Witness::from_slice(&w);
    negative.push(json!({"name":"invalid-mandatory-authorization","transaction":info(&changed)}));
    let mut changed = spending.clone();
    let mut w: Vec<Vec<u8>> = changed.input[1]
        .witness
        .iter()
        .map(|v| v.to_vec())
        .collect();
    w[0] = w[1].clone();
    changed.input[1].witness = Witness::from_slice(&w);
    negative.push(
        json!({"name":"repeat-short-signature-across-contexts","transaction":info(&changed)}),
    );
    let mut changed = spending.clone();
    let mut w: Vec<Vec<u8>> = changed.input[1]
        .witness
        .iter()
        .map(|v| v.to_vec())
        .collect();
    w[ROUNDS + 1] = owner_key();
    changed.input[1].witness = Witness::from_slice(&w);
    negative.push(json!({"name":"incorrect-target-public-key","transaction":info(&changed)}));
    println!("{}",serde_json::to_string_pretty(&json!({"scope":"Complete honest256-byte publication for the direct-key six-context candidate with an unresolved general extraction bound. No BitVM3 garbling/challenge integration is claimed.",
        "evidence":"locally-reproduced","deployment":"unclassified",
        "compiler_commit":provenance::compiler().unwrap().commit,"interpreter_commit":provenance::interpreter().unwrap().commit,
        "funding":info(&funding),"spending":info(&spending),"combined_vbytes":funding.vsize()+spending.vsize(),
        "payload_hex":hex(&payload),"payload_bytes":payload.len(),"radix":radix,"pool_count":POOLS,
        "candidate_count":POOLS*N,"selected_count":POOLS*THRESHOLD,"short_signature_count":POOLS*THRESHOLD*ROUNDS,
        "total_hint_items":POOLS*THRESHOLD,"total_entry_items":POOLS*(THRESHOLD*(ROUNDS+2)+1),
        "setup_generation_ms":setup_ms,"setup_verification_ms":verification_ms,"opening_ms":opening_ms,
        "setup_workers":workers,
        "opening_transaction_attempts":opening_attempts,
        "setup_curve_multiplications":setup_attempts,"short_signature_attempts":sign_attempts,
        "pools":records,"negative_cases":negative})).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rank(selected: &[usize], n: usize) -> u64 {
        let mut rank = 0;
        let mut first = 0;
        for (j, &last) in selected.iter().enumerate() {
            for i in first..last {
                rank += choose(n - i - 1, selected.len() - j - 1);
            }
            first = last + 1;
        }
        rank
    }
    #[test]
    fn every_pool_digit_roundtrips() {
        // Exhaust the actual alphabet, including the boundary where n=t=0.
        for digit in 0..choose(N, THRESHOLD) {
            let selected = unrank(digit, N, THRESHOLD);
            assert!(selected.windows(2).all(|v| v[0] < v[1]));
            assert_eq!(rank(&selected, N), digit);
        }
    }
    #[test]
    fn full_message_capacity_and_boundaries() {
        let radix = BigUint::from(choose(N, THRESHOLD));
        assert!(radix.pow(POOLS as u32) >= (BigUint::from(1u8) << 2048));
        for payload in [
            vec![0u8; 256],
            vec![255; 256],
            (0..256).map(|v| v as u8).collect(),
        ] {
            let selected = encode_payload(&payload);
            let mut result = BigUint::from(0u8);
            for pool in selected.iter().rev() {
                result = result * &radix + rank(pool, N);
            }
            assert_eq!(result, BigUint::from_bytes_be(&payload));
        }
    }
    #[test]
    #[should_panic]
    fn rejects_short_messages() {
        encode_payload(&[0; 255]);
    }
}
