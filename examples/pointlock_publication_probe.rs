//! End-to-end deterministic publication fixtures using common-G pools.
//! Default: 256 bytes. --profile 128 is a conditional compressed-proof sizing fixture.
//! All private values here are public test fixtures; never use these nonces or keys with funds.
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
use bitcoin_lab::{
    signatures::pointlocks::{self, sum_key},
    support::provenance,
};
use num_bigint::BigUint;
use serde_json::{json, Value};
use std::{collections::BTreeSet, str::FromStr};
fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    s.as_bytes()
        .chunks_exact(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}
fn compact_int(v: usize) -> Vec<u8> {
    if v == 0 {
        vec![]
    } else {
        assert!(v < 128);
        vec![v as u8]
    }
}
fn push_script(items: &[Vec<u8>], redeem: &ScriptBuf) -> ScriptBuf {
    let mut b = Builder::new();
    for item in items {
        b = if item.is_empty() {
            b.push_int(0)
        } else if item.len() == 1 && (1..=16).contains(&item[0]) {
            b.push_int(item[0] as i64)
        } else {
            b.push_slice(PushBytesBuf::try_from(item.clone()).unwrap())
        };
    }
    b.push_slice(PushBytesBuf::try_from(redeem.to_bytes()).unwrap())
        .into_script()
}
fn one() -> SecretKey {
    let mut b = [0; 32];
    b[31] = 1;
    SecretKey::from_slice(&b).unwrap()
}
fn p2tr() -> ScriptBuf {
    let key = PublicKey::from_secret_key(&Secp256k1::new(), &one())
        .x_only_public_key()
        .0;
    Builder::new()
        .push_int(1)
        .push_slice(key.serialize())
        .into_script()
}
fn input(outpoint: OutPoint) -> TxIn {
    TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }
}
fn sign_helper(tx: &mut Transaction, prevouts: &[TxOut]) {
    let hash = SighashCache::new(&*tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(prevouts), TapSighashType::Default)
        .unwrap();
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &one());
    let msg = Message::from_digest(hash.to_byte_array());
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
    secp.verify_schnorr(&sig, &msg, &kp.x_only_public_key().0)
        .unwrap();
    tx.input[0].witness = Witness::from_slice(&[sig.as_ref()]);
}
fn info(tx: &Transaction) -> Value {
    json!({"hex":hex(&serialize(tx)),"txid":tx.compute_txid().to_string(),"weight":tx.weight().to_wu(),"vbytes":tx.vsize(),"inputs":tx.input.len(),"outputs":tx.output.len(),"output_amount":tx.output[0].value.to_sat()})
}
fn choose(n: usize, k: usize) -> usize {
    if k > n {
        return 0;
    }
    let k = k.min(n - k);
    (0..k).fold(1usize, |v, i| v * (n - i) / (i + 1))
}
fn rank_combination(selection: &[usize], n: usize) -> usize {
    let mut rank = 0;
    let mut low = 0;
    for (j, &v) in selection.iter().enumerate() {
        for candidate in low..v {
            rank += choose(n - candidate - 1, selection.len() - j - 1);
        }
        low = v + 1;
    }
    rank
}
fn rank_message(selections: &[Vec<usize>], parameters: &[(usize, usize)]) -> BigUint {
    assert_eq!(selections.len(), parameters.len());
    let mut rank = BigUint::from(0u8);
    for (s, &(n, t)) in selections.iter().zip(parameters) {
        assert_eq!(s.len(), t);
        assert!(s.windows(2).all(|w| w[0] < w[1]));
        assert!(s.iter().all(|&v| v < n));
        rank = rank * choose(n, t) + rank_combination(s, n);
    }
    rank
}
// Legacy arithmetic accepts up to four sign-magnitude bytes. Minimal encoding
// is relay policy, not a universal consensus requirement.
fn positive_script_number(item: &[u8]) -> usize {
    assert!(!item.is_empty() && item.len() <= 4);
    let mut value = 0u32;
    for (i, &b) in item.iter().enumerate() {
        value |= u32::from(b) << (8 * i);
    }
    let sign = 0x80u32 << (8 * (item.len() - 1));
    assert_eq!(value & sign, 0, "negative lookup index");
    value as usize
}
fn parse_pushes(s: &ScriptBuf) -> Vec<Vec<u8>> {
    s.instructions()
        .map(|i| match i.unwrap() {
            Instruction::PushBytes(p) => p.as_bytes().to_vec(),
            Instruction::Op(op) if (0x51..=0x60).contains(&op.to_u8()) => {
                compact_int((op.to_u8() - 0x50) as usize)
            }
            Instruction::Op(op) if op.to_u8() == 0x4f => vec![0x81],
            _ => panic!("scriptSig not push-only"),
        })
        .collect()
}
struct Pool {
    candidates: Vec<layout::Candidate>,
    redeem: ScriptBuf,
    opening: Vec<Vec<u8>>,
    threshold: usize,
}
fn assertion(
    funding: &Transaction,
    pools: &[Pool],
    ids: &[usize],
    helper: OutPoint,
    helper_prevout: TxOut,
) -> Transaction {
    let mut tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input(helper)],
        output: vec![],
    };
    let mut prevouts = vec![helper_prevout.clone()];
    for &id in ids {
        let mut i = input(OutPoint {
            txid: funding.compute_txid(),
            vout: (id + 1) as u32,
        });
        i.script_sig = push_script(&pools[id].opening, &pools[id].redeem);
        tx.input.push(i);
        prevouts.push(funding.output[id + 1].clone());
    }
    let sum = prevouts.iter().map(|p| p.value.to_sat()).sum::<u64>();
    tx.output.push(TxOut {
        value: Amount::from_sat(
            sum.checked_sub(200_000)
                .expect("enough helper value for fee"),
        ),
        script_pubkey: p2tr(),
    });
    sign_helper(&mut tx, &prevouts);
    tx
}
fn decode_assertions(
    txs: &[(Transaction, Vec<usize>)],
    funding: &Transaction,
    pools: &[Pool],
    g: &[u8],
) -> (Vec<Vec<usize>>, usize) {
    let mut recovered = vec![vec![]; pools.len()];
    let mut opened = 0;
    let generator = PublicKey::from_slice(g).unwrap();
    let mut seen = BTreeSet::new();
    for (tx, ids) in txs {
        for (input_idx, &id) in ids.iter().enumerate() {
            let input_idx = input_idx + 1;
            assert!(seen.insert(id));
            assert_eq!(
                tx.input[input_idx].previous_output,
                OutPoint {
                    txid: funding.compute_txid(),
                    vout: (id + 1) as u32
                }
            );
            let mut pushes = parse_pushes(&tx.input[input_idx].script_sig);
            let redeem = ScriptBuf::from_bytes(pushes.pop().unwrap());
            assert_eq!(redeem, pools[id].redeem);
            assert_eq!(funding.output[id + 1].script_pubkey, redeem.to_p2sh());
            let consumed = 3 * pools[id].threshold;
            assert!(pushes.len() >= consumed);
            // Extra lower stack entries can survive under legacy consensus;
            // the fixed predicate only consumes these top opening frames.
            let pushes = pushes.split_off(pushes.len() - consumed);
            let mut remaining: Vec<_> = (0..pools[id].candidates.len()).collect();
            let mut selected = vec![];
            for frame in pushes.chunks_exact(3) {
                let depth = positive_script_number(&frame[2]);
                assert!((2..remaining.len() + 2).contains(&depth));
                let position = remaining.len() + 1 - depth;
                let index = remaining.remove(position);
                let p = PublicKey::from_slice(&frame[1]).unwrap();
                assert_eq!(
                    hash160::Hash::hash(&frame[1]),
                    hash160::Hash::hash(&pools[id].candidates[index].key)
                );
                assert_eq!(frame[1], pools[id].candidates[index].key);
                let flag = *frame[0].last().unwrap();
                let digest = SighashCache::new(tx)
                    .legacy_signature_hash(input_idx, &redeem, u32::from(flag))
                    .unwrap()
                    .to_byte_array();
                assert_eq!(digest, pointlocks::sighash_single_bug_message());
                let secret = sum_key::extract_from_digest(p, generator, &frame[0], digest).unwrap();
                let target = p.combine(&generator).unwrap();
                assert_eq!(
                    PublicKey::from_secret_key(&Secp256k1::new(), &secret),
                    target
                );
                selected.push(index);
                opened += 1;
            }
            selected.sort_unstable();
            assert!(!selected.is_empty() && selected.windows(2).all(|v| v[0] != v[1]));
            recovered[id] = selected;
        }
    }
    assert_eq!(seen.len(), pools.len());
    (recovered, opened)
}
fn point_serialization<A: ark_ec::AffineRepr>() -> Value {
    let point = A::generator();
    let mut compressed = Vec::new();
    let mut uncompressed = Vec::new();
    point.serialize_compressed(&mut compressed).unwrap();
    point.serialize_uncompressed(&mut uncompressed).unwrap();
    assert_eq!(
        A::deserialize_compressed(compressed.as_slice()).unwrap(),
        point
    );
    assert_eq!(
        A::deserialize_uncompressed(uncompressed.as_slice()).unwrap(),
        point
    );
    json!({"compressed_bytes":compressed.len(),"uncompressed_bytes":uncompressed.len(),"roundtrip":true})
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let profile = args
        .iter()
        .position(|a| a == "--profile")
        .map(|p| args[p + 1].parse::<usize>().unwrap())
        .unwrap_or(256);
    assert!(matches!(profile, 128 | 256));
    let arg = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .map(|p| args[p + 1].clone())
            .unwrap_or_else(|| panic!("missing {name}"))
    };
    let selection: Value =
        serde_json::from_slice(&std::fs::read(arg("--selection-json")).unwrap()).unwrap();
    let parameters: Vec<(usize, usize)> = selection["pool_parameters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["n"].as_u64().unwrap() as usize,
                p["t"].as_u64().unwrap() as usize,
            )
        })
        .collect();
    let total = selection["global_revelations"].as_u64().unwrap() as usize;
    let expected = unhex(selection["proof_hex"].as_str().unwrap());
    assert_eq!(expected.len(), profile);
    let selections: Vec<Vec<usize>> = selection["selections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            s.as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as usize)
                .collect()
        })
        .collect();
    let m = selections.len();
    if profile == 256 {
        assert_eq!((m, total), (183, 729));
        assert_eq!(parameters.iter().filter(|&&p| p == (17, 4)).count(), 180);
        assert_eq!(parameters.iter().filter(|&&p| p == (18, 3)).count(), 3);
    } else {
        assert_eq!((m, total), (92, 365));
        assert_eq!(parameters.iter().filter(|&&p| p == (17, 4)).count(), 89);
        assert_eq!(parameters.iter().filter(|&&p| p == (14, 3)).count(), 2);
        assert_eq!(parameters.iter().filter(|&&p| p == (15, 3)).count(), 1);
    }
    assert_eq!(parameters.len(), m);
    assert_eq!(
        rank_message(&selections, &parameters),
        BigUint::from_bytes_be(&expected)
    );
    let (candidates, g) = layout::candidates(parameters.iter().map(|p| p.0).sum());
    let generator = PublicKey::from_slice(&g).unwrap();
    let mut all_keys = BTreeSet::new();
    for row in &candidates {
        let p = PublicKey::from_slice(&row.key).unwrap();
        sum_key::target_point(p, generator).unwrap();
        assert!(
            all_keys.insert(row.key.clone()),
            "duplicate point across pools"
        );
        assert_eq!(row.signature.len(), 71);
    }
    let mut offset = 0;
    let pools: Vec<_> = parameters
        .iter()
        .zip(&selections)
        .map(|(&(n, t), selected)| {
            let c = &candidates[offset..offset + n];
            offset += n;
            let redeem = layout::redeem(c, t, &g);
            assert_eq!(
                redeem.len(),
                match (n, t) {
                    (17, 4) => 505,
                    (18, 3) => 502,
                    (14, 3) => 410,
                    (15, 3) => 434,
                    _ => panic!("unexpected profile pool"),
                }
            );
            Pool {
                candidates: c.to_vec(),
                opening: layout::items(c, selected),
                redeem,
                threshold: t,
            }
        })
        .collect();
    let fund_amount = arg("--funding-amount").parse::<u64>().unwrap();
    let origin = OutPoint {
        txid: bitcoin::Txid::from_str(&arg("--funding-txid")).unwrap(),
        vout: arg("--funding-vout").parse().unwrap(),
    };
    let previous = TxOut {
        value: Amount::from_sat(fund_amount),
        script_pubkey: p2tr(),
    };
    let helper_amount = fund_amount
        .checked_sub(m as u64 * 1000 + 50_000)
        .expect("funding amount");
    let mut funding = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input(origin)],
        output: vec![TxOut {
            value: Amount::from_sat(helper_amount),
            script_pubkey: p2tr(),
        }],
    };
    for p in &pools {
        funding.output.push(TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: p.redeem.to_p2sh(),
        });
    }
    sign_helper(&mut funding, &[previous]);
    let all_ids: Vec<_> = (0..m).collect();
    let single = assertion(
        &funding,
        &pools,
        &all_ids,
        OutPoint {
            txid: funding.compute_txid(),
            vout: 0,
        },
        funding.output[0].clone(),
    );
    let split = if profile == 128 {
        vec![(single.clone(), all_ids.clone())]
    } else {
        let first_ids: Vec<_> = (0..101).collect();
        let second_ids: Vec<_> = (101..m).collect();
        let first = assertion(
            &funding,
            &pools,
            &first_ids,
            OutPoint {
                txid: funding.compute_txid(),
                vout: 0,
            },
            funding.output[0].clone(),
        );
        let second = assertion(
            &funding,
            &pools,
            &second_ids,
            OutPoint {
                txid: first.compute_txid(),
                vout: 0,
            },
            first.output[0].clone(),
        );
        vec![(first, first_ids), (second, second_ids)]
    };
    let (recovered, opened) = decode_assertions(&split, &funding, &pools, &g);
    assert_eq!(opened, total);
    assert_eq!(recovered, selections);
    let recovered_rank = rank_message(&recovered, &parameters);
    assert_eq!(recovered_rank, BigUint::from_bytes_be(&expected));
    let (single_recovered, single_opened) =
        decode_assertions(&[(single.clone(), all_ids)], &funding, &pools, &g);
    assert_eq!(single_recovered, recovered);
    assert_eq!(single_opened, total);
    let infos: Vec<_> = split
        .iter()
        .map(|(tx, ids)| {
            let mut v = info(tx);
            v["pool_ids"] = json!(ids);
            v
        })
        .collect();
    let total_vbytes = funding.vsize() + split.iter().map(|(t, _)| t.vsize()).sum::<usize>();
    if profile == 128 {
        let g1 = point_serialization::<ark_bn254::G1Affine>();
        let g2 = point_serialization::<ark_bn254::G2Affine>();
        assert_eq!(g1["compressed_bytes"], 32);
        assert_eq!(g1["uncompressed_bytes"], 64);
        assert_eq!(g2["compressed_bytes"], 64);
        assert_eq!(g2["uncompressed_bytes"], 128);
        eprintln!("BN254 point serialization round trips: G1 64→32 bytes, G2 128→64 bytes; an A/B/C triple is 256→128 bytes. The publication payload is synthetic, not a Groth16 proof.");
    }
    println!("{}",serde_json::to_string_pretty(&json!({"compiler":provenance::compiler().unwrap().commit,"funding_tx_hex":hex(&serialize(&funding)),"assertion_tx_hexes":split.iter().map(|(t,_)|hex(&serialize(t))).collect::<Vec<_>>(),"funding":info(&funding),"assertions":infos,"single_assertion":info(&single),"combined_split_vbytes":total_vbytes,"combined_two_tx_vbytes":funding.vsize()+single.vsize(),"recovered_proof_hex":hex(&expected),"actual_native_digest_extractions":opened,"pool_parameters":parameters.iter().map(|&(n,t)|json!({"n":n,"t":t})).collect::<Vec<_>>(),"pool_count":m,"global_revelations":total,"verified_canonical_subsets":recovered,"pool_commitments":pools.iter().enumerate().map(|(id,p)|json!({"id":id,"n":p.candidates.len(),"t":p.threshold,"redeem_hex":hex(p.redeem.as_bytes()),"verification_keys_hex":p.candidates.iter().map(|c|hex(&c.key)).collect::<Vec<_>>(),"targets_hex":p.candidates.iter().map(|c|hex(&PublicKey::from_slice(&c.key).unwrap().combine(&generator).unwrap().serialize())).collect::<Vec<_>>()})).collect::<Vec<_>>() })).unwrap());
}
