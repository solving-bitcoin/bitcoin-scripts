//! Binohash-style direct stack access versus staged Sum-Key lookup tables.
//! Counts both transactions; repeated pool fixtures are sizing only.
#[allow(dead_code)]
#[path = "pointlock_sum_lookup_probe.rs"]
mod layout;

use bitcoin::{
    absolute,
    hashes::{hash160, sha256, Hash},
    script::{Builder, Instruction, PushBytesBuf},
    transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_lab::support::{
    provenance,
    script::{script, ScriptCompilation},
};
use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};
use num_bigint::BigUint;
use serde_json::{json, Value};

fn locking(c: &[layout::Candidate], t: usize, g: &[u8], direct: bool) -> ScriptBuf {
    assert!(t > 0 && t <= c.len());
    script! {
        if !direct { for _ in 0..3*t { OP_TOALTSTACK } }
        {g.to_vec()}
        for row in c { {hash160::Hash::hash(&row.key).to_byte_array().to_vec()} }
        for j in 0..t {
            // Direct frames are reversed at entry. Removing the oldest operand
            // from below G and the table leaves the next one at the same depth.
            if direct { {c.len()-j+3} OP_ROLL } else { OP_FROMALTSTACK }
            OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
            if direct {
                {c.len()-j+3} OP_ROLL
                {c.len()-j+3} OP_ROLL
            } else { OP_FROMALTSTACK OP_FROMALTSTACK }
            OP_DUP 2 {c.len()-j+2} OP_WITHIN OP_VERIFY
            OP_ROLL OP_OVER OP_HASH160 OP_EQUALVERIFY
            OP_OVER {c.len()-j+2} OP_PICK OP_CHECKSIGVERIFY OP_CHECKSIGVERIFY
        }
        // Bare consensus permits the unused commitments to remain.
        OP_TRUE
    }
    .compile_with_policy()
}

fn int(n: usize) -> Vec<u8> {
    Builder::new()
        .push_int(n as i64)
        .into_script()
        .instructions()
        .next()
        .map(|v| match v.unwrap() {
            Instruction::PushBytes(b) => b.as_bytes().to_vec(),
            Instruction::Op(op) if op.to_u8() >= 0x51 && op.to_u8() <= 0x60 => {
                vec![op.to_u8() - 0x50]
            }
            _ => panic!("unexpected number encoding"),
        })
        .unwrap()
}

fn opening(c: &[layout::Candidate], selected: &[usize], direct: bool) -> Vec<Vec<u8>> {
    let mut remaining: Vec<_> = (0..c.len()).collect();
    let mut frames = vec![];
    for &i in selected {
        let p = remaining.iter().position(|&v| v == i).unwrap();
        let depth = remaining.len() + 1 - p;
        remaining.remove(p);
        frames.push(vec![c[i].signature.clone(), c[i].key.clone(), int(depth)]);
    }
    if direct {
        frames.reverse();
    }
    frames.into_iter().flatten().collect()
}

fn push(items: &[Vec<u8>]) -> ScriptBuf {
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
    b.into_script()
}

fn opcount(s: &ScriptBuf) -> usize {
    s.instructions()
        .filter(|i| matches!(i, Ok(Instruction::Op(op)) if op.to_u8()>0x60))
        .count()
}

fn pools(n: usize, t: usize) -> usize {
    let mut radix = BigUint::from(1u8);
    for i in 0..t {
        radix = radix * (n - i) / (i + 1);
    }
    let target = BigUint::from(1u8) << 2048;
    let (mut capacity, mut count) = (BigUint::from(1u8), 0);
    while capacity < target {
        capacity *= &radix;
        count += 1;
    }
    count
}

fn input(vout: u32, script_sig: ScriptBuf, witness: Witness) -> TxIn {
    TxIn {
        previous_output: OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout,
        },
        script_sig,
        sequence: Sequence::MAX,
        witness,
    }
}

fn size(s: &ScriptBuf, ss: &ScriptBuf, count: usize) -> Value {
    // Valid serialization shapes, not independently funded candidate sets.
    let p2tr = Builder::new()
        .push_int(1)
        .push_slice([1u8; 32])
        .into_script();
    let helper = || input(0, ScriptBuf::new(), Witness::from_slice(&[vec![0u8; 64]]));
    let mut funding = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![helper()],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: p2tr.clone(),
        }],
    };
    funding.output.extend((0..count).map(|_| TxOut {
        value: Amount::ZERO,
        script_pubkey: s.clone(),
    }));
    let mut spend = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![helper()],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: p2tr,
        }],
    };
    spend
        .input
        .extend((1..=count).map(|i| input(i as u32, ss.clone(), Witness::new())));
    json!({"funding_vbytes":funding.vsize(), "spending_vbytes":spend.vsize(),
        "total_vbytes":funding.vsize()+spend.vsize(),
        "funding_weight":funding.weight().to_wu(), "spending_weight":spend.weight().to_wu()})
}

fn execute(s: &ScriptBuf, items: Vec<Vec<u8>>) -> (bool, usize) {
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            input(0, ScriptBuf::new(), Witness::new()),
            input(1, ScriptBuf::new(), Witness::new()),
        ],
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
    (e.result().unwrap().success, e.stats().max_nb_stack_items)
}

fn main() {
    let (all, g) = layout::candidates(100);
    let mut rows = vec![];
    for direct in [false, true] {
        for t in 1..=12 {
            for n in (t + 1).max(16)..=100 {
                let s = locking(&all[..n], t, &g, direct);
                let ops = opcount(&s);
                if ops > 201 || s.len() > 10_000 {
                    continue;
                }
                let entry = opening(&all[..n], &(0..t).collect::<Vec<_>>(), direct);
                let ss = push(&entry);
                let count = pools(n, t);
                rows.push(json!({"layout":if direct {"direct"} else {"staged"},
                    "n":n,"t":t,"pools":count,"candidates":n*count,"openings":t*count,
                    "script_bytes":s.len(),"script_sig_bytes":ss.len(),"static_non_push_opcodes":ops,
                    "hint_items_per_pool":t,"entry_items_per_pool":3*t,
                    "hint_items_total":t*count,"entry_items_total":3*t*count,
                    "serialized_witness_bytes":132+count,"sizes":size(&s,&ss,count)}));
            }
        }
    }
    rows.sort_by_key(|v| v["sizes"]["total_vbytes"].as_u64().unwrap());
    let best: Vec<_> = ["staged", "direct"]
        .into_iter()
        .map(|kind| {
            let mut row = rows.iter().find(|r| r["layout"] == kind).unwrap().clone();
            let n = row["n"].as_u64().unwrap() as usize;
            let t = row["t"].as_u64().unwrap() as usize;
            let s = locking(&all[..n], t, &g, kind == "direct");
            let entry = opening(&all[..n], &(0..t).collect::<Vec<_>>(), kind == "direct");
            let (ok, peak) = execute(&s, entry);
            assert!(ok);
            row["combined_stack_peak"] = json!(peak);
            row["pool_local_execution_accepted"] = json!(ok);
            row
        })
        .collect();
    println!("{}",serde_json::to_string_pretty(&json!({"compiler":provenance::compiler().unwrap().commit,
        "interpreter":provenance::interpreter().unwrap().commit,
        "evidence":"locally-reproduced","execution_class":"unclassified",
        "boundary":"Complete serialized transaction size estimates; repeated pool fixtures; no full publication validation",
        "source_sha256":{
            "examples/pointlock_hors_lookup_probe.rs":sha256::Hash::hash(include_bytes!("pointlock_hors_lookup_probe.rs")).to_string(),
            "examples/pointlock_sum_lookup_probe.rs":sha256::Hash::hash(include_bytes!("pointlock_sum_lookup_probe.rs")).to_string(),
            "Cargo.lock":sha256::Hash::hash(include_bytes!("../Cargo.lock")).to_string()},
        "scan":{"n_min":16,"n_max":100,"t_min":1,"t_max":12,"requires_t_lt_n":true},
        "signature_item_bytes":71,"best":best,"top20":rows[..20]})).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn direct_table_subsets_and_malformed_frames() {
        let (c, g) = layout::candidates(6);
        let s = locking(&c, 3, &g, true);
        assert_eq!(opcount(&s), 51);
        for a in 0..6 {
            for b in a + 1..6 {
                for d in b + 1..6 {
                    for selected in [[a, b, d], [d, b, a]] {
                        let entry = opening(&c, &selected, true);
                        assert!(execute(&s, entry.clone()).0);
                        let mut bad = entry.clone();
                        bad[6] = vec![0; 57];
                        assert!(!execute(&s, bad).0);
                        let mut bad = entry.clone();
                        bad[7] = c[(selected[0] + 1) % 6].key.clone();
                        assert!(!execute(&s, bad).0);
                        for hint in [vec![], vec![1], vec![8], vec![0x81], vec![1; 5]] {
                            let mut bad = entry.clone();
                            bad[8] = hint;
                            assert!(!execute(&s, bad).0);
                        }
                        let mut bad = entry.clone();
                        bad.drain(6..9);
                        assert!(!execute(&s, bad).0);
                        let mut bad = entry.clone();
                        bad[3] = entry[6].clone();
                        bad[4] = entry[7].clone();
                        assert!(!execute(&s, bad).0);
                    }
                }
            }
        }
    }
    #[test]
    fn direct_large_pool_and_opcode_boundary() {
        let (c, g) = layout::candidates(64);
        for direct in [false, true] {
            let t = if direct { 11 } else { 10 };
            let c = &c[..if direct { 64 } else { 57 }];
            let s = locking(&c, t, &g, direct);
            for selected in [
                (0..t).collect::<Vec<_>>(),
                (c.len() - t..c.len()).rev().collect(),
                (0..t).map(|i| 2 * i).collect(),
            ] {
                let entry = opening(&c, &selected, direct);
                let (ok, peak) = execute(&s, entry);
                assert!(ok);
                assert!(peak <= c.len() + 3 * t + 5);
            }
            assert!(opcount(&s) <= 201);
            assert!(opcount(&locking(&c, t + 1, &g, direct)) > 201);
            let ss = push(&opening(&c, &(0..t).collect::<Vec<_>>(), direct));
            let expected = if direct { 153687 } else { 153125 };
            assert_eq!(size(&s, &ss, pools(c.len(), t))["total_vbytes"], expected);
        }
    }
}
