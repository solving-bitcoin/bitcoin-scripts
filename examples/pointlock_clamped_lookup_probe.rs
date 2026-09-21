//! Table-first bounded lookup for Sum-Key point-lock subsets.
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
            // Select from the table alone. MIN bounds the upper end; negative
            // depths fail in ROLL. Remove the selected entry before any operand
            // is loaded above it, so no signature/key can be selected instead.
            if direct { {c.len()-j+1} OP_ROLL } else { OP_FROMALTSTACK }
            {c.len()-j-1} OP_MIN OP_ROLL
            if direct { {c.len()-j+1} OP_ROLL } else { OP_FROMALTSTACK }
            OP_DUP OP_HASH160 OP_ROT OP_EQUALVERIFY
            if direct { {c.len()-j+1} OP_ROLL } else { OP_FROMALTSTACK }
            OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
            OP_TUCK {c.len()-j+2} OP_PICK OP_CHECKSIGVERIFY OP_CHECKSIGVERIFY
        }
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
        let depth = remaining.len() - 1 - p;
        remaining.remove(p);
        frames.push(if direct {
            vec![c[i].signature.clone(), c[i].key.clone(), int(depth)]
        } else {
            vec![int(depth), c[i].key.clone(), c[i].signature.clone()]
        });
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
    mixed_size(&vec![s.clone(); count], &vec![ss.clone(); count])
}

fn mixed_size(scripts: &[ScriptBuf], openings: &[ScriptBuf]) -> Value {
    assert_eq!(scripts.len(), openings.len());
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
    funding.output.extend(scripts.iter().map(|s| TxOut {
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
    spend.input.extend(
        openings
            .iter()
            .enumerate()
            .map(|(i, ss)| input(i as u32 + 1, ss.clone(), Witness::new())),
    );
    json!({"funding_vbytes":funding.vsize(), "spending_vbytes":spend.vsize(),
        "total_vbytes":funding.vsize()+spend.vsize(),
        "funding_weight":funding.weight().to_wu(), "spending_weight":spend.weight().to_wu()})
}

fn mixed_profile(all: &[layout::Candidate], g: &[u8]) -> Value {
    let mut scripts = vec![];
    let mut openings = vec![];
    let mut capacity = BigUint::from(1u8);
    let mut profiles = vec![];
    for (n, count) in [(67usize, 10usize), (68, 38)] {
        let t = 12;
        let script = locking(&all[..n], t, g, true);
        let items = opening(&all[..n], &(0..t).collect::<Vec<_>>(), true);
        let ss = push(&items);
        let (ok, peak) = execute(&script, items);
        assert!(ok);
        let mut radix = BigUint::from(1u8);
        for i in 0..t {
            radix = radix * (n - i) / (i + 1);
        }
        for _ in 0..count {
            capacity *= &radix;
            scripts.push(script.clone());
            openings.push(ss.clone());
        }
        profiles.push(json!({"n":n,"t":t,"pools":count,"script_bytes":script.len(),
            "script_sig_bytes":ss.len(),"combined_stack_peak":peak,"static_non_push_opcodes":opcount(&script)}));
    }
    assert!(capacity >= BigUint::from(1u8) << 2048);
    let sizes = mixed_size(&scripts, &openings);
    assert_eq!(sizes["total_vbytes"], 151176);
    json!({"profiles":profiles,"candidates":3254,"openings":576,"hint_items_per_pool":12,
        "hint_items_total":576,"entry_items_per_pool":36,"entry_items_total":1728,
        "serialized_witness_bytes":180,"capacity":capacity.to_string(),"sizes":sizes})
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

fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}

fn cases(all: &[layout::Candidate], g: &[u8]) -> Vec<Value> {
    let mut out = vec![];
    for (n, t, direct) in [
        (8, 1, true),
        (57, 10, false),
        (62, 12, true),
        (67, 12, true),
        (68, 12, true),
    ] {
        let c = &all[..n];
        let s = locking(c, t, g, direct);
        let base = opening(c, &(0..t).collect::<Vec<_>>(), direct);
        let (sig, key, hint, next_sig, next_key) = if direct {
            (
                3 * t - 3,
                3 * t - 2,
                3 * t - 1,
                (3 * t).saturating_sub(6),
                (3 * t).saturating_sub(5),
            )
        } else {
            (2, 1, 0, 5, 4)
        };
        let mut add = |name: &str,
                       items: Vec<Vec<u8>>,
                       expected: bool,
                       script: &ScriptBuf,
                       index: usize,
                       outputs: usize| {
            let local = if index == 1 && outputs == 1 {
                Some(execute(script, items.clone()))
            } else {
                None
            };
            if let Some((accepted, _)) = local {
                assert_eq!(accepted, expected, "{name}");
            }
            out.push(json!({"name":format!("{n}-{t}-{direct}-{name}"),"n":n,"t":t,"direct":direct,
                "script_hex":hex(script.as_bytes()),"items_hex":items.iter().map(|v|hex(v)).collect::<Vec<_>>(),
                "expected":expected,"locked_input_index":index,"output_count":outputs,
                "combined_stack_peak":local.map(|v|v.1),"hint_items":t,
                "keys_hex":c.iter().map(|v|hex(&v.key)).collect::<Vec<_>>()}));
        };
        add("first", base.clone(), true, &s, 1, 1);
        for (name, selection) in [
            ("last", (n - t..n).collect::<Vec<_>>()),
            ("reverse", (0..t).rev().collect()),
            ("interleaved", (0..t).map(|i| 2 * i).collect()),
        ] {
            add(name, opening(c, &selection, direct), true, &s, 1, 1);
        }
        let mut alias = base.clone();
        alias[hint] = vec![0xff, 0xff, 0xff, 0x7f];
        add("upper-alias", alias, true, &s, 1, 1);
        let mut extra = vec![vec![42; 20]];
        extra.extend(base.clone());
        add("extra-lower-item", extra, true, &s, 1, 1);
        for (name, value) in [
            ("negative-hint", vec![0x81]),
            ("oversized-hint", vec![1; 5]),
        ] {
            let mut bad = base.clone();
            bad[hint] = value;
            add(name, bad, false, &s, 1, 1);
        }
        for (name, value) in [
            ("short-signature", vec![0; 57]),
            ("malformed-signature", vec![0; 71]),
        ] {
            let mut bad = base.clone();
            bad[sig] = value;
            add(name, bad, false, &s, 1, 1);
        }
        let mut bad = base.clone();
        bad[key] = c[t].key.clone();
        add("wrong-key", bad, false, &s, 1, 1);
        let mut bad = base.clone();
        *bad[sig].last_mut().unwrap() = 1;
        add("wrong-hashtype", bad, false, &s, 1, 1);
        if t > 1 {
            let mut bad = base.clone();
            bad[next_sig] = base[sig].clone();
            bad[next_key] = base[key].clone();
            add("duplicate-opening", bad, false, &s, 1, 1);
            let too_many = locking(c, t + 1, g, direct);
            add(
                "opcode-limit",
                opening(c, &(0..t + 1).collect::<Vec<_>>(), direct),
                false,
                &too_many,
                1,
                1,
            );
        }
        add("index-zero", base.clone(), false, &s, 0, 1);
        add("two-outputs", base, false, &s, 1, 2);
    }
    out
}

fn main() {
    let (all, g) = layout::candidates(100);
    let mut rows = vec![];
    for direct in [false, true] {
        for t in 1..=13 {
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
            "examples/pointlock_clamped_lookup_probe.rs":sha256::Hash::hash(include_bytes!("pointlock_clamped_lookup_probe.rs")).to_string(),
            "examples/pointlock_sum_lookup_probe.rs":sha256::Hash::hash(include_bytes!("pointlock_sum_lookup_probe.rs")).to_string(),
            "Cargo.lock":sha256::Hash::hash(include_bytes!("../Cargo.lock")).to_string()},
        "scan":{"n_min":16,"n_max":100,"t_min":1,"t_max":13,"requires_t_lt_n":true},
        "signature_item_bytes":71,"best":best,"mixed":mixed_profile(&all,&g),
        "top20":rows[..20],"cases":cases(&all,&g)})).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subsets_aliases_and_malformed_frames() {
        let (c, g) = layout::candidates(6);
        for direct in [false, true] {
            let s = locking(&c, 3, &g, direct);
            assert_eq!(opcount(&s), if direct { 48 } else { 57 });
            for a in 0..6 {
                for b in a + 1..6 {
                    for d in b + 1..6 {
                        for selected in [[a, b, d], [d, b, a]] {
                            let entry = opening(&c, &selected, direct);
                            assert!(execute(&s, entry.clone()).0);
                            let (sig, key, hint, next_sig, next_key) = if direct {
                                (6, 7, 8, 3, 4)
                            } else {
                                (2, 1, 0, 5, 4)
                            };
                            for value in [vec![0; 57], vec![0; 71]] {
                                let mut bad = entry.clone();
                                bad[sig] = value;
                                assert!(!execute(&s, bad).0);
                            }
                            let mut bad = entry.clone();
                            bad[key] = c[(selected[0] + 1) % 6].key.clone();
                            assert!(!execute(&s, bad).0);
                            for value in [vec![0x81], vec![1; 5]] {
                                let mut bad = entry.clone();
                                bad[hint] = value;
                                assert!(!execute(&s, bad).0);
                            }
                            // All nonnegative upper aliases clamp to the bottom table
                            // entry (candidate zero); they are not additional messages.
                            for value in [int(6), int(100), vec![0xff, 0xff, 0xff, 0x7f]] {
                                let mut alias = entry.clone();
                                alias[hint] = value;
                                assert_eq!(execute(&s, alias).0, selected[0] == 0);
                            }
                            let mut bad = entry.clone();
                            bad[next_sig] = entry[sig].clone();
                            bad[next_key] = entry[key].clone();
                            assert!(!execute(&s, bad).0);
                            let mut bad = entry.clone();
                            if direct {
                                bad.drain(6..9);
                            } else {
                                bad.drain(0..3);
                            }
                            assert!(!execute(&s, bad).0);
                            let mut extra = vec![vec![42; 20]];
                            extra.extend(entry.clone());
                            assert!(execute(&s, extra).0);
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn opcode_boundary() {
        let (c, g) = layout::candidates(80);
        for direct in [false, true] {
            let t = if direct { 12 } else { 10 };
            let s = locking(&c, t, &g, direct);
            for selected in [
                (0..t).collect::<Vec<_>>(),
                (c.len() - t..c.len()).rev().collect(),
                (0..t).map(|i| 2 * i).collect(),
            ] {
                let (ok, peak) = execute(&s, opening(&c, &selected, direct));
                assert!(ok);
                assert!(peak <= c.len() + 3 * t + 5);
            }
            assert!(opcount(&s) <= 201);
            assert!(opcount(&locking(&c, t + 1, &g, direct)) > 201);
        }
    }
}
