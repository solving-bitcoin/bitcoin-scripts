//! Round-major anchored point-lock layout; complete sizing uses placeholders.
//! Shared separators preserve d distinct contexts for every selected label.
use bitcoin::hashes::Hash;
use bitcoin::{
    absolute,
    consensus::serialize,
    secp256k1::{ecdsa::Signature, PublicKey, Secp256k1, SecretKey},
    transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_lab::support::{
    provenance,
    script::{script, ScriptCompilation},
};
use num_bigint::BigUint;
use serde_json::json;

fn key(i: usize) -> Vec<u8> {
    let mut b = [0; 32];
    b[24..].copy_from_slice(&(i as u64 + 1).to_be_bytes());
    PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&b).unwrap())
        .serialize()
        .to_vec()
}

fn candidates(n: usize) -> Vec<(Vec<u8>, usize)> {
    let mut out = vec![];
    for i in 1.. {
        let p = key(i);
        if p[1] == 0 || p[1] >= 128 {
            continue;
        }
        let mut compact = [0; 64];
        compact[..32].copy_from_slice(&p[1..]);
        compact[63] = 1;
        let mut tau = Signature::from_compact(&compact)
            .unwrap()
            .serialize_der()
            .to_vec();
        tau.push(1);
        if bitcoin::hashes::hash160::Hash::hash(&tau).to_byte_array()[0] == 0x30 {
            continue;
        }
        assert_eq!(tau.len(), 40);
        out.push((tau, i));
        if out.len() == n {
            break;
        }
    }
    out
}

fn body(taus: &[Vec<u8>], t: usize, d: usize) -> ScriptBuf {
    let n = taus.len();
    assert!(0 < t && t <= n && d > 0);
    assert!(taus.iter().all(|tau| tau.len() == 40));
    let table: Vec<_> = taus
        .iter()
        .map(|tau| {
            bitcoin::hashes::hash160::Hash::hash(tau)
                .to_byte_array()
                .to_vec()
        })
        .collect();
    // Preserve the typed-selector setup condition against zero/outside hints.
    assert!(table.iter().all(|h| h[0] != 0x30));
    script! {
        for h in table {{h}}
        for j in 0..t {
            {n-j} OP_ROLL {n-j+1} OP_ROLL
            OP_ROLL OP_OVER OP_HASH160 OP_EQUALVERIFY OP_TOALTSTACK
        }
        for _ in 0..n-t {OP_DROP}
        // The keys lie below all d*t short signatures. The selected anchors
        // leave the altstack in reverse selection order, matching key order.
        for j in 0..t {
            OP_FROMALTSTACK {d*t+j+1} OP_PICK OP_CHECKSIGVERIFY
        }
        for r in 0..d {
            if r > 0 {OP_CODESEPARATOR}
            for j in 0..t {
                OP_SIZE 60 OP_EQUALVERIFY
                // In early rounds, signature consumption and advancing to
                // the next key cancel in the depth. Consume original keys
                // in the final round so no unused keys remain at completion.
                if r+1 == d {{t-j} OP_ROLL}
                else {{(d-r)*t} OP_PICK}
                OP_CHECKSIGVERIFY
            }
        }
        OP_TRUE
    }
    .compile_with_policy()
}

fn code(taus: &[Vec<u8>], t: usize, d: usize) -> ScriptBuf {
    let body = body(taus, t, d);
    script! {{key(0)} OP_CHECKSIGVERIFY {body}}.compile_with_policy()
}

fn num(mut n: usize) -> Vec<u8> {
    let mut out = vec![];
    while n > 0 {
        out.push((n & 255) as u8);
        n >>= 8;
    }
    if out.last().is_some_and(|b| b & 128 != 0) {
        out.push(0);
    }
    out
}
fn choose(n: usize, t: usize) -> BigUint {
    (0..t).fold(BigUint::from(1u8), |v, i| {
        v * BigUint::from(n - i) / BigUint::from(i + 1)
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
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn ops(code: &ScriptBuf) -> usize {
    code.instructions()
        .filter(|v| matches!(v, Ok(bitcoin::script::Instruction::Op(op)) if op.to_u8()>0x60))
        .count()
}

fn main() {
    let all = candidates(120);
    let taus: Vec<_> = all.iter().map(|c| c.0.clone()).collect();
    if std::env::args().any(|v| v == "--fixtures") {
        let full_pool = std::env::args().any(|v| v == "--full-pool");
        let n = if full_pool { 54 } else { 4 };
        let t = if full_pool { 5 } else { 2 };
        let d = 6;
        let script = code(&taus[..n], t, d);
        let targets: Vec<_> = all[..n]
            .iter()
            .map(|(tau, i)| {
                json!({
                    "tau_hex":hex(tau), "point_hex":hex(&key(*i)), "scalar_fixture":i+1
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json!({
            "compiler_commit":provenance::compiler().unwrap().commit,
            "fixtures":[{"n":n,"t":t,"rounds":d,"phased":true,"round_major":true,
                "anchor_context_shared_first_short":true,"script_hex":hex(script.as_bytes()),
                "script_bytes":script.len(),"entry_items":1+t*(d+3),"hint_items":t,"targets":targets}]
        })).unwrap());
        return;
    }
    let helper = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: script! {OP_1 {key(0)[1..].to_vec()}}.compile_with_policy(),
    };
    let mut best = vec![];
    let mut feasible = 0;
    for d in 5..=8 {
        let mut rows = vec![];
        for n in 3..=120 {
            for t in 1..=8.min(n - 1) {
                let entry = 1 + t * (d + 3);
                // Structural opcode bound: no cryptographic/security inference.
                if entry > 100 || (10 + 4 * d) * t + d + (n - t + 1) / 2 > 201 {
                    continue;
                }
                let script = code(&taus[..n], t, d);
                if script.len() > 3600 || ops(&script) > 201 {
                    continue;
                }
                let radix = choose(n, t);
                let mut capacity = BigUint::from(1u8);
                let mut pools = 0;
                while capacity < (BigUint::from(1u8) << 2048) {
                    capacity *= &radix;
                    pools += 1;
                }
                let mut stream = vec![];
                for j in 0..t {
                    stream.extend([taus[j].clone(), num(n - j)]);
                }
                for _ in 0..d {
                    for _ in 0..t {
                        stream.push(vec![0x30; 60]);
                    }
                }
                for _ in 0..t {
                    stream.push(key(0));
                }
                stream.reverse();
                stream.push(vec![0x30; 72]);
                stream.push(script.to_bytes());
                let witness = Witness::from_slice(&stream);
                let funding = tx(
                    vec![input(0, Witness::from_slice(&[vec![0; 64]]))],
                    std::iter::once(helper.clone())
                        .chain((0..pools).map(|_| TxOut {
                            value: Amount::from_sat(100_000),
                            script_pubkey: script.to_p2wsh(),
                        }))
                        .collect(),
                );
                let spending = tx(
                    std::iter::once(input(0, Witness::from_slice(&[vec![0; 64]])))
                        .chain((0..pools).map(|i| input(i + 1, witness.clone())))
                        .collect(),
                    vec![helper.clone()],
                );
                rows.push(json!({"rounds":d,"n":n,"t":t,"pools":pools,
                "script_bytes":script.len(),"charged_ops":ops(&script),"entry_items":entry,
                "hint_items":t,"total_hint_items":pools*t,"total_entry_items":pools*entry,
                "complete_witness_items":stream.len(),"serialized_witness_bytes":serialize(&witness).len(),
                "combined_stack_upper_bound":n+entry+6,"separators":d-1,
                "funding_vbytes":funding.vsize(),"spending_vbytes":spending.vsize(),
                "combined_vbytes":funding.vsize()+spending.vsize(),"spending_weight":spending.weight().to_wu(),
                "spending_within_policy_weight":spending.weight().to_wu()<=400_000}));
            }
        }
        feasible += rows.len();
        rows.sort_by_key(|r| r["combined_vbytes"].as_u64().unwrap());
        best.push(rows.into_iter().next().unwrap());
    }
    println!("{}",serde_json::to_string_pretty(&json!({
        "scope":"Round-major shared contexts, scan n=3..120,t=1..8,d=5..8; homogeneous repeated profiles. Actual policy-compiled scripts and complete creation/spending serialization with placeholder signature/key items, including first P2TR helper and per-pool authorization. All hints coexist at input entry; totals across inputs are not one stack. Not a complete native publication or a security/setup result.",
        "evidence":"locally-reproduced","deployment":"unclassified","native_execution":false,
        "general_extraction_proved":false,"setup_benchmark":false,
        "compiler_commit":provenance::compiler().unwrap().commit,"feasible_rows":feasible,"best_by_rounds":best
    })).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::script::Instruction;
    use std::collections::BTreeSet;
    #[test]
    fn each_label_retains_distinct_contexts_and_all_first_checks_share_anchor() {
        let taus: Vec<_> = candidates(8).into_iter().map(|x| x.0).collect();
        for t in 1..=5 {
            for d in 1..=8 {
                let code = code(&taus, t, d);
                let mut start = 0;
                let mut checks = vec![];
                let mut separators = 0;
                for instruction in code.instruction_indices() {
                    let (offset, instruction) = instruction.unwrap();
                    match instruction {
                        Instruction::Op(op) if op.to_u8() == 0xab => {
                            start = offset + 1;
                            separators += 1;
                        }
                        Instruction::Op(op) if op.to_u8() == 0xad => checks.push(start),
                        _ => (),
                    }
                }
                assert_eq!(separators, d - 1);
                assert_eq!(checks.len(), 1 + t + t * d);
                assert!(checks[..1 + 2 * t].iter().all(|&v| v == 0));
                for j in 0..t {
                    let starts: BTreeSet<_> = (0..d).map(|r| checks[1 + t + r * t + j]).collect();
                    assert_eq!(starts.len(), d);
                }
            }
        }
    }
}
