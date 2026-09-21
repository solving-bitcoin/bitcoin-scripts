//! Typed destructive selection and two-phase table use for anchored point locks.
//! Signatures and recovered keys are placeholders. No extraction bound follows.
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
// Public setup MUST reject any table commitment that is itself an acceptable
// nonempty ECDSA signature. In particular, requiring first byte != 0x30 is a
// sufficient conservative check. Index zero otherwise admits a type confusion.
// This sizing probe checks that sufficient condition in its public fixtures.
pub(crate) fn redeem(taus: &[Vec<u8>], t: usize, d: usize, phased: bool) -> ScriptBuf {
    redeem_variant(taus, t, d, phased, true, false)
}

pub(crate) fn redeem_shared(taus: &[Vec<u8>], t: usize, d: usize, phased: bool) -> ScriptBuf {
    redeem_variant(taus, t, d, phased, true, true)
}

fn redeem_variant(
    taus: &[Vec<u8>],
    t: usize,
    d: usize,
    phased: bool,
    consume_last_key: bool,
    share_first_context: bool,
) -> ScriptBuf {
    let n = taus.len();
    assert!(t > 0 && t <= n && d > 0);
    assert!(taus.iter().all(|tau| tau.len() == 40));
    let table: Vec<_> = taus
        .iter()
        .map(|tau| {
            bitcoin::hashes::hash160::Hash::hash(tau)
                .to_byte_array()
                .to_vec()
        })
        .collect();
    assert!(table.iter().all(|h| h[0] != 0x30));
    script! {
        for h in table {{h}}
        for j in 0..t {
            {n-j} OP_ROLL {n-j+1} OP_ROLL
            OP_ROLL OP_OVER OP_HASH160 OP_EQUALVERIFY
            if phased {OP_TOALTSTACK}
            else {
                {n-j} OP_ROLL OP_TUCK OP_CHECKSIGVERIFY
                for r in 0..d {
                    {n-j} OP_ROLL OP_SIZE 60 OP_EQUALVERIFY
                    if consume_last_key && r+1==d {OP_SWAP} else {OP_OVER}
                    if !share_first_context || r > 0 {OP_CODESEPARATOR}
                    OP_CHECKSIGVERIFY
                }
                if !consume_last_key {OP_DROP}
            }
        }
        for _ in 0..n-t {OP_DROP}
        if phased {
            for _ in 0..t {
                OP_FROMALTSTACK OP_OVER OP_CHECKSIGVERIFY
                for r in 0..d {
                    OP_SWAP OP_SIZE 60 OP_EQUALVERIFY
                    if consume_last_key && r+1==d {OP_SWAP} else {OP_OVER}
                    if !share_first_context || r > 0 {OP_CODESEPARATOR}
                    OP_CHECKSIGVERIFY
                }
                if !consume_last_key {OP_DROP}
            }
        }
        OP_TRUE
    }
    .compile_with_policy()
}

use serde_json::json;

fn key(i: usize) -> Vec<u8> {
    let mut b = [0; 32];
    b[24..].copy_from_slice(&(i as u64 + 1).to_be_bytes());
    PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&b).unwrap())
        .serialize()
        .to_vec()
}
fn taus(n: usize) -> Vec<Vec<u8>> {
    let mut out = vec![];
    for i in 1.. {
        let p = key(i);
        if p[1] == 0 || p[1] >= 128 {
            continue;
        }
        let mut b = [0; 64];
        b[..32].copy_from_slice(&p[1..]);
        b[63] = 1;
        let mut tau = Signature::from_compact(&b)
            .unwrap()
            .serialize_der()
            .to_vec();
        tau.push(1);
        assert_eq!(tau.len(), 40);
        if bitcoin::hashes::hash160::Hash::hash(&tau).to_byte_array()[0] == 0x30 {
            continue;
        }
        out.push(tau);
        if out.len() == n {
            break;
        }
    }
    out
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
fn main() {
    run(false);
}

pub(crate) fn run(share_first_context: bool) {
    let make_body = if share_first_context {
        redeem_shared
    } else {
        redeem
    };
    let candidates = taus(180);
    let owner = key(0);
    if std::env::args().any(|v| v == "--fixtures") {
        let mut fixtures = vec![];
        for phased in [false, true] {
            let n = 4;
            let t = 2;
            let rounds = if share_first_context { 6 } else { 1 };
            let body = make_body(&candidates[..n], t, rounds, phased);
            let code = script! {{owner.clone()} OP_CHECKSIGVERIFY {body}}.compile_with_policy();
            let targets: Vec<_> = candidates[..n]
                .iter()
                .map(|tau| {
                    let compact = Signature::from_der(&tau[..tau.len() - 1])
                        .unwrap()
                        .serialize_compact();
                    let i = (1..1000).find(|&i| key(i)[1..] == compact[..32]).unwrap();
                    json!({"tau_hex":hex(tau),"point_hex":hex(&key(i)),"scalar_fixture":i+1})
                })
                .collect();
            fixtures.push(json!({"phased":phased,"n":n,"t":t,"rounds":rounds,
                "anchor_context_shared_first_short":share_first_context,
                "script_hex":hex(code.as_bytes()),"script_bytes":code.len(),
                "entry_items":1+t*(rounds+3),"hint_items":t,"targets":targets}));
        }
        println!("{}",serde_json::to_string_pretty(&json!({"compiler_commit":provenance::compiler().unwrap().commit,
            "scope":"Small native selector fixtures only; deterministic public secrets, no complete publication claim.",
            "fixtures":fixtures})).unwrap());
        return;
    }
    let helper = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: script! {OP_1 {owner[1..].to_vec()}}.compile_with_policy(),
    };
    let mut best = vec![];
    let mut feasible_rows = 0;
    for rounds in 5..=8 {
        let mut rows = vec![];
        for phased in [false, true] {
            for n in 3..=180 {
                for t in 1..=10.min(n - 1) {
                    let entry = 1 + t * (rounds + 3);
                    if entry > 100
                        || (7 + 6 * rounds - usize::from(share_first_context)) * t
                            + (n - t + 1) / 2
                            + 1
                            > 210
                    {
                        continue;
                    }
                    let body = make_body(&candidates[..n], t, rounds, phased);
                    let code =
                        script! {{owner.clone()} OP_CHECKSIGVERIFY {body}}.compile_with_policy();
                    let ops=code.instructions().filter(|v|matches!(v,Ok(bitcoin::script::Instruction::Op(op))if op.to_u8()>0x60)).count();
                    if code.len() > 3600 || ops > 201 {
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
                    if phased {
                        for j in 0..t {
                            items.extend([candidates[j].clone(), num(n - j)]);
                        }
                        for _ in (0..t).rev() {
                            items.push(owner.clone());
                            items.extend((0..rounds).map(|_| vec![0x30; 60]));
                        }
                    } else {
                        for j in 0..t {
                            items.extend([candidates[j].clone(), num(n - j), owner.clone()]);
                            items.extend((0..rounds).map(|_| vec![0x30; 60]));
                        }
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
                    rows.push(json!({"rounds":rounds,"phased":phased,"n":n,"t":t,"pools":pools,
                "script_bytes":code.len(),"charged_ops":ops,"entry_items":entry,
                "hint_items":t,"total_hint_items":pools*t,"total_entry_items":pools*entry,
                "complete_witness_items":items.len(),"serialized_witness_bytes":serialize(&witness).len(),
                "combined_stack_upper_bound":n+entry+6,
                "funding_vbytes":funding.vsize(),"spending_vbytes":spending.vsize(),
                "combined_vbytes":funding.vsize()+spending.vsize(),"spending_weight":spending.weight().to_wu(),
                "spending_within_policy_weight":spending.weight().to_wu()<=400_000}));
                }
            }
        }
        feasible_rows += rows.len();
        rows.sort_by_key(|r| r["combined_vbytes"].as_u64().unwrap());
        for phased in [false, true] {
            best.push(
                rows.iter()
                    .find(|r| r["phased"].as_bool() == Some(phased))
                    .unwrap()
                    .clone(),
            );
        }
    }
    println!("{}",serde_json::to_string_pretty(&json!({
        "scope":"Bounded scan n=3..180,t=1..10,rounds=5..8; typed selection with an inline or phased table. Every table hash begins with a byte other than 0x30. One repeated homogeneous profile per row, actual scripts but placeholder short/recovered-key/authorization witnesses. Includes full creation plus spending of every output, one P2TR helper and mandatory per-pool authorization. All hints coexist with other data at entry of their own input; sums across inputs are not one stack. Sizes are policy-compiled, not unoptimized. Not a global size bound or native execution; small native fixtures are reported separately.",
        "evidence":"locally-reproduced","deployment":"unclassified",
        "native_execution":false,"general_extraction_proved":false,"setup_benchmark":false,
        "anchor_context_shared_first_short":share_first_context,
        "compiler_commit":provenance::compiler().unwrap().commit,
        "feasible_rows":feasible_rows,"best_by_rounds":best})).unwrap());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_key_consumption_is_not_already_optimized() {
        let candidates = taus(4);
        for phased in [false, true] {
            let baseline = redeem_variant(&candidates, 2, 1, phased, false, false);
            let consumed = redeem(&candidates, 2, 1, phased);
            let count =
                |code: &ScriptBuf| {
                    code.instructions().filter(|i|
                matches!(i,Ok(bitcoin::script::Instruction::Op(op)) if op.to_u8()>0x60)).count()
                };
            // The final pair is consumed directly instead of retaining and
            // dropping P across CODESEPARATOR. Both are compiled first.
            // Core exercises the consumed form on every ordered 2-of-4 choice.
            assert_eq!(baseline.len(), consumed.len() + 2);
            assert_eq!(count(&baseline), count(&consumed) + 2);
        }
    }

    #[test]
    fn sharing_anchor_context_preserves_distinct_short_contexts() {
        use bitcoin::script::Instruction;
        use std::collections::BTreeSet;
        let candidates = taus(8);
        for phased in [false, true] {
            for d in 1..=8 {
                let previous = redeem(&candidates, 3, d, phased);
                let shared = redeem_shared(&candidates, 3, d, phased);
                assert_eq!(previous.len(), shared.len() + 3);
                let mut start = 0;
                let mut contexts = vec![];
                let mut separators = 0;
                for instruction in shared.instruction_indices() {
                    let (offset, instruction) = instruction.unwrap();
                    match instruction {
                        Instruction::Op(op) if op.to_u8() == 0xab => {
                            start = offset + 1;
                            separators += 1;
                        }
                        Instruction::Op(op) if op.to_u8() == 0xad => contexts.push(start),
                        _ => (),
                    }
                }
                assert_eq!(separators, 3 * (d - 1));
                assert_eq!(contexts.len(), 3 * (d + 1));
                for group in contexts.chunks_exact(d + 1) {
                    assert_eq!(group[0], group[1]);
                    assert_eq!(group[1..].iter().collect::<BTreeSet<_>>().len(), d);
                }
                // Equal scriptCode only implies equal BIP143 digest if the
                // complete sighash context, including raw flag, also matches.
            }
        }
    }
}
