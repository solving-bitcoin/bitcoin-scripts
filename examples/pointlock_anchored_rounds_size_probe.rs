//! Bounded sizing of the authenticated anchored candidate as rounds increase.
//! Signatures and recovered keys are placeholders. No extraction bound follows.
#[allow(dead_code)]
#[path = "pointlock_anchored_codesep_size_probe.rs"]
mod layout;

use bitcoin::{absolute, consensus::serialize, secp256k1::{ecdsa::Signature, PublicKey, Secp256k1, SecretKey},
    transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin_lab::support::{provenance, script::{script, ScriptCompilation}};
use num_bigint::BigUint;
use serde_json::json;

fn key(i:usize)->Vec<u8>{
    let mut b=[0;32];b[24..].copy_from_slice(&(i as u64+1).to_be_bytes());
    PublicKey::from_secret_key(&Secp256k1::new(),&SecretKey::from_slice(&b).unwrap()).serialize().to_vec()
}
fn taus(n:usize)->Vec<Vec<u8>>{
    let mut out=vec![];
    for i in 1..{
        let p=key(i);if p[1]==0||p[1]>=128{continue;}
        let mut b=[0;64];b[..32].copy_from_slice(&p[1..]);b[63]=1;
        let mut tau=Signature::from_compact(&b).unwrap().serialize_der().to_vec();tau.push(1);
        assert_eq!(tau.len(),40);out.push(tau);if out.len()==n{break;}
    }out
}
fn num(mut n:usize)->Vec<u8>{
    let mut out=vec![];while n>0{out.push((n&255)as u8);n>>=8;}
    if out.last().is_some_and(|b|b&128!=0){out.push(0);}out
}
fn choose(n:usize,t:usize)->BigUint{
    (0..t).fold(BigUint::from(1u8),|v,i|v*BigUint::from(n-i)/BigUint::from(i+1))
}
fn input(i:usize,witness:Witness)->TxIn{
    let mut outpoint=OutPoint::null();outpoint.vout=i as u32;
    TxIn{previous_output:outpoint,script_sig:ScriptBuf::new(),sequence:Sequence::MAX,witness}
}
fn tx(input:Vec<TxIn>,output:Vec<TxOut>)->Transaction{
    Transaction{version:transaction::Version::TWO,lock_time:absolute::LockTime::ZERO,input,output}
}
fn main(){
    let candidates=taus(180);let owner=key(0);
    let helper=TxOut{value:Amount::from_sat(100_000),script_pubkey:script!{OP_1 {owner[1..].to_vec()}}.compile_with_policy()};
    let mut best=vec![];let mut feasible_rows=0;
    for rounds in 3..=16{
        let mut rows=vec![];
        for n in 3..=180{for t in 1..=10.min(n-1){
            let entry=1+t*(rounds+3);
            if entry>100||(13+6*rounds)*t+(n-t+1)/2+1>203{continue;}
            let body=layout::redeem(&candidates[..n],t,rounds,true);
            let code=script!{{owner.clone()} OP_CHECKSIGVERIFY {body}}.compile_with_policy();
            let ops=code.instructions().filter(|v|matches!(v,Ok(bitcoin::script::Instruction::Op(op))if op.to_u8()>0x60)).count();
            if code.len()>3600||ops>201{continue;}
            let radix=choose(n,t);let mut capacity=BigUint::from(1u8);let mut pools=0;
            while capacity<(BigUint::from(1u8)<<2048){capacity*=&radix;pools+=1;}
            let mut items=vec![];
            for j in 0..t{
                items.extend([candidates[j].clone(),num(n-j),owner.clone()]);
                items.extend((0..rounds).map(|_|vec![0x30;60]));
            }
            items.reverse();items.push(vec![0x30;72]);items.push(code.to_bytes());
            let witness=Witness::from_slice(&items);
            let funding=tx(vec![input(0,Witness::from_slice(&[vec![0;64]]))],
                std::iter::once(helper.clone()).chain((0..pools).map(|_|TxOut{value:Amount::from_sat(100_000),script_pubkey:code.to_p2wsh()})).collect());
            let spending=tx(std::iter::once(input(0,Witness::from_slice(&[vec![0;64]])))
                .chain((0..pools).map(|i|input(i+1,witness.clone()))).collect(),vec![helper.clone()]);
            rows.push(json!({"rounds":rounds,"n":n,"t":t,"pools":pools,
                "script_bytes":code.len(),"charged_ops":ops,"entry_items":entry,
                "hint_items":t,"total_hint_items":pools*t,"total_entry_items":pools*entry,
                "complete_witness_items":items.len(),"serialized_witness_bytes":serialize(&witness).len(),
                "combined_stack_upper_bound":n+entry+6,
                "funding_vbytes":funding.vsize(),"spending_vbytes":spending.vsize(),
                "combined_vbytes":funding.vsize()+spending.vsize(),"spending_weight":spending.weight().to_wu(),
                "spending_within_policy_weight":spending.weight().to_wu()<=400_000}));
        }}
        feasible_rows+=rows.len();rows.sort_by_key(|r|r["combined_vbytes"].as_u64().unwrap());
        best.push(rows.into_iter().next().unwrap());
    }
    println!("{}",serde_json::to_string_pretty(&json!({
        "scope":"Bounded scan n=3..180,t=1..10,rounds=3..16. One repeated homogeneous profile per row, actual scripts but placeholder short/recovered-key/authorization witnesses. Includes full creation plus spending of every output, one P2TR helper and mandatory per-pool authorization. Not a global size bound or native execution.",
        "evidence":"locally-reproduced","deployment":"unclassified",
        "compiler_commit":provenance::compiler().unwrap().commit,
        "feasible_rows":feasible_rows,"best_by_rounds":best})).unwrap());
}
