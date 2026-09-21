//! Size probe: one anchored dynamic key, several separated ECDSA contexts.
//! Short signatures and recovered keys in serialized witnesses are placeholders.
use bitcoin::{absolute,consensus::serialize,hashes::{hash160,Hash},secp256k1::{ecdsa::Signature,PublicKey,Secp256k1,SecretKey},transaction,Amount,OutPoint,ScriptBuf,Sequence,Transaction,TxIn,TxOut,Witness};
use bitcoin_lab::support::script::{script,ScriptCompilation};
use num_bigint::BigUint;
use serde_json::json;

fn key(i:usize)->Vec<u8>{let mut a=[0;32];a[24..].copy_from_slice(&(i as u64+1).to_be_bytes());PublicKey::from_secret_key(&Secp256k1::new(),&SecretKey::from_slice(&a).unwrap()).serialize().to_vec()}
fn taus(n:usize)->Vec<Vec<u8>>{let mut out=vec![];for i in 1..{let p=key(i);if p[1]==0||p[1]&128!=0{continue;}let mut compact=[0;64];compact[..32].copy_from_slice(&p[1..]);compact[63]=1;let mut tau=Signature::from_compact(&compact).unwrap().serialize_der().to_vec();tau.push(1);assert_eq!(tau.len(),40);out.push(tau);if out.len()==n{break;}}out}
pub(crate) fn redeem(taus:&[Vec<u8>],t:usize,d:usize,hashed:bool)->ScriptBuf{
    let n=taus.len();assert!(t>0&&t<=n&&taus.iter().all(|v|v.len()==40));
    script!{
        for tau in taus{if hashed{{hash160::Hash::hash(tau).to_byte_array().to_vec()}}else{{tau.clone()}}}
        for j in 0..t{
            if hashed{
                {n-j} OP_ROLL {n-j+1} OP_ROLL
                OP_DUP 1 {n-j+1} OP_WITHIN OP_VERIFY
                OP_ROLL OP_OVER OP_HASH160 OP_EQUALVERIFY
            }else{
                {n-j} OP_ROLL OP_DUP 0 {n-j} OP_WITHIN OP_VERIFY OP_ROLL
            }
            {n-j} OP_ROLL OP_TUCK OP_CHECKSIGVERIFY
            for _ in 0..d{
                {n-j} OP_ROLL OP_SIZE 60 OP_EQUALVERIFY
                OP_OVER OP_CODESEPARATOR OP_CHECKSIGVERIFY
            }
            OP_DROP
        }
        for _ in 0..n-t{OP_DROP}
        OP_TRUE
    }.compile_with_policy()
}
fn num(mut n:usize)->Vec<u8>{let mut a=vec![];while n>0{a.push((n&255)as u8);n>>=8;}if a.last().map(|v|v&128!=0).unwrap_or(false){a.push(0);}a}
fn choose(n:usize,t:usize)->BigUint{let mut a=BigUint::from(1u8);for i in 0..t{a=a*BigUint::from(n-i)/BigUint::from(i+1);}a}
fn pools(radix:&BigUint)->usize{let mut a=BigUint::from(1u8);let target=BigUint::from(1u8)<<2048;let mut m=0;while a<target{a*=radix;m+=1;}m}
fn tx(input:Vec<TxIn>,output:Vec<TxOut>)->Transaction{Transaction{version:transaction::Version::TWO,lock_time:absolute::LockTime::ZERO,input,output}}
fn input(i:usize,witness:Witness)->TxIn{let mut outpoint=OutPoint::null();outpoint.vout=i as u32;TxIn{previous_output:outpoint,script_sig:ScriptBuf::new(),sequence:Sequence::MAX,witness}}
fn measure(taus:&[Vec<u8>],s:&ScriptBuf,t:usize,d:usize,hashed:bool,m:usize)->(usize,usize,usize,u64){
    let helper=TxOut{value:Amount::from_sat(10000),script_pubkey:script!{OP_1 {key(0)[1..].to_vec()}}.compile_with_policy()};
    let fund=tx(vec![input(0,Witness::from_slice(&[vec![0;64]]))],std::iter::once(helper.clone()).chain((0..m).map(|_|TxOut{value:Amount::from_sat(1000),script_pubkey:s.to_p2wsh()})).collect());
    let mut items=vec![];for j in 0..t{if hashed{items.push(taus[j].clone());}items.push(num(taus.len()-j-if hashed{0}else{1}));items.push(key(0));for _ in 0..d{items.push(vec![0x30;60]);}}items.reverse();items.push(s.to_bytes());let witness=Witness::from_slice(&items);
    let spend=tx(std::iter::once(input(0,Witness::from_slice(&[vec![0;64]]))).chain((0..m).map(|i|input(i+1,witness.clone()))).collect(),vec![helper]);
    (fund.vsize(),spend.vsize(),serialize(&witness).len(),spend.weight().to_wu())
}
fn main(){let all=taus(170);let mut rows=vec![];for hashed in [false,true]{for d in [3,4,5,6]{for n in 4..=if hashed{150}else{75}{for t in 1..=7.min(n-1){let rough=((if hashed{13}else{10})+6*d)*t+(n-t+1)/2;if rough>203{continue;}let s=redeem(&all[..n],t,d,hashed);let ops=s.instructions().filter(|v|matches!(v,Ok(bitcoin::script::Instruction::Op(op))if op.to_u8()>0x60)).count();let entry=t*(d+if hashed{3}else{2});if s.len()>3600||ops>201||entry>100{continue;}let m=pools(&choose(n,t));let(fv,sv,w,sw)=measure(&all[..n],&s,t,d,hashed,m);rows.push(json!({"table":if hashed{"hash160-tau"}else{"embedded-tau"},"replicas":d,"n":n,"t":t,"pools":m,"script_bytes":s.len(),"witness_bytes":w,"charged_ops":ops,"sigops":(d+1)*t,"hint_items":t,"entry_items":entry,"combined_stack_upper_bound":n+entry+6,"funding_vbytes":fv,"spending_vbytes":sv,"combined_vbytes":fv+sv,"spending_weight":sw}));}}}}rows.sort_by_key(|v|v["combined_vbytes"].as_u64().unwrap());println!("{}",serde_json::to_string_pretty(&json!({"scope":"Serialization and compilation only. Public DER tau40/ALL fixtures; sigma60 and recovered public keys are placeholders. One dynamic key per label, separated short-signature contexts. No amplification bound or native witness validity claimed.","evidence":"locally-reproduced","deployment":"unclassified","rows":rows})).unwrap());}
