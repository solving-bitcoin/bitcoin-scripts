//! Honest native SegWit-v0 checks for an anchored-key candidate.
//! This is not a proof that every accepted opening reveals the target scalar.
//! All fixture scalars are deterministic and public; never use them for funds.
use bitcoin::{
    absolute, hashes::{sha256, Hash}, opcodes::all::OP_CODESEPARATOR,
    script::Instruction, secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey},
    sighash::SighashCache, transaction, Amount, EcdsaSighashType, OutPoint, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_lab::{signatures::pointlocks, support::script::{script, ScriptCompilation}};
use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};
use num_bigint::BigUint;
use serde_json::json;
use std::str::FromStr;

fn scalar(v: &BigUint) -> SecretKey {
    let b = v.to_bytes_be();
    let mut out = [0u8; 32];
    out[32-b.len()..].copy_from_slice(&b);
    SecretKey::from_slice(&out).unwrap()
}
fn hex(v: &[u8]) -> String { v.iter().map(|b| format!("{b:02x}")).collect() }
fn input(txid: bitcoin::Txid, vout: u32) -> TxIn {
    TxIn { previous_output: OutPoint { txid, vout }, script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX, witness: Witness::new() }
}
fn digest(tx: &Transaction, code: &ScriptBuf, flag: EcdsaSighashType) -> [u8; 32] {
    SighashCache::new(tx).p2wsh_signature_hash(1, code, Amount::from_sat(100_000), flag)
        .unwrap().to_byte_array()
}
fn execute(tx: &Transaction, code: &ScriptBuf, data: Vec<Vec<u8>>) -> (bool, usize) {
    let mut exec = Exec::new(ExecCtx::SegwitV0, Options::default(), TxTemplate {
        tx: tx.clone(), prevouts: vec![
            TxOut { value: Amount::from_sat(100_000), script_pubkey: ScriptBuf::new() },
            TxOut { value: Amount::from_sat(100_000), script_pubkey: code.to_p2wsh() },
        ], input_idx: 1, taproot_annex_scriptleaf: None,
    }, code.clone(), data).unwrap();
    while exec.exec_next().is_ok() {}
    if !exec.result().unwrap().success && std::env::var_os("ANCHOR_DIAGNOSTIC").is_some() {
        eprintln!("{:?}", exec.result());
    }
    (exec.result().unwrap().success, exec.stats().max_nb_stack_items)
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| args.iter().position(|v|v==name).map(|i|args[i+1].clone());
    let funding_txid = bitcoin::Txid::from_str(&arg("--funding-txid")
        .unwrap_or_else(||"00".repeat(32))).unwrap();
    let selected_seed = arg("--seed").map(|s|s.parse::<usize>().unwrap());
    let selected_repetitions = arg("--repetitions").map(|s|s.parse::<usize>().unwrap());
    let order = BigUint::parse_bytes(b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16).unwrap();
    let half = (&order + BigUint::from(1u8))/2u8;
    let half_secret = scalar(&half);
    let half_r = BigUint::from_bytes_be(&pointlocks::G_HALF_R);
    let half_r_inverse = half_r.modpow(&(&order-2u8), &order);
    let secp = Secp256k1::new();
    let flags = [EcdsaSighashType::All, EcdsaSighashType::None,
        EcdsaSighashType::Single, EcdsaSighashType::AllPlusAnyoneCanPay,
        EcdsaSighashType::NonePlusAnyoneCanPay, EcdsaSighashType::SinglePlusAnyoneCanPay];
    let mut cases = vec![];
    let mut sign_attempts = 0;
    for seed in 0..16 {
        if selected_seed.is_some_and(|s|s!=seed) { continue; }
        let mut attempt = 0;
        let (target_secret, target, r, tau) = loop {
            let raw = sha256::Hash::hash(format!("anchored-native-{seed}-{attempt}").as_bytes()).to_byte_array();
            attempt += 1;
            let sk = SecretKey::from_slice(&raw).unwrap();
            let point = PublicKey::from_secret_key(&secp, &sk);
            let x = point.x_only_public_key().0.serialize();
            if x[0] == 0 || x[0] >= 128 { continue; }
            let r = BigUint::from_bytes_be(&x);
            // DER r has exactly32 bytes; s=1, and the committed flag is ALL.
            let mut bytes = vec![0x30, 0x25, 0x02, 0x20];
            bytes.extend(x);
            bytes.extend([0x02, 0x01, 0x01, 0x01]);
            assert_eq!(bytes.len(), 40);
            break (sk, point, r, bytes);
        };
        for repetitions in 1..=6 {
            if selected_repetitions.is_some_and(|d|d!=repetitions) { continue; }
            let code = script! {
                {tau.clone()} OP_OVER OP_CHECKSIGVERIFY
                for _ in 0..repetitions {
                    OP_SWAP OP_SIZE 60 OP_EQUALVERIFY OP_OVER
                    OP_CODESEPARATOR OP_CHECKSIGVERIFY
                }
                OP_DROP OP_TRUE
            }.compile_with_policy();
            let suffixes: Vec<_> = code.instruction_indices().filter_map(|item| match item.unwrap() {
                (offset, Instruction::Op(op)) if op == OP_CODESEPARATOR =>
                    Some(ScriptBuf::from_bytes(code.as_bytes()[offset+1..].to_vec())),
                _ => None,
            }).collect();
            assert_eq!(suffixes.len(), repetitions);
            let tx = Transaction { version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![input(funding_txid,0), input(funding_txid,1)],
                output: vec![TxOut { value: Amount::from_sat(190_000),
                    script_pubkey: script!{OP_1 {PublicKey::from_secret_key(&secp,&scalar(&BigUint::from(1u8)))
                        .x_only_public_key().0.serialize().to_vec()}}.compile_with_policy() }] };
            let z0 = BigUint::from_bytes_be(&digest(&tx, &code, EcdsaSighashType::All)) % &order;
            let t = BigUint::from_bytes_be(&target_secret.secret_bytes());
            let p = ((&t+&order-&z0) * r.modpow(&(&order-2u8), &order)) % &order;
            let p_secret = scalar(&p);
            let key = PublicKey::from_secret_key(&secp, &p_secret);
            secp.verify_ecdsa(&Message::from_digest(digest(&tx, &code, EcdsaSighashType::All)),
                &Signature::from_der(&tau[..tau.len()-1]).unwrap(), &key).unwrap();
            let mut signatures = vec![];
            let mut used_flags = vec![];
            for suffix in &suffixes {
                let (sigma, flag) = flags.iter().find_map(|&flag| {
                    sign_attempts += 1;
                    let sigma = pointlocks::sign_with_nonce(digest(&tx, suffix, flag),
                        p_secret, half_secret, flag).unwrap().to_vec();
                    (sigma.len()==60).then_some((sigma, flag))
                }).expect("deterministic fixture found no exact60 signature in six flags");
                let sig = Signature::from_der(&sigma[..sigma.len()-1]).unwrap();
                secp.verify_ecdsa(&Message::from_digest(digest(&tx, suffix, flag)), &sig, &key).unwrap();
                let s = BigUint::from_bytes_be(&sig.serialize_compact()[32..]);
                let z = BigUint::from_bytes_be(&digest(&tx, suffix, flag)) % &order;
                let mut recovered = false;
                for k in [&half, &(&order-&half)] {
                    let pp = ((&s*k+&order-&z)*&half_r_inverse) % &order;
                    let tt = (&r*pp+&z0) % &order;
                    if tt==t { recovered=true; }
                }
                assert!(recovered);
                signatures.push(sigma);
                used_flags.push(flag as u32);
            }
            let mut witness = signatures.iter().rev().cloned().collect::<Vec<_>>();
            witness.push(key.serialize().to_vec());
            let (success, peak) = execute(&tx, &code, witness.clone());
            let mut wrong_key = witness.clone();
            *wrong_key.last_mut().unwrap() = target.serialize().to_vec();
            let mut negative = vec![("wrong-recovered-key",wrong_key)];
            if repetitions>1 {
                let mut repeated = witness.clone();
                repeated[0] = repeated[1].clone();
                negative.push(("repeated-signature-across-contexts",repeated));
            }
            let mut wrong_length = witness.clone();
            wrong_length[0].push(0);
            negative.push(("wrong-signature-length",wrong_length));
            // The pinned local interpreter includes the executing separator in
            // SegWit-v0 scriptCode. Export a deliberately incorrect control for
            // a Core differential test; never use it as the native construction.
            let mut separator_including = vec![];
            for suffix in &suffixes {
                let mut bytes = vec![OP_CODESEPARATOR.to_u8()];
                bytes.extend(suffix.as_bytes());
                let incorrect_code = ScriptBuf::from_bytes(bytes);
                let sigma = flags.iter().find_map(|&flag| {
                    let sigma=pointlocks::sign_with_nonce(digest(&tx,&incorrect_code,flag),
                        p_secret,half_secret,flag).unwrap().to_vec();
                    (sigma.len()==60).then_some(sigma)
                }).unwrap();
                separator_including.push(sigma);
            }
            separator_including.reverse();
            separator_including.push(key.serialize().to_vec());
            let incorrect_local = execute(&tx,&code,separator_including.clone());
            let transaction = |data: &[Vec<u8>]| {
                let mut spending=tx.clone();
                spending.input[0].witness=Witness::from_slice(&[vec![0x51]]);
                spending.input[1].witness=Witness::from_slice(&data.iter().cloned()
                    .chain([code.to_bytes()]).collect::<Vec<_>>());
                json!({"hex":hex(&bitcoin::consensus::serialize(&spending)),
                    "txid":spending.compute_txid().to_string(),"wtxid":spending.compute_wtxid().to_string(),
                    "weight":spending.weight().to_wu(),"vbytes":spending.vsize()})
            };
            cases.push(json!({"seed":seed,"repetitions":repetitions,"script_bytes":code.len(),
                "tau_bytes":tau.len(),"target":hex(&target.serialize()),"script_hex":hex(code.as_bytes()),
                "target_scalar_fixture":hex(&target_secret.secret_bytes()),"anchor_digest":hex(&digest(&tx,&code,EcdsaSighashType::All)),
                "short_digests":suffixes.iter().zip(&used_flags).map(|(suffix,&flag)|hex(&digest(&tx,suffix,EcdsaSighashType::from_consensus(flag)))).collect::<Vec<_>>(),
                "witness_data":witness.iter().map(|v|hex(v)).collect::<Vec<_>>(),
                "correct_native_transaction":transaction(&witness),
                "negative_cases":negative.iter().map(|(name,data)|json!({"name":name,"transaction":transaction(data)})).collect::<Vec<_>>(),
                "incorrect_separator_including_transaction":transaction(&separator_including),
                "local_correct_native_accepted":success,"local_incorrect_separator_including_accepted":incorrect_local.0,
                "hint_items":0,"entry_items":witness.len(),"complete_witness_items":witness.len()+1,
                "serialized_witness_bytes":bitcoin::consensus::serialize(&Witness::from_slice(
                    &witness.iter().cloned().chain([code.to_bytes()]).collect::<Vec<_>>())).len(),
                "local_correct_native_stack_peak_before_failure":peak,
                "local_incorrect_separator_including_stack_peak":incorrect_local.1,"flags":used_flags}));
        }
    }
    println!("{}", serde_json::to_string_pretty(&json!({
        "scope":"Host-verified native SegWit-v0 signatures and extraction, plus a local interpreter CODESEPARATOR differential candidate. Funded only when invoked with an actual funding txid; Core validation is external. No general extraction soundness proof.",
        "evidence":"locally-reproduced","deployment":"unclassified",
        "host_positive_cases":cases.len(),
        "sign_attempts":sign_attempts,"cases":cases,
    })).unwrap());
}
