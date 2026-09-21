//! Sum-key ECDSA point locks: deterministic algebra and strict legacy probes.
//! Public research inputs only. This is not a complete transaction/Core test.
use bitcoin::{
    absolute,
    hashes::Hash,
    secp256k1::{ecdsa, Message, PublicKey, Scalar, Secp256k1, SecretKey},
    sighash::SighashCache,
    transaction, Amount, EcdsaSighashType, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};
use bitcoin_lab::{
    signatures::pointlocks,
    support::{
        provenance,
        script::{script, ScriptCompilation},
    },
};
use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};
use num_bigint::BigUint;
use serde_json::json;

fn order() -> BigUint {
    BigUint::parse_bytes(
        b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .unwrap()
}
fn bytes(value: &BigUint) -> [u8; 32] {
    let v = value.to_bytes_be();
    let mut out = [0; 32];
    out[32 - v.len()..].copy_from_slice(&v);
    out
}
fn inv(value: &BigUint) -> BigUint {
    value.modpow(&(order() - BigUint::from(2u8)), &order())
}
fn point(value: &BigUint) -> PublicKey {
    PublicKey::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&bytes(value)).unwrap(),
    )
}
fn mul(p: PublicKey, value: &BigUint) -> PublicKey {
    p.mul_tweak(
        &Secp256k1::new(),
        &Scalar::from_be_bytes(bytes(value)).unwrap(),
    )
    .unwrap()
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}
fn redeem(p: PublicKey, q: PublicKey) -> ScriptBuf {
    assert_ne!(
        p, q,
        "equal verification keys do not enforce opposite nonces"
    );
    assert!(
        p.combine(&q).is_ok(),
        "the locked sum point must not be infinity"
    );
    script! {
        OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
        OP_DUP { p.serialize().to_vec() } OP_CHECKSIGVERIFY
        { q.serialize().to_vec() } OP_CHECKSIG
    }
    .compile_with_policy()
}
fn transaction() -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: (0..2)
            .map(|vout| TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::all_zeros(),
                    vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        }],
    }
}
fn execute(script: &ScriptBuf, signature: Vec<u8>) -> (bool, usize) {
    let mut exec = Exec::new(
        ExecCtx::Legacy,
        Options::default(),
        TxTemplate {
            tx: transaction(),
            prevouts: vec![],
            input_idx: 1,
            taproot_annex_scriptleaf: None,
        },
        script.clone(),
        vec![signature],
    )
    .unwrap();
    while exec.exec_next().is_ok() {}
    (
        exec.result().unwrap().success && exec.stack().len() == 1,
        exec.stats().max_nb_stack_items,
    )
}
fn verify_and_extract(
    p: PublicKey,
    q: PublicKey,
    digest: [u8; 32],
    sig: &bitcoin::ecdsa::Signature,
) -> BigUint {
    assert!(sig.to_vec().len() > 57);
    assert_ne!(p, q);
    let secp = Secp256k1::new();
    let message = Message::from_digest(digest);
    secp.verify_ecdsa(&message, &sig.signature, &p).unwrap();
    secp.verify_ecdsa(&message, &sig.signature, &q).unwrap();
    let n = order();
    let z = BigUint::from_bytes_be(&digest) % &n;
    let r = BigUint::from_bytes_be(&sig.signature.serialize_compact()[..32]);
    let secret = (&n - BigUint::from(2u8) * z * inv(&r) % &n) % &n;
    assert_eq!(point(&secret), p.combine(&q).unwrap());
    secret
}
fn general_known_target(
    digest: [u8; 32],
) -> (
    PublicKey,
    PublicKey,
    bitcoin::ecdsa::Signature,
    BigUint,
    u64,
) {
    let secp = Secp256k1::new();
    let n = order();
    let t = BigUint::from_bytes_be(&[7u8; 32]);
    let z = BigUint::from_bytes_be(&digest) % &n;
    let s = BigUint::from_bytes_be(&[11u8; 32]);
    for a in 1u64..100 {
        let target_secret = BigUint::from(a) * &t % &n;
        let r = (&n - BigUint::from(2u8) * &z * inv(&target_secret) % &n) % &n;
        let mut compressed = vec![2u8];
        compressed.extend_from_slice(&bytes(&r));
        let Ok(r_point) = PublicKey::from_slice(&compressed) else {
            continue;
        };
        // Construct verification keys with group operations; no log of R is used.
        let numerator = mul(r_point, &s).combine(&point(&z).negate(&secp)).unwrap();
        let p = mul(numerator, &inv(&r));
        let q = point(&target_secret).combine(&p.negate(&secp)).unwrap();
        let mut compact = [0u8; 64];
        compact[..32].copy_from_slice(&bytes(&r));
        compact[32..].copy_from_slice(&bytes(&s));
        let mut inner = ecdsa::Signature::from_compact(&compact).unwrap();
        inner.normalize_s();
        let sig = bitcoin::ecdsa::Signature {
            signature: inner,
            sighash_type: EcdsaSighashType::Single,
        };
        if sig.to_vec().len() <= 57 {
            continue;
        }
        assert_eq!(verify_and_extract(p, q, digest, &sig), target_secret);
        return (p, q, sig, t, a);
    }
    panic!("deterministic lift retry bound exceeded")
}
fn main() {
    let secp = Secp256k1::new();
    let n = order();
    let c_bytes = pointlocks::sighash_single_bug_message();
    let c = BigUint::from_bytes_be(&c_bytes);
    let g_secret = SecretKey::from_slice(&bytes(&BigUint::from(1u8))).unwrap();
    let g = PublicKey::from_secret_key(&secp, &g_secret);
    let mut rows = vec![];
    let mut cases = vec![];
    for seed in 7u8..19 {
        let nonce = SecretKey::from_slice(&[seed; 32]).unwrap();
        let sig = pointlocks::sign_with_nonce(c_bytes, g_secret, nonce, EcdsaSighashType::Single)
            .unwrap();
        let r = BigUint::from_bytes_be(&sig.signature.serialize_compact()[..32]);
        let target_secret = (&n - BigUint::from(2u8) * &c * inv(&r) % &n) % &n;
        let target = point(&target_secret);
        let p = target.combine(&g.negate(&secp)).unwrap();
        assert_ne!(p, g);
        assert_eq!(verify_and_extract(p, g, c_bytes, &sig), target_secret);
        let script = redeem(p, g);
        let digest = SighashCache::new(transaction())
            .legacy_signature_hash(1, &script, 3)
            .unwrap()
            .to_byte_array();
        assert_eq!(digest, c_bytes);
        let (success, peak) = execute(&script, sig.to_vec());
        assert!(success);
        cases.push(json!({"name":format!("common-g-{seed}-valid"),"variant":"sum-common-g","n":1,"t":1,"script_hex":hex(script.as_bytes()),"items_hex":[hex(&sig.to_vec())],"expected":true,"expected_policy":true,"hint_items":0}));
        let mut wrong_flag = sig.to_vec();
        *wrong_flag.last_mut().unwrap() = 1;
        assert!(!execute(&script, wrong_flag.clone()).0);
        cases.push(json!({"name":format!("common-g-{seed}-wrong-flag"),"variant":"sum-common-g","n":1,"t":1,"script_hex":hex(script.as_bytes()),"items_hex":[hex(&wrong_flag)],"expected":false,"expected_policy":false,"hint_items":0}));
        assert!(!execute(&script, vec![1u8; 57]).0);
        cases.push(json!({"name":format!("common-g-{seed}-57-byte-item"),"variant":"sum-common-g","n":1,"t":1,"script_hex":hex(script.as_bytes()),"items_hex":[hex(&[1u8;57])],"expected":false,"expected_policy":false,"hint_items":0}));
        let other_p = point(&BigUint::from(99u8));
        let wrong_script = redeem(other_p, g);
        assert!(!execute(&wrong_script, sig.to_vec()).0);
        cases.push(json!({"name":format!("common-g-{seed}-wrong-key"),"variant":"sum-common-g","n":1,"t":1,"script_hex":hex(wrong_script.as_bytes()),"items_hex":[hex(&sig.to_vec())],"expected":false,"expected_policy":false,"hint_items":0}));
        rows.push(json!({
            "nonce_seed":seed,"target":hex(&target.serialize()),"public_test_scalar":hex(&bytes(&target_secret)),
            "verification_key":hex(&p.serialize()),"common_key":hex(&g.serialize()),
            "signature":hex(&sig.to_vec()),"script":hex(script.as_bytes()),"script_bytes":script.len(),
            "signature_bytes":sig.to_vec().len(),"combined_stack_peak":peak,
        }));
    }
    let (p, q, sig, t, a) = general_known_target(c_bytes);
    assert!(execute(&redeem(p, q), sig.to_vec()).0);
    cases.push(json!({"name":"given-target-valid","variant":"sum-given-target","n":1,"t":1,"script_hex":hex(redeem(p,q).as_bytes()),"items_hex":[hex(&sig.to_vec())],"expected":true,"expected_policy":true,"hint_items":0}));
    assert_eq!(
        verify_and_extract(p, q, c_bytes, &sig) * inv(&BigUint::from(a)) % &n,
        t
    );
    let general = json!({"a":a,"target":hex(&point(&t).serialize()),"p":hex(&p.serialize()),"q":hex(&q.serialize()),"signature":hex(&sig.to_vec())});
    // Arbitrary nonconstant digest: algebra/libsecp verification, not a native
    // transaction preimage or an ordinary-spend feasibility claim.
    let z = [0x23u8; 32];
    let (p, q, sig, t, a) = general_known_target(z);
    assert_eq!(
        verify_and_extract(p, q, z, &sig) * inv(&BigUint::from(a)) % &n,
        t
    );
    let ordinary = json!({"digest":hex(&z),"a":a,"target":hex(&point(&t).serialize()),"p":hex(&p.serialize()),"q":hex(&q.serialize()),"signature":hex(&sig.to_vec()),"boundary":"synthetic-digest algebra, not native ordinary transaction"});
    println!("{}",serde_json::to_string_pretty(&json!({
        "generator":"cargo run --locked --example pointlock_sum_probe",
        "compiler_commit":provenance::compiler().unwrap().commit,
        "interpreter_commit":provenance::interpreter().unwrap().commit,
        "local_context":"Legacy, Options::default(), stack limits enabled",
        "evidence":"locally-reproduced","deployment":"unclassified",
        "common_g_candidates":rows,"arbitrary_given_target":general,"synthetic_ordinary_digest":ordinary,
        "cases":cases,
        "passing_native_constant_cases":13,"rejected_mutations":36,
    })).unwrap());
}
