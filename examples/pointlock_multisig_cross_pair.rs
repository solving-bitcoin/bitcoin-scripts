//! Regression: two full-pool t-of-n CHECKMULTISIGs lose point-lock pairing.
//! Deterministic public scalars; emits a vector for multisig_core_check.py.
//! ECDSA equation/extraction assertions run here; Core checks the full spend.
use bitcoin::{
    hashes::{hash160, Hash},
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    EcdsaSighashType,
};
use bitcoin_lab::{
    signatures::pointlocks::{self, committed_two_check as lock},
    support::{
        provenance,
        script::{script, ScriptCompilation},
    },
};
use num_bigint::BigUint;

fn scalar(value: &BigUint) -> SecretKey {
    let bytes = value.to_bytes_be();
    let mut fixed = [0; 32];
    fixed[32 - bytes.len()..].copy_from_slice(&bytes);
    SecretKey::from_slice(&fixed).unwrap()
}
fn main() {
    let n = BigUint::parse_bytes(
        b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .unwrap();
    let inv = |v: &BigUint| v.modpow(&(&n - BigUint::from(2u8)), &n);
    let c = BigUint::from_bytes_be(&pointlocks::sighash_single_bug_message());
    let r0 = BigUint::from_bytes_be(&pointlocks::G_HALF_R);
    let secret0 = SecretKey::from_slice(&[7; 32]).unwrap();
    let nonce = SecretKey::from_slice(&[17; 32]).unwrap();
    let sigma = pointlocks::sign_with_nonce(
        pointlocks::sighash_single_bug_message(),
        secret0,
        nonce,
        EcdsaSighashType::Single,
    )
    .unwrap();
    let r = BigUint::from_bytes_be(&sigma.signature.serialize_compact()[..32]);
    assert_ne!(r, r0);
    assert!(sigma.to_vec().len() > 57);
    let a = BigUint::from_bytes_be(&secret0.secret_bytes());
    let offset = (&n - (BigUint::from(2u8) * &c * inv(&r0) % &n)) % &n;
    let secret1 = scalar(&((offset + a + BigUint::from(2u8) * c * inv(&r)) % &n));
    let secp = Secp256k1::new();
    let t0 = PublicKey::from_secret_key(&secp, &secret0);
    let t1 = PublicKey::from_secret_key(&secp, &secret1);
    let q0 = lock::companion_key(t0).unwrap();
    let q1 = lock::companion_key(t1).unwrap();
    let message =
        bitcoin::secp256k1::Message::from_digest(pointlocks::sighash_single_bug_message());
    assert!(secp.verify_ecdsa(&message, &sigma.signature, &t0).is_ok());
    assert!(secp.verify_ecdsa(&message, &sigma.signature, &q1).is_ok());
    assert!(secp.verify_ecdsa(&message, &sigma.signature, &q0).is_err());
    assert!(secp.verify_ecdsa(&message, &sigma.signature, &t1).is_err());
    assert!(
        pointlocks::extract_from_g_half(pointlocks::sighash_single_bug_message(), &sigma, t0)
            .is_err()
    );
    let h = hash160::Hash::hash(&sigma.to_vec())
        .to_byte_array()
        .to_vec();
    let redeem=script! {
        OP_DUP OP_HASH160 { h } OP_EQUALVERIFY
        OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
        OP_DUP OP_TOALTSTACK
        OP_0 OP_SWAP 1 { t0.serialize().to_vec() } { t1.serialize().to_vec() } 2 OP_CHECKMULTISIGVERIFY
        OP_0 OP_FROMALTSTACK 1 { q0.serialize().to_vec() } { q1.serialize().to_vec() } 2 OP_CHECKMULTISIG
    }.compile_with_policy();
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let script_sig = bitcoin::script::Builder::new()
        .push_slice(bitcoin::script::PushBytesBuf::try_from(sigma.to_vec()).unwrap())
        .push_slice(bitcoin::script::PushBytesBuf::try_from(redeem.to_bytes()).unwrap())
        .into_script();
    println!(
        "{}",
        serde_json::json!({
            "name": "cross-pair-full-pool-shortcut",
            "compiler_commit": provenance::compiler().unwrap().commit,
            "interpreter_commit": provenance::interpreter().unwrap().commit,
            "script": hex(redeem.as_bytes()),
            "script_sig": hex(script_sig.as_bytes()),
            "items": [hex(&sigma.to_vec())],
            "target0": hex(&t0.serialize()), "target1": hex(&t1.serialize()),
            "companion0": hex(&q0.serialize()), "companion1": hex(&q1.serialize()),
            "expected": true,
            "intended_pair_rejected": true,
            "g_half_extraction_failed": true,
            "redeem_bytes": redeem.len(), "signature_bytes": sigma.to_vec().len()
        })
    );
}
