//! Policy-compiled public research vectors for the independent Core harness.
use bitcoin::{
    hashes::hex::DisplayHex,
    secp256k1::{PublicKey, Secp256k1, SecretKey},
};
use bitcoin_lab::{
    signatures::pointlocks::{self, three_check, two_check},
    support::script::ScriptCompilation,
};
use num_bigint::BigUint;
use serde_json::json;

fn main() {
    let n = BigUint::parse_bytes(
        b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .unwrap();
    let c = BigUint::from_bytes_be(&pointlocks::sighash_single_bug_message());
    let r0 = BigUint::from_bytes_be(&pointlocks::G_HALF_R);
    let k0 = (&n + BigUint::from(1u8)) >> 1usize;
    let fallback = (&n + k0 - c) * r0.modpow(&(&n - BigUint::from(2u8)), &n) % &n;
    let mut fallback_bytes = [0u8; 32];
    let bytes = fallback.to_bytes_be();
    fallback_bytes[32 - bytes.len()..].copy_from_slice(&bytes);
    let cases: Vec<_> = [
        ("representative", [7u8; 32]),
        ("high_s_fallback", fallback_bytes),
    ].into_iter().map(|(name, bytes)| {
        let secret = SecretKey::from_slice(&bytes).unwrap();
        let target = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        let signature = two_check::sign(secret).unwrap();
        assert_eq!(signature, three_check::sign(secret).unwrap());
        json!({
            "name": name,
            "public_test_scalar": bytes.to_lower_hex_string(),
            "target": target.serialize().to_lower_hex_string(),
            "signature": signature.to_vec().to_lower_hex_string(),
            "two_check_script": two_check::point_lock(target).unwrap().compile_with_policy().as_bytes().to_lower_hex_string(),
            "three_check_script": three_check::point_lock(target).unwrap().compile_with_policy().as_bytes().to_lower_hex_string(),
        })
    }).collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "generator": "cargo run --locked --example pointlock_vectors",
            "compilation": "support::script::ScriptCompilation::compile_with_policy()",
            "cases": cases,
        }))
        .unwrap()
    );
}
