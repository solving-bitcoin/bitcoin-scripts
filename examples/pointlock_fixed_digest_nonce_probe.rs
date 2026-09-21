//! Research fixture: three known-key contexts pin the legacy constant digest;
//! a fourth ECDSA check locks the nonce scalar of an arbitrary input point.
use bitcoin::secp256k1::{ecdsa, PublicKey, Secp256k1, SecretKey};
use bitcoin_lab::support::{
    provenance,
    script::{script, ScriptCompilation},
};
use num_bigint::BigUint;
use serde_json::json;

fn n() -> BigUint {
    BigUint::parse_bytes(
        b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .unwrap()
}
fn bytes(x: &BigUint) -> [u8; 32] {
    let v = x.to_bytes_be();
    let mut out = [0; 32];
    out[32 - v.len()..].copy_from_slice(&v);
    out
}
fn point(x: &BigUint) -> PublicKey {
    PublicKey::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&bytes(x)).unwrap(),
    )
}
fn hex(x: &[u8]) -> String {
    x.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let order = n();
    let c = BigUint::from(1u8) << 248usize;
    let a = BigUint::from_bytes_be(&[7; 32]);
    let b = BigUint::from_bytes_be(&[11; 32]);
    let secrets = [
        a.clone(),
        b.clone(),
        (&a + &b) % &order,
        (&order + &a - &b) % &order,
    ];
    let g = point(&BigUint::from(1u8));
    let mut cases = Vec::new();
    let mut keys = Vec::new();
    for (index, k) in secrets.iter().enumerate() {
        let target = point(k);
        let r = BigUint::from_bytes_be(&target.serialize()[1..]);
        assert!(r.bits() >= 144 && r < order);
        let p = (&order
            - BigUint::from(2u8) * &c * r.modpow(&(&order - BigUint::from(2u8)), &order) % &order
            + &order
            - BigUint::from(1u8))
            % &order;
        assert!(p > BigUint::from(1u8));
        let key = point(&p);
        keys.push(key);
        let s = (&c + &r) * k.modpow(&(&order - BigUint::from(2u8)), &order) % &order;
        let low = std::cmp::min(s.clone(), &order - &s);
        let mut signatures = Vec::new();
        for response in [low.clone(), &order - &low] {
            let mut compact = [0; 64];
            compact[..32].copy_from_slice(&bytes(&r));
            compact[32..].copy_from_slice(&bytes(&response));
            let mut sig = ecdsa::Signature::from_compact(&compact)
                .unwrap()
                .serialize_der()
                .to_vec();
            sig.push(3);
            assert!(sig.len() > 57);
            signatures.push(hex(&sig));
        }
        let code = script! {
            OP_DEPTH OP_1 OP_EQUALVERIFY
            OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
            {g.serialize().to_vec()}
            OP_2DUP OP_CHECKSIGVERIFY OP_CODESEPARATOR
            OP_2DUP OP_CHECKSIGVERIFY OP_CODESEPARATOR
            OP_2DUP OP_CHECKSIGVERIFY OP_DROP
            {key.serialize().to_vec()} OP_CHECKSIG
        }
        .compile_with_policy();
        cases.push(json!({"index":index,"target_hex":hex(&target.serialize()),
            "scalar_hex":hex(&bytes(k)),"derived_key_hex":hex(&key.serialize()),
            "derived_key_scalar_hex":hex(&bytes(&p)),"signatures":signatures,
            "script_hex":hex(code.as_bytes()),"script_bytes":code.len()}));
    }
    // Entry: sigma, low bit, high bit. The selected key is kept on altstack.
    let selected = script! {
        OP_DEPTH OP_3 OP_EQUALVERIFY
        OP_IF
            OP_IF {keys[3].serialize().to_vec()} OP_ELSE {keys[2].serialize().to_vec()} OP_ENDIF
        OP_ELSE
            OP_IF {keys[1].serialize().to_vec()} OP_ELSE {keys[0].serialize().to_vec()} OP_ENDIF
        OP_ENDIF
        OP_TOALTSTACK
        OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
        {g.serialize().to_vec()}
        OP_2DUP OP_CHECKSIGVERIFY OP_CODESEPARATOR
        OP_2DUP OP_CHECKSIGVERIFY OP_CODESEPARATOR
        OP_2DUP OP_CHECKSIGVERIFY OP_DROP
        OP_FROMALTSTACK OP_CHECKSIG
    }
    .compile_with_policy();
    println!("{}",serde_json::to_string_pretty(&json!({
        "scope":"Policy-compiled legacy nonce-point lock and correlated quartet; research fixture without independent payment authorization.",
        "cases":cases,"quartet_script_hex":hex(selected.as_bytes()),
        "quartet_script_bytes":selected.len(),"generator_hex":hex(&g.serialize()),
        "compiler_commit":provenance::compiler().unwrap().commit,
        "interpreter_commit":provenance::interpreter().unwrap().commit,
        "script_compilation":"compile_with_policy; unoptimized sizes below 32 KiB"
    })).unwrap());
}
