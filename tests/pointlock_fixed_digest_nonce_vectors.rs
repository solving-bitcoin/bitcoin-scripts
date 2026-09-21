//! Independent rust-bitcoin sighashes for the small Core nonce-lock fixtures.
use bitcoin::{
    consensus,
    secp256k1::{ecdsa, Message, PublicKey, Secp256k1, SecretKey},
    sighash::SighashCache,
    ScriptBuf, Transaction,
};
use serde_json::Value;

fn bytes(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn fixed_digest_nonce_core_vectors_match_native_hashes_and_extraction() {
    let report: Value = serde_json::from_str(include_str!(
        "../research/pointlocks-2026-09-17/fixed-digest-nonce-core.json"
    ))
    .unwrap();
    assert_eq!(report["positive_cases"], 23);
    assert_eq!(report["negative_cases"], 8);
    let secp = Secp256k1::new();
    let mut equations = 0;
    let mut extracted = 0;
    for row in report["results"].as_array().unwrap() {
        let raw = bytes(row["transaction"]["hex"].as_str().unwrap());
        let tx: Transaction = consensus::deserialize(&raw).unwrap();
        assert_eq!(consensus::serialize(&tx), raw);
        assert_eq!(tx.compute_txid().to_string(), row["transaction"]["txid"]);
        assert_eq!(
            tx.weight().to_wu(),
            row["transaction"]["weight"].as_u64().unwrap()
        );
        let index = tx
            .input
            .iter()
            .position(|i| !i.script_sig.is_empty())
            .unwrap();
        let sig = bytes(row["entry_hex"][0].as_str().unwrap());
        for check in row["host_trace"]["checks"].as_array().unwrap() {
            let script = ScriptBuf::from_bytes(bytes(check["script_code"].as_str().unwrap()));
            let hash = SighashCache::new(&tx)
                .legacy_signature_hash(index, &script, u32::from(*sig.last().unwrap()))
                .unwrap();
            let expected = bytes(check["digest"].as_str().unwrap());
            let actual: &[u8] = hash.as_ref();
            assert_eq!(actual, expected.as_slice());
            let mut signature = ecdsa::Signature::from_der(&sig[..sig.len() - 1]).unwrap();
            // Core consensus accepts high-S; normalize for libsecp verification.
            signature.normalize_s();
            let key = PublicKey::from_slice(&bytes(check["key"].as_str().unwrap())).unwrap();
            let digest: [u8; 32] = expected.try_into().unwrap();
            let valid = secp
                .verify_ecdsa(&Message::from_digest(digest), &signature, &key)
                .is_ok();
            assert_eq!(valid, check["accepted"].as_bool().unwrap());
            equations += 1;
        }
        if !row["extraction"].is_null() {
            let secret =
                SecretKey::from_slice(&bytes(row["extraction"]["scalar_hex"].as_str().unwrap()))
                    .unwrap();
            let target =
                PublicKey::from_slice(&bytes(row["extraction"]["target_hex"].as_str().unwrap()))
                    .unwrap();
            assert_eq!(PublicKey::from_secret_key(&secp, &secret), target);
            extracted += 1;
        }
        assert_eq!(row["consensus"]["accepted"], row["expected_consensus"]);
    }
    assert_eq!(extracted, 23);
    assert!(equations >= 100);
}
