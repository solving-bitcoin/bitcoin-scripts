//! Offline regression of the complete, Core-mined bare publication artifacts.
use bitcoin::{
    consensus::deserialize,
    hashes::{hash160, sha256, Hash},
    script::Instruction,
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    sighash::SighashCache,
    Transaction,
};
use bitcoin_lab::signatures::pointlocks::sum_key;
use serde_json::Value;
use std::path::Path;

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn artifacts() -> (Value, Value) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("research/pointlocks-2026-09-17");
    let read = |name| serde_json::from_slice(&std::fs::read(root.join(name)).unwrap()).unwrap();
    (
        read("bare-publication-transactions.json"),
        read("bare-publication-core-check.json"),
    )
}

#[test]
fn bare_publication_artifact_sources_are_current() {
    let (_, report) = artifacts();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (path, hash) in report["source_sha256"].as_object().unwrap() {
        assert_eq!(
            sha256::Hash::hash(&std::fs::read(root.join(path)).unwrap()).to_string(),
            hash.as_str().unwrap(),
            "{path}"
        );
    }
    assert_eq!(report["summary"]["all_expectations_met"], true);
    assert_eq!(report["summary"]["positive_cases"], 11);
    assert_eq!(report["summary"]["negative_cases"], 15);
    assert_eq!(report["deployment"], "consensus-validated");
    assert_eq!(report["policy_accepted"], false);
}

#[test]
fn bare_publication_native_digests_and_scalars_replay() {
    let (built, report) = artifacts();
    let funding: Transaction =
        deserialize(&unhex(built["funding"]["hex"].as_str().unwrap())).unwrap();
    let secp = Secp256k1::new();
    let mut one = [0; 32];
    one[31] = 1;
    let g = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&one).unwrap());
    let mut total = 0;
    for (case, checked) in built["cases"]
        .as_array()
        .unwrap()
        .iter()
        .zip(report["cases"].as_array().unwrap())
        .take(3)
    {
        let tx: Transaction =
            deserialize(&unhex(case["transaction"]["hex"].as_str().unwrap())).unwrap();
        assert_eq!(
            tx.weight().to_wu(),
            case["transaction"]["weight"].as_u64().unwrap()
        );
        assert_eq!(
            tx.vsize() as u64,
            case["transaction"]["vbytes"].as_u64().unwrap()
        );
        assert_eq!(tx.input.len(), 80);
        assert_eq!(tx.output.len(), 1);
        assert!(checked["consensus"]["accepted"].as_bool().unwrap());
        let mut opened = 0;
        for (index, input) in tx.input.iter().enumerate().skip(1) {
            assert_eq!(input.previous_output.txid, funding.compute_txid());
            assert_eq!(input.previous_output.vout, index as u32);
            let script = &funding.output[index].script_pubkey;
            assert_eq!(script.len(), 1232);
            let table: Vec<_> = script
                .instructions()
                .filter_map(|i| match i.unwrap() {
                    Instruction::PushBytes(p) if p.len() == 20 => Some(p.as_bytes().to_vec()),
                    _ => None,
                })
                .collect();
            assert_eq!(table.len(), 48);
            let items: Vec<_> = input
                .script_sig
                .instructions()
                .map(|i| match i.unwrap() {
                    Instruction::PushBytes(p) => p.as_bytes().to_vec(),
                    Instruction::Op(op) if (0x51..=0x60).contains(&op.to_u8()) => {
                        vec![op.to_u8() - 0x50]
                    }
                    _ => panic!("noncanonical primary fixture"),
                })
                .collect();
            assert_eq!(items.len(), 21);
            let mut remaining: Vec<_> = (0..48).collect();
            for frame in items.chunks_exact(3) {
                assert_eq!(frame[0].len(), 71);
                assert_eq!(frame[2].len(), 1);
                let depth = frame[2][0] as usize;
                assert!((2..remaining.len() + 2).contains(&depth));
                let label = remaining.remove(remaining.len() + 1 - depth);
                assert_eq!(
                    hash160::Hash::hash(&frame[1]).as_byte_array(),
                    table[label].as_slice()
                );
                let p = PublicKey::from_slice(&frame[1]).unwrap();
                let digest = SighashCache::new(&tx)
                    .legacy_signature_hash(index, script, *frame[0].last().unwrap() as u32)
                    .unwrap()
                    .to_byte_array();
                let secret = sum_key::extract_from_digest(p, g, &frame[0], digest).unwrap();
                assert_eq!(
                    PublicKey::from_secret_key(&secp, &secret),
                    p.combine(&g).unwrap()
                );
                let expected = &checked["recovery"]["extractions"][opened];
                assert_eq!(expected["pool"], index - 1);
                assert_eq!(expected["label"], label);
                assert_eq!(
                    secret.secret_bytes().to_vec(),
                    unhex(expected["scalar"].as_str().unwrap())
                );
                opened += 1;
            }
        }
        assert_eq!(opened, 553);
        total += opened;
    }
    assert_eq!(total, 1659);
    assert_eq!(report["combined_vbytes"], 161382);
    assert_eq!(report["maximum_canonical_vbytes"], 161560);
}

#[test]
fn bare_publication_opt_in_policy_controls_are_current() {
    let (original, _) = artifacts();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |profile| -> Value {
        serde_json::from_slice(
            &std::fs::read(root.join(format!(
                "research/pointlocks-2026-09-17/bare-nonstandard-{profile}.json"
            )))
            .unwrap(),
        )
        .unwrap()
    };
    for profile in ["config-only", "patched", "patched-default"] {
        let report = read(profile);
        assert_eq!(report["transactions"], original);
        assert_eq!(report["summary"]["all_expectations_met"], true);
        assert_eq!(report["consensus_rules_relaxed"], false);
        assert_eq!(report["default_relay_accepted"], false);
        for (path, hash) in report["source_sha256"].as_object().unwrap() {
            assert_eq!(
                sha256::Hash::hash(&std::fs::read(root.join(path)).unwrap()).to_string(),
                hash.as_str().unwrap(),
                "{profile}: {path}"
            );
        }
        match profile {
            "config-only" => {
                assert_eq!(report["funding"]["policy"]["allowed"], true);
                assert!(report["cases"][0]["policy"]["reject-reason"]
                    .as_str()
                    .unwrap()
                    .contains("exactly one"));
            }
            "patched-default" => {
                assert_eq!(report["funding"]["policy"]["reject-reason"], "scriptpubkey");
                assert_eq!(
                    report["cases"][0]["policy"]["reject-reason"],
                    "bad-txns-nonstandard-inputs"
                );
            }
            "patched" => {
                assert_eq!(report["summary"]["mempool_accepted_variants"], 11);
                assert_eq!(
                    report["summary"]["invalid_mempool_and_consensus_rejections"],
                    15
                );
                assert_eq!(report["combined_vbytes"], 161382);
                assert_eq!(report["spending"]["policy"]["allowed"], true);
                assert_eq!(report["spending"]["consensus_accepted"], true);
                assert_eq!(report["recovery"]["extracted_scalars"], 553);
                for case in report["cases"].as_array().unwrap() {
                    assert_eq!(case["policy"]["allowed"], case["expected_consensus"]);
                    if case["expected_consensus"] == false {
                        assert_eq!(case["consensus"]["accepted"], false);
                    }
                }
            }
            _ => unreachable!(),
        }
    }
}
