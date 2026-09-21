//! Recheck the exact transactions accepted/rejected by isolated Bitcoin Core.
//! Core execution is recorded in the JSON; this test independently recomputes
//! native digests, byte/weight accounting, and public extraction in Rust.
use bitcoin::{
    consensus::encode::{deserialize, serialize},
    hashes::{hex::FromHex, Hash},
    secp256k1::{PublicKey, SecretKey},
    sighash::SighashCache,
    ScriptBuf, Transaction,
};
use bitcoin_lab::{
    signatures::pointlocks::{three_check, two_check},
    support::script::ScriptCompilation,
};
use serde_json::Value;
use std::str::FromStr;

fn bytes(value: &Value) -> Vec<u8> {
    Vec::from_hex(value.as_str().unwrap()).unwrap()
}

#[test]
fn core_transactions_match_rust_digests_and_extractors() {
    let report: Value = serde_json::from_str(include_str!(
        "../research/pointlocks-2026-09-17/core_check.json"
    ))
    .unwrap();
    let vectors: Value = serde_json::from_str(include_str!(
        "../research/pointlocks-2026-09-17/vectors.json"
    ))
    .unwrap();
    assert_eq!(report["all_expectations_met"], true);
    let rows = report["results"].as_array().unwrap();
    assert_eq!(rows.len(), 18);
    let mut extracted = 0;
    let mut rejected = 0;
    let funding: Transaction = deserialize(&bytes(&report["funding"]["hex"])).unwrap();
    for row in rows {
        let name = row["name"].as_str().unwrap();
        let target = PublicKey::from_str(row["target"].as_str().unwrap()).unwrap();
        let signature = bytes(&row["signature"]);
        let tx_bytes = bytes(&row["transaction"]["hex"]);
        let tx: Transaction = deserialize(&tx_bytes).unwrap();
        assert_eq!(serialize(&tx), tx_bytes, "{name}");
        assert_eq!(
            tx.weight().to_wu(),
            row["transaction"]["weight"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            tx.compute_txid().to_string(),
            row["transaction"]["txid"].as_str().unwrap(),
            "{name}"
        );
        let index = row["locked_input_index"].as_u64().unwrap() as usize;
        let expected_script = if row["variant"] == "two_check" {
            two_check::point_lock(target).unwrap().compile_with_policy()
        } else {
            three_check::point_lock(target)
                .unwrap()
                .compile_with_policy()
        };
        assert_eq!(expected_script.as_bytes(), bytes(&row["script"]), "{name}");
        assert_eq!(
            tx.input[index].script_sig.len(),
            row["script_sig_bytes"].as_u64().unwrap() as usize,
            "{name}"
        );
        assert!(tx.input[index].witness.is_empty());
        let pushes: Vec<_> = tx.input[index]
            .script_sig
            .instructions_minimal()
            .map(|entry| match entry.unwrap() {
                bitcoin::script::Instruction::PushBytes(data) => data.as_bytes(),
                _ => panic!("{name}: unexpected non-push scriptSig instruction"),
            })
            .collect();
        assert_eq!(pushes[0], signature, "{name}");
        let p2sh = row["wrapper"] == "p2sh";
        assert_eq!(pushes.len(), if p2sh { 2 } else { 1 }, "{name}");
        if p2sh {
            assert_eq!(pushes[1], expected_script.as_bytes(), "{name}");
        }
        let prevout = tx.input[index].previous_output;
        assert_eq!(prevout.txid, funding.compute_txid(), "{name}");
        assert_eq!(
            funding.output[prevout.vout as usize].script_pubkey,
            if p2sh {
                expected_script.to_p2sh()
            } else {
                expected_script.clone()
            },
            "{name}"
        );

        // Compare every reached CHECKSIG digest with the independent Python
        // serializer whose equation results were compared to Core execution.
        let checks = row["host_trace"]["checks"].as_array().unwrap();
        for (position, check) in checks.iter().enumerate() {
            let script_code = ScriptBuf::from_bytes(bytes(&check["script_code"]));
            let native = SighashCache::new(&tx)
                .legacy_signature_hash(index, &script_code, u32::from(*signature.last().unwrap()))
                .unwrap()
                .to_byte_array();
            assert_eq!(
                native.as_slice(),
                bytes(&check["digest"]),
                "{name}/{position}"
            );
            if row["variant"] == "two_check" {
                assert_eq!(
                    two_check::legacy_digest(&tx, index, target, *signature.last().unwrap())
                        .unwrap(),
                    native
                );
                assert_eq!(script_code, expected_script);
            } else {
                let views = three_check::script_code_views(target).unwrap();
                let pair =
                    three_check::legacy_digest_pair(&tx, index, target, *signature.last().unwrap())
                        .unwrap();
                assert_eq!(
                    script_code,
                    if position == 0 {
                        views.full
                    } else {
                        views.suffix
                    }
                );
                assert_eq!(
                    native,
                    if position == 0 {
                        pair.full
                    } else {
                        pair.suffix
                    }
                );
            }
        }
        let result = if row["variant"] == "two_check" {
            two_check::extract_from_transaction(target, &signature, &tx, index)
                .map_err(|err| format!("{err:?}"))
        } else {
            three_check::extract_from_transaction(target, &signature, &tx, index)
                .map_err(|err| format!("{err:?}"))
        };
        if row["consensus"]["accepted"] == true {
            let source = vectors["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|case| case["name"] == row["case_name"])
                .unwrap();
            let expected = SecretKey::from_slice(&bytes(&source["public_test_scalar"])).unwrap();
            assert_eq!(result, Ok(expected), "{name}");
            extracted += 1;
        } else {
            assert!(result.is_err(), "{name}: invalid spend must not extract");
            rejected += 1;
        }
    }
    assert_eq!((extracted, rejected), (10, 8));
}
