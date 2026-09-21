//! Full-width honest composition experiment; no new native transaction claim.
#![allow(dead_code)]
use super::{choose, decoder, inv, parallel, rank, unhex, Label, Pool, N, POOLS, T};
use bitcoin::hashes::{sha256, Hash};
use decoder::mixed_radix;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use serde_json::{json, Value};
use std::time::Instant;

const WIDTH: usize = 2048;
const RADIX: usize = 3_162_510;
const DIGIT_BITS: usize = 22;
const TAG: usize = 1_000_000;
const PRIVATE_FIXTURE_SEED: [u8; 32] = [63; 32];

fn milliseconds(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn digits(mut value: BigUint) -> Vec<usize> {
    let out = (0..POOLS)
        .map(|_| {
            let digit = (&value % RADIX).to_usize().unwrap();
            value /= RADIX;
            digit
        })
        .collect();
    assert_eq!(value, BigUint::from(0u8));
    out
}

fn selected_rank_labels(
    pairs: &[[Label; 2]],
    digits: &[usize],
    invalid_flag: Option<usize>,
) -> Vec<Label> {
    assert_eq!(digits.len(), POOLS);
    let mut selected = Vec::with_capacity(pairs.len());
    for (i, &digit) in digits.iter().enumerate() {
        for bit in 0..DIGIT_BITS {
            selected.push(pairs[i * (DIGIT_BITS + 1) + bit][digit >> bit & 1]);
        }
        selected
            .push(pairs[i * (DIGIT_BITS + 1) + DIGIT_BITS][usize::from(invalid_flag != Some(i))]);
    }
    selected
}

fn rank_labels_from_native(
    pools: &[Pool],
    tables: &[Vec<Label>],
    decoders: &[decoder::Decoder],
    inverses: &[Label],
    report: &Value,
) -> Vec<Label> {
    let records = report["recovery"]["extractions"].as_array().unwrap();
    assert_eq!(records.len(), POOLS * T);
    let mut selected_outputs = vec![];
    for i in 0..POOLS {
        let mut rows: Vec<_> = records
            .iter()
            .filter(|r| r["pool"].as_u64() == Some(i as u64))
            .collect();
        rows.sort_by_key(|r| r["label"].as_u64().unwrap());
        assert_eq!(rows.len(), T);
        let selection = std::array::from_fn(|k| rows[k]["label"].as_u64().unwrap() as usize);
        let secrets = std::array::from_fn(|k| {
            unhex(rows[k]["scalar"].as_str().unwrap())
                .try_into()
                .unwrap()
        });
        for k in 0..T {
            assert_eq!(
                pools[i].points[selection[k]].to_vec(),
                unhex(rows[k]["target"].as_str().unwrap())
            );
        }
        // The existing PublicView validates the scalars and opens actual retained
        // ciphertexts. Only its one-label-per-wire result enters evaluation.
        let labels = pools[i]
            .open(selection, &secrets, &tables[i], inverses)
            .unwrap();
        let outputs = decoders[i].evaluate(&labels).unwrap();
        assert_eq!(
            decoders[i].decode_outputs(&outputs),
            Some((rank(selection), true))
        );
        selected_outputs.extend(outputs);
    }
    selected_outputs
}

fn check_complete_codewords(gc: &decoder::Decoder, pairs: &[[Label; 2]]) -> Value {
    let modulus = BigUint::from(1u8) << WIDTH;
    let capacity = BigUint::from(RADIX).pow(POOLS as u32);
    assert!(capacity > &modulus + 1u8);
    let cases = [
        ("zero", BigUint::from(0u8)),
        ("one", BigUint::from(1u8)),
        ("maximum-message", &modulus - 1u8),
        ("first-unused-codeword", modulus.clone()),
        ("second-unused-codeword", &modulus + 1u8),
        ("maximum-codeword", &capacity - 1u8),
    ];
    let mut rows = vec![];
    let mut alias_labels = std::collections::BTreeMap::new();
    for (name, value) in cases {
        let selected = selected_rank_labels(pairs, &digits(value.clone()), None);
        let outputs = gc.evaluate(&selected).unwrap();
        let (decoded, valid) = mixed_radix::decode_bytes(gc, &outputs, WIDTH).unwrap();
        assert!(valid);
        assert_eq!(decoded.len(), 256);
        assert_eq!(BigUint::from_bytes_be(&decoded), &value % &modulus);
        if let Some(previous) = alias_labels.insert(decoded.clone(), outputs) {
            assert_eq!(previous, gc.evaluate(&selected).unwrap());
        }
        rows.push(json!({"name":name,"valid":valid,"output_hex":hex(&decoded),
            "codeword_at_or_above_2_2048":value>=modulus}));
    }
    let mut bad_digit = vec![0; POOLS];
    bad_digit[37] = RADIX;
    let input = selected_rank_labels(pairs, &bad_digit, None);
    assert!(
        !mixed_radix::decode_bytes(gc, &gc.evaluate(&input).unwrap(), WIDTH)
            .unwrap()
            .1
    );
    let input = selected_rank_labels(pairs, &vec![0; POOLS], Some(53));
    assert!(
        !mixed_radix::decode_bytes(gc, &gc.evaluate(&input).unwrap(), WIDTH)
            .unwrap()
            .1
    );
    let mut corrupt = selected_rank_labels(pairs, &vec![0; POOLS], None);
    corrupt[0] ^= 1;
    assert!(mixed_radix::decode_bytes(gc, &gc.evaluate(&corrupt).unwrap(), WIDTH).is_none());
    json!({"cases":rows,"malformed_rank_rejected":true,"false_pool_validity_rejected":true,
        "corrupted_input_label_rejected":true,"equal_message_aliases_have_identical_output_labels":true,
        "scope":"Garbler-held label pairs supply these boundary vectors; no additional native spends are claimed."})
}

pub(crate) fn run() {
    let args: Vec<_> = std::env::args().collect();
    let arg = |name: &str, default: usize| {
        args.iter()
            .position(|v| v == name)
            .map_or(default, |i| args[i + 1].parse().unwrap())
    };
    let workers = arg("--workers", 1).clamp(1, POOLS);
    let samples = arg("--samples", 1).max(1);
    let native_path = args
        .iter()
        .position(|v| v == "--native-recovery")
        .map(|i| args[i + 1].clone())
        .expect("--native-recovery must name the cached round-major Core report");
    let native_bytes = std::fs::read(&native_path).unwrap();
    let native: Value = serde_json::from_slice(&native_bytes).unwrap();
    assert!(native["all_expectations_met"].as_bool().unwrap());
    let native_hash = sha256::Hash::hash(&native_bytes).to_string();
    let manifest_path = args
        .iter()
        .position(|v| v == "--native-manifest")
        .map(|i| args[i + 1].clone())
        .expect("--native-manifest is required");
    let manifest_bytes = std::fs::read(&manifest_path).unwrap();
    let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
    let manifest_hash = sha256::Hash::hash(&manifest_bytes).to_string();
    assert_eq!(
        manifest_hash,
        native["transactions_sha256"].as_str().unwrap()
    );
    assert_eq!(manifest["pool_count"], POOLS);

    let radices = vec![RADIX; POOLS];
    assert_eq!(choose(N, T), RADIX);
    let mut measurements = vec![];
    let mut boundary = Value::Null;
    let mut native_result = Value::Null;
    for sample in 0..samples {
        let start = Instant::now();
        let inverses: Vec<_> = (0..64).map(|x| if x == 0 { 0 } else { inv(x) }).collect();
        let pools = parallel(POOLS, workers, |i| {
            let pool = Pool::new(i, N);
            for j in 0..N {
                assert_eq!(
                    pool.points[j].to_vec(),
                    unhex(manifest["pools"][i]["targets"][j].as_str().unwrap())
                );
            }
            pool
        });
        let tables = parallel(POOLS, workers, |i| pools[i].generate());
        let rank_gcs = parallel(POOLS, workers, |i| {
            decoder::build(i, &pools[i].labels, T, pools[i].private_garbling_seed)
        });
        // Both output labels are available only to the garbler. This one
        // evaluation per rank decoder, and its allocations, are timed setup.
        let pair_groups = parallel(POOLS, workers, |i| {
            mixed_radix::private_output_pairs(&rank_gcs[i], &pools[i].labels)
        });
        let pairs: Vec<_> = pair_groups.into_iter().flatten().collect();
        assert_eq!(pairs.len(), POOLS * (DIGIT_BITS + 1));
        let translation_and_rank_generation_ms = milliseconds(start);
        let start = Instant::now();
        let gc = mixed_radix::build(TAG, &pairs, &radices, WIDTH, PRIVATE_FIXTURE_SEED);
        let mixed_radix_generation_ms = milliseconds(start);
        let start = Instant::now();
        let audited = parallel(POOLS, workers, |i| {
            pools[i].check_opened(&tables[i])
                && rank_gcs[i].same_tables(&decoder::build(
                    i,
                    &pools[i].labels,
                    T,
                    pools[i].private_garbling_seed,
                ))
        });
        assert!(audited.into_iter().all(|v| v));
        let translation_and_rank_opened_audit_ms = milliseconds(start);
        let start = Instant::now();
        assert!(gc.same_tables(&mixed_radix::build(
            TAG,
            &pairs,
            &radices,
            WIDTH,
            PRIVATE_FIXTURE_SEED
        )));
        let mixed_radix_opened_audit_ms = milliseconds(start);
        let start = Instant::now();
        let selected = rank_labels_from_native(&pools, &tables, &rank_gcs, &inverses, &native);
        let translation_and_rank_evaluation_ms = milliseconds(start);
        let start = Instant::now();
        // Evaluator: public circuit plus one rank/validity label per wire only.
        let output = gc.evaluate(&selected).unwrap();
        let (decoded, valid) = mixed_radix::decode_bytes(&gc, &output, WIDTH).unwrap();
        let mixed_radix_evaluation_ms = milliseconds(start);
        assert!(valid);
        assert_eq!(
            hex(&decoded),
            native["recovery"]["payload_hex"].as_str().unwrap()
        );
        native_result = json!({"payload_hex":hex(&decoded),"payload_matches":true,"valid":valid,
            "scalar_opening_occurrences":POOLS*T,"membership_wire_labels":POOLS*N,
            "rank_and_validity_labels":selected.len(),"message_labels":WIDTH,"global_validity_labels":1,
            "scope":"Actual encrypted-share openings and composed garbled evaluation using cached Core scalar records; no fresh Core run."});
        if sample == 0 {
            boundary = check_complete_codewords(&gc, &pairs);
        }
        let (ands, xors, bytes) = gc.counts();
        measurements.push(json!({"sample":sample,
            "translation_and_rank_generation_ms":translation_and_rank_generation_ms,
            "mixed_radix_generation_ms":mixed_radix_generation_ms,
            "generation_ms":translation_and_rank_generation_ms+mixed_radix_generation_ms,
            "translation_and_rank_opened_audit_ms":translation_and_rank_opened_audit_ms,
            "mixed_radix_opened_audit_ms":mixed_radix_opened_audit_ms,
            "opened_audit_ms":translation_and_rank_opened_audit_ms+mixed_radix_opened_audit_ms,
            "generation_plus_opened_audit_ms":translation_and_rank_generation_ms+mixed_radix_generation_ms+translation_and_rank_opened_audit_ms+mixed_radix_opened_audit_ms,
            "translation_and_rank_evaluation_ms":translation_and_rank_evaluation_ms,"mixed_radix_evaluation_ms":mixed_radix_evaluation_ms,
            "mixed_radix_and_gates":ands,"mixed_radix_xor_gates":xors,"mixed_radix_garbled_payload_bytes":bytes,
            "rank_garbled_payload_bytes":rank_gcs.iter().map(|d|d.counts().2).sum::<usize>(),
            "mixed_radix_fingerprint_blake3":hex(&gc.fingerprint())}));
    }
    println!("{}",serde_json::to_string_pretty(&json!({"evidence":"locally-reproduced","deployment":"unclassified",
        "scope":"All95 independent 5-of-54 target pools, actual complement ciphertexts and per-pool garblings, private inter-circuit wiring, full2048-bit mixed-radix GC. Generation and all-secrets audit are separate. Public setup verification, BitVM3 verifier/garbling copies, native scripts/transactions, process startup and executable compilation are excluded. No free table cache.",
        "message_rule":"Little-endian mixed-radix integer modulo2^2048; overflow codewords are accepted and map to one256-byte message.",
        "pointlock_extraction_soundness_proved":false,"public_setup_verification_ms":Value::Null,
        "public_malicious_setup_binding":false,"bitcoin_execution_this_run":false,
        "incremental_onchain_script_bytes":0,"incremental_onchain_witness_bytes":0,
        "incremental_hint_items":0,"incremental_onchain_stack_items":0,
        "workers":workers,"build_profile":if cfg!(debug_assertions){"debug"}else{"release"},
        "native_report_sha256":native_hash,"native_manifest_sha256":manifest_hash,"pools":POOLS,"n":N,"t":T,"radix":RADIX,"encrypted_share_bytes":POOLS*N*(N-1)*16,
        "input_label_commitment_bytes":POOLS*N*64,"target_point_bytes":POOLS*N*33,
        "native_composition":native_result,"boundary_checks":boundary,"samples":measurements})).unwrap());
}
