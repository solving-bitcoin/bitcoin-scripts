//! Focused PRINCEv2 differential checks that compile only once per embedded key.
//!
//! Run with `cargo test --locked --release --test prince_differential -- --ignored --nocapture`.
//! `PRINCE_FUZZ_KEYS` controls additional random keys (default 2),
//! `PRINCE_FUZZ_PLAINTEXTS_PER_KEY` random blocks per key (default 32), and
//! `PRINCE_FUZZ_SEED` the reproducible decimal u64 seed. Zero, all-ones, and the
//! published-vector key are always covered, each with boundary plaintexts too.

use bitcoin::{
    consensus::serialize,
    opcodes::all::OP_EQUALVERIFY,
    script::{Builder, Instruction},
    ScriptBuf, Witness,
};
use bitcoin_lab::{
    ciphers::prince::{prince_encrypt, prince_encrypt_ref, u64_to_nibbles_msb},
    support::{execution::execute_raw_script_with_inputs_strict, script::ScriptCompilation},
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const DEFAULT_SEED: u64 = 0x5052_494e_4345_5632;
const VECTOR_KEY: u128 = 0x0123456789abcdeffedcba9876543210;

fn upstream_c_vectors() -> Vec<(u128, u64, u64)> {
    // These constants come from running unmodified upstream C, independently
    // of the native Rust reference and its constants. The checked-in generator
    // records the upstream revision, PRNG, draw order and compiler invocation.
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("data/princev2_upstream_vectors.json")).unwrap();
    assert_eq!(
        fixtures["commit"],
        "0c6172dcd85f1fe6a269519093a79c7350fe6e55"
    );
    let vectors = fixtures["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 37);
    vectors
        .iter()
        .map(|vector| {
            (
                u128::from_str_radix(vector["key"].as_str().unwrap(), 16).unwrap(),
                u64::from_str_radix(vector["plaintext"].as_str().unwrap(), 16).unwrap(),
                u64::from_str_radix(vector["ciphertext"].as_str().unwrap(), 16).unwrap(),
            )
        })
        .collect()
}

#[test]
fn prince_reference_matches_upstream_c_vectors() {
    for (key, plaintext, expected) in upstream_c_vectors() {
        assert_eq!(
            prince_encrypt_ref(key, plaintext),
            expected,
            "native oracle differs from upstream C: key={key:032x} plaintext={plaintext:016x}"
        );
    }
}

#[test]
#[ignore = "independent upstream-C fixture coverage; use --release for 36 embedded keys"]
fn prince_script_matches_upstream_c_vectors() {
    let mut fragments = BTreeMap::new();
    let mut peak = 0;
    for (key, plaintext, expected) in upstream_c_vectors() {
        let fragment = fragments.entry(key).or_insert_with(|| {
            let fragment = prince_encrypt(key).compile_with_policy();
            non_push_opcodes(&fragment);
            fragment
        });
        let result = execute_raw_script_with_inputs_strict(
            comparison_leaf(fragment, expected),
            plaintext_witness(plaintext),
        );
        assert!(
            result.success,
            "Script differs from upstream C: key={key:032x} plaintext={plaintext:016x} expected={expected:016x}: {result}"
        );
        assert_eq!(result.final_stack.len(), 1);
        assert_eq!(result.final_stack.get(0), vec![1]);
        assert!(result.stats.max_nb_stack_items <= 1_000);
        peak = peak.max(result.stats.max_nb_stack_items);
    }
    println!(
        "upstream-C vectors=37 distinct_keys={} combined_stack_peak={peak} hints_per_invocation=0 witness_data_items=16 context=tapscript stack_limit=1000",
        fragments.len()
    );
}

fn env_number<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .map(|value| value.parse().unwrap_or_else(|_| panic!("invalid {name}")))
        .unwrap_or(default)
}

fn plaintext_witness(plaintext: u64) -> Vec<Vec<u8>> {
    u64_to_nibbles_msb(plaintext)
        .into_iter()
        .rev()
        .map(|nibble| if nibble == 0 { vec![] } else { vec![nibble] })
        .collect()
}

fn comparison_leaf(fragment: &ScriptBuf, expected: u64) -> Vec<u8> {
    // Keep the exact policy-produced fragment bytes for every execution and
    // measurement. This test-only suffix is intentionally not optimized across
    // the fragment boundary; it contributes 33 bytes, separately disclosed.
    let mut comparison = Builder::new();
    for nibble in u64_to_nibbles_msb(expected) {
        comparison = comparison
            .push_int(i64::from(nibble))
            .push_opcode(OP_EQUALVERIFY);
    }
    let comparison = comparison.push_int(1).into_script();
    assert_eq!(comparison.len(), 33);
    let mut bytes = fragment.to_bytes();
    bytes.extend_from_slice(comparison.as_bytes());
    bytes
}

fn non_push_opcodes(fragment: &ScriptBuf) -> usize {
    fragment
        .instructions()
        .map(|instruction| match instruction.expect("valid generated script") {
            Instruction::PushBytes(_) => 0,
            Instruction::Op(opcode) => {
                let byte = opcode.to_u8();
                // The strict helper inherits an interpreter option enabling
                // experimental OP_CAT. Explicitly reject it and every other
                // OP_SUCCESSx so that option cannot affect these checks.
                assert!(
                    !matches!(byte, 80 | 98 | 126..=129 | 131..=134 | 137..=138 | 141..=142 | 149..=153 | 187..=254),
                    "unexpected tapscript OP_SUCCESSx: {opcode}"
                );
                // For this branch-free fragment the static non-push count is
                // also the executed count on every successful input. The
                // interpreter's legacy opcode counter is zero in tapscript.
                assert!(
                    !matches!(byte, 0x63 | 0x64 | 0x67 | 0x68),
                    "update executed-opcode measurement for conditional {opcode}"
                );
                usize::from(byte > 0x60)
            }
        })
        .sum()
}

#[test]
#[ignore = "focused randomized Script checks; use --release to avoid optimizer overhead"]
fn prince_randomized_differential_compiled_once() {
    let seed = env_number("PRINCE_FUZZ_SEED", DEFAULT_SEED);
    let random_keys = env_number("PRINCE_FUZZ_KEYS", 2usize);
    let random_plaintexts = env_number("PRINCE_FUZZ_PLAINTEXTS_PER_KEY", 32usize);
    assert!(
        random_plaintexts > 0,
        "random plaintext count must be nonzero"
    );
    // Pin the oracle's published vector independently of script generation.
    assert_eq!(
        prince_encrypt_ref(VECTOR_KEY, 0x0123456789abcdef),
        0x603cd95fa72a8704
    );

    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut keys = vec![0, u128::MAX, VECTOR_KEY];
    keys.extend((0..random_keys).map(|_| rng.gen::<u128>()));
    println!(
        "PRINCEv2 seed={seed} fixed_keys=3 random_keys={random_keys} random_plaintexts_per_key={random_plaintexts} target={}-{} profile={} interpreter=bitcoin-scriptexec@ba96bc2 context=tapscript stack_limit=1000 hints_per_invocation=0 witness_data_items=16",
        std::env::consts::ARCH,
        std::env::consts::OS,
        if cfg!(debug_assertions) { "debug" } else { "release" }
    );
    println!(
        "Boundary: fragment-with-memory includes table setup, encryption and cleanup; excludes input pushes and output checks. Test leaf appends a separate unoptimized 33-byte check. Witness bytes serialize only the 16 plaintext data items, excluding leaf and control block."
    );

    for (key_case, key) in keys.into_iter().enumerate() {
        let started = Instant::now();
        let fragment = prince_encrypt(key).compile_with_policy();
        let generation = started.elapsed();
        println!(
            "key_case={key_case} fragment_sha256={:x}",
            Sha256::digest(fragment.as_bytes())
        );
        let fragment_ops = non_push_opcodes(&fragment);
        let mut plaintexts = vec![
            0,
            u64::MAX,
            0x0123456789abcdef,
            0xfedcba9876543210,
            0x8000000000000000,
            1,
        ];
        plaintexts.extend((0..random_plaintexts).map(|_| rng.gen::<u64>()));
        let mut timings: Vec<Duration> = Vec::with_capacity(plaintexts.len());
        let mut peak = 0;
        let mut witness_min = usize::MAX;
        let mut witness_max = 0;
        for (plaintext_case, plaintext) in plaintexts.into_iter().enumerate() {
            let expected = prince_encrypt_ref(key, plaintext);
            let leaf = comparison_leaf(&fragment, expected);
            let witness = plaintext_witness(plaintext);
            let witness_bytes = serialize(&Witness::from_slice(&witness)).len();
            witness_min = witness_min.min(witness_bytes);
            witness_max = witness_max.max(witness_bytes);
            let started = Instant::now();
            let result = execute_raw_script_with_inputs_strict(leaf, witness);
            timings.push(started.elapsed());
            assert!(
                result.success,
                "seed={seed} key_case={key_case} plaintext_case={plaintext_case} key={key:032x} plaintext={plaintext:016x} expected={expected:016x}: {result}"
            );
            assert_eq!(result.final_stack.len(), 1);
            assert_eq!(result.final_stack.get(0), vec![1]);
            assert!(result.stats.max_nb_stack_items <= 1_000);
            assert_eq!(
                result.stats.start_validation_weight - result.stats.validation_weight,
                0,
                "PRINCEv2 uses no signature-validation budget"
            );
            peak = peak.max(result.stats.max_nb_stack_items);
        }

        // These failures are independent of the valid-nibble precondition.
        // Out-of-range nibble rejection is deliberately not asserted: callers
        // must validate nibble ranges before invoking this primitive fragment.
        let expected = prince_encrypt_ref(key, 0);
        let leaf = comparison_leaf(&fragment, expected);
        let mut short_witness = plaintext_witness(0);
        short_witness.pop();
        assert!(
            !execute_raw_script_with_inputs_strict(leaf.clone(), short_witness).success,
            "accepted 15-item plaintext: seed={seed} key_case={key_case} key={key:032x}"
        );
        let mut oversized_number = plaintext_witness(0);
        oversized_number[0] = vec![0xff, 0xff, 0xff, 0xff, 0];
        assert!(
            !execute_raw_script_with_inputs_strict(leaf, oversized_number).success,
            "accepted oversized ScriptNum: seed={seed} key_case={key_case} key={key:032x}"
        );
        assert!(
            !execute_raw_script_with_inputs_strict(
                comparison_leaf(&fragment, expected ^ 1),
                plaintext_witness(0),
            )
            .success,
            "accepted wrong ciphertext: seed={seed} key_case={key_case} key={key:032x}"
        );

        timings.sort_unstable();
        println!(
            "key_case={key_case} key={key:032x} fragment_bytes={} test_leaf_bytes={} fragment_non_push_ops={fragment_ops} test_leaf_executed_non_push_ops={} stack_peak={peak} witness_bytes={witness_min}..{witness_max} valid_cases={} invalid_cases=3 generation_ms={:.3} execution_ms_min={:.3} median={:.3} max={:.3}",
            fragment.len(),
            fragment.len() + 33,
            fragment_ops + 16,
            timings.len(),
            generation.as_secs_f64() * 1000.0,
            timings[0].as_secs_f64() * 1000.0,
            timings[timings.len() / 2].as_secs_f64() * 1000.0,
            timings.last().unwrap().as_secs_f64() * 1000.0,
        );
    }
}
