//! Shared runtime contract for vector scans, scalar reduction and forward delta.
use bitcoin_lab::{
    arithmetic::u4::{adjacent_delta, prefix_sum, sum},
    support::{
        execution::ExecuteInfo,
        script::{script, Script, ScriptCompilation},
        tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
    },
};
use bitcoin_scriptexec::ExecError;
#[path = "../research/u4-prefix-reconstruction/baseline.rs"]
mod baseline;
type Generator = fn(u32) -> Script;
const FAMILIES: [(&str, Generator, bool); 4] = [
    ("prefix", prefix_sum::u4_nibbles_to_prefix_sum, true),
    ("table-prefix", baseline::table, true),
    ("scalar-sum", sum::u4_nibbles_to_sum_mod16, true),
    ("delta", adjacent_delta::u4_nibbles_to_adjacent_delta, false),
];
fn num(x: i64) -> Vec<u8> {
    let mut b = [0u8; 8];
    let n = bitcoin::script::write_scriptint(&mut b, x);
    b[..n].to_vec()
}
fn exec(bytes: Vec<u8>, w: Vec<Vec<u8>>) -> ExecuteInfo {
    match execute_tapscript(
        bitcoin::ScriptBuf::from_bytes(bytes),
        w,
        TapscriptProfile::Consensus,
    )
    .outcome
    {
        TapscriptOutcome::Executed(r) => r,
        other => panic!("unexpected {other:?}"),
    }
}
fn rejects(r: &ExecuteInfo, e: ExecError) {
    assert_eq!(r.error, Some(e), "{r}");
    assert!(!r.success);
}
fn count(name: &str, n: u32) -> u32 {
    match name {
        "scalar-sum" => 1,
        "delta" => n - 1,
        _ => n,
    }
}
fn cleanup(name: &str, f: Script, n: u32) -> Vec<u8> {
    script! {{f} for _ in 0..count(name,n){OP_DROP} OP_TRUE}
        .compile_with_policy()
        .to_bytes()
}
fn expected(name: &str, v: &[u8]) -> Vec<u8> {
    match name {
        "canonical-delta-roundtrip" => v.to_vec(),
        "scalar-sum" => vec![(v.iter().map(|&x| u32::from(x)).sum::<u32>() % 16) as u8],
        "delta" => v.windows(2).map(|w| (16 + w[1] - w[0]) % 16).collect(),
        _ => {
            let mut acc = 0;
            v.iter()
                .map(|&x| {
                    acc = (acc + x) % 16;
                    acc
                })
                .collect()
        }
    }
}
fn check(name: &str, f: Script, v: &[u8]) {
    let e = expected(name, v);
    let leaf =
        script! {{f} for &x in e.iter().rev(){{x} OP_EQUALVERIFY} OP_TRUE}.compile_with_policy();
    let r = exec(leaf.to_bytes(), v.iter().map(|&x| num(x.into())).collect());
    assert!(r.success, "{name} {v:?}: {r}");
    assert_eq!(r.final_stack.len(), 1);
}
#[test]
fn exhaustive_short_scans_and_deterministic_long_vectors() {
    for (name, g, _) in FAMILIES.into_iter().take(2) {
        for n in 1..=3 {
            let f = g(n);
            for encoded in 0..16u32.pow(n) {
                let v: Vec<_> = (0..n).map(|i| ((encoded >> (4 * i)) & 15) as u8).collect();
                check(name, f.clone(), &v);
            }
        }
        for n in [4, 16, 32, 128] {
            let v: Vec<_> = (0..n).map(|i| ((7 * i + i / 3) % 16) as u8).collect();
            check(name, g(n), &v);
        }
        assert!(std::panic::catch_unwind(|| g(0)).is_err());
        assert!(std::panic::catch_unwind(|| g(if name == "prefix" { 998 } else { 967 })).is_err());
    }
}
#[test]
fn hostile_every_position_and_short_inputs_have_typed_errors_and_controls() {
    for (name, g, canonical) in FAMILIES {
        let leaf = cleanup(name, g(4), 4);
        let valid = vec![num(1), num(7), num(2), num(15)];
        assert!(exec(leaf.clone(), valid.clone()).success, "{name}");
        for (bad, e) in [
            (num(-1), ExecError::Verify),
            (num(16), ExecError::Verify),
            (num(i32::MAX.into()), ExecError::Verify),
            (vec![0; 5], ExecError::ScriptIntNumericOverflow),
            (vec![0; 521], ExecError::PushSize),
        ] {
            for position in 0..4 {
                let mut w = valid.clone();
                w[position] = bad.clone();
                rejects(&exec(leaf.clone(), w), e.clone());
            }
        }
        for bad in [vec![0], vec![0x80], vec![1, 0], vec![15, 0, 0, 0]] {
            for position in 0..4 {
                let mut w = valid.clone();
                w[position] = bad.clone();
                if canonical {
                    rejects(&exec(leaf.clone(), w), ExecError::EqualVerify);
                } else {
                    let mut v = [1, 7, 2, 15];
                    v[position] = match bad.as_slice() {
                        [0] | [0x80] => 0,
                        [1, 0] => 1,
                        _ => 15,
                    };
                    let e = expected(name, &v);
                    let verified =
                        script! {{g(4)}for &x in e.iter().rev(){{x}OP_EQUALVERIFY}OP_TRUE}
                            .compile_with_policy();
                    assert!(
                        exec(verified.to_bytes(), w).success,
                        "delta alias position {position}"
                    );
                }
            }
        }
        for len in 0..4 {
            rejects(
                &exec(leaf.clone(), valid[..len].to_vec()),
                ExecError::InvalidStackOperation,
            );
        }
    }
}
#[test]
fn asymmetric_outputs_and_runtime_caller_state_are_preserved() {
    for (name, g, _) in FAMILIES {
        let v = [1, 7, 2, 15];
        let e = expected(name, &v);
        let leaf = script! {OP_TOALTSTACK OP_TOALTSTACK {g(4)}
        for &x in e.iter().rev(){{x} OP_EQUALVERIFY}
        103 OP_EQUALVERIFY 99 OP_EQUALVERIFY
        OP_FROMALTSTACK 77 OP_EQUALVERIFY OP_FROMALTSTACK 81 OP_EQUALVERIFY OP_TRUE}
        .compile_with_policy();
        let w = [99, 103, 1, 7, 2, 15, 77, 81]
            .into_iter()
            .map(num)
            .collect();
        let r = exec(leaf.to_bytes(), w);
        assert!(r.success, "{name}: {r}");
        assert_eq!(r.final_stack.len(), 1);
    }
}
#[test]
fn exact_combined_stack_frontiers_keep_observable_outputs() {
    let cases: Vec<(&str, Generator, u32, u32)> = vec![
        ("canonical-delta-roundtrip", baseline::roundtrip, 32, 66),
        ("prefix", prefix_sum::u4_nibbles_to_prefix_sum, 1, 4),
        ("prefix", prefix_sum::u4_nibbles_to_prefix_sum, 2, 5),
        ("prefix", prefix_sum::u4_nibbles_to_prefix_sum, 32, 35),
        ("prefix", prefix_sum::u4_nibbles_to_prefix_sum, 997, 1000),
        ("table-prefix", baseline::table, 1, 4),
        ("table-prefix", baseline::table, 32, 66),
        ("table-prefix", baseline::table, 966, 1000),
        ("scalar-sum", sum::u4_nibbles_to_sum_mod16, 32, 66),
        (
            "delta",
            adjacent_delta::u4_nibbles_to_adjacent_delta,
            32,
            65,
        ),
    ];
    for (name, g, n, peak) in cases {
        let body = g(n);
        for a in [0, 1, 3] {
            let allowance = 1000 - peak;
            if a > allowance {
                continue;
            }
            let m = allowance - a;
            let leaf =
                script! {for _ in 0..a{OP_TOALTSTACK}{body.clone()}for _ in 0..a{OP_FROMALTSTACK}}
                    .compile_with_policy()
                    .to_bytes();
            let main: Vec<_> = (0..m).map(|i| num(10000 + i as i64)).collect();
            let alt: Vec<_> = (0..a).map(|i| num(20000 + i as i64)).collect();
            let mut w = main.clone();
            w.extend(vec![num(7); n as usize]);
            w.extend(alt.clone());
            let r = exec(leaf.clone(), w.clone());
            assert!(r.error.is_none(), "{name} n={n} a={a}: {r}");
            let mut all = main;
            all.extend(
                expected(name, &vec![7; n as usize])
                    .into_iter()
                    .map(|x| num(x.into())),
            );
            all.extend(alt);
            assert_eq!(r.final_stack.len(), all.len());
            for (i, x) in all.iter().enumerate() {
                assert_eq!(&r.final_stack.get(i), x, "{name} index={i}");
            }
            assert_eq!(r.stats.max_nb_stack_items, 1000, "{name} n={n} a={a}");
            w.insert(0, num(9999));
            rejects(&exec(leaf, w), ExecError::StackSize);
        }
    }
}
#[test]
fn deliberate_mutations_are_detected_by_the_same_typed_assertion() {
    for (name, g, canonical) in FAMILIES {
        let original = cleanup(name, g(4), 4);
        let checks = if canonical {
            vec![
                (
                    script! {OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY},
                    vec![],
                    vec![1, 0],
                    ExecError::EqualVerify,
                ),
                (
                    script! {OP_DUP 0 16 OP_WITHIN OP_VERIFY},
                    vec![],
                    num(16),
                    ExecError::Verify,
                ),
            ]
        } else {
            vec![
                (
                    script! {OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY},
                    vec![],
                    num(-1),
                    ExecError::Verify,
                ),
                (
                    script! {16 OP_LESSTHAN OP_VERIFY},
                    script! {OP_DROP}.compile_with_policy().to_bytes(),
                    num(16),
                    ExecError::Verify,
                ),
            ]
        };
        for (check, replacement, bad, error) in checks {
            let pattern = check.compile_with_policy().to_bytes();
            let mut modified = original.clone();
            let mut hits = 0;
            while let Some(i) = modified.windows(pattern.len()).position(|w| w == pattern) {
                modified.splice(i..i + pattern.len(), replacement.clone());
                hits += 1;
            }
            assert_eq!(hits, 4, "{name}: pattern={pattern:?}");
            let valid = vec![num(1), num(7), num(2), num(15)];
            assert!(
                exec(modified.clone(), valid.clone()).success,
                "{name} mutated control"
            );
            for position in 0..4 {
                let mut w = valid.clone();
                w[position] = bad.clone();
                rejects(&exec(original.clone(), w.clone()), error.clone());
                let r = exec(modified.clone(), w);
                assert!(r.success, "{name} mutated position={position}: {r}");
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rejects(
                        &r,
                        error.clone()
                    )))
                    .is_err()
                );
            }
        }
    }
}
#[test]
fn canonical_delta_roundtrip_retains_initial_and_rejects_unchecked_original_aliases() {
    for n in [2, 3, 4, 32, 128] {
        let f = baseline::roundtrip(n);
        let v: Vec<_> = (0..n).map(|i| ((7 * i + i / 3) % 16) as u8).collect();
        let leaf = script! {{f}for &x in v.iter().rev(){{x}OP_EQUALVERIFY}OP_TRUE}
            .compile_with_policy()
            .to_bytes();
        let w: Vec<_> = v.iter().map(|&x| num(x.into())).collect();
        assert!(exec(leaf.clone(), w.clone()).success);
        for i in 0..n as usize {
            let mut bad = w.clone();
            bad[i] = vec![1, 0];
            rejects(&exec(leaf.clone(), bad), ExecError::EqualVerify);
        }
    }
    for x in 0..16 {
        for y in 0..16 {
            let leaf = script! {{baseline::roundtrip(2)}{y}OP_EQUALVERIFY{x}OP_EQUALVERIFY OP_TRUE}
                .compile_with_policy();
            assert!(exec(leaf.to_bytes(), vec![num(x), num(y)]).success);
        }
    }
}

#[test]
fn complete_prefix_predicate_detects_wrong_outputs_and_a_terminal_mutation() {
    for (name, g, _) in FAMILIES.into_iter().take(2) {
        let v = [1, 7, 2, 15];
        let expected = expected(name, &v);
        let original = script! {{g(4)}for &x in expected.iter().rev(){{x}OP_EQUALVERIFY}OP_TRUE}
            .compile_with_policy();
        let w: Vec<_> = v.into_iter().map(|x| num(x.into())).collect();
        assert!(exec(original.to_bytes(), w.clone()).success);
        let mut bad = w;
        bad[3] = num(14);
        rejects(
            &exec(original.to_bytes(), bad.clone()),
            ExecError::EqualVerify,
        );
        let mutated = cleanup(name, g(4), 4);
        let r = exec(mutated, bad);
        assert!(r.success);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rejects(
                &r,
                ExecError::EqualVerify
            )))
            .is_err()
        );
    }
}

#[test]
fn report_binds_artifacts_inputs_options_and_dependency_pins() {
    use bitcoin::{
        consensus::encode::serialize,
        hashes::{sha256, Hash},
        script::Instruction,
        Witness,
    };
    use bitcoin_lab::support::{execution::execute_raw_script_with_inputs_strict, provenance};
    let report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/research/u4-prefix-reconstruction/metrics.json"
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        report["compiler_source"],
        provenance::compiler().unwrap().source
    );
    assert_eq!(
        report["interpreter_source"],
        provenance::interpreter().unwrap().source
    );
    assert_eq!(report["execution"], "unclassified");
    assert_eq!(report["evidence"], "locally-reproduced");
    assert_eq!(report["options"],"ExecCtx::Tapscript; Options::default with enforce_stack_limit=true; synthetic empty transaction; data-only budget; no signatures");
    assert_eq!(
        report["compilation"],
        "compile_with_policy: all fragments and leaves below 32KiB raw cutoff, CompileOptions::ALL"
    );
    assert_eq!(
        report["witness_generator"],
        "n canonical sevens, all data items present at entry, zero hints"
    );
    assert_eq!(
        report["terminal_predicate"],
        "reverse i=n..1 compare output with (7*i)%16 using OP_EQUALVERIFY, then OP_TRUE"
    );
    let mut configs = std::collections::BTreeSet::new();
    for row in report["records"]
        .as_array()
        .unwrap()
        .iter()
        .chain(std::iter::once(&report["composition"]))
    {
        let n = row["nibble_count"].as_u64().unwrap() as u32;
        let name = row["name"].as_str().unwrap();
        assert!(configs.insert((name, n)));
        let (fragment, values) = match name {
            "conditional" => (
                prefix_sum::u4_nibbles_to_prefix_sum(n),
                vec![7u8; n as usize],
            ),
            "table" => (baseline::table(n), vec![7u8; n as usize]),
            "canonical-delta-roundtrip" => (
                baseline::roundtrip(n),
                (0..n).map(|i| ((7 * i + i / 3) % 16) as u8).collect(),
            ),
            _ => panic!("unknown row {name}"),
        };
        let e = if name == "canonical-delta-roundtrip" {
            values.clone()
        } else {
            expected("prefix", &values)
        };
        let compiled = fragment.clone().compile_with_policy();
        let leaf = script! {{fragment}for &x in e.iter().rev(){{x}OP_EQUALVERIFY}OP_TRUE}
            .compile_with_policy();
        let witness: Vec<_> = values.into_iter().map(|x| num(x.into())).collect();
        let serialized = serialize(&Witness::from_slice(&witness));
        assert_eq!(row["fragment_bytes"], compiled.len());
        assert_eq!(row["leaf_bytes"], leaf.len());
        assert_eq!(
            row["fragment_sha256"],
            sha256::Hash::hash(compiled.as_bytes()).to_string()
        );
        assert_eq!(
            row["leaf_sha256"],
            sha256::Hash::hash(leaf.as_bytes()).to_string()
        );
        assert_eq!(
            row["witness_sha256"],
            sha256::Hash::hash(&serialized).to_string()
        );
        assert_eq!(row["witness_bytes"], serialized.len());
        assert_eq!(row["data_items"], n);
        assert_eq!(row["hint_items"], 0);
        assert_eq!(
            row["static_non_push_opcodes"],
            compiled
                .instructions()
                .filter(|i| matches!(i,Ok(Instruction::Op(op))if op.to_u8()>0x60))
                .count()
        );
        assert!(row["executed_opcodes"].is_null());
        assert!(row["validation_weight"].is_null());
        let r = execute_raw_script_with_inputs_strict(leaf.to_bytes(), witness);
        assert!(r.success, "{name} n={n}: {r}");
        assert_eq!(r.final_stack.len(), 1);
        assert_eq!(row["combined_peak"], r.stats.max_nb_stack_items);
    }
    let expected_configs: std::collections::BTreeSet<_> = [1, 2, 32, 128, 966, 997]
        .into_iter()
        .map(|n| ("conditional", n))
        .chain([1, 2, 32, 128, 966].into_iter().map(|n| ("table", n)))
        .chain(std::iter::once(("canonical-delta-roundtrip", 32)))
        .collect();
    assert_eq!(configs, expected_configs);
}

#[test]
fn catalog_configurations_match_the_reported_artifact_boundary() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("research/u4-prefix-reconstruction/metrics.json"))
            .unwrap(),
    )
    .unwrap();
    let catalog: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("knowledge/catalog.json")).unwrap(),
    )
    .unwrap();
    let record = catalog["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "arithmetic/u4-prefix-sum")
        .unwrap();
    for config in record["configurations"].as_array().unwrap() {
        let n = config["parameters"]["nibble_count"].as_u64().unwrap();
        let row = report["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == "conditional" && r["nibble_count"] == n)
            .unwrap();
        let complete = config["includes"]
            .as_str()
            .unwrap()
            .starts_with("complete-leaf:");
        assert_eq!(
            config["script_bytes"],
            row[if complete {
                "leaf_bytes"
            } else {
                "fragment_bytes"
            }]
        );
        assert_eq!(config["witness_bytes"], row["witness_bytes"]);
        assert_eq!(config["witness_bytes_max"], row["witness_bytes"]);
        assert_eq!(config["max_stack_items"], row["combined_peak"]);
        assert_eq!(
            config["static_non_push_opcodes"],
            row["static_non_push_opcodes"].as_u64().unwrap() + if complete { n } else { 0 }
        );
        assert_eq!(
            config["parameters"]["static_non_push_opcodes"],
            config["static_non_push_opcodes"]
        );
        for key in ["fragment_sha256", "leaf_sha256", "witness_sha256"] {
            assert_eq!(config["parameters"][key], row[key]);
        }
        assert_eq!(
            config["parameters"]["compiler_source"],
            report["compiler_source"]
        );
        assert_eq!(
            config["parameters"]["interpreter_source"],
            report["interpreter_source"]
        );
        assert_eq!(
            config["parameters"]["terminal_predicate"],
            report["terminal_predicate"]
        );
        assert_eq!(config["parameters"]["data_items"], n);
        assert_eq!(config["parameters"]["hint_items"], 0);
        assert!(config["executed_opcodes"].is_null());
        assert!(config["validation_weight"].is_null());
    }
}
