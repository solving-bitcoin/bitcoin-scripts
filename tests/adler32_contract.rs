//! Shared byte-witness contracts across checksum schedules and word adapters.
use bitcoin::{
    hashes::{sha256, Hash},
    ScriptBuf,
};
use bitcoin_lab::{
    arithmetic::{
        checksums::adler32::{adler32_state, MAX_BYTES},
        u32::bits,
    },
    support::{execution::ExecuteInfo, script::*},
};
use bitcoin_scriptexec::ExecError;
#[path = "../research/adler32-delayed-reduction/measure.rs"]
mod measure;
use measure::{baseline, leaf, num, run, states};
type Generator = fn(u32) -> Script;
fn canonical_bits(n: u32) -> Script {
    assert_eq!(n, 4);
    bits::u32_to_le_bits_canonical()
}
fn numeric_bits(n: u32) -> Script {
    assert_eq!(n, 4);
    bits::u32_to_le_bits()
}
const FAMILIES: [(&str, Generator, bool, bool); 5] = [
    ("delayed", adler32_state, true, false),
    (
        "bounded-streaming",
        baseline::bounded_streaming,
        true,
        false,
    ),
    ("interleaved", baseline::interleaved, true, false),
    ("word-canonical", canonical_bits, true, true),
    ("word-numeric", numeric_bits, false, true),
];
fn outputs(v: &[u8], word: bool) -> Vec<i64> {
    if word {
        v.iter()
            .flat_map(|&x| (0..8).rev().map(move |b| i64::from((x >> b) & 1)))
            .collect()
    } else {
        states(v).into_iter().map(i64::from).collect()
    }
}
fn cleanup(g: Generator, word: bool) -> ScriptBuf {
    let output_count = if word { 32 } else { 2 };
    script! {{g(4)}for _ in 0..output_count{OP_DROP}OP_TRUE}.compile_with_policy()
}
fn clean(r: &ExecuteInfo) {
    assert!(r.stack_limit_enforced);
    assert_eq!(r.error, None, "{r}");
    assert!(r.success, "{r}");
    assert_eq!(r.final_stack.len(), 1);
    assert_eq!(r.final_stack.get(0), vec![1]);
}
fn rejects(r: &ExecuteInfo, e: ExecError) {
    assert_eq!(r.error, Some(e), "{r}");
    assert!(!r.success);
    assert!(r.stack_limit_enforced);
}
fn caught(r: &ExecuteInfo, e: ExecError) {
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rejects(r, e))).is_err());
}
#[test]
fn independent_zlib_vectors_and_asymmetric_order() {
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../research/adler32-delayed-reduction/oracle.json"
    ))
    .unwrap();
    assert_eq!(oracle["vectors"].as_array().unwrap().len(), 555);
    for row in oracle["vectors"].as_array().unwrap() {
        let hex = row["hex"].as_str().unwrap();
        let v: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let e = [
            row["state"][0].as_u64().unwrap() as u32,
            row["state"][1].as_u64().unwrap() as u32,
        ];
        assert_eq!(states(&v), e);
        assert_eq!(
            u64::from(e[0]) + (u64::from(e[1]) << 16),
            row["packed"].as_u64().unwrap()
        );
        for (name, g, _, word) in FAMILIES {
            if word || (name == "interleaved" && v.len() > 995) {
                continue;
            }
            clean(&run(
                leaf(g(v.len() as u32), e).compile_with_policy(),
                v.iter().map(|&x| num(x.into())).collect(),
            ));
        }
    }
    let v = [0x80, 1, 0xaa, 0x55];
    for (_, g, _, word) in FAMILIES {
        let e = outputs(&v, word);
        clean(&run(
            script! {{g(4)}for &x in e.iter().rev(){{x}OP_EQUALVERIFY}OP_TRUE}
                .compile_with_policy(),
            v.iter().map(|&x| num(x.into())).collect(),
        ));
    }
    assert_eq!(states(b"123456789"), [478, 2334]);
    assert_eq!(states(&[1, 2, 1]), states(&[2, 0, 2])); // Intentional checksum collision.
    for n in [MAX_BYTES + 1, u32::MAX] {
        assert!(std::panic::catch_unwind(|| adler32_state(n)).is_err());
    }
}
#[test]
fn malformed_every_position_numeric_aliases_and_short_inputs() {
    let v = [1u8, 128, 0, 255];
    let valid: Vec<_> = v.iter().map(|&x| num(x.into())).collect();
    for (name, g, canonical, word) in FAMILIES {
        let s = cleanup(g, word);
        clean(&run(s.clone(), valid.clone()));
        for (bad, e) in [
            (num(-1), ExecError::Verify),
            (num(256), ExecError::Verify),
            (num(i32::MAX.into()), ExecError::Verify),
            (vec![0; 5], ExecError::ScriptIntNumericOverflow),
            (vec![0; 521], ExecError::PushSize),
        ] {
            for pos in 0..4 {
                let mut w = valid.clone();
                w[pos] = bad.clone();
                rejects(&run(s.clone(), w), e.clone());
            }
        }
        for (bad, value) in [
            (vec![0], 0),
            (vec![0x80], 0),
            (vec![1, 0], 1),
            (vec![255, 0, 0], 255),
        ] {
            for pos in 0..4 {
                let mut w = valid.clone();
                w[pos] = bad.clone();
                if canonical {
                    rejects(&run(s.clone(), w), ExecError::EqualVerify);
                } else {
                    let mut changed = v;
                    changed[pos] = value;
                    let e = outputs(&changed, word);
                    clean(&run(
                        script! {{g(4)}for &x in e.iter().rev(){{x}OP_EQUALVERIFY}OP_TRUE}
                            .compile_with_policy(),
                        w,
                    ));
                }
            }
        }
        for len in 0..4 {
            rejects(
                &run(s.clone(), valid[..len].to_vec()),
                ExecError::InvalidStackOperation,
            );
        }
        assert!(run(s, valid.clone()).success, "{name} valid control");
    }
}
#[test]
fn compiled_guard_mutations_trigger_the_same_rejection_assertion() {
    let valid: Vec<_> = [1, 128, 0, 255].into_iter().map(num).collect();
    for (name, g, canonical, word) in FAMILIES {
        let original = cleanup(g, word);
        let mut variants = vec![(
            script! {OP_DUP 0 256 OP_WITHIN OP_VERIFY},
            num(256),
            ExecError::Verify,
            if word && canonical { 8 } else { 4 },
        )];
        if canonical {
            variants.push((
                script! {OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY},
                vec![1, 0],
                ExecError::EqualVerify,
                4,
            ));
        }
        for (guard, bad, error, expected_hits) in variants {
            let pattern = guard.compile_with_policy().to_bytes();
            let mut bytes = original.to_bytes();
            let mut hits = 0;
            while let Some(i) = bytes.windows(pattern.len()).position(|w| w == pattern) {
                bytes.drain(i..i + pattern.len());
                hits += 1;
            }
            assert_eq!(hits, expected_hits, "{name}");
            let mutant = ScriptBuf::from_bytes(bytes);
            clean(&run(mutant.clone(), valid.clone()));
            for pos in 0..4 {
                let mut w = valid.clone();
                w[pos] = bad.clone();
                rejects(&run(original.clone(), w.clone()), error.clone());
                let r = run(mutant.clone(), w);
                clean(&r);
                caught(&r, error.clone());
            }
        }
    }
}
#[test]
fn caller_stacks_and_exact_live_resource_boundaries() {
    for (name, g, _, word) in FAMILIES {
        let counts = if word {
            vec![4]
        } else if name == "interleaved" {
            vec![0, 1, 32, 995]
        } else {
            vec![0, 1, 32, 997]
        };
        for n in counts {
            let peak = if word {
                35
            } else if n == 0 {
                2
            } else {
                n + if name == "interleaved" { 5 } else { 3 }
            };
            let allowance = 1000 - peak;
            for a in [0, 1, 3] {
                if a > allowance {
                    continue;
                }
                let m = allowance - a;
                let main: Vec<_> = (0..m).map(|i| num(10000 + i64::from(i))).collect();
                let alt: Vec<_> = (0..a).map(|i| num(20000 + i64::from(i))).collect();
                let v: Vec<_> = (0..n).map(|i| ((173 * i + 19) % 256) as u8).collect();
                let mut w = main.clone();
                w.extend(v.iter().map(|&x| num(x.into())));
                w.extend(alt.clone());
                let s = script! {for _ in 0..a{OP_TOALTSTACK}{g(n)}for _ in 0..a{OP_FROMALTSTACK}}
                    .compile_with_policy();
                let r = run(s.clone(), w.clone());
                assert_eq!(r.error, None, "{name} n={n} a={a}: {r}");
                assert_eq!(r.stats.max_nb_stack_items, 1000, "{name} n={n}");
                let mut e = main;
                e.extend(outputs(&v, word).into_iter().map(num));
                e.extend(alt);
                assert_eq!(r.final_stack.len(), e.len());
                for (i, item) in e.iter().enumerate() {
                    assert_eq!(&r.final_stack.get(i), item, "{name} n={n} index={i}");
                }
                w.insert(0, num(9999));
                rejects(&run(s, w), ExecError::StackSize);
            }
        }
    }
}
#[test]
fn original_schedule_counterexample_and_regression_detection() {
    for n in [995, 996, 997] {
        let v = vec![255; n as usize];
        let w = vec![num(255); n as usize];
        let e = states(&v);
        let original = run(
            leaf(baseline::interleaved(n), e).compile_with_policy(),
            w.clone(),
        );
        if n == 995 {
            clean(&original);
            assert_eq!(original.stats.max_nb_stack_items, 1000);
        } else {
            rejects(&original, ExecError::StackSize);
            assert_eq!(original.stats.max_nb_stack_items, 1001);
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| clean(&original)))
                    .is_err()
            );
        }
        let repaired = run(leaf(adler32_state(n), e).compile_with_policy(), w);
        clean(&repaired);
        assert_eq!(repaired.stats.max_nb_stack_items, n as usize + 3);
    }
    let r = run(
        leaf(baseline::bounded_streaming(998), states(&vec![255; 998])).compile_with_policy(),
        vec![num(255); 998],
    );
    rejects(&r, ExecError::StackSize);
    assert_eq!(r.stats.max_nb_stack_items, 1001);
}
#[test]
fn both_terminal_bindings_detect_changes_and_predicate_mutations() {
    let v = [1u8, 2, 9, 128];
    let w: Vec<_> = v.iter().map(|&x| num(x.into())).collect();
    let e = states(&v);
    for (_, g, _, word) in FAMILIES {
        if word {
            continue;
        }
        clean(&run(leaf(g(4), e).compile_with_policy(), w.clone()));
        for lane in 0..2 {
            let mut wrong = e;
            wrong[lane] += 1;
            rejects(
                &run(leaf(g(4), wrong).compile_with_policy(), w.clone()),
                ExecError::EqualVerify,
            );
            // Deliberately replace exactly the failed lane's predicate with DROP.
            let mutant = if lane == 0 {
                script! {{g(4)}{e[1]}OP_EQUALVERIFY OP_DROP OP_TRUE}
            } else {
                script! {{g(4)}OP_DROP{e[0]}OP_EQUALVERIFY OP_TRUE}
            };
            let r = run(mutant.compile_with_policy(), w.clone());
            clean(&r);
            caught(&r, ExecError::EqualVerify);
        }
        let mut changed = w.clone();
        changed[0] = num(2);
        rejects(
            &run(leaf(g(4), e).compile_with_policy(), changed.clone()),
            ExecError::EqualVerify,
        );
        let r = run(cleanup(g, false), changed);
        clean(&r);
        caught(&r, ExecError::EqualVerify);
    }
}
#[test]
fn report_and_catalog_bind_every_artifact_and_policy_boundary() {
    let report: serde_json::Value = serde_json::from_str(include_str!(
        "../research/adler32-delayed-reduction/metrics.json"
    ))
    .unwrap();
    assert_eq!(
        measure::report(report["source_revision"].as_str().unwrap()),
        report
    );
    assert_eq!(report["source_revision"].as_str().unwrap().len(), 40);
    let revision = report["source_revision"].as_str().unwrap();
    assert!(revision.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(revision, "0000000000000000000000000000000000000000");
    // Full clones additionally audit the immutable commit. Shallow CI retains
    // the current-tree SHA256/recomputation checks above without fetching history.
    let commit = std::process::Command::new("git")
        .args(["cat-file", "-e", revision])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    if !commit.status.success() {
        let shallow = std::process::Command::new("git")
            .args(["rev-parse", "--is-shallow-repository"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .unwrap();
        assert!(shallow.status.success());
        assert_eq!(shallow.stdout, b"true\n");
    }
    for (path, hash) in report["source_sha256"].as_object().unwrap() {
        if !commit.status.success() {
            continue;
        }
        let blob = std::process::Command::new("git")
            .args(["show", &format!("{revision}:{path}")])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .unwrap();
        assert!(blob.status.success(), "source revision lacks {path}");
        assert_eq!(
            sha256::Hash::hash(&blob.stdout).to_string(),
            hash.as_str().unwrap()
        );
    }
    let catalog: serde_json::Value =
        serde_json::from_str(include_str!("../knowledge/catalog.json")).unwrap();
    let r = catalog["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "arithmetic/adler32-state")
        .unwrap();
    assert_eq!(r["evidence"], "locally-reproduced");
    assert_eq!(r["execution"], "unclassified");
    assert_eq!(r["configurations"].as_array().unwrap().len(), 7);
    for c in r["configurations"].as_array().unwrap() {
        let n = c["parameters"]["byte_count"].as_u64().unwrap();
        let row = report["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["algorithm"] == "delayed" && x["n"] == n)
            .unwrap();
        let which = c["parameters"]["boundary"].as_str().unwrap();
        assert_eq!(c["script_bytes"], row[which]["script_bytes"]);
        assert_eq!(c["max_stack_items"], row[which]["max_stack_items"]);
        assert_eq!(c["parameters"]["sha256"], row[which]["sha256"]);
        assert_eq!(c["parameters"]["raw_bytes"], row[which]["raw_bytes"]);
        assert_eq!(
            c["parameters"]["compile_options"],
            row[which]["compile_options"]
        );
        assert_eq!(
            c["parameters"]["static_non_push_opcodes"],
            row[which]["static_non_push_opcodes"]
        );
        assert_eq!(c["parameters"]["witness_sha256"], row["witness_sha256"]);
        assert_eq!(c["witness_bytes"], row["witness_bytes"]);
        assert_eq!(c["witness_bytes_max"], row["witness_bytes"]);
        assert_eq!(c["parameters"]["data_items"], n);
        assert_eq!(c["parameters"]["hint_items"], 0);
        for key in ["source_revision", "compiler_source", "interpreter_source"] {
            assert_eq!(c["parameters"][key], report[key]);
        }
        assert!(c["executed_opcodes"].is_null());
        assert!(c["validation_weight"].is_null());
    }
    let find = |name: &str, n: u64| {
        report["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["algorithm"] == name && r["n"] == n)
            .unwrap()
    };
    let split = find("naive-streaming", 728);
    assert_eq!(split["fragment"]["raw_bytes"], 32762);
    assert_eq!(split["fragment"]["compile_options"], "ALL");
    assert_eq!(split["leaf"]["raw_bytes"], 32773);
    assert_eq!(split["leaf"]["compile_options"], "NONE");
    assert_eq!(
        find("bounded-streaming", 808)["fragment"]["compile_options"],
        "ALL"
    );
    assert_eq!(
        find("bounded-streaming", 809)["fragment"]["compile_options"],
        "NONE"
    );
    assert_eq!(find("delayed", 0)["fragment"]["max_stack_items"], 2);
    assert_eq!(find("delayed", 0)["leaf"]["max_stack_items"], 1);
    // Source bindings include this suite: changing the contract invalidates the artifact.
    assert_eq!(
        report["source_sha256"]["tests/adler32_contract.rs"],
        sha256::Hash::hash(include_bytes!("adler32_contract.rs")).to_string()
    );
}
