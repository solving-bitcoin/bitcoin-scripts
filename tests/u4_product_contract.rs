//! Shared contracts for exact and modulo products, with canonical/numeric inputs.
use bitcoin_lab::{
    arithmetic::u4::quarter_square,
    support::{
        execution::ExecuteInfo,
        script::*,
        tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
    },
};
use bitcoin_scriptexec::ExecError;
#[path = "../research/u4-quarter-square/baseline.rs"]
mod baseline;
type Generator = fn(u32) -> Script;
const FAMILIES: [(&str, Generator, bool, bool); 5] = [
    (
        "quarter-exact",
        quarter_square::u4_pairwise_mul_exact,
        true,
        true,
    ),
    ("full-exact", baseline::full_exact, true, true),
    ("quarter-mod", baseline::quarter_mod, true, false),
    ("full-mod-canonical", baseline::full_mod, true, false),
    ("full-mod-numeric", baseline::full_numeric_mod, false, false),
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
        o => panic!("unexpected {o:?}"),
    }
}
fn rejects(r: &ExecuteInfo, e: ExecError) {
    assert_eq!(r.error, Some(e), "{r}");
    assert!(!r.success);
}
fn outputs(v: &[u8], exact: bool) -> Vec<i64> {
    v.chunks_exact(2)
        .map(|p| {
            let x = i64::from(p[0]) * i64::from(p[1]);
            if exact {
                x
            } else {
                x % 16
            }
        })
        .collect()
}
fn leaf(g: Generator, n: u32, e: &[i64]) -> Vec<u8> {
    script! {{g(n)}for &x in e.iter().rev(){{x}OP_EQUALVERIFY}OP_TRUE}
        .compile_with_policy()
        .to_bytes()
}
fn cleanup(g: Generator, n: u32) -> Vec<u8> {
    script! {{g(n)}for _ in 0..n{OP_DROP}OP_TRUE}
        .compile_with_policy()
        .to_bytes()
}
#[test]
fn exhaustive_pairs_and_asymmetric_ordered_batches() {
    for (name, g, _, exact) in FAMILIES {
        // One extra host-oracle item below the operands, not a protocol hint or
        // part of the two-operand metric boundary. The same bytecode checks256 pairs.
        let comparison = script! {{g(1)}OP_EQUAL}.compile_with_policy().to_bytes();
        for a in 0..16 {
            for b in 0..16 {
                let product = a * b;
                let expected = if exact { product } else { product % 16 };
                let r = exec(comparison.clone(), vec![num(expected), num(a), num(b)]);
                assert!(r.success, "{name} {a}*{b}: {r}");
                assert_eq!(r.final_stack.len(), 1);
            }
        }
        let all_pairs: Vec<u8> = (0..16u8)
            .flat_map(|a| (0..16u8).flat_map(move |b| [a, b]))
            .collect();
        let repeated = exec(
            leaf(g, 256, &outputs(&all_pairs, exact)),
            all_pairs.iter().map(|&x| num(x.into())).collect(),
        );
        assert!(
            repeated.success,
            "{name}: all256 pairs sharing one table: {repeated}"
        );
        assert_eq!(repeated.final_stack.len(), 1);
        for n in [2, 8, 32, 128] {
            let v: Vec<_> = (0..2 * n).map(|i| ((7 * i + i / 3) % 16) as u8).collect();
            let r = exec(
                leaf(g, n, &outputs(&v, exact)),
                v.iter().map(|&x| num(x.into())).collect(),
            );
            assert!(r.success, "{name} n={n}: {r}");
        }
    }
    for n in [0, 484] {
        assert!(std::panic::catch_unwind(|| quarter_square::u4_pairwise_mul_exact(n)).is_err());
    }
}
#[test]
fn every_hostile_position_alias_contract_and_short_input() {
    let v = [1u8, 7, 2, 15, 0, 13];
    for (name, g, canonical, exact) in FAMILIES {
        let clean = cleanup(g, 3);
        let valid: Vec<_> = v.iter().map(|&x| num(x.into())).collect();
        assert!(exec(clean.clone(), valid.clone()).success, "{name}");
        for (bad, e) in [
            (num(-1), ExecError::Verify),
            (num(16), ExecError::Verify),
            (num(i32::MAX.into()), ExecError::Verify),
            (vec![0; 5], ExecError::ScriptIntNumericOverflow),
            (vec![0; 521], ExecError::PushSize),
        ] {
            for position in 0..6 {
                let mut w = valid.clone();
                w[position] = bad.clone();
                rejects(&exec(clean.clone(), w), e.clone());
            }
        }
        for (bad, value) in [
            (vec![0], 0),
            (vec![0x80], 0),
            (vec![1, 0], 1),
            (vec![15, 0, 0, 0], 15),
        ] {
            for position in 0..6 {
                let mut w = valid.clone();
                w[position] = bad.clone();
                if canonical {
                    rejects(&exec(clean.clone(), w), ExecError::EqualVerify);
                } else {
                    let mut x = v;
                    x[position] = value;
                    assert!(
                        exec(leaf(g, 3, &outputs(&x, exact)), w).success,
                        "{name} alias {position}"
                    );
                }
            }
        }
        for len in 0..6 {
            rejects(
                &exec(clean.clone(), valid[..len].to_vec()),
                ExecError::InvalidStackOperation,
            );
        }
    }
}
#[test]
fn both_runtime_caller_stacks_survive() {
    let v = [1u8, 7, 2, 15, 13, 14];
    for (name, g, _, exact) in FAMILIES {
        let e = outputs(&v, exact);
        let bytes=script!{OP_TOALTSTACK OP_TOALTSTACK{g(3)}for &x in e.iter().rev(){{x}OP_EQUALVERIFY}
            103 OP_EQUALVERIFY 99 OP_EQUALVERIFY OP_FROMALTSTACK 77 OP_EQUALVERIFY OP_FROMALTSTACK 81 OP_EQUALVERIFY OP_TRUE}.compile_with_policy().to_bytes();
        let w = [99, 103, 1, 7, 2, 15, 13, 14, 77, 81]
            .into_iter()
            .map(num)
            .collect();
        let r = exec(bytes, w);
        assert!(r.success, "{name}: {r}");
        assert_eq!(r.final_stack.len(), 1);
    }
}
#[test]
fn exact_resource_frontiers_keep_all_runtime_outputs_observable() {
    for (name, g, _, exact) in FAMILIES {
        let table = if name.starts_with("quarter") { 31 } else { 256 };
        let maximum = if table == 31 { 483 } else { 370 };
        for n in [1, 32, maximum] {
            let fragment = g(n);
            let peak = 2 * n + table + 3;
            let allowance = 1000 - peak;
            for a in [0, 1, 3] {
                if a > allowance {
                    continue;
                }
                let m = allowance - a;
                let bytes=script!{for _ in 0..a{OP_TOALTSTACK}{fragment.clone()}for _ in 0..a{OP_FROMALTSTACK}}.compile_with_policy().to_bytes();
                let main: Vec<_> = (0..m).map(|i| num(10000 + i as i64)).collect();
                let alt: Vec<_> = (0..a).map(|i| num(20000 + i as i64)).collect();
                let mut w = main.clone();
                w.extend(vec![num(7); (2 * n) as usize]);
                w.extend(alt.clone());
                let r = exec(bytes.clone(), w.clone());
                assert!(r.error.is_none(), "{name} n={n} a={a}: {r}");
                assert_eq!(r.stats.max_nb_stack_items, 1000);
                let mut e = main;
                e.extend(vec![num(if exact { 49 } else { 1 }); n as usize]);
                e.extend(alt);
                assert_eq!(r.final_stack.len(), e.len());
                for (i, x) in e.iter().enumerate() {
                    assert_eq!(&r.final_stack.get(i), x, "{name} index={i}");
                }
                w.insert(0, num(9999));
                rejects(&exec(bytes, w), ExecError::StackSize);
            }
        }
    }
}
#[test]
fn deliberate_compiled_validation_mutations_fail_the_same_typed_assertion() {
    for (name, g, canonical, _) in FAMILIES {
        // Caller zero ensures a bad a=16,b=0 row index256 has an executable
        // target below the full table even at the final pair. This prevents
        // an accidental OP_PICK failure from hiding removed range validation.
        let original = script! {{g(3)}for _ in 0..3{OP_DROP}OP_DROP OP_TRUE}
            .compile_with_policy()
            .to_bytes();
        let valid = vec![num(0); 7];
        assert!(exec(original.clone(), valid.clone()).success);
        let mut variants = vec![];
        if canonical {
            variants.push((
                vec![script! {OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY}],
                vec![1, 0],
                ExecError::EqualVerify,
            ));
        }
        let ranges = if name.starts_with("full-mod") {
            vec![
                script! {OP_DUP 0 16 OP_WITHIN OP_VERIFY},
                script! {1 OP_PICK 0 16 OP_WITHIN OP_VERIFY},
            ]
        } else {
            vec![script! {OP_DUP 0 16 OP_WITHIN OP_VERIFY}]
        };
        variants.push((ranges, num(16), ExecError::Verify));
        for (patterns, bad, error) in variants {
            let mut modified = original.clone();
            let mut hits = 0;
            for pattern in patterns {
                let pattern = pattern.compile_with_policy().to_bytes();
                while let Some(i) = modified.windows(pattern.len()).position(|w| w == pattern) {
                    modified.drain(i..i + pattern.len());
                    hits += 1;
                }
            }
            assert_eq!(hits, 6, "{name}: every operand validation must be mutated");
            assert!(exec(modified.clone(), valid.clone()).success);
            for position in 1..7 {
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
fn artifact_report_and_catalog_bind_the_exact_cost_boundary() {
    use bitcoin::{
        consensus::encode::serialize,
        hashes::{sha256, Hash},
        script::Instruction,
        Witness,
    };
    use bitcoin_lab::support::{execution::execute_raw_script_with_inputs_strict, provenance};
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("research/u4-quarter-square/metrics.json")).unwrap(),
    )
    .unwrap();
    let catalog: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("knowledge/catalog.json")).unwrap(),
    )
    .unwrap();
    let catalog_record = catalog["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "arithmetic/u4-exact-product")
        .unwrap();
    assert_eq!(
        report["compiler_source"],
        provenance::compiler().unwrap().source
    );
    assert_eq!(
        report["interpreter_source"],
        provenance::interpreter().unwrap().source
    );
    assert_eq!(report["options"],"ExecCtx::Tapscript; Options::default with enforce_stack_limit=true; synthetic empty transaction; data-only budget; no signatures");
    assert_eq!(report["compilation"],"compile_with_policy: every measured fragment and leaf below 32KiB raw cutoff, CompileOptions::ALL");
    assert_eq!(
        report["witness_generator"],
        "2*n canonical sevens, all operands present at entry, zero hints"
    );
    assert_eq!(report["terminal_predicate"],"compare n outputs in reverse using OP_EQUALVERIFY against49 for exact,1 for modulo, then OP_TRUE");
    assert_eq!(report["evidence"], "locally-reproduced");
    assert_eq!(report["execution"], "unclassified");
    let mut measured = std::collections::BTreeSet::new();
    for row in report["records"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let n = row["pair_count"].as_u64().unwrap() as u32;
        let (_, g, canonical, exact) = FAMILIES.iter().copied().find(|f| f.0 == name).unwrap();
        assert!(canonical);
        assert!(measured.insert((name, n)));
        let fragment = g(n);
        let compiled = fragment.clone().compile_with_policy();
        let expected = if exact { 49 } else { 1 };
        let complete = script! {{fragment}for _ in 0..n{{expected}OP_EQUALVERIFY}OP_TRUE}
            .compile_with_policy();
        let data = vec![num(7); (2 * n) as usize];
        let serialized = serialize(&Witness::from_slice(&data));
        assert_eq!(row["exact"], exact);
        assert_eq!(
            row["table_items"],
            if name.starts_with("quarter") { 31 } else { 256 }
        );
        assert_eq!(row["data_items"], 2 * n);
        assert_eq!(row["hint_items"], 0);
        assert_eq!(row["witness_bytes"], serialized.len());
        assert_eq!(row["fragment_bytes"], compiled.len());
        assert_eq!(row["leaf_bytes"], complete.len());
        assert_eq!(
            row["fragment_sha256"],
            sha256::Hash::hash(compiled.as_bytes()).to_string()
        );
        assert_eq!(
            row["leaf_sha256"],
            sha256::Hash::hash(complete.as_bytes()).to_string()
        );
        assert_eq!(
            row["witness_sha256"],
            sha256::Hash::hash(&serialized).to_string()
        );
        let count = compiled
            .instructions()
            .filter(|i| matches!(i,Ok(Instruction::Op(op))if op.to_u8()>0x60))
            .count();
        assert_eq!(row["static_non_push_opcodes"], count);
        let r = execute_raw_script_with_inputs_strict(complete.to_bytes(), data);
        assert!(r.success, "{name} n={n}: {r}");
        assert_eq!(r.final_stack.len(), 1);
        assert_eq!(row["combined_peak"], r.stats.max_nb_stack_items);
        assert!(row["executed_opcodes"].is_null());
        assert!(row["validation_weight"].is_null());
        if name == "quarter-exact" {
            for c in catalog_record["configurations"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|c| c["parameters"]["pair_count"] == n)
            {
                let leaf = c["includes"]
                    .as_str()
                    .unwrap()
                    .starts_with("complete-leaf:");
                assert_eq!(
                    c["script_bytes"],
                    row[if leaf { "leaf_bytes" } else { "fragment_bytes" }]
                );
                assert_eq!(c["max_stack_items"], row["combined_peak"]);
                assert_eq!(c["witness_bytes"], row["witness_bytes"]);
                assert_eq!(c["witness_bytes_max"], row["witness_bytes"]);
                assert_eq!(
                    c["static_non_push_opcodes"],
                    count + if leaf { n as usize } else { 0 }
                );
                assert_eq!(
                    c["parameters"]["static_non_push_opcodes"],
                    c["static_non_push_opcodes"]
                );
                for key in ["fragment_sha256", "leaf_sha256", "witness_sha256"] {
                    assert_eq!(c["parameters"][key], row[key]);
                }
                assert_eq!(
                    c["parameters"]["compiler_source"],
                    report["compiler_source"]
                );
                assert_eq!(
                    c["parameters"]["interpreter_source"],
                    report["interpreter_source"]
                );
                assert_eq!(c["parameters"]["data_items"], 2 * n);
                assert_eq!(c["parameters"]["hint_items"], 0);
                assert!(c["executed_opcodes"].is_null());
                assert!(c["validation_weight"].is_null());
            }
        }
    }
    let mut expected = std::collections::BTreeSet::new();
    for name in [
        "quarter-exact",
        "full-exact",
        "quarter-mod",
        "full-mod-canonical",
    ] {
        for n in [1, 2, 8, 32, 128, 370, 483] {
            if n == 483 && !name.starts_with("quarter") {
                continue;
            }
            expected.insert((name, n));
        }
    }
    assert_eq!(measured, expected);
    assert_eq!(
        catalog_record["configurations"].as_array().unwrap().len(),
        8
    );
}

#[test]
fn product_terminal_binding_detects_wrong_input_and_removed_predicates() {
    for (name, g, _, exact) in FAMILIES {
        let v = [3u8, 5, 13, 14, 15, 15];
        let e = outputs(&v, exact);
        let bytes = leaf(g, 3, &e);
        let mut w: Vec<_> = v.iter().map(|&x| num(x.into())).collect();
        assert!(exec(bytes.clone(), w.clone()).success, "{name} control");
        w[0] = num(2);
        rejects(&exec(bytes, w.clone()), ExecError::EqualVerify);
        let r = exec(cleanup(g, 3), w);
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
