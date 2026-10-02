//! Shared contracts for residual/threshold roots and canonical-input wrappers.
use bitcoin::{
    hashes::{sha256, Hash},
    ScriptBuf,
};
use bitcoin_lab::{
    arithmetic::{integer_root::scriptnum_isqrt, scriptint::verify_canonical},
    support::{
        execution::ExecuteInfo,
        script::*,
        tapscript::{
            execute_tapscript, TapscriptOutcome, TapscriptPolicyRejection, TapscriptProfile,
        },
    },
};
use bitcoin_scriptexec::ExecError;
#[path = "../research/integer-root-bounds/measure.rs"]
mod measure;
use measure::{baseline, num, run};
#[derive(Clone, Copy)]
struct Family {
    name: &'static str,
    g: fn(u32) -> Script,
    canonical: bool,
}
const FAMILIES: [Family; 4] = [
    Family {
        name: "restoring",
        g: scriptnum_isqrt,
        canonical: false,
    },
    Family {
        name: "thresholds",
        g: baseline::thresholds,
        canonical: false,
    },
    Family {
        name: "restoring-canonical",
        g: measure::restoring_canonical,
        canonical: true,
    },
    Family {
        name: "thresholds-canonical",
        g: measure::thresholds_canonical,
        canonical: true,
    },
];
fn output(r: &ExecuteInfo, q: u32) {
    assert!(r.stack_limit_enforced);
    assert_eq!(r.error, None, "{r}");
    assert_eq!(r.final_stack.len(), 1);
    assert_eq!(r.final_stack.get(0), num(q.into()));
}
fn clean(r: &ExecuteInfo) {
    output(r, 1);
    assert!(r.success, "{r}")
}
fn rejects(r: &ExecuteInfo, e: ExecError) {
    assert!(r.stack_limit_enforced);
    assert_eq!(r.error, Some(e), "{r}");
    assert!(!r.success)
}
fn caught(r: &ExecuteInfo, e: ExecError) {
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rejects(r, e))).is_err())
}
fn leaf(f: Family, b: u32, q: u32) -> ScriptBuf {
    script! {{(f.g)(b)}{num(q.into())}OP_EQUALVERIFY OP_TRUE}.compile_with_policy()
}
fn groups(f: Family, b: u32, n: u32) -> Script {
    script! {for _ in 0..n{{(f.g)(b)}OP_TOALTSTACK}for _ in 0..n{OP_FROMALTSTACK}}
}
fn replace_all(b: &mut Vec<u8>, pat: &[u8], repl: &[u8]) -> usize {
    let mut at = 0;
    let mut n = 0;
    while let Some(p) = b[at..].windows(pat.len()).position(|w| w == pat) {
        let i = at + p;
        b.splice(i..i + pat.len(), repl.iter().copied());
        at = i + repl.len();
        n += 1
    }
    n
}
#[test]
fn original_bytes_exhaustive_domains_and_constructor_boundaries() {
    for b in 1..=31 {
        assert_eq!(
            scriptnum_isqrt(b).compile_with_policy(),
            baseline::restoring(b).compile_with_policy()
        );
    }
    for f in FAMILIES {
        for b in [0, 32, u32::MAX] {
            assert!(
                std::panic::catch_unwind(|| (f.g)(b)).is_err(),
                "{} bits{b}",
                f.name
            )
        }
        let s = (f.g)(16).compile_with_policy();
        for x in 0..65536 {
            output(&run(s.clone(), vec![num(x.into())]), baseline::host_root(x));
        }
        for b in [1, 2, 3, 4, 6, 8, 16, 24, 31] {
            let s = (f.g)(b).compile_with_policy();
            for x in [0, 1, baseline::max(b) / 2, baseline::max(b)] {
                output(&run(s.clone(), vec![num(x.into())]), baseline::host_root(x));
            }
        }
    }
}
#[test]
fn every31bit_square_endpoint_and_numeric_intermediate_bounds() {
    let s = scriptnum_isqrt(31).compile_with_policy();
    let mut cases = std::collections::BTreeSet::new();
    for q in 0..=46340u32 {
        let sq = q * q;
        cases.insert(sq);
        if sq > 0 {
            cases.insert(sq - 1);
        }
        cases.insert(((u64::from(q) + 1).pow(2) - 1).min(2147483647) as u32);
    }
    assert_eq!(cases.len(), 92681);
    for x in cases {
        let q = baseline::host_root(x);
        assert!(u64::from(q).pow(2) <= u64::from(x));
        assert!(u64::from(x) < (u64::from(q) + 1).pow(2));
        output(&run(s.clone(), vec![num(x.into())]), q);
    }
    for k in 1..=16 {
        for j in 0..k {
            let b = 1u64 << j;
            let r = (1u64 << k) - 2 * b;
            let delta = 2 * r * b + b * b;
            assert!(delta <= 1342177280);
            assert!(2 * r * b <= delta);
            assert!(delta <= 2147483647);
        }
    }
    // Deterministic interiors, independent from the private creative seed.
    let mut state = 0x51427eu32;
    for b in 1..=31 {
        let s = scriptnum_isqrt(b).compile_with_policy();
        for _ in 0..128 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let x = state & baseline::max(b);
            output(&run(s.clone(), vec![num(x.into())]), baseline::host_root(x));
        }
    }
}
#[test]
fn malformed_aliases_and_short_inputs_cover_each_live_position() {
    for f in FAMILIES {
        for b in [1, 2, 8, 16, 31] {
            let s = leaf(f, b, 1);
            clean(&run(s.clone(), vec![num(1)]));
            for x in [-1, -2147483647, i64::from(baseline::max(b)) + 1] {
                rejects(
                    &run(s.clone(), vec![num(x)]),
                    if x > 2147483647 {
                        ExecError::ScriptIntNumericOverflow
                    } else {
                        ExecError::Verify
                    },
                );
            }
            for size in [5, 80, 81, 520, 521] {
                rejects(
                    &run(s.clone(), vec![vec![0; size]]),
                    if size == 521 {
                        ExecError::PushSize
                    } else {
                        ExecError::ScriptIntNumericOverflow
                    },
                );
            }
            rejects(&run(s.clone(), vec![]), ExecError::InvalidStackOperation);
            for (alias, x) in [
                (vec![0], 0),
                (vec![0x80], 0),
                (vec![1, 0], 1),
                (vec![1, 0, 0, 0], 1),
            ] {
                let l = leaf(f, b, x);
                if f.canonical {
                    rejects(&run(l, vec![alias]), ExecError::EqualVerify)
                } else {
                    clean(&run(l, vec![alias]))
                }
            }
        }
        let e = vec![num(0); 4];
        let l = measure::bound_outputs(groups(f, 16, 4), &e).compile_with_policy();
        let control = vec![num(0); 4];
        clean(&run(l.clone(), control.clone()));
        for p in 0..4 {
            for bad in [num(-1), num(65536), vec![0; 5], vec![0; 520], vec![0; 521]] {
                let err = if bad.len() == 521 {
                    ExecError::PushSize
                } else if bad.len() > 4 {
                    ExecError::ScriptIntNumericOverflow
                } else {
                    ExecError::Verify
                };
                let mut w = control.clone();
                w[p] = bad;
                rejects(&run(l.clone(), w), err);
            }
            let mut e = vec![num(0); 4];
            e[p] = num(1);
            let l = measure::bound_outputs(groups(f, 16, 4), &e).compile_with_policy();
            let mut w = control.clone();
            w[p] = num(1);
            clean(&run(l.clone(), w.clone()));
            w[p] = vec![1, 0];
            if f.canonical {
                rejects(&run(l, w), ExecError::EqualVerify)
            } else {
                clean(&run(l, w))
            }
        }
        for len in 0..4 {
            rejects(
                &run(l.clone(), control[..len].to_vec()),
                ExecError::InvalidStackOperation,
            );
        }
    }
    let (f, w, e) = measure::independent_roots(31, 32);
    let l = measure::bound_outputs(f, &e).compile_with_policy();
    clean(&run(l.clone(), w.clone()));
    for p in 0..32 {
        let mut bad = w.clone();
        bad[p] = num(-1);
        rejects(&run(l.clone(), bad), ExecError::Verify);
        let mut bad = w.clone();
        bad[p] = vec![0; 5];
        rejects(&run(l.clone(), bad), ExecError::ScriptIntNumericOverflow);
    }
    let zero = vec![num(0); 32];
    let e = zero.clone();
    let l = measure::bound_outputs(groups(FAMILIES[0], 31, 32), &e).compile_with_policy();
    clean(&run(l.clone(), zero.clone()));
    for len in 0..32 {
        rejects(
            &run(l.clone(), zero[..len].to_vec()),
            ExecError::InvalidStackOperation,
        );
    }
}
#[test]
fn compiled_guards_and_canonical_wrappers_fail_the_same_typed_assertion() {
    for f in FAMILIES {
        let n = 4;
        let e = vec![num(255); n];
        let original = measure::bound_outputs(groups(f, 16, n as u32), &e).compile_with_policy();
        let mut bytes = original.to_bytes();
        let pat = baseline::guard(16).compile_with_policy().to_bytes();
        assert_eq!(replace_all(&mut bytes, &pat, &[]), n);
        let mutant = ScriptBuf::from_bytes(bytes);
        let valid = vec![num(65535); n];
        clean(&run(original.clone(), valid.clone()));
        clean(&run(mutant.clone(), valid.clone()));
        for p in 0..n {
            let mut w = valid.clone();
            w[p] = num(65536);
            rejects(&run(original.clone(), w.clone()), ExecError::Verify);
            let r = run(mutant.clone(), w);
            clean(&r);
            caught(&r, ExecError::Verify);
        }
        if f.canonical {
            let e = vec![num(1); n];
            let original =
                measure::bound_outputs(groups(f, 16, n as u32), &e).compile_with_policy();
            let mut bytes = original.to_bytes();
            let pat = verify_canonical().compile_with_policy().to_bytes();
            assert_eq!(replace_all(&mut bytes, &pat, &[]), n);
            let mutant = ScriptBuf::from_bytes(bytes);
            let valid = vec![num(1); n];
            clean(&run(original.clone(), valid.clone()));
            clean(&run(mutant.clone(), valid.clone()));
            for p in 0..n {
                let mut w = valid.clone();
                w[p] = vec![1, 0];
                rejects(&run(original.clone(), w.clone()), ExecError::EqualVerify);
                let r = run(mutant.clone(), w);
                clean(&r);
                caught(&r, ExecError::EqualVerify);
            }
        }
    }
    let n = 32;
    let e = vec![num(255); n];
    let original =
        measure::bound_outputs(groups(FAMILIES[0], 16, n as u32), &e).compile_with_policy();
    let mut bytes = original.to_bytes();
    let pat = baseline::guard(16).compile_with_policy().to_bytes();
    assert_eq!(replace_all(&mut bytes, &pat, &[]), n);
    let mutant = ScriptBuf::from_bytes(bytes);
    let valid = vec![num(65535); n];
    clean(&run(original.clone(), valid.clone()));
    clean(&run(mutant.clone(), valid.clone()));
    for p in 0..n {
        let mut w = valid.clone();
        w[p] = num(65536);
        rejects(&run(original.clone(), w.clone()), ExecError::Verify);
        let r = run(mutant.clone(), w);
        clean(&r);
        caught(&r, ExecError::Verify);
    }
}
#[test]
fn every_caller_item_is_preserved_at_each_exact_frontier() {
    for f in FAMILIES {
        for b in [1, 2, 8, 16, 31] {
            for x in [0, baseline::max(b)] {
                let s = (f.g)(b).compile_with_policy();
                let p = run(s, vec![num(x.into())]).stats.max_nb_stack_items;
                for a in [0, 3] {
                    let count = 1000 - p;
                    let main: Vec<_> = (0..count - a).map(|i| vec![0x92, i as u8]).collect();
                    let alt: Vec<_> = (0..a).map(|i| vec![0x83, i as u8]).collect();
                    let mut w = main.clone();
                    w.extend(alt.clone());
                    w.push(num(x.into()));
                    let s=script!{for _ in 0..a{OP_SWAP OP_TOALTSTACK}{(f.g)(b)}for _ in 0..a{OP_FROMALTSTACK}}.compile_with_policy();
                    let r = run(s.clone(), w.clone());
                    assert_eq!(r.error, None, "{} b{b} x{x}: {r}", f.name);
                    assert_eq!(r.stats.max_nb_stack_items, 1000);
                    let mut e = main;
                    e.push(num(baseline::host_root(x).into()));
                    e.extend(alt);
                    assert_eq!(r.final_stack.len(), e.len());
                    for (i, x) in e.iter().enumerate() {
                        assert_eq!(&r.final_stack.get(i), x)
                    }
                    w.insert(0, vec![0x92]);
                    rejects(&run(s, w), ExecError::StackSize);
                }
            }
        }
    }
}
#[test]
fn root_trial_terminal_and_preloaded_order_regressions_remain_observable() {
    for f in FAMILIES {
        let original = leaf(f, 16, 12);
        let pat = script! {12 OP_EQUALVERIFY}.compile_with_policy().to_bytes();
        let mut bytes = original.to_bytes();
        assert_eq!(replace_all(&mut bytes, &pat, &[0x75]), 1);
        let mutant = ScriptBuf::from_bytes(bytes);
        clean(&run(original.clone(), vec![num(144)]));
        clean(&run(mutant.clone(), vec![num(144)]));
        rejects(&run(original, vec![num(169)]), ExecError::EqualVerify);
        let r = run(mutant, vec![num(169)]);
        clean(&r);
        caught(&r, ExecError::EqualVerify);
        let original =
            measure::bound_outputs(groups(f, 16, 2), &[num(12), num(13)]).compile_with_policy();
        clean(&run(original, vec![num(144), num(169)]));
        let mutant = measure::bound_outputs(script! {OP_SWAP{groups(f,16,2)}}, &[num(12), num(13)])
            .compile_with_policy();
        let r = run(mutant, vec![num(144), num(169)]);
        rejects(&r, ExecError::EqualVerify);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| clean(&r))).is_err());
        let same = measure::bound_outputs(script! {OP_SWAP{groups(f,16,2)}}, &[num(12), num(12)])
            .compile_with_policy();
        clean(&run(same, vec![num(144), num(144)]));
    }
    let original = leaf(FAMILIES[0], 16, 1);
    let pat = script! {2 OP_PICK OP_OVER OP_GREATERTHANOREQUAL OP_IF}
        .compile_with_policy()
        .to_bytes();
    let repl = script! {2 OP_PICK OP_OVER OP_GREATERTHAN OP_IF}
        .compile_with_policy()
        .to_bytes();
    let mut bytes = original.to_bytes();
    assert_eq!(replace_all(&mut bytes, &pat, &repl), 8);
    let mutant = ScriptBuf::from_bytes(bytes);
    clean(&run(original.clone(), vec![num(2)]));
    clean(&run(mutant.clone(), vec![num(2)]));
    clean(&run(original, vec![num(1)]));
    let r = run(mutant, vec![num(1)]);
    rejects(&r, ExecError::EqualVerify);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| clean(&r))).is_err());
}
#[test]
fn preloaded_roots_bind_all_outputs_and_all_live_inputs() {
    for n in [2, 3, 32, 53, 54, 996] {
        let (f, w, e) = measure::independent_roots(31, n);
        let l = measure::bound_outputs(f.clone(), &e).compile_with_policy();
        let r = run(l.clone(), w.clone());
        clean(&r);
        assert_eq!(r.stats.max_nb_stack_items, n as usize + 4);
        let wide: Vec<_> = w
            .iter()
            .map(|x| {
                let mut x = x.clone();
                x.resize(4, 0);
                x
            })
            .collect();
        clean(&run(l, wide));
        let allowance = 1000 - (n as usize + 4);
        for a in [0, 3] {
            if a > allowance {
                continue;
            }
            let main: Vec<_> = (0..allowance - a).map(|i| vec![0x92, i as u8]).collect();
            let alt: Vec<_> = (0..a).map(|i| vec![0x83, i as u8]).collect();
            let mut all = main.clone();
            all.extend(alt.clone());
            all.extend(w.clone());
            let s=script!{for _ in 0..a{{n}OP_ROLL OP_TOALTSTACK}{f.clone()}for _ in 0..a{OP_FROMALTSTACK}}.compile_with_policy();
            let r = run(s.clone(), all.clone());
            assert_eq!(r.error, None);
            assert_eq!(r.stats.max_nb_stack_items, 1000);
            let mut expected = main;
            expected.extend(e.clone());
            expected.extend(alt);
            assert_eq!(r.final_stack.len(), expected.len());
            for (i, x) in expected.iter().enumerate() {
                assert_eq!(&r.final_stack.get(i), x)
            }
            all.insert(0, vec![0x92]);
            rejects(&run(s, all), ExecError::StackSize);
        }
    }
    let (f, w, e) = measure::independent_roots(31, 997);
    let r = run(measure::bound_outputs(f, &e).compile_with_policy(), w);
    rejects(&r, ExecError::StackSize);
    assert_eq!(r.stats.max_nb_stack_items, 1001);
}
#[test]
fn numeric_policy_and_entry_item_precedence_stay_separate() {
    for f in FAMILIES {
        let s = leaf(f, 16, 1);
        let r = execute_tapscript(s.clone(), vec![num(1)], TapscriptProfile::Policy);
        clean(r.execution().unwrap());
        for b in [vec![1, 0], vec![1, 0, 0, 0]] {
            let r = execute_tapscript(s.clone(), vec![b], TapscriptProfile::Policy);
            rejects(r.execution().unwrap(), ExecError::MinimalData);
        }
        for size in [81, 520, 521] {
            let r = execute_tapscript(s.clone(), vec![vec![0; size]], TapscriptProfile::Policy);
            assert!(
                matches!(r.outcome,TapscriptOutcome::PolicyRejected(TapscriptPolicyRejection::WitnessStackItemSize{index:0,size:n})if n==size)
            );
            rejects(
                &run(s.clone(), vec![vec![0; size]]),
                if size == 521 {
                    ExecError::PushSize
                } else {
                    ExecError::ScriptIntNumericOverflow
                },
            );
        }
    }
}
#[test]
fn report_catalog_and_immutable_sources_bind_every_artifact() {
    let r: serde_json::Value =
        serde_json::from_str(include_str!("../research/integer-root-bounds/metrics.json")).unwrap();
    let rev = r["source_revision"].as_str().unwrap();
    assert_eq!(rev.len(), 40);
    assert!(rev.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(rev, "0000000000000000000000000000000000000000");
    assert_eq!(measure::report(rev), r);
    let root = env!("CARGO_MANIFEST_DIR");
    let commit = std::process::Command::new("git")
        .args(["cat-file", "-e", rev])
        .current_dir(root)
        .output()
        .unwrap();
    if commit.status.success() {
        for (p, h) in r["source_sha256"].as_object().unwrap() {
            let b = std::process::Command::new("git")
                .args(["show", &format!("{rev}:{p}")])
                .current_dir(root)
                .output()
                .unwrap();
            assert!(b.status.success());
            assert_eq!(
                sha256::Hash::hash(&b.stdout).to_string(),
                h.as_str().unwrap()
            );
        }
    } else {
        let s = std::process::Command::new("git")
            .args(["rev-parse", "--is-shallow-repository"])
            .current_dir(root)
            .output()
            .unwrap();
        assert!(s.status.success());
        assert_eq!(s.stdout, b"true\n");
    }
    let catalog: serde_json::Value =
        serde_json::from_str(include_str!("../knowledge/catalog.json")).unwrap();
    let record = catalog["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "arithmetic/scriptnum-isqrt")
        .unwrap();
    assert_eq!(record["evidence"], "locally-reproduced");
    assert_eq!(record["execution"], "unclassified");
    assert_eq!(record["configurations"].as_array().unwrap().len(), 17);
    for f in FAMILIES {
        let a = r["family_contracts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["algorithm"] == f.name)
            .unwrap();
        assert_eq!(a["canonical_input"], f.canonical);
        assert_eq!(
            a["fragment"]["sha256"],
            measure::sha((f.g)(16).compile_with_policy().as_bytes())
        );
        assert_eq!(a["data_items"], 1);
        assert_eq!(a["hint_items"], 0);
        assert_eq!(a["hint_bytes"], 0);
        assert_eq!(
            a["alias_control_artifact"]["error"],
            if f.canonical {
                serde_json::json!("EqualVerify")
            } else {
                serde_json::Value::Null
            }
        );
    }
    for c in record["configurations"].as_array().unwrap() {
        let p = &c["parameters"];
        let row = if let Some(id) = p["composition_id"].as_str() {
            r["compositions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|x| x["id"] == id)
                .unwrap()
        } else {
            r["rows"]
                .as_array()
                .unwrap()
                .iter()
                .find(|x| {
                    x["algorithm"] == "restoring"
                        && x["bit_count"] == p["bit_count"]
                        && x["input_pattern"] == p["input_pattern"]
                        && x["encoding"] == p["encoding"]
                })
                .unwrap()
        };
        let a = &row[p["boundary"].as_str().unwrap()];
        for k in ["script_bytes", "max_stack_items", "static_non_push_opcodes"] {
            assert_eq!(c[k], a[k]);
        }
        for k in ["sha256", "raw_bytes", "compile_options"] {
            assert_eq!(p[k], a[k]);
        }
        for k in ["source_revision", "compiler_source", "interpreter_source"] {
            assert_eq!(p[k], r[k]);
        }
        for k in ["data_items", "hint_items", "witness_sha256"] {
            assert_eq!(p[k], row[k]);
        }
        assert_eq!(c["witness_bytes"], row["witness_bytes"]);
        let n = row["data_items"].as_u64().unwrap();
        assert_eq!(
            c["witness_bytes_max"].as_u64().unwrap(),
            5 * n + if n < 253 { 1 } else { 3 }
        );
        assert!(c["executed_opcodes"].is_null());
        assert!(c["validation_weight"].is_null());
        assert_eq!(c["evidence"], "locally-reproduced");
        assert_eq!(c["execution"], "unclassified");
    }
    for x in r["rows"].as_array().unwrap() {
        assert_eq!(x["data_items"], 1);
        assert_eq!(x["hint_items"], 0);
        assert_eq!(x["hint_bytes"], 0);
        assert_eq!(x["fragment"]["output_sha256"], x["expected_output_sha256"]);
        assert_eq!(x["leaf"]["clean_success"], true);
        for k in ["fragment", "leaf"] {
            let a = &x[k];
            assert!(a["error"].is_null());
            assert_eq!(
                a["compile_options"],
                if a["raw_bytes"].as_u64().unwrap() <= 32768 {
                    "ALL"
                } else {
                    "NONE"
                }
            );
            assert_eq!(a["validation_weight_charged"], 0);
        }
        if x["encoding"] == "four-byte-alias" {
            assert_eq!(x["leaf"]["local_policy"]["error"], "MinimalData");
        } else {
            assert_eq!(x["leaf"]["local_policy"]["clean_success"], true);
        }
    }
    for x in r["compositions"].as_array().unwrap() {
        assert_eq!(x["data_items"], x["repeat_count"]);
        assert_eq!(x["hint_items"], 0);
        assert_eq!(x["hint_bytes"], 0);
        assert_eq!(
            x["fragment"]["script_bytes"].as_i64().unwrap(),
            x["component_bytes_sum"].as_i64().unwrap() + x["whole_policy_delta"].as_i64().unwrap()
        );
        for k in ["fragment", "leaf"] {
            let a = &x[k];
            assert_eq!(
                a["compile_options"],
                if a["raw_bytes"].as_u64().unwrap() <= 32768 {
                    "ALL"
                } else {
                    "NONE"
                }
            );
            if x["repeat_count"].as_u64().unwrap() <= 996 {
                assert!(a["error"].is_null());
                assert_eq!(
                    a["max_stack_items"].as_u64().unwrap(),
                    x["repeat_count"].as_u64().unwrap() + 4
                );
            } else {
                assert_eq!(a["error"], "StackSize");
                assert_eq!(a["max_stack_items"], 1001);
            }
        }
    }
}
