//! Shared numeric-checksum contracts, preserving each sibling's own domain.
use bitcoin::{
    hashes::{sha256, Hash},
    ScriptBuf,
};
use bitcoin_lab::{
    arithmetic::u4::{
        damm::{u4_decimal_digits_to_damm, DAMM_MAX_DIGITS},
        sum::{
            u4_nibbles_sum_exact, u4_nibbles_to_sum_mod16, U4_EXACT_SUM_MAX_BATCH, U4_SUM_MAX_BATCH,
        },
    },
    support::{
        execution::ExecuteInfo,
        script::*,
        tapscript::{
            execute_tapscript, TapscriptOutcome, TapscriptPolicyRejection, TapscriptProfile,
        },
    },
};
use bitcoin_scriptexec::ExecError;
#[path = "../research/damm-finite-state/measure.rs"]
mod measure;
use measure::{baseline, expected, num, run};
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Damm,
    Mod16,
    Exact,
}
#[derive(Clone, Copy)]
struct Family {
    name: &'static str,
    g: fn(u32) -> Script,
    kind: Kind,
    cap: u32,
    canonical: bool,
}
const FAMILIES: [Family; 6] = [
    Family {
        name: "resident",
        g: u4_decimal_digits_to_damm,
        kind: Kind::Damm,
        cap: DAMM_MAX_DIGITS,
        canonical: false,
    },
    Family {
        name: "warmup",
        g: baseline::warmup,
        kind: Kind::Damm,
        cap: 897,
        canonical: false,
    },
    Family {
        name: "row-table",
        g: baseline::row_table,
        kind: Kind::Damm,
        cap: 990,
        canonical: false,
    },
    Family {
        name: "dispatch",
        g: baseline::dispatch,
        kind: Kind::Damm,
        cap: 997,
        canonical: false,
    },
    Family {
        name: "mod16-canonical",
        g: u4_nibbles_to_sum_mod16,
        kind: Kind::Mod16,
        cap: U4_SUM_MAX_BATCH,
        canonical: true,
    },
    Family {
        name: "exact-numeric",
        g: u4_nibbles_sum_exact,
        kind: Kind::Exact,
        cap: U4_EXACT_SUM_MAX_BATCH,
        canonical: false,
    },
];
fn upper(f: Family) -> u8 {
    if f.kind == Kind::Damm {
        10
    } else {
        16
    }
}
fn value(f: Family, d: &[u8]) -> u32 {
    match f.kind {
        Kind::Damm => expected(d).into(),
        Kind::Mod16 => d.iter().map(|&x| u32::from(x)).sum::<u32>() % 16,
        Kind::Exact => d.iter().map(|&x| u32::from(x)).sum(),
    }
}
fn leaf(f: Family, d: &[u8]) -> ScriptBuf {
    script! {{(f.g)(d.len()as u32)}{num(value(f,d).into())}OP_EQUALVERIFY OP_TRUE}
        .compile_with_policy()
}
fn witness(d: &[u8]) -> Vec<Vec<u8>> {
    d.iter().map(|&x| num(x.into())).collect()
}
fn clean(r: &ExecuteInfo) {
    assert!(r.stack_limit_enforced);
    assert_eq!(r.error, None, "{r}");
    assert!(r.success, "{r}");
    assert_eq!(r.final_stack.len(), 1);
    assert_eq!(r.final_stack.get(0), vec![1]);
}
fn rejects(r: &ExecuteInfo, e: ExecError) {
    assert!(r.stack_limit_enforced);
    assert_eq!(r.error, Some(e), "{r}");
    assert!(!r.success);
}
fn caught(r: &ExecuteInfo, e: ExecError) {
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rejects(r, e))).is_err());
}
fn cleanup(f: Family, n: u32) -> ScriptBuf {
    script! {{(f.g)(n)}OP_DROP OP_TRUE}.compile_with_policy()
}
#[test]
fn all_short_vectors_long_asymmetric_paths_and_constructor_contracts() {
    for f in FAMILIES {
        for n in if f.kind == Kind::Damm { 0..=3 } else { 1..=3 } {
            let out_max = match f.kind {
                Kind::Damm => 9,
                Kind::Mod16 => 15,
                Kind::Exact => 15 * n,
            };
            let leaves: Vec<_> = (0..=out_max)
                .map(|out| {
                    script! {{(f.g)(n)}{num(out.into())}OP_EQUALVERIFY OP_TRUE}
                        .compile_with_policy()
                })
                .collect();
            for v in 0..10u32.pow(n) {
                let d: Vec<_> = (0..n)
                    .map(|i| ((v / 10u32.pow(n - i - 1)) % 10) as u8)
                    .collect();
                clean(&run(leaves[value(f, &d) as usize].clone(), witness(&d)));
            }
        }
        for n in [1, 4, 32, 128, f.cap] {
            for mode in 0..3 {
                let d: Vec<_> = (0..n)
                    .map(|i| match mode {
                        0 => ((7 * i + 3) % u32::from(upper(f))) as u8,
                        1 => 0,
                        _ => upper(f) - 1,
                    })
                    .collect();
                clean(&run(leaf(f, &d), witness(&d)));
            }
        }
        for d in 0..upper(f) {
            clean(&run(leaf(f, &[d]), witness(&[d])));
        }
        if f.kind != Kind::Damm {
            assert!(std::panic::catch_unwind(|| (f.g)(0)).is_err());
        }
    }
    for n in [DAMM_MAX_DIGITS + 1, u32::MAX] {
        assert!(std::panic::catch_unwind(|| u4_decimal_digits_to_damm(n)).is_err());
    }
    // The promoted schedule must retain the reproduced original serialization.
    for n in [0, 1, 2, 32, 128, 896] {
        assert_eq!(
            u4_decimal_digits_to_damm(n).compile_with_policy(),
            baseline::resident_unbounded(n).compile_with_policy()
        );
    }
}
#[test]
fn typed_malformed_digits_aliases_and_short_witnesses_at_every_position() {
    for f in FAMILIES {
        let s = cleanup(f, 4);
        let w = vec![num(0); 4];
        clean(&run(s.clone(), w.clone()));
        for pos in 0..4 {
            for bad in [
                num(-1),
                num(-129),
                num(upper(f).into()),
                num(i32::MAX.into()),
            ] {
                let mut x = w.clone();
                x[pos] = bad;
                rejects(&run(s.clone(), x), ExecError::Verify);
            }
            for size in [5, 80, 81, 520, 521] {
                let mut x = w.clone();
                x[pos] = vec![0; size];
                rejects(
                    &run(s.clone(), x),
                    if size == 521 {
                        ExecError::PushSize
                    } else {
                        ExecError::ScriptIntNumericOverflow
                    },
                );
            }
            for (alias, v) in [
                (vec![0], 0),
                (vec![0x80], 0),
                (vec![1, 0], 1),
                (vec![9, 0, 0, 0], 9),
            ] {
                let mut d = vec![0; 4];
                d[pos] = v;
                let mut x = witness(&d);
                x[pos] = alias;
                let l = leaf(f, &d);
                if f.canonical {
                    rejects(&run(l, x), ExecError::EqualVerify);
                } else {
                    clean(&run(l, x));
                }
            }
        }
        for len in 0..4 {
            rejects(
                &run(s.clone(), w[..len].to_vec()),
                ExecError::InvalidStackOperation,
            );
        }
        // Match the representative measured arity, as well as the small suite.
        let s = cleanup(f, 32);
        let control = vec![num(0); 32];
        clean(&run(s.clone(), control.clone()));
        for pos in 0..32 {
            let mut w = control.clone();
            w[pos] = num(upper(f).into());
            rejects(&run(s.clone(), w), ExecError::Verify);
        }
    }
}
fn replace_all(bytes: &mut Vec<u8>, pattern: &[u8], replacement: &[u8]) -> usize {
    let mut at = 0;
    let mut hits = 0;
    while let Some(p) = bytes[at..]
        .windows(pattern.len())
        .position(|w| w == pattern)
    {
        let i = at + p;
        bytes.splice(i..i + pattern.len(), replacement.iter().copied());
        at = i + replacement.len();
        hits += 1;
    }
    hits
}
#[test]
fn compiled_range_and_canonicality_mutations_fail_the_same_typed_assertion() {
    for f in FAMILIES {
        let original = script! {{(f.g)(4)}OP_2DROP OP_TRUE}.compile_with_policy();
        let (guard, replacement) = if f.kind == Kind::Exact {
            (
                script! {OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY 16 OP_LESSTHAN OP_VERIFY},
                script! {OP_DROP},
            )
        } else {
            (
                script! {OP_DUP 0 {upper(f)} OP_WITHIN OP_VERIFY},
                script! {},
            )
        };
        let mut bytes = original.to_bytes();
        let hits = replace_all(
            &mut bytes,
            &guard.compile_with_policy().to_bytes(),
            &replacement.compile_with_policy().to_bytes(),
        );
        assert_eq!(hits, 4, "{}: every range check mutated", f.name);
        let mutant = ScriptBuf::from_bytes(bytes);
        for d in [
            vec![0; 4],
            vec![1, 2, 3, upper(f) - 1],
            vec![upper(f) - 1; 4],
        ] {
            let mut w = vec![num(0)];
            w.extend(witness(&d));
            clean(&run(original.clone(), w.clone()));
            clean(&run(mutant.clone(), w));
        }
        for pos in 1..=4 {
            let mut w = vec![num(0); 5];
            w[pos] = num(upper(f).into());
            rejects(&run(original.clone(), w.clone()), ExecError::Verify);
            let r = run(mutant.clone(), w);
            clean(&r);
            caught(&r, ExecError::Verify);
        }
        if f.canonical {
            let canonical = script! {OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY}
                .compile_with_policy()
                .to_bytes();
            let mut bytes = original.to_bytes();
            assert_eq!(replace_all(&mut bytes, &canonical, &[]), 4);
            let mutant = ScriptBuf::from_bytes(bytes);
            for d in [vec![0; 4], vec![1, 2, 3, 15]] {
                let mut w = vec![num(0)];
                w.extend(witness(&d));
                clean(&run(original.clone(), w.clone()));
                clean(&run(mutant.clone(), w));
            }
            for pos in 1..=4 {
                let mut w = vec![num(0); 5];
                w[pos] = vec![0, 0];
                rejects(&run(original.clone(), w.clone()), ExecError::EqualVerify);
                let r = run(mutant.clone(), w);
                clean(&r);
                caught(&r, ExecError::EqualVerify);
            }
        }
    }
}
fn peak(f: Family, n: u32) -> u32 {
    if n == 0 {
        return 1;
    }
    match f.name {
        "resident" => n + 104,
        "warmup" => {
            if n == 1 {
                4
            } else {
                n + 103
            }
        }
        "row-table" => n + 10,
        "dispatch" => n + 3,
        "mod16-canonical" => n + 34,
        "exact-numeric" => n + 3,
        _ => unreachable!(),
    }
}
#[test]
fn every_caller_item_survives_at_the_exact_combined_frontier() {
    for f in FAMILIES {
        for n in [0, 1, 2, 32, f.cap] {
            if n == 0 && f.kind != Kind::Damm {
                continue;
            }
            for all_high in [false, true] {
                let d = vec![if all_high { upper(f) - 1 } else { 0 }; n as usize];
                let allowance = 1000 - peak(f, n);
                for a in [0, 1, 3] {
                    if a > allowance {
                        continue;
                    }
                    let m = allowance - a;
                    let main: Vec<_> = (0..m)
                        .map(|i| vec![0x91, (i % 256) as u8, (i / 256) as u8])
                        .collect();
                    let alt: Vec<_> = (0..a).map(|i| vec![0x82, i as u8]).collect();
                    let mut w = main.clone();
                    w.extend(witness(&d));
                    w.extend(alt.clone());
                    let s=script!{for _ in 0..a{OP_TOALTSTACK}{(f.g)(n)}for _ in 0..a{OP_FROMALTSTACK}}.compile_with_policy();
                    let r = run(s.clone(), w.clone());
                    assert_eq!(r.error, None, "{} n{n} high{all_high} alt{a}: {r}", f.name);
                    assert_eq!(r.stats.max_nb_stack_items, 1000, "{} n{n}", f.name);
                    let mut e = main;
                    e.push(num(value(f, &d).into()));
                    e.extend(alt);
                    assert_eq!(r.final_stack.len(), e.len());
                    for (i, x) in e.iter().enumerate() {
                        assert_eq!(&r.final_stack.get(i), x, "{} n{n} slot{i}", f.name);
                    }
                    w.insert(0, vec![0x92]);
                    rejects(&run(s, w), ExecError::StackSize);
                }
            }
        }
    }
    for (name, g, n) in [
        (
            "resident",
            baseline::resident_unbounded as fn(u32) -> Script,
            897,
        ),
        ("warmup", baseline::warmup, 898),
        ("row-table", baseline::row_table, 991),
        ("dispatch", baseline::dispatch, 998),
    ] {
        let r = run(
            script! {{g(n)}OP_DROP OP_TRUE}.compile_with_policy(),
            vec![num(0); n as usize],
        );
        rejects(&r, ExecError::StackSize);
        assert_eq!(r.stats.max_nb_stack_items, 1001, "{name}");
    }
}
#[test]
fn order_and_terminal_binding_mutations_remain_observable() {
    for f in FAMILIES {
        let d = vec![1, 3, 7, 9];
        let actual = value(f, &d);
        let wrong = match f.kind {
            Kind::Damm => (actual + 1) % 10,
            Kind::Mod16 => (actual + 1) % 16,
            Kind::Exact => actual + 1,
        };
        let original =
            script! {{(f.g)(4)}{num(wrong.into())}OP_EQUALVERIFY OP_TRUE}.compile_with_policy();
        let mut control: Vec<u8> = vec![0; 4];
        if f.kind == Kind::Damm {
            control[3] = (0..10).find(|&x| baseline::Q[0][x] == wrong as u8).unwrap() as u8;
        } else {
            let mut left = wrong;
            for v in control.iter_mut().rev() {
                *v = left.min(15) as u8;
                left -= u32::from(*v);
            }
            assert_eq!(left, 0);
        }
        clean(&run(original.clone(), witness(&control)));
        rejects(&run(original.clone(), witness(&d)), ExecError::EqualVerify);
        let predicate = script! {{num(wrong.into())}OP_EQUALVERIFY}
            .compile_with_policy()
            .to_bytes();
        let mut bytes = original.to_bytes();
        assert_eq!(replace_all(&mut bytes, &predicate, &[0x75]), 1);
        let mutant = ScriptBuf::from_bytes(bytes);
        clean(&run(mutant.clone(), witness(&control)));
        let r = run(mutant, witness(&d));
        clean(&r);
        caught(&r, ExecError::EqualVerify);
        if f.kind == Kind::Damm {
            let d = [5, 7, 2];
            let original = leaf(f, &d);
            clean(&run(original.clone(), witness(&d)));
            let mut bytes = script! {OP_SWAP 2 OP_ROLL}.compile_with_policy().to_bytes();
            bytes.extend(original.to_bytes());
            let r = run(ScriptBuf::from_bytes(bytes), witness(&d));
            rejects(&r, ExecError::EqualVerify);
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| clean(&r))).is_err());
        }
    }
}
#[test]
fn fixed_table_error_relations_and_forgeable_codewords() {
    let q = baseline::Q;
    for a in 0..10 {
        let mut row = q[a];
        row.sort();
        assert_eq!(row, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let mut col = std::array::from_fn::<_, 10, _>(|b| q[b][a]);
        col.sort();
        assert_eq!(col, row);
        assert_eq!(q[a][a], 0);
    }
    for c in 0..10 {
        for x in 0..10 {
            for y in 0..10 {
                assert_eq!(q[q[c][x] as usize][y] == q[q[c][y] as usize][x], x == y);
            }
        }
    }
    for f in FAMILIES.into_iter().filter(|f| f.kind == Kind::Damm) {
        let s = script! {{(f.g)(3)}0 OP_EQUALVERIFY OP_TRUE}.compile_with_policy();
        for a in 0..10 {
            for b in 0..10 {
                let d = vec![a, b, expected(&[a, b])];
                clean(&run(s.clone(), witness(&d)));
                for pos in 0..3 {
                    for bad in 0..10 {
                        if bad == d[pos] {
                            continue;
                        }
                        let mut x = d.clone();
                        x[pos] = bad;
                        assert_ne!(expected(&x), 0);
                        rejects(&run(s.clone(), witness(&x)), ExecError::EqualVerify);
                    }
                }
                for pos in 0..2 {
                    if d[pos] == d[pos + 1] {
                        continue;
                    }
                    let mut x = d.clone();
                    x.swap(pos, pos + 1);
                    assert_ne!(expected(&x), 0);
                    rejects(&run(s.clone(), witness(&x)), ExecError::EqualVerify);
                }
            }
        }
        // Distinct messages can have the same state and freely computed check digit.
        for d in [vec![0, 0, 0], vec![1, 3, 0]] {
            clean(&run(s.clone(), witness(&d)));
        }
    }
}
#[test]
fn numeric_alias_policy_and_oversized_item_precedence_are_separate() {
    for f in FAMILIES {
        let d = [0, 1, 2, 9];
        let s = leaf(f, &d);
        let w = witness(&d);
        let p = execute_tapscript(s.clone(), w.clone(), TapscriptProfile::Policy);
        match p.outcome {
            TapscriptOutcome::Executed(r) => clean(&r),
            o => panic!("{o:?}"),
        }
        for pos in 0..4 {
            let mut x = w.clone();
            x[pos] = vec![d[pos], 0, 0, 0];
            let p = execute_tapscript(s.clone(), x, TapscriptProfile::Policy);
            match p.outcome {
                TapscriptOutcome::Executed(r) => rejects(&r, ExecError::MinimalData),
                o => panic!("{o:?}"),
            }
            for size in [81, 520, 521] {
                let mut x = w.clone();
                x[pos] = vec![0; size];
                let p = execute_tapscript(s.clone(), x, TapscriptProfile::Policy);
                assert!(
                    matches!(p.outcome,TapscriptOutcome::PolicyRejected(TapscriptPolicyRejection::WitnessStackItemSize{index,size:n})if index==pos&&n==size)
                );
            }
        }
    }
}
#[test]
fn preloaded_independent_folds_bind_every_result_and_all_live_state() {
    for repeats in [2, 3, 28] {
        let (f, w, e) = measure::independent_groups(repeats);
        let leaf = script! {{f.clone()}for x in e.iter().rev(){{x.clone()}OP_EQUALVERIFY}OP_TRUE}
            .compile_with_policy();
        let r = run(leaf.clone(), w.clone());
        clean(&r);
        assert_eq!(r.stats.max_nb_stack_items, (32 * repeats + 104) as usize);
        let aliases = w
            .iter()
            .map(|x| vec![x.first().copied().unwrap_or(0), 0, 0, 0])
            .collect();
        clean(&run(leaf, aliases));
        if repeats == 2 {
            let leaf =
                script! {{f.clone()}for x in e.iter().rev(){{x.clone()}OP_EQUALVERIFY}OP_TRUE}
                    .compile_with_policy();
            clean(&run(leaf.clone(), w.clone()));
            for len in 0..w.len() {
                rejects(
                    &run(leaf.clone(), w[..len].to_vec()),
                    ExecError::InvalidStackOperation,
                );
            }
            let original = script! {{f.clone()}OP_2DROP OP_DROP OP_TRUE}.compile_with_policy();
            let mut bytes = original.to_bytes();
            let pattern = baseline::guard().compile_with_policy().to_bytes();
            assert_eq!(replace_all(&mut bytes, &pattern, &[]), 64);
            let mutant = ScriptBuf::from_bytes(bytes);
            let control = vec![num(0); 65];
            clean(&run(original.clone(), control.clone()));
            clean(&run(mutant.clone(), control.clone()));
            for pos in 1..=64 {
                let mut w = control.clone();
                w[pos] = num(10);
                rejects(&run(original.clone(), w.clone()), ExecError::Verify);
                let r = run(mutant.clone(), w);
                clean(&r);
                caught(&r, ExecError::Verify);
            }
        }
        let allowance = 1000 - (32 * repeats + 104);
        for a in [0, 1, 3] {
            if a > allowance {
                continue;
            }
            let m = allowance - a;
            let main: Vec<_> = (0..m)
                .map(|i| vec![0xa1, (i % 256) as u8, (i / 256) as u8])
                .collect();
            let alt: Vec<_> = (0..a).map(|i| vec![0xa2, i as u8]).collect();
            let mut input = main.clone();
            input.extend(w.clone());
            input.extend(alt.clone());
            let s = script! {for _ in 0..a{OP_TOALTSTACK}{f.clone()}for _ in 0..a{OP_FROMALTSTACK}}
                .compile_with_policy();
            let r = run(s.clone(), input.clone());
            assert_eq!(r.error, None);
            assert_eq!(r.stats.max_nb_stack_items, 1000);
            let mut out = main;
            out.extend(e.clone());
            out.extend(alt);
            assert_eq!(r.final_stack.len(), out.len());
            for (i, x) in out.iter().enumerate() {
                assert_eq!(&r.final_stack.get(i), x);
            }
            input.insert(0, vec![0xa3]);
            rejects(&run(s, input), ExecError::StackSize);
        }
    }
    let (f, w, _) = measure::independent_groups(29);
    let r = run(f.compile_with_policy(), w);
    rejects(&r, ExecError::StackSize);
    assert_eq!(r.stats.max_nb_stack_items, 1001);
}
#[test]
fn report_catalog_and_immutable_sources_bind_all_artifacts() {
    let report: serde_json::Value =
        serde_json::from_str(include_str!("../research/damm-finite-state/metrics.json")).unwrap();
    let rev = report["source_revision"].as_str().unwrap();
    assert_eq!(rev.len(), 40);
    assert!(rev.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(rev, "0000000000000000000000000000000000000000");
    assert_eq!(measure::report(rev), report);
    let root = env!("CARGO_MANIFEST_DIR");
    let commit = std::process::Command::new("git")
        .args(["cat-file", "-e", rev])
        .current_dir(root)
        .output()
        .unwrap();
    if commit.status.success() {
        for (path, hash) in report["source_sha256"].as_object().unwrap() {
            let b = std::process::Command::new("git")
                .args(["show", &format!("{rev}:{path}")])
                .current_dir(root)
                .output()
                .unwrap();
            assert!(b.status.success());
            assert_eq!(
                sha256::Hash::hash(&b.stdout).to_string(),
                hash.as_str().unwrap()
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
        .find(|r| r["id"] == "arithmetic/u4-damm")
        .unwrap();
    assert_eq!(record["evidence"], "locally-reproduced");
    assert_eq!(record["execution"], "unclassified");
    assert_eq!(record["configurations"].as_array().unwrap().len(), 12);
    for c in record["configurations"].as_array().unwrap() {
        let p = &c["parameters"];
        if let Some(id) = p["composition_id"].as_str() {
            let row = report["compositions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["id"] == id)
                .unwrap();
            let a = &row[p["boundary"].as_str().unwrap()];
            for key in ["script_bytes", "max_stack_items", "static_non_push_opcodes"] {
                assert_eq!(c[key], a[key]);
            }
            for key in ["sha256", "raw_bytes", "compile_options"] {
                assert_eq!(p[key], a[key]);
            }
            for key in ["source_revision", "compiler_source", "interpreter_source"] {
                assert_eq!(p[key], report[key]);
            }
            for key in ["witness_sha256", "data_items", "hint_items", "repeat_count"] {
                assert_eq!(p[key], row[key]);
            }
            assert_eq!(c["witness_bytes"], row["witness_bytes"]);
            let n = row["data_items"].as_u64().unwrap();
            assert_eq!(
                c["witness_bytes_max"].as_u64().unwrap(),
                5 * n + if n < 253 { 1 } else { 3 }
            );
            continue;
        }
        let row = report["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| {
                r["algorithm"] == "resident"
                    && r["n"] == p["digit_count"]
                    && r["digit_pattern"] == p["digit_pattern"]
                    && r["encoding"] == p["encoding"]
            })
            .unwrap();
        let a = &row[p["boundary"].as_str().unwrap()];
        for key in ["script_bytes", "max_stack_items", "static_non_push_opcodes"] {
            assert_eq!(c[key], a[key]);
        }
        for key in ["sha256", "raw_bytes", "compile_options"] {
            assert_eq!(p[key], a[key]);
        }
        for key in ["source_revision", "compiler_source", "interpreter_source"] {
            assert_eq!(p[key], report[key]);
        }
        for key in ["witness_sha256", "data_items", "hint_items"] {
            assert_eq!(p[key], row[key]);
        }
        assert_eq!(c["witness_bytes"], row["witness_bytes"]);
        let n = p["digit_count"].as_u64().unwrap();
        assert_eq!(
            c["witness_bytes_max"].as_u64().unwrap(),
            5 * n + if n < 253 { 1 } else { 3 }
        );
        assert!(c["executed_opcodes"].is_null());
        assert!(c["validation_weight"].is_null());
    }
    for r in report["rows"].as_array().unwrap() {
        assert_eq!(r["data_items"], r["n"]);
        assert_eq!(r["hint_items"], 0);
        assert_eq!(r["hint_bytes"], 0);
        for b in ["fragment", "leaf"] {
            let a = &r[b];
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
        if r["fragment"]["error"].is_null() {
            assert_eq!(r["fragment"]["output_sha256"], r["expected_output_sha256"]);
            assert_eq!(r["fragment"]["output_items"], 1);
            assert_eq!(r["leaf"]["clean_success"], true);
            if r["encoding"] == "four-byte-alias" && r["n"] != 0 {
                assert_eq!(r["leaf"]["local_policy"]["error"], "MinimalData");
            } else {
                assert_eq!(r["leaf"]["local_policy"]["clean_success"], true);
            }
        } else {
            assert_eq!(r["fragment"]["error"], "StackSize");
            assert_eq!(r["leaf"]["error"], "StackSize");
            assert_eq!(r["fragment"]["max_stack_items"], 1001);
        }
    }
    for r in report["compositions"].as_array().unwrap() {
        assert_eq!(
            r["data_items"].as_u64().unwrap(),
            32 * r["repeat_count"].as_u64().unwrap()
        );
        assert_eq!(r["hint_items"], 0);
        assert_eq!(r["hint_bytes"], 0);
        assert_eq!(
            r["fragment"]["script_bytes"].as_i64().unwrap(),
            r["component_bytes_sum"].as_i64().unwrap()
                + r["composition_optimizer_delta"].as_i64().unwrap()
        );
        if r["fragment"]["error"].is_null() {
            assert_eq!(r["fragment"]["output_sha256"], r["expected_output_sha256"]);
            assert_eq!(r["fragment"]["output_items"], r["repeat_count"]);
            assert_eq!(r["leaf"]["clean_success"], true);
        } else {
            assert_eq!(r["fragment"]["error"], "StackSize");
            assert_eq!(r["fragment"]["max_stack_items"], 1001);
        }
    }
}
