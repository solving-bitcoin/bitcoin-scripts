//! Shared native/explicit filter and numeric-word-selector witness contracts.
use bitcoin::{
    hashes::{sha256, Hash},
    ScriptBuf,
};
use bitcoin_lab::{
    arithmetic::u32::stack::u32_conditional_select,
    support::{
        execution::ExecuteInfo,
        script::*,
        selection::{compact_selected_items, MAX_PAIRS},
        tapscript::{
            execute_tapscript, TapscriptOutcome, TapscriptPolicyRejection, TapscriptProfile,
        },
    },
};
use bitcoin_scriptexec::ExecError;
#[path = "../research/stable-stack-compaction/measure.rs"]
mod measure;
use measure::{baseline, expected, input, leaf, num, run};
type Generator = fn(u32) -> Script;
fn word(n: u32) -> Script {
    assert_eq!(n, 4);
    u32_conditional_select()
}
#[derive(Clone, Copy)]
struct Family {
    name: &'static str,
    g: Generator,
    native: bool,
    word: bool,
    forward: bool,
}
const FAMILIES: [Family; 5] = [
    Family {
        name: "reverse-native",
        g: compact_selected_items,
        native: true,
        word: false,
        forward: false,
    },
    Family {
        name: "forward-native",
        g: baseline::forward_native,
        native: true,
        word: false,
        forward: true,
    },
    Family {
        name: "reverse-explicit",
        g: baseline::backward_explicit,
        native: false,
        word: false,
        forward: false,
    },
    Family {
        name: "forward-explicit",
        g: baseline::forward_explicit,
        native: false,
        word: false,
        forward: true,
    },
    Family {
        name: "word-numeric",
        g: word,
        native: false,
        word: true,
        forward: false,
    },
];
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
    if f.word {
        script! {{(f.g)(n)}for _ in 0..4{OP_DROP}OP_TRUE}.compile_with_policy()
    } else {
        script!{{(f.g)(n)}for i in 0..n{OP_DUP {i} OP_GREATERTHAN OP_IF OP_SWAP OP_DROP OP_ENDIF}OP_DROP OP_TRUE}.compile_with_policy()
    }
}
fn witness(f: Family, p: &[Vec<u8>], flags: &[bool]) -> Vec<Vec<u8>> {
    if f.word {
        assert_eq!(p.len(), 8);
        let mut w = p.to_vec();
        w.push(num(flags[0].into()));
        w
    } else {
        input(p, flags)
    }
}
fn output(f: Family, p: &[Vec<u8>], flags: &[bool]) -> Vec<Vec<u8>> {
    if f.word {
        p[if flags[0] { 4..8 } else { 0..4 }].to_vec()
    } else {
        expected(p, flags)
    }
}
fn positions(f: Family) -> Vec<usize> {
    if f.word {
        vec![8]
    } else {
        (0..4).map(|i| 2 * i + 1).collect()
    }
}
#[test]
fn exhaustive_masks_asymmetric_long_vectors_and_opaque_payloads() {
    for f in FAMILIES {
        if f.word {
            continue;
        }
        for n in 0..=8 {
            let p: Vec<_> = (0..n).map(|i| vec![i as u8, 0x80]).collect();
            for mask in 0..1usize << n {
                let flags: Vec<_> = (0..n).map(|i| mask >> i & 1 == 1).collect();
                clean(&run(
                    leaf((f.g)(n as u32), &expected(&p, &flags)).compile_with_policy(),
                    input(&p, &flags),
                ));
            }
        }
        for n in [32, 128, if f.native { 499 } else { 498 }] {
            let p: Vec<_> = (0..n)
                .map(|i| vec![(173 * i % 256) as u8, (i / 256) as u8])
                .collect();
            for mode in 0..3 {
                let flags: Vec<_> = (0..n)
                    .map(|i| match mode {
                        0 => false,
                        1 => true,
                        _ => i % 3 == 1,
                    })
                    .collect();
                clean(&run(
                    leaf((f.g)(n), &expected(&p, &flags)).compile_with_policy(),
                    input(&p, &flags),
                ));
            }
        }
    }
    let p = vec![
        vec![],
        vec![0x80],
        vec![0; 5],
        vec![0xab; 520],
        vec![1],
        vec![255, 0],
        vec![0; 4],
        vec![0x42; 80],
    ];
    for f in FAMILIES {
        let payloads = if f.word { p.clone() } else { p[..4].to_vec() };
        for mask in 0..if f.word { 2 } else { 16 } {
            let flags: Vec<_> = (0..if f.word { 1 } else { 4 })
                .map(|i| mask >> i & 1 == 1)
                .collect();
            clean(&run(
                leaf((f.g)(4), &output(f, &payloads, &flags)).compile_with_policy(),
                witness(f, &payloads, &flags),
            ));
        }
    }
    for n in [MAX_PAIRS + 1, u32::MAX] {
        assert!(std::panic::catch_unwind(|| compact_selected_items(n)).is_err());
    }
}
#[test]
fn typed_hostile_flags_at_every_position_and_allowed_numeric_aliases() {
    for f in FAMILIES {
        let p: Vec<_> = (0..if f.word { 8 } else { 4 })
            .map(|i| vec![0x42, i])
            .collect();
        let flags = vec![true; if f.word { 1 } else { 4 }];
        let valid = witness(f, &p, &flags);
        let s = cleanup(f, 4);
        clean(&run(s.clone(), valid.clone()));
        for bad in [num(-1), num(2), num(i32::MAX.into())] {
            for pos in positions(f) {
                let mut w = valid.clone();
                w[pos] = bad.clone();
                if f.word {
                    clean(&run(leaf((f.g)(4), &p[4..8]).compile_with_policy(), w));
                } else {
                    rejects(
                        &run(s.clone(), w),
                        if f.native {
                            ExecError::TapscriptMinimalIf
                        } else {
                            ExecError::Verify
                        },
                    );
                }
            }
        }
        for (bad, value) in [
            (vec![0], 0),
            (vec![0x80], 0),
            (vec![1, 0], 1),
            (vec![1, 0, 0, 0], 1),
        ] {
            for pos in positions(f) {
                let mut w = valid.clone();
                w[pos] = bad.clone();
                if f.word {
                    clean(&run(
                        leaf((f.g)(4), &p[if value == 0 { 0..4 } else { 4..8 }])
                            .compile_with_policy(),
                        w,
                    ));
                } else {
                    rejects(
                        &run(s.clone(), w),
                        if f.native {
                            ExecError::TapscriptMinimalIf
                        } else {
                            ExecError::EqualVerify
                        },
                    );
                }
            }
        }
        for (bad, e) in [
            (
                vec![0; 5],
                if f.native {
                    ExecError::TapscriptMinimalIf
                } else {
                    ExecError::ScriptIntNumericOverflow
                },
            ),
            (
                vec![0; 520],
                if f.native {
                    ExecError::TapscriptMinimalIf
                } else {
                    ExecError::ScriptIntNumericOverflow
                },
            ),
            (vec![0; 521], ExecError::PushSize),
        ] {
            for pos in positions(f) {
                let mut w = valid.clone();
                w[pos] = bad.clone();
                rejects(&run(s.clone(), w), e.clone());
            }
        }
    }
}
#[test]
fn oversized_even_discarded_payloads_and_unambiguous_short_inputs() {
    for f in FAMILIES {
        let p = vec![vec![1]; if f.word { 8 } else { 4 }];
        let s = cleanup(f, 4);
        for keep in [false, true] {
            let flags = vec![keep; if f.word { 1 } else { 4 }];
            let valid = witness(f, &p, &flags);
            clean(&run(s.clone(), valid.clone()));
            let positions: Vec<_> = if f.word {
                (0..8).collect()
            } else {
                (0..4).map(|i| 2 * i).collect()
            };
            for pos in positions {
                let mut w = valid.clone();
                w[pos] = vec![0; 521];
                rejects(&run(s.clone(), w), ExecError::PushSize);
            }
        }
        // All remaining items are valid selectors if an odd truncation shifts
        // pair alignment, so a flag error cannot mask the intended underflow.
        let valid = witness(f, &p, &vec![true; if f.word { 1 } else { 4 }]);
        clean(&run(s.clone(), valid.clone()));
        for len in 0..valid.len() {
            rejects(
                &run(s.clone(), valid[..len].to_vec()),
                ExecError::InvalidStackOperation,
            );
        }
    }
}
#[test]
fn compiled_validation_bypass_is_detected_by_the_same_assertion() {
    let normalize = script! {OP_SIZE OP_0NOTEQUAL OP_SWAP OP_DROP}
        .compile_with_policy()
        .to_bytes();
    for f in FAMILIES {
        let original = cleanup(f, 4);
        let mut bytes = original.to_bytes();
        if f.word {
            assert_eq!(bytes[0], 0x92); // OP_0NOTEQUAL parses the numeric selector.
            bytes.splice(0..1, normalize.clone());
        } else {
            let pattern = if f.native {
                script! {OP_IF}
            } else {
                script! {{baseline::flag()}OP_IF}
            }
            .compile_with_policy()
            .to_bytes();
            let mut search = 0;
            let mut hits = 0;
            while hits < 4 {
                let offset = bytes[search..]
                    .windows(pattern.len())
                    .position(|w| w == pattern)
                    .expect("runtime flag validation site");
                let i = search + offset;
                let mut replacement = normalize.clone();
                replacement.push(0x63); // OP_IF
                let len = replacement.len();
                bytes.splice(i..i + pattern.len(), replacement);
                search = i + len;
                hits += 1;
            }
            assert_eq!(hits, 4, "{}: mutate every runtime flag", f.name);
        }
        let mutant = ScriptBuf::from_bytes(bytes);
        let p = vec![vec![0x42]; if f.word { 8 } else { 4 }];
        for keep in [false, true] {
            let w = witness(f, &p, &vec![keep; if f.word { 1 } else { 4 }]);
            clean(&run(original.clone(), w.clone()));
            clean(&run(mutant.clone(), w));
        }
        let valid = witness(f, &p, &vec![true; if f.word { 1 } else { 4 }]);
        let bads = if f.word {
            vec![(vec![0; 5], ExecError::ScriptIntNumericOverflow)]
        } else {
            vec![
                (
                    num(2),
                    if f.native {
                        ExecError::TapscriptMinimalIf
                    } else {
                        ExecError::Verify
                    },
                ),
                (
                    vec![1, 0],
                    if f.native {
                        ExecError::TapscriptMinimalIf
                    } else {
                        ExecError::EqualVerify
                    },
                ),
                (
                    vec![0; 5],
                    if f.native {
                        ExecError::TapscriptMinimalIf
                    } else {
                        ExecError::ScriptIntNumericOverflow
                    },
                ),
            ]
        };
        for (bad, e) in bads {
            for pos in positions(f) {
                let mut w = valid.clone();
                w[pos] = bad.clone();
                rejects(&run(original.clone(), w.clone()), e.clone());
                let r = run(mutant.clone(), w);
                clean(&r);
                caught(&r, e.clone());
            }
        }
    }
}
#[test]
fn both_caller_stacks_and_exact_resource_frontiers_remain_observable() {
    for f in FAMILIES {
        let ns = if f.word {
            vec![4]
        } else {
            vec![0, 1, 2, 32, if f.native { 499 } else { 498 }]
        };
        for n in ns {
            for keep in [false, true] {
                let peak = if f.word {
                    9
                } else if n == 0 {
                    1
                } else if !f.native {
                    2 * n + 4
                } else if n == 1 {
                    if keep {
                        4
                    } else {
                        3
                    }
                } else {
                    2 * n + if f.forward { 2 } else { 1 }
                };
                let allowance = 1000 - peak;
                for a in [0, 1, 3] {
                    if a > allowance {
                        continue;
                    }
                    let m = allowance - a;
                    let main: Vec<_> = (0..m)
                        .map(|i| vec![0x90, (i % 256) as u8, (i / 256) as u8])
                        .collect();
                    let alt: Vec<_> = (0..a).map(|i| vec![0x80, i as u8]).collect();
                    let p: Vec<_> = (0..if f.word { 8 } else { n })
                        .map(|i| vec![0x42, (i % 256) as u8, (i / 256) as u8])
                        .collect();
                    let flags = vec![keep; if f.word { 1 } else { n as usize }];
                    let mut w = main.clone();
                    w.extend(witness(f, &p, &flags));
                    w.extend(alt.clone());
                    let s=script!{for _ in 0..a{OP_TOALTSTACK}{(f.g)(n)}for _ in 0..a{OP_FROMALTSTACK}}.compile_with_policy();
                    let r = run(s.clone(), w.clone());
                    assert_eq!(r.error, None, "{} n={n} keep={keep} a={a}: {r}", f.name);
                    assert_eq!(
                        r.stats.max_nb_stack_items, 1000,
                        "{} n={n} keep={keep}",
                        f.name
                    );
                    let mut e = main;
                    e.extend(output(f, &p, &flags));
                    e.extend(alt);
                    assert_eq!(r.final_stack.len(), e.len());
                    for (i, x) in e.iter().enumerate() {
                        assert_eq!(&r.final_stack.get(i), x, "{} n={n} slot={i}", f.name);
                    }
                    w.insert(0, vec![0x99]);
                    rejects(&run(s, w), ExecError::StackSize);
                }
            }
        }
    }
}
#[test]
fn count_payload_bindings_and_stable_order_regressions_are_detected() {
    let p: Vec<_> = (0..4).map(|i| vec![0x80, i, 0x42]).collect();
    let flags = [true, false, true, true];
    let e = expected(&p, &flags);
    let w = input(&p, &flags);
    for f in FAMILIES {
        if f.word {
            continue;
        }
        let original = leaf((f.g)(4), &e).compile_with_policy();
        clean(&run(original.clone(), w.clone()));
        let mut wrong = e.clone();
        *wrong.last_mut().unwrap() = num(2);
        rejects(
            &run(leaf((f.g)(4), &wrong).compile_with_policy(), w.clone()),
            ExecError::EqualVerify,
        );
        let bypass_count=script!{{(f.g)(4)}OP_DROP for x in e[..e.len()-1].iter().rev(){{x.clone()}OP_EQUALVERIFY}OP_TRUE}.compile_with_policy();
        let r = run(bypass_count, w.clone());
        clean(&r);
        caught(&r, ExecError::EqualVerify);
        let mut changed = w.clone();
        changed[0] = vec![0x81, 0, 0x42];
        rejects(&run(original, changed.clone()), ExecError::EqualVerify);
        let r = run(cleanup(f, 4), changed);
        clean(&r);
        caught(&r, ExecError::EqualVerify);
        let mut discarded = w.clone();
        discarded[2] = vec![0; 5];
        clean(&run(leaf((f.g)(4), &e).compile_with_policy(), discarded));
    }
    // Forward routing without reversal has correct count and the same items,
    // but reversed order: the positive stable-output assertion must catch it.
    let unreversed = script! {0 for i in 0..4{ {2*(4-i)-1}OP_ROLL OP_IF {2*(4-i)-1}OP_ROLL OP_TOALTSTACK OP_1ADD OP_ELSE {2*(4-i)-1}OP_ROLL OP_DROP OP_ENDIF}
    for i in 0..4{OP_DUP{i}OP_GREATERTHAN OP_IF OP_FROMALTSTACK OP_SWAP OP_ENDIF}};
    let r = run(leaf(unreversed, &e).compile_with_policy(), w);
    rejects(&r, ExecError::EqualVerify);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| clean(&r))).is_err());
}
#[test]
fn local_profiles_separate_opaque_payload_policy_and_native_if_semantics() {
    for size in [0, 5, 80, 81, 520] {
        for keep in [false, true] {
            let p = vec![vec![0x80; size]; 4];
            let flags = vec![keep; 4];
            let w = input(&p, &flags);
            let s = leaf(compact_selected_items(4), &expected(&p, &flags)).compile_with_policy();
            clean(&run(s.clone(), w.clone()));
            let policy = execute_tapscript(s, w, TapscriptProfile::Policy);
            if size <= 80 {
                match policy.outcome {
                    TapscriptOutcome::Executed(r) => clean(&r),
                    o => panic!("{o:?}"),
                }
            } else {
                assert_eq!(policy.accepted(), Some(false));
                assert!(
                    matches!(policy.outcome,TapscriptOutcome::PolicyRejected(TapscriptPolicyRejection::WitnessStackItemSize{index:0,size:n})if n==size)
                );
            }
        }
    }
    // These context-free verdicts never establish a funded Core/policy spend.
}
#[test]
fn report_catalog_and_immutable_source_bind_each_configuration() {
    let report: serde_json::Value = serde_json::from_str(include_str!(
        "../research/stable-stack-compaction/metrics.json"
    ))
    .unwrap();
    let revision = report["source_revision"].as_str().unwrap();
    assert_eq!(revision.len(), 40);
    assert!(revision.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(revision, "0000000000000000000000000000000000000000");
    assert_eq!(measure::report(revision), report);
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
    } else {
        for (path, hash) in report["source_sha256"].as_object().unwrap() {
            let blob = std::process::Command::new("git")
                .args(["show", &format!("{revision}:{path}")])
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .output()
                .unwrap();
            assert!(blob.status.success());
            assert_eq!(
                sha256::Hash::hash(&blob.stdout).to_string(),
                hash.as_str().unwrap()
            );
        }
    }
    let catalog: serde_json::Value =
        serde_json::from_str(include_str!("../knowledge/catalog.json")).unwrap();
    let record = catalog["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "support/stable-selection")
        .unwrap();
    assert_eq!(record["evidence"], "locally-reproduced");
    assert_eq!(record["execution"], "unclassified");
    assert_eq!(record["configurations"].as_array().unwrap().len(), 9);
    for c in record["configurations"].as_array().unwrap() {
        let p = &c["parameters"];
        let row = report["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| {
                r["algorithm"] == "reverse-native"
                    && r["n"] == p["pair_count"]
                    && r["payload_bytes"] == p["payload_bytes"]
                    && r["flags"] == p["flags"]
            })
            .unwrap();
        let boundary = p["boundary"].as_str().unwrap();
        let a = &row[boundary];
        for key in ["script_bytes", "max_stack_items", "static_non_push_opcodes"] {
            assert_eq!(c[key], a[key]);
        }
        for key in ["raw_bytes", "compile_options", "sha256"] {
            assert_eq!(p[key], a[key]);
        }
        assert_eq!(c["witness_bytes"], row["witness_bytes"]);
        assert_eq!(p["witness_sha256"], row["witness_sha256"]);
        assert_eq!(p["data_items"], row["data_items"]);
        assert_eq!(p["hint_items"], 0);
        for key in ["source_revision", "compiler_source", "interpreter_source"] {
            assert_eq!(p[key], report[key]);
        }
        assert!(c["executed_opcodes"].is_null());
        assert!(c["validation_weight"].is_null());
        let n = p["pair_count"].as_u64().unwrap();
        let max = report["rows"].as_array().unwrap().iter().find(|r| {
            r["algorithm"] == "reverse-native"
                && r["n"] == n
                && r["payload_bytes"] == 520
                && r["flags"] == "all-keep"
        });
        if boundary == "leaf" {
            // These catalog leaves bind all retained literal payloads and the
            // all-keep count, so their successful witness is fixed.
            assert_eq!(c["witness_bytes_max"], row["witness_bytes"]);
        } else if let Some(max) = max {
            assert_eq!(c["witness_bytes_max"], max["witness_bytes"]);
        } else {
            assert_eq!(
                c["witness_bytes_max"].as_u64().unwrap(),
                525 * n + if 2 * n < 253 { 1 } else { 3 }
            );
        }
    }
    let large = report["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["algorithm"] == "reverse-native"
                && r["n"] == 499
                && r["payload_bytes"] == 520
                && r["flags"] == "all-keep"
        })
        .unwrap();
    assert_eq!(large["fragment"]["compile_options"], "ALL");
    assert_eq!(large["leaf"]["compile_options"], "NONE");
    assert!(large["leaf"]["raw_bytes"].as_u64().unwrap() > 32768);
    assert_eq!(large["witness_bytes"], 261978);
    assert_eq!(large["fragment"]["max_stack_items"], 999);
    assert_eq!(large["leaf"]["max_stack_items"], 999);
    for row in report["rows"].as_array().unwrap() {
        assert_eq!(row["hint_items"], 0);
        assert_eq!(
            row["data_items"].as_u64().unwrap(),
            2 * row["n"].as_u64().unwrap()
        );
        if row["fragment"]["error"].is_null() {
            assert_eq!(
                row["fragment"]["output_sha256"],
                row["expected_output_sha256"]
            );
            assert_eq!(
                row["fragment"]["output_items"],
                row["expected_output_items"]
            );
            assert_eq!(row["leaf"]["clean_success"], true);
        } else {
            assert_eq!(row["fragment"]["error"], "StackSize");
            assert_eq!(row["leaf"]["error"], "StackSize");
            assert_eq!(row["fragment"]["max_stack_items"], 1001);
        }
    }
}
