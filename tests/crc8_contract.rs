#[path = "../research/crc8-nibble-feedback/measure.rs"]
mod measure;
use bitcoin::{script::Instruction, ScriptBuf};
use bitcoin_lab::{
    arithmetic::checksums::crc8::{crc8_smbus_nibbles, CRC8_SMBUS_MAX_BYTES},
    support::{
        execution::ExecuteInfo,
        script::*,
        tapscript::{
            execute_tapscript, TapscriptOutcome, TapscriptPolicyRejection, TapscriptProfile,
        },
    },
};
use bitcoin_scriptexec::ExecError;
use measure::*;
use serde_json::Value;
use std::{
    fs,
    panic::{catch_unwind, AssertUnwindSafe},
    path::Path,
    process::Command,
};

fn output(r: &ExecuteInfo, expected_top_first: &[u8]) {
    assert!(r.stack_limit_enforced);
    assert_eq!(r.error, None, "{r}");
    assert_eq!(r.final_stack.len(), expected_top_first.len(), "{r}");
    for (i, &q) in expected_top_first.iter().rev().enumerate() {
        assert_eq!(r.final_stack.get(i), num(q.into()), "{r}");
    }
}
fn clean(r: &ExecuteInfo) {
    output(r, &[1]);
    assert!(r.success, "{r}");
}
fn rejects(r: &ExecuteInfo, e: ExecError) {
    assert!(r.stack_limit_enforced);
    assert_eq!(r.error, Some(e), "{r}");
    assert!(!r.success);
}
fn caught(r: &ExecuteInfo, e: ExecError) {
    assert!(catch_unwind(AssertUnwindSafe(|| rejects(r, e))).is_err());
}
fn remove(s: &ScriptBuf, pattern: ScriptBuf, expected: usize) -> ScriptBuf {
    let mut bytes = Vec::new();
    let mut i = 0;
    let mut found = 0;
    while i < s.len() {
        if s.as_bytes()[i..].starts_with(pattern.as_bytes()) {
            i += pattern.len();
            found += 1;
        } else {
            bytes.push(s.as_bytes()[i]);
            i += 1;
        }
    }
    assert_eq!(found, expected);
    ScriptBuf::from_bytes(bytes)
}
fn caller(g: Script, expected: &[u8], main: &[Vec<u8>], alt: &[Vec<u8>]) -> Script {
    script! {
        for _ in 0..alt.len() {OP_TOALTSTACK}
        {g} for q in expected {{*q} OP_EQUALVERIFY}
        for m in main.iter().rev() {{m.clone()} OP_EQUALVERIFY}
        for a in alt.iter().rev() {OP_FROMALTSTACK {a.clone()} OP_EQUALVERIFY}
        OP_TRUE
    }
}
fn frontier(g: Script, w: &[Vec<u8>], e: &[u8], alt_count: usize) {
    output(&run(g.clone().compile_with_policy(), w.to_vec()), e);
    let peak = run(g.clone().compile_with_policy(), w.to_vec())
        .stats
        .max_nb_stack_items as usize;
    // The maximum-sized message leaves fewer than three caller slots.
    let alt_count = alt_count.min(1000 - peak);
    let main: Vec<Vec<u8>> = (0..1000 - peak - alt_count)
        .map(|i| vec![0x70, (i & 255) as u8, (i >> 8) as u8])
        .collect();
    let alt: Vec<Vec<u8>> = (0..alt_count).map(|i| vec![0x90, i as u8]).collect();
    let mut all = main.clone();
    all.extend_from_slice(w);
    // Runtime bytes make the preserved alt state observable even for empty
    // CRC input, whose constant arithmetic can be eliminated by the optimizer.
    all.extend(alt.iter().rev().cloned());
    let wrapped = caller(g, e, &main, &alt).compile_with_policy();
    let r = run(wrapped.clone(), all.clone());
    clean(&r);
    assert_eq!(r.stats.max_nb_stack_items, 1000);
    all.insert(0, vec![0x55]);
    let r = run(wrapped, all);
    rejects(&r, ExecError::StackSize);
    assert_eq!(r.stats.max_nb_stack_items, 1001);
}

#[test]
fn original_reproduction_and_every_two_byte_message_survive_public_promotion() {
    assert_eq!(CRC8_SMBUS_MAX_BYTES, 406);
    for bytes in [0, 1, 2, 9, 16, 64, 128, 249, 250, 306, 307, 406] {
        assert_eq!(
            crc8_smbus_nibbles(bytes).compile_with_policy(),
            baseline::feedback(2 * bytes, 0).compile_with_policy()
        );
    }
    for invalid in [407, u32::MAX] {
        assert!(catch_unwind(|| crc8_smbus_nibbles(invalid)).is_err());
    }
    for family in FAMILIES {
        let s = (family.generate)(2).compile_with_policy();
        for x in 0..=65535u32 {
            let d = [
                (x >> 12) as u8,
                ((x >> 8) & 15) as u8,
                ((x >> 4) & 15) as u8,
                (x & 15) as u8,
            ];
            output(&run(s.clone(), witness(&d)), &[baseline::oracle(&d, 0)]);
        }
        for bytes in [0, 1, 2, 3, 9, 16, 64, 128, 306, 307, 406] {
            for pattern in ["zero", "varied"] {
                let d = scalar_data(bytes, pattern);
                let q = baseline::oracle(&d, 0);
                clean(&run(
                    leaf((family.generate)(bytes), q).compile_with_policy(),
                    witness(&d),
                ));
                if !family.canonical {
                    let mut maximum = witness(&d);
                    for item in &mut maximum {
                        item.resize(4, 0);
                    }
                    assert_eq!(
                        encoded(&maximum).len(),
                        5 * maximum.len() + if maximum.len() >= 253 { 3 } else { 1 }
                    );
                    clean(&run(
                        leaf((family.generate)(bytes), q).compile_with_policy(),
                        maximum,
                    ));
                }
            }
        }
    }
}

#[test]
fn hostile_inputs_aliases_and_short_prefixes_share_four_family_contracts() {
    for f in FAMILIES {
        for bytes in [2, 9] {
            let n = 2 * bytes as usize;
            let d = vec![0; n];
            let s = leaf((f.generate)(bytes), 0).compile_with_policy();
            clean(&run(s.clone(), witness(&d)));
            for pos in 0..n {
                for (bad, e) in [
                    (num(-1), ExecError::Verify),
                    (num(16), ExecError::Verify),
                    (vec![0; 5], ExecError::ScriptIntNumericOverflow),
                    (vec![0; 80], ExecError::ScriptIntNumericOverflow),
                    (vec![0; 81], ExecError::ScriptIntNumericOverflow),
                    (vec![0; 520], ExecError::ScriptIntNumericOverflow),
                    (vec![0; 521], ExecError::PushSize),
                ] {
                    let mut w = witness(&d);
                    w[pos] = bad;
                    rejects(&run(s.clone(), w), e);
                }
                for (alias, value) in [
                    (vec![0], 0),
                    (vec![0x80], 0),
                    (vec![1, 0], 1),
                    (vec![15, 0, 0, 0], 15),
                ] {
                    let mut valid = d.clone();
                    valid[n - 1 - pos] = value;
                    let q = baseline::oracle(&valid, 0);
                    let checked = leaf((f.generate)(bytes), q).compile_with_policy();
                    clean(&run(checked.clone(), witness(&valid)));
                    let mut w = witness(&valid);
                    w[pos] = alias;
                    if f.canonical {
                        rejects(&run(checked, w), ExecError::EqualVerify);
                    } else {
                        clean(&run(checked, w));
                    }
                }
            }
            for len in 0..n {
                rejects(
                    &run(s.clone(), vec![vec![]; len]),
                    ExecError::InvalidStackOperation,
                );
            }
        }
    }
}

#[test]
fn compiled_range_and_canonicality_bypasses_are_caught_by_the_same_assertions() {
    for f in FAMILIES {
        for pos in 0..4 {
            let mut valid = vec![0; 4];
            if f.name.starts_with("serial") {
                valid[3 - pos] = 15;
            }
            let q = baseline::oracle(&valid, 0);
            let s = leaf((f.generate)(2), q).compile_with_policy();
            clean(&run(s.clone(), witness(&valid)));
            let mut bad = witness(&valid);
            bad[pos] = num(16);
            rejects(&run(s.clone(), bad.clone()), ExecError::Verify);
            let mut mutant = remove(&s, baseline::guard().compile_with_policy(), 4);
            if f.canonical {
                mutant = remove(
                    &mutant,
                    script! {OP_DUP 0 16 OP_WITHIN OP_VERIFY}.compile_with_policy(),
                    4,
                );
            }
            clean(&run(mutant.clone(), witness(&valid)));
            clean(&run(mutant.clone(), bad.clone()));
            caught(&run(mutant, bad), ExecError::Verify);
        }
        if f.canonical {
            let valid = vec![1; 4];
            let q = baseline::oracle(&valid, 0);
            let s = leaf((f.generate)(2), q).compile_with_policy();
            clean(&run(s.clone(), witness(&valid)));
            let mutant = remove(
                &s,
                script! {OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY}.compile_with_policy(),
                4,
            );
            for pos in 0..4 {
                let mut bad = witness(&valid);
                bad[pos] = vec![1, 0];
                rejects(&run(s.clone(), bad.clone()), ExecError::EqualVerify);
                clean(&run(mutant.clone(), witness(&valid)));
                clean(&run(mutant.clone(), bad.clone()));
                caught(&run(mutant.clone(), bad), ExecError::EqualVerify);
            }
        }
    }
}

#[test]
fn repeated_guard_bypasses_are_caught_at_every_live_position() {
    for f in FAMILIES {
        for pos in 0..36 {
            let mut logical = vec![0; 36];
            if f.name.starts_with("serial") {
                logical[35 - pos] = 15;
            }
            let expected = [
                baseline::oracle(&logical[..18], 0),
                baseline::oracle(&logical[18..], 0),
            ];
            let (g, _, _) = repeated(f, 9, 2);
            let s = bind_outputs(g, &expected).compile_with_policy();
            let valid = witness(&logical);
            clean(&run(s.clone(), valid.clone()));
            let mut bad = valid.clone();
            bad[pos] = num(16);
            rejects(&run(s.clone(), bad.clone()), ExecError::Verify);
            let mut mutant = remove(&s, baseline::guard().compile_with_policy(), 36);
            if f.canonical {
                mutant = remove(
                    &mutant,
                    script! {OP_DUP 0 16 OP_WITHIN OP_VERIFY}.compile_with_policy(),
                    36,
                );
            }
            clean(&run(mutant.clone(), valid));
            clean(&run(mutant.clone(), bad.clone()));
            caught(&run(mutant, bad), ExecError::Verify);
        }
    }
}

#[test]
fn order_and_terminal_mutations_preserve_valid_controls_and_fail_exact_contracts() {
    let ordered = [1, 2, 3, 4];
    let swapped = [2, 1, 3, 4];
    let q = baseline::oracle(&ordered, 0);
    let wrong = baseline::oracle(&swapped, 0);
    assert_ne!(q, wrong);
    for f in FAMILIES {
        let s = leaf((f.generate)(2), q).compile_with_policy();
        clean(&run(s.clone(), witness(&ordered)));
        rejects(&run(s, witness(&swapped)), ExecError::EqualVerify);
        let ordering_mutant = script! {OP_SWAP {(f.generate)(2)}}.compile_with_policy();
        let benign = [1, 1, 3, 4];
        let benign_q = baseline::oracle(&benign, 0);
        output(&run(ordering_mutant.clone(), witness(&benign)), &[benign_q]);
        output(
            &run((f.generate)(2).compile_with_policy(), witness(&ordered)),
            &[q],
        );
        assert!(catch_unwind(AssertUnwindSafe(|| output(
            &run(ordering_mutant, witness(&ordered)),
            &[q]
        )))
        .is_err());
        // Bind without a constant expected CRC in the script so the actual
        // compiled OP_EQUALVERIFY can be removed without changing cleanup.
        let checked = script! {{(f.generate)(2)} OP_EQUALVERIFY OP_TRUE}.compile_with_policy();
        let mut valid = vec![num(q.into())];
        valid.extend(witness(&ordered));
        clean(&run(checked.clone(), valid.clone()));
        let mut bad = vec![num(wrong.into())];
        bad.extend(witness(&ordered));
        rejects(&run(checked.clone(), bad.clone()), ExecError::EqualVerify);
        // Strict siblings also have four canonicality equality guards.
        let mut bytes = checked.to_bytes();
        let op = bitcoin::opcodes::all::OP_EQUALVERIFY.to_u8();
        let position = checked
            .instruction_indices()
            .filter_map(|x| match x.unwrap() {
                (i, Instruction::Op(o)) if o == bitcoin::opcodes::all::OP_EQUALVERIFY => Some(i),
                _ => None,
            })
            .last()
            .unwrap();
        assert_eq!(bytes.remove(position), op);
        bytes.insert(position, bitcoin::opcodes::all::OP_2DROP.to_u8());
        let mutant = ScriptBuf::from_bytes(bytes);
        clean(&run(mutant.clone(), valid));
        clean(&run(mutant.clone(), bad.clone()));
        caught(&run(mutant, bad), ExecError::EqualVerify);
    }
}

#[test]
fn every_caller_byte_and_exact_single_message_limits_are_observable() {
    for f in FAMILIES {
        for bytes in [0, 1, 9, 16, 406] {
            for pattern in ["zero", "varied"] {
                let d = scalar_data(bytes, pattern);
                let q = baseline::oracle(&d, 0);
                for alt in [0, 3] {
                    frontier((f.generate)(bytes), &witness(&d), &[q], alt);
                }
            }
        }
    }
    let d = message(406, 0);
    let r = run(
        leaf(crc8_smbus_nibbles(406), baseline::oracle(&d, 0)).compile_with_policy(),
        witness(&d),
    );
    clean(&r);
    assert_eq!(r.stats.max_nb_stack_items, 1000);
    let d = message(493, 0);
    for f in [FAMILIES[1], FAMILIES[3]] {
        frontier(
            (f.generate)(493),
            &witness(&d),
            &[baseline::oracle(&d, 0)],
            0,
        );
    }
    let over = vec![0; 988];
    rejects(
        &run(
            leaf(baseline::serial(988, 0), 0).compile_with_policy(),
            witness(&over),
        ),
        ExecError::StackSize,
    );
}

#[test]
fn independent_messages_bind_every_output_and_every_hostile_live_position() {
    for f in FAMILIES {
        for repeats in [2, 8, 25, 26, 45, 46] {
            if repeats == 46 && f.name.starts_with("feedback") {
                continue;
            }
            let (g, w, e) = repeated(f, 9, repeats);
            output(&run(g.clone().compile_with_policy(), w.clone()), &e);
            let checked = bind_outputs(g.clone(), &e).compile_with_policy();
            clean(&run(checked.clone(), w.clone()));
            if !f.canonical {
                let mut maximum = w.clone();
                for item in &mut maximum {
                    item.resize(4, 0);
                }
                assert_eq!(
                    encoded(&maximum).len(),
                    5 * maximum.len() + if maximum.len() >= 253 { 3 } else { 1 }
                );
                clean(&run(checked.clone(), maximum));
            }
            for pos in 0..w.len() {
                for (bad, error) in [
                    (num(-1), ExecError::Verify),
                    (vec![0; 5], ExecError::ScriptIntNumericOverflow),
                ] {
                    let mut hostile = w.clone();
                    hostile[pos] = bad;
                    rejects(&run(checked.clone(), hostile), error);
                }
            }
            for len in 0..w.len() {
                rejects(
                    &run(checked.clone(), w[..len].to_vec()),
                    ExecError::InvalidStackOperation,
                );
            }
            let alias = vec![vec![1, 0]; w.len()];
            let expected: Vec<u8> = (0..repeats)
                .map(|_| baseline::oracle(&[1; 18], 0))
                .collect();
            let canonical = vec![num(1); w.len()];
            let same = bind_outputs(g.clone(), &expected).compile_with_policy();
            clean(&run(same.clone(), canonical));
            if f.canonical {
                rejects(&run(same, alias), ExecError::EqualVerify);
            } else {
                clean(&run(same, alias));
            }
            for alt in [0, 3] {
                frontier(g.clone(), &w, &e, alt);
            }
        }
    }
    for f in [FAMILIES[0], FAMILIES[2]] {
        let (g, w, e) = repeated(f, 9, 46);
        let r = run(bind_outputs(g, &e).compile_with_policy(), w);
        rejects(&r, ExecError::StackSize);
        assert_eq!(r.stats.max_nb_stack_items, 1001);
    }
}

#[test]
fn local_policy_controls_do_not_claim_complete_relay_validation() {
    for f in FAMILIES {
        let d = vec![1; 4];
        let s = leaf((f.generate)(2), baseline::oracle(&d, 0)).compile_with_policy();
        match execute_tapscript(s.clone(), witness(&d), TapscriptProfile::Policy).outcome {
            TapscriptOutcome::Executed(r) => clean(&r),
            o => panic!("{o:?}"),
        }
        match execute_tapscript(s.clone(), vec![vec![1, 0]; 4], TapscriptProfile::Policy).outcome {
            TapscriptOutcome::Executed(r) => rejects(&r, ExecError::MinimalData),
            o => panic!("{o:?}"),
        }
        for size in [81, 520, 521] {
            let mut w = witness(&d);
            w[0] = vec![0; size];
            match execute_tapscript(s.clone(), w, TapscriptProfile::Policy).outcome {
                TapscriptOutcome::PolicyRejected(
                    TapscriptPolicyRejection::WitnessStackItemSize { index: 0, size: n },
                ) => assert_eq!(n, size),
                o => panic!("{o:?}"),
            }
        }
    }
}

#[test]
fn artifacts_match_immutable_source_actual_generators_and_catalog_configurations() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let stored: Value = serde_json::from_slice(
        &fs::read(root.join("research/crc8-nibble-feedback/metrics.json")).unwrap(),
    )
    .unwrap();
    let revision = stored["source_revision"].as_str().unwrap();
    assert_ne!(revision, "0".repeat(40));
    assert_eq!(stored, report(revision));
    for (path, digest) in stored["source_sha256"].as_object().unwrap() {
        assert_eq!(
            sha(&fs::read(root.join(path)).unwrap()),
            digest.as_str().unwrap()
        );
        let pinned = Command::new("git")
            .args(["show", &format!("{revision}:{path}")])
            .current_dir(root)
            .output()
            .unwrap();
        if pinned.status.success() {
            assert_eq!(sha(&pinned.stdout), digest.as_str().unwrap());
        } else {
            let shallow = Command::new("git")
                .args(["rev-parse", "--is-shallow-repository"])
                .current_dir(root)
                .output()
                .unwrap();
            assert!(shallow.status.success());
            assert_eq!(String::from_utf8(shallow.stdout).unwrap().trim(), "true");
        }
    }
    let catalog: Value =
        serde_json::from_slice(&fs::read(root.join("knowledge/catalog.json")).unwrap()).unwrap();
    let record = catalog["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "arithmetic/crc8-smbus")
        .unwrap();
    assert_eq!(record["evidence"], "locally-reproduced");
    assert_eq!(record["execution"], "unclassified");
    for cfg in record["configurations"].as_array().unwrap() {
        let p = &cfg["parameters"];
        assert_eq!(p["source_revision"], revision);
        assert_eq!(p["compiler_source"], stored["compiler_source"]);
        assert_eq!(p["interpreter_source"], stored["interpreter_source"]);
        assert_eq!(cfg["evidence"], "locally-reproduced");
        assert_eq!(cfg["execution"], "unclassified");
        let row = if let Some(index) = p["composition_index"].as_u64() {
            &stored["compositions"][index as usize]
        } else {
            &stored["rows"][p["row_index"].as_u64().unwrap() as usize]
        };
        let art = &row[p["boundary"].as_str().unwrap()];
        assert_eq!(cfg["script_bytes"], art["script_bytes"]);
        assert_eq!(cfg["witness_bytes"], row["witness_bytes"]);
        assert_eq!(cfg["witness_bytes_max"], row["witness_bytes_max"]);
        assert_eq!(cfg["max_stack_items"], art["max_combined_stack_items"]);
        assert_eq!(p["script_sha256"], art["script_sha256"]);
        assert_eq!(p["tapleaf_hash"], art["tapleaf_hash"]);
        assert_eq!(p["raw_script_bytes"], art["raw_script_bytes"]);
        assert_eq!(p["compilation_options"], art["compilation_options"]);
        assert_eq!(p["witness_sha256"], row["witness_sha256"]);
        assert_eq!(p["profile"], stored["profile"]);
        assert_eq!(cfg["executed_opcodes"], Value::Null);
        assert_eq!(cfg["validation_weight"], Value::Null);
    }
}
