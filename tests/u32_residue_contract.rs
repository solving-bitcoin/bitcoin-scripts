//! Shared runtime contract for four-byte, consuming u32 reductions.
use bitcoin::ScriptBuf;
use bitcoin_lab::{
    arithmetic::u32::{residue::u32_mod65537, zero::u32_iszero},
    support::{
        execution::ExecuteInfo,
        script::{script, Script, ScriptCompilation},
        tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
    },
};
use bitcoin_scriptexec::ExecError;

#[path = "../research/u32-fermat-residue/baseline.rs"]
mod baseline;

struct Family {
    name: &'static str,
    generate: fn() -> Script,
    canonical: bool,
    peak: u32,
}
const FAMILIES: [Family; 3] = [
    Family {
        name: "paired-lanes",
        generate: u32_mod65537,
        canonical: true,
        peak: 7,
    },
    Family {
        name: "bitwise-horner",
        generate: baseline::bitwise_horner,
        canonical: true,
        peak: 35,
    },
    Family {
        name: "numeric-zero",
        generate: u32_iszero,
        canonical: false,
        peak: 6,
    },
];
fn execute(bytes: Vec<u8>, witness: Vec<Vec<u8>>) -> ExecuteInfo {
    match execute_tapscript(
        ScriptBuf::from_bytes(bytes),
        witness,
        TapscriptProfile::Consensus,
    )
    .outcome
    {
        TapscriptOutcome::Executed(result) => result,
        outcome => panic!("unexpected outcome: {outcome:?}"),
    }
}
fn clean(fragment: Script) -> Vec<u8> {
    script! { { fragment } OP_DROP OP_TRUE }
        .compile_with_policy()
        .to_bytes()
}
fn rejects(result: &ExecuteInfo, expected: ExecError) {
    assert_eq!(result.error, Some(expected), "wrong failure: {result}");
    assert!(!result.success);
}
fn scriptnum(x: u32) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let len = bitcoin::script::write_scriptint(&mut bytes, i64::from(x));
    bytes[..len].to_vec()
}
fn witness(x: u32) -> Vec<Vec<u8>> {
    x.to_be_bytes().map(|x| scriptnum(u32::from(x))).to_vec()
}

#[test]
fn malformed_witnesses_at_every_position_have_valid_controls_and_typed_errors() {
    for family in FAMILIES {
        let leaf = clean((family.generate)());
        assert!(
            execute(leaf.clone(), witness(0x12345678)).success,
            "{} valid control",
            family.name
        );
        for (bad, error) in [
            (vec![0x81], ExecError::Verify),
            (scriptnum(256), ExecError::Verify),
            (scriptnum(2147483647), ExecError::Verify),
            (vec![0; 5], ExecError::ScriptIntNumericOverflow),
            (vec![0; 521], ExecError::PushSize),
        ] {
            for position in 0..4 {
                let mut data = witness(0x12345678);
                data[position] = bad.clone();
                rejects(&execute(leaf.clone(), data), error.clone());
            }
        }
        for length in 0..4 {
            rejects(
                &execute(leaf.clone(), witness(0x12345678)[..length].to_vec()),
                ExecError::InvalidStackOperation,
            );
        }
        for alias in [vec![0], vec![0x80], vec![1, 0], vec![127, 0, 0, 0]] {
            for position in 0..4 {
                let mut data = witness(0x12345678);
                data[position] = alias.clone();
                let result = execute(leaf.clone(), data);
                if family.canonical {
                    rejects(&result, ExecError::EqualVerify);
                } else {
                    assert!(
                        result.success,
                        "{} alias at {position}: {result}",
                        family.name
                    );
                    // Aliases accepted by numeric-only siblings must retain
                    // their numeric meaning, not merely survive cleanup.
                    let alias_is_zero = alias == vec![0] || alias == vec![0x80];
                    let mut zero_word = witness(0);
                    zero_word[position] = alias.clone();
                    let meaning = execute(
                        script! {
                            { (family.generate)() } { u32::from(alias_is_zero) } OP_EQUAL
                        }
                        .compile_with_policy()
                        .to_bytes(),
                        zero_word,
                    );
                    assert!(meaning.success, "alias meaning at {position}: {meaning}");
                }
            }
        }
    }
}

#[test]
fn asymmetric_values_preserve_both_surrounding_stacks() {
    for family in FAMILIES {
        for x in [0u32, 1, 65536, 0x12345678, 0xfedcba98] {
            let expected = if family.canonical {
                x % 65537
            } else {
                u32::from(x == 0)
            };
            let leaf = script! {
                OP_TOALTSTACK
                { (family.generate)() } {expected} OP_EQUALVERIFY
                99 OP_EQUALVERIFY OP_FROMALTSTACK 77 OP_EQUALVERIFY OP_TRUE
            }
            .compile_with_policy()
            .to_bytes();
            let data = std::iter::once(vec![99])
                .chain(witness(x))
                .chain(std::iter::once(vec![77]))
                .collect();
            let result = execute(leaf, data);
            assert!(result.success, "{} x={x:x}: {result}", family.name);
            assert_eq!(result.final_stack.len(), 1);
        }
    }
}

#[test]
fn exact_fragment_resource_boundaries_include_runtime_main_and_alt_state() {
    for family in FAMILIES {
        let max_preserved = 1000 - family.peak;
        for alt_items in [0, 1, 3] {
            let main_items = max_preserved - alt_items;
            let leaf = script! {
                for _ in 0..alt_items {OP_TOALTSTACK}
                {(family.generate)()}
                for _ in 0..alt_items {OP_FROMALTSTACK}
            }
            .compile_with_policy()
            .to_bytes();
            let data: Vec<_> = std::iter::repeat_n(vec![99], main_items as usize)
                .chain(witness(0))
                .chain(std::iter::repeat_n(vec![77], alt_items as usize))
                .collect();
            let result = execute(leaf.clone(), data.clone());
            assert!(result.error.is_none(), "{}: {result}", family.name);
            assert_eq!(
                result.stats.max_nb_stack_items, 1000,
                "{} alt={alt_items}",
                family.name
            );
            assert_eq!(result.final_stack.len(), max_preserved as usize + 1);
            for i in 0..main_items {
                assert_eq!(result.final_stack.get(i as usize), vec![99]);
            }
            assert_eq!(
                result.final_stack.get(main_items as usize),
                scriptnum(if family.canonical { 0 } else { 1 })
            );
            for i in 0..alt_items {
                assert_eq!(
                    result.final_stack.get((main_items + 1 + i) as usize),
                    vec![77]
                );
            }
            let overflow = std::iter::once(vec![99]).chain(data).collect();
            rejects(&execute(leaf, overflow), ExecError::StackSize);
        }
    }
}

fn remove_pattern(bytes: &[u8], check: Script, count: usize) -> Vec<u8> {
    let pattern = check.compile_with_policy().to_bytes();
    let mut mutated = bytes.to_vec();
    let mut removed = 0;
    while let Some(index) = mutated.windows(pattern.len()).position(|w| w == pattern) {
        mutated.drain(index..index + pattern.len());
        removed += 1;
    }
    assert_eq!(removed, count, "pattern={pattern:?}");
    // Each generated validation sequence contains only opcodes and small
    // constants; ensure the resulting mutation still parses as instructions.
    assert!(ScriptBuf::from_bytes(mutated.clone())
        .instructions()
        .all(|x| x.is_ok()));
    mutated
}

#[test]
fn actual_validation_mutations_are_detected_by_the_same_rejection_assertions() {
    for family in FAMILIES {
        let original = clean((family.generate)());
        let checks = if family.canonical {
            vec![
                (
                    script! {OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY},
                    vec![1, 0],
                    ExecError::EqualVerify,
                    4,
                ),
                (
                    script! {OP_DUP 0 256 OP_WITHIN OP_VERIFY},
                    scriptnum(256),
                    ExecError::Verify,
                    if family.name == "bitwise-horner" {
                        8
                    } else {
                        4
                    },
                ),
            ]
        } else {
            vec![(
                script! {OP_DUP 256 OP_LESSTHAN OP_VERIFY},
                scriptnum(256),
                ExecError::Verify,
                4,
            )]
        };
        for (check, bad, error, count) in checks {
            let mutated = remove_pattern(&original, check, count);
            assert!(execute(mutated.clone(), witness(0x12345678)).success);
            for position in 0..4 {
                let mut data = witness(0x12345678);
                data[position] = bad.clone();
                rejects(&execute(original.clone(), data.clone()), error.clone());
                let result = execute(mutated.clone(), data);
                assert!(
                    result.success,
                    "{} mutated control at {position}: {result}",
                    family.name
                );
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rejects(
                        &result,
                        error.clone()
                    )))
                    .is_err()
                );
            }
        }
    }
}

#[test]
fn report_binds_exact_policy_artifacts_and_embedded_dependency_pins() {
    use bitcoin::{
        consensus::encode::serialize,
        hashes::{sha256, Hash},
        Witness,
    };
    use bitcoin_lab::support::provenance;
    let report: serde_json::Value =
        serde_json::from_str(include_str!("../research/u32-fermat-residue/metrics.json")).unwrap();
    assert_eq!(
        report["compiler_source"],
        provenance::compiler().unwrap().source
    );
    assert_eq!(
        report["interpreter_source"],
        provenance::interpreter().unwrap().source
    );
    for record in report["records"].as_array().unwrap() {
        let fragment = match record["name"].as_str().unwrap() {
            "paired-lanes" => u32_mod65537(),
            "bitwise-horner" => baseline::bitwise_horner(),
            name => panic!("unknown algorithm {name}"),
        };
        let expected = 0x89abcdefu32 % 65537;
        let compiled = fragment.clone().compile_with_policy();
        let leaf = script! {{fragment}{expected} OP_EQUAL}.compile_with_policy();
        let data = witness(0x89abcdef);
        let serialized = serialize(&Witness::from_slice(&data));
        let result = execute(leaf.to_bytes(), data);
        assert!(result.success);
        assert_eq!(result.final_stack.len(), 1);
        assert_eq!(record["fragment_bytes"], compiled.len());
        assert_eq!(record["leaf_bytes"], leaf.len());
        assert_eq!(
            record["fragment_sha256"],
            sha256::Hash::hash(compiled.as_bytes()).to_string()
        );
        assert_eq!(
            record["leaf_sha256"],
            sha256::Hash::hash(leaf.as_bytes()).to_string()
        );
        assert_eq!(
            record["witness_sha256"],
            sha256::Hash::hash(&serialized).to_string()
        );
        assert_eq!(record["witness_bytes"], serialized.len());
        assert_eq!(record["expected_residue"], expected);
        assert_eq!(record["combined_peak"], result.stats.max_nb_stack_items);
        assert_eq!(record["data_items"], 4);
        assert_eq!(record["hint_items"], 0);
    }
}

#[test]
fn wrong_expected_residue_is_rejected_and_terminal_binding_mutation_is_caught() {
    let value = 0x89abcdefu32;
    for generate in [u32_mod65537 as fn() -> Script, baseline::bitwise_horner] {
        let control = script! { { generate() } { value % 65537 } OP_EQUALVERIFY OP_TRUE }
            .compile_with_policy()
            .to_bytes();
        assert!(execute(control, witness(value)).success);
        let original = script! { { generate() } { value % 65537 + 1 } OP_EQUALVERIFY OP_TRUE }
            .compile_with_policy()
            .to_bytes();
        rejects(
            &execute(original.clone(), witness(value)),
            ExecError::EqualVerify,
        );
        let mut mutated = original;
        // The last EQUALVERIFY is the consumer's residue binding, not one
        // of the four canonical byte checks. Replace it with correct cleanup.
        let binding = mutated.iter().rposition(|&byte| byte == 0x88).unwrap();
        assert_eq!(&mutated[binding..], &[0x88, 0x51]);
        mutated[binding] = 0x6d; // OP_2DROP instead of OP_EQUALVERIFY
        let result = execute(mutated, witness(value));
        assert!(result.success);
        assert_eq!(result.final_stack.len(), 1);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rejects(
                &result,
                ExecError::EqualVerify
            )))
            .is_err()
        );
    }
}
