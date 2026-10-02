//! Shared hostile-witness contract for canonical, consuming nibble reducers.
use bitcoin_lab::arithmetic::u4::{mod17, sum};
use bitcoin_lab::support::execution::ExecuteInfo;
use bitcoin_lab::support::script::{script, Script, ScriptCompilation};
use bitcoin_lab::support::tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile};
use bitcoin_scriptexec::ExecError;

fn execute_consensus_fragment(bytes: Vec<u8>, witness: Vec<Vec<u8>>) -> ExecuteInfo {
    match execute_tapscript(
        bitcoin::ScriptBuf::from_bytes(bytes),
        witness,
        TapscriptProfile::Consensus,
    )
    .outcome
    {
        TapscriptOutcome::Executed(result) => result,
        outcome => panic!("unexpected local outcome: {outcome:?}"),
    }
}

#[path = "../research/u4-mod17/baseline.rs"]
mod baseline;

type Reducer = fn(u32) -> Script;
const REDUCERS: [(&str, Reducer); 3] = [
    ("mod17", mod17::u4_nibbles_to_mod17),
    ("mod16-sum", sum::u4_nibbles_to_sum_mod16),
    ("forward-mod17", baseline::forward_horner),
];

fn run(fragment: Script, witness: Vec<Vec<u8>>) -> ExecuteInfo {
    execute_consensus_fragment(
        script! { { fragment } OP_DROP OP_TRUE }
            .compile_with_policy()
            .to_bytes(),
        witness,
    )
}

fn rejects(result: &ExecuteInfo, expected: ExecError) {
    assert_eq!(result.error, Some(expected), "wrong failure: {result}");
    assert!(!result.success);
}

#[test]
fn every_position_rejects_hostile_witnesses_with_valid_controls() {
    for (name, reducer) in REDUCERS {
        let fragment = reducer(4);
        let valid = vec![vec![1], vec![7], vec![], vec![15]];
        assert!(
            run(fragment.clone(), valid.clone()).success,
            "{name} control"
        );
        for (bad, error) in [
            (vec![0x81], ExecError::Verify),
            (vec![16], ExecError::Verify),
            (vec![255, 255, 255, 127], ExecError::Verify),
            (vec![0], ExecError::EqualVerify),
            (vec![0x80], ExecError::EqualVerify),
            (vec![1, 0], ExecError::EqualVerify),
            (vec![15, 0, 0, 0], ExecError::EqualVerify),
            (vec![0; 5], ExecError::ScriptIntNumericOverflow),
            (vec![0; 521], ExecError::PushSize),
        ] {
            for position in 0..4 {
                let mut witness = valid.clone();
                witness[position] = bad.clone();
                rejects(&run(fragment.clone(), witness), error.clone());
            }
        }
        for length in 0..4 {
            rejects(
                &run(fragment.clone(), valid[..length].to_vec()),
                ExecError::InvalidStackOperation,
            );
        }
    }
}

#[test]
fn asymmetric_outputs_and_both_preserved_stacks() {
    for (name, reducer) in REDUCERS {
        let digits = [1u8, 7, 2, 15];
        let expected = if name == "mod16-sum" { 9 } else { 2 };
        let result = execute_consensus_fragment(
            script! {
                77 OP_TOALTSTACK
                { reducer(4) } { expected } OP_EQUALVERIFY
                99 OP_EQUALVERIFY
                OP_FROMALTSTACK 77 OP_EQUALVERIFY OP_TRUE
            }
            .compile_with_policy()
            .to_bytes(),
            std::iter::once(vec![99])
                .chain(digits.map(|x| vec![x]))
                .collect(),
        );
        assert!(result.success, "{name}: {result}");
        assert_eq!(result.final_stack.len(), 1);
    }
}

#[test]
fn exact_mod17_combined_stack_frontier_uses_observable_output() {
    for n in [1, 2, 32, 500, mod17::U4_MOD17_MAX_BATCH] {
        let allowance = 1000 - n - 3;
        for alt_items in [0, 1] {
            if allowance < alt_items {
                continue;
            }
            let main_items = allowance - alt_items;
            let leaf = script! {
                for _ in 0..alt_items { OP_TOALTSTACK }
                { mod17::u4_nibbles_to_mod17(n) }
                for _ in 0..alt_items { OP_FROMALTSTACK }
            }
            .compile_with_policy()
            .to_bytes();
            let witness: Vec<_> = std::iter::repeat_n(vec![99], main_items as usize)
                .chain(std::iter::repeat_n(Vec::new(), n as usize))
                .chain(std::iter::repeat_n(vec![77], alt_items as usize))
                .collect();
            let accepted = execute_consensus_fragment(leaf.clone(), witness.clone());
            assert!(
                accepted.error.is_none(),
                "n={n} alt={alt_items}: {accepted}"
            );
            assert_eq!(
                accepted.final_stack.len(),
                (main_items + 1 + alt_items) as usize
            );
            for index in 0..main_items {
                assert_eq!(accepted.final_stack.get(index as usize), vec![99]);
            }
            assert_eq!(
                accepted.final_stack.get(main_items as usize),
                Vec::<u8>::new()
            );
            for index in 0..alt_items {
                assert_eq!(
                    accepted.final_stack.get((main_items + 1 + index) as usize),
                    vec![77]
                );
            }
            assert_eq!(
                accepted.stats.max_nb_stack_items, 1000,
                "n={n} alt={alt_items}"
            );
            let mut overflow = vec![vec![99]];
            overflow.extend(witness);
            rejects(
                &execute_consensus_fragment(leaf, overflow),
                ExecError::StackSize,
            );
        }
    }
}

#[test]
fn deliberate_validation_mutations_are_caught_by_the_same_rejection_assertion() {
    // Mutate the actual policy-produced fragments for every checked family.
    for (name, reducer) in REDUCERS {
        let original = script! { { reducer(4) } OP_DROP OP_TRUE }
            .compile_with_policy()
            .to_bytes();
        for (check, bad, expected) in [
            (
                script! { OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY },
                vec![1, 0],
                ExecError::EqualVerify,
            ),
            (
                script! { OP_DUP 0 16 OP_WITHIN OP_VERIFY },
                vec![16],
                ExecError::Verify,
            ),
        ] {
            let pattern = check.compile_with_policy().to_bytes();
            let mut mutated = original.clone();
            let mut count = 0;
            while let Some(index) = mutated.windows(pattern.len()).position(|w| w == pattern) {
                mutated.drain(index..index + pattern.len());
                count += 1;
            }
            assert_eq!(
                count, 4,
                "{name}: each validation must be mutated, pattern={pattern:?}"
            );
            assert!(execute_consensus_fragment(mutated.clone(), vec![vec![1]; 4]).success);
            for position in 0..4 {
                let mut witness = vec![vec![1]; 4];
                witness[position] = bad.clone();
                rejects(
                    &execute_consensus_fragment(original.clone(), witness.clone()),
                    expected.clone(),
                );
                let result = execute_consensus_fragment(mutated.clone(), witness);
                assert!(
                    result.success,
                    "{name}: mutation must be executable: {result}"
                );
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rejects(
                        &result,
                        expected.clone()
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
        serde_json::from_str(include_str!("../research/u4-mod17/metrics.json")).unwrap();
    assert_eq!(
        report["compiler_source"],
        provenance::compiler().unwrap().source
    );
    assert_eq!(
        report["interpreter_source"],
        provenance::interpreter().unwrap().source
    );
    for record in report["records"].as_array().unwrap() {
        let n = record["nibble_count"].as_u64().unwrap() as u32;
        let values: Vec<_> = (0..n).map(|i| ((7 * i + i / 3) % 16) as u8).collect();
        let expected = values
            .iter()
            .fold(0u32, |r, &x| (16 * r + u32::from(x)) % 17);
        let witness: Vec<_> = values
            .into_iter()
            .map(|x| if x == 0 { vec![] } else { vec![x] })
            .collect();
        let fragment = match record["name"].as_str().unwrap() {
            "reverse-fold" => mod17::u4_nibbles_to_mod17(n),
            "forward-horner" => baseline::forward_horner(n),
            name => panic!("unknown measured construction {name}"),
        };
        let compiled = fragment.clone().compile_with_policy();
        let leaf = script! { { fragment } { expected } OP_EQUAL }.compile_with_policy();
        assert_eq!(record["fragment_bytes"], compiled.len());
        assert_eq!(
            record["fragment_sha256"],
            sha256::Hash::hash(compiled.as_bytes()).to_string()
        );
        assert_eq!(record["leaf_bytes"], leaf.len());
        assert_eq!(
            record["leaf_sha256"],
            sha256::Hash::hash(leaf.as_bytes()).to_string()
        );
        assert_eq!(
            record["witness_bytes"],
            serialize(&Witness::from_slice(&witness)).len()
        );
        assert_eq!(
            record["witness_sha256"],
            sha256::Hash::hash(&serialize(&Witness::from_slice(&witness))).to_string()
        );
        assert_eq!(record["expected"], expected);
        assert_eq!(record["hint_items"], 0);
    }
}
