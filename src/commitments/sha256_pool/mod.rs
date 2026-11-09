//! Verify two distinct openings from one list of SHA-256 digests.

use crate::{arithmetic::scriptint::verify_canonical, support::script::*};

mod routing;
use routing::{check_rank, push_digests};
use std::collections::BTreeSet;

pub const MAX_DIGESTS: usize = 993;

/// Consume `second_preimage second_rank first_preimage first_rank` and
/// verify openings to distinct digests. The second rank indexes the list
/// after removal of the first digest. Ranks are canonical ScriptNums.
/// Requires 2 through 993 unique public digests. Leaves no result and
/// preserves both caller stacks for the exact four-item suffix.
/// Combined peak is `digests.len() + 7` plus preserved caller items.
pub fn verify_two_distinct_sha256_openings(digests: &[[u8; 32]]) -> Script {
    let n = digests.len();
    assert!(
        (2..=MAX_DIGESTS).contains(&n),
        "digest pool requires 2..=993 entries"
    );
    assert_eq!(
        digests.iter().collect::<BTreeSet<_>>().len(),
        n,
        "public digests must be unique"
    );

    script! {
        {push_digests(digests)}
        for remaining in [n, n - 1] {
            {remaining} OP_ROLL {check_rank(remaining)}
            OP_ROLL
            {remaining} OP_ROLL OP_SHA256 OP_EQUALVERIFY
        }
        for _ in 0..n-2 {OP_DROP}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{
        execution::ExecuteInfo,
        tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
    };
    use bitcoin::{
        hashes::{sha256, Hash},
        ScriptBuf,
    };
    use bitcoin_scriptexec::ExecError;

    mod baseline {
        use crate::{arithmetic::scriptint::verify_canonical, support::script::*};
        include!("../../../research/distinct-sha256-openings/baseline.rs");
    }

    mod fixture {
        use bitcoin::hashes::{sha256, Hash};
        include!("../../../research/distinct-sha256-openings/fixture.rs");
    }

    const GENERATORS: [fn(&[[u8; 32]]) -> Script; 3] = [
        verify_two_distinct_sha256_openings,
        baseline::fixed_indices,
        baseline::scan,
    ];

    fn leaf(fragment: Script) -> ScriptBuf {
        script! {{fragment} OP_TRUE}.compile_with_policy()
    }

    fn run(script: ScriptBuf, data: Vec<Vec<u8>>) -> ExecuteInfo {
        match execute_tapscript(script, data, TapscriptProfile::Consensus).outcome {
            TapscriptOutcome::Executed(result) => result,
            outcome => panic!("expected an execution: {outcome:?}"),
        }
    }

    fn assert_clean_true(result: &ExecuteInfo) {
        assert!(result.success, "{result}");
        assert!(result.stack_limit_enforced);
        assert_eq!(result.final_stack.len(), 1);
        assert_eq!(result.final_stack.get(0), vec![1]);
    }

    fn witnesses(first: &[u8], second: &[u8], i: usize, j: usize) -> [Vec<Vec<u8>>; 3] {
        let second_rank = j - usize::from(j > i);
        [
            vec![
                second.to_vec(),
                fixture::scriptnum(second_rank),
                first.to_vec(),
                fixture::scriptnum(i),
            ],
            vec![
                second.to_vec(),
                fixture::scriptnum(j),
                first.to_vec(),
                fixture::scriptnum(i),
            ],
            vec![second.to_vec(), first.to_vec()],
        ]
    }

    #[test]
    fn checks_all_ordered_pairs_and_rejects_repeated_openings() {
        for n in [2, 5, 17] {
            let (preimages, digests) = fixture::pool(n);
            let leaves = GENERATORS.map(|generate| leaf(generate(&digests)));
            for i in 0..n {
                for j in 0..n {
                    for (script, data) in
                        leaves
                            .iter()
                            .zip(witnesses(&preimages[i], &preimages[j], i, j))
                    {
                        let result = run(script.clone(), data);
                        if i == j {
                            assert!(!result.success);
                        } else {
                            assert_clean_true(&result);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn repeated_index_is_allowed_by_the_hors_opening_helper() {
        use crate::signatures::hors;

        let (preimages, digests) = fixture::pool(3);
        let public_keys = hors::hors_public_keys(&preimages);
        let indexed = hors::hors_locking_script(&public_keys, 2).compile_with_policy();
        let repeated = hors::hors_unlocking_witness(&preimages, &[1, 1]);
        assert_clean_true(&run(indexed, repeated));

        let [ranks, ..] = witnesses(&preimages[1], &preimages[1], 1, 1);
        let distinct = leaf(verify_two_distinct_sha256_openings(&digests));
        assert!(!run(distinct, ranks).success);
    }

    #[test]
    fn rejects_noncanonical_out_of_range_and_wrong_ranks() {
        let (preimages, digests) = fixture::pool(5);
        let scripts = GENERATORS.map(|generate| leaf(generate(&digests)));
        let original = witnesses(&preimages[0], &preimages[4], 0, 4);
        for schedule in 0..2 {
            let script = &scripts[schedule];
            assert_clean_true(&run(script.clone(), original[schedule].clone()));
            let second_limit = if schedule == 0 { 4 } else { 5 };
            for (position, limit) in [(1, second_limit), (3, 5)] {
                for (bad, error) in [
                    (vec![0x81], ExecError::Verify),
                    (fixture::scriptnum(limit), ExecError::Verify),
                    (vec![0x80], ExecError::EqualVerify),
                    (vec![1, 0], ExecError::EqualVerify),
                    (vec![0; 5], ExecError::ScriptIntNumericOverflow),
                    (vec![0; 521], ExecError::PushSize),
                ] {
                    let mut data = original[schedule].clone();
                    data[position] = bad;
                    assert_eq!(run(script.clone(), data).error, Some(error));
                }
            }
            let mut data = original[schedule].clone();
            data[1] = fixture::scriptnum(1);
            assert!(!run(script.clone(), data).success);
        }
        for (script, mut data) in scripts.iter().zip(original) {
            let mut bad = data.clone();
            bad[0][31] ^= 1;
            assert!(!run(script.clone(), bad).success);
            let mut short = data.clone();
            short.pop();
            assert!(!run(script.clone(), short).success);
            data.insert(0, vec![]);
            assert!(!run(script.clone(), data).success);
        }
    }

    #[test]
    fn accepts_opaque_boundaries_and_rejects_duplicate_public_digests() {
        let preimages = [vec![], vec![0x80; 520], vec![0x80; 521]];
        let digests: Vec<_> = preimages
            .iter()
            .map(|p| sha256::Hash::hash(p).to_byte_array())
            .collect();
        for (generate, data) in
            GENERATORS
                .into_iter()
                .zip(witnesses(&preimages[0], &preimages[1], 0, 1))
        {
            assert_clean_true(&run(leaf(generate(&digests)), data));
        }
        for (generate, data) in
            GENERATORS
                .into_iter()
                .zip(witnesses(&preimages[0], &preimages[2], 0, 2))
        {
            assert_eq!(
                run(leaf(generate(&digests)), data).error,
                Some(ExecError::PushSize)
            );
        }
        for bad in [
            vec![],
            vec![[0; 32]],
            vec![[0; 32], [0; 32]],
            vec![[0; 32]; MAX_DIGESTS + 1],
        ] {
            assert!(
                std::panic::catch_unwind(|| verify_two_distinct_sha256_openings(&bad)).is_err()
            );
        }
    }

    #[test]
    fn proves_combined_limit_and_preserves_exact_caller_state() {
        let (preimages, digests) = fixture::pool(MAX_DIGESTS);
        let closed = leaf(verify_two_distinct_sha256_openings(&digests));
        let [honest, ..] = witnesses(
            &preimages[1],
            &preimages[MAX_DIGESTS - 1],
            1,
            MAX_DIGESTS - 1,
        );
        let result = run(closed, honest);
        assert_clean_true(&result);
        assert_eq!(result.stats.max_nb_stack_items, 1000);

        let n = MAX_DIGESTS - 2;
        let (preimages, digests) = fixture::pool(n);
        let fragment = verify_two_distinct_sha256_openings(&digests);
        let script = script! {OP_TOALTSTACK {fragment} OP_FROMALTSTACK}.compile_with_policy();
        let main = digests[0].to_vec();
        let alt = vec![0x80];
        let [honest, ..] = witnesses(&preimages[1], &preimages[n - 1], 1, n - 1);
        let mut input = [vec![main.clone()], honest, vec![alt.clone()]].concat();
        let result = run(script.clone(), input.clone());
        assert_eq!(result.error, None);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        assert_eq!(result.final_stack.len(), 2);
        assert_eq!(result.final_stack.get(0), main);
        assert_eq!(result.final_stack.get(1), alt);
        let mut wrong_rank = input.clone();
        wrong_rank[4] = fixture::scriptnum(n);
        assert_eq!(
            run(script.clone(), wrong_rank).error,
            Some(ExecError::Verify)
        );
        input.insert(0, vec![]);
        assert_eq!(run(script, input).error, Some(ExecError::StackSize));
    }
}
