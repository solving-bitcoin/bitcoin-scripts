//! Encode a distinct nibble set as one canonical numeric mask.

use super::{
    one_hot::{table::push_one_hot_table, U4_ONE_HOT_TABLE_ITEMS},
    stack::{u4_drop, verify_canonical_nibble},
};
use crate::support::script::*;

mod fold;
use fold::sum_one_hot;

const MAX_MASK: u32 = (1 << U4_ONE_HOT_TABLE_ITEMS) - 1;

/// Consume `n` canonical nibbles and return the set mask with bit `x` set
/// for every input value `x`. Repeated values fail verification.
/// `n` must be in `0..=16`. Both caller stacks are preserved for an exact
/// input suffix. There are no hints. Nonempty peak is at most `n + 20`
/// plus preserved caller state.
pub fn u4_distinct_to_set_mask(n: u32) -> Script {
    assert!(
        n <= U4_ONE_HOT_TABLE_ITEMS,
        "distinct mask requires 0..=16 nibbles"
    );
    script! {
        {sum_one_hot(n)}
        if n == U4_ONE_HOT_TABLE_ITEMS {
            // A full distinct domain has the only possible 16-bit weight-16 mask.
            OP_DUP {MAX_MASK} OP_EQUALVERIFY
        } else if n > 1 {
            OP_DUP {MAX_MASK} OP_LESSTHANOREQUAL OP_VERIFY
            OP_DUP OP_TOALTSTACK
            0 OP_SWAP
            for bit in (1..U4_ONE_HOT_TABLE_ITEMS).rev() {
                OP_DUP {1u32 << bit} OP_GREATERTHANOREQUAL
                OP_IF
                    {1u32 << bit} OP_SUB
                    OP_SWAP OP_1ADD OP_SWAP
                OP_ENDIF
            }
            // Remainder is the low bit and contributes directly to weight.
            OP_ADD {n} OP_NUMEQUALVERIFY
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::test_helpers::{assert_clean_true, run_tapscript, scriptnum},
        support::tapscript::TapscriptProfile,
    };
    use bitcoin::ScriptBuf;
    use bitcoin_scriptexec::ExecError;

    mod baseline {
        use crate::{
            arithmetic::u4::{
                one_hot::U4_ONE_HOT_TABLE_ITEMS,
                stack::{u4_drop, verify_canonical_nibble},
            },
            support::script::*,
        };
        include!("../../../../research/carry-distinct-u4/baseline.rs");
    }

    const PROFILE: TapscriptProfile = TapscriptProfile::Consensus;
    const GENERATORS: [fn(u32) -> Script; 2] = [u4_distinct_to_set_mask, baseline::pairwise_mask];

    fn leaf(fragment: Script, mask: u32) -> ScriptBuf {
        script! {{fragment} {mask} OP_EQUALVERIFY OP_TRUE}.compile_with_policy()
    }

    fn data(values: &[u32]) -> Vec<Vec<u8>> {
        values
            .iter()
            .map(|&value| scriptnum(i64::from(value)))
            .collect()
    }

    fn check_case(n: u32, values: &[u32]) {
        use std::collections::BTreeSet;

        let set: BTreeSet<_> = values.iter().copied().collect();
        let mask: u32 = set.iter().map(|&v| 1 << v).sum();
        for generate in GENERATORS {
            let result = run_tapscript(leaf(generate(n), mask), data(values), PROFILE);
            if set.len() == values.len() {
                assert_clean_true(&result);
            } else {
                assert!(!result.success);
            }
        }
    }

    #[test]
    fn matches_independent_set_model() {
        check_case(0, &[]);
        for a in 0..16 {
            check_case(1, &[a]);
            for b in 0..16 {
                check_case(2, &[a, b]);
            }
        }
        for n in 3..=5u32 {
            for mut code in 0..3u32.pow(n) {
                let values: Vec<_> = (0..n)
                    .map(|_| {
                        let v = [0, 7, 15][code as usize % 3];
                        code /= 3;
                        v
                    })
                    .collect();
                check_case(n, &values);
            }
        }
        for n in 3..=16u32 {
            let mut values: Vec<_> = (0..n).map(|i| (i * 7 + 3) % 16).collect();
            check_case(n, &values);
            for position in 0..n as usize {
                let old = values[position];
                values[position] = values[(position + 1) % n as usize];
                check_case(n, &values);
                values[position] = old;
            }
        }
    }

    #[test]
    fn rejects_malformed_items_wrong_masks_and_input_counts() {
        let values = [0, 1, 2, 15];
        let expected = 32775;
        for generate in GENERATORS {
            let fragment = generate(4);
            let script = leaf(fragment.clone(), expected);
            assert_clean_true(&run_tapscript(script.clone(), data(&values), PROFILE));
            for position in 0..4 {
                for (bad, error) in [
                    (scriptnum(-1), ExecError::Verify),
                    (scriptnum(16), ExecError::Verify),
                    (vec![0x80], ExecError::EqualVerify),
                    (vec![1, 0], ExecError::EqualVerify),
                    (vec![0; 5], ExecError::ScriptIntNumericOverflow),
                    (vec![0; 521], ExecError::PushSize),
                ] {
                    let mut input = data(&values);
                    input[position] = bad;
                    assert_eq!(
                        run_tapscript(script.clone(), input, PROFILE).error,
                        Some(error)
                    );
                }
            }
            assert!(!run_tapscript(leaf(fragment, expected ^ 3), data(&values), PROFILE).success);
            let mut short = data(&values);
            short.pop();
            assert!(!run_tapscript(script.clone(), short, PROFILE).success);
            let mut long = data(&values);
            long.insert(0, vec![0x80]);
            assert!(!run_tapscript(script, long, PROFILE).success);
        }
        assert!(std::panic::catch_unwind(|| u4_distinct_to_set_mask(17)).is_err());
    }

    #[test]
    fn binds_weight_and_rejects_arithmetic_carries() {
        let input = data(&[0, 0, 2]);
        assert_clean_true(&run_tapscript(
            leaf(sum_one_hot(3), 6),
            input.clone(),
            PROFILE,
        ));
        assert!(!run_tapscript(leaf(u4_distinct_to_set_mask(3), 6), input, PROFILE).success);
        assert!(
            !run_tapscript(
                leaf(u4_distinct_to_set_mask(2), 65536),
                data(&[15, 15]),
                PROFILE
            )
            .success
        );
        assert!(
            !run_tapscript(
                leaf(u4_distinct_to_set_mask(16), 524288),
                data(&[15; 16]),
                PROFILE
            )
            .success
        );
    }

    #[test]
    fn preserves_surrounding_items_at_the_exact_combined_limit() {
        let n = 16;
        let script = script! {
            OP_TOALTSTACK {u4_distinct_to_set_mask(n)} OP_FROMALTSTACK
        }
        .compile_with_policy();
        let main = vec![0x91, 0x36];
        let alt = vec![0x82, 0x42];
        let mut input = vec![main.clone(); 963];
        input.extend(data(&(0..n).collect::<Vec<_>>()));
        input.push(alt.clone());
        let result = run_tapscript(script.clone(), input.clone(), PROFILE);
        assert_eq!(result.error, None);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        assert_eq!(result.final_stack.len(), 965);
        for i in 0..963 {
            assert_eq!(result.final_stack.get(i), main);
        }
        assert_eq!(result.final_stack.get(963), scriptnum(65535));
        assert_eq!(result.final_stack.get(964), alt);
        input.insert(0, vec![]);
        assert_eq!(
            run_tapscript(script, input, PROFILE).error,
            Some(ExecError::StackSize)
        );
    }
}
