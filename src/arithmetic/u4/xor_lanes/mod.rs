//! Zero-hint XOR reduction via parity of packed ScriptNum lane counts.

use super::stack::{u4_drop, verify_canonical_nibble};
use crate::support::script::*;

pub const MAX_INPUTS: u32 = 254;
const TABLE_ITEMS: u32 = 16;
const MAX_UNSIGNED_INPUTS: u32 = 127;

/// Consume `n` canonical nibbles and return their XOR as a canonical nibble.
/// Requires `1..=254` inputs and zero hints. For an exact suffix, both caller
/// stacks are preserved. Peak is at most `n + 20` plus caller state.
pub fn u4_xor_packed_lanes(n: u32) -> Script {
    assert!(
        (1..=MAX_INPUTS).contains(&n),
        "packed XOR requires 1..=254 nibbles"
    );
    if n == 1 {
        return verify_canonical_nibble();
    }

    let lane_bits = u32::BITS - n.leading_zeros();
    let signed = n > MAX_UNSIGNED_INPUTS;
    let top_bias = if signed { n / 2 } else { 0 };
    let initial = -(i64::from(top_bias) << (3 * lane_bits));
    let decoded_bits = if signed { 31 } else { 4 * lane_bits };
    let invert_top = top_bias % 2 != 0;

    script! {
        {sum_weights(n, lane_bits, initial)}
        if signed {
            // For negative S add 2^31 in two numeric-safe steps.
            OP_DUP 0 OP_LESSTHAN
            OP_IF
                {1u32 << 30} OP_ADD
                {1u32 << 30} OP_ADD
            OP_ENDIF
        }
        {if invert_top {8} else {0}} OP_SWAP
        for bit in (1..decoded_bits).rev() {
            OP_DUP {1u32 << bit} OP_GREATERTHANOREQUAL
            OP_IF
                {1u32 << bit} OP_SUB
                if bit % lane_bits == 0 {
                    OP_SWAP {1u32 << (bit / lane_bits)}
                    if bit == 3 * lane_bits && invert_top {OP_SUB}
                    else {OP_ADD}
                    OP_SWAP
                }
            OP_ENDIF
        }
        OP_ADD
    }
}

fn sum_weights(n: u32, lane_bits: u32, initial: i64) -> Script {
    script! {
        for nibble in (0..16u32).rev() {
            {(0..4).map(|i| ((nibble >> i) & 1) << (i * lane_bits)).sum::<u32>()}
        }
        {initial}
        for _ in 0..n {
            {TABLE_ITEMS + 1} OP_ROLL {verify_canonical_nibble()}
            OP_1ADD OP_PICK OP_ADD
        }
        OP_TOALTSTACK {u4_drop(TABLE_ITEMS)} OP_FROMALTSTACK
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
                logic::{
                    u4_drop_half_lookup, u4_drop_half_table, u4_half_table_operation,
                    u4_push_full_xor_table, u4_push_half_lookup, u4_push_half_xor_table,
                },
                stack::{u4_drop, verify_canonical_nibble},
                xor_reduce::U4_XOR_TABLE_ITEMS,
            },
            support::script::*,
        };
        include!("../../../../research/signed-xor-lanes/baseline.rs");
    }

    const PROFILE: TapscriptProfile = TapscriptProfile::Consensus;
    const GENERATORS: [fn(u32) -> Script; 3] = [
        u4_xor_packed_lanes,
        baseline::full_table,
        baseline::triangular_table,
    ];

    fn leaf(fragment: Script, expected: u32) -> ScriptBuf {
        script! {{fragment} {expected} OP_EQUALVERIFY OP_TRUE}.compile_with_policy()
    }

    fn data(values: &[u32]) -> Vec<Vec<u8>> {
        values
            .iter()
            .map(|&value| scriptnum(i64::from(value)))
            .collect()
    }

    #[test]
    fn agrees_with_host_xor_at_signed_and_unsigned_boundaries() {
        let mut cases = Vec::new();
        for a in 0..16 {
            cases.push(vec![a]);
            for b in 0..16 {
                cases.push(vec![a, b]);
            }
        }
        for n in [3, 16, 64, 127, 128, 129, 130, 131, 212, 253, 254] {
            cases.push(
                (0..n)
                    .map(|i| ((i * 7 + 5 * (i / 3)) % 16) as u32)
                    .collect(),
            );
            for value in [0, 7, 8, 15] {
                cases.push(vec![value; n]);
            }
        }
        let mut leaves = std::collections::BTreeMap::new();
        for values in cases {
            let expected = values.iter().fold(0, |acc, &x| acc ^ x);
            let n = values.len() as u32;
            let scripts = leaves.entry(n).or_insert_with(|| {
                GENERATORS.map(|generate| {
                    script! {
                        OP_TOALTSTACK {generate(n)}
                        OP_FROMALTSTACK OP_EQUALVERIFY OP_TRUE
                    }
                    .compile_with_policy()
                })
            });
            let mut witness = data(&values);
            witness.push(scriptnum(i64::from(expected)));
            for script in scripts {
                assert_clean_true(&run_tapscript(script.clone(), witness.clone(), PROFILE));
            }
        }
    }

    #[test]
    fn rejects_malformed_items_wrong_outputs_and_counts() {
        let values = [1, 2, 15, 4];
        let expected = 8;
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
            assert!(!run_tapscript(leaf(fragment, expected ^ 1), data(&values), PROFILE).success);
            let mut short = data(&values);
            short.pop();
            assert!(!run_tapscript(script.clone(), short, PROFILE).success);
            let mut long = data(&values);
            long.insert(0, vec![]);
            assert!(!run_tapscript(script, long, PROFILE).success);
        }
    }

    #[test]
    fn unsigned_overflow_and_expected_xor_collisions() {
        let unsigned =
            script! {{sum_weights(128,8,0)} 0 OP_GREATERTHANOREQUAL}.compile_with_policy();
        assert_eq!(
            run_tapscript(unsigned, data(&[15; 128]), PROFILE).error,
            Some(ExecError::ScriptIntNumericOverflow)
        );
        let collision = leaf(u4_xor_packed_lanes(4), 0);
        for values in [[0; 4], [3, 9, 3, 9]] {
            assert_clean_true(&run_tapscript(collision.clone(), data(&values), PROFILE));
        }
        for width in [0, MAX_INPUTS + 1] {
            assert!(std::panic::catch_unwind(|| u4_xor_packed_lanes(width)).is_err());
        }
    }

    #[test]
    fn preserves_both_stacks_at_the_exact_combined_limit() {
        let script = script! {
            OP_TOALTSTACK {u4_xor_packed_lanes(MAX_INPUTS)} OP_FROMALTSTACK
        }
        .compile_with_policy();
        let main = vec![0x01, 0x00];
        let alt = vec![0x80];
        let mut witness = vec![main.clone(); 725];
        witness.extend(vec![scriptnum(15); MAX_INPUTS as usize]);
        witness.push(alt.clone());
        let result = run_tapscript(script.clone(), witness.clone(), PROFILE);
        assert_eq!(result.error, None);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        assert_eq!(result.final_stack.len(), 727);
        for index in 0..725 {
            assert_eq!(result.final_stack.get(index), main);
        }
        assert!(result.final_stack.get(725).is_empty());
        assert_eq!(result.final_stack.get(726), alt);
        witness.insert(0, vec![]);
        assert_eq!(
            run_tapscript(script, witness, PROFILE).error,
            Some(ExecError::StackSize)
        );
    }
}
