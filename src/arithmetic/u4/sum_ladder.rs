//! Modulo-16 nibble sum with delayed reduction and no lookup table.
//!
//! Same contract as [`super::sum::u4_nibbles_to_sum_mod16`], which keeps a
//! 31-entry table live and reduces after every addition. Here the sum stays
//! exact and a short ladder of conditional subtractions reduces it once.

use super::stack::verify_canonical_nibble;
use crate::support::script::*;

/// Standalone bound; the combined peak is `n + 3`.
pub const U4_SUM_LADDER_MAX_BATCH: u32 = 997;

/// Consume canonical nibbles and return their sum modulo 16.
///
/// Before: `preserved | nibble[0] ... nibble[n-1]`, last nibble on top. After:
/// `preserved | (sum mod 16)` in `0..=15`. Every input is checked for range and
/// minimal encoding; no hints, tables or altstack use.
pub fn u4_nibbles_to_sum_mod16_ladder(nibble_count: u32) -> Script {
    assert!(
        (1..=U4_SUM_LADDER_MAX_BATCH).contains(&nibble_count),
        "nibble-sum batch out of range"
    );
    // The exact sum is at most 15n; subtract 16 * 2^k, k from the top down.
    let max_sum = 15 * i64::from(nibble_count);
    let levels = if max_sum >= 16 {
        63 - ((max_sum / 16) as u64).leading_zeros() + 1
    } else {
        0
    };
    script! {
        { verify_canonical_nibble() }
        for _ in 1..nibble_count {
            OP_SWAP
            { verify_canonical_nibble() }
            OP_ADD
        }
        for level in (0..levels).rev() {
            OP_DUP { 16i64 << level } OP_GREATERTHANOREQUAL
            OP_IF { 16i64 << level } OP_SUB OP_ENDIF
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::u4::sum::u4_nibbles_to_sum_mod16;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};
    use bitcoin_scriptexec::ExecError;

    fn item(value: u8) -> Vec<u8> {
        if value == 0 {
            Vec::new()
        } else {
            vec![value]
        }
    }

    fn compile(len: usize) -> Vec<u8> {
        // The expected residue is the lowest witness item.
        script! { { u4_nibbles_to_sum_mod16_ladder(len as u32) } OP_EQUAL }
            .compile_with_policy()
            .to_bytes()
    }

    fn run(compiled: &[u8], values: &[u8]) -> bool {
        let expected = values.iter().map(|&v| u32::from(v)).sum::<u32>() % 16;
        let mut witness = vec![item(expected as u8)];
        witness.extend(values.iter().map(|&v| item(v)));
        let result = execute_raw_script_with_inputs_strict(compiled.to_vec(), witness);
        assert!(result.error.is_none(), "values {values:?}: {result}");
        result.success
    }

    #[test]
    fn exhaustive_for_up_to_three_nibbles() {
        for len in 1..=3usize {
            let compiled = compile(len);
            for code in 0..16u32.pow(len as u32) {
                let values: Vec<u8> = (0..len).map(|i| ((code >> (4 * i)) & 15) as u8).collect();
                assert!(run(&compiled, &values), "values {values:?}");
            }
        }
    }

    #[test]
    fn deterministic_longer_vectors_and_extremes() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for len in [4usize, 7, 8, 16, 17, 31, 32, 33, 64, 128] {
            let compiled = compile(len);
            assert!(run(&compiled, &vec![15; len]), "all-F {len}");
            assert!(run(&compiled, &vec![0; len]), "zero {len}");
            for _ in 0..10 {
                let values: Vec<u8> = (0..len)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        (state % 16) as u8
                    })
                    .collect();
                assert!(run(&compiled, &values), "values {values:?}");
            }
        }
    }

    #[test]
    fn agrees_with_the_table_schedule_on_the_same_vectors() {
        for values in [
            vec![1u8, 7, 8, 15, 2, 14, 3, 13],
            (0..16).collect::<Vec<u8>>(),
        ] {
            let expected: u32 = values.iter().map(|&v| u32::from(v)).sum::<u32>() % 16;
            for fragment in [
                u4_nibbles_to_sum_mod16(values.len() as u32),
                u4_nibbles_to_sum_mod16_ladder(values.len() as u32),
            ] {
                let result = execute_raw_script_with_inputs_strict(
                    script! { { fragment } { expected } OP_EQUAL }
                        .compile_with_policy()
                        .to_bytes(),
                    values.iter().map(|&v| item(v)).collect(),
                );
                assert!(result.success, "{result}");
            }
        }
    }

    #[test]
    fn recorded_sizes_are_current() {
        // (n, table bytes, ladder bytes)
        for (n, table, ladder) in [
            (1u32, 65usize, 10usize),
            (2, 82, 29),
            (4, 116, 62),
            (8, 184, 119),
            (16, 320, 226),
            (32, 592, 429),
            (64, 1_136, 824),
            (128, 2_224, 1_603),
        ] {
            let measure = |script: Script| script.compile_with_policy().len();
            assert_eq!(measure(u4_nibbles_to_sum_mod16(n)), table, "table {n}");
            assert_eq!(
                measure(u4_nibbles_to_sum_mod16_ladder(n)),
                ladder,
                "ladder {n}"
            );
        }
    }

    #[test]
    fn rejects_noncanonical_and_out_of_range_nibbles_at_every_position() {
        let compiled = script! { { u4_nibbles_to_sum_mod16_ladder(4) } OP_DROP OP_TRUE }
            .compile_with_policy()
            .to_bytes();
        let numbers = |value: i64| {
            let mut bytes = [0u8; 8];
            let len = bitcoin::script::write_scriptint(&mut bytes, value);
            bytes[..len].to_vec()
        };
        for bad in [
            numbers(-1),
            numbers(16),
            numbers(255),
            vec![1, 0],
            vec![0x80],
            vec![0, 0],
        ] {
            for position in 0..4 {
                let mut witness: Vec<Vec<u8>> = vec![vec![5u8]; 4];
                witness[position] = bad.clone();
                let result = execute_raw_script_with_inputs_strict(compiled.clone(), witness);
                assert!(
                    result.error.is_some(),
                    "accepted bad nibble {bad:?} at {position}"
                );
            }
        }
    }

    #[test]
    fn preserves_state_and_hits_the_stack_frontier() {
        use crate::support::script::MAX_OPTIMIZER_INPUT_BYTES;
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            1 2 3 4
            { u4_nibbles_to_sum_mod16_ladder(4) }
            10 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "{result}");
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_sum_mod16_ladder(0)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_to_sum_mod16_ladder(U4_SUM_LADDER_MAX_BATCH + 1)
        })
        .is_err());
        let run_at = |extra: usize| {
            let compiled = script! {
                { u4_nibbles_to_sum_mod16_ladder(U4_SUM_LADDER_MAX_BATCH) }
                OP_DROP
                for _ in 0..extra { OP_DROP }
                OP_TRUE
                for _ in 0..=MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
            }
            .compile_with_policy()
            .to_bytes();
            let mut witness = vec![vec![9u8]; extra];
            witness.extend(vec![vec![7u8]; U4_SUM_LADDER_MAX_BATCH as usize]);
            execute_raw_script_with_inputs_strict(compiled, witness)
        };
        let base = run_at(0);
        assert!(base.success, "{base}");
        let spare = 1_000 - base.stats.max_nb_stack_items;
        assert!(run_at(spare).success);
        assert_eq!(run_at(spare + 1).error, Some(ExecError::StackSize));
    }
}
