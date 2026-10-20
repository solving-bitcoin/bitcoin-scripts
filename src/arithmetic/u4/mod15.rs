//! Table-free base-16 integer residue modulo 15 over canonical u4 limbs.
//!
//! Since 16 = 1 modulo 15, the residue is the digit sum modulo 15, independent
//! of digit order. Two reduction schedules are provided and compared.

use super::stack::verify_canonical_nibble;
use crate::support::script::*;

/// Standalone bound; combined preserved state must satisfy `n + 3 + p <= 1000`.
pub const U4_MOD15_MAX_BATCH: u32 = 997;

fn reduce_once() -> Script {
    script! {
        OP_DUP 15 OP_GREATERTHANOREQUAL
        OP_IF 15 OP_SUB OP_ENDIF
    }
}

/// Running schedule: one conditional subtraction after every addition.
///
/// Before: `preserved | nibble[0] ... nibble[n-1]`. After: `preserved | r` with
/// `r` the canonical residue of the integer in `0..=14`. Every input is checked
/// for range and minimal encoding.
pub fn u4_nibbles_to_mod15(nibble_count: u32) -> Script {
    assert!(
        (1..=U4_MOD15_MAX_BATCH).contains(&nibble_count),
        "modulo-15 batch out of range"
    );
    script! {
        { verify_canonical_nibble() }
        { reduce_once() }
        for _ in 1..nibble_count {
            OP_SWAP
            { verify_canonical_nibble() }
            OP_ADD
            { reduce_once() }
        }
    }
}

/// Sum-then-ladder schedule: add every nibble exactly, then subtract
/// `15 * 2^k` for `k` from `floor(log2 n)` down to zero.
pub fn u4_nibbles_to_mod15_ladder(nibble_count: u32) -> Script {
    assert!(
        (1..=U4_MOD15_MAX_BATCH).contains(&nibble_count),
        "modulo-15 batch out of range"
    );
    let top = 31 - nibble_count.leading_zeros();
    script! {
        { verify_canonical_nibble() }
        for _ in 1..nibble_count {
            OP_SWAP
            { verify_canonical_nibble() }
            OP_ADD
        }
        for level in (0..=top).rev() {
            OP_DUP { 15i64 << level } OP_GREATERTHANOREQUAL
            OP_IF { 15i64 << level } OP_SUB OP_ENDIF
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};
    use bitcoin_scriptexec::ExecError;

    type Make = fn(u32) -> Script;
    const SCHEDULES: [(&str, Make); 2] = [
        ("running", u4_nibbles_to_mod15),
        ("ladder", u4_nibbles_to_mod15_ladder),
    ];

    fn item(value: u8) -> Vec<u8> {
        if value == 0 {
            Vec::new()
        } else {
            vec![value]
        }
    }

    fn num(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let len = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..len].to_vec()
    }

    /// Conventional left-to-right base-16 evaluation, independent of the digit-sum identity.
    fn model(values: &[u8]) -> i64 {
        values
            .iter()
            .fold(0u64, |r, &x| (16 * r + u64::from(x)) % 15) as i64
    }

    fn compile(make: Make, len: usize) -> Vec<u8> {
        // The expected residue is the lowest witness item.
        script! { { make(len as u32) } OP_EQUAL }
            .compile_with_policy()
            .to_bytes()
    }

    fn run(compiled: &[u8], values: &[u8]) -> bool {
        let mut witness = vec![num(model(values))];
        witness.extend(values.iter().map(|&v| item(v)));
        let result = execute_raw_script_with_inputs_strict(compiled.to_vec(), witness);
        assert!(result.error.is_none(), "values {values:?}: {result}");
        result.success
    }

    #[test]
    fn exhaustive_one_two_and_three_digit_integers() {
        for (name, make) in SCHEDULES {
            for len in 1..=3usize {
                let compiled = compile(make, len);
                for code in 0..16u32.pow(len as u32) {
                    let values: Vec<u8> = (0..len)
                        .map(|i| ((code >> (4 * (len - 1 - i))) & 15) as u8)
                        .collect();
                    assert!(run(&compiled, &values), "{name} {values:?}");
                }
            }
        }
    }

    #[test]
    fn deterministic_longer_vectors_and_extremes() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for (name, make) in SCHEDULES {
            for len in [4usize, 7, 8, 16, 31, 32, 33, 64] {
                let compiled = compile(make, len);
                assert!(run(&compiled, &vec![15; len]), "{name} all-F {len}");
                assert!(run(&compiled, &vec![0; len]), "{name} zero {len}");
                for _ in 0..10 {
                    let values: Vec<u8> = (0..len)
                        .map(|_| {
                            state ^= state << 13;
                            state ^= state >> 7;
                            state ^= state << 17;
                            (state % 16) as u8
                        })
                        .collect();
                    assert!(run(&compiled, &values), "{name} {values:?}");
                }
            }
        }
    }

    #[test]
    fn transpositions_are_invisible_to_the_residue() {
        // Casting out fifteens cannot see a swap of two digits; document it with data.
        for (name, make) in SCHEDULES {
            let compiled = compile(make, 2);
            assert!(run(&compiled, &[1, 2]), "{name}");
            assert!(run(&compiled, &[2, 1]), "{name}");
            // Both orders have equal residues, so a transposition is invisible.
            assert_eq!(model(&[1, 2]), model(&[2, 1]));
        }
    }

    #[test]
    fn rejects_noncanonical_and_out_of_range_nibbles_at_every_position() {
        for (name, make) in SCHEDULES {
            let compiled = make(3);
            for bad in [vec![0x81u8], num(-1), num(16), vec![1, 0], vec![0x80]] {
                for position in 0..3 {
                    let mut witness: Vec<Vec<u8>> = vec![vec![5u8]; 3];
                    witness[position] = bad.clone();
                    let result = execute_raw_script_with_inputs_strict(
                        script! { { compiled.clone() } OP_DROP OP_TRUE }
                            .compile_with_policy()
                            .to_bytes(),
                        witness,
                    );
                    assert!(
                        result.error.is_some(),
                        "{name} accepted bad nibble {bad:?} at {position}"
                    );
                }
            }
        }
    }

    #[test]
    fn preserves_surrounding_state() {
        for (name, make) in SCHEDULES {
            let result = execute_script(script! {
                77 OP_TOALTSTACK
                99
                1 2 3
                { make(3) }
                { model(&[1, 2, 3]) } OP_EQUALVERIFY
                99 OP_EQUALVERIFY
                OP_FROMALTSTACK 77 OP_EQUALVERIFY
                OP_TRUE
            });
            assert!(result.success, "{name}: {result}");
        }
    }

    #[test]
    fn rejects_generation_bounds_and_stack_frontier_is_exact() {
        use crate::support::script::MAX_OPTIMIZER_INPUT_BYTES;
        for (name, make) in SCHEDULES {
            assert!(std::panic::catch_unwind(|| make(0)).is_err());
            assert!(std::panic::catch_unwind(|| make(U4_MOD15_MAX_BATCH + 1)).is_err());
            let run_at = |extra: usize| {
                let compiled = script! {
                    { make(U4_MOD15_MAX_BATCH) }
                    OP_DROP
                    for _ in 0..extra { OP_DROP }
                    OP_TRUE
                    for _ in 0..=MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
                }
                .compile_with_policy()
                .to_bytes();
                let mut witness = vec![vec![9u8]; extra];
                witness.extend(vec![vec![7u8]; U4_MOD15_MAX_BATCH as usize]);
                execute_raw_script_with_inputs_strict(compiled, witness)
            };
            let base = run_at(0);
            assert!(base.success, "{name}: {base}");
            let spare = 1_000 - base.stats.max_nb_stack_items;
            assert!(run_at(spare).success, "{name}");
            assert_eq!(
                run_at(spare + 1).error,
                Some(ExecError::StackSize),
                "{name}"
            );
        }
    }

    #[test]
    fn recorded_sizes_are_current() {
        use crate::arithmetic::u4::mod17::{u4_nibbles_to_mod17, u4_nibbles_to_mod17_delayed};
        // (n, mod15 running, mod15 ladder, mod17 running, mod17 delayed)
        for (n, run, ladder, m17, m17_delayed) in [
            (1u32, 17usize, 17usize, 10usize, 31usize),
            (4, 74, 71, 82, 80),
            (16, 302, 235, 334, 259),
            (32, 606, 438, 670, 467),
            (64, 1_214, 833, 1_342, 894),
            (128, 2_430, 1_612, 2_686, 1_737),
        ] {
            let measure = |script: Script| script.compile_with_policy().len();
            assert_eq!(measure(u4_nibbles_to_mod15(n)), run, "mod15 running {n}");
            assert_eq!(
                measure(u4_nibbles_to_mod15_ladder(n)),
                ladder,
                "mod15 ladder {n}"
            );
            assert_eq!(measure(u4_nibbles_to_mod17(n)), m17, "mod17 running {n}");
            assert_eq!(
                measure(u4_nibbles_to_mod17_delayed(n)),
                m17_delayed,
                "mod17 delayed {n}"
            );
        }
    }
}
