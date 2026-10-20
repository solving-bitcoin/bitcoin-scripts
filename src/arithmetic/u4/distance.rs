//! Distances between two checked u4 vectors.
//!
//! All fragments share one stack contract:
//! `preserved | a[0] ... a[n-1] | b[0] ... b[n-1]` becomes `preserved | distance`,
//! with the last `b` on top. Every nibble of both vectors is range-checked;
//! no hints are used.

use super::{logic::u4_push_full_xor_table, stack::u4_drop};
use crate::support::script::*;

/// Resident items of the fused Hamming table and of the composed XOR table.
pub const DISTANCE_TABLE_ITEMS: u32 = 256;

/// Largest vector length of the table-free metrics; the combined peak is `2n + 3`.
pub const DISTANCE_ARITHMETIC_MAX_LEN: u32 = 498;

/// Largest vector length of the fused table metric; the combined peak is `2n + 258`.
pub const DISTANCE_TABLE_MAX_LEN: u32 = 371;

/// Largest vector length of the composed XOR/popcount metric (`2n + 274` peak).
pub const DISTANCE_COMPOSED_MAX_LEN: u32 = 363;

fn range_check_all(count: u32) -> Script {
    script! {
        for _ in 0..count {
            OP_DUP 0 16 OP_WITHIN OP_VERIFY
            OP_TOALTSTACK
        }
    }
}

/// Table-free L1 (Manhattan) distance: the sum of `|a[i] - b[i]|`.
pub fn u4_nibbles_l1_distance(len: u32) -> Script {
    pairwise(len, script! { OP_SUB OP_ABS })
}

/// Table-free Lee distance on the cycle of 16: the sum of
/// `min(|a[i] - b[i]|, 16 - |a[i] - b[i]|)`.
pub fn u4_nibbles_lee_distance(len: u32) -> Script {
    pairwise(
        len,
        script! { OP_SUB OP_ABS OP_DUP 16 OP_SWAP OP_SUB OP_MIN },
    )
}

/// Sum a per-pair `[a, b] -> d` fragment over both vectors without tables.
fn pairwise(len: u32, combine: Script) -> Script {
    assert!(
        (1..=DISTANCE_ARITHMETIC_MAX_LEN).contains(&len),
        "length out of range"
    );
    script! {
        { range_check_all(2 * len) }
        for _ in 0..2 * len { OP_FROMALTSTACK }
        0
        for done in 0..len {
            // Stack top: acc, b[n-1-done], remaining b's, then a's.
            OP_SWAP
            { len - done + 1 } OP_ROLL
            // Stack top: a, b, acc.
            OP_SWAP
            { combine.clone() }
            OP_ADD
        }
    }
}

/// Hamming distance through one fused 256-entry table `T[16a + b] = popcount(a ^ b)`.
pub fn u4_nibbles_hamming_distance(len: u32) -> Script {
    assert!(
        (1..=DISTANCE_TABLE_MAX_LEN).contains(&len),
        "length out of range"
    );
    table_distance(len, hamming_table(), 0)
}

/// Hamming distance through the shared XOR table followed by a 16-entry popcount table.
pub fn u4_nibbles_hamming_distance_composed(len: u32) -> Script {
    assert!(
        (1..=DISTANCE_COMPOSED_MAX_LEN).contains(&len),
        "length out of range"
    );
    table_distance(len, u4_push_full_xor_table(), 16)
}

fn hamming_table() -> Script {
    script! {
        for a in (0..16u32).rev() {
            for b in (0..16u32).rev() {
                { (a ^ b).count_ones() }
            }
        }
    }
}

/// `extra_table` is the size of a second, popcount table pushed after the main one.
fn table_distance(len: u32, main_table: Script, extra_table: u32) -> Script {
    script! {
        { range_check_all(2 * len) }
        { main_table }
        if extra_table > 0 {
            for value in (0..16u32).rev() { { value.count_ones() } }
        }
        for _ in 0..2 * len { OP_FROMALTSTACK }
        0
        for done in 0..len {
            OP_SWAP
            { len - done + 1 } OP_ROLL
            // Stack top: a, b, acc. Form 16a + b.
            for _ in 0..4 { OP_DUP OP_ADD }
            OP_ADD
            // Items above the main table: acc + remaining a/b + (extra table).
            { 1 + 2 * (len - 1 - done) + extra_table } OP_ADD
            OP_PICK
            if extra_table > 0 {
                // Popcount of the XOR result: table is `extra_table` deep under acc and inputs.
                { 1 + 2 * (len - 1 - done) } OP_ADD
                OP_PICK
            }
            OP_ADD
        }
        OP_TOALTSTACK
        { u4_drop(DISTANCE_TABLE_ITEMS + extra_table) }
        OP_FROMALTSTACK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};
    use bitcoin_scriptexec::ExecError;

    type Make = fn(u32) -> Script;

    const ALL: [(&str, Make, fn(u8, u8) -> i64); 4] = [
        ("l1", u4_nibbles_l1_distance, l1),
        ("lee", u4_nibbles_lee_distance, lee),
        ("hamming", u4_nibbles_hamming_distance, hamming),
        (
            "hamming-composed",
            u4_nibbles_hamming_distance_composed,
            hamming,
        ),
    ];

    fn l1(a: u8, b: u8) -> i64 {
        i64::from(a.abs_diff(b))
    }

    fn lee(a: u8, b: u8) -> i64 {
        let d = i64::from(a.abs_diff(b));
        d.min(16 - d)
    }

    fn hamming(a: u8, b: u8) -> i64 {
        i64::from((a ^ b).count_ones())
    }

    fn item(value: u8) -> Vec<u8> {
        if value == 0 {
            Vec::new()
        } else {
            vec![value]
        }
    }

    fn expected(metric: fn(u8, u8) -> i64, a: &[u8], b: &[u8]) -> i64 {
        a.iter().zip(b).map(|(&x, &y)| metric(x, y)).sum()
    }

    fn compile(make: Make, len: usize) -> Vec<u8> {
        // The expected total is the lowest witness item, compared after the fragment.
        script! {
            { make(len as u32) }
            OP_EQUAL
        }
        .compile_with_policy()
        .to_bytes()
    }

    fn run_compiled(compiled: &[u8], a: &[u8], b: &[u8], want: i64) -> bool {
        let mut witness = vec![scriptnum_item(want)];
        witness.extend(a.iter().chain(b).map(|&v| item(v)));
        let result = execute_raw_script_with_inputs_strict(compiled.to_vec(), witness);
        assert!(result.error.is_none(), "{result}");
        result.success
    }

    fn run(make: Make, a: &[u8], b: &[u8], want: i64) -> bool {
        run_compiled(&compile(make, a.len()), a, b, want)
    }

    fn scriptnum_item(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let len = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..len].to_vec()
    }

    #[test]
    fn every_pair_matches_the_model_for_each_metric() {
        for (name, make, metric) in ALL {
            let compiled = compile(make, 1);
            for a in 0..16u8 {
                for b in 0..16u8 {
                    assert!(
                        run_compiled(&compiled, &[a], &[b], metric(a, b)),
                        "{name} a={a} b={b}"
                    );
                    assert!(
                        !run_compiled(&compiled, &[a], &[b], metric(a, b) + 1),
                        "{name} accepted a wrong total for a={a} b={b}"
                    );
                }
            }
        }
    }

    #[test]
    fn deterministic_vectors_match_the_model() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % 16) as u8
        };
        for (name, make, metric) in ALL {
            for len in [2usize, 3, 8, 16, 24] {
                for _ in 0..6 {
                    let a: Vec<u8> = (0..len).map(|_| next()).collect();
                    let b: Vec<u8> = (0..len).map(|_| next()).collect();
                    assert!(
                        run(make, &a, &b, expected(metric, &a, &b)),
                        "{name} {a:?} {b:?}"
                    );
                }
            }
        }
        // Extremes: complementary vectors have the largest Hamming and Lee distance.
        let a = vec![0u8; 16];
        let b = vec![15u8; 16];
        assert!(run(u4_nibbles_hamming_distance, &a, &b, 64));
        assert!(run(u4_nibbles_l1_distance, &a, &b, 240));
        assert!(run(u4_nibbles_lee_distance, &a, &vec![8u8; 16], 128));
    }

    #[test]
    fn rejects_out_of_range_nibbles_in_either_vector() {
        for (name, make, _) in ALL {
            for bad in [-1i64, 16, 255] {
                for position in 0..4 {
                    let result = execute_script(script! {
                        for index in 0..4 { { if index == position { bad } else { 5 } } }
                        { make(2) }
                        OP_DROP OP_TRUE
                    });
                    assert_eq!(
                        result.error,
                        Some(ExecError::Verify),
                        "{name} bad {bad} at {position}"
                    );
                }
            }
        }
    }

    #[test]
    fn preserves_surrounding_state() {
        for (name, make, metric) in ALL {
            let want = expected(metric, &[3, 12], &[9, 12]);
            let result = execute_script(script! {
                77 OP_TOALTSTACK
                99
                3 12 9 12
                { make(2) }
                { want } OP_EQUALVERIFY
                99 OP_EQUALVERIFY
                OP_FROMALTSTACK 77 OP_EQUALVERIFY
                OP_TRUE
            });
            assert!(result.success, "{name}: {result}");
        }
    }

    #[test]
    fn recorded_sizes_are_current() {
        // (len, l1, lee, fused hamming, composed hamming)
        for (len, l1, lee, fused, composed) in [
            (1u32, 18usize, 23usize, 415usize, 443usize),
            (2, 39, 49, 445, 477),
            (4, 81, 101, 505, 545),
            (8, 165, 205, 625, 681),
            (16, 334, 414, 874, 962),
            (32, 686, 846, 1_386, 1_538),
            (64, 1_390, 1_710, 2_410, 2_698),
        ] {
            let measure = |make: Make| script! { { make(len) } }.compile_with_policy().len();
            assert_eq!(measure(u4_nibbles_l1_distance), l1, "l1 {len}");
            assert_eq!(measure(u4_nibbles_lee_distance), lee, "lee {len}");
            assert_eq!(measure(u4_nibbles_hamming_distance), fused, "fused {len}");
            assert_eq!(
                measure(u4_nibbles_hamming_distance_composed),
                composed,
                "composed {len}"
            );
        }
    }

    #[test]
    fn rejects_generation_bounds() {
        for (_, make, _) in ALL {
            assert!(std::panic::catch_unwind(|| make(0)).is_err());
        }
        assert!(std::panic::catch_unwind(|| u4_nibbles_l1_distance(
            DISTANCE_ARITHMETIC_MAX_LEN + 1
        ))
        .is_err());
        assert!(std::panic::catch_unwind(|| u4_nibbles_hamming_distance(
            DISTANCE_TABLE_MAX_LEN + 1
        ))
        .is_err());
    }

    #[test]
    fn stack_frontier_is_exact_at_each_maximum() {
        use crate::support::script::MAX_OPTIMIZER_INPUT_BYTES;
        for (name, make, max) in [
            (
                "l1",
                u4_nibbles_l1_distance as Make,
                DISTANCE_ARITHMETIC_MAX_LEN,
            ),
            ("lee", u4_nibbles_lee_distance, DISTANCE_ARITHMETIC_MAX_LEN),
            (
                "hamming",
                u4_nibbles_hamming_distance,
                DISTANCE_TABLE_MAX_LEN,
            ),
            (
                "hamming-composed",
                u4_nibbles_hamming_distance_composed,
                DISTANCE_COMPOSED_MAX_LEN,
            ),
        ] {
            let run = |extra: usize| {
                let compiled = script! {
                    { make(max) }
                    OP_DROP
                    for _ in 0..extra { OP_DROP }
                    OP_TRUE
                    for _ in 0..=MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
                }
                .compile_with_policy()
                .to_bytes();
                let mut witness = vec![vec![9u8]; extra];
                witness.extend(vec![vec![5u8]; 2 * max as usize]);
                execute_raw_script_with_inputs_strict(compiled, witness)
            };
            let base = run(0);
            assert!(base.success, "{name}: {base}");
            let spare = 1_000 - base.stats.max_nb_stack_items;
            let exact = run(spare);
            assert!(exact.success, "{name}: {exact}");
            assert_eq!(exact.stats.max_nb_stack_items, 1_000, "{name}");
            let rejected = run(spare + 1);
            assert_eq!(
                rejected.error,
                Some(ExecError::StackSize),
                "{name}: {rejected}"
            );
        }
    }
}
