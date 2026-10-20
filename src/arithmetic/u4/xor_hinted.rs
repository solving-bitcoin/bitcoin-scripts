//! Parity-hinted XOR reduction of a checked u4 vector.
//!
//! The XOR of `n` nibbles is the per-bit parity of their set bits. Each nibble
//! adds `T[x] = sum_b bit_b(x) * B^b` to one accumulator, so lane `b` of the sum
//! `S` counts how many nibbles have bit `b` set (`B = n + 2` exceeds every lane,
//! so lanes never carry). A claimed result `y` and four claimed half-counts `h_b`
//! are accepted when `S == T[y] + 2 * sum_b h_b * B^b` with every `h_b` in
//! `0..=n/2`: the right-hand lanes are then `y_b + 2 h_b <= n + 1 < B`, so the
//! equality holds lane by lane, i.e. `count_b = y_b + 2 h_b`, which means
//! `y_b` is the parity of `count_b`.

use super::stack::u4_drop;
use crate::arithmetic::scriptint::mul_by_constant;
use crate::support::script::*;

/// Largest vector: the accumulator `n * (B^4 - 1) / (B - 1)` with `B = n + 2`
/// must stay below `2^31`.
pub const U4_XOR_HINTED_MAX_LEN: u32 = 212;

/// Lane base for vectors of length `len`.
fn base(len: u32) -> i64 {
    i64::from(len) + 2
}

/// Packed bit-count weight of nibble value `x`.
fn weight(x: u32, base: i64) -> i64 {
    (0..4).map(|b| i64::from((x >> b) & 1) * base.pow(b)).sum()
}

/// Verify a claimed XOR of `n` nibbles and return it.
///
/// Before (witness, bottom to top): `x[0] ... x[n-1] y h0 h1 h2 h3`. After:
/// `y`, with the vector and hints consumed. The script aborts unless `y` is the
/// XOR of the vector. Hint items: five (`y` and four lane halves).
pub fn u4_nibbles_xor_hinted(len: u32) -> Script {
    assert!(
        (1..=U4_XOR_HINTED_MAX_LEN).contains(&len),
        "length out of range"
    );
    let b = base(len);
    let half = i64::from(len / 2);
    script! {
        // Lane halves must be small so that no lane can carry.
        for k in 0..4 {
            { k } OP_PICK 0 { half + 1 } OP_WITHIN OP_VERIFY
        }
        // rhs = 2 * (h0 + h1 B + h2 B^2 + h3 B^3), Horner from the top lane.
        0 OP_PICK
        { mul_by_constant(b as u32) } 2 OP_PICK OP_ADD
        { mul_by_constant(b as u32) } 3 OP_PICK OP_ADD
        { mul_by_constant(b as u32) } 4 OP_PICK OP_ADD
        OP_DUP OP_ADD
        // Table T[0] on top, then the accumulator S.
        for value in (0..16u32).rev() { { weight(value, b) } }
        0
        for index in 0..len {
            // Items above x[index]: later nibbles, y, 4 hints, rhs, 16 table, acc.
            { (len - 1 - index) + 1 + 4 + 1 + 16 + 1 } OP_PICK
            OP_DUP 0 16 OP_WITHIN OP_VERIFY
            OP_DUP 2 OP_ADD OP_PICK OP_NIP
            OP_ADD
        }
        // Stack top: S, then the table, rhs, hints, y.
        { 16 + 1 + 4 + 1 } OP_PICK
        OP_DUP 0 16 OP_WITHIN OP_VERIFY
        // The consumed index leaves the table directly below S.
        1 OP_ADD OP_PICK
        { 16 + 2 } OP_PICK OP_ADD
        OP_NUMEQUALVERIFY
        // Drop the 16 table items, then rhs and the four hints.
        for _ in 0..8 { OP_2DROP }
        OP_2DROP OP_2DROP OP_DROP
        OP_TOALTSTACK
        { u4_drop(len) }
        OP_FROMALTSTACK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::u4::xor_reduce::u4_nibbles_to_xor;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};
    use bitcoin_scriptexec::ExecError;

    fn num(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let len = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..len].to_vec()
    }

    fn xor_of(values: &[u8]) -> u8 {
        values.iter().fold(0, |acc, &v| acc ^ v)
    }

    /// Honest lane halves: floor(count_b / 2) for each bit.
    fn honest_halves(values: &[u8]) -> [i64; 4] {
        let mut halves = [0i64; 4];
        for (bit, half) in halves.iter_mut().enumerate() {
            *half = values.iter().filter(|&&v| (v >> bit) & 1 == 1).count() as i64 / 2;
        }
        halves
    }

    fn witness(values: &[u8], y: i64, halves: [i64; 4]) -> Vec<Vec<u8>> {
        let mut w: Vec<Vec<u8>> = values.iter().map(|&v| num(i64::from(v))).collect();
        w.push(num(y));
        w.extend(halves.iter().map(|&h| num(h)));
        w
    }

    /// Compile once per length: the expected value is the lowest witness item.
    fn leaf(len: usize) -> Vec<u8> {
        script! {
            { u4_nibbles_xor_hinted(len as u32) }
            OP_EQUAL
        }
        .compile_with_policy()
        .to_bytes()
    }

    fn run_compiled(compiled: &[u8], values: &[u8], y: i64, halves: [i64; 4]) -> Option<bool> {
        let mut w = vec![num(y)];
        w.extend(witness(values, y, halves));
        let result = execute_raw_script_with_inputs_strict(compiled.to_vec(), w);
        if result.error.is_some() {
            None
        } else {
            Some(result.success)
        }
    }

    /// `Some(passed)` or `None` on an abort.
    fn run(values: &[u8], y: i64, halves: [i64; 4]) -> Option<bool> {
        run_compiled(&leaf(values.len()), values, y, halves)
    }

    #[test]
    fn honest_hints_are_accepted_for_every_short_vector() {
        for len in 1..=3usize {
            for code in 0..16u32.pow(len as u32) {
                let values: Vec<u8> = (0..len).map(|i| ((code >> (4 * i)) & 15) as u8).collect();
                let y = i64::from(xor_of(&values));
                assert_eq!(
                    run(&values, y, honest_halves(&values)),
                    Some(true),
                    "{values:?}"
                );
            }
        }
    }

    #[test]
    fn exhaustive_hint_search_finds_only_the_honest_xor() {
        // Every claimed result and every small half-count tuple, including
        // out-of-range values, for several vectors: only one pair may verify.
        for values in [
            vec![9u8, 5],
            vec![15, 15, 15],
            vec![0, 0],
            vec![3, 12, 6, 6],
        ] {
            let compiled = leaf(values.len());
            let mut accepted = Vec::new();
            for y in -1..17i64 {
                for h0 in -1..4i64 {
                    for h1 in -1..4i64 {
                        for h2 in -1..4i64 {
                            for h3 in -1..4i64 {
                                let halves = [h0, h1, h2, h3];
                                if run_compiled(&compiled, &values, y, halves) == Some(true) {
                                    accepted.push((y, halves));
                                }
                            }
                        }
                    }
                }
            }
            assert_eq!(
                accepted,
                vec![(i64::from(xor_of(&values)), honest_halves(&values))],
                "{values:?}"
            );
        }
    }

    #[test]
    fn deterministic_longer_vectors_match_the_table_reduction() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for len in [5usize, 8, 16, 33, 64, 200, 212] {
            for _ in 0..4 {
                let values: Vec<u8> = (0..len)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        (state % 16) as u8
                    })
                    .collect();
                let y = i64::from(xor_of(&values));
                assert_eq!(
                    run(&values, y, honest_halves(&values)),
                    Some(true),
                    "len {len}"
                );
                // The existing table reduction returns the same value.
                let reference = execute_script(script! {
                    for v in &values { { i64::from(*v) } }
                    { u4_nibbles_to_xor(len as u32) }
                    { y } OP_EQUAL
                });
                assert!(reference.success, "len {len}: {reference}");
            }
        }
        // Worst case for the lanes: every nibble 15.
        let values = vec![15u8; 212];
        assert_eq!(run(&values, 0, honest_halves(&values)), Some(true));
    }

    #[test]
    fn rejects_out_of_range_nibbles_claims_and_halves() {
        let values = [6u8, 9, 3];
        let halves = honest_halves(&values);
        let y = i64::from(xor_of(&values));
        for bad in [-1i64, 16, 255] {
            for position in 0..values.len() {
                let mut w = witness(&values, y, halves);
                w[position] = num(bad);
                let mut full = vec![num(y)];
                full.extend(w);
                let result = execute_raw_script_with_inputs_strict(leaf(values.len()), full);
                assert_eq!(
                    result.error,
                    Some(ExecError::Verify),
                    "nibble {bad} at {position}"
                );
            }
            assert_eq!(run(&values, bad, halves), None, "claim {bad}");
        }
        for bad in [-1i64, 2, 100] {
            let mut tampered = halves;
            tampered[1] = bad;
            assert_ne!(run(&values, y, tampered), Some(true), "half {bad}");
        }
    }

    #[test]
    fn recorded_sizes_are_current() {
        // (n, table bytes, hinted bytes)
        for (n, table, hinted) in [
            (4u32, 464usize, 175usize),
            (8, 556, 239),
            (16, 740, 367),
            (32, 1_122, 617),
            (64, 1_890, 1_087),
            (128, 3_426, 2_046),
            (212, 5_525, 3_378),
        ] {
            let measure = |script: Script| script.compile_with_policy().len();
            assert_eq!(measure(u4_nibbles_to_xor(n)), table, "table {n}");
            assert_eq!(measure(u4_nibbles_xor_hinted(n)), hinted, "hinted {n}");
        }
    }

    #[test]
    fn preserves_surrounding_state_and_checks_bounds() {
        let values = [10u8, 3];
        let result = execute_script(script! {
            77 OP_TOALTSTACK
            99
            10 3
            9
            { honest_halves(&values)[0] } { honest_halves(&values)[1] }
            { honest_halves(&values)[2] } { honest_halves(&values)[3] }
            { u4_nibbles_xor_hinted(2) }
            9 OP_EQUALVERIFY
            99 OP_EQUALVERIFY
            OP_FROMALTSTACK 77 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "{result}");
        assert!(std::panic::catch_unwind(|| u4_nibbles_xor_hinted(0)).is_err());
        assert!(
            std::panic::catch_unwind(|| u4_nibbles_xor_hinted(U4_XOR_HINTED_MAX_LEN + 1)).is_err()
        );
    }

    #[test]
    fn lane_accumulator_stays_inside_the_four_byte_domain_at_the_maximum() {
        let bound = |len: u128| {
            let b = len + 2;
            len * (b.pow(4) - 1) / (b - 1)
        };
        let max = u128::from(U4_XOR_HINTED_MAX_LEN);
        assert!(bound(max) < 1 << 31, "maximum accumulator {}", bound(max));
        assert!(
            bound(max + 1) < 1 << 31,
            "the limit is not tight: {}",
            bound(max + 1)
        );
        // The documented limit is conservative by design; the first overflowing length is above it.
        let first_overflow = (max..2_000).find(|&n| bound(n) >= 1 << 31).unwrap();
        assert!(first_overflow > max);
    }
}
