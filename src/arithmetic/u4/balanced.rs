//! Balanced-bracket check over nibble-packed bit strings.
//!
//! Each nibble `b3 b2 b1 b0` (most significant bit first) encodes four
//! brackets, `1` for open and `0` for close. A nibble is summarized by its net
//! change `D` and the largest prefix deficit `R = -min(0, min prefix)`. With
//! height `h` before the nibble, the nibble keeps every prefix nonnegative iff
//! `h >= R`, and leaves height `h + D`.

use crate::support::script::*;

/// Resident items: 16 deficits and 16 net changes.
pub const BALANCED_TABLE_ITEMS: u32 = 32;

/// Largest batch of nibbles; the measured combined peak is `n + 37`.
pub const BALANCED_MAX_LEN: u32 = 1_000 - BALANCED_TABLE_ITEMS - 5;

/// Net change and prefix deficit of one nibble, most significant bit first.
pub fn nibble_summary(value: u8) -> (i64, i64) {
    let (mut height, mut lowest) = (0i64, 0i64);
    for bit in (0..4).rev() {
        height += if (value >> bit) & 1 == 1 { 1 } else { -1 };
        lowest = lowest.min(height);
    }
    (height, -lowest)
}

/// Decide whether a nibble-packed bracket string is balanced.
///
/// Before: `preserved | v[0] ... v[n-1]`, last item on top (`v[0]` holds the
/// first four brackets). After: `preserved | balanced`, where `balanced` is `1`
/// iff no prefix has more closes than opens and the totals are equal. Every
/// nibble is range-checked; no hints are used.
pub fn u4_nibbles_balanced(len: u32) -> Script {
    assert!((1..=BALANCED_MAX_LEN).contains(&len), "length out of range");
    script! {
        // Tables, D[0] on top of R[15] .. R[0]: R[0] ends up nearest the accumulators.
        for value in (0..16u8).rev() { { nibble_summary(value).0 } }
        for value in (0..16u8).rev() { { nibble_summary(value).1 } }
        // Accumulators: height h below minimum slack m (starts high).
        0 100000
        for remaining in (1..=len).rev() {
            // The first unprocessed nibble is the deepest input.
            { BALANCED_TABLE_ITEMS + 1 + remaining } OP_ROLL
            OP_DUP 0 16 OP_WITHIN OP_VERIFY
            // stack top: x, m, h, R[0..15], D[0..15], inputs
            OP_DUP 3 OP_ADD OP_PICK
            3 OP_PICK OP_SWAP OP_SUB
            2 OP_ROLL OP_MIN
            OP_SWAP
            // stack top: x, m, h
            18 OP_ADD OP_PICK
            OP_ROT OP_ADD
            OP_SWAP
        }
        // Balanced iff the minimum slack is nonnegative and the final height is zero.
        OP_SWAP 0 OP_NUMEQUAL
        OP_SWAP 0 OP_GREATERTHANOREQUAL OP_BOOLAND
        OP_TOALTSTACK
        for _ in 0..BALANCED_TABLE_ITEMS / 2 { OP_2DROP }
        OP_FROMALTSTACK
    }
}

/// Bit-per-item comparator with the same verdict as [`u4_nibbles_balanced`].
///
/// Before: `preserved | b[0] ... b[m-1]`, each `b` in `{0, 1}` (`1` is open).
/// Scans from the top item with open and close exchanged, which decides the
/// same balanced-string predicate as a forward scan.
pub fn bracket_items_balanced(len: u32) -> Script {
    assert!((1..=996).contains(&len), "length out of range");
    script! {
        0 100000
        for _ in 0..len {
            2 OP_ROLL
            OP_DUP 0 2 OP_WITHIN OP_VERIFY
            OP_DUP OP_ADD 1 OP_SWAP OP_SUB
            OP_ROT OP_ADD
            OP_DUP OP_ROT OP_MIN
        }
        OP_SWAP 0 OP_NUMEQUAL
        OP_SWAP 0 OP_GREATERTHANOREQUAL OP_BOOLAND
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};
    use bitcoin_scriptexec::ExecError;

    fn bits_of(values: &[u8]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|v| (0..4).rev().map(move |bit| (v >> bit) & 1))
            .collect()
    }

    fn model(bits: &[u8]) -> bool {
        let mut height = 0i64;
        for &bit in bits {
            height += if bit == 1 { 1 } else { -1 };
            if height < 0 {
                return false;
            }
        }
        height == 0
    }

    fn item(value: u8) -> Vec<u8> {
        if value == 0 {
            Vec::new()
        } else {
            vec![value]
        }
    }

    fn run_packed(compiled: &[u8], values: &[u8]) -> bool {
        let witness: Vec<Vec<u8>> = values.iter().map(|&v| item(v)).collect();
        let result = execute_raw_script_with_inputs_strict(
            [
                compiled,
                script! { OP_VERIFY OP_TRUE }
                    .compile_with_policy()
                    .as_bytes(),
            ]
            .concat(),
            witness,
        );
        assert!(
            result.error.is_none() || result.error == Some(ExecError::Verify),
            "{result}"
        );
        result.success
    }

    #[test]
    fn nibble_summaries_match_the_definition() {
        assert_eq!(nibble_summary(0b1010), (0, 0));
        assert_eq!(nibble_summary(0b0101), (0, 1));
        assert_eq!(nibble_summary(0b0000), (-4, 4));
        assert_eq!(nibble_summary(0b1111), (4, 0));
        assert_eq!(nibble_summary(0b1100), (0, 0));
        assert_eq!(nibble_summary(0b0011), (0, 2));
    }

    #[test]
    fn packed_check_matches_model_exhaustively_to_three_nibbles() {
        for len in 1..=3u32 {
            let compiled = u4_nibbles_balanced(len).compile_with_policy().to_bytes();
            for code in 0..16u32.pow(len) {
                let values: Vec<u8> = (0..len).map(|i| ((code >> (4 * i)) & 15) as u8).collect();
                let want = model(&bits_of(&values));
                assert_eq!(run_packed(&compiled, &values), want, "values {values:?}");
            }
        }
    }

    #[test]
    fn packed_check_matches_model_on_deterministic_longer_strings() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for len in [4u32, 8, 16] {
            let compiled = u4_nibbles_balanced(len).compile_with_policy().to_bytes();
            let (mut accepted, mut rejected) = (0, 0);
            for _ in 0..200 {
                // Random Dyck words (accepted) and random strings (usually rejected).
                let values: Vec<u8> = if next() % 2 == 0 {
                    let bits = random_dyck(len as usize * 4, &mut next);
                    bits.chunks(4)
                        .map(|c| c.iter().fold(0u8, |acc, &b| (acc << 1) | b))
                        .collect()
                } else {
                    (0..len).map(|_| (next() % 16) as u8).collect()
                };
                let want = model(&bits_of(&values));
                assert_eq!(run_packed(&compiled, &values), want, "values {values:?}");
                if want {
                    accepted += 1;
                } else {
                    rejected += 1;
                }
            }
            assert!(
                accepted > 20 && rejected > 20,
                "len {len}: {accepted}/{rejected}"
            );
        }
    }

    fn random_dyck(bits: usize, next: &mut impl FnMut() -> u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(bits);
        let (mut open, mut height) = (bits / 2, 0usize);
        let mut close = bits / 2;
        while out.len() < bits {
            let can_open = open > 0;
            let can_close = height > 0 && close > 0;
            let choose_open = match (can_open, can_close) {
                (true, false) => true,
                (false, true) => false,
                _ => next() % 2 == 0,
            };
            if choose_open {
                out.push(1);
                open -= 1;
                height += 1;
            } else {
                out.push(0);
                close -= 1;
                height -= 1;
            }
        }
        out
    }

    #[test]
    fn rejects_out_of_range_nibbles_at_every_position() {
        for bad in [-1i64, 16, 255] {
            for position in 0..4 {
                let result = execute_script(script! {
                    for index in 0..4 { { if index == position { bad } else { 12 } } }
                    { u4_nibbles_balanced(4) }
                    OP_DROP OP_TRUE
                });
                assert_eq!(
                    result.error,
                    Some(ExecError::Verify),
                    "bad {bad} at {position}"
                );
            }
        }
    }

    #[test]
    fn preserves_surrounding_state_and_orders_brackets_first_nibble_first() {
        // "((((" then "))))" is balanced; the reverse order closes first.
        for (values, want) in [([0b1111u8, 0b0000], 1), ([0b0000, 0b1111], 0)] {
            let result = execute_script(script! {
                77 OP_TOALTSTACK
                99
                for v in values { { i64::from(v) } }
                { u4_nibbles_balanced(2) }
                { want } OP_EQUALVERIFY
                99 OP_EQUALVERIFY
                OP_FROMALTSTACK 77 OP_EQUALVERIFY
                OP_TRUE
            });
            assert!(result.success, "{values:?}: {result}");
        }
    }

    #[test]
    fn comparator_matches_the_packed_check_on_the_same_strings() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let compiled = bracket_items_balanced(16).compile_with_policy().to_bytes();
        for _ in 0..200 {
            let bits: Vec<u8> = if next() % 2 == 0 {
                random_dyck(16, &mut next)
            } else {
                (0..16).map(|_| (next() % 2) as u8).collect()
            };
            // The comparator scans from the top with open and close exchanged.
            let witness: Vec<Vec<u8>> = bits.iter().map(|&b| item(b)).collect();
            let result = execute_raw_script_with_inputs_strict(
                [
                    &compiled[..],
                    script! { OP_VERIFY OP_TRUE }
                        .compile_with_policy()
                        .as_bytes(),
                ]
                .concat(),
                witness,
            );
            assert_eq!(result.success, model(&bits), "bits {bits:?}: {result}");
        }
    }

    #[test]
    fn stack_frontier_is_exact() {
        use crate::support::script::MAX_OPTIMIZER_INPUT_BYTES;
        let run = |extra: usize| {
            let compiled = script! {
                { u4_nibbles_balanced(BALANCED_MAX_LEN) }
                OP_VERIFY
                for _ in 0..extra { OP_DROP }
                OP_TRUE
                for _ in 0..=MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
            }
            .compile_with_policy()
            .to_bytes();
            // 0b1100 is balanced on its own, so any repetition count is balanced.
            let mut witness = vec![vec![9u8]; extra];
            for _ in 0..BALANCED_MAX_LEN {
                witness.push(item(0b1100));
            }
            execute_raw_script_with_inputs_strict(compiled, witness)
        };
        let accepted = run(0);
        assert!(accepted.success, "{accepted}");
        let at_limit = accepted.stats.max_nb_stack_items;
        assert!(at_limit <= 1_000);
        let rejected = run(1_000 - at_limit + 1);
        assert_eq!(rejected.error, Some(ExecError::StackSize), "{rejected}");
    }

    #[test]
    fn recorded_sizes_are_current() {
        for (nibbles, packed, items) in [
            (1, 89, 75),
            (2, 115, 139),
            (4, 167, 267),
            (8, 271, 523),
            (16, 479, 1_035),
            (32, 895, 2_059),
            (64, 1_727, 4_107),
        ] {
            let measure = |script: Script| script.compile_with_policy().len();
            assert_eq!(
                measure(u4_nibbles_balanced(nibbles)),
                packed,
                "packed {nibbles}"
            );
            assert_eq!(
                measure(bracket_items_balanced(4 * nibbles)),
                items,
                "items {nibbles}"
            );
        }
    }

    #[test]
    fn rejects_generation_bounds() {
        assert!(std::panic::catch_unwind(|| u4_nibbles_balanced(0)).is_err());
        assert!(std::panic::catch_unwind(|| u4_nibbles_balanced(BALANCED_MAX_LEN + 1)).is_err());
    }
}
