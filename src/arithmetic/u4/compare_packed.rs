//! Lexicographic comparison of u4 vectors through packed 28-bit words.
//!
//! Same contract as [`super::compare::lexicographic_le`], which walks a
//! per-nibble first-difference state machine. Here each vector is packed into
//! words of up to seven nibbles with a Horner sum and the words are compared
//! with native ScriptNum arithmetic, so the first differing word decides.

use super::stack::u4_drop;
use crate::support::script::*;

/// Nibbles per packed word: 28 bits fit a four-byte ScriptNum.
pub const PACK_WIDTH: u32 = 7;

/// Largest width: the combined peak is `2n + 7`.
pub const LEXICOGRAPHIC_PACKED_MAX_NIBBLES: u32 = 496;

/// Return whether `left <= right` for two equal-width big-endian u4 vectors.
///
/// Stack before: `left[0] ... left[n-1] right[0] ... right[n-1]`. After:
/// `result` in `{0, 1}` (true for equality), both vectors consumed. Every input
/// is range-checked as a numeric nibble. No hints.
pub fn lexicographic_le_packed(nibble_count: u32) -> Script {
    assert!(
        (1..=LEXICOGRAPHIC_PACKED_MAX_NIBBLES).contains(&nibble_count),
        "comparison width out of range"
    );
    let n = nibble_count;
    let chunks: Vec<(u32, u32)> = (0..n.div_ceil(PACK_WIDTH))
        .map(|c| (c * PACK_WIDTH, ((c + 1) * PACK_WIDTH).min(n)))
        .collect();
    script! {
        1
        // The last chunk decides last: fold from the end toward the front.
        for &(start, end) in chunks.iter().rev() {
            // Stack top: result. Pack the left chunk, then the right chunk.
            0
            for index in start..end {
                for _ in 0..4 { OP_DUP OP_ADD }
                // items above left[index]: left[index+1..], right[..], result, acc
                { (n - 1 - index) + n + 2 } OP_PICK
                OP_DUP 0 16 OP_WITHIN OP_VERIFY
                OP_ADD
            }
            0
            for index in start..end {
                for _ in 0..4 { OP_DUP OP_ADD }
                // items above right[index]: right[index+1..], result, left word, acc
                { (n - 1 - index) + 3 } OP_PICK
                OP_DUP 0 16 OP_WITHIN OP_VERIFY
                OP_ADD
            }
            // result, left word, right word -> result'
            OP_2DUP OP_NUMEQUAL
            OP_IF
                OP_2DROP
            OP_ELSE
                OP_LESSTHAN OP_NIP
            OP_ENDIF
        }
        OP_TOALTSTACK
        { u4_drop(2 * n) }
        OP_FROMALTSTACK
    }
}

/// Embedded-constant form: the right vector is a public generation-time constant.
pub fn lexicographic_le_packed_constant(constant: &[u8]) -> Script {
    assert!(
        (1..=LEXICOGRAPHIC_PACKED_MAX_NIBBLES as usize).contains(&constant.len()),
        "comparison constant width out of range"
    );
    assert!(constant.iter().all(|&n| n < 16), "constant nibbles only");
    script! {
        for &nibble in constant { { nibble } }
        { lexicographic_le_packed(constant.len() as u32) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::u4::compare::lexicographic_le;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};
    use bitcoin_scriptexec::ExecError;

    fn item(value: u8) -> Vec<u8> {
        if value == 0 {
            Vec::new()
        } else {
            vec![value]
        }
    }

    /// Compile once; the expected Boolean is the lowest witness item.
    fn compile(make: fn(u32) -> Script, n: usize) -> Vec<u8> {
        script! { { make(n as u32) } OP_EQUAL }
            .compile_with_policy()
            .to_bytes()
    }

    fn run(compiled: &[u8], left: &[u8], right: &[u8]) -> bool {
        let expected = u8::from(left <= right);
        let mut witness = vec![item(expected)];
        witness.extend(left.iter().chain(right).map(|&v| item(v)));
        let result = execute_raw_script_with_inputs_strict(compiled.to_vec(), witness);
        assert!(result.error.is_none(), "{left:?} vs {right:?}: {result}");
        result.success
    }

    #[test]
    fn exhaustive_for_one_and_two_nibbles() {
        for n in 1..=2usize {
            let compiled = compile(lexicographic_le_packed, n);
            for l in 0..16u32.pow(n as u32) {
                for r in 0..16u32.pow(n as u32) {
                    let split = |v: u32| -> Vec<u8> {
                        (0..n)
                            .map(|i| ((v >> (4 * (n - 1 - i))) & 15) as u8)
                            .collect()
                    };
                    assert!(run(&compiled, &split(l), &split(r)), "{l:#x} vs {r:#x}");
                }
            }
        }
    }

    #[test]
    fn differences_at_every_position_across_chunk_boundaries() {
        for n in [6usize, 7, 8, 13, 14, 15, 21, 22] {
            let compiled = compile(lexicographic_le_packed, n);
            let base: Vec<u8> = (0..n).map(|i| ((i * 5 + 3) % 16) as u8).collect();
            assert!(run(&compiled, &base, &base), "equal n={n}");
            for position in 0..n {
                for delta in [1i32, -1, 15, -15] {
                    let value = i32::from(base[position]) + delta;
                    if !(0..16).contains(&value) {
                        continue;
                    }
                    let mut other = base.clone();
                    other[position] = value as u8;
                    // Later positions are overridden to defeat any suffix shortcut.
                    for suffix in [0u8, 15] {
                        for p in position + 1..n {
                            other[p] = suffix;
                        }
                        assert!(run(&compiled, &base, &other), "n={n} pos={position}");
                        assert!(run(&compiled, &other, &base), "n={n} pos={position}");
                    }
                }
            }
        }
    }

    #[test]
    fn agrees_with_the_per_nibble_comparison_on_deterministic_vectors() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for n in [8usize, 16, 29, 32] {
            let packed = compile(lexicographic_le_packed, n);
            let reference = compile(lexicographic_le, n);
            for _ in 0..30 {
                let left: Vec<u8> = (0..n).map(|_| (next() % 16) as u8).collect();
                let mut right = left.clone();
                // Mostly share a long prefix, as ordered Merkle siblings would.
                let cut = (next() as usize) % n;
                for p in cut..n {
                    right[p] = (next() % 16) as u8;
                }
                assert!(run(&packed, &left, &right));
                assert!(run(&reference, &left, &right));
            }
        }
    }

    #[test]
    fn recorded_sizes_are_current() {
        use crate::arithmetic::u4::compare::lexicographic_le;
        // (n, per-nibble bytes, packed bytes)
        for (n, reference, packed) in [
            (1u32, 44usize, 29usize),
            (2, 95, 63),
            (7, 347, 228),
            (8, 397, 256),
            (16, 843, 531),
            (32, 1_739, 1_079),
            (64, 3_532, 2_171),
            (128, 7_500, 4_486),
        ] {
            let measure = |script: Script| script.compile_with_policy().len();
            assert_eq!(measure(lexicographic_le(n)), reference, "reference {n}");
            assert_eq!(measure(lexicographic_le_packed(n)), packed, "packed {n}");
        }
    }

    #[test]
    fn rejects_out_of_range_nibbles_in_both_vectors() {
        for bad in [-1i64, 16, 255] {
            for position in 0..8 {
                let result = execute_script(script! {
                    for index in 0..8 { { if index == position { bad } else { 5 } } }
                    { lexicographic_le_packed(4) }
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
    fn constant_form_and_state_preservation() {
        let constant = [3u8, 14, 15, 0, 9];
        for (left, expected) in [
            ([3u8, 14, 15, 0, 9], 1),
            ([3, 14, 15, 0, 10], 0),
            ([3, 14, 14, 15, 15], 1),
            ([4, 0, 0, 0, 0], 0),
        ] {
            let result = execute_script(script! {
                77 OP_TOALTSTACK
                99
                for v in left { { i64::from(v) } }
                { lexicographic_le_packed_constant(&constant) }
                { expected } OP_EQUALVERIFY
                99 OP_EQUALVERIFY
                OP_FROMALTSTACK 77 OP_EQUALVERIFY
                OP_TRUE
            });
            assert!(result.success, "{left:?}: {result}");
        }
        assert!(std::panic::catch_unwind(|| lexicographic_le_packed(0)).is_err());
        assert!(std::panic::catch_unwind(|| {
            lexicographic_le_packed(LEXICOGRAPHIC_PACKED_MAX_NIBBLES + 1)
        })
        .is_err());
        assert!(std::panic::catch_unwind(|| lexicographic_le_packed_constant(&[16])).is_err());
    }

    #[test]
    fn stack_frontier_is_exact() {
        use crate::support::script::MAX_OPTIMIZER_INPUT_BYTES;
        let n = LEXICOGRAPHIC_PACKED_MAX_NIBBLES;
        let run_at = |extra: usize| {
            let compiled = script! {
                { lexicographic_le_packed(n) }
                OP_VERIFY
                for _ in 0..extra { OP_DROP }
                OP_TRUE
                for _ in 0..=MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
            }
            .compile_with_policy()
            .to_bytes();
            let mut witness = vec![vec![9u8]; extra];
            witness.extend(vec![vec![7u8]; 2 * n as usize]);
            execute_raw_script_with_inputs_strict(compiled, witness)
        };
        let base = run_at(0);
        assert!(base.success, "{base}");
        let spare = 1_000 - base.stats.max_nb_stack_items;
        assert!(run_at(spare).success);
        assert_eq!(run_at(spare + 1).error, Some(ExecError::StackSize));
    }
}
