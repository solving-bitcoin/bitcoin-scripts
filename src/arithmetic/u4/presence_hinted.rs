//! Hint-checked presence bits of a checked u4 vector.
//!
//! The zero-hint projection (`presence::u4_nibbles_to_presence_bits`) scans the
//! vector once per symbol, 16 * n equality tests. Here the prover supplies the
//! 16 presence flags and, for every flag that claims presence, the index of one
//! element holding that symbol. Soundness has two halves: every actual nibble
//! must have its flag set (n lookups), and every set flag must be witnessed by
//! an in-range index whose element equals the symbol (16 lookups).

use crate::support::script::*;

/// Largest vector: the combined peak is `n + 36`.
pub const PRESENCE_HINTED_MAX_LEN: u32 = 964;

/// Verify and return the presence bits.
///
/// Before (witness, bottom to top): `x[0] ... x[n-1]`, then `idx[0] ... idx[15]`,
/// then the flags `p[15] ... p[0]` (so `p[0]` is on top). After:
/// `p[15] ... p[0]` with `p[s] = 1` iff symbol `s` occurs in `x`, `p[0]` on top;
/// the vector and the indices are consumed. Flags must be the empty item or `[1]`
/// (in tapscript MINIMALIF aborts any other flag encoding); an index is only used
/// for a set flag and must lie in `0..n`.
pub fn u4_nibbles_to_presence_bits_hinted(len: u32) -> Script {
    assert!(
        (1..=PRESENCE_HINTED_MAX_LEN).contains(&len),
        "length out of range"
    );
    script! {
        // (a) every element's flag is set.
        for index in 0..len {
            { 32 + len - 1 - index } OP_PICK
            OP_DUP 0 16 OP_WITHIN OP_VERIFY
            OP_PICK OP_VERIFY
        }
        // (b) every set flag is witnessed by an element holding that symbol.
        for symbol in 0..16u32 {
            { symbol } OP_PICK
            OP_IF
                { 31 - symbol } OP_PICK
                OP_DUP 0 { len } OP_WITHIN OP_VERIFY
                { len - 1 + 32 } OP_SWAP OP_SUB
                OP_PICK
                { symbol } OP_EQUALVERIFY
            OP_ENDIF
        }
        // Keep the flags: park them, drop the vector and indices, restore.
        for _ in 0..16 { OP_TOALTSTACK }
        for _ in 0..(len + 16) / 2 { OP_2DROP }
        if (len + 16) % 2 == 1 { OP_DROP }
        for _ in 0..16 { OP_FROMALTSTACK }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::u4::presence::u4_nibbles_to_presence_bits;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};
    use bitcoin_scriptexec::ExecError;

    fn num(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let len = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..len].to_vec()
    }

    /// Honest witness: vector, one index per present symbol (zero otherwise), flags.
    fn honest(values: &[u8]) -> (Vec<Vec<u8>>, [bool; 16]) {
        let mut flags = [false; 16];
        let mut idx = [0usize; 16];
        for (i, &v) in values.iter().enumerate() {
            if !flags[v as usize] {
                flags[v as usize] = true;
                idx[v as usize] = i;
            }
        }
        let mut witness: Vec<Vec<u8>> = values.iter().map(|&v| num(i64::from(v))).collect();
        witness.extend(idx.iter().map(|&i| num(i as i64)));
        // Flags: p[15] deepest ... p[0] on top.
        witness.extend(
            (0..16)
                .rev()
                .map(|s| if flags[s] { vec![1u8] } else { Vec::new() }),
        );
        (witness, flags)
    }

    /// Compile a leaf that checks the 16 returned flags in order, p[0] on top.
    fn leaf(len: u32, flags: &[bool; 16]) -> Vec<u8> {
        script! {
            { u4_nibbles_to_presence_bits_hinted(len) }
            for symbol in 0..16 { { i64::from(flags[symbol]) } OP_EQUALVERIFY }
            OP_TRUE
        }
        .compile_with_policy()
        .to_bytes()
    }

    fn run(len: u32, flags: &[bool; 16], witness: Vec<Vec<u8>>) -> Option<bool> {
        let result = execute_raw_script_with_inputs_strict(leaf(len, flags), witness);
        if result.error.is_some() {
            None
        } else {
            Some(result.success)
        }
    }

    #[test]
    fn honest_witnesses_return_the_exact_presence_bits() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for len in [1usize, 2, 3, 7, 16, 33] {
            for round in 0..30 {
                // Alternate dense alphabets and tiny alphabets so both sparse and full sets occur.
                let modulus = if round % 2 == 0 { 16 } else { 3 };
                let values: Vec<u8> = (0..len).map(|_| (next() % modulus) as u8).collect();
                let (witness, flags) = honest(&values);
                assert_eq!(run(len as u32, &flags, witness), Some(true), "{values:?}");
            }
        }
        // All sixteen symbols, and a single repeated symbol.
        let all: Vec<u8> = (0..16).collect();
        let (witness, flags) = honest(&all);
        assert_eq!(run(16, &flags, witness), Some(true));
        let (witness, flags) = honest(&[15; 9]);
        assert_eq!(run(9, &flags, witness), Some(true));
    }

    #[test]
    fn agrees_with_the_zero_hint_projection() {
        let values = [3u8, 15, 0, 3, 9, 15];
        let (witness, flags) = honest(&values);
        // The zero-hint projection returns p[0] deepest; compare against the hinted order.
        let zero_hint = execute_script(script! {
            for v in values { { i64::from(v) } }
            { u4_nibbles_to_presence_bits(values.len() as u32) }
            for symbol in (0..16).rev() { { i64::from(flags[symbol]) } OP_EQUALVERIFY }
            OP_TRUE
        });
        assert!(zero_hint.success, "{zero_hint}");
        assert_eq!(run(values.len() as u32, &flags, witness), Some(true));
    }

    #[test]
    fn rejects_every_forged_flag_and_index() {
        let values = [2u8, 2, 9, 14];
        let (honest_witness, flags) = honest(&values);
        let n = values.len();
        // A flag set for an absent symbol cannot be witnessed by any index.
        for absent in (0..16).filter(|&s| !flags[s]) {
            for forged_index in 0..n as i64 {
                let mut w = honest_witness.clone();
                w[n + absent] = num(forged_index);
                w[n + 16 + (15 - absent)] = vec![1u8];
                assert_ne!(run(n as u32, &flags, w), Some(true), "absent {absent}");
            }
        }
        // A flag cleared for a present symbol is caught by that element's lookup.
        for present in (0..16).filter(|&s| flags[s]) {
            let mut w = honest_witness.clone();
            w[n + 16 + (15 - present)] = Vec::new();
            assert_ne!(run(n as u32, &flags, w), Some(true), "present {present}");
        }
        // An index that points at the wrong element, or outside the vector.
        for bad in [-1i64, n as i64, 255] {
            let mut w = honest_witness.clone();
            w[n + 9] = num(bad);
            assert_eq!(run(n as u32, &flags, w), None, "index {bad}");
        }
        let mut w = honest_witness.clone();
        w[n + 9] = num(0); // x[0] = 2, not 9
        assert_eq!(run(n as u32, &flags, w), None);
    }

    #[test]
    fn rejects_noncanonical_flags_and_out_of_range_nibbles() {
        let values = [1u8, 4];
        let (honest_witness, flags) = honest(&values);
        let n = values.len();
        // Flag encodings other than the empty item and [1] abort in tapscript.
        for bad in [vec![2u8], vec![1, 0], vec![0x80], vec![0, 0]] {
            for symbol in [0usize, 1, 4, 7] {
                let mut w = honest_witness.clone();
                w[n + 16 + (15 - symbol)] = bad.clone();
                assert_ne!(
                    run(n as u32, &flags, w),
                    Some(true),
                    "{bad:?} flag {symbol}"
                );
            }
        }
        for bad in [-1i64, 16, 255] {
            for position in 0..n {
                let mut w = honest_witness.clone();
                w[position] = num(bad);
                assert_eq!(run(n as u32, &flags, w), None, "nibble {bad} at {position}");
            }
        }
    }

    #[test]
    fn recorded_sizes_are_current() {
        use crate::arithmetic::u4::presence::u4_nibbles_to_presence_bits;
        // (n, zero-hint bytes, hinted bytes)
        for (n, zero, hinted) in [
            (4u32, 412usize, 383usize),
            (8, 778, 425),
            (16, 1_526, 509),
            (32, 3_261, 693),
            (64, 6_733, 1_029),
            (128, 13_709, 1_765),
        ] {
            let measure = |script: Script| script.compile_with_policy().len();
            assert_eq!(
                measure(u4_nibbles_to_presence_bits(n)),
                zero,
                "zero-hint {n}"
            );
            assert_eq!(
                measure(u4_nibbles_to_presence_bits_hinted(n)),
                hinted,
                "hinted {n}"
            );
        }
    }

    #[test]
    fn rejects_generation_bounds_and_hits_the_stack_frontier() {
        use crate::support::script::MAX_OPTIMIZER_INPUT_BYTES;
        assert!(std::panic::catch_unwind(|| u4_nibbles_to_presence_bits_hinted(0)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u4_nibbles_to_presence_bits_hinted(PRESENCE_HINTED_MAX_LEN + 1)
        })
        .is_err());
        let n = PRESENCE_HINTED_MAX_LEN;
        let values = vec![7u8; n as usize];
        let (witness, _) = honest(&values);
        let run_at = |extra: usize| {
            let compiled = script! {
                { u4_nibbles_to_presence_bits_hinted(n) }
                for _ in 0..16 { OP_DROP }
                for _ in 0..extra { OP_DROP }
                OP_TRUE
                for _ in 0..=MAX_OPTIMIZER_INPUT_BYTES { OP_NOP }
            }
            .compile_with_policy()
            .to_bytes();
            let mut w = vec![vec![9u8]; extra];
            w.extend(witness.clone());
            execute_raw_script_with_inputs_strict(compiled, w)
        };
        let base = run_at(0);
        assert!(base.success, "{base}");
        let spare = 1_000 - base.stats.max_nb_stack_items;
        assert!(run_at(spare).success);
        assert_eq!(run_at(spare + 1).error, Some(ExecError::StackSize));
    }
}
