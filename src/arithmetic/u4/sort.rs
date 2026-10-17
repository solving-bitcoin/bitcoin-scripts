//! Exact nibble sorting with bounded destructive-selection hints.

use super::stack::verify_canonical_nibble;
use crate::arithmetic::scriptint::verify_canonical;
use crate::support::script::*;

/// Includes all `n` operands, `n-1` hints, and validation temporaries.
pub fn u4_sort_stack_bound(n: u32) -> u32 {
    assert!((1..=499).contains(&n), "sort width must be in 1..=499");
    if n == 1 {
        4
    } else {
        2 * n + 2
    }
}

/// Consume canonical nibble operands and `n-1` selection hints, returning the
/// same multiset in ascending order (largest output on top).
///
/// Entry: `preserved | hint[n-2] ... hint[0] | x[0] ... x[n-1]`.
/// Each hint is the top-relative depth of the next maximum in the *remaining*
/// operand pool. Equal values may be selected in any order. Bounds prevent
/// selecting a hint or preserved state; destructive rolls prevent reuse.
/// Both stacks' unrelated state is preserved. Add its size to the stack bound.
pub fn u4_sort_with_hints(n: u32) -> Script {
    u4_sort_stack_bound(n);
    script! {
        for remaining in (1..=n).rev() {
            if remaining > 1 {
                // Pull the next hint past exactly the remaining operands.
                { remaining } OP_ROLL
                OP_DUP 0 { remaining } OP_WITHIN OP_VERIFY
                // Canonical hints even when MINIMALDATA is disabled.
                { verify_canonical() }
                OP_ROLL
            }
            { verify_canonical_nibble() }
            if remaining < n {
                // current <= previous; put the previous output back first.
                OP_FROMALTSTACK
                OP_2DUP OP_LESSTHANOREQUAL OP_VERIFY
                OP_TOALTSTACK
            }
            OP_TOALTSTACK
        }
        // Selection was descending, so this restores ascending output.
        for _ in 0..n {
            OP_FROMALTSTACK
        }
    }
}

/// Deterministic hint generator; ties choose the topmost remaining maximum.
/// Returns hints in witness order (the first consumed hint is last).
pub fn u4_sort_hints(input: &[u8]) -> Vec<u32> {
    u4_sort_stack_bound(input.len().try_into().expect("sort width fits u32"));
    assert!(input.iter().all(|x| *x < 16), "input must be u4");
    let mut pool = input.to_vec();
    let mut hints = Vec::with_capacity(pool.len() - 1);
    while pool.len() > 1 {
        let index = pool.iter().enumerate().max_by_key(|(_, x)| *x).unwrap().0;
        hints.push((pool.len() - 1 - index) as u32);
        pool.remove(index);
    }
    hints.reverse();
    hints
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{
        execute_raw_script_with_inputs_strict, execute_script_buf_with_options,
        execute_script_with_inputs_strict,
    };
    use bitcoin::{
        consensus::serialize,
        hashes::{sha256, Hash},
        Witness,
    };
    use bitcoin_scriptexec::{ExecError, Options};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn num(value: i64) -> Vec<u8> {
        let mut buf = [0; 8];
        let len = bitcoin::script::write_scriptint(&mut buf, value);
        buf[..len].to_vec()
    }

    fn witness(input: &[u8]) -> Vec<Vec<u8>> {
        u4_sort_hints(input)
            .into_iter()
            .map(|x| num(x.into()))
            .chain(input.iter().map(|x| num((*x).into())))
            .collect()
    }

    fn comparison(sorted: &[u8]) -> Script {
        script! {
            for x in sorted.iter().rev() {
                { *x as u32 } OP_EQUALVERIFY
            }
            OP_TRUE
        }
    }

    fn check(input: &[u8]) {
        let mut sorted = input.to_vec();
        sorted.sort_unstable();
        let result = execute_script_with_inputs_strict(
            script! {
                { u4_sort_with_hints(input.len() as u32) }
                { comparison(&sorted) }
            },
            witness(input),
        );
        assert!(result.success, "input {input:?}: {result}");
        assert_eq!(result.final_stack.len(), 1);
        assert_eq!(result.final_stack.get(0), vec![1]);
        assert!(
            result.stats.max_nb_stack_items <= u4_sort_stack_bound(input.len() as u32) as usize
        );
    }

    /// Zero-hint selection network using the existing two-item min/max sorter.
    /// Same canonical input/output contract; temporary minima use the altstack.
    fn network(n: u32) -> Script {
        script! {
            for depth in 0..n {
                { depth } OP_PICK
                { verify_canonical_nibble() } OP_DROP
            }
            for remaining in (1..=n).rev() {
                for _ in 1..remaining {
                    { super::super::logic::u4_sort() } OP_TOALTSTACK
                }
                for _ in 1..remaining { OP_FROMALTSTACK }
                { remaining - 1 } OP_ROLL OP_TOALTSTACK
            }
            for _ in 0..n { OP_FROMALTSTACK }
        }
    }

    #[test]
    fn exhaustive_small_and_deterministic_larger_inputs() {
        for a in 0..16 {
            for b in 0..16 {
                for c in 0..16 {
                    check(&[a, b, c]);
                }
            }
        }
        let mut rng = ChaCha20Rng::seed_from_u64(0x534f_5254_2026_1017);
        for n in [1, 2, 4, 8, 16, 32, 64] {
            check(&vec![0; n]);
            check(&vec![15; n]);
            check(&(0..n).map(|i| (i % 16) as u8).collect::<Vec<_>>());
            for _ in 0..16 {
                check(&(0..n).map(|_| rng.gen_range(0..16)).collect::<Vec<_>>());
            }
        }
    }

    #[test]
    fn hostile_operands_hints_and_wrong_multiplicity() {
        let input = [3, 0, 15, 3];
        let valid = witness(&input);
        let terminal = script! { { u4_sort_with_hints(4) } { comparison(&[0,3,3,15]) } };
        for position in 0..valid.len() {
            for bad in [
                num(-1),
                num(16),
                num(2_147_483_648),
                vec![1, 0],
                vec![0],
                vec![0x80],
                vec![1; 521],
            ] {
                let mut items = valid.clone();
                items[position] = bad;
                let result = execute_script_with_inputs_strict(terminal.clone(), items);
                assert!(
                    !result.success,
                    "accepted malformed item at {position}: {result}"
                );
            }
            let mut missing = valid.clone();
            missing.remove(position);
            assert!(!execute_script_with_inputs_strict(terminal.clone(), missing).success);
        }
        for (step, remaining) in (2..=4).rev().enumerate() {
            let mut items = valid.clone();
            items[2 - step] = num(remaining);
            let rejected = execute_script_with_inputs_strict(terminal.clone(), items);
            assert_eq!(rejected.error, Some(ExecError::Verify), "{rejected}");
        }
        let mut ascending_selection = valid.clone();
        ascending_selection[2] = num(2);
        assert!(!execute_script_with_inputs_strict(terminal.clone(), ascending_selection).success);
        let wrong = script! { { u4_sort_with_hints(4) } { comparison(&[0,3,15,15]) } };
        assert!(!execute_script_with_inputs_strict(wrong, valid.clone()).success);
        let mut extra = vec![num(9)];
        extra.extend(valid);
        assert!(!execute_script_with_inputs_strict(terminal, extra).success);
    }

    #[test]
    fn reencoding_checks_do_not_rely_on_minimaldata() {
        let input = [1, 2, 3];
        let terminal =
            script! { { u4_sort_with_hints(3) } { comparison(&input) } }.compile_with_policy();
        let options = Options {
            require_minimal: false,
            ..Options::default()
        };
        for position in 0..5 {
            let mut items = witness(&input);
            items[position].push(0);
            let result =
                execute_script_buf_with_options(terminal.clone(), items, options.clone()).unwrap();
            assert_eq!(
                result.error,
                Some(ExecError::EqualVerify),
                "position {position}: {result}"
            );
        }
    }

    #[test]
    fn pool_bound_prevents_stealing_preserved_state() {
        use bitcoin::{
            opcodes::all::*,
            script::{Builder, Instruction},
        };
        // With the bound removed, depth 2 steals a valid nibble from the
        // preserved prefix and replaces it with an operand. All remaining
        // nibble and ordering checks still pass.
        let original = u4_sort_with_hints(2).compile_with_policy();
        let mut mutant = Builder::new();
        let mut replaced = false;
        for instruction in original.instructions() {
            mutant = match instruction.unwrap() {
                Instruction::Op(op) if op == OP_WITHIN && !replaced => {
                    replaced = true;
                    mutant
                        .push_opcode(OP_2DROP)
                        .push_opcode(OP_DROP)
                        .push_opcode(OP_PUSHNUM_1)
                }
                Instruction::Op(op) => mutant.push_opcode(op),
                Instruction::PushBytes(bytes) => mutant.push_slice(bytes),
            };
        }
        assert!(replaced);
        let items = vec![num(15), num(2), num(1), num(2)];
        let rejected = execute_raw_script_with_inputs_strict(original.to_bytes(), items.clone());
        assert_eq!(rejected.error, Some(ExecError::Verify));
        let mutated = execute_raw_script_with_inputs_strict(mutant.into_script().to_bytes(), items);
        assert_eq!(
            mutated.stats.opcode_count,
            original.instructions().count() + 2
        );
        assert_eq!(mutated.final_stack.len(), 3);
        assert_eq!(mutated.final_stack.get(0), num(1));
        assert_eq!(mutated.final_stack.get(1), num(2));
        assert_eq!(mutated.final_stack.get(2), num(15));
    }

    #[test]
    fn preserves_main_and_alt_state_and_allows_equal_selector_orders() {
        let mut items = vec![num(77)];
        items.extend(witness(&[3, 1, 3, 0]));
        let result = execute_script_with_inputs_strict(
            script! {
                55 OP_TOALTSTACK
                { u4_sort_with_hints(4) }
                3 OP_EQUALVERIFY 3 OP_EQUALVERIFY 1 OP_EQUALVERIFY 0 OP_EQUALVERIFY
                77 OP_EQUALVERIFY OP_FROMALTSTACK 55 OP_EQUAL
            },
            items,
        );
        assert!(result.success, "{result}");
        // Every in-range shrinking-pool choice sorts an all-equal vector.
        for first in 0..4 {
            for second in 0..3 {
                for third in 0..2 {
                    let items = [third, second, first, 7, 7, 7, 7]
                        .into_iter()
                        .map(num)
                        .collect();
                    let result = execute_script_with_inputs_strict(
                        script! {
                            { u4_sort_with_hints(4) } { comparison(&[7;4]) }
                        },
                        items,
                    );
                    assert!(result.success, "{result}");
                }
            }
        }
    }

    #[test]
    fn exact_stack_frontier_and_preloaded_batches() {
        for n in [1, 2, 8, 32, 128, 499] {
            let input = vec![7; n as usize];
            let peak = u4_sort_stack_bound(n) as usize;
            let mut at_limit = vec![num(9); 1000 - peak];
            at_limit.extend(witness(&input));
            let terminal = script! {
                { u4_sort_with_hints(n) }
                for _ in 0..n { OP_DROP }
                for _ in 0..1000-peak { OP_DROP }
                OP_TRUE
            }
            .compile_with_policy();
            let result =
                execute_raw_script_with_inputs_strict(terminal.to_bytes(), at_limit.clone());
            assert!(result.success, "n={n}: {result}");
            assert_eq!(result.stats.max_nb_stack_items, 1000);
            at_limit.insert(0, num(9));
            let result = execute_raw_script_with_inputs_strict(terminal.to_bytes(), at_limit);
            assert_eq!(result.error, Some(ExecError::StackSize), "n={n}: {result}");
        }
        // Two batches coexist at entry: 64 operands + 62 hints = 126 items.
        let input: Vec<u8> = (0..32).map(|i| ((i * 7 + 3) % 16) as u8).collect();
        let mut sorted = input.clone();
        sorted.sort_unstable();
        let mut items = witness(&input);
        items.extend(witness(&input));
        let fragment = script! {
            { u4_sort_with_hints(32) }
            for _ in 0..32 { OP_DROP }
            { u4_sort_with_hints(32) }
        };
        let compiled = fragment.clone().compile_with_policy();
        let probe = execute_raw_script_with_inputs_strict(compiled.to_bytes(), items.clone());
        assert_eq!(probe.stats.opcode_count, compiled.instructions().count());
        eprintln!(
            "two batches n=32 bytes={} witness={} items={} hints=62 peak={} executed_nonpush={}",
            compiled.len(),
            serialize(&Witness::from_slice(&items)).len(),
            items.len(),
            probe.stats.max_nb_stack_items,
            compiled
                .instructions()
                .filter(|i| matches!(i,Ok(bitcoin::script::Instruction::Op(op)) if op.to_u8()>0x60))
                .count()
        );
        let result = execute_script_with_inputs_strict(
            script! { { fragment } { comparison(&sorted) } },
            items,
        );
        assert!(result.success, "{result}");
        assert_eq!(result.stats.max_nb_stack_items, 129);
    }

    #[test]
    fn invalid_parameters() {
        for n in [0, 500, u32::MAX] {
            assert!(std::panic::catch_unwind(|| u4_sort_with_hints(n)).is_err());
        }
        assert!(std::panic::catch_unwind(|| u4_sort_hints(&[16])).is_err());
    }

    #[test]
    fn order_guard_and_maximum_witness_sizes() {
        // Select the minimum first; rejection must come from the fragment,
        // even when the caller discards every output.
        let rejected = execute_script_with_inputs_strict(
            script! {
                { u4_sort_with_hints(3) }
                OP_DROP OP_DROP OP_DROP OP_TRUE
            },
            [0, 2, 1, 2, 3].into_iter().map(num).collect(),
        );
        assert_eq!(rejected.error, Some(ExecError::Verify), "{rejected}");
        for (n, maximum) in [(8, 31), (32, 127)] {
            // Equal nonzero operands allow every hint to be nonzero, attaining
            // the upper serialization bound at these one-byte selector widths.
            let mut items: Vec<Vec<u8>> = (1..n).map(num).collect();
            items.extend((0..n).map(|_| num(7)));
            assert_eq!(serialize(&Witness::from_slice(&items)).len(), maximum);
            let result = execute_script_with_inputs_strict(
                script! {
                    { u4_sort_with_hints(n as u32) } { comparison(&vec![7;n as usize]) }
                },
                items,
            );
            assert!(result.success, "{result}");
        }
    }

    #[test]
    fn compare_zero_hint_network() {
        eprintln!(
            "interpreter={} compiler={}",
            crate::support::provenance::interpreter().unwrap().commit,
            crate::support::provenance::compiler().unwrap().commit
        );
        for n in [1, 2, 4, 8, 16, 32] {
            let input: Vec<u8> = (0..n).map(|i| ((i * 7 + 3) % 16) as u8).collect();
            let mut sorted = input.clone();
            sorted.sort_unstable();
            for (name, fragment, items) in [
                ("hinted", u4_sort_with_hints(n), witness(&input)),
                (
                    "network",
                    network(n),
                    input.iter().map(|x| num((*x).into())).collect(),
                ),
            ] {
                let compiled = fragment.clone().compile_with_policy();
                let ops = compiled
                    .instructions()
                    .filter(
                        |i| matches!(i,Ok(bitcoin::script::Instruction::Op(op)) if op.to_u8()>0x60),
                    )
                    .count();
                // Probe the exact fragment bytes without an optimizable
                // terminal wrapper. The fragment leaves n outputs, so this
                // is an execution/stack probe, not a complete-leaf verdict.
                let probe =
                    execute_raw_script_with_inputs_strict(compiled.to_bytes(), items.clone());
                assert_eq!(probe.stats.opcode_count, compiled.instructions().count());
                assert_eq!(probe.final_stack.len(), n as usize);
                for (i, x) in sorted.iter().enumerate() {
                    assert_eq!(probe.final_stack.get(i), num((*x).into()));
                }
                let result = execute_script_with_inputs_strict(
                    script! { { fragment } { comparison(&sorted) } },
                    items.clone(),
                );
                assert!(result.success, "{name} n={n}: {result}");
                eprintln!("{name} n={n} bytes={} witness={} items={} hints={} peak={} executed_nonpush={ops} sha256={}",compiled.len(),serialize(&Witness::from_slice(&items)).len(),items.len(),if name=="hinted" {n-1} else {0},probe.stats.max_nb_stack_items,sha256::Hash::hash(compiled.as_bytes()));
            }
        }
    }
}
