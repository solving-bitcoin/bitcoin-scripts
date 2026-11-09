//! Runtime-offset rotation of opaque stack items.

use crate::{arithmetic::scriptint::verify_canonical, support::script::*};

mod routing;
use routing::{initial_depth, wrap_depth};

pub const MAX_PAYLOADS: u32 = 996;

/// Consume the canonical offset `k` from `x[0] ... x[n-1] k` and rotate the
/// opaque payloads left by `k` in that bottom-to-top order. Requires
/// `1..=996` items and `0 <= k < n`. Payload bytes and caller stacks
/// survive. There are no hints. Peak is at most `n + 4` plus caller state.
pub fn rotate_opaque_left(n: u32) -> Script {
    assert!(
        (1..=MAX_PAYLOADS).contains(&n),
        "rotation requires 1..=996 payloads"
    );
    script! {
        {initial_depth(n)}
        for remaining in (1..=n).rev() {
            {wrap_depth(remaining)}
            // The retained depth itself occupies one position above the data.
            OP_DUP OP_1ADD OP_ROLL OP_TOALTSTACK
        }
        OP_DROP
        for _ in 0..n {OP_FROMALTSTACK}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{
        execution::ExecuteInfo,
        tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
    };
    use bitcoin::ScriptBuf;
    use bitcoin_scriptexec::ExecError;

    mod baseline {
        use crate::{arithmetic::scriptint::verify_canonical, support::script::*};
        include!("../../../research/runtime-opaque-rotation/baseline.rs");
    }

    mod fixture {
        include!("../../../research/runtime-opaque-rotation/fixture.rs");
    }

    const GENERATORS: [fn(u32) -> Script; 2] = [rotate_opaque_left, baseline::copy];

    fn leaf(fragment: Script, expected: &[Vec<u8>]) -> ScriptBuf {
        script! {
            {fragment}
            for value in expected.iter().rev() {{value.clone()} OP_EQUALVERIFY}
            OP_TRUE
        }
        .compile_with_policy()
    }

    fn run(script: ScriptBuf, witness: Vec<Vec<u8>>) -> ExecuteInfo {
        match execute_tapscript(script, witness, TapscriptProfile::Consensus).outcome {
            TapscriptOutcome::Executed(result) => result,
            outcome => panic!("expected executed result: {outcome:?}"),
        }
    }

    fn assert_clean_true(result: &ExecuteInfo) {
        assert!(result.success, "{result}");
        assert!(result.stack_limit_enforced);
        assert_eq!(result.final_stack.len(), 1);
        assert_eq!(result.final_stack.get(0), vec![1]);
    }

    #[test]
    fn agrees_with_host_for_every_small_offset() {
        for n in 1..=12u32 {
            let payloads: Vec<_> = (0..n)
                .map(|i| match i % 4 {
                    0 => vec![],
                    1 => vec![0x80],
                    2 => vec![1, 0],
                    _ => vec![i as u8; 520],
                })
                .collect();
            let scripts = GENERATORS.map(|generate| {
                script! {
                    for _ in 0..n {OP_TOALTSTACK}
                    {generate(n)}
                    for _ in 0..n {OP_FROMALTSTACK OP_EQUALVERIFY}
                    OP_TRUE
                }
                .compile_with_policy()
            });
            for k in 0..n {
                let mut expected = payloads.clone();
                expected.rotate_left(k as usize);
                let mut witness = payloads.clone();
                witness.push(fixture::scriptnum(k));
                witness.extend(expected.into_iter().rev());
                for script in &scripts {
                    assert_clean_true(&run(script.clone(), witness.clone()));
                }
            }
        }
    }

    #[test]
    fn rejects_malformed_offsets_shapes_and_wrong_output_order() {
        let payloads = fixture::payloads(4);
        let mut expected = payloads.clone();
        expected.rotate_left(3);
        for generate in GENERATORS {
            let fragment = generate(4);
            let script = leaf(fragment.clone(), &expected);
            let mut honest = payloads.clone();
            honest.push(fixture::scriptnum(3));
            assert_clean_true(&run(script.clone(), honest.clone()));
            assert!(!run(leaf(fragment, &payloads), honest.clone()).success);
            for (bad, error) in [
                (vec![0x81], ExecError::Verify),
                (fixture::scriptnum(4), ExecError::Verify),
                (vec![0x80], ExecError::EqualVerify),
                (vec![1, 0], ExecError::EqualVerify),
                (vec![0; 5], ExecError::ScriptIntNumericOverflow),
                (vec![0; 521], ExecError::PushSize),
            ] {
                let mut data = payloads.clone();
                data.push(bad);
                assert_eq!(run(script.clone(), data).error, Some(error));
            }
            let mut oversized = honest.clone();
            oversized[1] = vec![0; 521];
            assert_eq!(
                run(script.clone(), oversized).error,
                Some(ExecError::PushSize)
            );
            let mut short = honest.clone();
            short.remove(0);
            assert!(!run(script.clone(), short).success);
            let mut extra = honest;
            extra.insert(0, vec![]);
            assert!(!run(script, extra).success);
        }
    }

    #[test]
    fn periodic_payloads_can_have_more_than_one_matching_offset() {
        let payloads = vec![vec![0x61], vec![0x62], vec![0x61], vec![0x62]];
        let script = leaf(rotate_opaque_left(4), &payloads);
        for offset in [0, 2] {
            let mut witness = payloads.clone();
            witness.push(fixture::scriptnum(offset));
            assert_clean_true(&run(script.clone(), witness));
        }
    }

    #[test]
    fn proves_stack_frontiers_and_preserves_caller_data() {
        let n = MAX_PAYLOADS;
        let payloads = fixture::payloads(n);
        let mut expected = payloads.clone();
        expected.rotate_left((n - 1) as usize);
        let closed = leaf(rotate_opaque_left(n), &expected);
        let mut witness = payloads;
        witness.push(fixture::scriptnum(n - 1));
        let result = run(closed, witness);
        assert_clean_true(&result);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        for n in [499u32, 500] {
            let script = leaf(baseline::copy(n), &vec![vec![]; n as usize]);
            let result = run(script, vec![vec![]; n as usize + 1]);
            if n == 499 {
                assert_clean_true(&result);
                assert_eq!(result.stats.max_nb_stack_items, 1000);
            } else {
                assert_eq!(result.error, Some(ExecError::StackSize));
            }
        }

        let n = MAX_PAYLOADS - 2;
        let payloads = fixture::payloads(n);
        let mut expected = payloads.clone();
        expected.rotate_left(1);
        let script = script! {
            OP_TOALTSTACK {rotate_opaque_left(n)} OP_FROMALTSTACK
        }
        .compile_with_policy();
        let main = vec![0x91, 0x36];
        let alt = vec![0x82, 0x42];
        let mut witness = [
            vec![main.clone()],
            payloads,
            vec![fixture::scriptnum(1), alt.clone()],
        ]
        .concat();
        let result = run(script.clone(), witness.clone());
        assert_eq!(result.error, None);
        assert_eq!(result.stats.max_nb_stack_items, 1000);
        let actual: Vec<_> = (0..result.final_stack.len())
            .map(|i| result.final_stack.get(i))
            .collect();
        assert_eq!(actual, [vec![main], expected, vec![alt]].concat());
        witness.insert(0, vec![]);
        assert_eq!(run(script, witness).error, Some(ExecError::StackSize));
        for n in [0, MAX_PAYLOADS + 1] {
            assert!(std::panic::catch_unwind(|| rotate_opaque_left(n)).is_err());
        }
    }
}
