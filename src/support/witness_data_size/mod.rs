//! A byte cap on a fixed suffix serialized as a standalone witness data vector.

use crate::{arithmetic::scriptint::MAX_SCRIPTNUM, support::script::*};

mod schedule;
use schedule::{check_with, fixed_bytes, LONG_COMPACTSIZE};

pub const MAX_TIGHT_ITEMS: u32 = 997;
pub const MAX_EXACT_ITEMS: u32 = 996;

/// Verify a cap on the serialized size of the top `items` data elements,
/// including their vector count and per-item CompactSize lengths.
///
/// The suffix consists of opaque byte vectors of at most 520 bytes. The
/// fragment preserves their order and content and both caller stacks.
/// It leaves no predicate result and requires no hints. The cap is at
/// most the largest positive four-byte ScriptNum. Tight caps use at most
/// `items + 3` combined items; other caps use at most `items + 4` for
/// nonempty data, plus preserved caller state.
pub fn verify_data_witness_size_at_most(items: u32, cap: u32) -> Script {
    assert!(items <= MAX_TIGHT_ITEMS, "too many data items");
    assert!(
        cap <= MAX_SCRIPTNUM,
        "byte cap exceeds positive ScriptNum range"
    );

    let tight = cap < fixed_bytes(items) + LONG_COMPACTSIZE;
    assert!(
        tight || items <= MAX_EXACT_ITEMS,
        "exact size check has a 996-item limit"
    );
    let surcharge = script! {
        if !tight {
            // Stack top is the raw item length. Add two bytes for a long prefix.
            OP_DUP {LONG_COMPACTSIZE} OP_GREATERTHANOREQUAL
            OP_DUP OP_ADD OP_ADD
        }
    };
    check_with(items, cap, surcharge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{
        execution::ExecuteInfo,
        tapscript::{
            execute_tapscript, TapscriptOutcome, TapscriptPolicyRejection, TapscriptProfile,
        },
    };
    use bitcoin::{consensus::encode::serialize, ScriptBuf, Witness};
    use bitcoin_scriptexec::ExecError;

    mod baseline {
        use crate::support::script::*;
        include!("../../../research/witness-data-byte-cap/baseline.rs");
    }

    const PROFILE: TapscriptProfile = TapscriptProfile::Consensus;
    const GENERATORS: [fn(u32, u32) -> Script; 2] =
        [verify_data_witness_size_at_most, baseline::conditional];

    fn run_tapscript(
        script: ScriptBuf,
        data: Vec<Vec<u8>>,
        profile: TapscriptProfile,
    ) -> ExecuteInfo {
        match execute_tapscript(script, data, profile).outcome {
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

    fn leaf(fragment: Script, items: u32) -> ScriptBuf {
        script! {
            {fragment}
            for _ in 0..items {OP_DROP}
            OP_TRUE
        }
        .compile_with_policy()
    }

    fn serialized_size(data: &[Vec<u8>]) -> u32 {
        serialize(&Witness::from_slice(data)).len() as u32
    }

    fn fixture(lengths: &[usize]) -> Vec<Vec<u8>> {
        lengths
            .iter()
            .enumerate()
            .map(|(i, &size)| vec![0x80 | i as u8; size])
            .collect()
    }

    #[test]
    fn compares_exactly_with_host_serialization() {
        let sizes = [0, 1, 80, 251, 252, 253, 254, 519, 520];
        let mut cases = vec![vec![], vec![vec![]; 252], vec![vec![]; 253]];
        for a in sizes {
            for b in sizes {
                cases.push(fixture(&[a, b]));
            }
        }
        cases.push(fixture(&[0, 1, 32, 252, 253, 520]));
        for data in cases {
            let n = data.len() as u32;
            let size = serialized_size(&data);
            for generate in GENERATORS {
                for cap in [size - 1, size, size + 1] {
                    let result = run_tapscript(leaf(generate(n, cap), n), data.clone(), PROFILE);
                    if cap < size {
                        assert_eq!(result.error, Some(ExecError::Verify));
                    } else {
                        assert_clean_true(&result);
                    }
                }
            }
        }
    }

    #[test]
    fn first_unsafe_cap_requires_the_compactsize_surcharge() {
        let short = fixture(&[252, 0]);
        let long = fixture(&[253, 0]);
        assert_eq!(serialized_size(&short), 255);
        assert_eq!(serialized_size(&long), 258);
        let tight = leaf(verify_data_witness_size_at_most(2, 255), 2);
        assert_clean_true(&run_tapscript(tight.clone(), short, PROFILE));
        assert!(!run_tapscript(tight, long.clone(), PROFILE).success);
        let weak = leaf(check_with(2, 256, script! {}), 2);
        assert_clean_true(&run_tapscript(weak, long.clone(), PROFILE));
        for cap in [256, 257] {
            assert!(
                !run_tapscript(
                    leaf(verify_data_witness_size_at_most(2, cap), 2),
                    long.clone(),
                    PROFILE
                )
                .success
            );
        }
        assert_clean_true(&run_tapscript(
            leaf(verify_data_witness_size_at_most(2, 258), 2),
            long,
            PROFILE,
        ));
    }

    #[test]
    fn preserves_opaque_data_and_surrounding_stacks() {
        let n = 4;
        let data = fixture(&[0, 1, 253, 520]);
        let cap = serialized_size(&data);
        let main = vec![0x01, 0x00];
        let alt = vec![0x80];
        for generate in GENERATORS {
            let fragment = generate(n, cap);
            let script =
                script! {OP_TOALTSTACK {fragment.clone()} OP_FROMALTSTACK}.compile_with_policy();
            let input = [vec![main.clone()], data.clone(), vec![alt.clone()]].concat();
            let result = run_tapscript(script, input.clone(), PROFILE);
            assert_eq!(result.error, None);
            let actual: Vec<_> = (0..result.final_stack.len())
                .map(|i| result.final_stack.get(i))
                .collect();
            assert_eq!(actual, input);
            let mut oversized = data.clone();
            oversized[1] = vec![0; 521];
            let closed = leaf(fragment, n);
            assert_eq!(
                run_tapscript(closed.clone(), oversized, PROFILE).error,
                Some(ExecError::PushSize)
            );
            let mut short = data.clone();
            short.pop();
            assert!(!run_tapscript(closed.clone(), short, PROFILE).success);
            let mut long = data.clone();
            long.insert(0, vec![]);
            assert!(!run_tapscript(closed, long, PROFILE).success);
        }
    }

    #[test]
    fn reaches_the_exact_stack_frontiers() {
        for (n, wide) in [(MAX_TIGHT_ITEMS, false), (MAX_EXACT_ITEMS, true)] {
            let cap = fixed_bytes(n) + if wide { LONG_COMPACTSIZE } else { 0 };
            let closed = leaf(verify_data_witness_size_at_most(n, cap), n);
            let mut data = vec![vec![]; n as usize];
            let result = run_tapscript(closed.clone(), data.clone(), PROFILE);
            assert_clean_true(&result);
            assert_eq!(result.stats.max_nb_stack_items, 1000);
            data.insert(0, vec![]);
            assert_eq!(
                run_tapscript(closed, data, PROFILE).error,
                Some(ExecError::StackSize)
            );
        }
        for (n, cap) in [
            (998, 0),
            (997, fixed_bytes(997) + LONG_COMPACTSIZE),
            (1, MAX_SCRIPTNUM + 1),
        ] {
            assert!(std::panic::catch_unwind(|| verify_data_witness_size_at_most(n, cap)).is_err());
        }
    }

    #[test]
    fn item_policy_is_checked_before_the_fragment() {
        let script = leaf(verify_data_witness_size_at_most(1, 100), 1);
        let profile = TapscriptProfile::Policy;
        assert_eq!(
            execute_tapscript(script.clone(), fixture(&[80]), profile).accepted(),
            Some(true)
        );
        assert!(matches!(
            execute_tapscript(script, fixture(&[81]), profile).outcome,
            TapscriptOutcome::PolicyRejected(TapscriptPolicyRejection::WitnessStackItemSize {
                index: 0,
                size: 81
            })
        ));
    }
}
