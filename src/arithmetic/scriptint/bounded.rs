//! Canonical bounded division by a positive public ScriptNum constant.

use super::{assert_divisor, verify_canonical, MAX_SCRIPTNUM};
use crate::support::script::*;

/// Consume canonical `x` in `0..=maximum` and return `quotient | remainder`,
/// with the remainder on top. No hints or altstack space are needed.
///
/// The public divisor is in `1..=MAX_SCRIPTNUM`; maximum is in
/// `0..=MAX_SCRIPTNUM`. Both are required, with no default. Caller main/alt
/// state is preserved. This is an arithmetic fragment, not a terminal leaf.
pub fn div_rem(divisor: u32, maximum: u32) -> Script {
    let arithmetic = div_rem_unchecked(divisor, maximum);
    script! {
        { verify_canonical() }
        OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
        OP_DUP { maximum } OP_LESSTHANOREQUAL OP_VERIFY
        { arithmetic }
    }
}

/// Shared arithmetic core for already-certified residuals, including the
/// factoradic permutation decoder. The caller proves canonical `0<=x<=maximum`.
pub(crate) fn div_rem_unchecked(divisor: u32, maximum: u32) -> Script {
    assert_divisor(divisor);
    assert!(
        maximum <= MAX_SCRIPTNUM,
        "maximum must fit positive ScriptNum"
    );
    let bits = u32::BITS - (maximum / divisor).leading_zeros();
    script! {
        0 OP_SWAP
        for bit in (0..bits).rev() {
            // divisor*2^bit <= maximum: every constant and intermediate
            // remains in the four-byte operand domain, even at MAX_SCRIPTNUM.
            OP_DUP { divisor * (1u32 << bit) } OP_GREATERTHANOREQUAL
            OP_IF
                { divisor * (1u32 << bit) } OP_SUB
                OP_SWAP { 1u32 << bit } OP_ADD OP_SWAP
            OP_ENDIF
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::{
            scriptint::hinted_div_rem,
            test_helpers::{assert_clean_true, run_tapscript, scriptnum},
        },
        support::{script::ScriptCompilation, tapscript::TapscriptProfile},
    };
    use bitcoin::{consensus::serialize, Witness};
    use bitcoin_scriptexec::ExecError;

    fn leaf(fragment: Script, quotient: u32, remainder: u32) -> bitcoin::ScriptBuf {
        script! {
            { fragment }
            { remainder } OP_EQUALVERIFY
            { quotient } OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy()
    }

    fn check(divisor: u32, maximum: u32, x: u32) {
        let result = run_tapscript(
            leaf(div_rem(divisor, maximum), x / divisor, x % divisor),
            vec![scriptnum(x.into())],
            TapscriptProfile::Consensus,
        );
        assert_clean_true(&result);
        assert!(result.stats.max_nb_stack_items <= 4);
    }

    #[test]
    fn exhaustive_small_divisors_and_paired_choices() {
        for divisor in 1..=32 {
            for x in 0..=63 {
                check(divisor, 63, x);
            }
        }
        // One packed payload encodes a choice in 0..32 and another in 0..31.
        for first in 0..32 {
            for second in 0..31 {
                check(31, 991, 31 * first + second);
            }
        }
    }

    #[test]
    fn full_scriptnum_boundaries_and_deterministic_values() {
        for divisor in [1, 2, 3, 17, 31, 256, 65537, MAX_SCRIPTNUM] {
            for maximum in [0, 1, 127, 128, 255, 256, 991, 65535, MAX_SCRIPTNUM] {
                for x in [0, maximum / 2, maximum] {
                    check(divisor, maximum, x);
                }
                for multiple in [1u64, 2, 3, 7, 16, 31] {
                    let boundary = multiple * u64::from(divisor);
                    for x in [boundary.saturating_sub(1), boundary, boundary + 1] {
                        if x <= u64::from(maximum) {
                            check(divisor, maximum, x as u32);
                        }
                    }
                }
            }
        }
        let mut state = 0x4449_565f_2026_1017u64;
        for _ in 0..128 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let x = (state as u32) & MAX_SCRIPTNUM;
            check(31, MAX_SCRIPTNUM, x);
        }
    }

    #[test]
    fn hostile_encodings_and_widths_reject_without_minimaldata() {
        let compiled = leaf(div_rem(31, 991), 31, 30);
        for bad in [
            scriptnum(-1),
            scriptnum(992),
            scriptnum(2147483648),
            vec![0],
            vec![0x80],
            vec![32, 0],
            vec![0; 5],
            vec![0; 521],
        ] {
            let result = run_tapscript(compiled.clone(), vec![bad], TapscriptProfile::Consensus);
            assert!(!result.success, "{result}");
        }
        assert!(!run_tapscript(compiled.clone(), vec![], TapscriptProfile::Consensus).success);
        assert!(
            !run_tapscript(
                compiled,
                vec![scriptnum(7), scriptnum(991)],
                TapscriptProfile::Consensus
            )
            .success
        );
    }

    #[test]
    fn input_guards_are_load_bearing() {
        let public = run_tapscript(
            leaf(div_rem(31, 991), 1, 1),
            vec![vec![32, 0]],
            TapscriptProfile::Consensus,
        );
        assert_eq!(public.error, Some(ExecError::EqualVerify));
        let no_canonical = script! {
            OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP 991 OP_LESSTHANOREQUAL OP_VERIFY
            { div_rem_unchecked(31,991) }
        };
        let mutated = run_tapscript(
            leaf(no_canonical, 1, 1),
            vec![vec![32, 0]],
            TapscriptProfile::Consensus,
        );
        assert_clean_true(&mutated);

        let rejected = run_tapscript(
            leaf(div_rem(31, 991), 31, 31),
            vec![scriptnum(992)],
            TapscriptProfile::Consensus,
        );
        assert_eq!(rejected.error, Some(ExecError::Verify));
        let unchecked = run_tapscript(
            leaf(div_rem_unchecked(31, 991), 31, 31),
            vec![scriptnum(992)],
            TapscriptProfile::Consensus,
        );
        assert_clean_true(&unchecked); // Invalid remainder exposes the missing bound.
    }

    #[test]
    fn both_caller_stacks_and_exact_frontiers() {
        let compiled = script! {
            1 OP_ROLL OP_TOALTSTACK
            { div_rem(31,991) }
            30 OP_EQUALVERIFY 31 OP_EQUALVERIFY
            77 OP_EQUALVERIFY OP_FROMALTSTACK 55 OP_EQUALVERIFY OP_TRUE
        }
        .compile_with_policy();
        assert_clean_true(&run_tapscript(
            compiled,
            vec![scriptnum(77), scriptnum(55), scriptnum(991)],
            TapscriptProfile::Consensus,
        ));
        for preserved in [996, 997] {
            let compiled = script! {
                { div_rem(31,991) }
                30 OP_EQUALVERIFY 31 OP_EQUALVERIFY
                for _ in 0..preserved { 7 OP_EQUALVERIFY }
                OP_TRUE
            }
            .compile_with_policy();
            let mut items = vec![scriptnum(7); preserved];
            items.push(scriptnum(991));
            let result = run_tapscript(compiled, items, TapscriptProfile::Consensus);
            if preserved == 996 {
                assert_clean_true(&result);
                assert_eq!(result.stats.max_nb_stack_items, 1000);
            } else {
                assert_eq!(result.error, Some(ExecError::StackSize));
            }
        }
    }

    #[test]
    fn invalid_parameters_reject_at_generation() {
        for (divisor, maximum) in [
            (0, 991),
            (MAX_SCRIPTNUM + 1, 991),
            (31, MAX_SCRIPTNUM + 1),
            (u32::MAX, u32::MAX),
        ] {
            assert!(std::panic::catch_unwind(|| div_rem(divisor, maximum)).is_err());
        }
    }

    // Same canonical dividend/output contract. A quotient hint is normalized
    // before the existing verifier, allowing harmless numeric aliases while
    // returning canonical outputs even with MINIMALDATA disabled.
    fn hinted_checked(divisor: u32, maximum: u32) -> Script {
        script! {
            { verify_canonical() }
            OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
            OP_DUP {maximum} OP_LESSTHANOREQUAL OP_VERIFY
            OP_SWAP 0 OP_ADD OP_SWAP
            { hinted_div_rem(divisor) }
        }
    }

    #[test]
    fn matched_hint_baseline_and_metric_probe() {
        eprintln!(
            "compiler={} interpreter={}",
            crate::support::provenance::compiler().unwrap().commit,
            crate::support::provenance::interpreter().unwrap().commit
        );
        for (divisor, maximum, x) in [
            (31, 991, 991),
            (17, 271, 271),
            (31, MAX_SCRIPTNUM, MAX_SCRIPTNUM),
        ] {
            for (name, fragment, items, hints) in [
                (
                    "direct",
                    div_rem(divisor, maximum),
                    vec![scriptnum(x.into())],
                    0,
                ),
                (
                    "hinted",
                    hinted_checked(divisor, maximum),
                    vec![scriptnum((x / divisor).into()), scriptnum(x.into())],
                    1,
                ),
            ] {
                let fragment_bytes = fragment.clone().compile_with_policy().len();
                let compiled = leaf(fragment, x / divisor, x % divisor);
                let result =
                    run_tapscript(compiled.clone(), items.clone(), TapscriptProfile::Consensus);
                assert_clean_true(&result);
                eprintln!("{name} d={divisor} maximum={maximum} x={x} fragment={fragment_bytes} leaf={} witness={} items={} hints={hints} peak={}",compiled.len(),serialize(&Witness::from_slice(&items)).len(),items.len(),result.stats.max_nb_stack_items);
            }
        }
        for (divisor, x) in [(31, 991), (17, 271)] {
            let q = x / divisor;
            let compiled = leaf(hinted_checked(divisor, x), q, x % divisor);
            let mut aliases = vec![scriptnum(q.into()), scriptnum(x.into())];
            aliases[0].resize(4, 0);
            assert_eq!(serialize(&Witness::from_slice(&aliases)).len(), 9);
            assert_clean_true(&run_tapscript(
                compiled.clone(),
                aliases,
                TapscriptProfile::Consensus,
            ));
            for raw in [
                scriptnum(-1),
                scriptnum(0),
                scriptnum(i64::from(q) - 1),
                scriptnum(i64::from(q) + 1),
                scriptnum(2147483647),
                scriptnum(2147483648),
                vec![0; 521],
            ] {
                let bad = run_tapscript(
                    compiled.clone(),
                    vec![raw, scriptnum(x.into())],
                    TapscriptProfile::Consensus,
                );
                assert!(!bad.success, "{bad}");
            }
        }
        assert_clean_true(&run_tapscript(
            leaf(hinted_checked(31, 991), 0, 0),
            vec![vec![0x80], vec![]],
            TapscriptProfile::Consensus,
        ));
    }
}
