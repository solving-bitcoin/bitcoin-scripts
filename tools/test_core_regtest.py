"""Offline guards for the Core harness's serialization and rejection criteria."""

import unittest

from core_regtest import RPCError, compact_size, compare_local_profiles, consensus_check, interpreter_provenance, rejection_matches


class CoreHarnessTests(unittest.TestCase):
    def test_compact_size_boundaries(self):
        for value, expected in [(0, "00"), (252, "fc"), (253, "fdfd00"),
                                (65535, "fdffff"), (65536, "fe00000100"),
                                (2**32, "ff0000000001000000")]:
            self.assertEqual(compact_size(value).hex(), expected)
        with self.assertRaises(ValueError):
            compact_size(-1)

    def test_wrong_script_failure_does_not_satisfy_a_boundary(self):
        result = {"accepted": False, "reason": "TestBlockValidity failed: block-script-verify-flag-failed (Witness program hash mismatch), input 0 of abc"}
        self.assertTrue(rejection_matches(result, "taproot-commitment"))
        self.assertFalse(rejection_matches(result, "stack-size"))
        self.assertFalse(rejection_matches(result, None))

    def test_policy_failure_is_distinct_from_consensus_failure(self):
        result = {"allowed": False, "reject-reason": "bad-witness-nonstandard"}
        self.assertTrue(rejection_matches(result, "witness-stack-item-size", policy=True))
        self.assertFalse(rejection_matches(result, "push-size", policy=True))
        self.assertFalse(rejection_matches({"allowed": True}, "witness-stack-item-size", policy=True))

    def test_infrastructure_errors_are_not_consensus_rejections(self):
        class FailingNode:
            def __init__(self, code, message):
                self.error = RPCError({"code": code, "message": message})

            def tick(self):
                pass

            def rpc(self, method, *params):
                if method == "getblockcount":
                    return 102
                raise self.error

        for code, message in [(-22, "Transaction decode failed"), (-25, "TestBlockValidity failed: bad-txns-inputs-missingorspent"),
                              (-1, "Failed to make block.")]:
            with self.subTest(code=code, message=message), self.assertRaises(RPCError):
                consensus_check(FailingNode(code, message), "address", {"hex": "00"})
        accepted_error = FailingNode(-25, "TestBlockValidity failed: block-script-verify-flag-failed (Stack size limit exceeded), input 0 of abc")
        self.assertFalse(consensus_check(accepted_error, "address", {"hex": "00"})["accepted"])

    @staticmethod
    def profile_fixture(consensus=False, policy=False):
        return {"name": "ordinary-boundary",
                "local_profile_comparison": {"compare_to_core": True,
                                             "expected": {"consensus": consensus, "policy": policy}},
                "local_profiles": {name: {"accepted": accepted, "outcome": "executed"}
                                   for name, accepted in [("consensus", consensus), ("policy", policy)]}}

    def test_profile_difference_must_match_both_core_verdicts(self):
        fixture = self.profile_fixture(consensus=True, policy=False)
        matched = compare_local_profiles(fixture, {"accepted": True}, {"allowed": False})
        self.assertTrue(matched["matches_expected"])
        wrong_consensus = compare_local_profiles(fixture, {"accepted": False}, {"allowed": False})
        self.assertFalse(wrong_consensus["matches_expected"])
        self.assertEqual(wrong_consensus["profiles"]["consensus"]["status"], "mismatch")
        fixture["local_profiles"]["policy"]["accepted"] = True
        self.assertFalse(compare_local_profiles(fixture, {"accepted": True}, {"allowed": False})["matches_expected"])

    def test_panics_unsupported_and_initialization_errors_are_not_rejections(self):
        for outcome in ["panic", "unsupported-opcode", "initialization-error"]:
            for accepted in [None, False]:
                with self.subTest(outcome=outcome, accepted=accepted):
                    fixture = self.profile_fixture()
                    fixture["local_profiles"]["consensus"] = {"outcome": outcome, "accepted": accepted}
                    comparison = compare_local_profiles(fixture, {"accepted": False}, {"allowed": False})
                    self.assertFalse(comparison["matches_expected"])
                    self.assertEqual(comparison["profiles"]["consensus"]["status"], "no-verdict")

    def test_only_explicit_commitment_case_may_skip_core_profile_equality(self):
        fixture = self.profile_fixture(consensus=True, policy=True)
        fixture["local_profile_comparison"]["compare_to_core"] = False
        with self.assertRaises(ValueError):
            compare_local_profiles(fixture, {"accepted": False}, {"allowed": False})
        fixture["name"] = "winternitz-invalid-control-block"
        comparison = compare_local_profiles(fixture, {"accepted": False}, {"allowed": False})
        self.assertTrue(comparison["matches_expected"])
        self.assertIsNone(comparison["profiles"]["consensus"]["matches_core"])
        fixture["local_profiles"]["consensus"]["accepted"] = False
        self.assertFalse(compare_local_profiles(fixture, {"accepted": False}, {"allowed": False})["matches_expected"])

    def test_minimal_push_and_numeric_minimality_use_distinct_diagnostics(self):
        push = {"allowed": False, "reject-reason": "mempool-script-verify-flag-failed (Data push larger than necessary)"}
        number = {"allowed": False, "reject-reason": "mempool-script-verify-flag-failed (unknown error)"}
        self.assertTrue(rejection_matches(push, "minimal-push", policy=True))
        self.assertFalse(rejection_matches(push, "minimaldata", policy=True))
        self.assertTrue(rejection_matches(number, "minimaldata", policy=True))
        self.assertFalse(rejection_matches(number, "minimal-push", policy=True))

    def test_interpreter_provenance_requires_exactly_one_matching_immutable_source(self):
        commit = "4b7269a415f21be3fccee9730547f1426eb80326"
        fixture = {"local_interpreter": {"commit": commit}}
        package = {"name": "bitcoin-scriptexec", "version": "0.0.0",
                   "source": f"git+https://github.com/adrienlacombe/rust-bitcoin-scriptexec?rev={commit}#{commit}"}
        self.assertEqual(interpreter_provenance(fixture, {"packages": [package]}), package)
        for packages in [[], [package, package], [{**package, "source": None}],
                         [{**package, "source": package["source"].replace(commit, "0" * 40)}]]:
            with self.subTest(packages=packages), self.assertRaises(RuntimeError):
                interpreter_provenance(fixture, {"packages": packages})
        with self.assertRaises(RuntimeError):
            interpreter_provenance({"local_interpreter": {"commit": "master"}}, {"packages": [package]})


if __name__ == "__main__":
    unittest.main()
