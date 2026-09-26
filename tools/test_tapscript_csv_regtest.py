"""Offline failure guards for funded CHECKSEQUENCEVERIFY comparisons."""

import copy
import unittest

from tapscript_csv_regtest import (compare_local, csv_transaction, rejection_matches,
                                  run_passed, validate_funded_manifest, validate_witness)


class CsvHarnessTests(unittest.TestCase):
    def test_transaction_sequence_and_version_change_the_identifiers(self):
        witness = [b"\0\0\0\0\1", b"\xb2\x75\x51", b"\xc0" * 33]
        args = ("42" * 32, 3, witness, [(990_000, b"\x51")])
        base = csv_transaction(*args, 2, 0)
        assert base["witness_bytes"] == 1 + sum(1 + len(item) for item in witness)
        assert base["weight"] == 4 * base["base_bytes"] + 2 + base["witness_bytes"]
        self.assertNotEqual(base["txid"], csv_transaction(*args, 1, 0)["txid"])
        self.assertNotEqual(base["txid"], csv_transaction(*args, 2, 1)["txid"])
        self.assertNotEqual(base["wtxid"], csv_transaction(*args, 2, 1)["wtxid"])

    def test_panics_and_initialization_errors_cannot_match_core_rejection(self):
        for outcome in ("panic", "initialization-error", "unsupported"):
            fixture = {"expected": {"consensus_rejection": "unsatisfied-locktime"},
                       "local_consensus": {"outcome": outcome, "accepted": False,
                                           "error": "UnsatisfiedLocktime"}}
            self.assertEqual(compare_local(fixture, {"accepted": False}, "consensus")["status"], "no-verdict")

    def test_local_verdict_and_error_category_both_matter(self):
        fixture = {"expected": {"consensus_rejection": "unsatisfied-locktime"},
                   "local_consensus": {"outcome": "executed", "accepted": False,
                                       "error": "NegativeLocktime"}}
        self.assertFalse(compare_local(fixture, {"accepted": False}, "consensus")["matches_core"])
        fixture["local_consensus"]["error"] = "UnsatisfiedLocktime"
        self.assertTrue(compare_local(fixture, {"accepted": False}, "consensus")["matches_core"])
        self.assertFalse(compare_local(fixture, {"accepted": True}, "consensus")["matches_core"])

    def test_error_category_has_exact_core_diagnostic(self):
        consensus = {"accepted": False, "reason": "TestBlockValidity failed: block-script-verify-flag-failed (Locktime requirement not satisfied), input 0 of 42"}
        policy = {"allowed": False, "reject-reason": "mempool-script-verify-flag-failed (Locktime requirement not satisfied)"}
        self.assertTrue(rejection_matches(consensus, "unsatisfied-locktime"))
        self.assertTrue(rejection_matches(policy, "unsatisfied-locktime", policy=True))
        self.assertFalse(rejection_matches(consensus, "negative-locktime"))
        self.assertFalse(rejection_matches(policy, "numeric-overflow", policy=True))

    def test_manifest_mutations_are_not_accepted_after_funding(self):
        manifest = {"funding_txid": None, "local_interpreter": {"commit": "abc"},
                    "fixtures": [{"name": "high", "input_sequence": 0,
                                  "operand_hex": "0000000001"}]}
        funded = copy.deepcopy(manifest)
        funded["funding_txid"] = "42"
        funded["fixtures"][0]["transaction"] = {"txid": "later"}
        validate_funded_manifest(manifest, funded, "42")
        for path, value in (("input_sequence", 1), ("operand_hex", "00")):
            changed = copy.deepcopy(funded)
            changed["fixtures"][0][path] = value
            with self.assertRaises(RuntimeError):
                validate_funded_manifest(manifest, changed, "42")
        funded["local_interpreter"]["commit"] = "def"
        with self.assertRaises(RuntimeError):
            validate_funded_manifest(manifest, funded, "42")

    def test_witness_budget_and_hint_claims_are_independently_checked(self):
        data = b"\0\0\0\0\1"
        witness = [data, b"\xb2\x75\x51", b"\xc0" * 33]
        size = 1 + sum(1 + len(item) for item in witness)
        fixture = {"data_witness_hex": [data.hex()], "script_hex": witness[1].hex(),
                   "control_block_hex": witness[2].hex(), "hint_items": 0,
                   "metrics": {"data_items": 1, "taproot_witness_items": 3,
                               "hint_items": 0, "data_witness_bytes": 1 + 1 + len(data),
                               "taproot_witness_bytes": size, "locking_script_bytes": 3,
                               "control_block_bytes": 33, "initial_validation_weight": 50 + size,
                               "stack_peak": 1},
                   "local_consensus": {"outcome": "executed", "stats": {
                       "initial_validation_weight": 50 + size,
                       "remaining_validation_weight": 50 + size,
                       "combined_stack_peak": 1}},
                   "local_policy": {"outcome": "executed", "stats": {
                       "initial_validation_weight": 50 + size,
                       "remaining_validation_weight": 50 + size}}}
        validate_witness(fixture, witness, size)
        changed = copy.deepcopy(fixture)
        changed["metrics"]["hint_items"] = 1
        with self.assertRaises(RuntimeError):
            validate_witness(changed, witness, size)
        changed = copy.deepcopy(fixture)
        changed["local_consensus"]["stats"]["remaining_validation_weight"] -= 50
        with self.assertRaises(RuntimeError):
            validate_witness(changed, witness, size)

    def test_diagnostic_mode_never_waives_core_failure(self):
        report = {"all_core_expectations_met": True, "all_local_consensus_comparisons_matched": False,
                  "all_local_policy_comparisons_matched": True}
        self.assertFalse(run_passed(report, False))
        self.assertTrue(run_passed(report, True))
        self.assertFalse(run_passed({**report, "all_core_expectations_met": False}, True))
        self.assertFalse(run_passed({**report, "infrastructure_error": "RPC failed"}, True))


if __name__ == "__main__":
    unittest.main()
