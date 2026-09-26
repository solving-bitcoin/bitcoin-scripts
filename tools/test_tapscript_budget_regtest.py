"""Offline failure guards for funded signature-budget/Core comparisons."""
import copy
import unittest

from tapscript_budget_regtest import (compare_local, rejection_matches, run_passed,
                                      validate_budget_metrics, validate_funded_manifest,
                                      validate_witness_counts)
from core_regtest import compact_size, vector


class BudgetHarnessTests(unittest.TestCase):
    def fixture(self, annex=False):
        data = [b"\x11" * 64, b"\x22" * 32, b"\x55"]
        witness = data + [b"\x51", b"\xc0" * 33] + ([b"\x50"] if annex else [])
        full_bytes = len(compact_size(len(witness))) + sum(len(vector(item)) for item in witness)
        data_bytes = len(compact_size(len(data))) + sum(len(vector(item)) for item in data)
        row = {"data_witness_hex": [item.hex() for item in data], "script_hex": "51",
               "control_block_hex": (b"\xc0" * 33).hex(), "annex_hex": "50" if annex else None,
               "hint_items": 0, "nonempty_signature_checks": 3,
               "metrics": {"data_items": 3, "taproot_witness_items": len(witness), "hint_items": 0,
                           "data_witness_bytes": data_bytes, "taproot_witness_bytes": full_bytes,
                           "initial_full_witness_validation_weight": 50 + full_bytes,
                           "initial_data_only_validation_weight": 50 + data_bytes,
                           "requested_validation_weight": 150,
                           "expected_remaining_if_all_checks_charged": 50 + full_bytes - 150},
               "local_full_witness": {"outcome": "executed", "stats": {"initial_validation_weight": 50 + full_bytes,
                                                                        "remaining_validation_weight": 50 + full_bytes - 150}},
               "local_legacy_fragment": {"outcome": "executed", "stats": {"initial_validation_weight": 50 + data_bytes}}}
        return row, witness, full_bytes

    def test_panics_and_initialization_errors_are_not_rejections(self):
        for outcome in ["panic", "initialization-error", "unsupported"]:
            row = {"local_full_witness": {"outcome": outcome, "accepted": False, "error": "TapscriptValidationWeight"},
                   "expected": {"consensus_rejection": "validation-weight"}}
            self.assertEqual(compare_local(row, {"accepted": False})["status"], "no-verdict")

    def test_local_error_category_and_boolean_must_both_match(self):
        row = {"local_full_witness": {"outcome": "executed", "accepted": False, "error": "CheckSigVerify"},
               "expected": {"consensus_rejection": "validation-weight"}}
        self.assertFalse(compare_local(row, {"accepted": False})["matches_consensus"])
        row["local_full_witness"]["error"] = "TapscriptValidationWeight"
        self.assertTrue(compare_local(row, {"accepted": False})["matches_consensus"])
        self.assertFalse(compare_local(row, {"accepted": True})["matches_consensus"])

    def test_baseline_mode_never_waives_core_or_infrastructure_failure(self):
        row = {"all_core_expectations_met": True, "all_local_consensus_comparisons_matched": False}
        self.assertFalse(run_passed(row, False))
        self.assertTrue(run_passed(row, True))
        self.assertFalse(run_passed({**row, "all_core_expectations_met": False}, True))
        self.assertFalse(run_passed({**row, "infrastructure_error": "RPC failed"}, True))

    def test_policy_nonstandard_and_consensus_budget_are_separate_errors(self):
        self.assertTrue(rejection_matches({"allowed": False, "reject-reason": "bad-witness-nonstandard"}, "witness-nonstandard", policy=True))
        self.assertFalse(rejection_matches({"allowed": False, "reject-reason": "bad-witness-nonstandard"}, "validation-weight", policy=True))
        result = {"accepted": False, "reason": "TestBlockValidity failed: block-script-verify-flag-failed (Too much signature validation relative to witness weight), input 0 of abc"}
        self.assertTrue(rejection_matches(result, "validation-weight"))
        self.assertFalse(rejection_matches(result, "checksigverify"))

    def test_funding_manifest_must_preserve_annex_control_and_pin(self):
        manifest = {"funding_txid": None, "local_interpreter": {"commit": "abc"},
                    "fixtures": [{"annex_hex": "50", "control_block_hex": "c0"}]}
        funded = copy.deepcopy(manifest); funded["funding_txid"] = "42"
        validate_funded_manifest(manifest, funded, "42")
        for key in ["annex_hex", "control_block_hex"]:
            changed = copy.deepcopy(funded); changed["fixtures"][0][key] = "00"
            with self.assertRaises(RuntimeError):
                validate_funded_manifest(manifest, changed, "42")
        funded["local_interpreter"]["commit"] = "def"
        with self.assertRaises(RuntimeError):
            validate_funded_manifest(manifest, funded, "42")

    def test_complete_witness_includes_annex_and_checks_commitment_bytes(self):
        for annex in [False, True]:
            row, witness, _ = self.fixture(annex)
            validate_witness_counts(row, witness)
            for changed in [witness[:-1], [b"wrong"] + witness[1:]]:
                with self.assertRaises(RuntimeError):
                    validate_witness_counts(row, changed)
            if annex:
                row["annex_hex"] = "51"
                with self.assertRaises(RuntimeError):
                    validate_witness_counts(row, witness)

    def test_independent_budget_metrics_reject_each_wrong_boundary(self):
        row, _, full_bytes = self.fixture(True)
        validate_budget_metrics(row, full_bytes)
        for key in ["data_witness_bytes", "taproot_witness_bytes", "initial_full_witness_validation_weight",
                    "initial_data_only_validation_weight", "requested_validation_weight",
                    "expected_remaining_if_all_checks_charged"]:
            changed = copy.deepcopy(row); changed["metrics"][key] += 1
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                validate_budget_metrics(changed, full_bytes)
        for key in ["initial_validation_weight", "remaining_validation_weight"]:
            changed = copy.deepcopy(row); changed["local_full_witness"]["stats"][key] += 1
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                validate_budget_metrics(changed, full_bytes)


if __name__ == "__main__":
    unittest.main()
