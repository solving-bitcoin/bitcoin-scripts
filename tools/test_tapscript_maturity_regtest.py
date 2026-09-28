"""Offline guards for the funded BIP68 maturity differential."""

import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from tapscript_maturity_regtest import (BLOCK_REJECTION, NAMES, maturity_rejection_matches,
                                        local_probe, report_passed)

REPORT = Path(__file__).resolve().parents[1] / "tests/data/tapscript-maturity-v30.3.json"
CORE_COMMIT = "49faec4f87f5cd19c88db01a82e5c68b087c8227"


def row(name):
    txid = "42" * 32
    return {"name": name, "transaction": {"txid": txid},
            "local_leaf_consensus": {"accepted": True},
            "local_leaf_policy": {"accepted": True},
            "immature": {"local_sequence_lock": {"verdict": "premature"},
                         "local_without_chain_context": {"verdict": "unsupported"},
                         "core": {"consensus": {"accepted": False, "rpc_code": -25,
                                                "reason": BLOCK_REJECTION + txid},
                                  "policy": {"allowed": False, "txid": txid,
                                             "reject-reason": "non-BIP68-final"}}},
            "mature": {"local_sequence_lock": {"verdict": "mature"},
                       "core": {"consensus": {"accepted": True},
                                "policy": {"allowed": True}}}}


class MaturityHarnessTests(unittest.TestCase):
    def test_nonfinal_rejection_must_match_context_and_transaction(self):
        fixture = row("height")
        immature = fixture["immature"]["core"]
        txid = fixture["transaction"]["txid"]
        self.assertTrue(maturity_rejection_matches(immature["consensus"], txid))
        self.assertTrue(maturity_rejection_matches(immature["policy"], txid, policy=True))
        wrong = {**immature["consensus"], "reason": BLOCK_REJECTION + "24" * 32}
        self.assertFalse(maturity_rejection_matches(wrong, txid))
        wrong = {**immature["policy"], "reject-reason": "bad-txns-nonfinal"}
        self.assertFalse(maturity_rejection_matches(wrong, txid, policy=True))
        wrong = {**immature["consensus"], "reason": "TestBlockValidity failed: block-script-verify-flag-failed (Locktime requirement not satisfied)"}
        self.assertFalse(maturity_rejection_matches(wrong, txid))

    def test_missing_context_and_leaf_execution_remain_separate(self):
        report = {"schema_version": 1, "experiment": "funded-bip68-maturity",
                  "fixture_count": 2,
                  "results": [row("csv-high-height-exact"), row("csv-high-time-exact")]}
        self.assertTrue(report_passed(report))
        wrong = copy.deepcopy(report)
        wrong["experiment"] = "funded-tapscript-csv-five-byte"
        self.assertFalse(report_passed(wrong))
        wrong = copy.deepcopy(report)
        wrong["results"][0]["immature"]["local_without_chain_context"]["verdict"] = "mature"
        self.assertFalse(report_passed(wrong))
        wrong = copy.deepcopy(report)
        wrong["results"][1]["local_leaf_consensus"]["accepted"] = False
        self.assertFalse(report_passed(wrong))
        wrong = copy.deepcopy(report)
        wrong["results"][0]["immature"]["local_sequence_lock"]["verdict"] = "unsupported"
        self.assertFalse(report_passed(wrong))
        wrong = copy.deepcopy(report)
        wrong["infrastructure_error"] = "Core unavailable"
        self.assertFalse(report_passed(wrong))

    def test_local_probe_rejects_an_unrelated_transaction(self):
        with patch("tapscript_maturity_regtest.subprocess.check_output",
                   return_value=b'{"txid":"different","verdict":"mature"}'):
            with self.assertRaisesRegex(RuntimeError, "different transaction"):
                local_probe({"hex": "00", "txid": "expected"}, 102, 1000, 107, 3560)

    def test_stored_report_has_exact_chain_boundaries_and_identity(self):
        report = json.loads(REPORT.read_text())
        self.assertTrue(report["run_passed"])
        self.assertTrue(report_passed(report))
        self.assertEqual(report["experiment"], "funded-bip68-maturity")
        self.assertEqual(report["fixture_count"], 2)
        self.assertEqual(report["source_manifest_fixture_count"], 19)
        self.assertEqual(report["source_manifest_experiment"], "funded-tapscript-csv-five-byte")
        self.assertEqual({item["name"] for item in report["results"]}, set(NAMES))
        self.assertEqual(report["bitcoin_core"]["commit"], CORE_COMMIT)
        self.assertIn("csv", report["active_consensus_deployments"])
        self.assertEqual(report["immature_context"]["candidate_height"], report["funding_height"] + 4)
        self.assertEqual(report["mature_context"]["candidate_height"], report["funding_height"] + 5)
        self.assertEqual(report["immature_context"]["mtp_since_funding_parent"], 4 * 512)
        self.assertEqual(report["mature_context"]["mtp_since_funding_parent"], 5 * 512)
        self.assertEqual(report["immature_context"]["tip_time"] - report["funding_block_time"], 3 * 512)
        self.assertEqual(report["mature_context"]["tip_time"] - report["funding_block_time"], 4 * 512)
        for item in report["results"]:
            self.assertEqual(item["immature"]["local_without_chain_context"]["verdict"], "unsupported")


if __name__ == "__main__":
    unittest.main()
