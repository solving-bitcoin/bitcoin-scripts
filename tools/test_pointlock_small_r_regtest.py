"""Offline guards for the funded G/2 small-R Core comparison."""

import copy
import json
import unittest
from pathlib import Path

from pointlock_small_r_regtest import RELEASE, report_passed

REPORT = Path(__file__).resolve().parents[1] / "tests/data/pointlock-small-r-core-v30.3.json"


class SmallRCoreHarnessTests(unittest.TestCase):
    def setUp(self):
        self.report = json.loads(REPORT.read_text())

    def test_checked_report_passes(self):
        self.assertTrue(self.report["run_passed"])
        self.assertTrue(report_passed(self.report))
        self.assertEqual(self.report["bitcoin_core"]["commit"], RELEASE["commit"])

    def test_policy_consensus_and_extraction_are_distinct(self):
        self.assertTrue(self.report["fixture"]["extracted_secret_matches"])
        self.assertTrue(self.report["results"]["honest"]["consensus"]["accepted"])
        self.assertTrue(self.report["results"]["honest"]["policy"]["allowed"])
        self.assertFalse(self.report["results"]["length_control"]["consensus"]["accepted"])
        self.assertFalse(self.report["results"]["length_control"]["policy"]["allowed"])

    def test_mutated_report_cannot_pass(self):
        mutations = [
            (("bitcoin_core", "commit"), "unknown"),
            (("fixture", "extracted_secret_matches"), False),
            (("fixture", "ordinary_signature_bytes"), 60),
            (("results", "honest", "consensus", "accepted"), False),
            (("results", "honest", "policy", "allowed"), False),
            (("results", "length_control", "consensus", "rpc_code"), -26),
            (("results", "length_control", "policy", "reject-reason"), "different failure"),
            (("results", "honest", "decoded", "script_sig_hex"), "00"),
            (("results", "honest", "transaction", "weight"), 0),
        ]
        for path, value in mutations:
            with self.subTest(path=path):
                changed = copy.deepcopy(self.report)
                target = changed
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self.assertFalse(report_passed(changed))


if __name__ == "__main__":
    unittest.main()
