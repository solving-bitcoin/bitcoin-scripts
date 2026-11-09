"""Offline guards for the funded 2-of-3 Binohash subset comparison."""

import copy
import json
import unittest
from pathlib import Path

from binohash_subset_regtest import CONTROLS, RELEASE, rejection_matches, report_passed

REPORT = Path(__file__).resolve().parents[1] / "tests/data/binohash-subset-v30.3.json"


class BinohashSubsetHarnessTests(unittest.TestCase):
    def setUp(self):
        self.report = json.loads(REPORT.read_text())

    def test_checked_report_passes(self):
        self.assertTrue(self.report["run_passed"])
        self.assertTrue(report_passed(self.report))
        self.assertEqual(self.report["bitcoin_core"]["commit"], RELEASE["commit"])
        self.assertEqual([spend["selected_pair"] for spend in self.report["spends"]],
                         [[0, 1], [0, 2]])
        for spend in self.report["spends"]:
            self.assertEqual(set(spend["controls"]), set(CONTROLS))

    def test_each_control_has_the_expected_core_rejection(self):
        for spend in self.report["spends"]:
            for name, control in spend["controls"].items():
                with self.subTest(spend=spend["name"], name=name):
                    self.assertTrue(rejection_matches(
                        control["consensus"], name, control["transaction"]["txid"]))
            self.assertTrue(spend["valid"]["consensus"]["accepted"])
            self.assertFalse(spend["valid"]["policy"]["allowed"])

    def test_mutated_report_cannot_pass(self):
        mutations = [
            ("bitcoin_core", "commit", "unknown"),
            ("spends", 0, "candidates", 1, "local_digest_hex",
             self.report["spends"][0]["candidates"][0]["local_digest_hex"]),
            ("spends", 1, "selected_pair", [2, 2]),
            ("spends", 1, "valid", "consensus", "accepted", False),
            ("spends", 0, "valid", "policy", "allowed", True),
            ("spends", 1, "controls", "wrong_indices", "consensus", "accepted", True),
            ("spends", 0, "controls", "wrong_preimage", "consensus", "reason", "other failure"),
            ("spends", 1, "controls", "wrong_size", "decoded", "txid", "00" * 32),
        ]
        for *path, value in mutations:
            with self.subTest(path=path):
                changed = copy.deepcopy(self.report)
                target = changed
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self.assertFalse(report_passed(changed))


if __name__ == "__main__":
    unittest.main()
