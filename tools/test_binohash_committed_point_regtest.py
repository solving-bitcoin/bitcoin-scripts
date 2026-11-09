"""Offline guards for the funded committed ECDSA point-lock Core report."""

import copy
import json
import unittest
from pathlib import Path

from binohash_committed_point_regtest import (POLICY_REJECTIONS, RELEASE,
                                             rejection_matches, report_passed)

REPORT = Path(__file__).resolve().parents[1] / "tests/data/binohash-committed-point-v30.3.json"


class BinohashCommittedPointHarnessTests(unittest.TestCase):
    def setUp(self):
        self.report = json.loads(REPORT.read_text())

    def test_checked_report_passes(self):
        self.assertTrue(self.report["run_passed"])
        self.assertTrue(report_passed(self.report))
        self.assertEqual(self.report["bitcoin_core"]["commit"], RELEASE["commit"])
        self.assertEqual(self.report["fixture"]["expected_point_secret_hex"],
                         self.report["fixture"]["extracted_point_secret_hex"])

    def test_consensus_and_default_policy(self):
        valid = self.report["valid"]
        self.assertTrue(valid["consensus"]["accepted"])
        self.assertTrue(valid["policy"]["allowed"])
        for name, control in self.report["controls"].items():
            self.assertTrue(rejection_matches(
                control["consensus"], name, control["transaction"]["txid"]))
            self.assertFalse(control["policy"]["allowed"])
            self.assertEqual(control["policy"]["reject-reason"], POLICY_REJECTIONS[name])

    def test_mutated_report_cannot_pass(self):
        mutations = [
            ("bitcoin_core", "commit", "unknown"),
            ("fixture", "extracted_point_secret_hex", "00" * 32),
            ("fixture", "bug_digest_hex", "00" * 32),
            ("fixture", "redeem_script_bytes", 522),
            ("valid", "consensus", "accepted", False),
            ("valid", "policy", "allowed", False),
            ("valid", "decoded", "txid", "00" * 32),
            ("controls", "wrong_signature", "consensus", "accepted", True),
            ("controls", "wrong_signature", "policy", "allowed", True),
            ("controls", "added_output", "consensus", "reason", "other"),
            ("controls", "added_output", "policy", "reject-reason", "other"),
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
