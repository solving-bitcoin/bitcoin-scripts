"""Offline guards for the nine-byte Binohash SIGHASH_SINGLE anchor report."""

import copy
import json
import unittest
from pathlib import Path

from binohash_single_anchor_regtest import (CONTROLS, POLICY_REJECTION, RELEASE,
                                            rejection_matches, report_passed)

REPORT = Path(__file__).resolve().parents[1] / "tests/data/binohash-single-anchor-v30.3.json"


class BinohashSingleAnchorHarnessTests(unittest.TestCase):
    def setUp(self):
        self.report = json.loads(REPORT.read_text())

    def test_checked_report_passes(self):
        self.assertTrue(self.report["run_passed"])
        self.assertTrue(report_passed(self.report))
        self.assertEqual(self.report["bitcoin_core"]["commit"], RELEASE["commit"])
        self.assertEqual(set(self.report["controls"]), set(CONTROLS))
        self.assertEqual(self.report["fixture"]["anchor_signature_bytes"], 9)

    def test_consensus_and_policy_boundaries(self):
        valid = self.report["valid"]
        self.assertTrue(valid["consensus"]["accepted"])
        self.assertFalse(valid["policy"]["allowed"])
        self.assertEqual(valid["policy"]["reject-reason"], POLICY_REJECTION)
        for name, input_index in (("added_output", 1), ("moved_input", 0)):
            control = self.report["controls"][name]
            self.assertTrue(rejection_matches(
                control["consensus"], control["transaction"]["txid"], input_index))

    def test_mutated_report_cannot_pass(self):
        mutations = [
            ("bitcoin_core", "commit", "unknown"),
            ("fixture", "anchor_signature_bytes", 10),
            ("fixture", "anchor_redeem_script_bytes", 44),
            ("fixture", "local_digests", "valid_hex", "00" * 32),
            ("valid", "consensus", "accepted", False),
            ("valid", "policy", "allowed", True),
            ("valid", "policy", "reject-reason", "other"),
            ("valid", "transaction", "weight", 736),
            ("controls", "added_output", "consensus", "accepted", True),
            ("controls", "moved_input", "consensus", "reason", "other"),
            ("controls", "added_output", "decoded", "txid", "00" * 32),
            ("controls", "moved_input", "transaction", "input_vouts", [0, 1]),
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
