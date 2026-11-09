"""Offline guards for the SIGHASH_SINGLE bug pinning-skip report."""

import copy
import json
import unittest
from pathlib import Path

from binohash_single_bug_pinning_skip_regtest import (BUG_DIGEST, CONTROLS,
                                                     MUTATIONS, RELEASE, report_passed)

REPORT = Path(__file__).resolve().parents[1] / "tests/data/binohash-single-bug-pinning-skip-v30.3.json"


class SingleBugPinningSkipTests(unittest.TestCase):
    def setUp(self):
        self.report = json.loads(REPORT.read_text())

    def test_checked_report_passes(self):
        self.assertTrue(self.report["run_passed"])
        self.assertTrue(report_passed(self.report))
        self.assertEqual(self.report["bitcoin_core"]["commit"], RELEASE["commit"])

    def test_mutations_and_boundary_controls(self):
        self.assertEqual(self.report["consensus"]["confirmed_txids"], 9)
        self.assertEqual([row["mutation"] for row in self.report["rows"]], list(MUTATIONS))
        for row in self.report["rows"]:
            self.assertEqual(row["local_digest_hex"], BUG_DIGEST)
            self.assertFalse(row["policy"]["allowed"])
        self.assertEqual(set(self.report["controls"]), set(CONTROLS))
        for control in self.report["controls"].values():
            self.assertNotEqual(control["local_digest_hex"], BUG_DIGEST)
            self.assertFalse(control["consensus"]["accepted"])

    def test_mutated_report_cannot_pass(self):
        mutations = [
            ("bitcoin_core", "commit", "unknown"),
            ("consensus", "confirmed_txids", 8),
            ("rows", 0, "local_digest_hex", "00" * 32),
            ("rows", 2, "policy", "allowed", True),
            ("rows", 8, "transaction", "input_vouts", [32, 33]),
            ("controls", "added_output", "consensus", "accepted", True),
            ("controls", "moved_input", "consensus", "reason", "other"),
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
