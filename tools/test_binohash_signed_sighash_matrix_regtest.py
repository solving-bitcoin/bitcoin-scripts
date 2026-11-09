"""Offline guards for the signed six-mode legacy sighash matrix report."""

import copy
import json
import unittest
from pathlib import Path

from binohash_signed_sighash_matrix_regtest import (EXPECTED, MUTATIONS, RELEASE,
                                                    report_passed)

REPORT = Path(__file__).resolve().parents[1] / "tests/data/binohash-signed-sighash-matrix-v30.3.json"


class SignedSighashMatrixTests(unittest.TestCase):
    def setUp(self):
        self.report = json.loads(REPORT.read_text())

    def test_checked_report_passes(self):
        self.assertTrue(self.report["run_passed"])
        self.assertTrue(report_passed(self.report))
        self.assertEqual(self.report["bitcoin_core"]["commit"], RELEASE["commit"])

    def test_all_modes_and_field_verdicts(self):
        self.assertEqual(len(self.report["rows"]), 6)
        for mode_index, row in enumerate(self.report["rows"]):
            self.assertTrue(row["baseline_policy"]["allowed"])
            self.assertEqual([variant["mutation"] for variant in row["variants"]], MUTATIONS)
            for case, variant in enumerate(row["variants"]):
                changed = EXPECTED[case][mode_index]
                self.assertEqual(variant["digest_changed"], changed)
                self.assertEqual(variant["policy"]["allowed"], not changed)
                if changed:
                    self.assertFalse(variant["consensus"]["accepted"])
                else:
                    self.assertIsNone(variant["consensus"])

    def test_mutated_reports_cannot_pass(self):
        mutations = [
            ("bitcoin_core", "commit", "unknown"),
            ("baseline_consensus", "confirmed_txids", 5),
            ("rows", 0, "baseline_policy", "allowed", False),
            ("rows", 0, "variants", 0, "policy", "allowed", True),
            ("rows", 4, "variants", 6, "consensus", "fabricated"),
            ("rows", 2, "variants", 2, "consensus", "rpc_code", -26),
            ("rows", 2, "variants", 2, "consensus", "reason", "other"),
            ("rows", 5, "variants", 0, "digest_changed", False),
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
