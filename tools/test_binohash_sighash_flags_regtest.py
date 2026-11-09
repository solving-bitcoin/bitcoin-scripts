"""Offline checks for the pinned Core raw-sighash-byte census."""

import copy
import json
import unittest
from pathlib import Path

from binohash_sighash_flags_regtest import (CANONICAL, POLICY_REJECTION, RELEASE,
                                           report_passed)

REPORT = Path(__file__).resolve().parents[1] / "tests/data/binohash-sighash-flags-v30.3.json"


class BinohashSighashFlagsTests(unittest.TestCase):
    def setUp(self):
        self.report = json.loads(REPORT.read_text())

    def test_checked_report(self):
        self.assertTrue(self.report["run_passed"])
        self.assertTrue(report_passed(self.report))
        self.assertEqual(self.report["bitcoin_core"]["commit"], RELEASE["commit"])
        self.assertEqual({row["flag"] for row in self.report["rows"]
                          if row["policy_allowed"]}, CANONICAL)
        self.assertEqual(sum(row["policy_reject_reason"] == POLICY_REJECTION
                             for row in self.report["rows"]), 250)

    def test_mutated_report_fails(self):
        cases = [
            ("bitcoin_core", "commit", "unknown"),
            ("consensus", "confirmed_txids", 255),
            ("rows", 7, "policy_allowed", True),
            ("rows", 1, "policy_allowed", False),
            ("rows", 8, "local_digest_hex", self.report["rows"][0]["local_digest_hex"]),
            ("fixed_template_digests_hex", 8,
             self.report["fixed_template_digests_hex"][0]),
            ("rows", 9, "policy_reject_reason", "other"),
            ("wrong_flag_control", "accepted", True),
        ]
        for *path, value in cases:
            with self.subTest(path=path):
                changed = copy.deepcopy(self.report)
                target = changed
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self.assertFalse(report_passed(changed))


if __name__ == "__main__":
    unittest.main()
