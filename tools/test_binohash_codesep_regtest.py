"""Offline guards for the funded legacy CODESEPARATOR/FindAndDelete report."""

import copy
import json
import unittest
from pathlib import Path

from binohash_codesep_regtest import (CONTROLS, POLICY_REJECTION, RELEASE,
                                      report_passed)

REPORT = Path(__file__).resolve().parents[1] / "tests/data/binohash-codesep-v30.3.json"


class BinohashCodesepHarnessTests(unittest.TestCase):
    def setUp(self):
        self.report = json.loads(REPORT.read_text())

    def test_checked_report_passes(self):
        self.assertTrue(self.report["run_passed"])
        self.assertTrue(report_passed(self.report))
        self.assertEqual(self.report["bitcoin_core"]["commit"], RELEASE["commit"])
        self.assertEqual(
            [row["selected_push_position"] for row in self.report["results"]],
            ["before", "after"],
        )

    def test_valid_and_control_verdicts_are_separate(self):
        for row in self.report["results"]:
            self.assertEqual(set(row["controls"]), set(CONTROLS))
            self.assertEqual(len(set(row["digests"].values())), 5)
            self.assertTrue(row["valid"]["consensus"]["accepted"])
            self.assertFalse(row["valid"]["policy"]["allowed"])
            self.assertEqual(
                row["valid"]["policy"]["reject-reason"], POLICY_REJECTION
            )
            for control in row["controls"].values():
                self.assertFalse(control["consensus"]["accepted"])
                self.assertEqual(control["consensus"]["rpc_code"], -25)
                self.assertFalse(control["policy"]["allowed"])
                self.assertEqual(control["policy"]["reject-reason"], POLICY_REJECTION)

    def test_mutated_report_cannot_pass(self):
        mutations = [
            ("bitcoin_core", "commit", "unknown"),
            ("results", 0, "selected_push_position", "after"),
            ("results", 0, "digests", "dead_boundary",
             self.report["results"][0]["digests"]["correct"]),
            ("results", 1, "valid", "consensus", "accepted", False),
            ("results", 0, "valid", "policy", "allowed", True),
            ("results", 1, "controls", "wrong_full_boundary", "consensus", "accepted", True),
            ("results", 0, "controls", "wrong_dead_boundary", "consensus", "rpc_code", -26),
            ("results", 0, "controls", "wrong_retained_dead_separator", "policy", "allowed", True),
            ("results", 1, "controls", "wrong_find_and_delete", "decoded", "txid", "00" * 32),
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
