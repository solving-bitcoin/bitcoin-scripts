"""Guard the checked two-round Core report against missing evidence."""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from binohash_two_round_regtest import report_passed  # noqa: E402


class TwoRoundReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads((ROOT / "tests/data/binohash-two-round-v30.3.json").read_text())

    def test_checked_report_passes(self):
        self.assertTrue(report_passed(self.report))

    def test_critical_evidence_changes_fail(self):
        edits = [
            lambda r: r["fixture"].__setitem__("selected_indices", [0, 0]),
            lambda r: r["fixture"].__setitem__("round_candidate_counts", [1, 1]),
            lambda r: r["fixture"]["round_candidates"][1][1].__setitem__("passes_size", False),
            lambda r: r["fixture"].__setitem__("redeem_script_bytes", 521),
            lambda r: r["fixture"].__setitem__("hint_items", 1),
            lambda r: r["fixture"]["transactions"]["valid"].__setitem__("weight", 1),
            lambda r: r["valid_policy"].__setitem__("allowed", True),
            lambda r: r["controls"]["flip_first"]["consensus"].__setitem__("reason", "wrong input"),
            lambda r: r["controls"]["wrong_size"]["consensus"].__setitem__("accepted", True),
        ]
        for index, edit in enumerate(edits):
            with self.subTest(index=index):
                changed = copy.deepcopy(self.report)
                edit(changed)
                self.assertFalse(report_passed(changed))


if __name__ == "__main__":
    unittest.main()
