"""Guard the checked exact-size ECDSA Core report."""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from binohash_der_size_grind_regtest import report_passed  # noqa: E402


class DerSizeReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads((ROOT / "tests/data/binohash-der-size-grind-v30.3.json").read_text())

    def test_checked_report_passes(self):
        self.assertTrue(report_passed(self.report))

    def test_weakened_evidence_fails(self):
        edits = [
            lambda r: r["fixture"].__setitem__("seed_hex", "00" * 32),
            lambda r: r["fixture"].__setitem__("attempts", 1),
            lambda r: r["fixture"].__setitem__("redeem_static_non_push_opcodes", 2),
            lambda r: r["fixture"].__setitem__("good_signature_hex", r["fixture"]["good_signature_hex"][:-2]),
            lambda r: r["fixture"]["transactions"]["valid"].__setitem__("weight", 819),
            lambda r: r["valid_policy"].__setitem__("allowed", False),
            lambda r: r["controls"]["invalid_size"]["consensus"].__setitem__("reason", "bad DER"),
            lambda r: r["controls"]["invalid_ecdsa"]["consensus"].__setitem__("accepted", True),
        ]
        for index, edit in enumerate(edits):
            with self.subTest(index=index):
                report = copy.deepcopy(self.report)
                edit(report)
                self.assertFalse(report_passed(report))


if __name__ == "__main__":
    unittest.main()
