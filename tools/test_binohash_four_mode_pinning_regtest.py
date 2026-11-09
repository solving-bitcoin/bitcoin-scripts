"""Guard the checked four-mode Core report against weakened evidence."""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from binohash_four_mode_pinning_regtest import report_passed  # noqa: E402


class FourModeReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads((ROOT / "tests/data/binohash-four-mode-pinning-v30.3.json").read_text())

    def test_checked_report_passes(self):
        self.assertTrue(report_passed(self.report))

    def test_evidence_mutations_fail(self):
        edits = [
            lambda r: r["fixture"]["flags_hex"].reverse(),
            lambda r: r["fixture"]["attempts"].__setitem__(0, 1),
            lambda r: r["fixture"].__setitem__("locking_script_bytes", 158),
            lambda r: r["fixture"].__setitem__("static_non_push_opcodes", 14),
            lambda r: r["fixture"]["signatures_hex"].__setitem__(0, r["fixture"]["signatures_hex"][0][:-2] + "01"),
            lambda r: r["fixture"]["mutations"][3]["changed_modes"].__setitem__(0, True),
            lambda r: r["mutations"][4]["changed_modes"].__setitem__(2, False),
            lambda r: r["fixture"]["mutations"][5]["digests_hex"].__setitem__(3, r["fixture"]["digests_hex"][3]),
            lambda r: r["funding_decoded"].__setitem__("weight", 1),
            lambda r: r["valid_decoded"].__setitem__("txid", "00" * 32),
            lambda r: r["valid_policy"].__setitem__("reject-reason", "version"),
            lambda r: r["valid_consensus"].__setitem__("block_height", 102),
            lambda r: r["mutations"][3]["consensus"].__setitem__("reason", "input 0 rejected"),
            lambda r: r["wrong_sizes"][2]["consensus"].__setitem__("reason", "bad DER"),
            lambda r: r["fixture"]["wrong_sizes"].pop(),
        ]
        for index, edit in enumerate(edits):
            with self.subTest(index=index):
                changed = copy.deepcopy(self.report)
                edit(changed)
                self.assertFalse(report_passed(changed))


if __name__ == "__main__":
    unittest.main()
