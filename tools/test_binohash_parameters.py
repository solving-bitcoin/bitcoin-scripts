"""Checks for the Binohash subset-space planning report."""

import json
import math
import unittest

from binohash_parameters import (CHECKED_REPORT, evaluate,
                                 maximum_pool_size_under_paper_size_formula,
                                 minimum_pool_size, render, report)


class BinohashParameterTests(unittest.TestCase):
    def test_exact_subset_frontier(self):
        self.assertEqual(math.comb(120, 8), 840_261_910_995)
        self.assertEqual(minimum_pool_size(8, 42), 147)
        self.assertLess(math.comb(146, 8), 1 << 42)
        self.assertGreaterEqual(math.comb(147, 8), 1 << 42)
        self.assertEqual(maximum_pool_size_under_paper_size_formula(2), 151)
        self.assertLessEqual(evaluate(151, 8, 2, 42)[
            "paper_formula_script_bytes_t8_only"], 10_000)
        self.assertGreater(evaluate(152, 8, 2, 42)[
            "paper_formula_script_bytes_t8_only"], 10_000)

    def test_conditional_probability_model(self):
        small = evaluate(2, 1, 2, 1)
        self.assertEqual(small["exact_subsets_per_round"], 2)
        self.assertEqual(small["one_round_hit_probability_if_independent"], 0.75)
        self.assertEqual(small["all_rounds_hit_probability_if_independent"], 0.5625)
        profiles = report()["profiles"]
        self.assertLess(profiles["120"]["one_round_hit_probability_if_independent"],
                        profiles["147"]["one_round_hit_probability_if_independent"])
        self.assertLess(profiles["147"]["one_round_hit_probability_if_independent"],
                        profiles["151"]["one_round_hit_probability_if_independent"])

    def test_paper_formula_is_not_extrapolated_across_t(self):
        result = evaluate(140, 9, 2, 49)
        self.assertNotIn("paper_formula_script_bytes_t8_only", result)
        self.assertEqual(result["paper_formula_nonpush_opcodes"], 221)
        self.assertEqual(result["paper_formula_nonpush_opcode_margin"], -20)
        self.assertEqual(evaluate(120, 8, 2, 42)[
            "paper_formula_nonpush_opcodes"], 199)

    def test_invalid_inputs(self):
        for args in ((0, 0, 2, 42), (3, 4, 2, 42),
                     (120, 8, 0, 42), (120, 8, 2, 0)):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    evaluate(*args)
        with self.assertRaises(ValueError):
            minimum_pool_size(0, 42)
        with self.assertRaises(ValueError):
            maximum_pool_size_under_paper_size_formula(0)

    def test_checked_report_is_current(self):
        self.assertEqual(json.loads(CHECKED_REPORT.read_text()), report())
        self.assertEqual(CHECKED_REPORT.read_text(), render())


if __name__ == "__main__":
    unittest.main()
