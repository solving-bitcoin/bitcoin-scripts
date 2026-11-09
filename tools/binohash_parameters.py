#!/usr/bin/env python3
"""Exact subset counts and explicitly conditional Binohash planning estimates."""

import argparse
import json
import math
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKED_REPORT = ROOT / "tests/data/binohash-parameters.json"
LEGACY_SCRIPT_LIMIT = 10_000
LEGACY_NONPUSH_OPCODE_LIMIT = 201
PAPER_PINNING_NONPUSH_OPCODES = 13
PAPER_FIXED_SCRIPT_BYTES = 100
PAPER_ROUND_FIXED_BYTES = 244
PAPER_POOL_ENTRY_BYTES = 31


def minimum_pool_size(selected, difficulty_bits):
    """Smallest n for which C(n, selected) reaches 2**difficulty_bits."""
    if selected < 1 or difficulty_bits < 1:
        raise ValueError("selected and difficulty_bits must be positive")
    pool = selected
    while math.comb(pool, selected) < 1 << difficulty_bits:
        pool += 1
    return pool


def maximum_pool_size_under_paper_size_formula(rounds):
    """An estimate, valid only for the paper's t=8 layout, not Core evidence."""
    if rounds < 1:
        raise ValueError("rounds must be positive")
    fixed = PAPER_FIXED_SCRIPT_BYTES + rounds * PAPER_ROUND_FIXED_BYTES
    return (LEGACY_SCRIPT_LIMIT - fixed) // (rounds * PAPER_POOL_ENTRY_BYTES)


def evaluate(pool, selected, rounds, difficulty_bits):
    if not (1 <= selected <= pool and rounds >= 1 and 1 <= difficulty_bits <= 256):
        raise ValueError("require 1 <= selected <= pool, rounds >= 1, 1 <= difficulty_bits <= 256")
    combinations = math.comb(pool, selected)
    hit_probability = math.ldexp(1.0, -difficulty_bits)
    # Conditional model: each distinct subset has an independent Bernoulli hit.
    one_round = -math.expm1(combinations * math.log1p(-hit_probability))
    nonpush_estimate = (PAPER_PINNING_NONPUSH_OPCODES +
                        rounds * (11 * selected + 4) + 2)
    result = {
        "pool_signatures_per_round": pool,
        "selected_signatures_per_round": selected,
        "rounds": rounds,
        "puzzle_difficulty_bits": difficulty_bits,
        "exact_subsets_per_round": combinations,
        "subset_entropy_bits": round(math.log2(combinations), 9),
        "expected_hits_per_round_if_uniform": round(
            combinations * hit_probability, 9),
        "one_round_hit_probability_if_independent": round(one_round, 9),
        "all_rounds_hit_probability_if_independent": round(one_round ** rounds, 9),
        "paper_formula_nonpush_opcodes": nonpush_estimate,
        "paper_formula_nonpush_opcode_margin": (
            LEGACY_NONPUSH_OPCODE_LIMIT - nonpush_estimate),
    }
    if selected == 8:
        # The paper's approximate byte formula has no t term. Do not
        # extrapolate it to a different selector count.
        size = (PAPER_FIXED_SCRIPT_BYTES + rounds *
                (PAPER_ROUND_FIXED_BYTES + PAPER_POOL_ENTRY_BYTES * pool))
        result["paper_formula_script_bytes_t8_only"] = size
        result["paper_formula_script_byte_margin_t8_only"] = (
            LEGACY_SCRIPT_LIMIT - size)
    return result


def report():
    rounds = 2
    selected = 8
    difficulty = 42
    first_match = minimum_pool_size(selected, difficulty)
    estimated_max = maximum_pool_size_under_paper_size_formula(rounds)
    return {
        "schema_version": 1,
        "question": "How much 8-of-n subset space fits the paper's two-round byte estimate, and what is the conditional chance of a 42-bit puzzle hit?",
        "source": {
            "id": "binohash-paper",
            "url": "https://robinlinus.com/binohash.pdf",
            "sections": ["4.4", "5.2", "6.1", "6.2"],
            "revision": "2026 PDF reviewed 2026-10-29",
            "sha256": "1be2b63034a86db1f9f4a35c7963248d307583723079ff25284a9fc4affee94a",
        },
        "limits": {
            "legacy_script_bytes": LEGACY_SCRIPT_LIMIT,
            "legacy_nonpush_opcodes": LEGACY_NONPUSH_OPCODE_LIMIT,
        },
        "assumptions": [
            "The exact C(n,t) count assumes distinct selectable pool entries; it does not prove all subsets yield distinct sighashes.",
            "Each subset is evaluated once with a fixed sighash flag; alternate consensus-valid flag bytes or transaction mutations are outside this model.",
            "Signature-puzzle hits for distinct subsets are independent and uniform at 2^-difficulty; this is a model, not measured distribution.",
            "The paper's 100 + rounds * (244 + 31*n) byte expression is an approximation for its t=8 layout, not serialized Script or consensus evidence.",
            "The paper's 13 + rounds * (11*t + 4) + 2 opcode expression is arithmetic from its stated components, not an independently counted script.",
            "Round probabilities are multiplied only under an additional independence assumption; no transaction pinning or full protocol is reproduced.",
        ],
        "minimum_n_for_at_least_one_expected_42_bit_hit_t8": first_match,
        "maximum_n_under_paper_t8_byte_estimate_two_rounds": estimated_max,
        "profiles": {
            str(pool): evaluate(pool, selected, rounds, difficulty)
            for pool in (120, first_match, estimated_max)
        },
    }


def render():
    return json.dumps(report(), indent=2, sort_keys=True) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="compare deterministic output with the checked report")
    parser.add_argument("--output", type=Path, help="write deterministic JSON report")
    args = parser.parse_args()
    rendered = render()
    if args.check:
        if not CHECKED_REPORT.exists() or CHECKED_REPORT.read_text() != rendered:
            print(f"stale report: {CHECKED_REPORT}", file=sys.stderr)
            return 1
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    elif not args.check:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
