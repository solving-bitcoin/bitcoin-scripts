#!/usr/bin/env python3
"""Exact finite-oracle checks; no Bitcoin execution or cryptographic attack."""
import itertools
import json
import math
from fractions import Fraction
from pathlib import Path


def first_success(bits):
    return next((i + 1 for i, b in enumerate(bits) if b), len(bits))


def pin_and_rounds(m, rounds):
    # p=1/2. Pin search costs exactly 2 in expectation. After pinning,
    # independent digest rows have m candidates each; stop on failed round.
    total_cost = Fraction(0)
    total_success = 0
    samples = 1 << (m * rounds)
    for bits in itertools.product((0, 1), repeat=m * rounds):
        cost = Fraction(2)
        success = True
        for r in range(rounds):
            row = bits[r * m:(r + 1) * m]
            cost += first_success(row)
            if not any(row):
                success = False
                break
        total_cost += cost
        total_success += success
    expected = total_cost / total_success
    s = 1 - Fraction(1, 2) ** m
    formula = sum(Fraction(2) / s ** i for i in range(rounds + 1))
    assert expected == formula
    return {"m": m, "rounds": rounds, "samples": samples,
            "success_per_pinned_transaction": str(Fraction(total_success, samples)),
            "expected_native_queries": str(expected), "formula": str(formula)}


def selected_query_attack():
    # Four mutually inconsistent local requirements on one committed bit:
    # x=0, x=1, x=1, x=1. Commit x=0. Exactly q=0 accepts this trace.
    # Native relation is a uniformly random 3-transaction x 4-query bit table.
    targeted = random_query = 0
    for bits in itertools.product((0, 1), repeat=12):
        targeted += any(bits[4 * t] for t in range(3))
        for qs in itertools.product(range(4), repeat=3):
            random_query += any(q == 0 and bits[4 * t + q]
                                for t, q in enumerate(qs))
    assert Fraction(targeted, 4096) == Fraction(7, 8)
    assert Fraction(random_query, 4096 * 64) == Fraction(169, 512)
    return {"native_gate_probability": "1/2", "queries": 4,
            "transaction_candidates": 3, "fixed_trace_accepting_fraction": "1/4",
            "targeted_query_success": str(Fraction(targeted, 4096)),
            "uniform_independent_query_success": str(Fraction(random_query, 4096 * 64)),
            "scope": "one native gate; no separate QSB pin or other digest rounds"}


def main():
    p = 780555 / 2 ** 65
    costs = []
    for log_m in (0, 20, 40, 45.4258592336, 50):
        m = 2 ** log_m
        s = -math.expm1(m * math.log1p(-p))
        costs.append({"log2_eligible_candidates_per_round": log_m,
                      "single_round_success_per_pinned_tx": s,
                      "log2_pin_plus_one_round_queries": math.log2((1 + 1 / s) / p),
                      "log2_pin_plus_two_round_queries": math.log2((1 + 1 / s + 1 / s ** 2) / p)})
    result = {"evidence": "locally-reproduced", "deployment": "unclassified",
              "scope": "exhaustive toy random-oracle accounting; no Script metrics",
              "selected_query_attack": selected_query_attack(),
              "pinning_checks": [pin_and_rounds(m, r) for m in range(1, 5) for r in (1, 2)],
              "sha256_der_estimates": costs}
    out = Path(__file__).with_suffix('.json')
    out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
