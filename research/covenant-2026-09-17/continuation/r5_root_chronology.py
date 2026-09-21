#!/usr/bin/env python3
"""Exact renewal accounting for a proposed proof-root/native-puzzle chronology.

Host probability models only: no Script execution, proof system, or mined gate.
All finite random tables are exhaustively enumerated; no random seed is needed.
"""
import itertools
import json
import math
from fractions import Fraction
from pathlib import Path


def transaction_attempt(bits, m):
    """Pin, then two sequential rounds, stopping immediately on failure."""
    cost = 1
    if not bits[0]:
        return cost, False
    for round_index in range(2):
        row = bits[1 + round_index * m:1 + (round_index + 1) * m]
        found = False
        for hit in row:
            cost += 1
            if hit:
                found = True
                break
        if not found:
            return cost, False
    return cost, True


def exhaustive_renewal(m, transaction_family_size):
    """p=a=1/2. Mining a root costs exactly 1/a=2 in expectation."""
    length = (1 + 2 * m) * transaction_family_size
    total_cost = 0
    successes = 0
    tables = 1 << length
    for bits in itertools.product((0, 1), repeat=length):
        cost = 2
        success = False
        for transaction_index in range(transaction_family_size):
            start = transaction_index * (1 + 2 * m)
            local_cost, success = transaction_attempt(bits[start:start + 1 + 2 * m], m)
            cost += local_cost
            if success:
                break
        total_cost += cost
        successes += success
    actual = Fraction(total_cost, successes)
    p = a = Fraction(1, 2)
    s = 1 - (1 - p) ** m
    b = p * s * s
    t = 1 - (1 - b) ** transaction_family_size
    expected = 1 / (a * t) + (1 + s + s * s) / b
    assert actual == expected
    assert Fraction(successes, tables) == t
    return {"eligible_digest_subsets_per_round": m,
            "transaction_family_size": transaction_family_size,
            "finite_native_tables_enumerated": tables,
            "success_per_root": str(t),
            "expected_root_plus_native_queries": str(actual)}


def dynamic_trace_counterexample():
    # Fixed program: wire a equals public input x, and output y equals a.
    # Claim x=0,y=1. Program truth is committed, dynamic wire a is not.
    def accepts(a, query):
        return a == 0 if query == 0 else a == 1

    fixed = {str(a): [accepts(a, query) for query in range(2)] for a in range(2)}
    adaptive = [any(accepts(a, query) for a in range(2)) for query in range(2)]
    assert all(sum(row) == 1 for row in fixed.values())
    assert all(adaptive)
    return {"public_input": 0, "claimed_output": 1,
            "constraints": ["a=x", "y=a"],
            "fixed_trace_acceptance_by_query": fixed,
            "trace_chosen_after_query_acceptance": adaptive,
            "scope": "committing program wiring does not commit input-dependent wire values"}


def estimates():
    p = 780555 / 2 ** 65
    rows = []
    # a=p grants recovery-point existence, nonzero scalars and flag enforcement
    # for free. It is deliberately optimistic, not a measured viable-root rate.
    for log_m in (40, 45, 50, 56):
        s = -math.expm1(2 ** log_m * math.log1p(-p))
        b = p * s * s
        for log_l in (0, 27, 32, 40, 48):
            t = -math.expm1(2 ** log_l * math.log1p(-b))
            native = (1 + s + s * s) / b
            query_count = 1 / (p * t) + native
            rows.append({"log2_subsets_per_round": log_m,
                         "log2_statement_preserving_transactions_per_root": log_l,
                         "round_success": s, "root_family_success": t,
                         "log2_expected_root_and_native_queries": math.log2(query_count),
                         "log2_native_component": math.log2(native)})
    return {"native_sha256_der_probability": "780555/2^65",
            "optimistic_root_probability": "a=p; valid recovery and flags granted free",
            "excluded_costs": ["proof construction", "proof audit", "root serialization/hash blocks",
                               "EC recovery", "sighash computations", "subset enumeration",
                               "opening construction and verification"],
            "configurations": rows}


def main():
    data = {"evidence": "locally-reproduced", "deployment": "unclassified",
            "scope": "host finite-oracle accounting; no consensus or covenant claim",
            "renewal_checks": [exhaustive_renewal(m, l)
                               for m in (1, 2) for l in (1, 2, 3)],
            "program_root_counterexample": dynamic_trace_counterexample(),
            "estimates": estimates()}
    Path(__file__).with_suffix('.json').write_text(json.dumps(data, indent=2) + '\n')
    print(json.dumps(data, indent=2))


if __name__ == '__main__':
    main()
