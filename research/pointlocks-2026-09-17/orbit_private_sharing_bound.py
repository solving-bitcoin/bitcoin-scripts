#!/usr/bin/env python3
"""Cost of fixed-orbit key reuse, with and without alternative-label privacy.

Abstract graph counting and synthetic known-ratio secp256k1 controls only.
The synthetic second base is NOT an ECDSA recovery root. No native predicate,
transaction, setup benchmark, or general point-lock impossibility is claimed.
"""
from collections import Counter
from decimal import Decimal, localcontext, ROUND_CEILING
import hashlib
import json
from pathlib import Path
import unittest

from orbit_key_sharing_probe import (
    canonical, orbit, propagate_openings, rate_bound, recover_base_ratio,
    roots, scalar_fixture, mul,
)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PROFILES = (
    (("path", 1),),
    (("cycle", 2),),  # two shared keys: parallel edges, no self-loops
    (("path", 8),),
    (("cycle", 8),),
    (("path", 3), ("cycle", 3), ("path", 1), ("path", 1)),
    (("path", 2), ("path", 2), ("cycle", 4)),
)


def graph_rate(signature_bytes):
    """Root of the double-edge component partition function, 90-digit bracket."""
    with localcontext() as ctx:
        ctx.prec = 90
        lo, hi = Decimal("0.001"), Decimal(1000)
        ln2 = Decimal(2).ln()
        costs = (40, 106 + signature_bytes, 106 + 2 * signature_bytes)
        for _ in range(200):
            mid = (lo + hi) / 2
            weights = [(-Decimal(cost) * ln2 / mid).exp() for cost in costs]
            mass = weights[0] + 2 * weights[1] + weights[2]
            if mass < 1:
                lo = mid
            else:
                hi = mid
        low_int, high_int = [int((2048 * r).to_integral_value(rounding=ROUND_CEILING))
                             for r in (lo, hi)]
        assert low_int == high_int
        return dict(signature_bytes=signature_bytes, rate_lower=str(lo), rate_upper=str(hi),
                    lower_bound_2048_bits_vbytes=low_int,
                    dimer_costs_vbytes=dict(neither=costs[0], one=costs[1], both=costs[2]))


def private_rate(signature_bytes):
    row = rate_bound(20, 66 + signature_bytes)
    with localcontext() as ctx:
        ctx.prec = 90
        endpoints = [int((2047 * Decimal(row[name])).to_integral_value(rounding=ROUND_CEILING))
                     for name in ("rate_lower", "rate_upper")]
        assert endpoints[0] == endpoints[1]
    return dict(signature_bytes=signature_bytes, rate_lower=row["rate_lower"],
                rate_upper=row["rate_upper"], family_union_mass_bound=2,
                lower_bound_2048_bits_vbytes=endpoints[0])


def make_graph(profile):
    """A fixed two-key packet per vertex; each key has at most two owners."""
    keys, edges, components = [], [], []
    next_key = 0
    for kind, size in profile:
        assert size >= (2 if kind == "cycle" else 1)
        start = len(keys)
        keys.extend(set() for _ in range(size))
        vertices = tuple(range(start, start + size))
        components.append(frozenset(vertices))
        pairs = list(zip(vertices, vertices[1:]))
        if kind == "cycle":
            pairs.append((vertices[-1], vertices[0]))
        else:
            assert kind == "path"
        for left, right in pairs:
            keys[left].add(next_key)
            keys[right].add(next_key)
            next_key += 1
            edges.append((left, right))
        for vertex in vertices:
            while len(keys[vertex]) < 2:
                keys[vertex].add(next_key)
                next_key += 1
            assert len(keys[vertex]) == 2
    owners = Counter(key for packet in keys for key in packet)
    assert max(owners.values()) <= 2
    return keys, edges, components


def independent(selected, edges):
    return not any(left in selected and right in selected for left, right in edges)


def component_union(selected, components):
    return all(not selected.intersection(c) or c.issubset(selected) for c in components)


def exposed_ratio_closure(selected, edges):
    """Graph consequence of one shared pair exposing the *global* base ratio.

    With no selected edge, return the selection unchanged. This grants privacy
    in that case; it is not a proof that no other computation can reveal rho.
    """
    opened = set(selected)
    if independent(selected, edges):
        return opened
    todo = list(selected)
    while todo:
        current = todo.pop()
        for left, right in edges:
            other = right if current == left else left if current == right else None
            if other is not None and other not in opened:
                opened.add(other)
                todo.append(other)
    return opened


def inventory_cases():
    graph_r = float(graph_rate(40)["rate_lower"])
    private_r = float(private_rate(40)["rate_lower"])
    rows = []
    for profile in PROFILES:
        keys, edges, components = make_graph(profile)
        counts = Counter()
        masses = Counter()
        for mask in range(1 << len(keys)):
            selected = {i for i in range(len(keys)) if mask >> i & 1}
            present = set().union(*(keys[i] for i in selected))
            shared_edges = sum(left in selected and right in selected for left, right in edges)
            assert len(present) == 2 * len(selected) - shared_edges
            cost = 20 * len(keys) + 40 * len(selected) + 33 * len(present)
            is_i = independent(selected, edges)
            is_u = component_union(selected, components)
            safe = exposed_ratio_closure(selected, edges) == selected
            assert safe == (is_i or is_u)
            if is_i:
                assert len(present) == 2 * len(selected)
            if is_u:
                for c in components:
                    if c.issubset(selected):
                        assert len(set().union(*(keys[i] for i in c))) >= len(c)
            counts["all"] += 1
            masses["all_at_graph_rate"] += 2 ** (-cost / graph_r)
            for name, included in (("independent", is_i), ("component_unions", is_u),
                                   ("safe_union", safe)):
                if included:
                    counts[name] += 1
                    masses[name + "_at_private_rate"] += 2 ** (-cost / private_r)
        # Floating-point checks reproduce finite examples, not the analytic proof.
        assert masses["all_at_graph_rate"] <= 1 + 1e-12
        assert masses["independent_at_private_rate"] <= 1 + 1e-12
        assert masses["component_unions_at_private_rate"] <= 1 + 1e-12
        assert masses["safe_union_at_private_rate"] <= 2 + 1e-12
        rows.append(dict(profile=profile, labels=len(keys), counts=dict(counts),
                         numerical_partition_masses=dict(masses)))
    return rows


def cross_component_control():
    root0 = roots(2)[0]
    rho = 7
    bases = (root0, mul(rho, root0))  # synthetic, not both ECDSA lifts
    values = []
    for component, size in enumerate((3, 3, 1)):
        seed = scalar_fixture(f"orbit-private-sharing/component/{component}")
        values.extend(canonical(seed * pow(rho, j)) for j in range(size))
    packets = [orbit(s, bases) for s in values]
    edges = [(i, j) for i in range(7) for j in range(i + 1, 7)
             if packets[i].intersection(packets[j])]
    assert edges == [(0, 1), (1, 2), (3, 4), (4, 5)]
    recovered = recover_base_ratio(bases, values[0], values[1])
    assert recovered == rho
    rows = []
    for selected, expected in (({0, 1, 2, 3}, set(range(6))),
                               (set(range(6)), set(range(6))),
                               ({0, 1, 2, 6}, {0, 1, 2, 6})):
        opened = propagate_openings(bases, packets, {i: values[i] for i in selected}, recovered)
        assert set(opened) == expected
        assert all(value == values[i] for i, value in opened.items())
        rows.append(dict(selected=sorted(selected), recovered=sorted(opened),
                         extra_labels=sorted(set(opened) - selected)))
    return rows


class PrivateSharingTests(unittest.TestCase):
    def test_graph_bound_including_double_edges(self):
        self.assertEqual(graph_rate(40)["lower_bound_2048_bits_vbytes"], 110865)
        keys, edges, _ = make_graph((("cycle", 2),))
        self.assertEqual(keys[0], keys[1])
        self.assertEqual(len(edges), 2)

    def test_privacy_bound_and_short_profile_boundary(self):
        self.assertEqual(private_rate(40)["lower_bound_2048_bits_vbytes"], 116643)
        self.assertEqual(private_rate(13)["lower_bound_2048_bits_vbytes"], 100291)
        self.assertEqual(private_rate(12)["lower_bound_2048_bits_vbytes"], 99664)

    def test_every_subset_of_bounded_graphs(self):
        rows = inventory_cases()
        self.assertEqual(sum(row["counts"]["all"] for row in rows), 1030)
        # A mixed selection opens a pair in one component and just one label
        # in another: local component checks alone would miss the disclosure.
        _, edges, components = make_graph((("cycle", 2), ("path", 2)))
        chosen = {0, 1, 2}
        self.assertFalse(independent(chosen, edges))
        self.assertFalse(component_union(chosen, components))
        self.assertEqual(exposed_ratio_closure(chosen, edges), {0, 1, 2, 3})

    def test_known_ratio_disclosure_crosses_selected_components(self):
        rows = cross_component_control()
        self.assertEqual(rows[0]["extra_labels"], [4, 5])
        self.assertEqual(rows[1]["extra_labels"], [])
        self.assertEqual(rows[2]["extra_labels"], [])


if __name__ == "__main__":
    program = unittest.main(exit=False)
    if not program.result.wasSuccessful():
        raise SystemExit(1)
    sources = [Path(__file__), HERE / "orbit_key_sharing_probe.py",
               HERE / "four_root_orbit_probe.py", HERE / "four_recovery_key_probe.py",
               HERE / "core_check.py", HERE / "anchored_extraction.py",
               HERE / "publication_core_check.py", HERE / "nonce_relation_extraction.py",
               HERE.parent / "covenant-2026-09-17/legacy_same_signature_counterexample.py"]
    rows = inventory_cases()
    report = dict(scope=__doc__, evidence="locally-reproduced", deployment="unclassified",
                  tests_run=program.result.testsRun,
                  graph_bounds=[graph_rate(length) for length in (40, 13, 12, 0)],
                  privacy_bounds=[private_rate(length) for length in (40, 13, 12)],
                  bounded_graphs=rows,
                  enumerated_subsets=sum(row["counts"]["all"] for row in rows),
                  synthetic_cross_component_controls=cross_component_control(),
                  synthetic_bases_are_ecdsa_root_sets=False, actual_root_ratio_computed=False,
                  native_execution=False, setup_benchmark=False,
                  new_script_bytes=None, new_witness_bytes=None,
                  new_hint_items=None, new_stack_peak=None,
                  source_sha256={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in sources})
    (HERE / "orbit-private-sharing-bound.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("tests_run", "enumerated_subsets", "graph_bounds",
                                            "privacy_bounds")}, indent=2))
