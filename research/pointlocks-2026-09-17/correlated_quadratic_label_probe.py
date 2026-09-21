#!/usr/bin/env python3
"""Correlated scalar openings and the quadratic point-label degree boundary.

Exact finite-field checks and small secp256k1 controls, not Bitcoin execution.
No native transaction, garbling implementation or setup benchmark is claimed.
"""
import hashlib
import itertools
import json
import math
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CURVE = HERE.parent / 'covenant-2026-09-17/legacy_same_signature_counterexample.py'
sys.path.insert(0, str(CURVE.parent))
from legacy_same_signature_counterexample import G, N, add, mul

FIELD = 101
PROFILES = ((4, 1), (5, 1), (5, 2), (6, 2),
            (6, 3), (7, 3), (7, 4), (8, 4))


def dot(left, right, modulus):
    return sum(a*b for a, b in zip(left, right)) % modulus


def rref(rows, modulus):
    out = [[v % modulus for v in row] for row in rows]
    if not out:
        return out, []
    width = len(out[0])
    assert all(len(row) == width for row in out)
    pivots = []
    for col in range(width):
        candidates = [i for i in range(len(pivots), len(out)) if out[i][col]]
        if not candidates:
            continue
        pivot = len(pivots)
        source = candidates[0]
        out[pivot], out[source] = out[source], out[pivot]
        inverse = pow(out[pivot][col], -1, modulus)
        out[pivot] = [v*inverse % modulus for v in out[pivot]]
        for i in range(len(out)):
            if i != pivot and out[i][col]:
                scale = out[i][col]
                out[i] = [(a-scale*b) % modulus for a, b in zip(out[i], out[pivot])]
        pivots.append(col)
    return out, pivots


def forms(count, opened, modulus):
    # Candidate i is evaluation of a degree-opened secret polynomial at i+1.
    assert count < modulus and 1 <= opened < count
    return [tuple(pow(i+1, degree, modulus) for degree in range(opened+1))
            for i in range(count)]


def fiber_direction(selected, modulus):
    # Coefficients of product (u-(i+1)); its evaluations at selected rows vanish.
    coefficients = [1]
    for index in selected:
        result = [0] * (len(coefficients)+1)
        for degree, value in enumerate(coefficients):
            result[degree] = (result[degree]-(index+1)*value) % modulus
            result[degree+1] = (result[degree+1]+value) % modulus
        coefficients = result
    assert coefficients[-1] == 1
    return tuple(coefficients)


def monomials(variables, degree):
    if variables == 1:
        yield (degree,)
        return
    for first in range(degree+1):
        for tail in monomials(variables-1, degree-first):
            yield (first,) + tail


def evaluate_monomial(point, powers, modulus):
    result = 1
    for value, exponent in zip(point, powers):
        result = result * pow(value, exponent, modulus) % modulus
    return result


def degree_screen(count, opened):
    points = [fiber_direction(s, FIELD)
              for s in itertools.combinations(range(count), opened)]
    threshold = count-opened+1
    degrees = []
    for degree in range(threshold+1):
        powers = list(monomials(opened+1, degree))
        matrix = [[evaluate_monomial(p, m, FIELD) for m in powers] for p in points]
        rank = len(rref(matrix, FIELD)[1])
        degrees.append(dict(degree=degree, monomials=len(powers), rank=rank,
                            kernel_dimension=len(powers)-rank))
    return dict(candidates=count, opened=opened, secret_dimension=opened+1,
                subset_count=len(points), predicted_initial_degree=threshold,
                degrees=degrees)


def partition_labels(count):
    left = tuple(range(2))
    right = tuple(range(2, count))
    return tuple(tuple(itertools.combinations(side, 2)) for side in (left, right))


def label_available(edges, candidate_forms, direction, modulus):
    return all(dot(candidate_forms[i], direction, modulus)
               * dot(candidate_forms[j], direction, modulus) % modulus == 0
               for i, j in edges)


def particular_solution(candidate_forms, selected, values, modulus):
    dimension = len(candidate_forms[0])
    equations = [list(candidate_forms[i][:-1])+[values[i]] for i in selected]
    reduced, pivots = rref(equations, modulus)
    assert pivots == list(range(dimension-1))
    return tuple(row[-1] for row in reduced) + (0,)


def secret_fixture(dimension):
    return tuple(int.from_bytes(hashlib.sha256(
        f'correlated-quadratic-label-v1:{dimension}:{i}'.encode()).digest(), 'big') % N
        for i in range(dimension))


def curve_controls():
    results = []
    for opened in (1, 2, 3):
        count = opened+3
        candidate_forms = forms(count, opened, N)
        labels = partition_labels(count)
        secret = secret_fixture(opened+1)
        public = [mul(x) for x in secret]
        values = [dot(row, secret, N) for row in candidate_forms]
        candidate_points = [mul(value) for value in values]
        label_points = [[mul(values[i]*values[j] % N) for i, j in edges]
                        for edges in labels]
        recovered_components = opposite_embeddings = 0
        for selected in itertools.combinations(range(count), opened):
            # Only opened scalar values and public coefficient points are used below.
            for i in selected:
                assert mul(values[i]) == candidate_points[i]
            u = particular_solution(candidate_forms, selected, values, N)
            h = fiber_direction(selected, N)
            assert all((u[j]+h[j]*secret[-1]) % N == secret[j]
                       for j in range(opened+1))
            available = [label_available(edges, candidate_forms, h, N) for edges in labels]
            assert sum(available) == 1
            chosen = available.index(True)
            opposite = 1-chosen
            for component, (i, j) in enumerate(labels[chosen]):
                ai, bi = dot(candidate_forms[i], u, N), dot(candidate_forms[i], h, N)
                aj, bj = dot(candidate_forms[j], u, N), dot(candidate_forms[j], h, N)
                assert bi*bj % N == 0
                point = add(mul(ai*aj % N), mul((ai*bj+aj*bi) % N, public[-1]))
                assert point == label_points[chosen][component]
                recovered_components += 1
            # An oracle supplying one unavailable component yields the square-CDH value.
            component, (i, j) = next((c, edge) for c, edge in enumerate(labels[opposite])
                if dot(candidate_forms[edge[0]], h, N)*dot(candidate_forms[edge[1]], h, N) % N)
            ai, bi = dot(candidate_forms[i], u, N), dot(candidate_forms[i], h, N)
            aj, bj = dot(candidate_forms[j], u, N), dot(candidate_forms[j], h, N)
            residual = add(label_points[opposite][component], mul(-ai*aj % N))
            residual = add(residual, mul(-(ai*bj+aj*bi) % N, public[-1]))
            square = mul(pow(bi*bj % N, -1, N), residual)
            assert square == mul(secret[-1]*secret[-1] % N)
            opposite_embeddings += 1
        results.append(dict(candidates=count, opened=opened,
            secret_dimension=opened+1, selected_views=math.comb(count, opened),
            label_vector_lengths=[len(edges) for edges in labels],
            recovered_point_components=recovered_components,
            square_cdh_embeddings=opposite_embeddings))
    return results


class CorrelatedQuadraticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.screens = [degree_screen(n, t) for n, t in PROFILES]
        cls.curve = curve_controls()

    def test_rref_exact_field_arithmetic(self):
        self.assertEqual(len(rref([[1, 2], [2, 4]], FIELD)[1]), 1)
        self.assertEqual(len(rref([[1, 2], [2, 5]], FIELD)[1]), 2)

    def test_full_subset_scalar_privacy_premise(self):
        for count, opened in PROFILES:
            candidates = forms(count, opened, FIELD)
            for selected in itertools.combinations(range(count), opened+1):
                self.assertEqual(len(rref([candidates[i] for i in selected], FIELD)[1]), opened+1)

    def test_fiber_directions_and_affine_particular_solution(self):
        for count, opened in PROFILES:
            candidates = forms(count, opened, FIELD)
            secret = tuple(range(2, opened+3))
            values = [dot(row, secret, FIELD) for row in candidates]
            for selected in itertools.combinations(range(count), opened):
                h = fiber_direction(selected, FIELD)
                self.assertTrue(all(dot(candidates[i], h, FIELD) == 0 for i in selected))
                self.assertTrue(all(dot(candidates[i], h, FIELD) != 0
                                    for i in range(count) if i not in selected))
                u = particular_solution(candidates, selected, values, FIELD)
                self.assertEqual(tuple((a+b*secret[-1]) % FIELD for a, b in zip(u, h)), secret)

    def test_minimum_degree_including_nonlinear_forms(self):
        for screen in self.screens:
            for row in screen['degrees'][:-1]:
                self.assertEqual(row['kernel_dimension'], 0)
            self.assertGreater(screen['degrees'][-1]['kernel_dimension'], 0)

    def test_explicit_polynomial_at_the_boundary(self):
        for count, opened in PROFILES:
            candidates = forms(count, opened, FIELD)
            factors = candidates[:count-opened+1]
            for selected in itertools.combinations(range(count), opened):
                h = fiber_direction(selected, FIELD)
                product = 1
                for factor in factors:
                    product = product*dot(factor, h, FIELD) % FIELD
                self.assertEqual(product, 0)

    def test_correlated_missing_three_positive_boundary(self):
        for opened in range(1, 6):
            count = opened+3
            candidates = forms(count, opened, FIELD)
            for selected in itertools.combinations(range(count), opened):
                h = fiber_direction(selected, FIELD)
                available = [label_available(edges, candidates, h, FIELD)
                             for edges in partition_labels(count)]
                self.assertEqual(sum(available), 1)

    def test_dependent_candidates_are_an_excluded_countercontrol(self):
        candidates = [(1, 0), (0, 1), (1, 1), (1, -1), (2, 0)]
        # x*y*(x+y)*(x-y) vanishes on all five fibers, violating the degree
        # conclusion if the required pairwise-independence premise is omitted.
        for a, b in candidates:
            x, y = b % FIELD, -a % FIELD
            self.assertEqual(x*y*(x+y)*(x-y) % FIELD, 0)
        self.assertEqual(len(rref([candidates[0], candidates[4]], FIELD)[1]), 1)
        self.assertEqual(dot(candidates[4], (7, 11), FIELD), 2*7)

    def test_curve_reconstruction_and_opposite_label_embedding(self):
        self.assertEqual(sum(row['selected_views'] for row in self.curve), 34)
        self.assertEqual(sum(row['square_cdh_embeddings'] for row in self.curve), 34)


if __name__ == '__main__':
    result = unittest.main(argv=[sys.argv[0], '-v'], exit=False).result
    if not result.wasSuccessful():
        raise SystemExit(1)
    report = dict(
        question='Can correlated scalar candidates evade the quadratic two-label subset boundary?',
        conclusion='Not for a full t-of-N alphabet with every t+1 linear forms independent: N-t <= 3 is necessary.',
        field=FIELD, finite_degree_screens=CorrelatedQuadraticTests.screens,
        curve_controls=CorrelatedQuadraticTests.curve, tests_run=result.testsRun,
        evidence='locally-reproduced', algebra_evidence='inspected', deployment='unclassified',
        complete_publication=False, native_wrapper_added=False, public_garbling_verified=False,
        setup_benchmark=None, locking_script_bytes=None, serialized_witness_bytes=None,
        hint_items=None, entry_items=None, combined_stack_peak=None,
        executed_opcodes=None, validation_budget=None, total_onchain_vbytes=None,
        primary_reference='https://arxiv.org/pdf/1203.5685v1',
        source_sha256={str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in (Path(__file__), CURVE)})
    output = HERE/'correlated-quadratic-labels.json'
    output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(dict(output=str(output), tests=result.testsRun,
                         degree_screens=len(report['finite_degree_screens']))))
