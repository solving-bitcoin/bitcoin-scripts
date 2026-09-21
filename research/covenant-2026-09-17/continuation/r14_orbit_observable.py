#!/usr/bin/env python3
"""Complete coordinate-orbit enumeration when every ECDSA r is <=2^191-1.

Exact public host mathematics. No Bitcoin Script verifier or nonce logs.
"""
from fractions import Fraction
import itertools
import json
import math
from pathlib import Path

from r11_endomorphism import (
    BETA, LAMBDA, GAP, N, P, lift, mul, signature,
    gauss_reduce, box_lines, points_in_lines,
)

HERE = Path(__file__).resolve().parent
RMAX = 2**191-1


def ceildiv(a, b):
    return -((-a)//b)


def enumerate_short_orbit():
    assert 3*RMAX < N and 2*GAP < N
    a, b, steps = gauss_reduce((1, BETA), (0, P))
    assert a[0]*b[1]-a[1]*b[0] == P
    assert all((v[1]-BETA*v[0]) % P == 0 for v in (a, b))
    # Independently bound BOTH lattice coefficients using the inverse matrix.
    # Every point of the entire box must lie in these exact intervals.
    corners = list(itertools.product((1, GAP-1), repeat=2))
    numerators_a = [b[1]*x-b[0]*y for x, y in corners]
    numerators_b = [-a[1]*x+a[0]*y for x, y in corners]
    bounds = [(ceildiv(min(v), P), max(v)//P) for v in (numerators_a, numerators_b)]
    candidates, inspected = [], []
    for ca in range(bounds[0][0], bounds[0][1]+1):
        for cb in range(bounds[1][0], bounds[1][1]+1):
            x, y = ca*a[0]+cb*b[0], ca*a[1]+cb*b[1]
            inside = 1 <= x < GAP and 1 <= y < GAP
            inspected.append({'coefficients': [ca, cb], 'x': str(x),
                              'y': str(y), 'inside_box': inside})
            if inside:
                candidates.append((x, y))
    independent_lines = box_lines({'basis': (a, b), 'determinant': P}, 1, GAP-1, 1, GAP-1)
    assert candidates == list(points_in_lines({'basis': (a, b), 'determinant': P}, independent_lines))
    assert len(candidates) == 1
    x, y = candidates[0]
    assert x+y < GAP
    positive = [x, y, P-x-y]
    negative = [P-x, P-y, x+y]
    assert all(positive[(i+1) % 3] == BETA*positive[i] % P for i in range(3))
    assert all(negative[(i+1) % 3] == BETA*negative[i] % P for i in range(3))
    assert all(lift(u) is None for u in positive)
    roots = [lift(u) for u in negative]
    assert all(roots)
    assert all(mul(LAMBDA, roots[i]) == roots[(i+1) % 3] for i in range(3))
    rs = [u % N for u in negative]
    assert sum(rs) == 2*GAP and max(rs) < RMAX
    assert rs[2]-rs[1] == 1
    both_lifts = [sum(lift(v) is not None for v in (r, r+N) if v < P) for r in rs]
    strings = []
    total_strings = 0
    for r in rs:
        r_bytes = len(signature(r, 1, 1))-8
        # Total encoded length is 7+nr+ns, including the sighash flag.
        assert r_bytes in (16, 17)
        s_bytes = 25-r_bytes
        low, high = 2**(8*s_bytes-9), 2**(8*s_bytes-1)-1
        assert len(signature(r, low, 1)) == len(signature(r, high, 1)) == 32
        assert len(signature(r, low-1, 1)) == 31
        assert len(signature(r, high+1, 1)) == 33
        count = 256*(high-low+1)
        total_strings += count
        strings.append({'r': str(r), 'r_integer_bytes': r_bytes,
                        's_integer_bytes': s_bytes, 'smallest_s': str(low),
                        'largest_s': str(high), 'all_flag_string_count': str(count)})
    probability = Fraction(total_strings, 2**256)
    assert probability == Fraction(32895, 2**192)
    return {
        'gauss_basis': [list(map(str, a)), list(map(str, b))], 'gauss_steps': steps,
        'determinant': str(P), 'inverse_coefficient_bounds': bounds,
        'coefficient_pairs_inspected': inspected, 'box_coordinate_pairs': [list(map(str, pair)) for pair in candidates],
        'h1_candidate_x': list(map(str, positive)), 'h1_liftable': False,
        'h2_unique_coordinate_orbit': list(map(str, negative)),
        'h2_r': list(map(str, rs)), 'r_bit_lengths': [r.bit_length() for r in rs],
        'h2_even_y': str(roots[0][1]), 'nonzero_y': True,
        'oriented_point_orbits_up_to_rotation': 2,
        'x_lifts_per_r': both_lifts,
        'hash_der_sets': strings, 'total_32byte_strings_with_one_of_these_r': str(total_strings),
        'uniform_SHA256_probability': str(probability),
        'uniform_SHA256_probability_log2': math.log2(probability),
        'at_most_2_64_fresh_queries_success_upper_bound': str(2**64*probability),
        'at_most_2_64_queries_bound_log2': math.log2(2**64*probability),
    }


def main():
    report = {'question': 'Can three short hash-derived ECDSA signatures supply a variable orbit h?',
              'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
              'conditions': 'one genuine three-point secp256k1 endomorphism orbit; all r nonzero and <=2^191-1',
              'coordinate_enumeration': enumerate_short_orbit(),
              'scope': 'Complete exact coordinate enumeration; SHA256 query estimates additionally assume a fresh ideal uniform oracle. No native orbit verifier, nonce logarithm, hash preimage or complete covenant.'}
    destination = HERE/'r14_orbit_observable.json'
    destination.write_text(json.dumps(report, indent=2)+'\n')
    row = report['coordinate_enumeration']
    print(json.dumps({'output': str(destination), 'coefficient_bounds': row['inverse_coefficient_bounds'],
                      'coefficient_pairs': len(row['coefficient_pairs_inspected']), 'coordinate_orbits': 1,
                      'r_bit_lengths': row['r_bit_lengths'], 'x_lifts_per_r': row['x_lifts_per_r'],
                      'hash_query_bound_log2_at_2_64': row['at_most_2_64_queries_bound_log2']}, indent=2))


if __name__ == '__main__':
    main()
