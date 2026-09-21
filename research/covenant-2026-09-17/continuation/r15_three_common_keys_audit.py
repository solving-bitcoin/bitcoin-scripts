#!/usr/bin/env python3
"""Independent exhaustive small-curve audit of the mismatched-pair quartic.

No imported curve or quartic implementation, no Core or library field tests.
"""
from itertools import combinations
import json
from pathlib import Path


def audit(p, n, generator):
    def add(first, second):
        if first is None:
            return second
        if second is None:
            return first
        x, y = first
        u, v = second
        if x == u and (y+v) % p == 0:
            return None
        slope = ((3*x*x)*pow(2*y, -1, p) if first == second
                 else (v-y)*pow(u-x, -1, p)) % p
        nx = (slope*slope-x-u) % p
        return nx, (slope*(x-nx)-y) % p

    points = [None]
    for scalar in range(1, n):
        points.append(add(points[-1], generator))
    assert add(points[-1], generator) is None and len(set(points)) == n
    assert set(points[1:]) == {(x, y) for x in range(p) for y in range(p)
                              if (y*y-x*x*x-7) % p == 0}
    roots = {r: [k for k in range(1, n) if points[k][0] % n == r] for r in range(1, n)}
    roots = {r: ks for r, ks in roots.items() if len(ks) == 4}
    counts = {'four_root_sets': len(roots), 'maps_tested': 0, 'matched': 0,
              'mismatched': 0, 'quartics_checked': 0}
    mismatched = []
    for source_r, source_roots in roots.items():
        for triple in combinations(source_roots, 3):
            for a in range(1, n):
                for b in range(n):
                    counts['maps_tested'] += 1
                    targets = [(a*k+b) % n for k in triple]
                    if 0 in targets:
                        continue
                    target_rs = {points[k][0] % n for k in targets}
                    if len(target_rs) != 1 or 0 in target_rs:
                        continue
                    pair = next(pair for pair in combinations(triple, 2) if sum(pair) % n == 0)
                    if sum((a*k+b) % n for k in pair) % n == 0:
                        assert b == 0
                        counts['matched'] += 1
                        continue
                    counts['mismatched'] += 1
                    B = next(k for k in triple if k not in pair)
                    A = next(k for k in pair if (a*(k+B)+2*b) % n == 0)
                    V, U = (A+B)*pow(2, -1, n) % n, (A-B)*pow(2, -1, n) % n
                    assert V and U and (b+a*V) % n == 0
                    v, w = points[V]
                    X, Y = points[U]
                    delta = points[A][0]-points[B][0]
                    assert delta in (-n, n) and X != v and w
                    assert Y == -delta*(X-v)**2*pow(4*w, -1, p) % p
                    assert (delta*delta*(X-v)**4-16*w*w*(X**3+7)) % p == 0
                    assert set(targets) == {a*U % n, -a*U % n, -a*(2*V+U) % n}
                    counts['quartics_checked'] += 1
                    mismatched.append({'source_r': source_r, 'target_r': next(iter(target_rs)),
                                       'source_scalar_triple': triple, 'a': a, 'b': b,
                                       'A_scalar': A, 'B_scalar': B, 'U': points[U],
                                       'V': points[V], 'signed_integer_gap': delta})
    return {'p': p, 'n': n, 'generator': generator, 'counts': counts,
            'mismatched_vectors': mismatched}


def main():
    cases = [audit(211, 199, (3, 33)), audit(163, 139, (2, 34))]
    assert [c['counts']['maps_tested'] for c in cases] == [315216, 306912]
    assert [c['counts']['matched'] for c in cases] == [16, 48]
    assert [c['counts']['mismatched'] for c in cases] == [0, 8]
    result = {'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
              'scope': 'Independent exhaustive small-curve algebra; no Bitcoin script or native hash construction',
              'cases': cases}
    output = Path(__file__).with_suffix('.json')
    output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'output': str(output), 'cases': [c['counts'] for c in cases]}, indent=2))


if __name__ == '__main__':
    main()
