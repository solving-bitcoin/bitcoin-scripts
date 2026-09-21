#!/usr/bin/env python3
"""Reproduce the scoped span obstruction for scalar-linear complement labels.

The universal proof is in complement-linear-obstruction.md. These are exact
finite-field regression examples, not an empirical proof of impossibility.
"""
import hashlib
import itertools
import json
from pathlib import Path

MOD = 101
HERE = Path(__file__).resolve().parent


def rank(vectors, dimension):
    a = [list(v) for v in vectors]
    row = 0
    for col in range(dimension):
        pivot = next((i for i in range(row, len(a)) if a[i][col] % MOD), None)
        if pivot is None:
            continue
        a[row], a[pivot] = a[pivot], a[row]
        inverse = pow(a[row][col] % MOD, -1, MOD)
        a[row] = [x * inverse % MOD for x in a[row]]
        for i in range(row+1, len(a)):
            factor = a[i][col] % MOD
            a[i] = [(x-factor*y) % MOD for x, y in zip(a[i], a[row])]
        row += 1
    return row


def contains(vectors, target):
    return rank(vectors, len(target)) == rank([*vectors, target], len(target))


def main():
    examples = []
    for t in range(1, 6):
        n, dimension = t+2, t+1
        v = [[pow(i+1, k, MOD) for k in range(dimension)] for i in range(n)]
        tested = 0
        for group in itertools.combinations(range(n), t+1):
            assert rank([v[i] for i in group], dimension) == t+1
            tested += 1
        # j=0, U={1,...,t-1}; two distinct remaining candidates a,b.
        u = list(range(1,t))
        a, b = t, t+1
        left, right = [v[i] for i in [*u,a]], [v[i] for i in [*u,b]]
        intersection_dimension = rank(left,dimension)+rank(right,dimension)-rank(left+right,dimension)
        assert intersection_dimension == t-1
        assert rank([v[i] for i in u], dimension) == t-1
        # A constant required in both spans lies in span(U), hence is available
        # to U union {j}, where j's zero-label was required to stay secret.
        candidate_zero = [sum(v[i][k] for i in u) % MOD for k in range(dimension)]
        assert contains(left,candidate_zero) and contains(right,candidate_zero)
        assert contains([v[i] for i in [*u,0]],candidate_zero)
        # Tight boundary n=t+1: independent scalar inputs, Z_j=sum_{i!=j} x_i.
        boundary_n = t+1
        e = [[int(i==k) for k in range(boundary_n)] for i in range(boundary_n)]
        boundary_checks = 0
        for j in range(boundary_n):
            z = [int(i!=j) for i in range(boundary_n)]
            for selected in itertools.combinations(range(boundary_n),t):
                assert contains([e[i] for i in selected],z) == (j not in selected)
                for k in range(boundary_n):
                    if k not in selected:
                        assert not contains([e[i] for i in selected],e[k])
                boundary_checks += 1
        examples.append(dict(t=t, excluded_n=n, every_t_plus_one_independent_checks=tested,
                             intersection_dimension=intersection_dimension,
                             selected_zero_becomes_reconstructible=True,
                             tight_boundary_n=boundary_n, tight_boundary_checks=boundary_checks))
    # A short dependency creates the other forbidden branch: an unselected x.
    vectors = [[1,0,0],[0,1,0],[0,0,1],[1,1,0]]
    assert contains([vectors[0],vectors[1]],vectors[3])
    result=dict(evidence='locally-reproduced',deployment='unclassified',
        scope=__doc__,field_prime=MOD,examples=examples,
        dependent_scalar_example=dict(selected=[0,1],unselected_recovered=3,relation='x_3=x_0+x_1'),
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    (HERE/'complement-linear-obstruction.json').write_text(json.dumps(result,indent=2)+'\n')
    print('PASS t=1..5 obstruction examples, tight n=t+1 boundary, and scalar-dependency leak')


if __name__=='__main__':
    main()
