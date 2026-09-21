#!/usr/bin/env python3
"""Endpoint graph algebra and relaxed byte bounds; no Script/Core execution."""
from fractions import Fraction
from itertools import product
from math import comb
from pathlib import Path
import json
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "covenant-2026-09-17" / "continuation"))
from r11_endomorphism import C, G, N, P, mul, add, BETA, LAMBDA


def rank(rows, width):
    a = [list(row) for row in rows]
    rank = 0
    for col in range(width):
        pivot = next((i for i in range(rank, len(a)) if a[i][col] % N), None)
        if pivot is None:
            continue
        a[rank], a[pivot] = a[pivot], a[rank]
        z = pow(a[rank][col] % N, -1, N)
        a[rank] = [v*z % N for v in a[rank]]
        for i in range(len(a)):
            if i != rank and a[i][col]:
                z = a[i][col]
                a[i] = [(x-z*y) % N for x, y in zip(a[i], a[rank])]
        rank += 1
    return rank


def edge_row(edge, width):
    row = [0] * width
    for v in edge:
        row[v] += 1
    return row


def closure(selected, edges, width):
    rows = [edge_row(e, width) for e in selected]
    dim = rank(rows, width)
    return [e for e in edges if rank(rows + [edge_row(e, width)], width) == dim]


def closed_assignment_test():
    edges = [(i, 3+j) for i in range(3) for j in range(3)]
    for choices in product(range(3), repeat=3):
        selected = [(i, 3+j) for i, j in enumerate(choices)]
        assert set(closure(selected, edges, 6)) == set(selected)
    # Different spanning trees of K2,2 disclose the fourth edge for free.
    square = [(0, 2), (0, 3), (1, 2), (1, 3)]
    assert closure(square[:3], square, 4) == square
    return {"K3_3_closed_one_edge_per_left_assignments": 27,
            "K2_2_three_edge_witness_closure_edges": 4}


def odd_cycle_fixture():
    # Public deterministic fixture secrets only, never production secrets.
    ks = [7, 19, 31]
    nonce_points = [mul(k) for k in ks]
    rs = [point[0] % N for point in nonce_points]
    ts = [-2*C*pow(r, -1, N) % N for r in rs]
    half = pow(2, -1, N)
    vs = [(ts[0]-ts[1]+ts[2])*half % N,
          (ts[0]+ts[1]-ts[2])*half % N,
          (-ts[0]+ts[1]+ts[2])*half % N]
    edges = [(0, 1), (1, 2), (2, 0)]
    signatures = []
    for edge, k, r, target in zip(edges, ks, rs, ts):
        u, v = edge
        assert (vs[u]+vs[v]) % N == target
        s = (C+r*vs[u])*pow(k, -1, N) % N
        s = min(s, N-s)
        assert s and r > P-N
        for vertex in edge:
            recovered = mul((C+r*vs[vertex])*pow(s, -1, N) % N)
            assert recovered[0] % N == r
        signatures.append({"r": str(r), "s": str(s)})
    assert rank([edge_row(e, 3) for e in edges], 3) == 3
    # The endomorphism gives three different r values, not three additive
    # inverse-coordinate targets. Record one explicit failed candidate.
    orbit_r = [(pow(BETA, j, P)*nonce_points[0][0] % P) % N for j in range(3)]
    orbit_t = [-2*C*pow(r, -1, N) % N for r in orbit_r]
    assert len(set(orbit_r)) == 3
    assert sum(orbit_t) % N != 0
    assert mul(LAMBDA, nonce_points[0]) == (BETA*nonce_points[0][0] % P, nonce_points[0][1])
    return {"nonce_scalars": list(map(str, ks)), "endpoint_scalars": list(map(str, vs)),
            "edge_target_scalars": list(map(str, ts)), "signatures": signatures,
            "all_six_ECDSA_equations_hold": True,
            "endomorphism_inverse_coordinate_sum_mod_n": str(sum(orbit_t) % N)}


def byte_bounds():
    target = 1 << 2048
    density_limits = [Fraction(1), Fraction(8, 7), Fraction(4, 3),
                      Fraction(3, 2), Fraction(2), Fraction(3), Fraction(4)]
    best = {rho: None for rho in density_limits}
    least_density = None
    e = 2054
    t = e//2
    count = comb(e, t)
    assert count >= target and comb(e-1, (e-1)//2) < target
    for e in range(2054, 8001):
        if e != 2054:
            count = count*e//(e-t)
        while t and count*t//(e-t+1) >= target:
            count = count*t//(e-t+1)
            t -= 1
        assert count >= target and count*t//(e-t+1) < target
        for rho in density_limits:
            v = (e*rho.denominator+rho.numerator-1)//rho.numerator
            cost = 34*v+72*t
            if best[rho] is None or cost < best[rho]["bytes"]:
                best[rho] = {"vertices": v, "edges": e, "revelations": t, "bytes": cost}
        max_v = (99999-72*t)//34
        if max_v > 0:
            rho = Fraction(e, max_v)
            if least_density is None or rho < least_density[0]:
                least_density = (rho, {"vertices": max_v, "edges": e,
                                       "revelations": t, "bytes": 34*max_v+72*t})
    # At E>8000, even the cheapest table allowed by rho<=4 exceeds
    # that profile's incumbent; all lower-density profiles are also bounded.
    for rho, row in best.items():
        assert 34*((8001*rho.denominator+rho.numerator-1)//rho.numerator) > row["bytes"]
    assert Fraction(8001, 99999//34) > least_density[0]
    return {"density_limits": {str(r): v for r, v in best.items()},
            "least_relaxed_density_below_100000": {
                "E_over_V": str(least_density[0]), "decimal": float(least_density[0]),
                **least_density[1]},
            "scope": "Full embedded 33B endpoints, 71B signatures; all t-subsets counted, even nonclosed ones; all verification and transaction overhead omitted."}


def main():
    result = {"evidence": "locally-reproduced", "deployment": "unclassified",
              "closed_sets": closed_assignment_test(), "odd_cycle": odd_cycle_fixture(),
              "bounds": byte_bounds()}
    output = HERE / "endpoint-graph-search.json"
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
