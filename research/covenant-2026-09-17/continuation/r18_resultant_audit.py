#!/usr/bin/env python3
"""Independent audit: generic polynomial Euclidean resultants and toy groups.

No imports from the construction's curve, resultant or polynomial code.
"""
import hashlib
from itertools import combinations
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
P = 2**256 - 2**32 - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


def trim(a, p):
    a = [x % p for x in a]
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    return a


def plus(a, b, p):
    c = [0] * max(len(a), len(b))
    for i, x in enumerate(a): c[i] += x
    for i, x in enumerate(b): c[i] += x
    return trim(c, p)


def scale(a, k, p): return trim([k*x for x in a], p)


def times(a, b, p):
    c = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b): c[i+j] += x*y
    return trim(c, p)


def remainder(a, b, p):
    a, b = trim(a, p), trim(b, p)
    assert b != [0]
    inv = pow(b[-1], -1, p)
    while a != [0] and len(a) >= len(b):
        offset = len(a) - len(b)
        q = a[-1]*inv % p
        for i, x in enumerate(b): a[i+offset] = (a[i+offset]-q*x) % p
        a = trim(a, p)
    return a


def gcd(a, b, p):
    while b != [0]: a, b = b, remainder(a, b, p)
    return scale(a, pow(a[-1], -1, p), p)


def powmod(a, k, f, p):
    out = [1]
    while k:
        if k & 1: out = remainder(times(out, a, p), f, p)
        a = remainder(times(a, a, p), f, p)
        k >>= 1
    return out


def at(a, x, p):
    out = 0
    for c in reversed(a): out = (out*x+c) % p
    return out


def resultant(a, b, p):
    """Euclidean identity; no matrix determinant or interpolation."""
    a, b = trim(a, p), trim(b, p)
    if a == [0] or b == [0]: return 0
    m, n = len(a)-1, len(b)-1
    if n == 0: return pow(b[0], m, p)
    r = remainder(a, b, p)
    if r == [0]: return 0
    return ((-1)**(m*n) * pow(b[-1], m-(len(r)-1), p)
            * resultant(b, r, p)) % p


def symbolic_K(u, v, numerator, denominator, p):
    """Direct polynomial transcription of K(u,v,num/den)*den^2."""
    uv = times(u, v, p)
    upv = plus(u, v, p)
    umv = plus(u, scale(v, -1, p), p)
    a = times(times(umv, umv, p), times(numerator, numerator, p), p)
    middle = plus(times(uv, upv, p), [14], p)
    b = scale(times(middle, times(numerator, denominator, p), p), -2, p)
    last = plus(times(uv, uv, p), scale(upv, -28, p), p)
    c = times(last, times(denominator, denominator, p), p)
    return plus(plus(a, b, p), c, p)


def independent_fg(x, d, e, p):
    numerator, denominator = [0, -56, 0, 0, 1], [28, 0, 0, 4]
    f = symbolic_K([x], [x+d], numerator, denominator, p)
    g = symbolic_K([0, 1], [e, 1], [at(numerator, x, p)], [at(denominator, x, p)], p)
    return f, g


def numeric_K(u, v, w, p):
    return ((u-v)**2*w*w - 2*(u*v*(u+v)+14)*w + (u*v)**2 - 28*(u+v)) % p


def duplication_x(x, p): return (x**4-56*x)*pow(4*(x**3+7), -1, p) % p


def audit_secp():
    report = json.loads((HERE/'r18_endomorphism_resultant.json').read_text())
    results = []
    beta = pow(2, (P-1)//3, P)
    assert beta != 1 and pow(beta, 3, P) == 1
    assert {(r['endomorphism_exponent'], r['source_integer_gap_sign'], r['target_integer_gap_sign']) for r in report['cases']} == {(k, a, b) for k in range(3) for a in (-1, 1) for b in (-1, 1)}
    for row in report['cases']:
        d, e = int(row['delta_source_mod_p']), int(row['delta_target_before_endomorphism_mod_p'])
        assert d == row['source_integer_gap_sign']*N % P
        assert e == row['target_integer_gap_sign']*N*pow(pow(beta,row['endomorphism_exponent'],P),-1,P) % P
        poly = list(map(int, row['resultant_coefficients_low_to_high']))
        assert 1 < len(poly) <= 81
        xs = list(range(81)) + [81, 82, 97, 257, N-1, N+1, P-1]
        xs += [int.from_bytes(hashlib.sha256(('independent resultant audit '+str(j)).encode()).digest(), 'big') % P for j in range(7)]
        xs += list(map(int, row['field_roots']))
        xs = sorted(set(xs))
        numeric_tests = 0
        for x in xs:
            f, g = independent_fg(x, d, e, P)
            expected = resultant(f, g, P)
            assert at(poly, x, P) == expected
            for y in (0, 1, 19, P-1):
                assert at(f, y, P) == numeric_K(x, x+d, duplication_x(y, P), P) * (4*(y**3+7))**2 % P
                assert at(g, y, P) == numeric_K(y, y+e, duplication_x(x, P), P) * (4*(x**3+7))**2 % P
                numeric_tests += 2
        frobenius = plus(powmod([0, 1], P, poly, P), [0, -1], P)
        factor = gcd(poly, frobenius, P)
        assert factor == list(map(int, row['linear_factor_product']))
        roots = list(map(int, row['field_roots']))
        reconstructed = [1]
        for root in roots: reconstructed = times(reconstructed, [-root, 1], P)
        assert reconstructed == factor and len(roots) == len(set(roots))
        admissible = []
        for x in roots:
            other = x + row['source_integer_gap_sign']*N
            if 0 < x < P and 0 < other < P and 0 < x % N < P-N and x % N == other % N:
                admissible.append(x)
        assert admissible == []
        results.append({'exponent':row['endomorphism_exponent'],
            'source_sign':row['source_integer_gap_sign'], 'target_sign':row['target_integer_gap_sign'],
            'independent_Euclidean_resultants':len(xs), 'direct_K_evaluations':numeric_tests,
            'independent_Frobenius_gcd_matches':True, 'root_product_matches_gcd':True,
            'field_roots':len(roots), 'exact_source_branch_roots':len(admissible)})
    return results


def audit_toy(p, n, generator):
    def add(a, b):
        if a is None: return b
        if b is None: return a
        x, y = a
        u, v = b
        if x == u and (y+v) % p == 0: return None
        slope = (3*x*x*pow(2*y, -1, p) if a == b else (v-y)*pow(u-x, -1, p)) % p
        nx = (slope*slope-x-u) % p
        return nx, (slope*(x-nx)-y) % p
    points = [None]
    for _ in range(1, n): points.append(add(points[-1], generator))
    assert add(points[-1], generator) is None
    assert set(points[1:]) == {(x, y) for x in range(p) for y in range(p) if (y*y-x*x*x-7) % p == 0}
    assert len(set(points)) == n
    beta = next(x for x in range(2, p) if pow(x, 3, p) == 1)
    lam = points.index((beta*generator[0] % p, generator[1]))
    assert pow(lam, 3, n) == 1 and lam != 1
    slopes = {(sign*pow(lam, k, n)) % n: k for k in range(3) for sign in (-1, 1)}
    assert len(slopes) == 6
    roots = {r:[k for k in range(1, n) if points[k][0] % n == r] for r in range(1, p-n)}
    roots = {r:ks for r, ks in roots.items() if len(ks) == 4}
    tested, hits, equations = 0, [], 0
    all_maps, other_slope_controls = 0, []
    for ri, source in roots.items():
        for triple in combinations(source, 3):
            pair = next((a, b) for a, b in combinations(triple, 2) if (a+b) % n == 0)
            B = next(k for k in triple if k not in pair)
            for slope in range(1, n):
                exponent = slopes.get(slope)
                for shift in range(1, n):
                    all_maps += 1
                    tested += exponent is not None
                    target = [(slope*k+shift) % n for k in triple]
                    if 0 in target: continue
                    rhos = {points[k][0] % n for k in target}
                    if len(rhos) != 1 or 0 in rhos: continue
                    A = next(k for k in pair if (slope*(k+B)+2*shift) % n == 0)
                    C, D = (A-B)*pow(2, -1, n) % n, (-3*A-B)*pow(2, -1, n) % n
                    assert set(target) == {slope*C % n, -slope*C % n, slope*D % n}
                    x, xb, y, yd = (points[k][0] for k in (A, B, C, D))
                    dx = xb-x
                    assert abs(dx) == n
                    if exponent is not None:
                        dy = (pow(beta, exponent, p)*yd % p)-(pow(beta, exponent, p)*y % p)
                        assert abs(dy) == n
                        e = dy*pow(pow(beta, exponent, p), -1, p) % p
                    else:
                        dy = points[slope*D % n][0]-points[slope*C % n][0]
                        assert abs(dy) == n
                        e = (yd-y) % p
                    f, g = independent_fg(x, dx, e, p)
                    assert at(f, y, p) == at(g, y, p) == 0
                    assert numeric_K(x, xb, points[2*C % n][0], p) == 0
                    assert numeric_K(y, yd, points[2*A % n][0], p) == 0
                    assert points[2*A % n][0] == duplication_x(x, p)
                    assert points[2*C % n][0] == duplication_x(y, p)
                    equations += 2
                    target_list = hits if exponent is not None else other_slope_controls
                    target_list.append({'source_r':ri, 'target_r':next(iter(rhos)), 'source_triple':triple,
                        'slope':slope, 'shift':shift, 'exponent':exponent, 'A':A, 'B':B, 'C':C, 'D':D,
                        'source_gap':dx, 'target_gap':dy})
    return {'p':p, 'n':n, 'generator':generator, 'beta':beta, 'lambda':lam,
            'four_root_sets':len(roots), 'complete_affine_maps_tested':tested,
            'nonzero_translation_three_root_matches':len(hits),
            'necessary_K_equations_checked':equations, 'matches':hits,
            'all_nonzero_slope_translation_maps_tested':all_maps,
            'non_endomorphism_positive_controls':other_slope_controls}


def main():
    secp = audit_secp()
    small = [audit_toy(43,31,(2,12)), audit_toy(79,67,(1,18)),
             audit_toy(163,139,(2,34)), audit_toy(211,199,(3,33))]
    result = {'evidence':'locally-reproduced', 'deployment_class':'unclassified',
        'scope':'Independent host polynomial and finite-group audit; no Script or Core execution.',
        'independence':'No construction imports. Euclidean resultants replace Sylvester determinants; polynomial coefficients use direct K composition; Frobenius gcd and curve enumeration are independently implemented.',
        'secp256k1_cases':secp, 'toy_complete_cases':small, 'all_assertions_passed':True,
        'no_arbitrary_slope_impossibility_claim':True}
    (HERE/'r18_resultant_audit.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'cases':len(secp), 'independent_resultants':sum(r['independent_Euclidean_resultants'] for r in secp),
        'toy_counts':[{k:r[k] for k in ('p','n','complete_affine_maps_tested','nonzero_translation_three_root_matches')} for r in small]}, indent=2))


if __name__ == '__main__': main()
