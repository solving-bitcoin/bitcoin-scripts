#!/usr/bin/env python3
"""Exact certificates for two proposed ECDSA orbit-binding graphs."""
import json
from pathlib import Path

from r11_endomorphism import BETA, LAMBDA, G, N, P, GAP, add, mul, lift, neg
from r9_four_roots import polynomial_powmod, polynomial_subtract, polynomial_gcd
from r9_recovery_audit import mpow, rank

HERE = Path(__file__).resolve().parent


def cubic_certificates():
    rows = []
    for sign in (-1, 1):
        polynomial = [28, 0, sign*3*N % P, 4]
        remainder = polynomial_subtract(polynomial_powmod([0, 1], P, polynomial), [0, 1])
        divisor = polynomial_gcd(polynomial, remainder)
        assert divisor == [1]
        # Independent matrix-power certificate: multiplication by X in Fp[X]/F.
        inv = pow(4, -1, P)
        matrix = [[0, 0, -polynomial[0]*inv % P],
                  [1, 0, 0], [0, 1, -polynomial[2]*inv % P]]
        powered = mpow(matrix, P)
        difference = [[(x-y) % P for x, y in zip(ra, rb)] for ra, rb in zip(powered, matrix)]
        matrix_rank, rref = rank(difference)
        assert matrix_rank == 3
        rows.append({'sign': sign, 'polynomial_low_to_high': list(map(str, polynomial)),
                     'X_to_p_minus_X_remainder': list(map(str, remainder)),
                     'polynomial_gcd': divisor, 'field_root_count': 0,
                     'independent_multiplication_matrix': [list(map(str, row)) for row in matrix],
                     'independent_difference_rank': matrix_rank, 'difference_rref': rref})
    return rows


def point_formula_vectors():
    delta = (LAMBDA-LAMBDA*LAMBDA) % N
    assert delta*delta % N == N-3
    starts = [mul(k) for k in (1, 2, 7, 19)] + [lift(2), lift(N+2), lift(4), lift(N+4)]
    vectors = []
    for point in starts:
        assert point is not None and point[0]
        result = mul(delta, point)
        assert result == add(mul(LAMBDA, point), neg(mul(LAMBDA*LAMBDA, point)))
        formula = -(point[0]**3+28)*pow(3*point[0]*point[0], -1, P) % P
        assert result[0] == formula
        assert (formula-point[0]) % P not in (N, (-N) % P)
        vectors.append({'input': list(map(str, point)), 'delta_times_point': list(map(str, result)),
                        'formula_x': str(formula)})
    return vectors


def four_root_transport():
    rows = []
    for r in (2, 4, 6, 16):
        assert r < GAP and lift(r) is not None and lift(r+N) is not None
        roots = [q for x in (r, r+N) for q in (lift(x), neg(lift(x)))]
        assert len(set(roots)) == 4
        for exponent in (1, 2):
            beta, scalar = pow(BETA, exponent, P), pow(LAMBDA, exponent, N)
            transformed = [mul(scalar, root) for root in roots]
            assert (beta*N) % P not in (N, (-N) % P)
            xs = sorted(set(q[0] for q in transformed))
            assert len(xs) == 2 and xs[1]-xs[0] != N
            rows.append({'r': str(r), 'exponent': exponent,
                         'transformed_distinct_x': list(map(str, xs)),
                         'integer_x_gap': str(xs[1]-xs[0]),
                         'same_ECDSA_r_after_transport': False})
    return rows


def main():
    result = {'question': 'Can affine orbit keys or four-common-key graphs enforce a nontrivial ECDSA nonce orbit?',
              'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
              'affine_key_orbit_cubic_certificates': cubic_certificates(),
              'delta_point_formula_vectors': point_formula_vectors(),
              'four_root_endomorphism_transport_vectors': four_root_transport(),
              'scope': 'Two specific graph templates. No exclusion of all native predicates; no Script or Core execution.'}
    output = HERE/'r14_orbit_binding.json'
    output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'output': str(output), 'cubics_without_any_field_root': 2,
                      'independent_matrix_certificates': 2, 'point_formula_vectors': 8,
                      'four_root_transport_vectors': 8}, indent=2))


if __name__ == '__main__':
    main()
