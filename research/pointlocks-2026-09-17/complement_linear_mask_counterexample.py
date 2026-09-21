#!/usr/bin/env python3
"""Public affine scalar masks are not a safe substitute for secret PRF pads.

Bounded construction counterexample, not an impossibility theorem for all
algebraic label-delivery protocols. Every secret is a public test fixture.
"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def scalar(tag):
    return int.from_bytes(hashlib.sha256(('complement-affine-mask-v1/' + tag).encode()).digest(), 'big') % ORDER


def solve(rows, width):
    matrix = [r[:] for r in rows]
    pivots = []
    for col in range(width):
        pivot = next((i for i in range(len(pivots), len(matrix)) if matrix[i][col]), None)
        if pivot is None:
            continue
        i = len(pivots)
        matrix[i], matrix[pivot] = matrix[pivot], matrix[i]
        factor = pow(matrix[i][col], -1, ORDER)
        matrix[i] = [(v * factor) % ORDER for v in matrix[i]]
        for j in range(len(matrix)):
            if j != i and matrix[j][col]:
                factor = matrix[j][col]
                matrix[j] = [(a - factor * b) % ORDER for a, b in zip(matrix[j], matrix[i])]
        pivots.append(col)
    assert all(any(row[:width]) or row[width] == 0 for row in matrix)
    if len(pivots) != width:
        return len(pivots), None
    result = [0] * width
    for i, col in enumerate(pivots):
        result[col] = matrix[i][width]
    return len(pivots), result


def main():
    n, t = 8, 4
    secrets = [scalar(f'point-scalar/{i}') for i in range(n)]
    coefficients = [[scalar(f'polynomial/{j}/{k}') for k in range(t)] for j in range(n)]
    private = secrets + [v for row in coefficients for v in row]
    width = len(private)
    equations = []
    for i in range(n):
        for j in range(n):
            if i == j:
                continue
            alpha = scalar(f'public-mask/{i}/{j}')
            row = [0] * width
            row[i] = alpha
            for k in range(t):
                row[n + j * t + k] = pow(i + 1, k, ORDER)
            ciphertext = sum(a * b for a, b in zip(row, private)) % ORDER
            equations.append(row + [ciphertext])
    # Recovery has only the public matrix and public scalar ciphertexts.
    rank, recovered = solve(equations, width)
    assert recovered == private
    output = dict(evidence='locally-reproduced', deployment='unclassified', n=n, t=t,
                  public_scalar_equations=len(equations), unknowns=width, rank=rank,
                  recovered_point_scalars=n, recovered_polynomial_coefficients=n*t,
                  all_secrets_recovered_from_public_equations=True,
                  scope='Specific publicly chosen affine-mask construction over the secp256k1 scalar field. No curve attack or universal impossibility claim.',
                  source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    (HERE/'complement-linear-mask-counterexample.json').write_text(json.dumps(output, indent=2)+'\n')
    print(json.dumps(output, indent=2))


if __name__ == '__main__':
    main()
