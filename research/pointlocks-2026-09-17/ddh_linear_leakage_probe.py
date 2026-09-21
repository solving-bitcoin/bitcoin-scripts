#!/usr/bin/env python3
"""Scoped algebraic leakage tests for the local DDH batch-select interface.

Public deterministic fixtures, no Bitcoin Script or setup benchmark. The
extractor receives the public table, one opening, and the declared extra
linear disclosure; no hidden coefficients or row randomizers.
"""
import hashlib
import itertools
import json
from functools import lru_cache
from pathlib import Path

import core_check  # Installs the existing local curve helper's import path.
from legacy_same_signature_counterexample import N, P, G, add, mul as raw_mul

HERE = Path(__file__).resolve().parent
DOMAIN = b'bitcoin-lab/ddh-linear-leakage/v1/PUBLIC-FIXTURE/'


@lru_cache(maxsize=8192)
def mul(k, point=G):
    return raw_mul(k % N, point)


def sub(a, b):
    return add(a, None if b is None else (b[0], -b[1] % P))


def scalar(name):
    return int.from_bytes(hashlib.sha256(DOMAIN + name.encode()).digest(), 'big') % (N-1) + 1


def transparent_row(name):
    """Public hash-and-lift base. No scalar relative to G is generated."""
    tag = DOMAIN + b'row-base/' + name.encode()
    parity = hashlib.sha256(tag + b'/parity').digest()[0] & 1
    for counter in range(256):
        x = int.from_bytes(hashlib.sha256(tag + counter.to_bytes(4, 'big')).digest(), 'big')
        if x >= P:
            continue
        square = (x*x*x+7) % P
        y = pow(square, (P+1)//4, P)
        if y*y % P == square:
            return x, y if y % 2 == parity else P-y
    raise ValueError('transparent row counter exhausted')


def encode(label):
    assert len(label) == 16
    for counter in range(65536):
        x = (int.from_bytes(label, 'big') << 16) + counter
        y = pow((x*x*x+7) % P, (P+1)//4, P)
        if y*y % P == (x*x*x+7) % P:
            return x, y if y % 2 == 0 else P-y
    raise ValueError('label embedding counter exhausted')


def decode(point):
    if point is None or point[1] % 2 or point[0] >> 144:
        return None
    label = (point[0] >> 16).to_bytes(16, 'big')
    return label if encode(label) == point else None


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def hash_label(label):
    return hashlib.sha256(label).hexdigest()


def dot(a, k, modulus=N):
    return sum(x*y for x, y in zip(a, k)) % modulus


def setup(width, dependent_rows=False):
    keys = [scalar(f'key/{i}') for i in range(width+1)]
    rows = [transparent_row(str(i)) for i in range(width)]
    if dependent_rows:
        assert width == 3
        rows[2] = add(mul(7), add(mul(3, rows[0]), mul(5, rows[1])))
    delta_raw = scalar('delta').to_bytes(32, 'big')[:16]
    delta = (int.from_bytes(delta_raw, 'big') | 1).to_bytes(16, 'big')
    labels = []
    for i in range(width):
        zero = scalar(f'label/{i}').to_bytes(32, 'big')[:16]
        labels.append([zero, xor(zero, delta)])
    points = [[encode(l) for l in pair] for pair in labels]
    offset = [add(points[i][0], mul(keys[0], rows[i])) for i in range(width)]
    matrix = [[add(mul(keys[j+1], rows[i]), sub(points[i][1], points[i][0]) if i == j else None)
               for j in range(width)] for i in range(width)]
    public = dict(key_points=[mul(k) for k in keys], rows=rows, offset=offset,
                  matrix=matrix, hashes=[[hash_label(l) for l in pair] for pair in labels])
    return public, keys, labels


def open_labels(public, bits, key):
    width = len(bits)
    target = public['key_points'][0]
    for j, bit in enumerate(bits):
        if bit:
            target = add(target, public['key_points'][j+1])
    assert target == mul(key)
    out = []
    for i in range(width):
        c = public['offset'][i]
        for j, bit in enumerate(bits):
            if bit:
                c = add(c, public['matrix'][i][j])
        label = decode(sub(c, mul(key, public['rows'][i])))
        assert label is not None and hash_label(label) == public['hashes'][i][bits[i]]
        out.append(label)
    return out


def finish_recovery(public, bits, delivered, row, zero_point, one_point):
    zero, one = decode(zero_point), decode(one_point)
    if zero is None or one is None:
        return None
    if [hash_label(zero), hash_label(one)] != public['hashes'][row]:
        return None
    if [zero, one][bits[row]] != delivered[row]:
        return None
    delta = xor(zero, one)
    alternatives = [xor(label, delta) for label in delivered]
    if any(hash_label(label) != public['hashes'][j][1-bits[j]] for j, label in enumerate(alternatives)):
        return None
    return dict(row=row, delta=delta.hex(), alternatives=[label.hex() for label in alternatives])


def recover_linear_disclosure(public, bits, key, delivered, coefficients, disclosure):
    """Public-data attack; returns None for the proportional-leak boundary."""
    a = [x % N for x in coefficients]
    assert len(a) == len(bits)+1
    i = next((i for i, bit in enumerate(bits) if (a[i+1]-a[0]*bit) % N), None)
    if i is None:
        return None
    u = mul(key, public['rows'][i])
    v = mul(disclosure, public['rows'][i])
    for j, bit in enumerate(bits):
        if i != j:
            u = sub(u, mul(bit, public['matrix'][i][j]))
            v = sub(v, mul(a[j+1], public['matrix'][i][j]))
    denominator = (a[i+1]-a[0]*bits[i]) % N
    mask_i = mul(pow(denominator, -1, N), sub(v, mul(a[0], u)))
    mask_zero = sub(u, mul(bits[i], mask_i))
    zero = sub(public['offset'][i], mask_zero)
    one = add(zero, sub(public['matrix'][i][i], mask_i))
    return finish_recovery(public, bits, delivered, i, zero, one)


def recover_public_row_relation(public, bits, delivered, row, constant, other_rows):
    """Ri = constant*G + sum coefficient*Rj, j != i; all inputs public."""
    checked_row = mul(constant)
    mask = mul(constant, public['key_points'][row+1])
    for j, coefficient in other_rows:
        assert j != row
        checked_row = add(checked_row, mul(coefficient, public['rows'][j]))
        mask = add(mask, mul(coefficient, public['matrix'][j][row]))
    assert checked_row == public['rows'][row]
    difference = sub(public['matrix'][row][row], mask)
    opened = encode(delivered[row])
    zero = sub(opened, difference) if bits[row] else opened
    return finish_recovery(public, bits, delivered, row, zero, add(zero, difference))


def main():
    # Exact finite-field exhaustiveness for the coefficient criterion. This is
    # separate from the actual secp256k1 checks and is not a privacy proof.
    coefficient_checks = 0
    for bits in itertools.product((0, 1), repeat=3):
        c = (1, *bits)
        for a in itertools.product(range(5), repeat=4):
            proportional = all((a[i]-a[0]*c[i]) % 5 == 0 for i in range(4))
            determinant_exists = any((a[i+1]-a[0]*bits[i]) % 5 != 0 for i in range(3))
            assert determinant_exists != proportional
            coefficient_checks += 1
    public, keys, labels = setup(3)
    assert public['rows'] == [transparent_row(str(i)) for i in range(3)]
    coefficient_vectors = [[int(i == j) for i in range(4)] for j in range(4)]
    coefficient_vectors += [[1, 3, 5, 7], [N-1, 0, 2, N-3]]
    curve_cases, proportional_controls, bad_value_controls = [], 0, 0
    for bits in itertools.product((0, 1), repeat=3):
        c = (1, *bits)
        key = dot(c, keys)
        delivered = open_labels(public, bits, key)
        assert delivered == [labels[i][bits[i]] for i in range(3)]
        for a in coefficient_vectors:
            value = dot(a, keys)
            got = recover_linear_disclosure(public, bits, key, delivered, a, value)
            nonproportional = any((a[i+1]-a[0]*bits[i]) % N for i in range(3))
            if nonproportional:
                assert got is not None
                assert got['alternatives'] == [labels[i][1-bits[i]].hex() for i in range(3)]
                curve_cases.append(dict(bits=list(bits), coefficients=[str(x) for x in a],
                                        recovery=got, all_alternative_labels_recovered=True))
            else:
                assert got is None
                proportional_controls += 1
        for factor in (0, 1, 7, N-1):
            a = [factor*x % N for x in c]
            assert recover_linear_disclosure(public, bits, key, delivered, a, factor*key % N) is None
            proportional_controls += 1
        # e1 always exposes a nonproportional direction; a wrong value must
        # not be reported as an extraction of the committed label pair.
        a = [0, 1, 0, 0]
        assert recover_linear_disclosure(public, bits, key, delivered, a, (keys[1]+1) % N) is None
        bad_value_controls += 1
    related, related_keys, related_labels = setup(3, dependent_rows=True)
    row_relation_cases = []
    for bits in itertools.product((0, 1), repeat=3):
        key = dot((1, *bits), related_keys)
        delivered = open_labels(related, bits, key)
        got = recover_public_row_relation(related, bits, delivered, 2, 7, [(0, 3), (1, 5)])
        assert got['alternatives'] == [related_labels[i][1-bits[i]].hex() for i in range(3)]
        row_relation_cases.append(dict(bits=list(bits), recovery=got))
    result = dict(evidence='locally-reproduced', deployment='unclassified', scope=__doc__,
        coefficient_criterion=dict(prime=5, bits=3, checked_vectors=coefficient_checks),
        secp256k1_nonproportional_cases=curve_cases,
        proportional_controls=proportional_controls, wrong_disclosure_controls=bad_value_controls,
        public_row_relation=dict(equation='R2=7G+3R0+5R1', cases=row_relation_cases),
        honest_row_generation=dict(method='Public domain-separated SHA256 hash-and-lift with independently hashed parity; 256-counter bound.',
            discrete_logarithms_not_generated=True,
            bases=[dict(x=f'{r[0]:064x}', y=f'{r[1]:064x}') for r in public['rows']],
            caveat='The deliberate affine-row control is outside this fixed transparent-row profile. No theorem about the discrete-log hardness of the derived points is claimed.'),
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        curve_helper_sha256=hashlib.sha256((HERE.parent/'covenant-2026-09-17/legacy_same_signature_counterexample.py').read_bytes()).hexdigest(),
        existing_ddh_source_sha256=hashlib.sha256((HERE.parents[1]/'examples/pointlock_ddh_batch_select_probe.rs').read_bytes()).hexdigest(),
        caveats=['Applies to the displayed local ciphertext layout, not all DDH batch-select schemes.',
                 'Rank-one boundary only means this extraction does not apply; it is not a full security proof.',
                 'No Bitcoin predicate, transaction, native extraction, or public setup verification supplied.',
                 'No change to prior benchmark sources or reported timings.'])
    (HERE/'ddh-linear-leakage.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(dict(coefficient_checks=coefficient_checks,
        full_curve_recoveries=len(curve_cases), proportional_controls=proportional_controls,
        wrong_value_rejections=bad_value_controls, affine_row_relation_recoveries=len(row_relation_cases)), indent=2))


if __name__ == '__main__':
    main()
