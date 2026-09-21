#!/usr/bin/env python3
"""Reproduce the direct scalar-linear binary-label rank boundary.

Small exact rational vector examples and one secp256k1 commitment/KDF fixture.
No Script, Bitcoin execution, field-library tests, or full garbling is run.
"""
from fractions import Fraction
from hashlib import sha256
from itertools import product
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE.parent/'covenant-2026-09-17'))
from legacy_same_signature_counterexample import N, mul


def rank(rows):
    if not rows:
        return 0
    a = [[Fraction(x) for x in row] for row in rows]
    width = len(a[0])
    assert all(len(row) == width for row in a)
    pivot = 0
    for column in range(width):
        row = next((j for j in range(pivot, len(a)) if a[j][column]), None)
        if row is None:
            continue
        a[pivot], a[row] = a[row], a[pivot]
        divisor = a[pivot][column]
        a[pivot] = [x/divisor for x in a[pivot]]
        for j in range(len(a)):
            if j == pivot:
                continue
            multiple = a[j][column]
            a[j] = [x-multiple*y for x,y in zip(a[j],a[pivot])]
        pivot += 1
        if pivot == len(a):
            break
    return pivot


def basis(width, i):
    return [int(j == i) for j in range(width)]


def tight_examples():
    rows = []
    for bits in range(1, 9):
        # L_i^b = A_i + b*Delta. The k+1 hidden forms are independent.
        labels = [[basis(bits+1, i),
                   [int(j == i or j == bits) for j in range(bits+1)]]
                  for i in range(bits)]
        messages = alternatives = 0
        for message in product((0,1), repeat=bits):
            selected = [labels[i][value] for i,value in enumerate(message)]
            assert rank(selected) == bits
            for i,value in enumerate(message):
                # An opposite form is outside the entire selected-label span.
                assert rank(selected+[labels[i][1-value]]) == bits+1
                # Fewer than k selected forms cannot span all k outputs.
                assert rank(selected[:i]+selected[i+1:]) == bits-1
                alternatives += 1
            messages += 1
        rows.append(dict(bits=bits, messages=messages,
                         opposite_label_checks=alternatives,
                         selected_rank=bits, secret_dimension=bits+1))
    return rows


def dependent_examples():
    rows = []
    for bits in range(2,9):
        width = 2*bits
        zero = [basis(width,i) for i in range(bits-1)]
        zero.append([int(i < bits-1) for i in range(width)])
        # No common Delta is needed for the failure: use separate one labels.
        one = [basis(width,bits+i) for i in range(bits)]
        initial_rank = rank(zero)
        selected = zero[:-1]+[one[-1]]  # Message 00...01.
        recovered_opposite = [sum(row[i] for row in selected[:-1]) for i in range(width)]
        assert recovered_opposite == zero[-1]
        assert rank(selected+[zero[-1]]) == rank(selected)
        assert initial_rank == bits-1
        # The same disclosure evaluates both 00...01 and 00...00.
        rows.append(dict(bits=bits, dependent_assignment='0'*bits,
            opened_message='0'*(bits-1)+'1', alternative_message='0'*bits,
            dependent_selected_rank=initial_rank, opposite_label_recovered=True,
            common_offset_required=False))
    return rows


def encoded(point):
    return (bytes([2+point[1] % 2])+point[0].to_bytes(32,'big')).hex()


def commitment_fixture():
    # Public deterministic fixtures, never private application material.
    scalar = lambda tag: int.from_bytes(sha256(tag.encode()).digest(),'big') % N
    a,b,delta = [scalar('binary-linear-label-rank/'+tag) for tag in ('A','B','Delta')]
    zero = [a,b,(a+b) % N]
    labels = [[x,(x+delta) % N] for x in zero]
    assert all(x for pair in labels for x in pair)
    public_points = [[encoded(mul(x)) for x in pair] for pair in labels]
    selected = [labels[0][0],labels[1][0],labels[2][1]]
    # Recovery receives only the three selected scalars, not private state.
    other_last = (selected[0]+selected[1]) % N
    recovered_delta = (selected[2]-other_last) % N
    recovered = [[selected[0],(selected[0]+recovered_delta) % N],
                 [selected[1],(selected[1]+recovered_delta) % N],
                 [other_last,selected[2]]]
    assert recovered == labels
    assert [[encoded(mul(x)) for x in pair] for pair in recovered] == public_points
    kdf = lambda x: sha256(b'fixture-label/'+x.to_bytes(32,'big')).digest()[:16].hex()
    assert kdf(other_last) == kdf(labels[2][0])
    return dict(opened_message='001', alternative_message='000',
        public_label_points=public_points,
        opening_scalars=[f'{x:064x}' for x in selected],
        recovered_opposite_scalar=f'{other_last:064x}',
        recovered_opposite_label=kdf(other_last),
        all_six_labels_recovered=True,
        scope='Public scalar-linear point commitments and post-recovery KDF; no native spend or garbled circuit.')


def main():
    tight, dependent = tight_examples(), dependent_examples()
    report = dict(evidence='locally-reproduced', deployment='unclassified',
        scope=__doc__, exact_vector_field='rationals; theorem is over any field',
        tight_examples=tight, dependent_examples=dependent,
        messages_checked=sum(x['messages'] for x in tight),
        opposite_label_checks=sum(x['opposite_label_checks'] for x in tight),
        commitment_fixture=commitment_fixture(),
        restricted_legacy_bound=dict(message_bits=2048,
            minimum_independent_scalar_openings=2048,
            guarded_signature_minimum_bytes=58, direct_push_bytes=1,
            signature_push_bytes_only=2048*59,
            scope='One scalar per guarded legacy sum-key signature, direct scalar-linear binary-label delivery; no witness discount; all keys/checks/transactions free.'),
        incremental_onchain_bytes=0, incremental_onchain_hint_items=0,
        sha256={str(p.relative_to(ROOT)):sha256(p.read_bytes()).hexdigest()
                for p in (Path(__file__), HERE.parent/'covenant-2026-09-17/legacy_same_signature_counterexample.py')})
    (HERE/'binary-linear-label-rank.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('messages_checked','opposite_label_checks','restricted_legacy_bound')},indent=2))


if __name__ == '__main__':
    main()
