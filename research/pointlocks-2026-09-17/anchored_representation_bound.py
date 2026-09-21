#!/usr/bin/env python3
"""Optimistic representation bound for explicit HASH160-tau anchored tables.

This does not cover other representations or label encodings. Every selected
point has tau40, a compressed recovered key33, and d exact60-byte signatures.
Everything receives witness discount; every opcode and transaction is free.
"""
import json
import math
from pathlib import Path


def bound(rounds):
    a, b = 21, 75+61*rounds
    low, high = 0.0, 10000.0
    for _ in range(100):
        middle = (low+high)/2
        if 2**(-a/middle)+2**(-(a+b)/middle) < 1:
            low = middle
        else:
            high = middle
    rate = (low+high)/2
    p = 2**(-(a+b)/rate)
    h = -p*math.log2(p)-(1-p)*math.log2(1-p)
    assert abs(rate-(a+b*p)/h) < 1e-9
    return dict(rounds=rounds, fixed_bytes_per_candidate=a, selected_bytes_per_label=b,
                optimizing_selection_density=p, bytes_per_message_bit=rate,
                optimistic_total_vbytes=2048*rate/4)


def main():
    report = dict(scope=__doc__, evidence='inspected', deployment='unclassified',
                  method='Weighted binary entropy bound, computed by 100 bisection steps. Derivation is in anchored-rounds-limits.md.',
                  rows=[bound(d) for d in range(3,17)])
    Path(__file__).with_suffix('.json').write_text(json.dumps(report,indent=2)+'\n')
    for row in report['rows']:
        print(row['rounds'],f'{row["optimistic_total_vbytes"]:.2f}')


if __name__ == '__main__':
    main()
