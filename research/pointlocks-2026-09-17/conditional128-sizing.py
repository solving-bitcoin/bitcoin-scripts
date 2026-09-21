#!/usr/bin/env python3
"""Conditional 1024-bit payload sizing; this does not compress arbitrary bytes."""
import hashlib
import importlib.util
import itertools
import json
import random
import sys
from collections import Counter
from math import comb
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('conditional_encoding', HERE / 'encoding-optimization.py')
encoding = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = encoding
spec.loader.exec_module(encoding)
encoding.BITS = 1024
encoding.TARGET = 1 << 1024
encoding.min_count.__defaults__ = (encoding.TARGET,)
options = [r for r in encoding.layouts() if r.name.startswith('common-g-hash-lookup')]

# A known feasible upper bound. The DP below permits any mixture of the
# measured layouts, including mixtures with more than two different rows.
upper_counts = Counter({next(r for r in options if (r.n, r.t) == (17, 4)): 87,
                        next(r for r in options if (r.n, r.t) == (16, 5)): 4})
upper_weight = sum(r.pair_weight * count for r, count in upper_counts.items())
capacities = [0] * (upper_weight + 1)
previous = [None] * (upper_weight + 1)
capacities[0] = 1
for cost in range(1, upper_weight + 1):
    best = 0
    for j, row in enumerate(options):
        if cost >= row.pair_weight and capacities[cost - row.pair_weight]:
            capacity = capacities[cost - row.pair_weight] * row.radix
            if capacity > best:
                best = capacity
                previous[cost] = j
    capacities[cost] = best
    if best >= encoding.TARGET:
        counts = Counter()
        remaining = cost
        while remaining:
            row = options[previous[remaining]]
            counts[row] += 1
            remaining -= row.pair_weight
        break
else:
    raise AssertionError('known feasible upper bound not reached')

encoding.verify_serialization(counts)
result = encoding.report(counts)
assert result['two_tx_vbytes'] == 92853
assert {(r.n, r.t): count for r, count in counts.items()} == {(17, 4): 89, (14, 3): 2, (15, 3): 1}
parameters = [{'n': 17, 't': 4}] * 89 + [{'n': 14, 't': 3}] * 2 + [{'n': 15, 't': 3}]

def encode(value):
    selections = []
    digits = []
    for p in reversed(parameters):
        value, digit = divmod(value, comb(p['n'], p['t']))
        selections.append(list(tuple(itertools.combinations(range(p['n']), p['t']))[digit]))
        digits.append(digit)
    assert value == 0
    return list(reversed(selections)), list(reversed(digits))

def decode(selections):
    value = 0
    for p, selected in zip(parameters, selections):
        digit = tuple(itertools.combinations(range(p['n']), p['t'])).index(tuple(selected))
        value = value * comb(p['n'], p['t']) + digit
    return value

rng = random.Random(0xB17B3)
values = [rng.getrandbits(1024) for _ in range(8)]
for value in [0, 1, encoding.TARGET - 1] + values:
    assert decode(encode(value)[0]) == value
selections, digits = encode(values[0])
selection = dict(seed='0xB17B3', proof_hex=values[0].to_bytes(128, 'big').hex(),
                 scope='Conditional synthetic 128-byte payload, not an actual Groth16 proof.',
                 global_revelations=365, pool_count=92, pool_parameters=parameters,
                 selections=selections, digits=digits,
                 codec_order='Big-endian mixed radix; lexicographic subset rank; funding-output order.')
(HERE / 'conditional128-publication-selection.json').write_text(json.dumps(selection, indent=2) + '\n')
report = dict(payload_bits=1024, evidence='locally-reproduced', deployment_class='unclassified',
              method='Exact integer dynamic programming maximizing product of binomial radices at every total pair weight; all mixtures of recorded fixed common-G HASH160 lookup pools.',
              pair_weight=cost, result=result,
              scope='Conditional 128-byte capacity. Does not satisfy arbitrary 256-byte publication.',
              source_metrics_sha256=hashlib.sha256((HERE / 'sum-lookup-vectors.json').read_bytes()).hexdigest(),
              layouts=[dict(row.__dict__, count=count) for row, count in counts.items()],
              codec_roundtrips=11, worst_case_serialization_checked=True)
(HERE / 'conditional128-sizing.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
