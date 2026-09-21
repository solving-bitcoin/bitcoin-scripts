#!/usr/bin/env python3
"""Exact tiny-random-function audit of distinct-word nonce independence."""
from fractions import Fraction
import itertools
import json
import math
from pathlib import Path

# A root is outside the internal-state domain. Its first hash is uniform.
# Subsequent same-hash iterations use one shared random function on that domain.
k = 4
count = 0
joint = 0
bad = 0
joint_bad = 0
for table in itertools.product(range(k), repeat=k):
    for first in range(k):
        second = table[first]
        third = table[second]
        event = first < 2 and third < 2
        collision = first == second  # third evaluation reuses the second's input
        count += 1
        joint += event
        bad += collision
        joint_bad += event and collision
report = {
    'evidence': 'locally-reproduced',
    'deployment': 'unclassified',
    'scope': 'Exact reduced random-function model; no Bitcoin Script executed.',
    'domain_size': k,
    'exhaustive_assignments': count,
    'words': ['s', 'sss'],
    'gate': 'output < 2',
    'actual_joint_probability': str(Fraction(joint, count)),
    'independent_joint_probability': '1/4',
    'internal_collision_probability': str(Fraction(bad, count)),
    'joint_and_internal_collision_probability': str(Fraction(joint_bad, count)),
    'union_bound_at_2pow64_160bit_states': '2^-33 (strict upper bound for output-output collisions)',
    'union_bound_at_2pow68_160bit_states': '2^-25 (strict upper bound for output-output collisions)',
    'notes': [
        'Distinct hash words are not exactly independent in a finite random-function model.',
        'These tiny-domain discrepancies do not estimate attacks against full-width Bitcoin hashes.',
        'A coupling to fresh independent samples differs only after a repeated internal state/query input.',
        'External oracle queries and the native-transaction digest derivation require additional accounting.',
    ],
}
assert Fraction(joint, count) != Fraction(1, 4)
assert Fraction(bad, count) == Fraction(1, 4)
out = Path(__file__).with_suffix('.json')
out.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
