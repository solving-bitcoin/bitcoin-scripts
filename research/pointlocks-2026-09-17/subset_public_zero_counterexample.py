#!/usr/bin/env python3
"""Reject public zero labels plus a released one label under one free-XOR delta."""
import hashlib
import json
from pathlib import Path


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def main():
    def h(value):
        return hashlib.sha256(value).digest()[:16]
    delta = h(b'public-zero-shortcut/delta')
    zeros = [h(b'public-zero-shortcut/zero/'+bytes([i])) for i in range(50)]
    ones = [xor(z, delta) for z in zeros]
    recovered = xor(zeros[7], ones[7])
    assert recovered == delta
    assert all(xor(z, recovered) == one for z, one in zip(zeros, ones))
    report = dict(evidence='locally-reproduced', deployment='unclassified',
        scope='Algebraic free-XOR label counterexample only; no Script execution or general garbling impossibility claim.',
        public_zero_labels=50, released_one_labels=1, all_one_labels_recovered=50,
        all_expectations_met=True)
    Path(__file__).with_name('subset-public-zero-counterexample.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
