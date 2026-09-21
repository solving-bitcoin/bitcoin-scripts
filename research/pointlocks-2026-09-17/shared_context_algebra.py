#!/usr/bin/env python3
"""Same-digest anchor/short-check extraction for signed GLV nonce relations.

Assigned algebraic digests only, not Bitcoin hash preimages or an all-nonce
proof. The independent native selector report tests actual BIP143 contexts.
"""
import hashlib
import json
from pathlib import Path
import unittest

from anchored_extraction import der, extract, fixture
from legacy_same_signature_counterexample import N, mul, signature_integer
from nonce_relation_extraction import DEFAULT_RELATIONS
from publication_core_check import encode_key

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


class SharedContextTests(unittest.TestCase):
    def test_nondegenerate_signed_glv_relations_at_equal_digest(self):
        t, _, anchor = fixture()
        rt = mul(t)[0]
        for sign in (1, -1):
            for a, _ in DEFAULT_RELATIONS:
                if a in (1, N-1):
                    continue
                with self.subTest(anchor_sign=sign, multiplier=a):
                    k = a*sign*t % N
                    r = mul(k)[0] % N
                    self.assertNotEqual(r, rt)
                    s_bytes = 53 - (len(signature_integer(r))-2)
                    s = 1 << (8*s_bytes-2)
                    determinant = (a*s*rt-r) % N
                    z = determinant*sign*t*pow(rt-r, -1, N) % N
                    p = (sign*t-z)*pow(rt, -1, N) % N
                    self.assertNotEqual(z, 0)
                    self.assertNotEqual(determinant, 0)
                    sigma = der(r, s)
                    self.assertEqual(len(sigma), 60)
                    digest = z.to_bytes(32, 'big')
                    result = extract(anchor[0], digest, encode_key(mul(p)), anchor[3],
                                     [(sigma, digest)])
                    self.assertEqual(result['scalar'], t)
                    self.assertEqual(result['method'], 'affine-related-nonces')
                    self.assertEqual(result['relation']['pair'], [0, 1])

    def test_identity_or_negation_degeneracy_cannot_have_size_60(self):
        t, _, anchor = fixture()
        rt = mul(t)[0]
        # Equal nonzero digest and D=0 force r=rt and a*s=1. For the
        # identity/negation orbit this means s=1 or -1, respectively.
        self.assertEqual(len(anchor[0]), 40)
        self.assertEqual([len(der(rt, s)) for s in (1, N-1)], [40, 72])


if __name__ == '__main__':
    program = unittest.main(exit=False)
    if not program.result.wasSuccessful():
        raise SystemExit(1)
    paths = [Path(__file__), HERE/'anchored_extraction.py',
             HERE/'nonce_relation_extraction.py', HERE/'core_check.py',
             HERE/'publication_core_check.py',
             HERE.parent/'covenant-2026-09-17/legacy_same_signature_counterexample.py']
    report = dict(evidence='locally-reproduced', deployment='unclassified',
        tests_run=program.result.testsRun, equal_digest_signed_glv_cases=8,
        identity_negation_degenerate_signature_bytes=[40,72],
        scope=__doc__, native_execution=False, general_extraction_proved=False,
        sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    (HERE/'shared-context-algebra.json').write_text(json.dumps(report, indent=2)+'\n')
