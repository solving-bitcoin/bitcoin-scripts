#!/usr/bin/env python3
"""Exact ECDSA key recovery from a verified public affine nonce relation.

This is an offchain extractor extension, not a new Script predicate or a
general extraction proof. A caller supplies actual independently derived
native digests. Default relations are the six signed secp256k1 endomorphisms;
additional (a,b) pairs describe R_j = a*R_i + b*G, with PUBLIC known scalars.
The method returns None when no nondegenerate tested relation extracts.
"""
import hashlib
import json
from pathlib import Path
import sys
import unittest

# Reuse the pinned repository curve reference without importing its tests.
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE.parent/'covenant-2026-09-17'))
from legacy_same_signature_counterexample import G, N, P, add, mul, verify

BETA = pow(2, (P-1)//3, P)
LAMBDA = pow(3, (N-1)//3, N)
if mul(LAMBDA) != (BETA*G[0] % P, G[1]):
    LAMBDA = LAMBDA*LAMBDA % N
assert mul(LAMBDA) == (BETA*G[0] % P, G[1])
SIGNED_ENDOMORPHISMS = {
    sign*pow(LAMBDA, j, N) % N: (pow(BETA, j, P), sign)
    for j in range(3) for sign in (1, -1)
}
DEFAULT_RELATIONS = tuple((a, 0) for a in SIGNED_ENDOMORPHISMS)


def affine_point(point, a, b, offset):
    """Use the actual endomorphism, not a field/order approximation."""
    if a in SIGNED_ENDOMORPHISMS:
        beta, sign = SIGNED_ENDOMORPHISMS[a]
        transformed = (beta*point[0] % P, sign*point[1] % P)
    else:
        transformed = mul(a, point)
    return add(transformed, offset[b])


def analyze_rows(key, rows, relations=None):
    """Rows are (r,s,z); z is an already reduced, authenticated native digest.

    Validate the key and all ECDSA equations before inspecting any pair. Neither
    one matching point relation nor a zero determinant certifies extraction.
    This accepts mathematical ECDSA rows; wrappers enforce their own DER sizes.
    """
    if (not isinstance(key, tuple) or len(key) != 2
            or any(not isinstance(v, int) or not 0 <= v < P for v in key)
            or (key[1]*key[1]-key[0]**3-7) % P):
        raise ValueError('invalid verification point')
    rows = list(rows)
    nonces = []
    for r, s, z in rows:
        if not (0 < r < N and 0 < s < N and 0 <= z < N):
            raise ValueError('noncanonical ECDSA row')
        valid, nonce = verify(z, r, s, key)
        if not valid:
            raise ValueError('invalid ECDSA equation')
        nonces.append(nonce)
    relations = tuple(dict.fromkeys((a % N, b % N) for a, b in
                                   (DEFAULT_RELATIONS if relations is None else relations)))
    if any(a == 0 for a, _ in relations):
        raise ValueError('affine multiplier must be nonzero')
    offset = {b: mul(b) for _, b in relations}
    transformed = {(i, a, b): affine_point(point, a, b, offset)
                   for i, point in enumerate(nonces) for a, b in relations}
    report = dict(result=None, matching_relations=0, degenerate_relations=0,
                  tested_relations=len(relations), signature_rows=len(rows))
    for i, (r, s, z) in enumerate(rows):
        for j in range(i+1, len(rows)):
            rr, ss, zz = rows[j]
            for a, b in relations:
                if transformed[i, a, b] != nonces[j]:
                    continue
                report['matching_relations'] += 1
                denominator = (a*ss*r - s*rr) % N
                numerator = (s*zz - a*ss*z - b*s*ss) % N
                if denominator == 0:
                    # A verified point relation makes the numerator zero too.
                    # There is no invertible equation for the secret in this case.
                    if numerator != 0:
                        raise AssertionError('inconsistent verified relation')
                    report['degenerate_relations'] += 1
                    continue
                secret = numerator*pow(denominator, -1, N) % N
                if mul(secret) != key:
                    raise AssertionError('extracted scalar does not match key')
                report['result'] = dict(scalar=secret, method='affine-related-nonces',
                    pair=[i, j], multiplier=a, translation=b)
                return report
    return report


def extract_rows(key, rows, relations=None):
    return analyze_rows(key, rows, relations)['result']


def scalar_fixture(tag):
    return int.from_bytes(hashlib.sha256(tag.encode()).digest(), 'big') % N or 1


class RelationExtractionTests(unittest.TestCase):
    """Synthetic-digest algebra tests, not new accepted Bitcoin transactions."""

    def test_anchor_nonce_relations_without_related_short_pair(self):
        from anchored_extraction import fixture, small_s_check, extract as anchored
        from core_check import unpack_signature
        t, secret, anchor = fixture()
        rt, _, _ = unpack_signature(anchor[0])
        for sign in (1, -1):
            z0 = (sign*t - rt*secret) % N
            signed_anchor = (anchor[0], z0.to_bytes(32, 'big'), *anchor[2:])
            for a, _ in DEFAULT_RELATIONS:
                with self.subTest(anchor_sign=sign, multiplier=a):
                    checks = [small_s_check(secret, a*sign*t % N, 13)]
                    checks += [small_s_check(secret, scalar_fixture(f'anchor-only/filler/{i}'), 31+i)
                               for i in range(4)]
                    rows = [(unpack_signature(s)[0], unpack_signature(s)[1], int.from_bytes(z, 'big'))
                            for s,z in checks]
                    self.assertIsNone(extract_rows(mul(secret), rows))
                    result = anchored(*signed_anchor, checks)
                    self.assertEqual(result['scalar'], t)
                    self.assertEqual(result['method'], 'affine-related-nonces')
                    self.assertEqual(result['relation']['pair'], [0, 1])
                    self.assertEqual(result['relation']['multiplier'], a)
                    self.assertEqual(result['relation']['row_order'], 'anchor, then short checks')

    def test_signed_endomorphisms_in_both_pointlock_wrappers(self):
        from anchored_extraction import fixture, small_s_check, extract as anchored
        from direct_context_extraction import extract as direct
        from publication_core_check import encode_key
        t, secret, anchor = fixture()
        nonce = scalar_fixture('affine-extraction/shared-fixture-nonce')
        for a, _ in DEFAULT_RELATIONS:
            with self.subTest(multiplier=a):
                checks = [small_s_check(secret, nonce, 11),
                          small_s_check(secret, a*nonce % N, 23)]
                # Five rounds with distinct unrelated fillers: only the chosen
                # pair has a tested relation (except +/-1, which repeats r).
                checks += [small_s_check(secret, scalar_fixture(f'affine/filler/{i}'), 31+i)
                           for i in range(3)]
                result = anchored(*anchor, checks)
                self.assertEqual(result['scalar'], t)
                self.assertEqual(direct(encode_key(mul(secret)), checks)['scalar'], secret)
                if a not in (1, N-1):
                    self.assertEqual(result['method'], 'affine-related-nonces')
                    self.assertEqual(len({int.from_bytes(c[0][4:4+c[0][3]], 'big')
                                          for c in checks}), 5)

    def test_public_translations_require_explicit_relation_and_handle_signs(self):
        from anchored_extraction import fixture, small_s_check, extract as anchored
        from direct_context_extraction import extract as direct
        from publication_core_check import encode_key
        t, secret, anchor = fixture()
        nonce = scalar_fixture('affine-extraction/translated-fixture-nonce')
        for a, b in ((1, 17), (N-1, 17), (LAMBDA, N-23), (7, 29)):
            with self.subTest(multiplier=a, translation=b):
                checks = [small_s_check(secret, nonce, 2),
                          small_s_check(secret, (a*nonce+b) % N, 4)]
                self.assertIsNone(anchored(*anchor, checks))
                self.assertEqual(anchored(*anchor, checks, nonce_relations=[(a,b)])['scalar'], t)
                self.assertEqual(direct(encode_key(mul(secret)), checks,
                                        nonce_relations=[(a,b)])['scalar'], secret)

    def test_degenerate_relation_does_not_manufacture_a_scalar(self):
        # Transparent unknown-log base. Match public coefficients of that base
        # to build valid equations, without ever computing its scalar or key's.
        x = scalar_fixture('affine-extraction/unknown-log-base') % P
        while True:
            y = pow((x*x*x+7) % P, (P+1)//4, P)
            if y*y % P == (x*x*x+7) % P:
                break
            x = (x+1) % P
        base = (x, y)
        coefficient, shift = 7, 11
        key = add(mul(coefficient, base), mul(shift))
        rows = []
        for a, b in ((1, 0), (LAMBDA, 17)):
            nonce = add(mul(a, base), mul(b))
            r = nonce[0] % N
            s = r*coefficient*pow(a, -1, N) % N
            z = (s*b-r*shift) % N
            rows.append((r,s,z))
        report = analyze_rows(key, rows, [(LAMBDA,17)])
        self.assertIsNone(report['result'])
        self.assertEqual(report['matching_relations'], 1)
        self.assertEqual(report['degenerate_relations'], 1)
        # These are unrestricted-length ECDSA equations. No cap60 or native
        # pointlock counterexample is claimed for this degeneracy control.

    def test_high_s_and_reduced_digest_boundary(self):
        secret, nonce = scalar_fixture('affine/key'), scalar_fixture('affine/nonce')
        a, b = LAMBDA, 19
        rows = []
        for k,z in ((nonce,0), ((a*nonce+b) % N,N-1)):
            r = mul(k)[0] % N
            s = (z+r*secret)*pow(k,-1,N) % N
            rows.append((r,s,z))
        self.assertEqual(extract_rows(mul(secret), rows, [(a,b)])['scalar'], secret)
        # Negating the second s negates its recovered nonce, including b.
        r,s,z = rows[1]
        rows[1] = (r,N-s,z)
        self.assertIsNone(extract_rows(mul(secret), rows, [(a,b)]))
        self.assertEqual(extract_rows(mul(secret), rows, [(-a,-b)])['scalar'], secret)

    def test_invalid_rows_and_keys_reject_before_extraction(self):
        from anchored_extraction import small_s_check
        from core_check import unpack_signature
        secret = scalar_fixture('affine/invalid/key')
        sigma, digest = small_s_check(secret, 1729, 1)
        r,s,_ = unpack_signature(sigma)
        z = int.from_bytes(digest, 'big')
        for row in ((0,s,z),(r,0,z),(N,s,z),(r,N,z),(r,s,N),(r,s,(z+1)%N)):
            with self.subTest(row=row):
                with self.assertRaises(ValueError):
                    analyze_rows(mul(secret), [row])
        for key in (None,(1,1),(P,G[1])):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    analyze_rows(key, [(r,s,z)])
        with self.assertRaises(ValueError):
            analyze_rows(mul(secret), [(r,s,z)], [(0,1)])

    def test_unrelated_short_nonces_stay_unresolved(self):
        from anchored_extraction import fixture, small_s_check, extract as anchored
        _, secret, anchor = fixture()
        checks = [small_s_check(secret, scalar_fixture(f'affine-independent/{i}'), i+1)
                  for i in range(6)]
        self.assertIsNone(anchored(*anchor, checks))


if __name__ == '__main__':
    program = unittest.main(exit=False)
    if not program.result.wasSuccessful():
        raise SystemExit(1)
    paths = [Path(__file__), HERE/'anchored_extraction.py',
             HERE/'direct_context_extraction.py', HERE/'core_check.py',
             HERE/'publication_core_check.py',
             HERE.parent/'covenant-2026-09-17/legacy_same_signature_counterexample.py']
    report = dict(evidence='locally-reproduced', deployment='unclassified',
        tests_run=program.result.testsRun, failures=0, errors=0,
        scope='Offchain ECDSA affine-relation extraction; synthetic digest algebra, no new Bitcoin execution.',
        default_relations=[dict(multiplier=str(a),translation=str(b)) for a,b in DEFAULT_RELATIONS],
        signed_endomorphism_wrapper_cases=12, translated_wrapper_cases=8,
        anchor_only_relation_cases=12,
        degenerate_relation_refused=True, unrelated_short_nonces_unresolved=True,
        incremental_onchain_bytes=0, incremental_onchain_hint_items=0,
        general_extraction_proved=False,
        sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    (HERE/'nonce-relation-extraction.json').write_text(json.dumps(report, indent=2)+'\n')
