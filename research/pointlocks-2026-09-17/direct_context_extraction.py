#!/usr/bin/env python3
"""Known-, repeated- and affine-related-nonce extraction for the direct candidate.

None means unresolved, NOT impossible. Synthetic tests assign digest scalars;
they are not non-extracting Bitcoin transactions or hash preimage attacks.
"""
import hashlib
import unittest

from anchored_extraction import HALF, HALF_R, der, decode_verification_key, small_s_check
from core_check import unpack_signature
from publication_core_check import encode_key
from legacy_same_signature_counterexample import N, mul, verify


def extract(key_bytes, checks, *, nonce_relations=None):
    """Caller must bind key_bytes to the setup and derive actual native digests."""
    key = decode_verification_key(key_bytes)
    rows = []
    for sigma, digest in checks:
        assert len(sigma) == 60
        r, s, _ = unpack_signature(sigma)
        z = int.from_bytes(digest, 'big') % N
        assert verify(z, r, s, key)[0]
        rows.append((r, s, z))

    def finish(t, method):
        return dict(scalar=t, method=method) if mul(t) == key else None

    for r, s, z in rows:
        if r == HALF_R:
            for nonce in (HALF, -HALF % N):
                found = finish((s*nonce-z)*pow(r, -1, N) % N, 'known-G/2-nonce')
                if found:
                    return found
    for i, (r, s, z) in enumerate(rows):
        for rr, ss, zz in rows[i+1:]:
            if r != rr or z == zz:
                continue
            for sign in (1, -1):
                denominator = (s-sign*ss) % N
                if not denominator:
                    continue
                nonce = (z-zz)*pow(denominator, -1, N) % N
                found = finish((s*nonce-z)*pow(r, -1, N) % N, 'repeated-nonce')
                if found:
                    return found
    from nonce_relation_extraction import extract_rows
    return extract_rows(key, rows, nonce_relations)


class DirectExtractionTests(unittest.TestCase):
    def setUp(self):
        self.t = int.from_bytes(hashlib.sha256(b'direct-context-extractor').digest(), 'big') % N
        self.key = encode_key(mul(self.t))

    def test_known_nonce(self):
        z = 1
        while True:
            s = 2*(z+HALF_R*self.t) % N
            sigma = der(HALF_R, min(s, N-s))
            if len(sigma) == 60:
                break
            z += 1
        self.assertEqual(extract(self.key, [(sigma, z.to_bytes(32, 'big'))])['scalar'], self.t)

    def test_repeated_unknown_nonce_both_signs(self):
        for sign in (1, -1):
            checks = [small_s_check(self.t, 1729, 1), small_s_check(self.t, sign*1729 % N, 2)]
            result = extract(self.key, checks)
            self.assertEqual((result['scalar'], result['method']), (self.t, 'repeated-nonce'))

    def test_identical_digest_is_not_extraction(self):
        check = small_s_check(self.t, 1729, 1)
        self.assertIsNone(extract(self.key, [check, check]))

    def test_six_distinct_unknown_nonces_remain_unresolved(self):
        nonces = [int.from_bytes(hashlib.sha256(f'direct-unknown-{i}'.encode()).digest(), 'big') % N for i in range(6)]
        self.assertIsNone(extract(self.key, [small_s_check(self.t, k, i) for i, k in enumerate(nonces)]))

    def test_wrong_digest_rejected(self):
        sigma, _ = small_s_check(self.t, 1729, 1)
        with self.assertRaises(AssertionError):
            extract(self.key, [(sigma, bytes(32))])


if __name__ == '__main__':
    unittest.main()
