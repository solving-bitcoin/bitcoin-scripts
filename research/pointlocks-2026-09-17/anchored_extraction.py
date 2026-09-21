#!/usr/bin/env python3
"""The proved branches of anchored point extraction, plus bounded algebra tests.

None means the implemented known-, repeated- and related-nonce branches did not extract. It is
not proof that extraction is impossible. All tests use arbitrary algebraic
digests, not native transactions or random-oracle preimages.
"""
import hashlib
import unittest

from core_check import unpack_signature, decode_key
from publication_core_check import encode_key
from legacy_same_signature_counterexample import N, P, mul, verify, signature_integer

HALF = (N + 1) // 2
HALF_R = mul(HALF)[0] % N


def der(r, s):
    body = signature_integer(r) + signature_integer(s)
    return bytes([0x30, len(body)]) + body + b'\x01'


def decode_verification_key(data):
    """Compressed, uncompressed and parity-consistent hybrid ECDSA keys.

    The latter two are nonstandard in P2WSH but are not forbidden by this
    script or current consensus. The setup's target encoding remains canonical.
    """
    if len(data) == 33:
        return decode_key(data)
    assert len(data) == 65 and data[0] in (4, 6, 7)
    x, y = int.from_bytes(data[1:33], 'big'), int.from_bytes(data[33:], 'big')
    assert x < P and y < P and y*y % P == (x*x*x+7) % P
    if data[0] in (6, 7):
        assert y % 2 == data[0] % 2
    return x, y


def extract(tau, anchor_digest, key_bytes, target_bytes, short_checks, *, nonce_relations=None):
    """Validate ECDSA equations and attempt the implemented exact branches.

    The caller must authenticate tau/target and independently derive each native
    digest from the actually spent output, script execution and transaction.
    Returning None preserves the candidate's unresolved extraction boundary.
    """
    rt, st, flag = unpack_signature(tau)
    target, key = decode_key(target_bytes), decode_verification_key(key_bytes)
    assert len(tau) == 40 and st == flag == 1
    assert rt == target[0] and target_bytes[1] in range(1, 128)
    z0 = int.from_bytes(anchor_digest, 'big') % N
    assert verify(z0, rt, st, key)[0]
    rows = []
    for sigma, digest in short_checks:
        assert len(sigma) == 60
        r, s, _ = unpack_signature(sigma)
        z = int.from_bytes(digest, 'big') % N
        assert verify(z, r, s, key)[0]
        rows.append((r, s, z))

    def finish(p, method):
        if mul(p) != key:
            return None
        for sign in (1, -1):
            t = sign * (rt * p + z0) % N
            if mul(t) == target:
                return dict(scalar=t, key_scalar=p, method=method)
        raise AssertionError('verified anchor/key is inconsistent with target')

    for r, s, z in rows:
        if r == HALF_R:
            for nonce in (HALF, -HALF % N):
                found = finish((s * nonce - z) * pow(r, -1, N) % N, 'known-G/2-nonce')
                if found:
                    return found
    for i, (r, s, z) in enumerate(rows):
        for rr, ss, zz in rows[i + 1:]:
            if rr != r or z == zz:
                continue
            for sign in (1, -1):
                denominator = (s - sign * ss) % N
                if not denominator:
                    continue
                nonce = (z - zz) * pow(denominator, -1, N) % N
                found = finish((s * nonce - z) * pow(r, -1, N) % N, 'repeated-nonce')
                if found:
                    return found
    from nonce_relation_extraction import extract_rows
    # The fixed anchor is also a verified ECDSA row: its actual nonce is +/-T.
    # Including it covers relations to T even when all short nonces are
    # unrelated to each other. Pair indices are anchor=0, then short checks=1..
    related = extract_rows(key, [(rt, st, z0)] + rows, nonce_relations)
    if related:
        found = finish(related['scalar'], related['method'])
        if found:
            found['relation'] = {k: related[k] for k in ('pair', 'multiplier', 'translation')}
            found['relation']['row_order'] = 'anchor, then short checks'
            return found
    return None


def fixture():
    # Public deterministic secrets; never use these in a funded application.
    t = 1
    while not 0 < encode_key(mul(t))[1] < 128:
        t += 1
    target = encode_key(mul(t))
    rt = mul(t)[0]
    p = int.from_bytes(hashlib.sha256(b'anchored-extractor-fixture').digest(), 'big') % N
    z0 = (t - rt * p) % N
    return t, p, (der(rt, 1), z0.to_bytes(32, 'big'), encode_key(mul(p)), target)


def small_s_check(p, nonce, index):
    r = mul(nonce)[0] % N
    r_bytes = len(signature_integer(r)) - 2
    s_bytes = 53 - r_bytes
    s = (1 << (8 * s_bytes - 2)) + index
    z = (s * nonce - r * p) % N
    sigma = der(r, s)
    assert len(sigma) == 60
    return sigma, z.to_bytes(32, 'big')


class AlgebraTests(unittest.TestCase):
    def test_known_nonce(self):
        t, p, anchor = fixture()
        r = HALF_R
        z = 1
        while True:
            s = ((z + r * p) * pow(HALF, -1, N)) % N
            s = min(s, N-s)
            sigma = der(r, s)
            if len(sigma) == 60:
                break
            z += 1
        result = extract(*anchor, [(sigma, z.to_bytes(32, 'big'))])
        self.assertEqual((result['scalar'], result['method']), (t, 'known-G/2-nonce'))

    def test_repeated_unknown_nonce_both_signs(self):
        t, p, anchor = fixture()
        nonce = int.from_bytes(hashlib.sha256(b'unknown-extractor-nonce').digest(), 'big') % N
        for sign in (1, -1):
            checks = [small_s_check(p, nonce, 1), small_s_check(p, sign * nonce % N, 2)]
            result = extract(*anchor, checks)
            self.assertEqual((result['scalar'], result['method']), (t, 'repeated-nonce'))

    def test_consensus_uncompressed_and_hybrid_keys(self):
        t, p, anchor = fixture()
        checks = [small_s_check(p, 1729, 1), small_s_check(p, 1729, 2)]
        x, y = mul(p)
        for tag in (4, 6+y%2):
            key = bytes([tag])+x.to_bytes(32, 'big')+y.to_bytes(32, 'big')
            alternate = anchor[:2]+(key,)+anchor[3:]
            self.assertEqual(extract(*alternate, checks)['scalar'], t)
        wrong = bytes([6+(1-y%2)])+x.to_bytes(32, 'big')+y.to_bytes(32, 'big')
        with self.assertRaises(AssertionError):
            decode_verification_key(wrong)

    def test_identical_digest_is_not_nonce_reuse_extraction(self):
        _, p, anchor = fixture()
        check = small_s_check(p, 1729, 1)
        self.assertIsNone(extract(*anchor, [check, check]))

    def test_distinct_unknown_nonces_remain_unresolved(self):
        _, p, anchor = fixture()
        nonces = [int.from_bytes(hashlib.sha256(f'unknown-{i}'.encode()).digest(), 'big') % N for i in range(5)]
        checks = [small_s_check(p, nonce, i) for i, nonce in enumerate(nonces)]
        self.assertIsNone(extract(*anchor, checks))
        # This exposes a missing proof obligation, not an attack: these digest
        # values were assigned algebraically, not realized by Bitcoin hashing.

    def test_mismatched_digest_rejected(self):
        _, p, anchor = fixture()
        sigma, _ = small_s_check(p, 1729, 1)
        with self.assertRaises(AssertionError):
            extract(*anchor, [(sigma, bytes(32))])


if __name__ == '__main__':
    unittest.main()
