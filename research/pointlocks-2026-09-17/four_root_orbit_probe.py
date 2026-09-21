#!/usr/bin/env python3
"""A fixed four-root orbit binds a full scalar, but explicit legacy tables exceed 100k.

Curve algebra and representation bound only. No generated Script or Core run.
All scalars are public deterministic fixtures. The nonconstant-digest bound
explicitly models the native hash as a random oracle.
"""
import hashlib
import json
import math
from functools import reduce
from pathlib import Path

from core_check import unpack_signature
from publication_core_check import encode_key
from legacy_same_signature_counterexample import N, P, G, add, mul, verify
from anchored_extraction import der
from four_recovery_key_probe import root

HERE = Path(__file__).resolve().parent
C = 1 << 248


def roots(r):
    a, b = root(r), root(r+N)
    assert a is not None and b is not None
    return [a, (a[0], -a[1] % P), b, (b[0], -b[1] % P)]


def point_set(points):
    return sorted(encode_key(q).hex() for q in points)


def sqrt_prime(a, p):
    assert pow(a, (p-1)//2, p) == 1
    q, s = p-1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p-1)//2, p) != p-1:
        z += 1
    c, x, t, m = pow(z, q, p), pow(a, (q+1)//2, p), pow(a, q, p), s
    while t != 1:
        i, power = 0, t
        while power != 1:
            power = power * power % p
            i += 1
        b = pow(c, 1 << (m-i-1), p)
        x, t, c, m = x*b % p, t*b*b % p, b*b % p, i
    assert x*x % p == a % p
    return x


def cost_rate(a, b):
    lo, hi = 0.001, 1000.
    for _ in range(150):
        mid = (lo+hi)/2
        if 2**(-a/mid) + 2**(-(a+b)/mid) < 1:
            lo = mid
        else:
            hi = mid
    return hi


def recover_orbit(keys, signature, digest, r0, basis):
    r, s, _ = unpack_signature(signature)
    assert len(set(keys)) == 4
    assert reduce(add, keys) == mul(-4*C*pow(r0, -1, N) % N)
    recovered = []
    for key in keys:
        ok, nonce = verify(digest, r, s, key)
        assert ok
        recovered.append(nonce)
    assert len(set(recovered)) == 4
    assert 0 < r < P-N
    assert digest % N == (C*r*pow(r0, -1, N)) % N
    label = min(s, N-s)
    committed = [add(mul(r0, key), mul(C)) for key in keys]
    return label if point_set(committed) == point_set([mul(label, R) for R in basis]) else None


def main():
    r0 = next(r for r in range(1, 1000) if root(r) is not None and root(r+N) is not None)
    assert r0 == 2
    basis = roots(r0)
    order_four = sqrt_prime(N-1, N)
    assert order_four*order_four % N == N-1
    assert mul(order_four, basis[0]) not in basis
    assert mul(-order_four, basis[0]) not in basis
    cases = []
    for seed in range(5):
        raw = int.from_bytes(hashlib.sha256(f'four-root-orbit-label-v1-{seed}'.encode()).digest(), 'big') % N
        scalar = min(raw, N-raw)
        committed = [mul(scalar, R) for R in basis]
        keys = [mul(pow(r0, -1, N), add(H, mul(-C))) for H in committed]
        signature = der(r0, scalar)[:-1] + b'\x03'
        recovered = recover_orbit(keys, signature, C, r0, basis)
        assert recovered == scalar
        # HIGH_S is a separate consensus encoding of the same orbit opening.
        high = der(r0, N-scalar)[:-1] + b'\x03'
        assert recover_orbit(keys, high, C, r0, basis) == scalar
        assert point_set(committed) == point_set([mul(N-scalar, R) for R in basis])
        cases.append(dict(seed=seed, scalar_fixture=f'{scalar:064x}', signature_hex=signature.hex(),
                          signature_bytes=len(signature), high_s_signature_bytes=len(high),
                          keys=point_set(keys), orbit_commitment=point_set(committed), extracted=True))
    # The sum/distinctness conditions alone do not algebraically force z=C.
    # This deliberately chosen digest is NOT an actual native Bitcoin hash.
    r1 = next(r for r in range(r0+1, 1000) if root(r) is not None and root(r+N) is not None)
    z1 = C*r1*pow(r0, -1, N) % N
    s1 = 17
    keys1 = [mul(pow(r1, -1, N), add(mul(s1, R), mul(-z1))) for R in roots(r1)]
    sigma1 = der(r1, s1)[:-1]+b'\x01'
    assert recover_orbit(keys1, sigma1, z1, r0, basis) is None
    bounds = []
    for name, a, b in [('raw-packet-payload-only', 20, 132),
                       ('hypothetical-single-packet-hash', 21, 136),
                       ('four-separate-key-hashes', 84, 136),
                       ('four-embedded-keys', 136, 0)]:
        rate = cost_rate(a, b)
        bounds.append(dict(representation=name, candidate_bytes=a, selected_key_bytes=b,
                           bytes_per_bit_lower_bound=rate, legacy_vbytes_lower_bound=2048*rate,
                           integral_vbytes_lower_bound=math.ceil(2048*rate)))
    # Each allowed reduced z has at most two 256-bit hash preimages.
    allowed_r = P-N-1
    log_failure_per_query = math.log2(2*allowed_r)-256
    output = dict(evidence='locally-reproduced', deployment='unclassified', scope=__doc__,
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        r0=r0, bases=point_set(basis), roots_log_assumption='No known discrete logarithms relative to G; fixed public x=2 and x=n+2 lifts. No proof of DLP hardness.',
        order_four_scalar=f'{order_four:064x}', order_four_does_not_stabilize_orbit=True,
        orbit_scalar_unique_up_to_sign_argument='A scalar stabilizer permutes four nonzero points freely, hence has order dividing four. Order four is explicitly excluded; only +/-1 remain.',
        cases=cases, synthetic_nonconstant_digest=dict(r=r1, digest=f'{z1:064x}', signature_hex=sigma1.hex(),
            all_four_checks_valid=True, fixed_public_key_sum_valid=True, reference_orbit_extraction_succeeds=False,
            native_hash_realized=False),
        nonconstant_hash_bound=dict(allowed_r_count=allowed_r, log2_failure_per_distinct_hash_query_upper_bound=log_failure_per_query,
            model='Native nonconstant sighash outputs modeled as uniform 256-bit random-oracle values. Adaptive setup cannot change the fixed r0/C target set. q distinct queries give at most q*2*(p-n-1)/2^256; raw flags/targets do not create free queries.',
            not_a_proof_about_actual_sha256=True),
        representation_bounds=bounds,
        caveats=['Unordered four-point orbit commitment, not scalar extraction relative to the standard G point.',
                 'No Script, transaction, native policy/consensus result or setup benchmark.',
                 'Bounds cover explicit independent candidate tables and subset messages, not every algebraic or shared representation.',
                 'Full garbled-label setup binding and the original sub100k goal remain unresolved.'])
    (HERE/'four-root-orbit-probe.json').write_text(json.dumps(output, indent=2)+'\n')
    print(json.dumps(dict(r0=r0, checked_ecdsa_equations=44,
        ordinary_hash_failure_log2=log_failure_per_query, bounds=bounds), indent=2))


if __name__ == '__main__':
    main()
