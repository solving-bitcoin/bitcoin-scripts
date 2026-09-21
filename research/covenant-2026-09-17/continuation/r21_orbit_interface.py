#!/usr/bin/env python3
"""Public algebra controls for the one-short/two-long orbit interface.

This is a standalone host-side point calculation. It does not find a hash
preimage, execute Script, calculate transaction hashes, or claim deployment.
"""
import hashlib
import json
import math
from pathlib import Path

from r11_endomorphism import BETA, C, GAP, G, LAMBDA, N, P, add, mul, signature, verify


def neg(point):
    return point[0], (-point[1]) % P


def extracted_log(left, right, base):
    # Each tuple is (a,b) in the public equation K=a*base-b*G.
    a, b = left
    c, d = right
    denominator, numerator = (a-c) % N, (b-d) % N
    if denominator == 0:
        assert numerator == 0
        return {'case': 'equal_coefficients'}
    candidate = numerator*pow(denominator, -1, N) % N
    return {'case': 'extractable', 'candidate': candidate,
            'point_check': mul(candidate) == base}


def main():
    k0 = pow(2, -1, N)
    roots = [mul(k0*pow(LAMBDA, i, N)) for i in range(3)]
    rs = [point[0] % N for point in roots]
    assert roots[1] == (BETA*roots[0][0] % P, roots[0][1])
    assert roots[2] == (BETA*roots[1][0] % P, roots[1][1])
    assert len(set(rs)) == 3
    assert rs[0] == 0x3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63
    assert rs[0] < 2**191 and all(r > 2**191 for r in rs[1:])
    s0 = 2**24
    q = (s0*k0-C)*pow(rs[0], -1, N) % N
    key = mul(q)
    alpha = signature(rs[0], s0, 3)
    assert len(alpha) == 32

    # An arbitrary fixed digest, deliberately not described as a native hash.
    z = int.from_bytes(hashlib.sha256(b'R21 public orbit interface control').digest(), 'big') % N
    digests = [C, z, z]
    ss = [s0] + [(digests[i]+rs[i]*q)*pow(k0*pow(LAMBDA, i, N) % N, -1, N) % N
                 for i in (1, 2)]
    sigs = [signature(rs[i], ss[i], 3 if i == 0 else 1) for i in range(3)]
    assert all(verify(digests[i], rs[i], ss[i], key) == (True, roots[i]) for i in range(3))
    assert all(len(sig) > 57 for sig in sigs[1:])
    # The opposite nonce gives each signature a second accepted key.
    companion_scalars = [(-q-2*digests[i]*pow(rs[i], -1, N)) % N for i in range(3)]
    companion_keys = [mul(scalar) for scalar in companion_scalars]
    assert len({key, *companion_keys}) == 4
    assert all(verify(digests[i], rs[i], ss[i], companion_keys[i]) == (True, neg(roots[i]))
               for i in range(3))
    coefficients = [(pow(LAMBDA, i, N)*ss[i]*pow(rs[i], -1, N) % N,
                     digests[i]*pow(rs[i], -1, N) % N) for i in range(3)]
    extracts = [extracted_log(coefficients[0], coefficients[i], roots[0]) for i in (1, 2)]
    assert all(item['case'] == 'extractable' and item['point_check'] and item['candidate'] == k0
               for item in extracts)

    # Signature validity alone also accepts these unrelated nonce choices.
    unrelated = []
    for i, nonce in enumerate((11, 13), 1):
        point = mul(nonce)
        r = point[0] % N
        s = (z+r*q)*pow(nonce, -1, N) % N
        assert verify(z, r, s, key) == (True, point)
        assert point not in roots and neg(point) not in roots
        claimed = (pow(LAMBDA, i, N)*s*pow(r, -1, N) % N, z*pow(r, -1, N) % N)
        result = extracted_log(coefficients[0], claimed, roots[0])
        assert result['case'] == 'extractable' and not result['point_check']
        unrelated.append({'nonce': nonce, 'r': r, 's': s, 'signature_valid': True,
                          'orbit_claim_valid': False, 'claimed_orbit_extractor': result})

    # A real orbit with the same TWO keys needs manufactured digest ratios.
    other_key = mul((-s0*k0-C)*pow(rs[0], -1, N) % N)
    pair_digests = [C*r*pow(rs[0], -1, N) % N for r in rs]
    pair_ss = [rs[i]*s0*pow(pow(LAMBDA, i, N)*rs[0] % N, -1, N) % N for i in range(3)]
    pair_coefficients = []
    for i in range(3):
        assert verify(pair_digests[i], rs[i], pair_ss[i], key) == (True, roots[i])
        assert verify(pair_digests[i], rs[i], pair_ss[i], other_key) == (True, neg(roots[i]))
        pair_coefficients.append((pow(LAMBDA, i, N)*pair_ss[i]*pow(rs[i], -1, N) % N,
                                  pair_digests[i]*pow(rs[i], -1, N) % N))
    assert len(set(pair_coefficients)) == 1
    assert len(set(pair_digests)) == 3

    maximum_r = 2**191-1
    source_coordinates = maximum_r+GAP-1
    target_pairs_bound = 2*source_coordinates
    count_s_for_fixed_r = 255*2**23  # A positive canonical four-byte DER integer.
    for s in (2**23, 2**31-1):
        assert len(signature(rs[0], s, 3)) == 32
    assert len(signature(rs[0], 2**23-1, 3)) == 31
    assert len(signature(rs[0], 2**31, 3)) == 33

    return {
        'question': 'What exact public relation is still required to bind one short ECDSA signature to two long orbit signatures?',
        'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
        'scope': 'Host-side algebra only; digests are synthetic, no hash preimage or Script/native transaction execution.',
        'base_nonce': k0, 'base_point': roots[0], 'orbit_r': rs,
        'one_key_positive': {'digests': digests, 'known_key_scalar': q,
                             'signature_hex': [sig.hex() for sig in sigs],
                             'signature_bytes': [len(sig) for sig in sigs],
                             'all_three_reconstructed_points_in_exact_orbit': True,
                             'distinct_pair_companion_keys': companion_keys,
                             'all_six_star_graph_signature_checks_valid': True,
                             'base_log_extractors': extracts},
        'valid_non_orbit_controls': unrelated,
        'same_pair_positive': {'manufactured_digests': pair_digests, 's': pair_ss,
                               'normalized_coefficients_equal': True,
                               'signature_bytes': [len(signature(rs[i], pair_ss[i], 3 if i == 0 else 1)) for i in range(3)]},
        'short_source_coordinate_count_bound': source_coordinates,
        'ordered_target_digest_pairs_bound': target_pairs_bound,
        'uniform_canonical_pair_probability_bound_log2': math.log2(target_pairs_bound)-2*math.log2(N),
        'uniform_independent_256_bit_pair_probability_bound_log2': 2+math.log2(target_pairs_bound)-512,
        'fixed_half_generator_r_hash_format': {
            'r_der_integer_bytes': 21, 's_der_integer_bytes': 4,
            's_count': count_s_for_fixed_r,
            'all_256_flag_strings': 256*count_s_for_fixed_r,
            'all_flags_probability_log2': math.log2(256*count_s_for_fixed_r)-256,
            'eight_single_bug_flags_strings': 8*count_s_for_fixed_r,
            'eight_flags_probability_log2': math.log2(8*count_s_for_fixed_r)-256},
        'script_metrics': None,
    }


if __name__ == '__main__':
    result = main()
    Path(__file__).with_suffix('.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'evidence': result['evidence'],
                      'signature_bytes': result['one_key_positive']['signature_bytes'],
                      'extractors_checked': len(result['one_key_positive']['base_log_extractors']),
                      'valid_non_orbit_controls': len(result['valid_non_orbit_controls']),
                      'target_pair_probability_log2': result['uniform_canonical_pair_probability_bound_log2']}, indent=2))
