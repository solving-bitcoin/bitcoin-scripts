#!/usr/bin/env python3
"""Native Taproot edge -> public ECDSA pair on a manufactured digest.

Host equations and exact commitment bytes only. No transaction, Script/Core
execution, native transaction digest, rare search, or field-library tests.
"""
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from r4_taproot import N, G, FIELD, add, mul, b32, even, lift, h, challenge, verify as verify_schnorr
sys.path.insert(0, str(HERE.parent))
from legacy_same_signature_counterexample import signature_integer, verify as verify_ecdsa


def enc(point):
    assert point is not None
    return bytes([2 + point[1] % 2]) + b32(point[0])


def neg(point):
    return (point[0], (-point[1]) % FIELD) if point is not None else None


def compact(n):
    if n < 253:
        return bytes([n])
    if n < 65536:
        return b'\xfd' + n.to_bytes(2, 'little')
    raise ValueError('fixture compact size too large')


def leaf_hash(script):
    return h('TapLeaf', b'\xc0' + compact(len(script)) + script)


def branch(a, b):
    return h('TapBranch', min(a, b) + max(a, b))


def check_opening(output_x, script, control):
    """Host check of current-version control-block relation, not Script."""
    if len(control) < 33 or (len(control) - 33) % 32 or len(control) > 33 + 128 * 32:
        return False
    if control[0] & 0xfe != 0xc0:
        return False
    x = int.from_bytes(control[1:33], 'big')
    if x >= FIELD:
        return False
    try:
        internal = lift(x)
    except AssertionError:
        return False
    root = leaf_hash(script)
    for offset in range(33, len(control), 32):
        root = branch(root, control[offset:offset + 32])
    tweak = int.from_bytes(h('TapTweak', b32(x) + root), 'big')
    if tweak >= N:
        return False
    output = add(internal, mul(tweak))
    return output is not None and output[0] == output_x and output[1] % 2 == control[0] & 1


def nonce_roots(r):
    roots = []
    for x in (r, r + N):
        if x >= FIELD:
            continue
        try:
            a = lift(x)
        except AssertionError:
            continue
        roots.extend([a, neg(a)])
    return roots


def sig_bytes(r, s):
    payload = signature_integer(r) + signature_integer(s)
    return b'\x30' + bytes([len(payload)]) + payload + b'\x01'


def main():
    source = lift(1)  # No logarithm of this point is an input to the fixture.
    edges = []
    pair_count = 0
    for i in range(16):
        internal, internal_sign = even(add(source, mul(i % 4)))
        # Exact legal leaf bytes with no transaction restrictions: push/drop/true.
        # The sibling is OP_RETURN. These are commitment controls, not a covenant.
        script = b'\x20' + hashlib.sha256(('r22-leaf-%d' % i).encode()).digest() + b'\x75\x51'
        leaf = leaf_hash(script)
        siblings = [] if i % 2 == 0 else [leaf_hash(b'\x6a')]
        root = leaf
        for sibling in siblings:
            root = branch(root, sibling)
        tweak = int.from_bytes(h('TapTweak', b32(internal[0]) + root), 'big')
        assert 0 <= tweak < N
        output = add(internal, mul(tweak))
        assert output is not None
        control = bytes([0xc0 | (output[1] % 2)]) + b32(internal[0]) + b''.join(siblings)
        assert check_opening(output[0], script, control)
        assert not check_opening(output[0], script, bytes([control[0] ^ 1]) + control[1:])
        assert not check_opening(output[0], script + b'\x61', control)
        assert not check_opening((output[0] + 1) % FIELD, script, control)
        midpoint = add(internal, mul(tweak * pow(2, -1, N)))
        assert midpoint is not None
        pairs = []
        for scale in (1, 2, 3, 5):
            nonce = mul(pow(scale, -1, N), midpoint)
            r = nonce[0] % N
            assert r != 0
            s = scale * r % N
            assert s != 0
            z = tweak * r * pow(2, -1, N) % N
            roots = nonce_roots(r)
            assert len(roots) == 2
            for actual_s in (s, min(s, N - s)):
                recovered = [mul(pow(r, -1, N), add(mul(actual_s, a), mul(-z))) for a in roots]
                assert all(q is not None for q in recovered)
                assert {enc(q) for q in recovered} == {enc(internal), enc(neg(output))}
                assert all(verify_ecdsa(z, r, actual_s, q)[0] for q in recovered)
                assert not all(verify_ecdsa((z + 1) % N, r, actual_s, q)[0] for q in recovered)
            low_s = min(s, N - s)
            raw, normalized = sig_bytes(r, s), sig_bytes(r, low_s)
            if scale == 1:
                assert len(raw) % 2 == 1
                assert len(raw) not in (20, 32) and len(normalized) not in (20, 32)
            pairs.append({'public_scale_a': scale, 'nonce': enc(nonce).hex(),
                          'r': str(r), 's': str(s), 'low_s': str(low_s),
                          'manufactured_z': str(z), 'nonce_root_count': len(roots),
                          'der_plus_flag': raw.hex(), 'der_plus_flag_bytes': len(raw),
                          'low_s_der_plus_flag': normalized.hex(),
                          'low_s_der_plus_flag_bytes': len(normalized),
                          'complete_recovery_pair_matches': True,
                          'altered_digest_pair_rejected': True})
            pair_count += 1
        # The same midpoint used as BIP340 nonce returns to R4's challenge target.
        output_even, output_sign = even(output)
        nonce_even, nonce_sign = even(midpoint)
        required_e = (-nonce_sign * output_sign) % N
        candidate_s = -nonce_sign * tweak * pow(2, -1, N) % N
        assert mul(candidate_s) == add(nonce_even, mul(required_e, output_even))
        message = hashlib.sha256(('r22-synthetic-schnorr-message-%d' % i).encode()).digest()
        actual_e = challenge(nonce_even, output_even, message)
        assert actual_e != required_e and not verify_schnorr(output_even, message, nonce_even, candidate_s)
        edges.append({'index': i, 'internal_key': enc(internal).hex(),
                      'internal_normalization_sign': internal_sign,
                      'output_key': enc(output).hex(), 'output_x': b32(output[0]).hex(),
                      'leaf_script': script.hex(), 'leaf_hash': leaf.hex(),
                      'merkle_root': root.hex(), 'tweak': str(tweak),
                      'control_block': control.hex(), 'opening_relation_passes': True,
                      'malformed_opening_controls_rejected': 3,
                      'midpoint': enc(midpoint).hex(), 'source_pairs': pairs,
                      'schnorr_control': {'synthetic_message': message.hex(),
                          'required_challenge': str(required_e), 'actual_challenge': str(actual_e),
                          'candidate_s': str(candidate_s), 'native_equation_rejects': True}})
    parities = sorted({(int(row['output_key'][:2], 16) & 1,
                        int(row['midpoint'][:2], 16) & 1) for row in edges})
    assert len(parities) == 4
    # The short-container parity claim covers all DER-length regimes explicitly.
    boundaries = sorted({1, N // 2, N // 2 + 1, N - 1} |
                        {x for k in range(1, 257) for x in (2**k - 1, 2**k) if 0 < x < N})
    for r in boundaries:
        assert len(sig_bytes(r, r)) % 2 == 1
        assert len(sig_bytes(r, min(r, N - r))) not in (20, 32)
        assert (len(sig_bytes(r, r)) <= 32) == (r <= 2**95 - 1)
    report = {'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
              'scope': __doc__, 'edges': edges, 'edge_count': len(edges),
              'source_pair_count': pair_count, 'output_midpoint_parities': parities,
              'DER_boundary_controls': len(boundaries),
              'all_source_pairs_have_exactly_two_roots': True,
              'native_transaction_digest_found': False, 'script_execution_claimed': False,
              'all_assertions_passed': True}
    Path(__file__).with_suffix('.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'edges': len(edges), 'source_pairs': pair_count,
                      'parities': parities, 'DER_boundaries': len(boundaries)}, indent=2))


if __name__ == '__main__':
    main()
