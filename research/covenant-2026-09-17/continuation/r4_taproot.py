#!/usr/bin/env python3
"""Public host-only Taproot/ECDSA/Schnorr algebra. No wallet or transaction."""
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from legacy_same_signature_counterexample import G, N, P as FIELD, add, mul


def h(tag, data):
    prefix = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(prefix + prefix + data).digest()


def b32(x):
    return x.to_bytes(32, 'big')


def even(point):
    sign = 1 if point[1] % 2 == 0 else -1
    return mul(sign % N, point), sign


def lift(x):
    y = pow((x**3 + 7) % FIELD, (FIELD + 1) // 4, FIELD)
    assert y*y % FIELD == (x**3 + 7) % FIELD
    return even((x, y))[0]


def taproot(point, leaf):
    root = h('TapLeaf', b'\xc0' + bytes([len(leaf)]) + leaf)
    t = int.from_bytes(h('TapTweak', b32(point[0]) + root), 'big')
    assert t < N
    return add(point, mul(t)), t, root


def challenge(nonce, key, message):
    return int.from_bytes(h('BIP0340/challenge', b32(nonce[0]) + b32(key[0]) + message), 'big') % N


def verify(key, message, nonce, s):
    e = challenge(nonce, key, message)
    return 0 <= s < N and nonce[1] % 2 == 0 and mul(s) == add(nonce, mul(e, key))


def main():
    nonce = lift(1)  # r = s_ECDSA = 1; this point's logarithm is not supplied.
    cases = []
    for sigma in [-1, 1]:
        for i in range(8):
            msg = hashlib.sha256(f'r4 synthetic digest {i}'.encode()).digest()
            z = int.from_bytes(msg, 'big') % N
            recovered = add(mul(sigma % N, nonce), mul((-z) % N))
            internal, delta = even(recovered)
            # OP_RETURN is a deliberately unspendable script branch, not a covenant.
            output, tweak, root = taproot(internal, b'\x6a')
            output_even, epsilon = even(output)
            e_required = (-epsilon * delta * sigma) % N
            s = (sigma * z - delta * sigma * tweak) % N
            assert mul(s) == add(nonce, mul(e_required, output_even))
            e_actual = challenge(nonce, output_even, msg)
            actual_pass = verify(output_even, msg, nonce, s)
            assert not actual_pass and e_actual != e_required
            cases.append({'sigma': sigma, 'internal_parity_sign': delta,
                          'output_parity_sign': epsilon, 'synthetic_z': f'{z:064x}',
                          'tweak': f'{tweak:064x}', 'required_e': f'{e_required:064x}',
                          'actual_e': f'{e_actual:064x}', 's': f'{s:064x}',
                          'cancelled_equation_passes': True,
                          'actual_challenge_passes': actual_pass})

    # Public test scalar, expressly not secret. Retained setup permits both messages.
    internal, sign = even(mul(7))
    output, tweak, root = taproot(internal, b'\x6a')
    output_even, output_sign = even(output)
    signing_scalar = output_sign * (sign * 7 + tweak) % N
    assert mul(signing_scalar) == output_even
    bypass = []
    for i, label in enumerate(['prescribed outputs placeholder', 'different outputs placeholder']):
        message = hashlib.sha256(label.encode()).digest()
        R, nonce_sign = even(mul(11 + i))
        k = nonce_sign * (11 + i) % N
        s = (k + challenge(R, output_even, message) * signing_scalar) % N
        assert verify(output_even, message, R, s)
        bypass.append({'synthetic_message': message.hex(), 'signature': (b32(R[0]) + b32(s)).hex(),
                       'accepted': True})

    a, b = h('TapLeaf', b'\xc0\x01\x51'), h('TapLeaf', b'\xc0\x01\x6a')
    branch = lambda a, b: h('TapBranch', min(a,b) + max(a,b))
    assert branch(a, b) == branch(b, a)
    result = {'evidence': 'locally-reproduced', 'deployment': 'unclassified',
              'boundary': 'host-only public point equations; no Bitcoin transaction or Script execution',
              'hybrid_cases': cases, 'parity_pairs_covered': sorted(set((c['internal_parity_sign'], c['output_parity_sign']) for c in cases)),
              'known_log_keypath_signatures': bypass, 'sorted_branch_swap_equal': True,
              'warning': 'Messages are synthetic 32-byte digests, not transaction sighashes; artificial challenges are not valid Schnorr signatures.'}
    target = Path(__file__).with_suffix('.json')
    target.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'hybrid_cases': len(cases), 'actual_challenge_accepts': sum(c['actual_challenge_passes'] for c in cases),
                      'parity_pairs': result['parity_pairs_covered'], 'known_log_signatures': len(bypass), 'result': str(target)}, indent=2))


if __name__ == '__main__':
    main()
