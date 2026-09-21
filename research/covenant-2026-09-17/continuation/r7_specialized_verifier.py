#!/usr/bin/env python3
"""One-round polynomial lookup: exact host experiments, no Script execution.

The secp256k1 check is a public group-equation fixture, not a KZG pairing
implementation and not a native Bitcoin verifier. No field-library tests run.
"""
import hashlib
import importlib.util
import json
from pathlib import Path

MOD = 257


def trim(a):
    a = list(a)
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    return a


def plus(a, b, p=MOD):
    out = [0] * max(len(a), len(b))
    for i, x in enumerate(a):
        out[i] = (out[i] + x) % p
    for i, x in enumerate(b):
        out[i] = (out[i] + x) % p
    return trim(out)


def times(a, b, p=MOD):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i+j] = (out[i+j] + x*y) % p
    return trim(out)


def scale(a, k, p=MOD):
    return trim([x*k % p for x in a])


def at(a, x, p=MOD):
    out = 0
    for c in reversed(a):
        out = (out*x+c) % p
    return out


def interpolate(rows):
    out = [0]
    for x, y in enumerate(rows):
        basis, denom = [1], 1
        for j in range(len(rows)):
            if j != x:
                basis = times(basis, [-j % MOD, 1])
                denom = denom * (x-j) % MOD
        out = plus(out, scale(basis, y*pow(denom, -1, MOD)))
    return out


def divide_linear(a, x):
    a = trim(a)
    if len(a) == 1:
        return [0], a[0]
    q = [0] * (len(a)-1)
    q[-1] = a[-1]
    for i in range(len(q)-2, -1, -1):
        q[i] = (a[i+1] + x*q[i+1]) % MOD
    return trim(q), (a[0] + x*q[0]) % MOD


def equation(f_r, x, y, r, q_r):
    return (f_r-y) % MOD == (r-x)*q_r % MOD


def secp_fixture():
    path = Path(__file__).parents[1] / 'legacy_same_signature_counterexample.py'
    spec = importlib.util.spec_from_file_location('r7_secp', path)
    secp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(secp)
    # Public coefficients are only used to create and cross-check the fixture.
    # Forge() consumes a group commitment C and public tau, not its logarithm.
    coeff = [7, 0, 9, 4, 19]
    tau = 73
    c = secp.mul(at(coeff, tau, secp.N))
    cases = []
    for x in (0, 1, 17, 74):
        true_y = at(coeff, x, secp.N)
        for delta in (1, 2, 0x100000000):
            false_y = (true_y + delta) % secp.N
            numerator = secp.add(c, secp.mul(-false_y))
            witness = secp.mul(pow((tau-x) % secp.N, -1, secp.N), numerator)
            assert witness is not None
            assert secp.add(secp.mul(tau-x, witness), secp.mul(false_y)) == c
            cases.append({'x': x, 'false_y': str(false_y),
                          'witness_compressed': (bytes([2+witness[1] % 2])
                           + witness[0].to_bytes(32, 'big')).hex()})
    return {'curve': 'secp256k1', 'tau': tau, 'false_openings': len(cases),
            'uses_commitment_discrete_log_for_forgery': False, 'cases': cases}


def root_cost(n_rows, field_bits):
    # Direct R6 bit-root authentication of Q's N-1 coefficients only.
    bits = (n_rows-1)*field_bits
    return {'rows': n_rows, 'quotient_coefficients': n_rows-1,
            'field_encoding_bits': field_bits, 'selector_data_items': bits,
            'auxiliary_hint_items': 0, 'entry_data_items': bits+1,
            'combined_stack_peak': bits+3,
            'raw_fragment_bytes': 5+10*bits,
            'static_non_push_opcodes': 3+8*bits,
            'excludes': 'F authentication, arithmetic, native gates, input pushes, cleanup'}


def main():
    rows = [int.from_bytes(hashlib.sha256(b'R7 fixed reference '+bytes([i])).digest(),
                           'big') % MOD for i in range(16)]
    f = interpolate(rows)
    assert len(f) == 16
    assert all(at(f, i) == y for i, y in enumerate(rows))
    honest = 0
    unbound = 0
    for x, y in enumerate(rows):
        q, remainder = divide_linear(plus(f, [-y % MOD]), x)
        assert remainder == 0
        for r in range(MOD):
            assert equation(at(f, r), x, y, r, at(q, r))
            honest += 1
            if r != x:
                false_y = (y+1) % MOD
                forged_q_r = (at(f, r)-false_y)*pow((r-x) % MOD, -1, MOD) % MOD
                assert equation(at(f, r), x, false_y, r, forged_q_r)
                unbound += 1

    # A genuinely precommitted degree-14 Q can target exactly 15 challenges.
    x = 7
    y = (rows[x]+1) % MOD
    roots = list(range(16, 31))
    error = [1]
    for r in roots:
        error = times(error, [-r % MOD, 1])
    error = scale(error, (rows[x]-y)*pow(at(error, x), -1, MOD))
    numerator = plus(plus(f, [-y % MOD]), scale(error, -1))
    fixed_q, remainder = divide_linear(numerator, x)
    assert remainder == 0 and len(fixed_q) <= 15
    accepted = [r for r in range(MOD) if r != x
                and equation(at(f, r), x, y, r, at(fixed_q, r))]
    assert accepted == roots

    result = {
        'evidence': 'locally-reproduced', 'deployment': 'unclassified',
        'scope': 'host polynomial and public group equations; no Bitcoin Script execution',
        'rng': 'none; deterministic SHA256 domain-separated rows',
        'toy': {'prime': MOD, 'rows': rows, 'reference_coefficients': f,
                'reference_degree': len(f)-1, 'honest_checks': honest,
                'unbound_quotient_false_accepts': unbound,
                'fixed_forgery': {'x': x, 'false_y': y, 'coefficients': fixed_q,
                                 'accepted_challenges': accepted,
                                 'eligible_challenges': MOD-1}},
        'public_tau': secp_fixture(),
        'direct_r6_root_only': [root_cost(16, 9), root_cost(2**32, 33),
                                root_cost(2**77, 78)],
        'ordinary_uniform_challenge_only': {
            'bound': '(N-1)/(p-1), when r excludes x',
            'not_a_QSB_or_Binohash_attack_lower_bound': True},
    }
    dest = Path(__file__).with_suffix('.json')
    dest.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'honest_checks': honest, 'unbound_false_checks': unbound,
                      'fixed_false_accepts': len(accepted),
                      'public_tau_false_openings': result['public_tau']['false_openings'],
                      'artifact': str(dest)}, indent=2))


if __name__ == '__main__':
    main()
