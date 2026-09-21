#!/usr/bin/env python3
"""Same-key SHA256(alpha) closure: all recovery branches and public offsets.

Exact finite host research. No rare DER witness, Core or full covenant.
"""
from collections import Counter, defaultdict
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from r11_endomorphism import C, GAP, N, P, BETA, LAMBDA, add, mul, neg, lift, solve, signature, layout
from r12_live_reference import tx, strict_der
from r10_parallel_cycles import hash256, instructions, pubkey
from legacy_same_signature_counterexample import verify
from r9_hash_xonly import TP, TN, TG, tmul

RMAX = 2**191-1
ONE_KEY_SCRIPT = bytes.fromhex('6ead7ca87cac')
TWO_KEY_SCRIPT = bytes.fromhex('7453885279a8527a527a') + layout()


def recovery_roots(rho):
    if not 1 <= rho < N:
        return []
    result = []
    for x in (rho, rho+N):
        if x >= P:
            continue
        point = lift(x)
        if point is not None:
            result += [point, neg(point)]
    return result


def closure_points(R, r, s, rho, tau, g):
    a = rho*s*pow(r*tau, -1, N) % N
    b = (g-rho*C*pow(r, -1, N))*pow(tau, -1, N) % N
    return add(mul(a, R), mul(b)), add(mul(-a, R), mul(b)), a, b


def toy_incidence():
    points = {k: tmul(k) for k in range(1, TN)}
    logs = {point: k for k, point in points.items()}
    root_logs = defaultdict(list)
    for k, point in points.items():
        if point[0] % TN:
            root_logs[point[0] % TN].append(k)
    k, c, g = 2, 5, 13
    r = points[k][0] % TN
    ss = [s for s in range(1, TN//2+1)
          if (s*k-c) % TN and (-s*k-c) % TN]
    pkeys = {s: (s*k-c)*pow(r, -1, TN) % TN for s in ss}
    qkeys = {s: (-s*k-c)*pow(r, -1, TN) % TN for s in ss}
    # This is an explicitly separate toy alphabet, not Bitcoin DER.
    gamma_domain = [(rho, tau) for rho in range(1, 32) for tau in range(1, TN//2+1)]
    one_counts, two_counts = Counter(), Counter()
    histogram, branches, examples = Counter(), Counter(), []
    comparisons = 0
    for rho, tau in gamma_domain:
        roots = root_logs[rho]
        keys = {(tau*w-g)*pow(rho, -1, TN) % TN for w in roots}
        predicted = {(r*d+c)*pow(k, -1, TN) % TN for d in keys if d}
        predicted &= set(ss)
        predicted_two = {s for s in predicted if qkeys[s] in keys}
        direct, direct_two = set(), set()
        for s in ss:
            up = (g+rho*pkeys[s])*pow(tau, -1, TN) % TN
            uq = (g+rho*qkeys[s])*pow(tau, -1, TN) % TN
            goodp = up != 0 and points[up][0] % TN == rho
            goodq = uq != 0 and points[uq][0] % TN == rho
            if goodp:
                direct.add(s)
            if goodp and goodq:
                direct_two.add(s)
                branch = 'antipodal' if (up+uq) % TN == 0 else 'mixed_n_wrap'
                branches[branch] += 1
                if branch == 'antipodal':
                    assert rho == g*r*pow(c, -1, TN) % TN
                else:
                    assert rho < TP-TN and abs(points[up][0]-points[uq][0]) == TN
                # Exact sum and difference form of the two-key condition.
                a = rho*s*pow(r*tau, -1, TN) % TN
                b = (g-rho*c*pow(r, -1, TN))*pow(tau, -1, TN) % TN
                assert (up+uq) % TN == 2*b % TN
                assert (up-uq) % TN == 2*a*k % TN
                if len(examples) < 8:
                    examples.append({'rho': rho, 'tau': tau, 's': s, 'branch': branch,
                                     'verification_nonce_logs': [up, uq], 'a': a, 'b': b})
            comparisons += 1
        assert predicted == direct and predicted_two == direct_two
        assert len(predicted) <= len(roots) <= 4 and predicted_two <= predicted
        histogram[len(predicted)] += 1
        for s in predicted:
            one_counts[s] += 1
        for s in predicted_two:
            two_counts[s] += 1
    alphabet = 2**20
    statistics = {}
    for name, counts in [('one_key', one_counts), ('two_keys', two_counts)]:
        expectation = Fraction(sum(counts.values()), alphabet)
        failure = math.prod(Fraction(alphabet-counts[s], alphabet) for s in ss)
        probability = 1-failure
        assert probability <= expectation
        assert expectation <= Fraction(4*len(gamma_domain), alphabet)
        statistics[name] = {'incidences': sum(counts.values()),
                            'expected_closed_hash_hits': str(expectation),
                            'probability_of_any_hit_float': float(probability),
                            'exact_probability_numerator': str(probability.numerator),
                            'exact_probability_denominator': str(probability.denominator)}
    # Enumerate public offsets independently: equality of reduced x for
    # W+=tR+dG and W-=-tR+dG forces d=0 or the mixed n-wrap branch.
    offset_cases, offset_accepts, nonzero_offset_examples = 0, Counter(), []
    for t in range(1, TN):
        for d in range(TN):
            u, v = (t*k+d) % TN, (-t*k+d) % TN
            offset_cases += 1
            if not u or not v:
                continue
            x, y = points[u][0], points[v][0]
            if x % TN == y % TN and x % TN:
                if d == 0:
                    assert x == y and (u+v) % TN == 0
                    offset_accepts['zero_offset_antipodal'] += 1
                else:
                    assert abs(x-y) == TN and x % TN < TP-TN
                    offset_accepts['nonzero_offset_mixed'] += 1
                    if len(nonzero_offset_examples) < 4:
                        nonzero_offset_examples.append({'t': t, 'd': d, 'x_plus': x, 'x_minus': y})
    return {'curve': {'p': TP, 'n': TN, 'G': TG}, 'fixed_family': {'k': k, 'r': r, 'C': c, 'g': g},
            'scalar_domain_count': len(ss), 'gamma_domain_count': len(gamma_domain),
            'direct_membership_comparisons': comparisons, 'maximum_in_degree': max(histogram),
            'in_degree_histogram': dict(histogram), 'shared_two_key_branches': dict(branches),
            'four_root_r_values': [rho for rho, rs in root_logs.items() if len(rs) == 4],
            'same_key_statistics': statistics, 'toy_hash_output_alphabet': alphabet,
            'two_key_examples': examples, 'offset_cases': offset_cases,
            'offset_accepts': dict(offset_accepts), 'nonzero_offset_examples': nonzero_offset_examples,
            'toy_uses_discrete_logs_only_for_exhaustive_validation': True}


def native_offset_vectors():
    result = []
    for recipient in (0x11, 0x22):
        outputs = [(990000, b'\x00\x14'+bytes([recipient])*20)]
        preimage = tx(ONE_KEY_SCRIPT, outputs, 0)+struct.pack('<I', 1)
        g = int.from_bytes(hash256(preimage), 'big') % N
        for index, W in enumerate(recovery_roots(2)):
            for d in (1, 17):
                t = LAMBDA
                R = mul(pow(t, -1, N), add(W, mul(-d)))
                assert R is not None
                r, rho = R[0] % N, 2
                tau = (g-rho*C*pow(r, -1, N))*pow(d, -1, N) % N
                s = r*tau*t*pow(rho, -1, N) % N
                assert r and tau and s
                Pkey = mul(pow(r, -1, N), add(mul(s, R), mul(-C)))
                Qkey = mul(pow(r, -1, N), add(mul(-s, R), mul(-C)))
                assert Pkey is not None and Qkey is not None and Pkey != Qkey
                alpha = signature(r, min(s, N-s), 3)
                gamma = signature(rho, min(tau, N-tau), 1)
                assert strict_der(alpha) and strict_der(gamma)
                assert verify(C, r, min(s, N-s), Pkey)[0]
                assert verify(g, rho, min(tau, N-tau), Pkey)[0]
                wp, wm, a, b = closure_points(R, r, s, rho, tau, g)
                assert wp == W and a == t and b == d
                assert wm == add(mul(-t, R), mul(d))
                second_passes = verify(g, rho, min(tau, N-tau), Qkey)[0]
                assert not second_passes
                assert wp[0] % N != wm[0] % N
                h = hashlib.sha256(alpha).digest()
                assert h != gamma  # Hash closure is not supplied by these equations.
                result.append({'recipient': recipient, 'all_preimage': preimage.hex(),
                               'all_digest': hex(g), 'recovery_branch': index,
                               'recovery_x': str(W[0]), 'd': d, 't': str(t),
                               'alpha_r': str(r), 'alpha_s_raw': str(s),
                               'gamma_r': rho, 'gamma_s_raw': str(tau),
                               'alpha_hex': alpha.hex(), 'unhashed_gamma_hex': gamma.hex(),
                               'actual_sha256_alpha': h.hex(), 'key_hex': pubkey(Pkey).hex(),
                               'signature_bytes': [len(alpha), len(gamma)],
                               'one_key_native_equations_valid': True,
                               'two_key_gamma_equations_valid': second_passes,
                               'hash_closure_valid': False, 'funded': False})
    return result


def transferred_strip():
    planted = []
    for start in (2**190, 2**190+1000, 2**190+2000):
        rho = next(start+i for i in range(256) if lift(start+i) is not None)
        W = lift(rho)
        tau = 1
        for exponent in (1, 2):
            t = pow(LAMBDA, exponent, N)
            R = mul(pow(t, -1, N), W)
            r = R[0] % N
            u = rho*pow(r, -1, N) % N
            # Applying R11 to the inverse ratio and swapping its points
            # restricts gamma's coordinate, rather than alpha's.
            found = solve(pow(u, -1, N), max_r=RMAX, exponents=(3-exponent,))
            assert found is not None and found['r_alpha'] <= RMAX
            assert found['r_beta']*u % N == found['r_alpha']
            g = C*u % N
            s = r*tau*t*pow(rho, -1, N) % N
            keys = [mul(pow(r, -1, N), add(mul(sign*s, R), mul(-C))) for sign in (1, -1)]
            assert all(verify(C, r, min(s, N-s), key)[0] for key in keys)
            assert all(verify(g, rho, tau, key)[0] for key in keys)
            alpha, gamma = signature(r, min(s, N-s), 3), signature(rho, tau, 1)
            assert len(gamma) == 32 and hashlib.sha256(alpha).digest() != gamma
            planted.append({'alpha_r': str(r), 'gamma_r': str(rho), 'gamma_s': tau,
                            'endomorphism_exponent': exponent, 'target_ratio': str(u),
                            'manufactured_digest_scalar': str(g),
                            'alpha_hex': alpha.hex(), 'unhashed_gamma_hex': gamma.hex(),
                            'inverse_lattice_found': True, 'actual_native_digest': False,
                            'hash_closure_valid': False})
    native_trials, found_count = [], 0
    outputs = [(990000, b'\x00\x14'+b'\x11'*20)]
    for locktime in range(64):
        digest = hash256(tx(TWO_KEY_SCRIPT, outputs, locktime)+struct.pack('<I', 1))
        g = int.from_bytes(digest, 'big') % N
        u = g*pow(C, -1, N) % N
        witness = solve(pow(u, -1, N), max_r=RMAX)
        found_count += witness is not None
        native_trials.append({'locktime': locktime, 'digest_hex': digest.hex(),
                              'short_gamma_coordinate_found': witness is not None})
    return {'planted_vectors': planted, 'native_digest_trials': native_trials,
            'native_short_coordinate_witness_count': found_count,
            'solver_failure_means_no_result_within_its_explicit_cap': True}


def layout_metrics():
    # These are structural counts only: neither hash-closed script has a witness.
    return {'one_key': {'raw_hex': ONE_KEY_SCRIPT.hex(), 'raw_bytes': len(ONE_KEY_SCRIPT),
                        'static_ops': sum(op > 0x60 for _, _, op, _ in instructions(ONE_KEY_SCRIPT)),
                        'entry_data_items': 2, 'hint_items': 0, 'peak_by_inspection': 4,
                        'native_checks_if_successful': 2, 'executed_with_valid_witness': False},
            'two_keys': {'raw_hex': TWO_KEY_SCRIPT.hex(), 'raw_bytes': len(TWO_KEY_SCRIPT),
                         'static_ops': sum(op > 0x60 for _, _, op, _ in instructions(TWO_KEY_SCRIPT)),
                         'entry_data_items': 3, 'hint_items': 0, 'peak_by_inspection': 7,
                         'native_checks_if_successful': 4, 'executed_with_valid_witness': False}}


def main():
    toy = toy_incidence()
    offsets = native_offset_vectors()
    strip = transferred_strip()
    pder = Fraction(780555, 2**65)
    strip_size = RMAX+min(RMAX, GAP-1)
    support = 2*strip_size
    result = {'evidence': 'locally-reproduced', 'deployment': 'unclassified',
              'no_hash_closed_bitcoin_witness': True, 'no_core_run': True,
              'native_offset_vectors': offsets, 'transferred_strip': strip,
              'toy': toy, 'unmined_layouts': layout_metrics(),
              'exact_large_bounds': {
                  'gamma_r_max': str(RMAX), 'p_minus_n': str(GAP),
                  'two_endomorphism_ratio_support_upper_bound': str(support),
                  'uniform_scalar_support_bound': str(Fraction(support, N)),
                  'uniform_256_bit_digest_support_bound': str(Fraction(support+min(support, 2**256-N), 2**256)),
                  'one_fixed_family_closed_hash_expected_hits_upper_bound': str(4*pder),
                  'one_fixed_family_bound_log2': math.log2(4*pder),
                  'two_key_mixed_branch_per_flag_expected_hits_upper_bound': str(Fraction(8*(GAP-1), 2**256)),
                  'two_key_mixed_branch_bound_log2': math.log2(Fraction(8*(GAP-1), 2**256)),
                  'scope': 'fixed family chosen before fresh independent ideal SHA256 answers; not arbitrary adaptive family selection'},
              'sources': [
                  'https://github.com/bitcoin/bitcoin/blob/v29.0/src/script/interpreter.cpp',
                  'https://github.com/bitcoin-core/secp256k1/blob/v0.6.0/src/scalar_impl.h']}
    path = HERE/'r13_gamma_closure.json'
    path.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'toy_comparisons': toy['direct_membership_comparisons'],
                      'toy_offset_cases': toy['offset_cases'], 'native_offset_vectors': len(offsets),
                      'planted_short_gamma_vectors': len(strip['planted_vectors']),
                      'actual_native_short_gamma_hits': strip['native_short_coordinate_witness_count'],
                      'toy_statistics': toy['same_key_statistics'],
                      'large_bounds': result['exact_large_bounds']}))


if __name__ == '__main__':
    main()
