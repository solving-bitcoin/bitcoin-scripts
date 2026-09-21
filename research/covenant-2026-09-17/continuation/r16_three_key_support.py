#!/usr/bin/env python3
"""Five-center support for three shared ECDSA recovery keys.

Exact support/counting mathematics and complete small-curve signature tests.
No native Bitcoin script or hash-closed covenant witness.
"""
from fractions import Fraction
from itertools import combinations
import json
import math
from pathlib import Path

from r11_endomorphism import P, N, GAP
from r15_three_common_keys import Curve

HERE = Path(__file__).resolve().parent


def integer_interval(size):
    return (1 if size == 1 else 2**(8*size-9)), 2**(8*size-1)-1


def der_probability(max_r):
    total, rows = 0, []
    for nr in range(1, 25):
        low, high = integer_interval(nr)
        high = min(high, max_r)
        r_count = max(0, high-low+1)
        slow, shigh = integer_interval(25-nr)
        count = r_count*(shigh-slow+1)*256
        total += count
        if count:
            rows.append({'r_integer_bytes': nr, 's_integer_bytes': 25-nr,
                         'r_min': str(low), 'r_max': str(high),
                         'r_count': str(r_count), 's_count': str(shigh-slow+1),
                         'all_flag_string_count': str(count)})
    return Fraction(total, 2**256), rows


def exact_bounds():
    full_probability, _ = der_probability(2**191-1)
    assert full_probability == Fraction(780045, 2**65)
    root_probability, rows = der_probability(GAP-1)
    support = 5*(GAP-1)
    native_probability = Fraction(support+min(support, 2**256-N), 2**256)
    Q = 2**64
    bound = Fraction(Q*(Q-1), 2)*root_probability*native_probability
    return {'delta': str(GAP), 'positive_scalar_DER_probability': str(full_probability),
            'syntactic_DER_with_zero_scalars_upper_bound': str(Fraction(780555, 2**65)),
            'source_r_below_delta_probability': str(root_probability),
            'source_probability_log2': math.log2(root_probability),
            'source_DER_length_rows': rows,
            'max_pair_center_points': 5, 'scalar_digest_support_upper_bound': str(support),
            'uniform_scalar_probability_upper_bound': str(Fraction(support, N)),
            'uniform_256bit_digest_probability_upper_bound': str(native_probability),
            'native_probability_log2': math.log2(native_probability),
            'adaptive_total_query_bound_at_2_64': str(bound),
            'adaptive_total_query_bound_log2': math.log2(bound),
            'approximate_log2_queries_necessary_for_half_success': -math.log2(root_probability*native_probability)/2,
            'probability_model': 'Fresh independent source-hash and native-digest answer tapes; all setup/online distinct queries counted. Not a bound for shared answers such as alpha=z or an arbitrary correlated hash construction.'}


def complete_toy(p, n, generator):
    curve = Curve(p, n, generator)
    points = [curve.mul(k) for k in range(n)]
    assert len(set(points)) == n
    roots = {r: [k for k in range(1, n) if points[k][0] % n == r] for r in range(1, n)}
    roots = {r: values for r, values in roots.items() if len(values) == 4}
    constant = 7
    beta_rows = []
    for z in range(n):
        for rb, nonce_scalars in roots.items():
            for sb in range(1, n//2+1):
                keys = {(sb*k-z)*pow(rb, -1, n) % n for k in nonce_scalars}
                keys.discard(0)
                beta_rows.append((z, rb, sb, keys))
    result, comparisons = [], 0
    for ra, nonce_scalars in roots.items():
        trial_s = {1, 2, 7, n//2}
        # Include all source-key-infinity values, normalized to LOW_S.
        trial_s |= {min(v, n-v) for k in nonce_scalars
                    for v in [constant*pow(k, -1, n) % n]}
        # Also include values producing a zero pair-center.
        for left, right in combinations(nonce_scalars, 2):
            if (left+right) % n:
                v = 2*constant*pow(left+right, -1, n) % n
                trial_s.add(min(v, n-v))
        for sa in sorted(trial_s):
            all_keys = {(sa*k-constant)*pow(ra, -1, n) % n for k in nonce_scalars}
            keys = all_keys-{0}
            centers = {-(left+right)*pow(2, -1, n) % n for left, right in combinations(keys, 2)}
            assert len(centers) <= 5
            envelope = {t*rb % n for t in centers for rb in range(1, p-n)}
            assert len(envelope) <= min(n, 5*(p-n-1))
            accepted, witnesses = set(), 0
            for z, rb, sb, other_keys in beta_rows:
                comparisons += 1
                if len(keys & other_keys) >= 3:
                    assert z in envelope
                    accepted.add(z)
                    witnesses += 1
            result.append({'alpha_r': ra, 'alpha_s': sa, 'constant_digest': constant,
                           'source_infinity_key_excluded': 0 in all_keys,
                           'finite_key_scalars': sorted(keys), 'pair_center_scalars': sorted(centers),
                           'zero_center': 0 in centers, 'support_envelope': sorted(envelope),
                           'actual_accepted_digest_scalars': sorted(accepted),
                           'actual_target_signature_count': witnesses})
    assert any(row['source_infinity_key_excluded'] for row in result)
    assert any(row['zero_center'] for row in result)
    return {'p': p, 'n': n, 'generator': generator,
            'source_four_root_r': sorted(roots), 'alpha_configurations': len(result),
            'complete_beta_signatures_per_alpha': len(beta_rows),
            'signature_set_comparisons': comparisons, 'cases': result,
            'scope': 'All native scalar messages and all LOW_S four-root target signatures for each listed source alpha; omitted two-root beta cannot share three finite keys.'}


def main():
    report = {'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
              'question': 'How many native message scalars can share three keys with a fixed alpha under constant C?',
              'bounds': exact_bounds(),
              'complete_toys': [complete_toy(43, 31, (2, 12)), complete_toy(211, 199, (3, 33))],
              'no_native_Bitcoin_witness': True}
    output = HERE/'r16_three_key_support.json'
    output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'output': str(output),
                      'toy_signature_comparisons': [row['signature_set_comparisons'] for row in report['complete_toys']],
                      'Q_2_64_probability_bound_log2': report['bounds']['adaptive_total_query_bound_log2']}, indent=2))


if __name__ == '__main__':
    main()
