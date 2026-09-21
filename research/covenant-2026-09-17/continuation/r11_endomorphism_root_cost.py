#!/usr/bin/env python3
"""Finite fixed-endomorphism target accounting, not a general search bound.

Host-only exact small-curve enumeration and explicitly idealized query models.
No native hash-derived signature or complete covenant is constructed.
"""
from fractions import Fraction
import itertools
import json
import math
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from r9_hash_xonly import TP, TN, TG, tlift, tmul
sys.path.insert(0, str(HERE.parent))
from legacy_same_signature_counterexample import N, P


def toy_targets(r, betas):
    targets = set()
    for x in (r, r+TN):
        if x >= TP or tlift(x) is None:
            continue
        for beta in betas:
            image = beta*x % TP
            rb = image % TN
            if rb:
                targets.add(rb*pow(r, -1, TN) % TN)
    return targets


def main():
    betas = [b for b in range(2, TP) if pow(b, 3, TP) == 1]
    assert len(betas) == 2
    multipliers = []
    for beta in betas:
        image = (TG[0]*beta % TP, TG[1])
        lambdas = [k for k in range(1, TN) if tmul(k) == image]
        assert len(lambdas) == 1 and pow(lambdas[0], 3, TN) == 1
        multipliers += lambdas
    strips = []
    for maximum in range(1, TN):
        targets = set().union(*(toy_targets(r, betas) for r in range(1, maximum+1)))
        bound = 2*(maximum+min(maximum, TP-TN-1))
        assert len(targets) <= min(TN-1, bound)
        strips.append({'r_maximum': maximum, 'target_count': len(targets),
                       'integer_support_bound': bound})
    selected = [r for r in range(1, TN) if toy_targets(r, betas)][:4]
    # A 16-symbol ideal root oracle: four valid root classes and twelve
    # rejected classes. Not a model of actual Bitcoin DER byte encodings.
    alphabet = [toy_targets(r, betas) for r in selected]+[set() for _ in range(12)]
    events = pairs = 0
    for first, second, native in itertools.product(range(16), range(16), range(TN)):
        count = int(native in alphabet[first])+int(native in alphabet[second])
        events += int(count != 0)
        pairs += count
    denominator = 16*16*TN
    success, expectation = Fraction(events, denominator), Fraction(pairs, denominator)
    union = Fraction(2, 1)*Fraction(4, 16)*Fraction(4, TN)
    assert success <= expectation <= union
    # Adaptive allocation cannot replace fixed query caps by Q^2/4 when
    # allocation depends on root validity. Exact Q=3 counterexample.
    adaptive_events = 0
    for r1, r2, z1, z2 in itertools.product(range(4), range(4), range(8), range(8)):
        ok = (z1 == 0 or z2 == 0) if r1 == 0 else (r2 == 0 and z1 == 0)
        adaptive_events += int(ok)
    adaptive_success = Fraction(adaptive_events, 4*4*8*8)
    assert adaptive_success == Fraction(21, 256) > Fraction(1, 16)

    r32max = 2**191-1
    r20max = 2**95-1
    support32 = 2*(r32max+min(r32max, P-N-1))
    support20 = 2*(r20max+min(r20max, P-N-1))
    p_der = Fraction(780555, 2**65)
    # 2^256 digest bytes reduced mod n give at most TWO representations
    # of any scalar. Each valid root supplies <=4 endomorphism targets.
    qtotal = 2**64
    pair_bound = Fraction((qtotal//2)**2*8, 2**256)*p_der
    adaptive_bound = Fraction(qtotal*(qtotal-1)//2*8, 2**256)*p_der
    uniform_scalar_bound = Fraction((qtotal//2)**2*4, N)*p_der
    report = {'question': 'Does cheap free-signature endomorphism recovery also supply a hash-derived reference root?',
              'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
              'scope': __doc__, 'all_assertions_passed': True,
              'toy_curve': {'p': TP, 'n': TN, 'generator': TG, 'betas': betas,
                            'lambdas': multipliers, 'strip_cases': strips},
              'finite_oracle_toy': {'outcomes': denominator, 'selected_r': selected,
                  'valid_root_fraction': '1/4', 'root_queries': 2, 'native_queries': 1,
                  'success': str(success), 'expected_pairs': str(expectation),
                  'union_bound': str(union)},
              'adaptive_allocation_counterexample': {'total_queries': 3,
                  'root_validity_probability': '1/4', 'native_match_probability': '1/8',
                  'exhaustive_outcomes': 1024, 'success': str(adaptive_success),
                  'invalid_fixed_cap_bound': '1/16'},
              'exact_der_limits': {'32_byte_signature_r_maximum': str(r32max),
                  '20_byte_signature_r_maximum': str(r20max),
                  'two_endomorphism_target_support_bound_32': str(support32),
                  'two_endomorphism_target_support_bound_20': str(support20),
                  'uniform_scalar_support_32_log2': math.log2(support32)-math.log2(N),
                  'uniform_scalar_support_20_log2': math.log2(support20)-math.log2(N)},
              'fixed_catalogue_iid_model': {'total_fresh_queries': str(qtotal),
                  'root_syntax_probability': str(p_der), 'targets_per_valid_root_upper_bound': 4,
                  'max_digest_representations_per_scalar': 2,
                  'fixed_equal_query_caps_bound_log2': math.log2(float(pair_bound)),
                  'adaptive_total_budget_bound_log2': math.log2(float(adaptive_bound)),
                  'uniform_scalar_approximation_bound_log2': math.log2(float(uniform_scalar_bound)),
                  'assumptions': ['The catalogue is the two fixed nonidentity endomorphisms.',
                      'Root outputs and fresh native digests use independent ideal-oracle domains.',
                      'Setup and both query lists are counted; no free precomputed root/native list.',
                      'A real hash-query overlap or new adaptive scalar-map construction needs separate analysis.'],
                  'not_claimed': 'No bound on all covenant constructions, all nonce maps, or actual SHA cryptanalysis.'}}
    output = Path(__file__).with_suffix('.json')
    output.write_text(json.dumps(report, indent=2)+'\n')
    print(output)


if __name__ == '__main__':
    main()
