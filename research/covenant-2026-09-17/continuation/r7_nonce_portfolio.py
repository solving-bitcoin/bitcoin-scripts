#!/usr/bin/env python3
"""Known-nonce portfolios: exact scalar models, format costs and replay vectors.

Public, deterministic host research. No full covenant or Core validation.
"""
from collections import Counter
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from legacy_same_signature_counterexample import (
    G, N, add, hash256, mul, signature_integer, tx, verify, vector,
)


def der_width(x):
    assert x > 0
    return (x.bit_length() + 8) // 8


def bounds(width, maximum):
    low = 1 if width == 1 else 1 << (8 * width - 9)
    high = min(1 << (8 * width - 1), maximum + 1)
    return low, max(low, high)


def masses(a, b):
    # Ideal uniform nonzero r; actual curve x coordinates are not asserted uniform.
    lo, hi = bounds(a, N - 1)
    slo, shi = bounds(b, (N - 1) // 2)
    return Fraction(hi - lo, N - 1), Fraction(2 * (shi - slo), N)


def slope_model():
    order = 509
    configurations = [
        ('common-slope', [2] * 8),
        ('different-small-slopes', [2, 3, 5, 7, 11, 13, 17, 19]),
        ('different-wide-slopes', [1, 257, 409, 123, 163, 245, 301, 501]),
    ]
    rows = []
    for name, slopes in configurations:
        def answers(z):
            result = []
            for index, slope in enumerate(slopes):
                raw = slope * (z + 37 * index + 1) % order
                scalar = min(raw, -raw % order)
                result.append(0 if scalar == 0 else der_width(scalar))
            return tuple(result)
        histogram = Counter(answers(z) for z in range(order))
        entropy = -sum((v / order) * math.log2(v / order) for v in histogram.values())
        rows.append({'name': name, 'slopes': slopes, 'distinct_length_vectors': len(histogram),
                     'support_bits': math.log2(len(histogram)), 'entropy_bits': entropy,
                     'maximum_cell_size': max(histogram.values())})
    assert rows[2]['distinct_length_vectors'] > 5 * rows[0]['distinct_length_vectors']
    return {'order': order, 'offsets': [37 * i + 1 for i in range(8)],
            'exhaustively_evaluated_digests_per_configuration': order, 'results': rows}


def costs():
    rows = []
    pair_mass = Fraction(0)
    strata = []
    for a in range(16, 34):
        b = 48 - a
        u, v = masses(a, b)
        pair_mass += u * v
        strata.append((u, v))
        # Relax M to a positive real, then compare the two neighboring integers.
        ratio = u / v
        ideal_m_floor = math.isqrt(ratio.numerator // ratio.denominator)
        candidates = {max(1, ideal_m_floor), max(1, ideal_m_floor + 1)}
        best_m = min(candidates, key=lambda m: Fraction(m, 1) / u + Fraction(1, m) / v)
        bound = Fraction(best_m, 1) / u + Fraction(1, best_m) / v
        rows.append({'r_der_bytes': a, 's_der_bytes': b,
                     'ideal_nonce_type_probability': str(u), 'message_probability': str(v),
                     'single_nonce_setup_bits': -math.log2(u),
                     'single_nonce_message_bits': -math.log2(v),
                     'best_integer_portfolio_size_for_relaxed_bound': best_m,
                     'setup_plus_digest_lower_bound_bits': math.log2(bound)})
    mixed = []
    # This is an explicit independent-row surrogate, not secp256k1 independence.
    for total_bits in (63.0, 63.7, 64.0, 65.0):
        queries = points = 2.0 ** (total_bits - 1)
        row_mass = sum(float(u) * -math.expm1(queries * math.log1p(-float(v)))
                       for u, v in strata)
        success = -math.expm1(points * math.log1p(-row_mass))
        mixed.append({'sample_only_total_bits': total_bits,
                      'point_samples': points, 'digest_samples': queries,
                      'independent_row_success_probability': success,
                      'naive_pair_tests_bits': 2 * (total_bits - 1)})
    # Exhaustive tiny independent-row model: type probabilities 1/2 each,
    # one type accepts each cell with p=1/2 and the other with p=1/4.
    # R=Q=2, each row has 2*4*4 equally likely type/edge outcomes.
    row_outcomes = []
    for typ in range(2):
        for a in range(4):
            for b in range(4):
                cutoff = 2 if typ == 0 else 1
                row_outcomes.append(a < cutoff or b < cutoff)
    success_count = sum(a or b for a in row_outcomes for b in row_outcomes)
    row_success = Fraction(1, 2) * (1 - Fraction(1, 2) ** 2) + Fraction(1, 2) * (1 - Fraction(3, 4) ** 2)
    exact = 1 - (1 - row_success) ** 2
    assert Fraction(success_count, len(row_outcomes) ** 2) == exact
    return {'signature_bytes': 55, 'signing_strategy': 'LOW_S only', 'fixed_length_strata': rows,
            'mixed_length_ideal_pair_probability': str(pair_mass),
            'mixed_length_ideal_pair_work_bits': -math.log2(pair_mass),
            'mixed_sample_only_models': mixed,
            'toy_independent_row_exhaustive_outcomes': len(row_outcomes) ** 2,
            'toy_independent_row_exact_success': str(exact)}


def native_shape():
    pub = bytes([2 + (G[1] & 1)]) + G[0].to_bytes(32, 'big')
    # Raw boundary serialization only; does not invoke a repository compiler.
    script = b'\x82' + vector(bytes([70])) + b'\x88' + vector(pub) + b'\xac'
    assert len(script) == 39
    # All public nonce points come from a deterministic incremental walk.
    portfolio = []
    point = None
    for k in range(1, 16385):
        point = add(point, G)
        r = point[0] % N
        if r and der_width(r) == 31:
            portfolio.append((k, r))
        if len(portfolio) == 8:
            break
    assert len(portfolio) == 8
    variants = []
    for byte in (0x11, 0x22):
        output = b'\x00\x14' + bytes([byte]) * 20
        digest = hash256(tx(script, output) + b'\x01\0\0\0')
        z = int.from_bytes(digest, 'big')
        signatures = []
        for k, r in portfolio:
            raw = (z + r) * pow(k, -1, N) % N  # Public d=1.
            s = min(raw, N - raw)
            if not s:
                continue
            body = signature_integer(r) + signature_integer(s)
            signature = b'\x30' + vector(body) + b'\x01'
            if len(signature) != 70:
                continue
            assert verify(z, r, s, G)[0]
            script_sig = vector(signature) + vector(script)
            raw_tx = tx(script_sig, output)
            signatures.append({'known_nonce_scalar': k, 'r': hex(r), 's': hex(s),
                               'signature': signature.hex(), 'signature_bytes': len(signature),
                               'script_sig_bytes': len(script_sig), 'transaction_hex': raw_tx.hex(),
                               'transaction_weight_by_serialization': 4 * len(raw_tx)})
            if len(signatures) == 2:
                break
        assert len(signatures) == 2 and signatures[0]['r'] != signatures[1]['r']
        variants.append({'output_script': output.hex(), 'sighash': digest.hex(), 'signatures': signatures})
    return {'scope': 'Synthetic unspent fixed outpoint; host ECDSA equations only, no Core execution.',
            'raw_script': script.hex(), 'raw_script_bytes': len(script),
            'raw_static_non_push_opcodes': 3, 'signature_input_data_items': 1,
            'hint_items': 0, 'combined_stack_peak_by_inspection': 3, 'witness_bytes': 0,
            'public_signing_scalar': 1, 'incremental_point_steps': k if not portfolio else portfolio[-1][0],
            'preprocessed_nonce_count': len(portfolio),
            'nonce_portfolio': [{'k': x, 'r': hex(y)} for x, y in portfolio],
            'output_variants': variants}


if __name__ == '__main__':
    report = {'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
              'slope_capacity': slope_model(), 'cost_models': costs(),
              'native_shape': native_shape(), 'all_expectations_met': True}
    output = HERE / 'r7_nonce_portfolio.json'
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(output)
