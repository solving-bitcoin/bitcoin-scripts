#!/usr/bin/env python3
"""Range/congruence join for public small-nonce ECDSA candidates.

The grid algorithm is exact. Its cost experiment is small, deterministic host
research; no Core execution, full covenant, or large-budget search is claimed.
"""
from collections import defaultdict
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import random
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from legacy_same_signature_counterexample import G, N, add, mul, verify


def arcs(order, k, center, low, high):
    """Inclusive modular windows, each with its own congruence residue.

    All outputs z correspond to z+wrap*order=center+sign*k*s, low<=s<high.
    A window only brackets the progression: its congruence must also be tested.
    """
    assert 1 <= k < order and 1 <= low < high <= (order + 1) // 2
    assert k * (high - low - 1) < order
    out = []
    for sign in (1, -1):
        if sign == 1:
            left, right = center + k * low, center + k * (high - 1)
        else:
            left, right = center - k * (high - 1), center - k * low
        for wrap in range(left // order, right // order + 1):
            lo = max(left, wrap * order) - wrap * order
            hi = min(right, (wrap + 1) * order - 1) - wrap * order
            assert 0 <= lo <= hi < order
            out.append((lo, hi, (center - wrap * order) % k, sign, wrap))
    assert 2 <= len(out) <= 4
    return out


def grid_join(order, digests, rows, d):
    """Join canonical scalar digests 0<=z<order; callers reduce raw hashes."""
    assert digests and all(0 <= z < order for z in digests)
    # The proof does not require power-of-two bucket width. Large implementation
    # can use high bits, avoiding a division for each table insert.
    width = (order + len(digests) - 1) // len(digests)
    table = defaultdict(list)
    for index, z in enumerate(digests):
        table[z // width].append((index, z))
    counts = {'digest_insertions': len(digests), 'retained_nonce_rows': len(rows),
              'bucket_lookups': 0, 'bucket_entry_reads': 0, 'interval_candidates': 0,
              'congruence_tests': 0, 'modular_windows': 0, 'wrapped_windows': 0,
              'naive_pair_tests': len(rows) * len(digests)}
    hits = set()
    for row in rows:
        k, r, low, high = row['k'], row['r'], row['low'], row['high']
        center = -r * d % order
        windows = arcs(order, k, center, low, high)
        counts['modular_windows'] += len(windows)
        counts['wrapped_windows'] += sum(wrap != 0 for _, _, _, _, wrap in windows)
        for lo, hi, residue, sign, wrap in windows:
            for bucket in range(lo // width, hi // width + 1):
                counts['bucket_lookups'] += 1
                for index, z in table.get(bucket, ()):
                    counts['bucket_entry_reads'] += 1
                    if not lo <= z <= hi:
                        continue
                    counts['interval_candidates'] += 1
                    counts['congruence_tests'] += 1
                    if z % k != residue:
                        continue
                    signed_s = (z + wrap * order - center) // k
                    s = sign * signed_s
                    assert low <= s < high
                    assert (z + r * d - sign * k * s) % order == 0
                    hits.add((k, index, s))
    counts['distinct_hits'] = len(hits)
    counts['occupied_buckets'] = len(table)
    counts['bucket_width'] = width
    return hits, counts


def brute_join(order, digests, rows, d):
    hits = set()
    for row in rows:
        inv = pow(row['k'], -1, order)
        for index, z in enumerate(digests):
            raw = (z + row['r'] * d) * inv % order
            s = min(raw, -raw % order)
            if row['low'] <= s < row['high']:
                hits.add((row['k'], index, s))
    return hits


def boundary_checks():
    checks, wrap_cases = 0, 0
    for k in range(1, 8):
        for center in (0, 1, 50, 100):
            windows = arcs(101, k, center, 2, 7)
            expected = {(center + sign * k * s) % 101
                        for sign in (1, -1) for s in range(2, 7)}
            observed = {z for z in range(101)
                        if any(lo <= z <= hi and z % k == residue
                               for lo, hi, residue, _, _ in windows)}
            assert observed == expected
            checks += 101
            wrap_cases += sum(wrap != 0 for _, _, _, _, wrap in windows)
    for invalid in ([], [-1], [101], [102]):
        try:
            grid_join(101, invalid, [{'k': 1, 'r': 1, 'low': 2, 'high': 3}], 1)
        except AssertionError:
            pass
        else:
            raise AssertionError('Noncanonical or empty digest input was accepted')
    return {'fully_checked_memberships': checks, 'wrapped_window_cases': wrap_cases,
            'empty_or_noncanonical_digest_rejections': 4}


def toy_join():
    order, d = 65521, 7
    reports = []
    # Radix-16 widths are an intentionally small analogue, not DER bytes.
    for seed in (1701, 1702, 1703):
        for point_count, digest_count in ((32, 64), (64, 128), (128, 256)):
            rng = random.Random(seed)
            digests = [rng.randrange(order) for _ in range(digest_count)]
            rows = []
            for k in range(1, point_count + 1):
                r = 1 + int.from_bytes(hashlib.sha256(('%d:%d' % (seed, k)).encode()).digest(), 'big') % (order - 1)
                a = (r.bit_length() + 3) // 4
                if a < 3:
                    continue
                b = 5 - a
                rows.append({'k': k, 'r': r, 'low': 1 if b == 1 else 16 ** (b - 1),
                             'high': 16 ** b})
            actual, counts = grid_join(order, digests, rows, d)
            expected = brute_join(order, digests, rows, d)
            assert actual == expected
            reports.append({'seed': seed, 'point_candidates_generated': point_count,
                            'digest_count': digest_count, **counts})
    return {'order': order, 'public_scalar': d, 'minimum_r_radix16_width': 3,
            'target_r_plus_s_radix16_width': 5, 'cases': reports}


def actual_secp_vectors():
    d, qcount, count = 7, 96, 96
    rows, point = [], None
    low, high = 1 << 120, 1 << 121
    for k in range(1, count + 1):
        point = add(point, G)
        rows.append({'k': k, 'r': point[0] % N, 'low': low, 'high': high})
    digests = [int.from_bytes(hashlib.sha256(('r8-secp-%d' % i).encode()).digest(), 'big') % N
               for i in range(qcount)]
    planted = []
    for index, k in enumerate((1, 2, 7, 16, 31, 48, 65, 96)):
        row = rows[k - 1]
        sign = 1 if index % 2 == 0 else -1
        s = low + index + 1
        z = (sign * k * s - row['r'] * d) % N
        digests[index] = z
        planted.append({'k': k, 'sign': sign, 's': hex(s), 'z': hex(z), 'r': hex(row['r'])})
    actual, counts = grid_join(N, digests, rows, d)
    assert actual == brute_join(N, digests, rows, d)
    public_key = mul(d)
    for k, index, s in actual:
        assert verify(digests[index], rows[k - 1]['r'], s, public_key)[0]
    assert len(actual) >= len(planted)
    return {'scope': 'Planted algebraic scalar digests, not native transaction hashes or mined PoW.',
            'public_scalar': d, 'known_nonce_point_additions': count, 'digest_table_items': qcount,
            'short_s_interval': [hex(low), hex(high)], 'operation_counts': counts,
            'planted_cases': planted, 'verified_secp256k1_matches': len(actual)}


def polynomial_checks():
    primes, centers, roots = [3, 5, 7], [1, 2, 4], [9, 11, 17]
    modulus = math.prod(primes)
    crt = sum(c * (modulus // p) * pow(modulus // p, -1, p)
              for c, p in zip(centers, primes)) % modulus
    product = math.prod(crt - z for z in roots) % modulus
    for p, c in zip(primes, centers):
        assert product % p == math.prod(c - z for z in roots) % p
    assert (2 * 3) % 6 == 0 and all(z % 6 for z in (2, 3))
    heights = []
    for degree in (8, 16, 32, 64):
        poly = [1]
        for i in range(degree):
            root = int.from_bytes(hashlib.sha256(('r8-poly-%d' % i).encode()).digest(), 'big')
            result = [0] * (len(poly) + 1)
            for j, coefficient in enumerate(poly):
                result[j] -= root * coefficient
                result[j + 1] += coefficient
            poly = result
        heights.append({'degree': degree, 'coefficient_payload_bits': sum(abs(x).bit_length() for x in poly),
                        'largest_coefficient_bits': max(abs(x).bit_length() for x in poly)})
    return {'crt': crt, 'modulus': modulus, 'composite_zero_product_without_root': {'k': 6, 'roots': [2, 3]},
            'integer_product_polynomial_sizes': heights}


def cost_models():
    models = []
    for minimum_a in (24, 25):
        strata = []
        for a in range(minimum_a, 34):
            b = 48 - a
            u = Fraction(min(1 << (8 * a - 1), N) - (1 << (8 * a - 9)), N - 1)
            v = Fraction(2 * ((1 << (8 * b - 1)) - (1 << (8 * b - 9))), N)
            strata.append((float(u), float(v)))
        mass = sum(u * v for u, v in strata)
        choices = []
        for q_step in range(6000, 6601):
            qbits = q_step / 100
            q = 2 ** qbits
            # Surrogate only. Actual rows share the same digest table.
            t = sum(u * -math.expm1(q * math.log1p(-v)) for u, v in strata)
            candidates = q * mass / (t * t)
            choices.append({'digest_table_bits': qbits, 'point_count_mean_bits': -math.log2(t),
                            'input_only_bits': math.log2(q + 1 / t),
                            'full_last_row_candidate_charge_bits': math.log2(q + 1 / t + candidates),
                            'approx_candidate_reports_bits': math.log2(candidates)})
        best_input = min(choices, key=lambda x: x['input_only_bits'])
        best_scan = min(choices, key=lambda x: x['full_last_row_candidate_charge_bits'])
        models.append({'minimum_r_der_width': minimum_a, 'retained_pair_mass_bits': -math.log2(mass),
                       'independent_row_best_input_model': best_input,
                       'independent_row_best_full_scan_accounting_model': best_scan})
    return {'scope': 'Uncapped independent-row stream surrogate only; not fixed-portfolio waiting time or a proved runtime of the capped-window API.',
            'models': models}


if __name__ == '__main__':
    report = {'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
              'boundary_checks': boundary_checks(), 'toy_join': toy_join(),
              'secp_vectors': actual_secp_vectors(), 'crt_and_polynomial': polynomial_checks(),
              'cost_models': cost_models(), 'all_expectations_met': True}
    output = HERE / 'r8_batch_incidence.json'
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(output)
