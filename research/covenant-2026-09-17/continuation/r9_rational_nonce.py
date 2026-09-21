#!/usr/bin/env python3
"""Bounded comparison of dyadic public nonce portfolios and interval grids.

Host algebra and deterministic counters only. No covenant or Core claim.
"""
from fractions import Fraction
from collections import defaultdict
import hashlib
import json
import math
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from legacy_same_signature_counterexample import N, G, add, mul, verify
from r8_batch_incidence import arcs, grid_join, brute_join


def preimage_join(order, original, original_grid, bucket_width, rows, d, b):
    hits = set()
    counts = {'nonempty_preimage_intervals': 0, 'bucket_lookups': 0,
              'bucket_entry_reads': 0, 'interval_candidates': 0,
              'on_demand_digest_transforms': 0, 'congruence_tests': 0}
    for row in rows:
        a, center = row['k'], -row['r'] * d % order
        for lo, hi, residue, sign, wrap in arcs(order, a, center, row['low'], row['high']):
            for t in range(b):
                zlo = max(0, (lo + t * order + b - 1) // b)
                zhi = min(order - 1, (hi + t * order) // b)
                if zlo > zhi:
                    continue
                counts['nonempty_preimage_intervals'] += 1
                for bucket in range(zlo // bucket_width, zhi // bucket_width + 1):
                    counts['bucket_lookups'] += 1
                    for index, z in original_grid.get(bucket, ()):
                        counts['bucket_entry_reads'] += 1
                        if not zlo <= z <= zhi:
                            continue
                        counts['interval_candidates'] += 1
                        counts['on_demand_digest_transforms'] += 1
                        y = b * z % order
                        assert lo <= y <= hi
                        counts['congruence_tests'] += 1
                        if y % a != residue:
                            continue
                        s = sign * (y + wrap * order - center) // a
                        assert row['low'] <= s < row['high']
                        hits.add((a, index, s))
    return hits, counts


def numerator_sets(cap, denominators):
    return [list(range(1, cap + 1, 1 if j == 0 else 2)) for j in range(denominators)]


def duplicate_check(cap, denominators):
    maximum_denominator = 1 << (denominators - 1)
    assert 2 * cap * maximum_denominator < N
    raw = [(a, 1 << j) for j in range(denominators) for a in range(1, cap + 1)]
    fractions = {Fraction(a, b) for a, b in raw}
    scalars = {a * pow(b, -1, N) % N for a, b in raw}
    unique = [(a, 1 << j) for j, values in enumerate(numerator_sets(cap, denominators)) for a in values]
    assert len(unique) == len(fractions) == len(scalars)
    assert len({Fraction(a, b) for a, b in unique}) == len(unique)
    assert not any((-k % N) in scalars for k in scalars)
    folded = [a * (maximum_denominator // b) for a, b in unique]
    count = len(unique)
    assert len(set(folded)) == count
    assert sum(folded) >= count * (count + 1) // 2
    weight = sum(a for a, _ in unique)
    if cap % 2 == 0:
        assert Fraction(weight, 1) == Fraction(count * (count + 1), denominators + 1)
    return {'numerator_cap': cap, 'denominator_count': denominators,
            'raw_fraction_count': len(raw), 'distinct_scalar_classes_up_to_sign': count,
            'duplicate_fractions_removed': len(raw) - count,
            'dyadic_numerator_sum': weight,
            'same_size_dense_integer_numerator_sum': count * (count + 1) // 2,
            'folded_common_denominator': maximum_denominator,
            'folded_maximum_numerator': max(folded), 'folded_numerator_sum': sum(folded)}


def real_curve_join(cap=16, denominators=4, digest_count=128):
    d = 7
    original = [int.from_bytes(hashlib.sha256(('r9-original-%d' % i).encode()).digest(), 'big') % N
                for i in range(digest_count)]
    transformed = original[:]
    bucket_width = (N + digest_count - 1) // digest_count
    original_grid = defaultdict(list)
    for index, z in enumerate(original):
        original_grid[z // bucket_width].append((index, z))
    public_key = mul(d)
    reports, total_hits = [], set()
    nsets = numerator_sets(cap, denominators)
    for j, values in enumerate(nsets):
        b = 1 << j
        if j:
            transformed = [2 * z % N for z in transformed]
        assert transformed == [b * z % N for z in original]
        base = G if j == 0 else mul(pow(b, -1, N))
        step = base if j == 0 else add(base, base)
        point = base
        rows, originals = [], {}
        for index, a in enumerate(values):
            if index:
                point = add(point, step)
            r = point[0] % N
            width = (r.bit_length() + 8) // 8
            if width < 32:
                continue
            s_width = 63 - width  # Exactly 70-byte signature item.
            low, high = 1 << (8 * s_width - 9), 1 << (8 * s_width - 1)
            assert a * (high - low - 1) < N
            rows.append({'k': a, 'r': b * r % N, 'low': low, 'high': high})
            originals[a] = (r, a * pow(b, -1, N) % N)
        hits, counts = grid_join(N, transformed, rows, d)
        assert hits == brute_join(N, transformed, rows, d)
        reused_hits, reused_counts = preimage_join(N, original, original_grid, bucket_width, rows, d, b)
        assert reused_hits == hits
        for a, index, s in hits:
            actual_r, k = originals[a]
            assert verify(original[index], actual_r, s, public_key)[0]
            total_hits.add((k, index, s))
        reports.append({'denominator': b, 'distinct_nonce_points_generated': len(values),
                        'new_digest_hashes': digest_count if j == 0 else 0,
                        'modular_doublings_for_table_reuse': digest_count if j else 0,
                        'point_increment_additions': len(values) - 1,
                        'point_step_doublings': 1 if j else 0,
                        'base_scalar_multiplications': 1 if j else 0,
                        'original_grid_preimage_strategy': reused_counts, **counts})
    assert total_hits
    return {'scope': 'Actual secp256k1 equations and deterministic hash-label digests; synthetic messages, not native transactions.',
            'numerator_cap': cap, 'denominator_count': denominators, 'digest_count': digest_count,
            'public_signing_scalar': d, 'retained_r_der_width_at_least': 32,
            'complete_signature_item_bytes_if_serialized': 70,
            'unique_original_digest_hashes': digest_count,
            'tables_built': denominators, 'total_grid_insertions': denominators * digest_count,
            'total_modular_digest_doublings': (denominators - 1) * digest_count,
            'maximum_live_digest_records_in_streaming_layout': digest_count,
            'verified_distinct_curve_signature_matches': len(total_hits), 'tables': reports}


def work_proxy():
    # This minimizes a fixed expected-incidence proxy RQF=lambda. It does not
    # approximate E[1/actual acceptance union] or establish expected time to hit.
    regimes = [
        ('unit-costs', 1, 1, 1, 1, 1),
        ('expensive-native-hash', 64, 1, 1, 1, 1),
        ('expensive-point-and-hash', 64, 16, 1, 1, 1),
    ]
    out = []
    for name, h, p, index_cost, transform, candidate in regimes:
        rows = []
        for D in range(1, 9):
            alpha = h + index_cost * D + transform * (D - 1)
            beta = p + candidate / (D + 1)
            factor = 2 * math.sqrt(alpha * beta)
            rows.append({'denominator_count': D,
                         'digest_side_coefficient': alpha, 'point_side_coefficient': beta,
                         'optimal_digest_to_point_count_ratio': beta / alpha,
                         'coefficient_multiplying_one_over_sqrt_pair_mass': factor})
        baseline = rows[0]['coefficient_multiplying_one_over_sqrt_pair_mass']
        for row in rows:
            row['cost_ratio_to_one_denominator_proxy'] = row['coefficient_multiplying_one_over_sqrt_pair_mass'] / baseline
        out.append({'regime': name, 'assumed_costs': {'hash': h, 'point': p, 'grid_insert': index_cost,
                                                   'transform': transform, 'candidate': candidate},
                    'best_denominator_count_among_1_to_8': min(rows, key=lambda x: x['cost_ratio_to_one_denominator_proxy'])['denominator_count'],
                    'rows': rows})
    return {'scope': 'Fixed expected-pair-count proxy lambda=1 only; NOT expected total work until a solution.',
            'regimes': out}


if __name__ == '__main__':
    report = {'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
              'duplicate_and_folding_checks': [duplicate_check(a, d) for a, d in ((15, 4), (16, 4), (32, 8), (60, 2))],
              'curve_join': real_curve_join(), 'work_proxy': work_proxy(),
              'all_expectations_met': True}
    path = HERE / 'r9_rational_nonce.json'
    path.write_text(json.dumps(report, indent=2) + '\n')
    print(path)
