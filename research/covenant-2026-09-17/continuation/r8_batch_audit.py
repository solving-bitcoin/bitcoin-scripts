#!/usr/bin/env python3
"""Independent deterministic audit of the R8 range/congruence batch API.

Writes only its own JSON. The forward-enumeration reference below does not use
the implementation's brute_join or modular-inverse signing formula. No Core
execution, repository Script executor, or field-library tests are invoked.
"""
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import random

HERE = Path(__file__).resolve().parent
IMPLEMENTATION = HERE / 'r8_batch_incidence.py'
SPEC = importlib.util.spec_from_file_location('audited_batch_incidence', IMPLEMENTATION)
BATCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BATCH)


def exhaustive_arcs():
    counts = Counter()
    memberships = 0
    wraps = Counter()
    for order in (5, 7, 11, 13, 17, 19):
        for k in range(1, order):
            for low in range(1, (order+1)//2):
                for high in range(low+1, (order+1)//2+1):
                    if k*(high-low-1) >= order:
                        continue
                    for center in range(order):
                        windows = BATCH.arcs(order, k, center, low, high)
                        expected = {(center+sign*k*s) % order
                                    for sign in (-1, 1) for s in range(low, high)}
                        observed = {z for z in range(order)
                                    if any(a <= z <= b and z % k == residue
                                           for a, b, residue, _, _ in windows)}
                        assert observed == expected, (order, k, low, high, center)
                        for _, _, _, _, wrap in windows:
                            wraps['negative' if wrap < 0 else 'positive' if wrap > 0 else 'zero'] += 1
                        counts[order] += 1
                        memberships += order
    assert sum(counts.values()) == 18258
    return {'primes': list(counts), 'all_k': '1..order-1',
            'all_centers': '0..order-1',
            'all_intervals': '1<=low<high<=(order+1)//2 with k*(high-low-1)<order',
            'configurations_by_prime': dict(counts),
            'configurations': sum(counts.values()),
            'individual_membership_comparisons': memberships,
            'windows_by_wrap_sign': dict(wraps)}


def forward_join(order, digests, rows, d):
    # Independent reference: enumerate the allowed low-S values and both nonce
    # signs, then match canonical digests. No arcs, buckets or inverse formula.
    hits = set()
    for row in rows:
        k = row['k']
        center = -row['r']*d % order
        for s in range(row['low'], row['high']):
            allowed = {(center+sign*k*s) % order for sign in (-1, 1)}
            for index, z in enumerate(digests):
                if z in allowed:
                    hits.add((k, index, s))
    return hits


def grid_cases():
    seed = 8171
    rng = random.Random(seed)
    records = []
    for order in (5, 7, 11, 13, 17, 19, 31, 101):
        for trial in range(20):
            d = rng.randrange(order)
            digests = [0, order-1] + [rng.randrange(order)
                                     for _ in range(rng.randrange(1, 2*order))]
            rows = []
            for k in range(1, order):
                low = rng.randrange(1, (order+1)//2)
                high = rng.randrange(low+1, (order+1)//2+1)
                if k*(high-low-1) < order:
                    rows.append({'k': k, 'r': rng.randrange(order), 'low': low, 'high': high})
            actual, metrics = BATCH.grid_join(order, digests, rows, d)
            expected = forward_join(order, digests, rows, d)
            assert actual == expected, (order, trial)
            transcript = {'order': order, 'd': d, 'digests': digests, 'rows': rows}
            records.append({'order': order, 'trial': trial, 'digest_items': len(digests),
                            'retained_rows': len(rows), 'hits': len(actual),
                            'input_sha256': hashlib.sha256(json.dumps(transcript, sort_keys=True).encode()).hexdigest(),
                            'bucket_entry_reads': metrics['bucket_entry_reads']})
    assert len(records) == 160
    return {'rng': 'Python random.Random', 'seed': seed,
            'primes': [5, 7, 11, 13, 17, 19, 31, 101],
            'trials_per_prime': 20, 'cases': len(records),
            'reference': 'direct forward enumeration over low-S interval and both nonce signs',
            'includes': 'canonical endpoint digests, duplicate digests, random row subsets and bucket boundaries',
            'records': records}


def api_regression():
    row = {'k': 1, 'r': 1, 'low': 2, 'high': 3}
    rejects = []
    for invalid in ([], [-1], [101], [102]):
        try:
            BATCH.grid_join(101, invalid, [row], 1)
        except AssertionError:
            rejects.append(invalid)
        else:
            raise AssertionError(('missing canonical-input rejection', invalid))
    normalized_hits = BATCH.grid_join(101, [102 % 101], [row], 1)[0]
    assert normalized_hits == {(1, 0, 2)}
    return {'original_counterexample': {
                'order': 101, 'raw_digest': 102, 'd': 1, 'row': row,
                'historically_observed_unchecked_grid_hits': [],
                'correct_hit_after_scalar_reduction': [[1, 0, 2]],
                'reason': 'Raw102 occupies bucket1; every canonical arc lies in bucket0 when width101.'},
            'current_contract': 'nonempty canonical scalars 0<=z<order; caller reduces raw hashes',
            'currently_rejected_inputs': rejects,
            'normalized_original_counterexample_passes': True}


def recorded_core_artifact():
    path = HERE / 'r8_batch_core.json'
    if not path.exists():
        return {'available': False}
    source = json.loads(path.read_text())
    script = bytes.fromhex(source['redeemscript'])
    observations = []
    for item in source['results']:
        raw = bytes.fromhex(item['transaction']['hex'])
        assert raw[4] == 1  # This fixture is a legacy transaction with one input.
        length = raw[41]
        assert length < 253
        script_sig = raw[42:42+length]
        assert length == item['script_sig_bytes']
        sig = bytes.fromhex(item['signature'])
        assert script_sig == bytes([len(sig)])+sig+bytes([len(script)])+script
        preimage = raw[:41]+bytes([len(script)])+script+raw[42+length:]+b'\x01\0\0\0'
        digest = hashlib.sha256(hashlib.sha256(preimage).digest()).digest()
        assert digest.hex() == item['actual_spend_sighash']
        assert 4*len(raw) == item['transaction']['weight']
        assert hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex() == item['transaction']['txid']
        mathematically_valid = False
        if sig:
            assert sig[0] == 0x30 and sig[1] == len(sig)-3 and sig[2] == 2 and sig[-1] == 1
            r_width = sig[3]
            assert sig[4+r_width] == 2
            s_width = sig[5+r_width]
            assert r_width+s_width+7 == len(sig)
            r = int.from_bytes(sig[4:4+r_width], 'big')
            s = int.from_bytes(sig[6+r_width:6+r_width+s_width], 'big')
            z = int.from_bytes(digest, 'big') % BATCH.N
            mathematically_valid = BATCH.verify(z, r, s, BATCH.G)[0]
            if item['consensus']['accepted']:
                assert r_width == item['r_der_bytes']
                assert BATCH.mul(item['nonce_scalar'])[0] % BATCH.N == r
                assert BATCH.mul(s*item['nonce_sign']*item['nonce_scalar']) == BATCH.mul(z+r)
        predicate_valid = len(sig) == 70 and mathematically_valid
        assert predicate_valid == item['consensus']['accepted'] == item['policy']['allowed']
        observations.append({'name': item['name'], 'signature_bytes': len(sig),
                             'native_signature_equation': mathematically_valid,
                             'size_and_signature_predicate': predicate_valid,
                             'transaction_weight': item['transaction']['weight']})
    return {'available': True, 'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'source': str(path), 'scope': 'Read-only serialized-sighash and group-equation replay; Core not rerun',
            'cases': len(observations), 'observations': observations}


def main():
    report = {'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
              'scope': 'Independent host audit only; no Core or covenant validation',
              'implementation': str(IMPLEMENTATION),
              'implementation_sha256': hashlib.sha256(IMPLEMENTATION.read_bytes()).hexdigest(),
              'exhaustive_arcs': exhaustive_arcs(), 'grid_comparison': grid_cases(),
              'canonical_input_regression': api_regression(),
              'recorded_core_artifact': recorded_core_artifact(), 'all_expectations_met': True}
    output = Path(__file__).with_suffix('.json')
    output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'arc_configurations': report['exhaustive_arcs']['configurations'],
                      'membership_comparisons': report['exhaustive_arcs']['individual_membership_comparisons'],
                      'grid_cases': report['grid_comparison']['cases'],
                      'api_rejections': len(report['canonical_input_regression']['currently_rejected_inputs']),
                      'artifact': str(output)}, indent=2))


if __name__ == '__main__':
    main()
