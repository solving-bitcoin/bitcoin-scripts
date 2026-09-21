#!/usr/bin/env python3
"""Native BIP143 dependency test and scoped staged-grinding estimate.

No rare nonce search or non-extracting native transaction is executed. The
dependency test uses the real direct-context witness script and checks its
baseline digests against the funded Core fixture before making mutations.
"""
import hashlib
import json
import math
from pathlib import Path

from anchored_native_core_check import digest
from anchored_alternative_opening_cost import interval, P, N
from core_check import instructions
from legacy_same_signature_counterexample import G

HERE = Path(__file__).resolve().parent


def native_dependencies(built):
    pool = built['pools'][0]
    script = bytes.fromhex(pool['script_hex'])
    codes = [script[end:] for _, end, op, _ in instructions(script) if op == 0xab]
    assert len(codes) == 24
    tx = dict(version=2, locktime=0,
        vin=[dict(txid=built['funding']['txid'], vout=i, sequence=0xffffffff)
             for i in range(built['pool_count']+1)],
        vout=[dict(value=0.9985, scriptPubKey=dict(hex='5120'+f'{G[0]:064x}'))])
    tx['vin'][0]['sequence'] -= built['opening_transaction_attempts']-1
    # Verify the exact baseline native hash boundary, not an arbitrary z model.
    for slot, frame in enumerate(pool['frames']):
        for j, check in enumerate(frame['short_checks']):
            assert digest(tx, 1, codes[slot*6+j], check['flag']).hex() == check['digest']
    # Add a corresponding output for input 1 and one extra data output.
    # These variant preimages are not claimed to be Core-validated spends.
    tx['vout'][0]['value'] -= 0.00001
    tx['vout'] += [dict(value=0.00001, scriptPubKey=dict(hex='0020'+'11'*32)),
                   dict(value=0., scriptPubKey=dict(hex='6a20'+'22'*32))]
    flags = [130, 130, 131, 3, 1, 1]
    def hashes(current):
        return [digest(current, 1, codes[i], flag).hex() for i, flag in enumerate(flags)]
    before = hashes(tx)
    stages = []
    for name, expected in [
        ('own-sequence', [True]*6),
        ('corresponding-output', [False, False, True, True, True, True]),
        ('other-input-outpoint', [False, False, False, True, True, True]),
        ('noncorresponding-output', [False, False, False, False, True, True]),
    ]:
        if name == 'own-sequence':
            tx['vin'][1]['sequence'] -= 1
        elif name == 'corresponding-output':
            tx['vout'][1]['scriptPubKey']['hex'] = '0020'+'33'*32
        elif name == 'other-input-outpoint':
            tx['vin'][0]['txid'] = hashlib.sha256(b'different-valid-ancestor-would-be-required').hexdigest()
        else:
            tx['vout'][2]['scriptPubKey']['hex'] = '6a20'+'44'*32
        after = hashes(tx)
        changed = [x != y for x, y in zip(before, after)]
        assert changed == expected, name
        stages.append(dict(mutation=name, changed_contexts=changed,
            previous_digests=before, new_digests=after))
        before = after
    return dict(baseline_digests_matched=24, flags=flags, stages=stages,
        scope='Real BIP143 suffix digests and baseline funded fixture. The mutated outpoint is a dependency fixture, not an existing UTXO; a real attack must generate its replacement ancestor.')


def estimate(rbytes, q, flags=4):
    rlo, rhi = interval(rbytes)
    slo, shi = interval(53-rbytes)
    pr = (rhi-rlo)/P
    ps = 2*(shi-slo)/N
    p_round = -math.expm1(q*flags*math.log1p(-ps))
    groups = [2, 1, 1, 2]
    stage_logs = [-d*math.log2(p_round) for d in groups]
    checks = [log_trials+math.log2(d*q*flags) for d,log_trials in zip(groups, stage_logs)]
    peak = max(checks)
    total_checks = peak+math.log2(sum(2**(v-peak) for v in checks))
    return dict(r_der_bytes=rbytes, s_der_bytes=53-rbytes,
        groups=groups, nonces_per_context=q, distinct_nonces=6*q,
        raw_flags_per_context=flags,
        log2_nonce_point_trials=math.log2(6*q/pr),
        log2_stage_transaction_trials=stage_logs,
        log2_total_scalar_signature_checks=total_checks)


def main():
    source=HERE/'direct-context-publication-transactions.json'
    built=json.loads(source.read_text())
    rows=[estimate(width, q) for width in range(22,31)
          for q in sorted(set(range(1,17)) | {1 << i for i in range(5,41)})]
    best=min(rows,key=lambda r:max(r['log2_nonce_point_trials'],r['log2_total_scalar_signature_checks']))
    report=dict(evidence='locally-reproduced', deployment='unclassified',
        scope=__doc__, source_fixture_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        native_dependency_test=native_dependencies(built),
        staged_cost_model=dict(evidence='inspected', best_screened=best,
            warning='Heuristic estimate of one strategy avoiding known/repeated nonces; no attack executed, no lower bound, no general extraction impossibility. Group trials, scalar checks, native hashes and ancestor work are distinct costs. Four raw flags per class deliberately ignores extra ALL-type choices.'),
        all_expectations_met=True)
    (HERE/'direct-context-staged-sighashes.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(best,indent=2))


if __name__ == '__main__':
    main()
