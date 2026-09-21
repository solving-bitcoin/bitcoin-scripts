#!/usr/bin/env python3
"""Exact known-nonce DER-length probability, with optional isolated Core checks.

Raw boundary fixture, not full Binohash, QSB or a covenant. All keys are public.
"""
import argparse
from fractions import Fraction
import json
import math
from pathlib import Path
import struct
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from core_gate_check import isolated_core_binary, p2sh, push
from core_regtest import Node, consensus_check, transaction
from legacy_same_signature_counterexample import N, mul, hash256, signature_integer, verify
from second_pass_structure import raw_tx

R = mul(pow(2, -1, N))
r = R[0] % N
Q = mul(pow(r, -1, N))
PUBLIC_KEY = bytes([2 + (Q[1] & 1)]) + Q[0].to_bytes(32, 'big')
SCRIPT = b'\x82' + push(bytes([59])) + b'\x88' + push(PUBLIC_KEY) + b'\xac'
assert len(signature_integer(r)) - 2 == 21
assert len(SCRIPT) == 39


def intervals(order, low, high):
    """Inclusive z intervals for low <= min(2(z+1),-2(z+1)) mod n < high."""
    rows = []
    for sign, lower, upper in ((1, low, high), (-1, order-high+1, order-low+1)):
        for parity in (0, 1):
            first = lower + ((parity-lower) % 2)
            last = upper - 1 - ((upper-1-parity) % 2)
            if first > last:
                continue
            start = (first + parity*order)//2 - 1
            end = (last + parity*order)//2 - 1
            assert 0 <= start <= end < order
            rows.append({'sign': sign, 's_raw_parity': parity, 'start': start, 'end': end})
    return rows


def raw_count(rows, order, domain):
    assert order <= domain < 2*order
    extra = domain-order
    return sum(x['end']-x['start']+1 + max(0, min(x['end']+1, extra)-x['start']) for x in rows)


def der_signature(z):
    s_raw = (2*(z+1)) % N
    if s_raw == 0:
        return None
    s = min(s_raw, N-s_raw)
    body = signature_integer(r) + signature_integer(s)
    return b'\x30' + bytes([len(body)]) + body + b'\x01'


def host_report():
    toy = []
    for order, domain, low, high in [(251,256,1,8), (251,256,8,64),
                                    (257,512,1,8), (257,512,8,128),
                                    (509,512,1,128), (509,512,128,254)]:
        rows = intervals(order, low, high)
        accepted = [z for z in range(domain)
                    if low <= min(2*(z+1)%order, -2*(z+1)%order) < high]
        from_windows = [z for z in range(domain)
                        if any(x['start'] <= z%order <= x['end'] for x in rows)]
        assert accepted == from_windows
        assert len(accepted) == raw_count(rows, order, domain)
        toy.append({'order': order, 'digest_domain': domain, 'low': low, 'high': high,
                    'accepted_count': len(accepted)})
    cases = []
    for length in (31, 30, 27, 26):
        low, high = 1 << (8*(length-1)-1), 1 << (8*length-1)
        rows = intervals(N, low, high)
        count = raw_count(rows, N, 1 << 256)
        probability = Fraction(count, 1 << 256)
        assert probability == Fraction(255, 1 << (8*(32-length)+8))
        for row in rows:
            for z in (row['start'], row['end']):
                sig = der_signature(z)
                assert len(sig) == 28+length
                s = min(2*(z+1)%N, -2*(z+1)%N)
                assert verify(z, r, s, Q)[0]
            for z in (row['start']-1, row['end']+1):
                assert not low <= min(2*(z+1)%N, -2*(z+1)%N) < high
        cases.append({'signature_bytes': 28+length, 's_der_bytes': length,
                      'raw_digest_intervals': rows, 'accepted_digest_count': count,
                      'probability': str(probability), 'expected_query_bits': -math.log2(probability),
                      'zero_prefix_strategy_bits': 8*(32-length)+2})
    return {'scope': __doc__, 'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
            'toy_exhaustive_checks': toy, 'known_nonce_r': r, 'public_key': PUBLIC_KEY.hex(),
            'cases': cases, 'all_expectations_met': True}


def with_locktime(txid, index, script, outputs, locktime):
    return raw_tx([(txid, index, script)], outputs)[:-4] + struct.pack('<I', locktime)


def core_report():
    binary, provenance = isolated_core_binary(Path('/private/tmp/covenant-core-30.3'), False)
    windows = intervals(N, 1 << 239, 1 << 247)
    out = {'bitcoin_core': provenance, 'redeemscript': SCRIPT.hex(), 'redeemscript_bytes': 39,
           'locking_script_bytes': 23, 'results': []}
    with tempfile.TemporaryDirectory(prefix='covenant-r6-length-') as tmp:
        node = Node(binary, Path(tmp))
        try:
            node.ready()
            address = node.rpc('decodescript', '51')['segwit']['address']
            mining_script = bytes.fromhex(node.rpc('validateaddress', address)['scriptPubKey'])
            blocks = []
            for _ in range(101):
                node.tick()
                blocks += node.rpc('generatetoaddress', 1, address)
            cb = node.rpc('getblock', blocks[0], 2)['tx'][0]
            coin = next(o for o in cb['vout'] if o['scriptPubKey']['hex'] == mining_script.hex())
            funding = transaction(cb['txid'], coin['n'], [b'\x51'],
                                  [(1000000, p2sh(SCRIPT))]*5 + [(4994990000, mining_script)])
            assert consensus_check(node, address, funding)['accepted']
            out['funding'] = funding
            outputs = [(990000, b'\x00\x14' + b'\x11'*20)]

            def search(index, branch=None, size=59):
                for nonce in range(1 << 20):
                    digest = hash256(with_locktime(funding['txid'], index, SCRIPT, outputs, nonce) + b'\x01\x00\x00\x00')
                    z = int.from_bytes(digest, 'big')
                    sig = der_signature(z)
                    if sig is not None and len(sig) == size:
                        if branch is None or windows[branch]['start'] <= z%N <= windows[branch]['end']:
                            s = min(2*(z+1)%N, -2*(z+1)%N)
                            assert verify(z, r, s, Q)[0]
                            return nonce, digest, sig
                raise RuntimeError('Deterministic fixture search cap exhausted')

            def check(name, index, nonce, digest, sig, tx_outputs, expected, **details):
                assert node.rpc('getrawmempool') == []
                script_sig = push(sig) + push(SCRIPT)
                raw = with_locktime(funding['txid'], index, script_sig, tx_outputs, nonce)
                spend = {'hex': raw.hex(), 'txid': hash256(raw)[::-1].hex(),
                         'weight': 4*len(raw), 'total_bytes': len(raw), 'witness_bytes': 0}
                policy = node.rpc('testmempoolaccept', [spend['hex']])[0]
                result = consensus_check(node, address, spend)
                assert result['accepted'] == expected and policy['allowed'] == expected, (name, result, policy)
                z = int.from_bytes(digest, 'big')
                actual_digest = hash256(with_locktime(funding['txid'], index, SCRIPT, tx_outputs, nonce) + b'\x01\x00\x00\x00')
                if expected:
                    assert actual_digest == digest
                out['results'].append({'name': name, 'signing_sighash': digest.hex(),
                    'actual_spend_sighash': actual_digest.hex(), 'locktime_nonce': nonce,
                    'leading_zero_bits': 256-z.bit_length(), 'signature': sig.hex(),
                    'signature_bytes': len(sig), 'input_data_items': 1, 'hint_items': 0,
                    'script_sig_push_items': 2, 'script_sig_bytes': len(script_sig),
                    'combined_stack_peak_by_inspection': 3, 'executed_non_push_opcodes_redeem_if_success': 3 if expected else None,
                    'p2sh_additional_opcodes_if_success': 2 if expected else None,
                    'transaction': spend, 'policy': policy, 'consensus': result,
                    'evidence': 'differentially-validated',
                    'deployment_class': 'policy-validated' if expected else 'consensus-incompatible', **details})
                print('PASS', name, 'leading_zero_bits=', 256-z.bit_length(), 'accepted=', expected)

            for branch in range(4):
                nonce, digest, sig = search(branch, branch)
                check('accepted-digest-window-%d' % branch, branch, nonce, digest, sig, outputs, True,
                      window=windows[branch], candidates_tried=nonce+1)
            nonce, digest, sig = search(4, size=60)
            check('wrong-length-60', 4, nonce, digest, sig, outputs, False)
            nonce, digest, sig = search(4)
            changed = [(990000, b'\x00\x14' + b'\x22'*20)]
            check('same-signature-changed-output', 4, nonce, digest, sig, changed, False)
            check('empty-signature', 4, nonce, digest, b'', outputs, False)
            out['all_expectations_met'] = True
        finally:
            node.close()
    return out


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', action='store_true')
    parser.add_argument('--output', type=Path, default=HERE/'r6_length_puzzle.json')
    args = parser.parse_args()
    report = host_report()
    if args.core:
        report['core'] = core_report()
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print('Exact counts and all requested checks passed:', args.output)
