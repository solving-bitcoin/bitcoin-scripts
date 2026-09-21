#!/usr/bin/env python3
"""Actual 70-byte legacy signatures selected by the R8 interval/congruence join.

Isolated Core boundary fixtures, public d=1. No full covenant or 55-byte mining.
"""
import json
from pathlib import Path
import struct
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from core_gate_check import isolated_core_binary, p2sh, push
from core_regtest import Node, consensus_check, transaction
from legacy_same_signature_counterexample import G, N, add, hash256, signature_integer, verify
from r6_length_puzzle import with_locktime
from r8_batch_incidence import grid_join

KEY = bytes([2+(G[1] & 1)]) + G[0].to_bytes(32, 'big')
SCRIPT = b'\x82' + push(bytes([70])) + b'\x88' + push(KEY) + b'\xac'
assert len(SCRIPT) == 39


def nonce_rows():
    point, rows = None, []
    for k in range(1, 129):
        point = add(point, G)
        r = point[0] % N
        a = (r.bit_length()+8)//8
        if a < 32:
            continue
        b = 63-a
        rows.append({'k': k, 'r': r, 'r_der_bytes': a,
                     'low': 1 << (8*b-9), 'high': 1 << (8*b-1)})
    return rows


def encode(r, s):
    body = signature_integer(r) + signature_integer(s)
    return b'\x30' + bytes([len(body)]) + body + b'\x01'


def main():
    rows = nonce_rows()
    row_by_k = {r['k']: r for r in rows}
    binary, provenance = isolated_core_binary(Path('/private/tmp/covenant-core-30.3'), False)
    report = {'scope': __doc__, 'bitcoin_core': provenance, 'redeemscript': SCRIPT.hex(),
              'redeemscript_bytes': 39, 'p2sh_locking_script_bytes': 23,
              'public_signing_scalar': 1, 'nonce_point_additions': 128,
              'nonce_rows': rows, 'results': []}
    with tempfile.TemporaryDirectory(prefix='covenant-r8-batch-') as tmp:
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
            report['funding'] = funding

            def search(index, outputs, wanted_width=None, wanted_sign=None):
                for count in (4096, 16384, 65536):
                    digests = [hash256(with_locktime(funding['txid'], index, SCRIPT, outputs, nonce)
                                       + b'\x01\x00\x00\x00') for nonce in range(count)]
                    # Native ECDSA reduces 256-bit digests modulo the curve order.
                    scalars = [int.from_bytes(digest, 'big') % N for digest in digests]
                    hits, operations = grid_join(N, scalars, rows, 1)
                    for k, nonce, s in sorted(hits):
                        row = row_by_k[k]
                        raw_s = (scalars[nonce]+row['r'])*pow(k, -1, N) % N
                        sign = 1 if raw_s == s else -1
                        assert raw_s == sign*s % N
                        if wanted_width is not None and row['r_der_bytes'] != wanted_width:
                            continue
                        if wanted_sign is not None and sign != wanted_sign:
                            continue
                        sig = encode(row['r'], s)
                        assert len(sig) == 70 and verify(scalars[nonce], row['r'], s, G)[0]
                        return nonce, digests[nonce], sig, {
                            'nonce_scalar': k, 'nonce_sign': sign, 'r': hex(row['r']), 's': hex(s),
                            'r_der_bytes': row['r_der_bytes'], 'digest_table_items': count,
                            'grid_operations': operations}
                raise RuntimeError('Deterministic batch search cap exhausted')

            def check(name, index, nonce, digest, sig, outputs, expected, details):
                assert node.rpc('getrawmempool') == []
                script_sig = push(sig) + push(SCRIPT)
                raw = with_locktime(funding['txid'], index, script_sig, outputs, nonce)
                spend = {'hex': raw.hex(), 'txid': hash256(raw)[::-1].hex(), 'weight': 4*len(raw),
                         'total_bytes': len(raw), 'witness_bytes': 0}
                actual_digest = hash256(with_locktime(funding['txid'], index, SCRIPT, outputs, nonce)
                                        + b'\x01\x00\x00\x00')
                policy = node.rpc('testmempoolaccept', [spend['hex']])[0]
                consensus = consensus_check(node, address, spend)
                assert policy['allowed'] == expected and consensus['accepted'] == expected, (name, policy, consensus)
                if expected:
                    assert digest == actual_digest
                report['results'].append({'name': name, 'signing_sighash': digest.hex(),
                    'actual_spend_sighash': actual_digest.hex(), 'locktime_nonce': nonce,
                    'signature': sig.hex(), 'signature_bytes': len(sig),
                    'outputs': [{'amount': value, 'script_pubkey': script.hex()} for value, script in outputs],
                    'input_data_items': 1, 'hint_items': 0, 'combined_stack_peak_by_inspection': 3,
                    'script_sig_push_items': 2, 'script_sig_bytes': len(script_sig),
                    'executed_non_push_opcodes_redeem_if_success': 3 if expected else None,
                    'p2sh_additional_opcodes_if_success': 2 if expected else None,
                    'transaction': spend, 'policy': policy, 'consensus': consensus,
                    'evidence': 'differentially-validated',
                    'deployment_class': 'policy-validated' if expected else 'consensus-incompatible', **details})
                print('PASS', name, 'accepted=', expected, flush=True)

            for index, (width, sign) in enumerate(((32, 1), (32, -1), (33, 1), (33, -1))):
                outputs = [(990000, b'\x00\x14' + bytes([0x11+index])*20)]
                if index == 3:
                    outputs = [(490000, b'\x00\x14'+b'\x44'*20),
                               (500000, b'\x00\x14'+b'\x55'*20)]
                nonce, digest, sig, details = search(index, outputs, width, sign)
                check('batch-r%d-sign%+d' % (width, sign), index, nonce, digest, sig, outputs, True, details)
            outputs = [(990000, b'\x00\x14'+b'\x11'*20)]
            nonce, digest, sig, details = search(4, outputs)
            changed = [(990000, b'\x00\x14'+b'\x22'*20)]
            check('same-signature-changed-output', 4, nonce, digest, sig, changed, False, details)
            check('empty-signature', 4, nonce, digest, b'', outputs, False, {})
            # An independently valid d=1, k=1 signature whose length is not 70.
            for candidate in range(100):
                digest = hash256(with_locktime(funding['txid'], 4, SCRIPT, outputs, candidate)
                                 + b'\x01\x00\x00\x00')
                r = G[0] % N
                raw_s = (int.from_bytes(digest, 'big')+r) % N
                s = min(raw_s, N-raw_s)
                wrong = encode(r, s)
                if s and len(wrong) != 70:
                    assert verify(int.from_bytes(digest, 'big'), r, s, G)[0]
                    check('valid-signature-wrong-length', 4, candidate, digest, wrong, outputs, False,
                          {'nonce_scalar': 1, 'r': hex(r), 's': hex(s)})
                    break
            else:
                raise AssertionError('No wrong-length fixture')
            report['all_expectations_met'] = True
        finally:
            node.close()
    output = HERE/'r8_batch_core.json'
    output.write_text(json.dumps(report, indent=2)+'\n')
    print(output)


if __name__ == '__main__':
    main()
