#!/usr/bin/env python3
"""Isolated Core checks of routing and recovery-set boundary vectors.

The routing fixtures deliberately omit both rare DER gates and the native
root-binding check. They validate routing only; no two-hit PoW was mined.
Raw bytecode is intentional, not an optimized repository primitive metric.
"""
import argparse
import json
from pathlib import Path
import struct
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from core_gate_check import isolated_core_binary, p2sh
from core_regtest import Node, consensus_check, transaction
from second_pass_structure import raw_tx, serialize
from legacy_same_signature_counterexample import N, P, add, mul, hash256, verify
from search1_nonce_encoding import num_bytes, push, push_num

SIG = bytes.fromhex('300602010102010101')


def two_keys_script(separator):
    # Entry Q0 Q1. Enforce canonical compressed length and distinct points.
    script = b''
    for depth in (1, 0):
        script += push_num(depth) + b'\x79\x82' + push_num(33) + b'\x88\x75'
    script += b'\x51\x79\x51\x79\x87\x91\x69'
    for context in range(2):
        if context and separator:
            script += b'\xab'
        for depth in (2, 1):
            script += push(SIG) + push_num(depth) + b'\x79\xad'
    return script + b'\x6d\x51'


def compressed(point):
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, 'big')


def recovery_keys(txid, index, script_code, outputs):
    digest = hash256(raw_tx([(txid, index, script_code)], outputs) + struct.pack('<I', 1))
    z = int.from_bytes(digest, 'big') % N
    y = pow(8, (P + 1) // 4, P)
    assert y * y % P == 8
    keys = [add((1, yy), mul(-z % N)) for yy in (y, -y % P)]
    assert all(verify(z, 1, 1, key)[0] for key in keys)
    return [compressed(key) for key in keys], digest.hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=HERE / 'core_fragments.json')
    args = parser.parse_args()
    binary, provenance = isolated_core_binary(Path('/private/tmp/covenant-core-30.3'), False)
    vectors = json.loads((HERE / 'search1_nonce_encoding.json').read_text())['observable_vectors']
    routes = [bytes.fromhex(row['script_hex']) for row in vectors]
    same = two_keys_script(False)
    different = two_keys_script(True)
    scripts = routes + [same, different]
    report = {'bitcoin_core': provenance, 'scope': __doc__, 'results': []}
    with tempfile.TemporaryDirectory(prefix='covenant-seven-core-') as tmp:
        node = Node(binary, Path(tmp))
        try:
            node.ready()
            address = node.rpc('decodescript', '51')['segwit']['address']
            mining_script = bytes.fromhex(node.rpc('validateaddress', address)['scriptPubKey'])
            hashes = []
            for _ in range(101):
                node.tick()
                hashes += node.rpc('generatetoaddress', 1, address)
            cb = node.rpc('getblock', hashes[0], 2)['tx'][0]
            coin = next(o for o in cb['vout'] if o['scriptPubKey']['hex'] == mining_script.hex())
            funding_outputs = [(1000000, p2sh(s)) for s in scripts]
            funding_outputs.append((5000000000 - 1000000 * len(scripts) - 10000, mining_script))
            funding = transaction(cb['txid'], coin['n'], [b'\x51'], funding_outputs)
            assert consensus_check(node, address, funding)['accepted']
            report['funding'] = funding

            def check(name, index, items, expected, **details):
                script_sig = b''.join(push(x) for x in items) + push(scripts[index])
                outputs = [(990000, b'\x00\x14' + b'\x11' * 20)]
                spend = serialize([(funding['txid'], index, script_sig)], outputs)
                policy = node.rpc('testmempoolaccept', [spend['hex']])[0]
                result = consensus_check(node, address, spend)
                assert result['accepted'] == expected, (name, result)
                report['results'].append({
                    'name': name, 'redeemscript_hex': scripts[index].hex(),
                    'redeemscript_bytes': len(scripts[index]), 'locking_script_bytes': 23,
                    'input_items_hex': [x.hex() for x in items], 'input_items': len(items),
                    'script_sig_bytes': len(script_sig), 'script_sig_push_items': len(items)+1,
                    'transaction': spend, 'consensus': result, 'policy': policy,
                    'evidence': 'differentially-validated',
                    'deployment_class': ('policy-validated' if policy['allowed'] else 'consensus-validated') if expected else 'consensus-incompatible',
                    **details,
                })
                print('PASS', name, 'consensus=', expected, 'policy=', policy['allowed'])
                if expected:
                    node.rpc('invalidateblock', result['block_hash'])

            for i, row in enumerate(vectors):
                items = [bytes.fromhex(x) for x in row['input_items_hex']]
                check('routing-observable-%d' % i, i, items, True, hint_items=60,
                      measured_boundary='complete-transaction: observable routing only; excludes DER gates and native root binding',
                      combined_stack_peak_by_inspection=max(row['host_evaluation']['peak'], len(items)+2),
                      executed_non_push_opcodes_redeem=row['host_evaluation']['opcodes'])
            base = [bytes.fromhex(x) for x in vectors[0]['input_items_hex']]
            for position in (0, 29, 59):
                bad = base.copy()
                bad[-2-position] = num_bytes(2)
                check('routing-invalid-index-stage-%d' % position, 0, bad, False, hint_items=60)
            check('routing-extra-entry-item', 0, [b'extra']+base, False, hint_items=60)
            check('routing-missing-entry-item', 0, base[1:], False, hint_items=59)
            bad = base.copy()
            bad[-1] = b'\x02' + b'\x22'*32
            check('routing-changed-root', 0, bad, False, hint_items=60)

            outputs = [(990000, b'\x00\x14'+b'\x11'*20)]
            # All four fixed signature pushes are deleted, before hashing.
            code = same.replace(push(SIG), b'')
            keys, digest = recovery_keys(funding['txid'], 8, code, outputs)
            check('two-recovery-keys-same-context', 8, keys, True, hint_items=0,
                  digest=digest, combined_stack_peak_by_inspection=5,
                  executed_non_push_opcodes_redeem=22)
            check('two-recovery-keys-duplicate-rejected', 8, [keys[0], keys[0]], False, hint_items=0)
            check('two-recovery-keys-short-encoding-rejected', 8, [keys[0][1:],keys[1]], False, hint_items=0)
            first_code = different.replace(b'\xab',b'').replace(push(SIG), b'')
            keys, digest = recovery_keys(funding['txid'], 9, first_code, outputs)
            second_code = different.split(b'\xab')[1].replace(push(SIG), b'')
            other, digest2 = recovery_keys(funding['txid'], 9, second_code, outputs)
            assert digest != digest2 and keys != other
            check('two-recovery-keys-different-context-rejected', 9, keys, False,
                  hint_items=0, first_digest=digest, second_digest=digest2)
            report['all_expectations_met'] = True
        finally:
            node.close()
    args.output.write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
