#!/usr/bin/env python3
"""A public hash preimage used as an actual ECDSA signature in isolated Core.

Raw consensus-boundary fixture, not a complete proof verifier or covenant.
No rare event is mined: the preimage is an existing public test vector.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import time
import urllib.error

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from core_gate_check import isolated_core_binary, p2sh, push
import core_regtest
from core_regtest import Node, RPCError, consensus_check, transaction
from legacy_same_signature_counterexample import N, P, add, mul, hash256, verify
from second_pass_structure import raw_tx, serialize

PREIMAGE = bytes.fromhex('00000000000000000200a8013bbb8678')
ALPHA = hashlib.sha256(PREIMAGE).digest()
SCRIPT = bytes.fromhex('a87cac')  # entry P, preimage; SHA256 SWAP CHECKSIG
GUARD_SCRIPT = bytes.fromhex('a87c6eadabac91')


def recover(digest):
    lr = ALPHA[3]
    ls = ALPHA[5 + lr]
    r = int.from_bytes(ALPHA[4:4 + lr], 'big')
    s = int.from_bytes(ALPHA[6 + lr:6 + lr + ls], 'big')
    z = int.from_bytes(digest, 'big') % N
    points = []
    checks = []
    for x in (r, r + N):
        if x >= P:
            continue
        y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
        valid = y * y % P == (x * x * x + 7) % P
        checks.append({'x_hex': '%064x' % x, 'on_curve': valid})
        if valid:
            for yy in (y, -y % P):
                nonce = (x, yy)
                pubkey = mul(pow(r, -1, N), add(mul(s, nonce), mul(-z % N)))
                assert verify(z, r, s, pubkey)[0]
                encoded = bytes([2 + (pubkey[1] & 1)]) + pubkey[0].to_bytes(32, 'big')
                points.append(encoded)
    assert len(points) == 2 and not checks[0]['on_curve'] and checks[1]['on_curve']
    return points, {'r': r, 's': s, 'flag': ALPHA[-1], 'nonce_x_checks': checks,
                    'recovered_public_keys': [p.hex() for p in points]}


def wait_restarted(node, expected_height):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if node.process.poll() is not None:
            raise RuntimeError((node.datadir / 'process.log').read_text())
        try:
            chain = node.rpc('getblockchaininfo')
            assert chain['chain'] == 'regtest' and chain['blocks'] == expected_height
            return
        except (FileNotFoundError, urllib.error.URLError, RPCError):
            time.sleep(0.1)
    raise RuntimeError('Isolated Core restart timed out')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=HERE / 'r5_root_core.json')
    args = parser.parse_args()
    assert ALPHA.hex() == '301d020a7993dad81d0e10285a7e020f682a7033db72199360c2dc3599f2d302'
    assert ALPHA[-1] == 2
    binary, provenance = isolated_core_binary(Path('/private/tmp/covenant-core-30.3'), False)
    report = {'scope': __doc__, 'bitcoin_core': provenance,
              'preimage': PREIMAGE.hex(), 'hash_signature': ALPHA.hex(),
              'redeemscript_hex': SCRIPT.hex(), 'redeemscript_bytes': len(SCRIPT),
              'locking_script_bytes': 23, 'results': []}
    with tempfile.TemporaryDirectory(prefix='covenant-r5-root-') as tmp:
        node = Node(binary, Path(tmp))
        try:
            node.ready()
            address = node.rpc('decodescript', '51')['segwit']['address']
            mining_script = bytes.fromhex(node.rpc('validateaddress', address)['scriptPubKey'])
            blocks = []
            for _ in range(101):
                node.tick()
                blocks += node.rpc('generatetoaddress', 1, address)
            coinbase = node.rpc('getblock', blocks[0], 2)['tx'][0]
            coin = next(o for o in coinbase['vout'] if o['scriptPubKey']['hex'] == mining_script.hex())
            funding = transaction(coinbase['txid'], coin['n'], [b'\x51'],
                                  [(1000000, p2sh(SCRIPT)), (1000000, p2sh(GUARD_SCRIPT)),
                                   (4997990000, mining_script)])
            assert consensus_check(node, address, funding)['accepted']
            report['funding'] = funding
            # For the sole input NONE strips all outputs, retaining this input's
            # sequence. The complete flag 2 is appended little-endian.
            digest = hash256(raw_tx([(funding['txid'], 0, SCRIPT)], []) + struct.pack('<I', 2))
            keys, recovery = recover(digest)
            report['none_digest'] = digest.hex()
            report['recovery'] = recovery
            script_a = b'\x00\x14' + b'\x11' * 20
            script_b = b'\x00\x14' + b'\x22' * 20
            outputs = [
                ('recipient-a', [(990000, script_a)]),
                ('recipient-b', [(990000, script_b)]),
                ('amount-change', [(980000, script_a)]),
                ('two-outputs-ab', [(400000, script_a), (590000, script_b)]),
                ('two-outputs-ba', [(590000, script_b), (400000, script_a)]),
            ]

            def check(name, entries, tx_outputs, expected, script=SCRIPT, index=0):
                nonlocal node
                assert node.rpc('getrawmempool') == [], 'Policy probes require an empty mempool'
                script_sig = b''.join(push(x) for x in entries) + push(script)
                spend = serialize([(funding['txid'], index, script_sig)], tx_outputs)
                decoded = node.rpc('decoderawtransaction', spend['hex'])
                assert decoded['txid'] == spend['txid'] and decoded['weight'] == spend['weight']
                policy = node.rpc('testmempoolaccept', [spend['hex']])[0]
                result = consensus_check(node, address, spend)
                assert result['accepted'] == expected, (name, result)
                assert policy['allowed'] == (expected and script == SCRIPT), (name, policy)
                report['results'].append({
                    'name': name, 'input_items_hex': [x.hex() for x in entries],
                    'redeemscript_hex': script.hex(), 'redeemscript_bytes': len(script),
                    'input_data_items': len(entries), 'hint_items': 0,
                    'script_sig_bytes': len(script_sig), 'script_sig_push_items': len(entries) + 1,
                    'witness_bytes': 0, 'combined_stack_peak_by_inspection': len(entries) + 2,
                    'executed_non_push_opcodes_redeem_if_success': len(script) if expected else None,
                    'executed_non_push_opcodes_p2sh_if_success': 2 if expected else None,
                    'transaction': spend, 'consensus': result, 'policy': policy,
                    'evidence': 'differentially-validated',
                    'deployment_class': ('policy-validated' if policy['allowed'] else 'consensus-validated')
                        if expected else 'consensus-incompatible',
                })
                print('PASS', name, 'consensus=', expected, 'policy=', policy['allowed'])
                if expected:
                    node.rpc('invalidateblock', result['block_hash'])
                    # Disconnecting a block can re-add its transaction to the
                    # mempool. Restart with persistmempool=0 so the next policy
                    # check measures script policy rather than RBF fees.
                    mocktime = node.mocktime
                    height = node.rpc('getblockcount')
                    node.close()
                    # The helper's default startup clock predates our mined
                    # chain. Set its in-process constructor default for this
                    # restart only, or Core correctly rejects future blocks.
                    old_start_time = core_regtest.START_TIME
                    core_regtest.START_TIME = mocktime
                    try:
                        node = Node(binary, Path(tmp))
                    finally:
                        core_regtest.START_TIME = old_start_time
                    wait_restarted(node, height)
                    node.mocktime = mocktime
                    node.rpc('setmocktime', mocktime)

            for name, tx_outputs in outputs:
                check(name, [keys[0], PREIMAGE], tx_outputs, True)
            check('second-recovery-branch', [keys[1], PREIMAGE], outputs[0][1], True)
            check('mutated-preimage', [keys[0], PREIMAGE + b'\x00'], outputs[0][1], False)
            check('wrong-public-key', [bytes.fromhex('02' + '11' * 32), PREIMAGE], outputs[0][1], False)
            check('missing-preimage', [keys[0]], outputs[0][1], False)
            # The proposed context-inequality guard removes constant-digest
            # SINGLE-bug cases. It does not remove NONE: both context hashes
            # still omit all outputs, although they differ from one another.
            first_code = GUARD_SCRIPT.replace(b'\xab', b'')
            digest_guard = hash256(raw_tx([(funding['txid'], 1, first_code)], []) + struct.pack('<I', 2))
            digest_guard_second = hash256(raw_tx([(funding['txid'], 1, b'\xac\x91')], []) + struct.pack('<I', 2))
            keys_guard, recovery_guard = recover(digest_guard)
            assert digest_guard != digest_guard_second
            report['guard'] = {'first_digest': digest_guard.hex(), 'second_digest': digest_guard_second.hex(),
                               'recovery': recovery_guard}
            for name, tx_outputs in outputs[:2]:
                check('context-inequality-guard-' + name, [keys_guard[0], PREIMAGE], tx_outputs,
                      True, GUARD_SCRIPT, 1)
            report['all_expectations_met'] = True
        finally:
            node.close()
    args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
