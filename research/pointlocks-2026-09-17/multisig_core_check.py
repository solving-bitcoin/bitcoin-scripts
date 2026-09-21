#!/usr/bin/env python3
"""Exercise exact compiled point-lock multisig vectors on isolated Core regtest.

No existing node, wallet, peers, or production funds are used. Every case gets
its own funded outpoints. Positive block inclusion and negative consensus
script rejection are checked separately from the default mempool policy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import tempfile

from core_check import isolated_core_binary, Node, consensus_check, p2sh
from core_check import serialize_spend, transaction

HERE = Path(__file__).resolve().parent


def minimal_push(data):
    if not data:
        return b'\x00'
    if len(data) == 1 and 1 <= data[0] <= 16:
        return bytes([0x50 + data[0]])
    if data == b'\x81':
        return b'\x4f'
    if len(data) <= 75:
        return bytes([len(data)]) + data
    if len(data) <= 255:
        return b'\x4c' + bytes([len(data)]) + data
    if len(data) <= 65535:
        return b'\x4d' + struct.pack('<H', len(data)) + data
    raise ValueError('Oversized fixture item')


def script_counts(script):
    """Static non-push operations and Core's accurate legacy sigop count."""
    pc, last, operations, sigops = 0, None, 0, 0
    while pc < len(script):
        op = script[pc]
        pc += 1
        if 1 <= op <= 75:
            pc += op
        elif op in (0x4c, 0x4d, 0x4e):
            width = {0x4c: 1, 0x4d: 2, 0x4e: 4}[op]
            size = int.from_bytes(script[pc:pc + width], 'little')
            pc += width + size
        assert pc <= len(script), 'Truncated compiled script'
        if op > 0x60:
            operations += 1
        if op in (0xac, 0xad):
            sigops += 1
        elif op in (0xae, 0xaf):
            sigops += last - 0x50 if last is not None and 0x51 <= last <= 0x60 else 20
        last = op
    return operations, sigops


def selected_cases(vectors):
    if 'cases' in vectors:
        return vectors['cases']
    rows = []
    for configuration in vectors['configurations']:
        # All positive subsets for representative 2-of-5 and 2-of-6 pools;
        # seven malformed variants of the first subset in each configuration.
        if configuration['n'] not in (5, 6) or configuration['t'] != 2:
            continue
        for case in configuration['cases']:
            if not case['expected'] and not case['name'].startswith('subset-[0, 1]-'):
                continue
            rows.append({
                'name': f"{configuration['mode']}-{configuration['n']}-{configuration['t']}-{case['name']}",
                'variant': configuration['mode'], 'n': configuration['n'], 't': configuration['t'],
                'script_hex': configuration['redeem_script'], 'items_hex': case['items'],
                'p2sh_script_sig_hex': case['script_sig'],
                'expected': case['expected'], 'expected_policy': case['expected'] and configuration['fits_p2sh'],
                'hint_items': configuration['hint_items'],
                'compiler_static_ops': configuration['static_ops'],
                'compiler_charged_ops': configuration['charged_ops'],
            })
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vectors', type=Path, default=HERE / 'multisig-vectors.json')
    parser.add_argument('--output', type=Path, default=HERE / 'multisig_core_check.json')
    parser.add_argument('--cross-pair', type=Path, default=HERE / 'multisig_cross_pair.json')
    args = parser.parse_args()
    vector_bytes = args.vectors.read_bytes()
    vectors = json.loads(vector_bytes)
    rows = selected_cases(vectors)
    cross_pair_bytes = args.cross_pair.read_bytes()
    cross_pair = json.loads(cross_pair_bytes)
    rows.append({
        **cross_pair, 'variant': 'unsound-full-pool-shortcut', 'n': 2, 't': 1,
        'script_hex': cross_pair['script'], 'items_hex': cross_pair['items'],
        'p2sh_script_sig_hex': cross_pair['script_sig'], 'hint_items': 0,
        'expected_policy': True,
    })
    assert rows and len(rows) < 2000
    binary, provenance = isolated_core_binary(Path('/private/tmp/covenant-core-30.3'), False)
    report = {
        'scope': __doc__, 'bitcoin_core': provenance,
        'vectors_file': str(args.vectors.relative_to(HERE)) if args.vectors.is_relative_to(HERE) else str(args.vectors),
        'vectors_sha256': hashlib.sha256(vector_bytes).hexdigest(),
        'script_compilation': vectors.get('compilation', vectors.get('compiler')),
        'cross_pair_vectors_sha256': hashlib.sha256(cross_pair_bytes).hexdigest(),
        'fixture_count': len(rows), 'results': [],
        'consensus_method': 'generateblock with raw transactions; verify connected block contains txid',
        'policy_method': 'testmempoolaccept with acceptnonstdtxn=0; mempool stays empty',
        'local_interpreter': 'Not used: the pinned bitcoin-scriptexec Legacy CHECKMULTISIG arm is unimplemented',
        'measured_stack_peak': None,
    }
    with tempfile.TemporaryDirectory(prefix='bitcoin-lab-multisig-') as temporary:
        node = Node(binary, Path(temporary))
        try:
            node.ready()
            report['node_options'] = node.options
            report['network_info'] = {
                'networkactive': node.rpc('getnetworkinfo')['networkactive'],
                'peer_count': len(node.rpc('getpeerinfo')),
            }
            assert report['network_info'] == {'networkactive': False, 'peer_count': 0}
            address = node.rpc('decodescript', '51')['segwit']['address']
            mining = bytes.fromhex(node.rpc('validateaddress', address)['scriptPubKey'])
            blocks = []
            for _ in range(101):
                node.tick()
                blocks += node.rpc('generatetoaddress', 1, address)
            coinbase = node.rpc('getblock', blocks[0], 2)['tx'][0]
            coin = next(out for out in coinbase['vout'] if out['scriptPubKey']['hex'] == mining.hex())
            funding_outputs = []
            for row in rows:
                script = bytes.fromhex(row['script_hex'])
                wrapper = row.get('wrapper', 'p2sh' if len(script) <= 520 else 'bare')
                assert wrapper in ('p2sh', 'bare')
                if wrapper == 'p2sh':
                    assert len(script) <= 520
                funding_outputs += [(1000000, mining), (1000000, p2sh(script) if wrapper == 'p2sh' else script)]
            funding_outputs.append((5000000000 - len(funding_outputs) * 1000000 - 10000, mining))
            funding = transaction(coinbase['txid'], coin['n'], [b'\x51'], funding_outputs)
            assert consensus_check(node, address, funding)['accepted']
            report['funding'] = funding
            maturity_blocks = int(vectors.get('funding_maturity_blocks', 0))
            assert 0 <= maturity_blocks <= 10
            for _ in range(maturity_blocks):
                node.tick()
                node.rpc('generatetoaddress', 1, address)
            report['funding_maturity_blocks'] = maturity_blocks
            for ordinal, row in enumerate(rows):
                script = bytes.fromhex(row['script_hex'])
                items = [bytes.fromhex(item) for item in row['items_hex']]
                wrapper = row.get('wrapper', 'p2sh' if len(script) <= 520 else 'bare')
                script_sig = b''.join(minimal_push(item) for item in items)
                if wrapper == 'p2sh':
                    script_sig += minimal_push(script)
                    if 'p2sh_script_sig_hex' in row:
                        assert script_sig.hex() == row['p2sh_script_sig_hex']
                inputs = [(funding['txid'], ordinal * 2, b'', 0xffffffff),
                          (funding['txid'], ordinal * 2 + 1, script_sig,
                           row.get('locked_sequence', 0xffffffff))]
                locked_index, helper_index = 1, 0
                if row.get('locked_input_index') == 0:
                    inputs.reverse()
                    locked_index, helper_index = 0, 1
                outputs = [(1990000, b'\x00\x14' + b'\x11' * 20)]
                if row.get('output_count') == 2:
                    outputs = [(990000, outputs[0][1]), (1000000, b'\x00\x14' + b'\x22' * 20)]
                spend = serialize_spend(inputs, outputs, helper_index)
                decoded = node.rpc('decoderawtransaction', spend['hex'])
                for actual, expected in [('txid', 'txid'), ('weight', 'weight'), ('hash', 'wtxid'), ('size', 'total_bytes')]:
                    assert decoded[actual] == spend[expected]
                spend['vsize'] = decoded['vsize']
                assert node.rpc('getrawmempool') == []
                policy = node.rpc('testmempoolaccept', [spend['hex']])[0]
                consensus = consensus_check(node, address, spend)
                assert consensus['accepted'] == row['expected'], (row['name'], consensus)
                if 'expected_policy' in row:
                    assert policy['allowed'] == row['expected_policy'], (row['name'], policy)
                operations, sigops = script_counts(script)
                report['results'].append({
                    **row, 'wrapper': wrapper,
                    'script_bytes': len(script), 'locking_script_bytes': 23 if wrapper == 'p2sh' else len(script),
                    'script_sig_bytes': len(script_sig),
                    'script_sig_push_items': len(items) + (wrapper == 'p2sh'),
                    'locked_input_index': locked_index, 'locked_input_data_items': len(items),
                    'locked_input_witness_items': 0, 'all_entry_data_coexists': True,
                    'static_non_push_opcodes': operations, 'accurate_sigops': sigops,
                    'complete_transaction_witness_bytes': spend['witness_bytes'],
                    'transaction': spend, 'consensus': consensus, 'policy': policy,
                    'evidence': 'locally-reproduced',
                    'deployment_class': ('policy-validated' if policy['allowed'] else 'consensus-validated')
                        if consensus['accepted'] else 'consensus-incompatible',
                })
                print('PASS', row['name'], 'consensus=', consensus['accepted'], 'policy=', policy['allowed'], flush=True)
            report['all_expectations_met'] = True
        finally:
            node.close()
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(args.output)


if __name__ == '__main__':
    main()
