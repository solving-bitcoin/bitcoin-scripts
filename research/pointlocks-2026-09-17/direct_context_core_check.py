#!/usr/bin/env python3
"""Full direct-key six-context publication on isolated Core; general extraction is open.

All secrets are public deterministic fixtures. Networking and wallets are off.
The external test grant models a pre-existing P2TR coin and is not protocol cost.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from core_check import isolated_core_binary, Node, consensus_check, transaction, instructions, unpack_signature, decode_key
from publication_core_check import accept_and_mine, encode_key, hash160
from anchored_native_core_check import digest
from anchored_consensus_flags_check import serialized
from windowed_native_core_check import rank_subset
from legacy_same_signature_counterexample import N, G, mul, verify

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def straight_line_stack_peak(script, entry):
    """Exact height trace for this branch-free script; not a Core trace hook.

    Core checks values and ROLL depths. The independent height calculation
    includes all entry items and pushes, and asserts no alt-stack opcode exists.
    """
    height = peak = entry
    delta = {0x6d: -2, 0x75: -1, 0x76: 1, 0x78: 1, 0x7a: -1, 0x7c: 0, 0x7d: 1,
             0x82: 1, 0x88: -2, 0x69: -1, 0xa3: -1, 0xa5: -2, 0xa9: 0, 0xab: 0, 0xad: -2}
    for _, _, op, data in instructions(script):
        if data is not None or op == 0 or 0x51 <= op <= 0x60:
            height += 1
        else:
            assert op in delta, f'unmodeled opcode {op:x}'
            height += delta[op]
        assert height >= 0
        peak = max(peak, height)
    assert height == 1
    return peak


def recover(funding, spend, built):
    records = []
    digits = []
    signature_checks = 0
    assert len(spend['vin']) == len(funding['vout']) == built['pool_count'] + 1
    for pool in built['pools']:
        index = pool['input_index']
        vin = spend['vin'][index]
        assert vin['txid'] == funding['txid'] and vin['vout'] == index
        witness = [bytes.fromhex(v) for v in vin['txinwitness']]
        script = witness.pop()
        assert script.hex() == pool['script_hex']
        assert funding['vout'][index]['scriptPubKey']['hex'] == '0020' + hashlib.sha256(script).hexdigest()
        auth = witness.pop()
        ra, sa, flag = unpack_signature(auth)
        assert flag == 1 and verify(int.from_bytes(digest(spend, index, script, flag), 'big'), ra, sa, G)[0]
        signature_checks += 1
        table = [data for _, _, _, data in instructions(script) if data is not None and len(data) == 20]
        assert table == [hash160(bytes.fromhex(target)) for target in pool['targets']]
        assert len(table) == len(set(table)) == pool['n']
        contexts = []
        start = 0
        for _, end, opcode, _ in instructions(script):
            if opcode == 0xab:
                start = end
            elif opcode == 0xad:
                contexts.append(script[start:])
        assert len(contexts) == 1 + pool['t'] * pool['rounds']
        stream = list(reversed(witness))
        assert len(stream) == pool['t'] * (2 + pool['rounds'])
        remaining = list(range(pool['n']))
        selected = []
        for slot in range(pool['t']):
            frame = stream[slot * (2 + pool['rounds']):(slot + 1) * (2 + pool['rounds'])]
            key_bytes, hint, *shorts = frame
            depth = min(int.from_bytes(hint, 'little'), len(remaining))
            assert 1 <= depth <= len(remaining)
            label = remaining.pop(len(remaining) - depth)
            selected.append(label)
            assert hash160(key_bytes) == table[label]
            point = decode_key(key_bytes)
            target = bytes.fromhex(pool['targets'][label])
            assert key_bytes == target
            check = 1 + slot * pool['rounds']
            extractions = []
            for j, sigma in enumerate(shorts):
                r, s, flag = unpack_signature(sigma)
                assert len(sigma) == 60 and r == int('3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63', 16)
                msg = digest(spend, index, contexts[check + j], flag)
                assert msg.hex() == pool['frames'][slot]['short_checks'][j]['digest']
                z = int.from_bytes(msg, 'big') % N
                assert verify(z, r, s, point)[0]
                signature_checks += 1
                matches = []
                for nonce in ((N+1)//2, (N-1)//2):
                    t = (s*nonce-int.from_bytes(msg, 'big')) * pow(r, -1, N) % N
                    if encode_key(mul(t)) == target:
                        matches.append(t)
                assert len(matches) == 1
                extractions.append(matches[0])
            assert len(set(extractions)) == 1
            scalar = extractions[0]
            assert f'{scalar:064x}' == pool['frames'][slot]['target_scalar_fixture']
            records.append(dict(pool=pool['pool'], label=label, scalar=f'{scalar:064x}', target=target.hex()))
        assert selected == pool['selected'] == sorted(selected)
        digits.append(rank_subset(selected, pool['n']))
        if (index % 10) == 0:
            print(f'PASS independent recovery pools {index}/{built["pool_count"]}', flush=True)
    # Generator places the least significant mixed-radix digit in the first pool.
    rank = 0
    for digit in reversed(digits):
        rank = rank * built['radix'] + digit
    assert rank < 1 << 2048
    payload = rank.to_bytes(256, 'big')
    assert payload.hex() == built['payload_hex']
    assert len(records) == built['selected_count']
    return dict(extracted_points=len(records), signature_checks=signature_checks,
                short_signature_extractions=built['short_signature_count'],
                payload_hex=payload.hex(), payload_sha256=hashlib.sha256(payload).hexdigest(),
                extractions=records)


def main():
    binary, provenance = isolated_core_binary(Path('/private/tmp/covenant-core-30.3'), False)
    report = dict(scope=__doc__, bitcoin_core=provenance,
                  evidence='differentially-validated', deployment_class='policy-validated',
                  extraction_soundness_established=False, negative_cases=[])
    with tempfile.TemporaryDirectory(prefix='bitcoin-lab-direct-context-') as temporary:
        node = Node(binary, Path(temporary))
        try:
            node.ready()
            report['node_options'] = node.options
            assert not node.rpc('getnetworkinfo')['networkactive'] and not node.rpc('getpeerinfo')
            address = node.rpc('decodescript', '51')['segwit']['address']
            mining = bytes.fromhex(node.rpc('validateaddress', address)['scriptPubKey'])
            blocks = []
            for _ in range(101):
                node.tick()
                blocks += node.rpc('generatetoaddress', 1, address)
            coinbase = node.rpc('getblock', blocks[0], 2)['tx'][0]
            coin = next(v for v in coinbase['vout'] if v['scriptPubKey']['hex'] == mining.hex())
            amount = 100_000_000
            grant = transaction(coinbase['txid'], coin['n'], [b'\x51'], [
                (amount, b'\x51\x20' + G[0].to_bytes(32, 'big')),
                (5_000_000_000 - amount - 10_000, mining)])
            granted, report['excluded_test_setup_grant'] = accept_and_mine(node, address, grant['hex'])
            command = ['cargo', 'run', '--release', '--locked', '--example', 'pointlock_direct_context_publication_probe',
                       '--', '--funding-txid', granted['txid'], '--funding-vout', '0', '--funding-amount', str(amount)]
            result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=True)
            built = json.loads(result.stdout)
            (HERE/'direct-context-publication-transactions.json').write_text(json.dumps(built, indent=2)+'\n')
            report['rust_generation_stderr'] = result.stderr
            funding, report['funding'] = accept_and_mine(node, address, built['funding']['hex'])
            print('PASS full funding transaction', flush=True)
            for case in built['negative_cases']:
                tx = case['transaction']
                policy = node.rpc('testmempoolaccept', [tx['hex']])[0]
                consensus = consensus_check(node, address, tx)
                assert not policy['allowed'] and not consensus['accepted'], case['name']
                report['negative_cases'].append(dict(name=case['name'], policy=policy, consensus=consensus))
                print('PASS negative', case['name'], flush=True)
            template = node.rpc('decoderawtransaction', built['spending']['hex'])
            pool = next(p for p in built['pools'] if p['selected'][0] == 0)
            idx = pool['input_index']
            witness = template['vin'][idx]['txinwitness']
            hint_position = len(witness)-4
            key_position = len(witness)-3
            assert int.from_bytes(bytes.fromhex(witness[hint_position]), 'little') == pool['n']
            for name, value, self_auth in [('zero-index', '00', False),
                     ('negative-index', '81', False), ('five-byte-index', 'ffffffff00', False),
                     ('zero-index-self-authenticated-key', '00', True)]:
                changed = json.loads(json.dumps(template))
                w = changed['vin'][idx]['txinwitness']; w[hint_position] = value
                if self_auth:
                    w[key_position] = hash160(hash160(bytes.fromhex(pool['targets'][-1]))).hex()
                tx = serialized(changed)
                policy = node.rpc('testmempoolaccept', [tx['hex']])[0]
                consensus = consensus_check(node, address, tx)
                assert not policy['allowed'] and not consensus['accepted'], name
                report['negative_cases'].append(dict(name=name, policy=policy, consensus=consensus))
                print('PASS negative', name, flush=True)
            changed = json.loads(json.dumps(template))
            changed['vin'][idx]['txinwitness'][hint_position] = 'ffffff7f'
            alias = serialized(changed)
            alias_policy = node.rpc('testmempoolaccept', [alias['hex']])[0]
            assert alias_policy['allowed'], alias_policy
            spend, report['spending'] = accept_and_mine(node, address, built['spending']['hex'])
            print('PASS full publication accepted and mined', flush=True)
            report['recovery'] = recover(funding, spend, built)
            report['combined_vbytes'] = report['funding']['vsize'] + report['spending']['vsize']
            assert report['combined_vbytes'] == built['combined_vbytes'] < 100_000
            report['metrics'] = {key: built[key] for key in ('pool_count', 'candidate_count', 'selected_count',
                'short_signature_count', 'total_hint_items', 'total_entry_items', 'setup_generation_ms',
                'setup_verification_ms', 'opening_ms')}
            report['per_pool_metrics'] = [{key: p[key] for key in ('pool', 'script_bytes', 'charged_ops', 'hint_items',
                'entry_items', 'complete_witness_items', 'serialized_witness_bytes', 'combined_stack_upper_bound')}
                for p in built['pools']]
            for metrics, pool in zip(report['per_pool_metrics'], built['pools']):
                metrics['combined_stack_peak_static_trace'] = straight_line_stack_peak(bytes.fromhex(pool['script_hex']), pool['entry_items'])
            # Same logical selection with a large positive index, after the
            # canonical transaction has already been checked and extracted.
            node.rpc('invalidateblock', report['spending']['block_hash'])
            alias_consensus = consensus_check(node, address, alias)
            assert alias_consensus['accepted'], alias_consensus
            report['clamped_alias'] = dict(raw_index=2147483647, effective_index=pool['n'],
                pool=pool['pool'], policy=alias_policy, consensus=alias_consensus,
                transaction=alias, selected_labels_unchanged=True)
            report['all_expectations_met'] = True
            print(f'PASS {report["combined_vbytes"]} combined vB; {report["recovery"]["extracted_points"]} labels; full256-byte roundtrip', flush=True)
        finally:
            node.close()
    (HERE/'direct_context_core_check.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
