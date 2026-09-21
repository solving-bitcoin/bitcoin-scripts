#!/usr/bin/env python3
"""Full honest round-major anchored publication on isolated Core; general extraction is open.

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
from windowed_native_core_check import rank_subset
from legacy_same_signature_counterexample import N, G, mul, verify

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def straight_line_stack_peak(script, entry):
    """Combined main/alt height trace; Core independently checks stack values."""
    height = peak = entry
    alt = 0
    delta = {0x6d:-2, 0x75:-1, 0x76:1, 0x77:-1, 0x78:1, 0x79:0,
             0x7a:-1, 0x7b:0, 0x7c:0, 0x7d:1, 0x82:1, 0x88:-2,
             0xa9:0, 0xab:0, 0xad:-2}
    for _, _, op, data in instructions(script):
        if data is not None or op == 0 or 0x51 <= op <= 0x60:
            height += 1
        elif op == 0x6b:
            height -= 1; alt += 1
        elif op == 0x6c:
            height += 1; alt -= 1
        else:
            assert op in delta, f'unmodeled opcode {op:x}'
            height += delta[op]
        assert height >= 0 and alt >= 0
        peak = max(peak, height+alt)
    assert height == 1 and alt == 0
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
        assert table == [hash160(bytes.fromhex(tau)) for tau in pool['tau_table']]
        assert len(table) == len(set(table)) == pool['n']
        contexts = []
        start = 0
        for _, end, opcode, _ in instructions(script):
            if opcode == 0xab:
                start = end
            elif opcode == 0xad:
                contexts.append(script[start:])
        assert len(contexts) == 1 + pool['t'] * (pool['rounds'] + 1)
        stream = list(reversed(witness))
        assert len(stream) == pool['t'] * (3 + pool['rounds'])
        threshold, rounds = pool['t'], pool['rounds']
        remaining = list(range(pool['n']))
        selected = []
        anchors = []
        for slot in range(threshold):
            tau, hint = stream[2*slot:2*slot+2]
            depth = int.from_bytes(hint, 'little')
            assert 1 <= depth <= len(remaining)
            label = remaining.pop(len(remaining)-depth)
            selected.append(label)
            assert hash160(tau) == table[label]
            anchors.append(tau)
        assert len(set(contexts[:1+2*threshold])) == 1
        for slot, (label, tau) in enumerate(reversed(list(zip(selected, anchors)))):
            key_bytes = stream[2*threshold+rounds*threshold+slot]
            shorts = [stream[2*threshold+r*threshold+slot] for r in range(rounds)]
            assert len({contexts[1+threshold+r*threshold+slot] for r in range(rounds)}) == rounds
            point = decode_key(key_bytes)
            rt, st, flag = unpack_signature(tau)
            assert len(tau) == 40 and st == flag == 1
            target = bytes.fromhex(pool['targets'][label])
            assert rt == decode_key(target)[0]
            check = 1 + slot
            anchor = digest(spend, index, contexts[check], flag)
            assert anchor.hex() == pool['frames'][slot]['anchor_digest']
            z0 = int.from_bytes(anchor, 'big') % N
            assert verify(z0, rt, st, point)[0]
            signature_checks += 1
            extractions = []
            for j, sigma in enumerate(shorts):
                r, s, flag = unpack_signature(sigma)
                assert len(sigma) == 60 and r == int('3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63', 16)
                msg = digest(spend, index, contexts[1+threshold+j*threshold+slot], flag)
                assert msg.hex() == pool['frames'][slot]['short_checks'][j]['digest']
                z = int.from_bytes(msg, 'big') % N
                assert verify(z, r, s, point)[0]
                signature_checks += 1
                matches = []
                for k in ((N + 1) // 2, (N - 1) // 2):
                    p = ((s * k - z) * pow(r, -1, N)) % N
                    if mul(p) != point:
                        continue
                    for sign in (1, -1):
                        t = sign * (rt * p + z0) % N
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
    with tempfile.TemporaryDirectory(prefix='bitcoin-lab-round-major-publication-') as temporary:
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
            command = ['cargo', 'run', '--release', '--locked', '--example', 'pointlock_round_major_publication_probe',
                       '--', '--funding-txid', granted['txid'], '--funding-vout', '0', '--funding-amount', str(amount)]
            result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=True)
            built = json.loads(result.stdout)
            assert built['pool_count'] == 95 and built['selected_count'] == 475
            (HERE/'round-major-publication-transactions.json').write_text(json.dumps(built, indent=2)+'\n')
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
            report['all_expectations_met'] = True
            print(f'PASS {report["combined_vbytes"]} combined vB; {report["recovery"]["extracted_points"]} labels; full256-byte roundtrip', flush=True)
        finally:
            node.close()
    paths = [Path(__file__), ROOT/'examples/pointlock_round_major_publication_probe.rs',
             ROOT/'Cargo.lock', ROOT/'tools/core_regtest.py', HERE/'core_check.py',
             HERE/'publication_core_check.py', HERE/'anchored_native_core_check.py',
             HERE/'windowed_native_core_check.py',
             HERE.parent/'covenant-2026-09-17/legacy_same_signature_counterexample.py']
    report['source_sha256'] = {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    binary_path=ROOT/'target/release/examples/pointlock_round_major_publication_probe'
    report['generator_binary_sha256'] = hashlib.sha256(binary_path.read_bytes()).hexdigest()
    report['transactions_sha256'] = hashlib.sha256((HERE/'round-major-publication-transactions.json').read_bytes()).hexdigest()
    (HERE/'round_major_publication_core_check.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
