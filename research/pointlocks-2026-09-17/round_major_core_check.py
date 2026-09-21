#!/usr/bin/env python3
"""Small round-major P2WSH fixtures, not full publication or general extraction.

All fixture secrets are public. Core runs without wallets or network peers.
"""
import argparse
import copy
import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import tempfile

from core_check import (Node, consensus_check, instructions, isolated_core_binary,
                        scalar_bytes, scalar_value, transaction, unpack_signature)
from core_regtest import compact_size, vector
from publication_core_check import accept_and_mine, encode_key, hash160
from anchored_native_core_check import digest
from anchored_consensus_flags_check import serialized
from anchored_extraction import decode_verification_key, extract
from legacy_same_signature_counterexample import N, mul, verify
from typed_selector_core_check import contexts, sign, mutate_first

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EXAMPLE = 'pointlock_anchored_round_major_probe'


def make_case(fixture, funding_txid, mining, selected):
    code = bytes.fromhex(fixture['script_hex'])
    checks = contexts(code)
    t, d = fixture['t'], fixture['rounds']
    assert len(checks) == 1+t+t*d
    assert len(set(checks[:1+2*t])) == 1
    for j in range(t):
        assert len({checks[1+t+r*t+j] for r in range(d)}) == d
    tx = dict(version=2, locktime=0, vin=[
        dict(txid=funding_txid, vout=0, sequence=0xffffffff,
             scriptSig={'hex': ''}, txinwitness=['51']),
        dict(txid=funding_txid, vout=1, sequence=0xffffffff,
             scriptSig={'hex': ''}, txinwitness=[]),
    ], vout=[dict(value=0.0019, scriptPubKey={'hex': mining.hex()})])
    order = list(reversed(selected))
    taus = [bytes.fromhex(v['tau_hex']) for v in fixture['targets']]
    for attempt in range(100):
        tx['vin'][1]['sequence'] = 0xffffffff-attempt
        keys, sigmas, recoveries = [], [], []
        for j, label in enumerate(order):
            tau = taus[label]
            rt, _, _ = unpack_signature(tau)
            target = fixture['targets'][label]
            anchor = digest(tx, 1, checks[1+j], 1)
            p = (target['scalar_fixture']-int.from_bytes(anchor, 'big'))*pow(rt, -1, N) % N
            messages = [digest(tx, 1, checks[1+t+r*t+j], 1) for r in range(d)]
            signatures = [sign(p, msg) for msg in messages]
            if p == 0 or any(len(s) != 60 for s in signatures):
                break
            key = encode_key(mul(p))
            recovered = extract(tau, anchor, key, bytes.fromhex(target['point_hex']), list(zip(signatures, messages)))
            assert recovered['scalar'] == target['scalar_fixture']
            keys.append(key)
            sigmas.append(signatures)
            recoveries.append(dict(label=label, scalar=recovered['scalar']))
        else:
            break
    else:
        raise AssertionError('fixture retry exhaustion')
    remaining = list(range(fixture['n']))
    stream = []
    for label in selected:
        hint = len(remaining)-remaining.index(label)
        stream.extend([taus[label], scalar_bytes(hint)])
        remaining.remove(label)
    stream += [sigmas[j][r] for r in range(d) for j in range(t)]
    stream += keys
    auth = sign(1, digest(tx, 1, code, 1))
    tx['vin'][1]['txinwitness'] = [v.hex() for v in reversed(stream)] + [auth.hex(), code.hex()]
    return tx, recoveries


def execute_values(tx):
    """Independent group-equation and combined-height trace; Core is the oracle."""
    stack = [bytes.fromhex(x) for x in tx['vin'][1]['txinwitness']]
    code = stack.pop()
    alt, start, checks = [], 0, 0
    peak, failure = len(stack), None
    try:
        for _, end, op, data in instructions(code):
            if data is not None:
                stack.append(data)
            elif op == 0:
                stack.append(b'')
            elif 0x51 <= op <= 0x60:
                stack.append(bytes([op-0x50]))
            elif op == 0x6b:
                alt.append(stack.pop())
            elif op == 0x6c:
                stack.append(alt.pop())
            elif op == 0x6d:
                stack.pop(); stack.pop()
            elif op == 0x75:
                stack.pop()
            elif op == 0x77:
                del stack[-2]
            elif op == 0x78:
                stack.append(stack[-2])
            elif op in (0x79, 0x7a):
                raw = stack.pop()
                assert len(raw) <= 4, 'oversized-index'
                depth = scalar_value(raw)
                assert 0 <= depth < len(stack), 'index-out-of-stack'
                index = len(stack)-1-depth
                stack.append(stack[index] if op == 0x79 else stack.pop(index))
            elif op == 0x7c:
                stack[-2:] = stack[-2:][::-1]
            elif op == 0x7b:
                stack.append(stack.pop(-3))
            elif op == 0x7d:
                stack.insert(len(stack)-2, stack[-1])
            elif op == 0x82:
                stack.append(scalar_bytes(len(stack[-1])))
            elif op == 0x88:
                assert stack.pop() == stack.pop(), 'equality'
            elif op == 0xa9:
                stack.append(hash160(stack.pop()))
            elif op == 0xab:
                start = end
            elif op == 0xad:
                key, sigma = stack.pop(), stack.pop()
                assert sigma and sigma[0] == 0x30, 'non-DER-table-element'
                assert len(key) in (33, 65), 'wrong-key-shape'
                r, s, flag = unpack_signature(sigma)
                point = decode_verification_key(key)
                message = digest(tx, 1, code[start:], flag)
                assert verify(int.from_bytes(message, 'big'), r, s, point)[0], 'ecdsa'
                checks += 1
            else:
                raise ValueError(f'unmodeled opcode {op:x}')
            peak = max(peak, len(stack)+len(alt))
        assert stack == [b'\x01'] and not alt, 'unclean-terminal-stack'
    except (AssertionError, IndexError) as error:
        failure = str(error) or type(error).__name__
    return dict(accepted=failure is None, failure=failure, signature_checks=checks,
                combined_stack_peak=peak)


def cases_for(fixture, txid, mining):
    result = []
    n, t = fixture['n'], fixture['t']
    if t == 2:
        selections = itertools.permutations(range(n), t)
    else:
        endpoints = [tuple(range(t)), tuple(range(n-t, n)), (0, 13, 27, 40, 53)]
        selections = endpoints + [tuple(reversed(v)) for v in endpoints]
    for selected in selections:
        tx, recovery = make_case(fixture, txid, mining, selected)
        result.append(dict(name=f'select-{selected}', expected=True, tx=tx, recovery=recovery))
    tx, _ = make_case(fixture, txid, mining, (0, 2, *range(3, t+1)))
    zero, _ = make_case(fixture, txid, mining, (n-1, *range(t-1)))
    last_hash = hash160(bytes.fromhex(fixture['targets'][-1]['tau_hex']))
    variants = [
        ('zero-index-hash-satisfied', mutate_first(zero, tau=hash160(last_hash), hint=b'')),
        ('negative-zero-hash-satisfied', mutate_first(zero, tau=hash160(last_hash), hint=b'\x80')),
        ('negative-index', mutate_first(tx, hint=scalar_bytes(-1))),
        ('beyond-stack', mutate_first(tx, hint=scalar_bytes(1000))),
        ('five-byte-index', mutate_first(tx, hint=b'\x01\x00\x00\x00\x00')),
        ('extra-entry-item', mutate_first(tx, extra=b'\x01')),
    ]
    outside = copy.deepcopy(tx)
    w = outside['vin'][1]['txinwitness']
    w[-6] = scalar_bytes(fixture['n']).hex()
    w[-7] = hash160(bytes.fromhex(fixture['targets'][2]['tau_hex'])).hex()
    if t == 2:
        variants.append(('outside-table-hash-satisfied', outside))
    # Keys are the lowest t witness items; changing their order must fail.
    wrong_keys = copy.deepcopy(tx)
    w = wrong_keys['vin'][1]['txinwitness']
    w[0], w[1] = w[1], w[0]
    variants.append(('swapped-recovered-keys', wrong_keys))
    # Signature stream follows 2*t selection items when read from the top.
    for name, mutate in [('short-item', 'truncate'), ('cross-round-replay', 'replay')]:
        bad = copy.deepcopy(tx)
        w = bad['vin'][1]['txinwitness']
        first = -3-2*fixture['t']
        if mutate == 'truncate':
            w[first] = w[first][:-2]
        else:
            w[first-fixture['t']] = w[first]
        variants.append((name, bad))
    result.extend(dict(name=name, expected=False, tx=bad) for name, bad in variants)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host-only', action='store_true')
    parser.add_argument('--full-pool', action='store_true')
    args = parser.parse_args()
    command = ['cargo', 'run', '--release', '--locked', '--example', EXAMPLE, '--', '--fixtures']
    if args.full_pool:
        command.append('--full-pool')
    built = subprocess.run(command,
                           cwd=ROOT, text=True, capture_output=True, check=True)
    data = json.loads(built.stdout)
    fixture = data['fixtures'][0]
    report = dict(scope=__doc__, compiler_commit=data['compiler_commit'], cases=[],
                  general_extraction_proved=False, complete_publication=False,
                  setup_benchmark=False, evidence='locally-reproduced', deployment='unclassified')
    binary, provenance = (None, None) if args.host_only else isolated_core_binary(Path('/private/tmp/covenant-core-30.3'), False)
    with tempfile.TemporaryDirectory(prefix='bitcoin-lab-round-major-') as temporary:
        node = Node(binary, Path(temporary)) if binary else None
        try:
            if node:
                node.ready()
                assert not node.rpc('getnetworkinfo')['networkactive'] and not node.rpc('getpeerinfo')
                address = node.rpc('decodescript', '51')['segwit']['address']
                mining = bytes.fromhex(node.rpc('validateaddress', address)['scriptPubKey'])
                blocks = []
                for _ in range(101):
                    node.tick(); blocks += node.rpc('generatetoaddress', 1, address)
                coinbase = node.rpc('getblock', blocks[0], 2)['tx'][0]
                coin = next(o for o in coinbase['vout'] if o['scriptPubKey']['hex'] == mining.hex())
                outputs = [(100_000, mining),
                    (100_000, b'\x00\x20'+hashlib.sha256(bytes.fromhex(fixture['script_hex'])).digest()),
                    (5_000_000_000-210_000, mining)]
                fund = transaction(coinbase['txid'], coin['n'], [b'\x51'], outputs)
                funding, report['test_only_funding'] = accept_and_mine(node, address, fund['hex'])
                txid = funding['txid']
                report.update(bitcoin_core=provenance, node_options=node.options)
            else:
                txid = '11'*32
                mining = b'\x00\x20'+hashlib.sha256(b'\x51').digest()
            cases = cases_for(fixture, txid, mining)
            for case in cases:
                trace = execute_values(case['tx'])
                assert trace['accepted'] == case['expected'], (case['name'], trace)
                record = {k:v for k,v in case.items() if k != 'tx'}
                record.update(transaction=serialized(case['tx']), independent_trace=trace)
                if node:
                    policy = node.rpc('testmempoolaccept', [record['transaction']['hex']])[0]
                    assert policy['allowed'] == case['expected'], (case['name'], policy)
                    record['policy'] = policy
                report['cases'].append(record)
            if node:
                height = node.rpc('getblockcount')
                for case in report['cases']:
                    result = consensus_check(node, address, case['transaction'])
                    assert result['accepted'] == case['expected'], (case['name'], result)
                    case['consensus'] = result
                    if result['accepted']:
                        node.rpc('invalidateblock', result['block_hash'])
                    assert node.rpc('getblockcount') == height
                report.update(evidence='differentially-validated', deployment='policy-validated')
            positive = [c for c in report['cases'] if c['expected']]
            witnesses = [[bytes.fromhex(v) for v in c['tx']['vin'][1]['txinwitness']] for c in cases if c['expected']]
            report['metrics'] = dict(n=fixture['n'], t=fixture['t'], rounds=fixture['rounds'],
                script_bytes=fixture['script_bytes'],
                charged_ops=sum(op>0x60 for _,_,op,data in instructions(bytes.fromhex(fixture['script_hex'])) if data is None),
                hint_items_per_input=fixture['hint_items'], entry_items=fixture['entry_items'],
                complete_witness_items=len(witnesses[0]),
                serialized_witness_bytes=sorted({len(compact_size(len(w)))+sum(len(vector(v)) for v in w) for w in witnesses}),
                combined_stack_peak=max(c['independent_trace']['combined_stack_peak'] for c in positive),
                distinct_short_contexts_per_label=fixture['rounds'], shared_round_contexts=True)
            report['summary'] = dict(positive_cases=len(positive), negative_cases=len(cases)-len(positive), all_expectations_met=True)
        finally:
            if node: node.close()
    paths = [Path(__file__), ROOT/f'examples/{EXAMPLE}.rs', ROOT/'Cargo.lock',
             HERE/'core_check.py', ROOT/'tools/core_regtest.py', HERE/'publication_core_check.py',
             HERE/'anchored_native_core_check.py', HERE/'anchored_consensus_flags_check.py',
             HERE/'anchored_extraction.py', HERE/'nonce_relation_extraction.py', HERE/'typed_selector_core_check.py',
             HERE.parent/'covenant-2026-09-17/legacy_same_signature_counterexample.py']
    report['source_sha256'] = {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    suffix = ('full-pool-' if args.full_pool else '') + ('host' if args.host_only else 'core')
    (HERE/f'round-major-{suffix}-check.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(summary=report['summary'],metrics=report['metrics'])))


if __name__ == '__main__':
    main()
