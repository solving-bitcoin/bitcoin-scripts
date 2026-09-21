#!/usr/bin/env python3
"""Typed destructive selection in two anchored P2WSH layouts.

Only small selector fixtures, not a complete 256-byte publication or a proof
of general short-signature extraction. Secrets are public deterministic tests.
Native tests use a disposable network/wallet-disabled Bitcoin Core regtest.
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
from anchored_extraction import HALF, HALF_R, der, decode_verification_key, extract
from legacy_same_signature_counterexample import N, G, mul, verify

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def contexts(code):
    start, result = 0, []
    for _, end, op, _ in instructions(code):
        if op == 0xab:
            start = end
        elif op == 0xad:
            result.append(code[start:])
    return result


def sign(secret, message):
    # A known nonce is appropriate only for these explicitly public fixtures.
    s = (int.from_bytes(message, 'big') + HALF_R * secret) * 2 % N
    return der(HALF_R, min(s, N-s))


def make_case(fixture, funding_txid, vout, mining, selected):
    code = bytes.fromhex(fixture['script_hex'])
    checks = contexts(code)
    rounds = fixture['rounds']
    assert len(checks) == 1 + fixture['t']*(rounds+1)
    for slot in range(fixture['t']):
        group = checks[1+slot*(rounds+1):1+(slot+1)*(rounds+1)]
        assert len(set(group[1:])) == rounds
        assert (group[0] == group[1]) == fixture.get('anchor_context_shared_first_short', False)
    tx = dict(version=2, locktime=0, vin=[
        dict(txid=funding_txid, vout=0, sequence=0xffffffff,
             scriptSig={'hex': ''}, txinwitness=['51']),
        dict(txid=funding_txid, vout=vout, sequence=0xffffffff,
             scriptSig={'hex': ''}, txinwitness=[]),
    ], vout=[dict(value=0.0019, scriptPubKey={'hex': mining.hex()})])
    order = list(reversed(selected)) if fixture['phased'] else list(selected)
    taus = [bytes.fromhex(t['tau_hex']) for t in fixture['targets']]
    table = [hash160(tau) for tau in taus]
    assert all(h[0] != 0x30 for h in table)
    for attempt in range(100):
        tx['vin'][1]['sequence'] = 0xffffffff-attempt
        verification = []
        recoveries = []
        for slot, label in enumerate(order):
            tau = taus[label]
            rt, _, _ = unpack_signature(tau)
            target = fixture['targets'][label]
            start = 1+slot*(rounds+1)
            anchor = digest(tx, 1, checks[start], 1)
            p = (target['scalar_fixture'] - int.from_bytes(anchor, 'big')) * pow(rt, -1, N) % N
            messages = [digest(tx, 1, checks[start+1+j], 1) for j in range(rounds)]
            sigmas = [sign(p, msg) for msg in messages]
            if any(len(sigma) != 60 for sigma in sigmas) or p == 0:
                break
            key = encode_key(mul(p))
            recovered = extract(tau, anchor, key, bytes.fromhex(target['point_hex']), list(zip(sigmas, messages)))
            assert recovered['scalar'] == target['scalar_fixture']
            recoveries.append(dict(label=label, scalar=recovered['scalar']))
            verification.append([key] + sigmas)
        else:
            break
    else:
        raise AssertionError('deterministic fixture retry exhaustion')
    remaining = list(range(fixture['n']))
    selection = []
    for label in selected:
        hint = len(remaining)-remaining.index(label)
        selection.append([taus[label], scalar_bytes(hint)])
        remaining.remove(label)
    if fixture['phased']:
        stream = sum(selection, []) + sum(verification, [])
    else:
        stream = sum([a+b for a, b in zip(selection, verification)], [])
    auth = sign(1, digest(tx, 1, code, 1))
    tx['vin'][1]['txinwitness'] = [v.hex() for v in reversed(stream)] + [auth.hex(), code.hex()]
    return tx, recoveries


def execute_values(tx):
    """Independent, deliberately narrow value/height trace of these bytecodes.

    Actual ECDSA and BIP143 equations are checked, with the executed separator
    excluded. Bitcoin Core remains the native validity authority.
    """
    items = [bytes.fromhex(x) for x in tx['vin'][1]['txinwitness']]
    code = items.pop()
    stack, alt = items, []
    peak, start, checks = len(stack), 0, 0
    failure = None
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
            elif op == 0x7a:
                raw = stack.pop()
                assert len(raw) <= 4, 'oversized-roll-index'
                depth = scalar_value(raw)
                assert 0 <= depth < len(stack), 'roll-index-out-of-stack'
                stack.append(stack.pop(len(stack)-1-depth))
            elif op == 0x7c:
                stack[-2:] = stack[-2:][::-1]
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
                # DER is consensus-enforced for every nonempty signature.
                assert sigma and sigma[0] == 0x30, 'non-DER-table-element'
                r, s, flag = unpack_signature(sigma)
                assert len(key) in (33, 65), 'table-element-used-as-key'
                point = decode_verification_key(key)
                msg = digest(tx, 1, code[start:], flag)
                assert verify(int.from_bytes(msg, 'big'), r, s, point)[0], 'ecdsa'
                checks += 1
            else:
                raise ValueError(f'unmodeled opcode {op:x}')
            peak = max(peak, len(stack)+len(alt))
        assert stack == [b'\x01'] and not alt, 'unclean-terminal-stack'
    except (AssertionError, IndexError) as error:
        failure = str(error) or type(error).__name__
    return dict(accepted=failure is None, failure=failure,
                signature_checks=checks, combined_stack_peak=peak)


def mutate_first(tx, tau=None, hint=None, following=None, extra=None):
    changed = copy.deepcopy(tx)
    w = changed['vin'][1]['txinwitness']
    # The script and owner authorization are the last two witness elements.
    if tau is not None:
        w[-3] = tau.hex()
    if hint is not None:
        w[-4] = hint.hex()
    if following is not None:
        w[-5] = following.hex()
    if extra is not None:
        w.insert(0, extra.hex())
    return changed


def cases_for(fixture, txid, vout, mining):
    result = []
    mode = 'phased' if fixture['phased'] else 'inline'
    for selected in itertools.permutations(range(fixture['n']), fixture['t']):
        tx, recovery = make_case(fixture, txid, vout, mining, selected)
        result.append(dict(name=f'{mode}-select-{selected[0]}-{selected[1]}',
                           expected=True, tx=tx, recovery=recovery))
    tx, _ = make_case(fixture, txid, vout, mining, (0, 2))
    zero_base, _ = make_case(fixture, txid, vout, mining, (3, 0))
    tau = bytes.fromhex(fixture['targets'][0]['tau_hex'])
    last_hash = hash160(bytes.fromhex(fixture['targets'][-1]['tau_hex']))
    variants = [
        ('zero-index-hash-equation-satisfied', mutate_first(zero_base, tau=hash160(last_hash), hint=b'')),
        ('negative-index', mutate_first(tx, hint=scalar_bytes(-1))),
        ('beyond-stack', mutate_first(tx, hint=scalar_bytes(1000))),
        ('five-byte-index', mutate_first(tx, hint=b'\x01\x00\x00\x00\x00')),
        ('extra-entry-item', mutate_first(tx, extra=b'\x01')),
    ]
    if fixture['phased']:
        # Select the first table item correctly, then satisfy the last lookup's
        # hash equation with an injected witness hash outside the residual table.
        outside = copy.deepcopy(tx)
        w = outside['vin'][1]['txinwitness']
        w[-6] = scalar_bytes(fixture['n']).hex()
        w[-7] = hash160(bytes.fromhex(fixture['targets'][2]['tau_hex'])).hex()
    else:
        outside = mutate_first(tx, hint=scalar_bytes(fixture['n']+1), following=hash160(tau))
    variants.append(('outside-table-hash-equation-satisfied', outside))
    result.extend(dict(name=f'{mode}-{name}', expected=False, tx=bad) for name, bad in variants)
    # Negative zero is consensus zero but nonminimal under relay policy.
    result.append(dict(name=f'{mode}-negative-zero', expected=False,
                       tx=mutate_first(zero_base, tau=hash160(last_hash), hint=b'\x80')))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host-only', action='store_true')
    parser.add_argument('--shared-anchor-context', action='store_true')
    args = parser.parse_args()
    example = ('pointlock_anchored_shared_context_size_probe' if args.shared_anchor_context
               else 'pointlock_anchored_typed_size_probe')
    built = subprocess.run(['cargo', 'run', '--release', '--locked', '--example',
                            example, '--', '--fixtures'],
                           cwd=ROOT, text=True, capture_output=True, check=True)
    data = json.loads(built.stdout)
    report = dict(scope=__doc__, compiler_commit=data['compiler_commit'], cases=[],
                  general_extraction_proved=False, complete_publication=False,
                  setup_benchmark=False, evidence='locally-reproduced',
                  anchor_context_shared_first_short=args.shared_anchor_context,
                  deployment_class='unclassified')
    binary, provenance = (None, None) if args.host_only else isolated_core_binary(Path('/private/tmp/covenant-core-30.3'), False)
    with tempfile.TemporaryDirectory(prefix='bitcoin-lab-typed-selector-') as temporary:
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
                outputs = [(100_000, mining)] + [(100_000, b'\x00\x20'+hashlib.sha256(bytes.fromhex(f['script_hex'])).digest()) for f in data['fixtures']]
                outputs += [(5_000_000_000-310_000, mining)]
                fund = transaction(coinbase['txid'], coin['n'], [b'\x51'], outputs)
                funding, report['test_only_funding'] = accept_and_mine(node, address, fund['hex'])
                txid = funding['txid']
                report.update(bitcoin_core=provenance, node_options=node.options)
            else:
                txid = '11'*32
                mining = b'\x00\x20'+hashlib.sha256(b'\x51').digest()
            cases = []
            for vout, fixture in enumerate(data['fixtures'], 1):
                cases.extend(cases_for(fixture, txid, vout, mining))
            # All policy checks precede competing-spend block resets.
            for case in cases:
                trace = execute_values(case['tx'])
                assert trace['accepted'] == case['expected'], (case['name'], trace)
                record = {k: v for k, v in case.items() if k != 'tx'}
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
                report.update(evidence='differentially-validated', deployment_class='policy-validated')
            report['metrics'] = []
            for fixture in data['fixtures']:
                mode = 'phased' if fixture['phased'] else 'inline'
                positive = [c for c in cases if c['expected'] and c['name'].startswith(mode)]
                witnesses = [[bytes.fromhex(v) for v in c['tx']['vin'][1]['txinwitness']] for c in positive]
                report['metrics'].append(dict(mode=mode, script_bytes=fixture['script_bytes'],
                    n=fixture['n'], t=fixture['t'], rounds=fixture['rounds'],
                    distinct_short_contexts_per_label=fixture['rounds'],
                    anchor_context_shared_first_short=args.shared_anchor_context,
                    charged_ops=sum(op > 0x60 for _, _, op, data in instructions(bytes.fromhex(fixture['script_hex'])) if data is None),
                    hint_items_per_input=fixture['hint_items'], entry_items=fixture['entry_items'],
                    complete_witness_items=len(witnesses[0]),
                    serialized_witness_bytes=sorted(set(len(compact_size(len(w)))+sum(len(vector(v)) for v in w) for w in witnesses)),
                    combined_stack_peak=max(c['independent_trace']['combined_stack_peak'] for c in report['cases'] if c['expected'] and c['name'].startswith(mode))))
            report['summary'] = dict(positive_cases=sum(c['expected'] for c in cases),
                                   negative_cases=sum(not c['expected'] for c in cases), all_expectations_met=True)
        finally:
            if node:
                node.close()
    paths = [Path(__file__), ROOT/'examples/pointlock_anchored_typed_size_probe.rs',
             ROOT/'Cargo.lock', HERE/'core_check.py', HERE/'anchored_native_core_check.py',
             HERE/'anchored_extraction.py', HERE/'anchored_consensus_flags_check.py',
             HERE/'nonce_relation_extraction.py', HERE/'publication_core_check.py',
             HERE.parent/'covenant-2026-09-17/legacy_same_signature_counterexample.py']
    if args.shared_anchor_context:
        paths.append(ROOT/f'examples/{example}.rs')
    report['source_sha256'] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    suffix = 'host' if args.host_only else 'core'
    prefix = 'shared-context-selector' if args.shared_anchor_context else 'typed-selector'
    (HERE/f'{prefix}-{suffix}-check.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report['summary'], sort_keys=True))


if __name__ == '__main__':
    main()
