#!/usr/bin/env python3
"""Validate exact policy-compiled point-lock vectors on isolated Core regtest.

Only public deterministic test vectors and a temporary regtest chain are used.
The scripts are read byte-for-byte from vectors.json; no NOP padding is added.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / 'research/covenant-2026-09-17'))
from core_gate_check import isolated_core_binary, p2sh, push
from core_regtest import Node, consensus_check, transaction, compact_size, vector
from legacy_same_signature_counterexample import N, P, hash256, verify

BUG_DIGEST = b'\x01' + bytes(31)


def instructions(script):
    pc = 0
    while pc < len(script):
        start = pc
        op = script[pc]
        pc += 1
        data = None
        if 1 <= op <= 75:
            data = script[pc:pc + op]
            assert len(data) == op
            pc += op
        elif op == 0x4c:
            size = script[pc]
            pc += 1
            data = script[pc:pc + size]
            assert len(data) == size
            pc += size
        yield start, pc, op, data


def scalar_bytes(value):
    if value == 0:
        return b''
    sign = value < 0
    value = abs(value)
    data = bytearray(value.to_bytes((value.bit_length() + 7) // 8, 'little'))
    if data[-1] & 128:
        data.append(128 if sign else 0)
    elif sign:
        data[-1] |= 128
    return bytes(data)


def scalar_value(data):
    if not data:
        return 0
    value = int.from_bytes(data, 'little')
    if data[-1] & 128:
        value &= ~(128 << (8 * (len(data) - 1)))
        return -value
    return value


def unpack_signature(sig):
    assert 9 <= len(sig) <= 73 and sig[0] == 0x30 and sig[1] == len(sig) - 3
    assert sig[2] == 2
    nr = sig[3]
    assert nr > 0 and sig[4] & 128 == 0
    assert not (nr > 1 and sig[4] == 0 and sig[5] & 128 == 0)
    assert sig[4 + nr] == 2
    ns = sig[5 + nr]
    assert ns > 0 and nr + ns + 7 == len(sig) and sig[6 + nr] & 128 == 0
    assert not (ns > 1 and sig[6 + nr] == 0 and sig[7 + nr] & 128 == 0)
    r = int.from_bytes(sig[4:4 + nr], 'big')
    s = int.from_bytes(sig[6 + nr:-1], 'big')
    assert 0 < r < N and 0 < s < N
    return r, s, sig[-1]


def decode_key(data):
    assert len(data) == 33 and data[0] in (2, 3)
    x = int.from_bytes(data[1:], 'big')
    assert x < P
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    assert y * y % P == (x * x * x + 7) % P
    if y % 2 != data[0] % 2:
        y = -y % P
    return x, y


def serialize_base(inputs, outputs):
    raw = struct.pack('<I', 2) + compact_size(len(inputs))
    for txid, vout, code, sequence in inputs:
        raw += bytes.fromhex(txid)[::-1] + struct.pack('<I', vout) + vector(code) + struct.pack('<I', sequence)
    raw += compact_size(len(outputs))
    for amount, script in outputs:
        raw += struct.pack('<Q', amount) + vector(script)
    return raw + bytes(4)


def serialize_spend(inputs, outputs, helper_index):
    base = serialize_base(inputs, outputs)
    witnesses = b''.join(b'\x01\x01\x51' if i == helper_index else b'\x00'
                         for i in range(len(inputs)))
    raw = base[:4] + b'\x00\x01' + base[4:-4] + witnesses + base[-4:]
    return {'hex': raw.hex(), 'txid': hash256(base)[::-1].hex(),
            'wtxid': hash256(raw)[::-1].hex(), 'base_bytes': len(base),
            'total_bytes': len(raw), 'witness_bytes': len(witnesses),
            'marker_flag_bytes': 2, 'weight': len(base) * 4 + len(witnesses) + 2}


def native_digest(inputs, outputs, input_index, script_suffix, sig):
    # A valid signature push is absent at every opcode boundary in these locks.
    # This explicitly checks the FindAndDelete premise before stripping separators.
    signature_push = push(sig)
    chunks = []
    for start, end, op, _ in instructions(script_suffix):
        assert not script_suffix.startswith(signature_push, start), 'Unexpected FindAndDelete match'
        if op != 0xab:
            chunks.append(script_suffix[start:end])
    code = b''.join(chunks)
    flag = sig[-1]
    base_flag = flag & 31
    if base_flag == 3 and input_index >= len(outputs):
        return BUG_DIGEST, None, code
    active_inputs = []
    for i, (txid, vout, _, sequence) in enumerate(inputs):
        if i != input_index and base_flag in (2, 3):
            sequence = 0
        active_inputs.append((txid, vout, code if i == input_index else b'', sequence))
    active_outputs = list(outputs)
    if base_flag == 2:
        active_outputs = []
    elif base_flag == 3:
        active_outputs = [(2**64 - 1, b'')] * input_index + [outputs[input_index]]
    if flag & 128:
        active_inputs = [active_inputs[input_index]]
    preimage = serialize_base(active_inputs, active_outputs) + struct.pack('<I', flag)
    return hash256(preimage), preimage, code


def host_trace(script, signature, inputs, outputs, locked_index):
    """Independent small interpreter for the exact two supported opcode layouts."""
    stack = [signature]
    peak = 1
    counted = 0
    checks = []
    separator = 0
    reason = None
    for _, end, op, data in instructions(script):
        if op > 0x60:
            counted += 1
        if data is not None:
            stack.append(data)
        elif 0x51 <= op <= 0x60:
            stack.append(scalar_bytes(op - 0x50))
        elif op == 0x82:  # SIZE
            stack.append(scalar_bytes(len(stack[-1])))
        elif op == 0xa0:  # GREATERTHAN
            right, left = scalar_value(stack.pop()), scalar_value(stack.pop())
            stack.append(scalar_bytes(int(left > right)))
        elif op == 0x69:  # VERIFY
            if scalar_value(stack.pop()) == 0:
                reason = 'verify-failed'
                break
        elif op == 0x76:
            stack.append(stack[-1])
        elif op == 0x6e:
            stack.extend(stack[-2:])
        elif op == 0xab:
            separator = end
        elif op in (0xac, 0xad):
            key, sig = stack.pop(), stack.pop()
            digest, preimage, code = native_digest(inputs, outputs, locked_index, script[separator:], sig)
            try:
                r, s, flag = unpack_signature(sig)
                accepted = verify(int.from_bytes(digest, 'big') % N, r, s, decode_key(key))[0]
            except (AssertionError, ValueError):
                accepted = False
                r = s = flag = None
            checks.append({'key': key.hex(), 'signature': sig.hex(), 'digest': digest.hex(),
                           'script_code': code.hex(), 'preimage': preimage.hex() if preimage else None,
                           'single_bug': digest == BUG_DIGEST and preimage is None,
                           'r': r, 's': s, 'flag': flag, 'accepted': accepted})
            if op == 0xad and not accepted:
                reason = 'checksigverify-failed'
                break
            if op == 0xac:
                stack.append(scalar_bytes(int(accepted)))
        else:
            raise ValueError('Unsupported opcode: %02x' % op)
        peak = max(peak, len(stack))
    success = reason is None and len(stack) == 1 and scalar_value(stack[-1]) != 0
    return {'accepted': success, 'checks': checks, 'combined_stack_peak': peak,
            'executed_non_push_opcodes': counted, 'final_stack_items': len(stack), 'failure': reason}


def fixtures(vectors):
    rows = []
    cases = vectors['cases']
    for case in cases:
        for kind in ('two_check', 'three_check'):
            for wrapper in ('p2sh', 'bare'):
                rows.append({'name': case['name'] + '-' + kind + '-' + wrapper, 'case': case,
                             'kind': kind, 'wrapper': wrapper, 'mutation': None, 'expected': True})
    representative = next(case for case in cases if case['name'] == 'representative')
    for kind in ('two_check', 'three_check'):
        for mutation, expected in (('undefined-flag-23', True), ('mutated-s', False),
                                   ('locked-input-index-zero', False), ('two-outputs', False),
                                   ('size-57', False)):
            rows.append({'name': kind + '-' + mutation, 'case': representative, 'kind': kind,
                         'wrapper': 'p2sh', 'mutation': mutation, 'expected': expected})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vectors', type=Path, default=HERE / 'vectors.json')
    parser.add_argument('--output', type=Path, default=HERE / 'core_check.json')
    args = parser.parse_args()
    vector_bytes = args.vectors.read_bytes()
    vectors = json.loads(vector_bytes)
    rows = fixtures(vectors)
    binary, provenance = isolated_core_binary(Path('/private/tmp/covenant-core-30.3'), False)
    report = {'scope': __doc__, 'bitcoin_core': provenance,
              'vectors_sha256': hashlib.sha256(vector_bytes).hexdigest(),
              'fixture_count': len(rows), 'results': [],
              'consensus_method': 'generateblock with raw transactions, verifies connected block contains txid',
              'policy_method': 'testmempoolaccept with acceptnonstdtxn=0; no transactions submitted to mempool',
              'script_compilation': vectors.get('compilation', 'Policy-compiled vectors supplied by Rust generator'),
              'host_verification': 'Independent Python ECDSA equation and opcode stack trace, not bitcoin-scriptexec'}
    with tempfile.TemporaryDirectory(prefix='bitcoin-lab-pointlock-') as temporary:
        node = Node(binary, Path(temporary))
        try:
            node.ready()
            report['node_options'] = node.options
            report['network_info'] = {'networkactive': node.rpc('getnetworkinfo')['networkactive'],
                                      'peer_count': len(node.rpc('getpeerinfo'))}
            assert report['network_info'] == {'networkactive': False, 'peer_count': 0}
            address = node.rpc('decodescript', '51')['segwit']['address']
            mining = bytes.fromhex(node.rpc('validateaddress', address)['scriptPubKey'])
            blocks = []
            for _ in range(101):
                node.tick()
                blocks += node.rpc('generatetoaddress', 1, address)
            coinbase = node.rpc('getblock', blocks[0], 2)['tx'][0]
            coin = next(output for output in coinbase['vout'] if output['scriptPubKey']['hex'] == mining.hex())
            funding_outputs = []
            for row in rows:
                script = bytes.fromhex(row['case'][row['kind'] + '_script'])
                assert len(script) == {'two_check': 76, 'three_check': 79}[row['kind']]
                funding_outputs += [(1000000, mining),
                                    (1000000, p2sh(script) if row['wrapper'] == 'p2sh' else script)]
            funding_outputs.append((5000000000 - len(funding_outputs) * 1000000 - 10000, mining))
            funding = transaction(coinbase['txid'], coin['n'], [b'\x51'], funding_outputs)
            assert consensus_check(node, address, funding)['accepted']
            report['funding'] = funding
            for ordinal, row in enumerate(rows):
                script = bytes.fromhex(row['case'][row['kind'] + '_script'])
                sig = bytes.fromhex(row['case']['signature'])
                if row['mutation'] == 'undefined-flag-23':
                    sig = sig[:-1] + b'\x23'
                elif row['mutation'] == 'mutated-s':
                    changed = bytearray(sig)
                    changed[-2] ^= 1
                    sig = bytes(changed)
                elif row['mutation'] == 'size-57':
                    sig = bytes(57)
                script_sig = push(sig) + (push(script) if row['wrapper'] == 'p2sh' else b'')
                inputs = [(funding['txid'], ordinal * 2, b'', 0xffffffff),
                          (funding['txid'], ordinal * 2 + 1, script_sig, 0xffffffff)]
                locked_index, helper_index = 1, 0
                if row['mutation'] == 'locked-input-index-zero':
                    inputs.reverse()
                    locked_index, helper_index = 0, 1
                outputs = [(1990000, b'\x00\x14' + b'\x11' * 20)]
                if row['mutation'] == 'two-outputs':
                    outputs = [(990000, outputs[0][1]), (1000000, b'\x00\x14' + b'\x22' * 20)]
                spend = serialize_spend(inputs, outputs, helper_index)
                trace = host_trace(script, sig, inputs, outputs, locked_index)
                assert trace['accepted'] == row['expected'], (row['name'], trace)
                decoded = node.rpc('decoderawtransaction', spend['hex'])
                assert decoded['txid'] == spend['txid'] and decoded['weight'] == spend['weight']
                assert decoded['hash'] == spend['wtxid'] and decoded['size'] == spend['total_bytes']
                assert node.rpc('getrawmempool') == []
                policy = node.rpc('testmempoolaccept', [spend['hex']])[0]
                consensus = consensus_check(node, address, spend)
                assert consensus['accepted'] == row['expected'], (row['name'], consensus)
                has_separator = any(op == 0xab for _, _, op, _ in instructions(script))
                try:
                    _, s, flag = unpack_signature(sig)
                    policy_encoding = s <= N // 2 and flag in (1, 2, 3, 129, 130, 131)
                except AssertionError:
                    policy_encoding = False
                expected_policy = row['expected'] and row['wrapper'] == 'p2sh' and not has_separator and policy_encoding
                assert policy['allowed'] == expected_policy, (row['name'], policy, expected_policy)
                report['results'].append({
                    'name': row['name'], 'case_name': row['case']['name'], 'variant': row['kind'],
                    'wrapper': row['wrapper'], 'mutation': row['mutation'], 'expected_consensus': row['expected'],
                    'expected_policy': expected_policy, 'has_codeseparator': has_separator,
                    'target': row['case']['target'], 'signature': sig.hex(), 'signature_bytes': len(sig),
                    'script': script.hex(), 'script_bytes': len(script),
                    'locking_script_bytes': 23 if row['wrapper'] == 'p2sh' else len(script),
                    'locked_input_index': locked_index, 'locked_input_data_items': 1, 'hint_items': 0,
                    'script_sig_bytes': len(script_sig), 'script_sig_push_items': 2 if row['wrapper'] == 'p2sh' else 1,
                    'locked_input_witness_items': 0, 'helper_witness_items': 1,
                    'complete_transaction_witness_bytes': spend['witness_bytes'],
                    'combined_stack_peak': trace['combined_stack_peak'],
                    'executed_lock_non_push_opcodes': trace['executed_non_push_opcodes'],
                    'wrapper_extra_non_push_opcodes': 2 if row['wrapper'] == 'p2sh' else 0,
                    'all_entry_data_coexists': True, 'altstack_used': False,
                    'host_trace': trace, 'transaction': spend, 'consensus': consensus, 'policy': policy,
                    'evidence': 'differentially-validated',
                    'deployment_class': ('policy-validated' if expected_policy else 'consensus-validated')
                        if row['expected'] else 'consensus-incompatible'})
                print('PASS', row['name'], 'consensus=', consensus['accepted'], 'policy=', policy['allowed'], flush=True)
            report['all_expectations_met'] = True
        finally:
            node.close()
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(args.output)


if __name__ == '__main__':
    main()
