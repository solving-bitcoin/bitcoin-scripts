#!/usr/bin/env python3
"""Literal native-recovery lookup and its remaining funding dependency.

Raw host Script boundary, not a Bitcoin consensus interpreter. The native
lookup fixtures use actual secp256k1 equations and ALL transaction hashes.
The combined numeric-root fixture has explicitly mocked signature checks.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from legacy_same_signature_counterexample import P, N, G, add, mul, hash256, signature_integer, verify
sys.path.insert(0, str(HERE))
from r10_parameter_frontier import schedule_for, opcode_count, Q_MIN, Q_MAX
from r9_numeric_root import root_script, decode
sys.path.insert(0, str(HERE.parent / 'seven'))
from search1_nonce_encoding import HASH_OPCODE, EXPANSIONS, hash_word, num_bytes, push, push_num, routing_output


def compact(n):
    if n < 253:
        return bytes([n])
    if n <= 65535:
        return b'\xfd' + struct.pack('<H', n)
    return b'\xfe' + struct.pack('<I', n)


def transaction(outpoint, script_code, outputs, locktime=0):
    """One-input version-2 legacy transaction, final sequence and explicit locktime.

    Outpoint is already the wire-order 32-byte hash. No transaction is funded.
    """
    raw = struct.pack('<I', 2) + b'\x01' + outpoint + bytes(4)
    raw += compact(len(script_code)) + script_code + b'\xff' * 4
    raw += compact(len(outputs))
    for value, script in outputs:
        raw += struct.pack('<Q', value) + compact(len(script)) + script
    return raw + struct.pack('<I', locktime)


def digest(outpoint, suffix, outputs, locktime=0):
    # The suffix contains no CODESEPARATOR and no pushed signature. Therefore
    # legacy CODESEPARATOR stripping and signature FindAndDelete do nothing.
    return int.from_bytes(hash256(transaction(outpoint, suffix, outputs, locktime) + struct.pack('<I', 1)), 'big') % N


def encoded(point):
    assert point is not None
    return bytes([2 + point[1] % 2]) + point[0].to_bytes(32, 'big')


def point(raw):
    if len(raw) != 33 or raw[0] not in (2, 3):
        raise ValueError('noncanonical compressed key')
    x = int.from_bytes(raw[1:], 'big')
    if x >= P:
        raise ValueError('key coordinate')
    y = pow((x*x*x + 7) % P, (P+1)//4, P)
    if y*y % P != (x*x*x+7) % P:
        raise ValueError('key not on curve')
    return x, y if y % 2 == raw[0] % 2 else P-y


def parse_signature(raw):
    if len(raw) < 9 or raw[0] != 0x30 or raw[1] != len(raw)-3 or raw[-1] != 1:
        raise ValueError('strict DER plus ALL required')
    values, pos = [], 2
    for _ in range(2):
        if raw[pos] != 2:
            raise ValueError('DER integer tag')
        size = raw[pos+1]
        data = raw[pos+2:pos+2+size]
        if not size or len(data) != size or data[0] & 128 or (size > 1 and data[0] == 0 and not data[1] & 128):
            raise ValueError('DER integer encoding')
        values.append(int.from_bytes(data, 'big'))
        pos += 2+size
    r, s = values
    if pos != len(raw)-1 or not 0 < r < N or not 0 < s <= N//2:
        raise ValueError('DER scalar or LOW_S')
    return r, s


def recovery_row(alpha, z):
    r, s = parse_signature(alpha)
    roots = []
    for x in (r, r+N):
        if x >= P:
            continue
        try:
            a = point(b'\x02'+x.to_bytes(32, 'big'))
        except ValueError:
            continue
        roots += [a, (a[0], P-a[1])]
    if len(roots) != 4:
        raise ValueError('three-key row requires all four nonce roots')
    minus_zg = mul(-z)
    keys = [encoded(mul(pow(r, -1, N), add(mul(s, a), minus_zg))) for a in roots[:3]]
    assert len(set(keys)) == 3 and all(verify(z, r, s, point(k))[0] for k in keys)
    return (alpha, *keys)


def tail(m):
    # Selected alpha,P1,P2,P3 -> bool; preserve bool while clearing unused rows.
    return bytes.fromhex('53797cad52797cadac6b') + b'\x6d'*(2*m-2) + b'\x6c'


def lookup(rows, standalone=False):
    m = len(rows)
    assert 1 <= m <= 200 and all(len(row) == 4 for row in rows)
    # Incoming alpha,j. In the composition the numeric root checks exact depth.
    raw = bytes.fromhex('745288') if standalone else b''
    raw += b'\x76\x00'+push_num(m)+b'\xa5\x69'  # 0 <= j < m
    raw += b'\x76\x93'*2 + b'\x53\x93\x6b'  # K = 4*j+3 to alt
    for row in reversed(rows):
        for item in row:
            raw += push(item)
    raw += b'\x6c' + bytes.fromhex('766b7a6c')*3 + b'\x7a'
    raw += push_num(4*m)+bytes.fromhex('7a547988ab')
    return raw + tail(m)


def combined(schedule, rows):
    # Entry: reversed selectors, x, q, j. Alt saves j then q before root.
    raw = b'\x6b\x6b'+root_script(schedule)
    raw += b'\x6c\x6c'+b'\x76\x93'*4+b'\x57\x93\x9d\x6c'
    return raw+lookup(rows)


def execute(raw, items, digest_for_suffix=None, mock_check=None):
    stack, alt, pc, separator, peak, ops = list(items), [], 0, 0, len(items), 0
    checks = []
    if len(raw) > 10000 or len(stack) > 1000 or any(len(i) > 520 for i in stack):
        raise ValueError('entry bound')
    while pc < len(raw):
        op = raw[pc]
        pc += 1
        if op <= 75:
            if pc+op > len(raw):
                raise ValueError('truncated push')
            stack.append(raw[pc:pc+op]); pc += op
        elif 0x51 <= op <= 0x60:
            stack.append(num_bytes(op-0x50))
        else:
            ops += 1
            if op == 0x6b: alt.append(stack.pop())
            elif op == 0x6c: stack.append(alt.pop())
            elif op == 0x6d: stack.pop(); stack.pop()
            elif op == 0x74: stack.append(num_bytes(len(stack)))
            elif op == 0x76: stack.append(stack[-1])
            elif op == 0x77: del stack[-2]
            elif op == 0x7c: stack[-1], stack[-2] = stack[-2], stack[-1]
            elif op in (0x79, 0x7a):
                index = decode(stack.pop())
                if not 0 <= index < len(stack): raise ValueError('PICK/ROLL index')
                stack.append(stack[-1-index] if op == 0x79 else stack.pop(-1-index))
            elif op == 0x93:
                a, b = decode(stack.pop()), decode(stack.pop())
                stack.append(num_bytes(a+b))
            elif op == 0xa5:
                upper, lower, value = decode(stack.pop()), decode(stack.pop()), decode(stack.pop())
                stack.append(num_bytes(int(lower <= value < upper)))
            elif op == 0x69:
                if decode(stack.pop()) == 0: raise ValueError('VERIFY')
            elif op in (0x88, 0x9d):
                a, b = stack.pop(), stack.pop()
                if not (a == b if op == 0x88 else decode(a) == decode(b)): raise ValueError('equality')
            elif op in HASH_OPCODE.values():
                name = next(k for k, v in HASH_OPCODE.items() if v == op)
                stack.append(hash_word(stack.pop(), EXPANSIONS[name]))
            elif op == 0xab: separator = pc
            elif op in (0xac, 0xad):
                key, sig = stack.pop(), stack.pop()
                if mock_check is None:
                    r, s = parse_signature(sig)
                    z = digest_for_suffix(raw[separator:])
                    valid = verify(z, r, s, point(key))[0]
                else:
                    valid = mock_check(sig, key, raw[separator:])
                checks.append({'signature': sig.hex(), 'key': key.hex(), 'valid': valid})
                if op == 0xad:
                    if not valid: raise ValueError('CHECKSIGVERIFY')
                else: stack.append(num_bytes(int(valid)))
            else: raise ValueError(f'unsupported opcode {op:02x}')
        peak = max(peak, len(stack)+len(alt))
        if peak > 1000 or any(len(i) > 520 for i in stack): raise ValueError('stack bound')
    return stack, alt, {'script_bytes': len(raw), 'counted_opcodes': ops,
                        'combined_stack_peak': peak, 'native_checks': checks}


def p2sh(script):
    return b'\xa9\x14'+hashlib.new('ripemd160', hashlib.sha256(script).digest()).digest()+b'\x87'


def main():
    body = signature_integer(2)+signature_integer(2**183+17)
    alpha = b'\x30'+bytes([len(body)])+body+b'\x01'
    assert len(alpha) == 32
    outpoint = b'\x42'*32
    # Both authorized rows have EXACTLY the same ordered outputs. Locktime is
    # their explicit non-output transaction-family coordinate, with final input.
    outputs = [[(400000, b'\x51'), (590000, b'\x52')]]*2
    m = len(outputs)
    digests = [digest(outpoint, tail(m), o, j) for j, o in enumerate(outputs)]
    rows = [recovery_row(alpha, z) for z in digests]
    raw = lookup(rows, standalone=True)
    positives = []
    for j, out in enumerate(outputs):
        stack, alt, metrics = execute(raw, [alpha, num_bytes(j)], lambda suffix: digest(outpoint, suffix, out, j))
        assert stack == [b'\x01'] and alt == [] and len(metrics['native_checks']) == 3
        positives.append(metrics)
    negatives = []
    variants = [
        ('wrong row', [alpha, b'\x01'], outputs[0]),
        ('amount changed', [alpha, b''], [(400001, b'\x51'), (589999, b'\x52')]),
        ('output order changed', [alpha, b''], list(reversed(outputs[0]))),
        ('script changed', [alpha, b''], [(400000, b'\x53'), (590000, b'\x52')]),
        ('negative index', [alpha, num_bytes(-1)], outputs[0]),
        ('index above table', [alpha, num_bytes(m)], outputs[0]),
        ('oversized index', [alpha, b'\x01'*5], outputs[0]),
        ('different alpha', [alpha[:-1]+b'\x02', b''], outputs[0]),
        ('extra entry item', [b'junk', alpha, b''], outputs[0]),
        ('missing entry item', [alpha], outputs[0]),
    ]
    for name, items, out in variants:
        try:
            stack, alt, _ = execute(raw, items, lambda suffix: digest(outpoint, suffix, out))
            assert stack != [b'\x01'] or alt
        except (ValueError, IndexError): pass
        negatives.append(name)

    # Replacing the whole uncommitted table trivially authorizes other outputs.
    replacement_outputs = [(990000, b'\x55')]
    replacement_rows = [recovery_row(alpha, digest(outpoint, tail(m), replacement_outputs))]+rows[1:]
    replacement_script = lookup(replacement_rows, standalone=True)
    stack, alt, replacement_metrics = execute(replacement_script, [alpha, b''], lambda suffix: digest(outpoint, suffix, replacement_outputs))
    assert stack == [b'\x01'] and not alt and p2sh(raw) != p2sh(replacement_script)

    # Chronology: a funding tx paying the newly filled table has a NEW outpoint.
    chronology = []
    proposed_outpoint, current_script = outpoint, raw
    for step in range(3):
        funding = transaction(b'\x24'*32, b'', [(1000000, p2sh(current_script))])
        real_outpoint = hash256(funding)
        stale_z = digest(proposed_outpoint, tail(m), outputs[0])
        actual_z = digest(real_outpoint, tail(m), outputs[0])
        assert actual_z != stale_z
        try:
            execute(current_script, [alpha, b''], lambda suffix: digest(real_outpoint, suffix, outputs[0]))
            raise AssertionError('stale row unexpectedly accepted')
        except ValueError as exc:
            assert str(exc) == 'CHECKSIGVERIFY'
        chronology.append({'step': step, 'proposed_outpoint_wire': proposed_outpoint.hex(),
                           'resulting_funding_txid': real_outpoint[::-1].hex(),
                           'script_hash160': p2sh(current_script)[2:-1].hex(),
                           'reference_scalar': f'{stale_z:064x}', 'actual_scalar': f'{actual_z:064x}',
                           'stale_table_rejected': True})
        proposed_outpoint = real_outpoint
        current_rows = [recovery_row(alpha, digest(proposed_outpoint, tail(m), o, j)) for j, o in enumerate(outputs)]
        current_script = lookup(current_rows, standalone=True)

    # Real hash routing and exact Script stack operations. Signature checks are
    # mocks here because no rare DER numeric-root output was mined.
    schedule = schedule_for(37)
    structural = []
    for size in (1, 2, 17, 18):
        for q in (Q_MIN, 0, Q_MAX):
            selectors = tuple(i % 2 for i in range(36))
            x = 16*q+7
            root = routing_output(hashlib.sha256(num_bytes(x)).digest(), schedule, selectors)
            fake_rows = [(root, *rows[0][1:]) for _ in range(size)]
            for j in sorted(set((0, size-1))):
                combined_raw = combined(schedule, fake_rows)
                items = [num_bytes(i) for i in reversed(selectors)]+[num_bytes(x), num_bytes(q), num_bytes(j)]
                stack, alt, metrics = execute(combined_raw, items, mock_check=lambda sig, key, suffix: sig == root and key in rows[0][1:] and suffix == tail(size))
                assert stack == [b'\x01'] and not alt
                assert metrics['counted_opcodes'] == opcode_count(combined_raw) == 3*37+55+2*size
                structural.append({'rows': size, 'q': q, 'index': j,
                                   **{k: v for k, v in metrics.items() if k != 'native_checks'}})
    resource_table = []
    for size in (1, 2, 3, 8, 17, 18):
        packed = combined(schedule, [rows[0]]*size)
        assert len(packed) == 137*size+(213 if size <= 4 else 214 if size <= 16 else 215)
        resource_table.append({'rows': size, 'script_bytes': len(packed), 'opcodes': opcode_count(packed),
                               'redeem_element_within_520_bytes': len(packed) <= 520,
                               'within_201_opcodes': opcode_count(packed) <= 201,
                               'complete_entry_items': 39, 'path_hint_items': 36, 'packing_hint_items': 1,
                               'incremental_lookup_hint_items': 0, 'table_literal_items': 4*size,
                               'upper_bound_combined_stack_peak': max(42, 4*size+3)})
    # All 36 path selectors are OP_0/OP_1 pushes in the structural fixtures.
    # x and q use either a one-byte small-integer push or at most 5 bytes each.
    assert all(0 <= i <= 1 for i in selectors)
    assert len(push(alpha)+push_num(0)) == len(push(alpha)+push_num(1)) == 34
    report = {
        'question': 'Can a precommitted small native recovery table bind actual outputs within the R10 opcode frontier?',
        'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
        'scope': 'Raw host model; actual curve/ALL hashes for standalone lookup, mocked CHECKSIG for combined root layout. No funded chain or Core execution.',
        'result': 'Exact native table lookup fits. CODESEPARATOR removes table from scriptCode, but table commitment still changes the funding txid needed to generate that table.',
        'signature_32_bytes': alpha.hex(), 'standalone_script_hex': raw.hex(),
        'standalone_rows': [[v.hex() for v in row] for row in rows],
        'standalone_tail_hex': tail(m).hex(), 'standalone_reference_scalars': [f'{z:064x}' for z in digests],
        'standalone_intended_ordered_outputs': [{'value': v, 'script_hex': s.hex()} for v, s in outputs[0]],
        'standalone_reference_locktimes': [0, 1],
        'standalone_positive_vectors': positives, 'standalone_negative_rejections': negatives,
        'standalone_entry_items': 2, 'standalone_hint_items': 0,
        'standalone_script_sig_data_bytes': [len(push(alpha)+push_num(j)) for j in range(m)],
        'standalone_serialized_witness_bytes': 0,
        'witness_only_table_replacement_accepts_other_outputs': bool(replacement_metrics['native_checks']),
        'funding_dependency_steps': chronology,
        'combined_root_structural_mock_vectors': structural, 'combined_resources': resource_table,
        'combined_witness_accounting': {'complete_entry_items': 39, 'path_hints': 36,
                                      'packing_hints': 1, 'nonhint_x_and_index_items': 2,
                                      'unlocking_script_push_items_including_redeem_script': 40,
                                      'serialized_hint_push_bytes': [37, 41],
                                      'hints_coexist_at_entry': True,
                                      'table_entry_items_at_invocation': 0,
                                      'data_script_sig_bytes_for_M2': [39, 47],
                                      'P2SH_redeem_script_push_bytes_M2': 490,
                                      'P2SH_script_sig_bytes_M2': [529, 537],
                                      'serialized_witness_bytes': 0,
                                      'scope': 'Bounds for the raw unmined n37 layout, not a generated valid spend.'},
        'finite_table_cost': {'per_row_literal_bytes': 135, 'per_row_EC_recovery': 'One zG, three fixed-root scalar products (shared for common alpha), and three affine recovery keys; O(M) after a fixed outpoint.',
                              'lookup_opcodes': '34+2M', 'combined_opcodes': '3n+55+2M',
                              'combined_bytes_n37': '213+137M for 1<=M<=4; 214+137M for 5<=M<=16; 215+137M for 17<=M<=31',
                              'setup_below_2_64_established': False,
                              'fixed_point_search_complexity_proved': False}
    }
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
