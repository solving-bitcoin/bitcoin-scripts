#!/usr/bin/env python3
"""Two parallel ECDSA cycles: exact public algebra and inspectable raw layouts.

No Core, repository compiler, field-library tests, or funded transactions.
The local stack interpreter below is deliberately limited to this raw vector.
"""
from collections import Counter, defaultdict
import hashlib
import itertools
import json
import math
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from legacy_same_signature_counterexample import G, N, P, add, mul, signature_integer, verify
from r9_four_roots import encoded, neg, roots


def scalar(label):
    return int.from_bytes(hashlib.sha256(label.encode()).digest(), 'big') % N or 1


def compact(n):
    if n < 253:
        return bytes([n])
    if n <= 65535:
        return b'\xfd'+struct.pack('<H', n)
    return b'\xfe'+struct.pack('<I', n)


def push(data):
    if len(data) <= 75:
        return bytes([len(data)])+data
    if len(data) <= 255:
        return b'\x4c'+bytes([len(data)])+data
    return b'\x4d'+struct.pack('<H', len(data))+data


def number(n):
    assert 0 <= n < 128
    return bytes([0 if n == 0 else 0x50+n]) if n <= 16 else push(bytes([n]))


def der(r, s):
    body = signature_integer(r)+signature_integer(s)
    return b'\x30'+bytes([len(body)])+body+b'\x01'


def pubkey(point):
    assert point is not None
    return bytes.fromhex(encoded(point))


def unpack_der(sig):
    assert sig[0] == 0x30 and sig[1] == len(sig)-3
    assert sig[2] == 2
    length = sig[3]
    r = int.from_bytes(sig[4:4+length], 'big')
    pos = 4+length
    assert sig[pos] == 2 and pos+2+sig[pos+1] == len(sig)-1
    return r, int.from_bytes(sig[pos+2:-1], 'big')


def decode_pubkey(key):
    assert len(key) == 33 and key[0] in (2, 3)
    x = int.from_bytes(key[1:], 'big')
    assert x < P
    y = pow((x**3+7) % P, (P+1)//4, P)
    assert y*y % P == (x**3+7) % P
    return x, y if y % 2 == key[0] % 2 else P-y


def instructions(raw):
    pc = 0
    while pc < len(raw):
        start = pc
        op = raw[pc]
        pc += 1
        data = None
        if 1 <= op <= 75:
            data = raw[pc:pc+op]
            assert len(data) == op
            pc += op
        yield start, pc, op, data
    assert pc == len(raw)


def layout(m, separators=True, size_cap=False):
    # Entry: P0 Q0 ... P(m-1) Q(m-1) sigma0 ... sigma(m-1).
    assert 2 <= m <= 12
    total = 3*m
    raw = b''
    for v in range(m):
        for key in (2*v, 2*v+1):
            raw += number(total-1-key)+b'\x79\x82'+number(33)+b'\x88\x75'
        raw += number(total-1-2*v)+b'\x79'+number(total-2*v-1)+b'\x79\x87\x91\x69'
    for edge in range(m):
        for side, vertex in enumerate((edge, (edge+1) % m)):
            if separators and (edge or side):
                raw += b'\xab'
            for copy in (0, 1):
                raw += number(m-1-edge)+b'\x79'
                if size_cap and side == 0 and copy == 0:
                    raw += b'\x82'+number(60)+b'\xa1\x69'
                raw += number(total-(2*vertex+copy))+b'\x79\xad'
    raw += b'\x6d'*(total//2)+(b'\x75' if total % 2 else b'')+b'\x51'
    opcount = sum(op > 0x60 for _, _, op, _ in instructions(raw))
    expected = 25*m+(2*m-1 if separators else 0)+(3*m if size_cap else 0)+(total+1)//2
    assert opcount == expected
    return raw, {'vertices': m, 'raw_redeemscript_bytes': len(raw),
                 'raw_redeemscript_hex': raw.hex(), 'counted_opcodes': opcount,
                 'signature_checks': 4*m, 'code_separators': 2*m-1 if separators else 0,
                 'entry_key_data_items': 2*m, 'entry_signature_data_items': m,
                 'entry_data_items': total, 'auxiliary_hint_items': 0,
                 'entry_bottom_to_top': [f'{c}{i}' for i in range(m) for c in ('P', 'Q')]
                                       +[f'sigma{i}' for i in range(m)],
                 'combined_stack_peak_by_inspection': total+3,
                 'signature_size_cap': 60 if size_cap else None,
                 'deployment_class': 'consensus-incompatible' if opcount > 201 else 'unclassified',
                 'includes': 'complete-leaf: exact raw boundary vector, guards, checks, cleanup and true; input pushes and transaction excluded; not compiler-produced'}


def contexts(raw):
    start, result = 0, []
    for _, end, op, _ in instructions(raw):
        if op == 0xab:
            start = end
        elif op == 0xad:
            # All pushed data are one-byte numeric constants: no serialized
            # signature can match at an opcode boundary for FindAndDelete.
            suffix = raw[start:]
            result.append(b''.join(suffix[a:b] for a, b, o, _ in instructions(suffix) if o != 0xab))
    return result


def raw_tx(script_sig, recipient=0x11):
    output_script = b'\x00\x14'+bytes([recipient])*20
    return (struct.pack('<I', 2)+b'\x01'+b'\x42'*32+struct.pack('<I', 0)
            +compact(len(script_sig))+script_sig+b'\xff'*4+b'\x01'
            +struct.pack('<Q', 990000)+compact(len(output_script))+output_script+bytes(4))


def hash256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def native_contexts(raw, recipient=0x11):
    preimages = [raw_tx(code, recipient)+struct.pack('<I', 1) for code in contexts(raw)]
    return [int.from_bytes(hash256(pre), 'big') % N for pre in preimages], preimages


def run_layout(raw, entry, digests):
    stack = list(entry)
    peak, checks, operations = len(stack), 0, 0
    for _, _, op, data in instructions(raw):
        operations += int(op > 0x60)
        if data is not None:
            stack.append(data)
        elif op == 0:
            stack.append(b'')
        elif 0x51 <= op <= 0x60:
            stack.append(bytes([op-0x50]))
        elif op == 0x79:
            index = int.from_bytes(stack.pop(), 'little')
            assert index < len(stack)
            stack.append(stack[-1-index])
        elif op == 0x82:
            stack.append(bytes([len(stack[-1])]))
        elif op == 0x88:
            assert stack.pop() == stack.pop()
        elif op == 0x87:
            stack.append(bytes([int(stack.pop() == stack.pop())]))
        elif op == 0x91:
            stack.append(bytes([int(not any(stack.pop()))]))
        elif op == 0x69:
            assert any(stack.pop())
        elif op == 0xa1:
            b, a = stack.pop(), stack.pop()
            stack.append(bytes([int(int.from_bytes(a, 'little') <= int.from_bytes(b, 'little'))]))
        elif op == 0x75:
            stack.pop()
        elif op == 0x6d:
            stack.pop()
            stack.pop()
        elif op == 0xab:
            pass
        elif op == 0xad:
            q, sig = decode_pubkey(stack.pop()), stack.pop()
            r, s = unpack_der(sig)
            assert 1 <= r < N and 1 <= s <= N//2
            assert verify(digests[checks], r, s, q)[0]
            checks += 1
        else:
            raise AssertionError(hex(op))
        peak = max(peak, len(stack))
        assert peak <= 1000
    assert stack == [b'\x01'] and checks == len(digests)
    return {'checks': checks, 'combined_stack_peak': peak, 'executed_non_push_opcodes': operations}


def algebra_case(m):
    centers = [scalar(f'R10-center-{m}-{i}') for i in range(m)]
    width = scalar(f'R10-width-{m}')
    orientation = [(-1)**(i % 3) for i in range(m)]
    nonces = [i+1 for i in range(m)]
    rs = [mul(k)[0] % N for k in nonces]
    assert all(r >= P-N for r in rs)  # These fixtures have exactly two roots.
    pairs = [(mul((c+o*width) % N), mul((c-o*width) % N)) for c, o in zip(centers, orientation)]
    sigs, zs, signs = [], [], []
    for i, (k, r) in enumerate(zip(nonces, rs)):
        s0 = width*r*pow(k, -1, N) % N
        s = min(s0, N-s0)
        sigs.append(der(r, s))
        left, right = -r*centers[i] % N, -r*centers[(i+1) % m] % N
        zs.extend((left, left, right, right))
        observed = []
        for j, z in ((i, left), ((i+1) % m, right)):
            results = [verify(z, r, s, q) for q in pairs[j]]
            assert all(v[0] for v in results) and results[0][1] == neg(results[1][1])
            observed.append(results[0][1])
        signs.append(1 if observed[0] == observed[1] else -1)
    assert math.prod(signs) == 1
    for i in range(m):
        assert zs[4*((i-1) % m)+2]*pow(rs[(i-1) % m], -1, N) % N == zs[4*i]*pow(rs[i], -1, N) % N
    entry = [pubkey(q) for pair in pairs for q in pair]+sigs
    raw, _ = layout(m)
    execution = run_layout(raw, entry, zs)
    changed = list(zs)
    changed[2] = changed[3] = (zs[2]+1) % N
    try:
        run_layout(raw, entry, changed)
        raise RuntimeError('bad digest accepted')
    except AssertionError:
        pass
    return {'vertices': m, 'source': 'constructed scalar contexts, NOT native transaction hashes',
            'known_nonce_scalars_hex': [f'{k:x}' for k in nonces],
            'r_hex': [f'{r:x}' for r in rs], 'centers_hex': [f'{c:x}' for c in centers],
            'half_width_hex': f'{width:x}', 'observed_edge_parities': signs,
            'digest_scalars_hex': [f'{z:x}' for z in zs],
            'entry_hex': [v.hex() for v in entry], 'execution': execution,
            'single_local_digest_mutation_rejected': True}


def native_smoke(m, size_cap=False):
    # Same-context variant is readily spendable for either output; it is a
    # control case, not evidence that the distinct-context construction works.
    raw, metrics = layout(m, separators=False, size_cap=size_cap)
    k = pow(2, -1, N)
    r = mul(k)[0] % N
    width = scalar('R10-native-common-width')
    s0 = width*r*pow(k, -1, N) % N
    s = min(s0, N-s0)
    results = []
    for recipient in (0x11, 0x22):
        zs, preimages = native_contexts(raw, recipient)
        assert len(set(zs)) == 1
        center = -zs[0]*pow(r, -1, N) % N
        pair = [pubkey(mul((center+width) % N)), pubkey(mul((center-width) % N))]
        entry = pair*m+[der(r, s)]*m
        observed = run_layout(raw, entry, zs)
        script_sig = b''.join(push(v) for v in entry)+push(raw)
        tx = raw_tx(script_sig, recipient)
        results.append({'recipient_byte': recipient, 'preimage_hex': preimages[0].hex(),
                        'digest_hex': hash256(preimages[0]).hex(), 'entry_hex': [v.hex() for v in entry],
                        'script_sig_bytes': len(script_sig), 'script_sig_push_items': len(entry)+1,
                        'serialized_witness_bytes': 0, 'transaction_hex': tx.hex(),
                        'transaction_weight': 4*len(tx), 'txid': hash256(tx)[::-1].hex(),
                        'execution': observed, 'funded': False})
    sep_raw, _ = layout(m, size_cap=size_cap)
    sep_zs, _ = native_contexts(sep_raw)
    failures = [i for i in range(m) if sep_zs[4*((i-1) % m)+2] != sep_zs[4*i]]
    assert len(failures) == m and all(sep_zs[i] == sep_zs[i+1] for i in range(0, 4*m, 2))
    return {'layout': metrics, 'results': results, 'with_separators_fixed_common_r':
            {'distinct_native_contexts': len(set(sep_zs)), 'failed_local_equalities': failures,
             'digest_scalars_hex': [f'{z:x}' for z in sep_zs]},
            'scope': 'independent local ECDSA and stack replay of unfunded legacy ALL transaction vectors; no Core result'}


def four_root_states():
    points = roots()
    pairs = [(i, j) for i in range(4) for j in range(4) if i != j]
    differences = defaultdict(list)
    for i, j in pairs:
        differences[add(points[i], neg(points[j]))].append((i, j))
    transitions = []
    for difference, states in differences.items():
        for left, right in itertools.product(states, repeat=2):
            shift = add(points[right[0]], neg(points[left[0]]))
            assert shift == add(points[right[1]], neg(points[left[1]]))
            transitions.append({'from': left, 'to': right, 'difference': encoded(difference),
                                'translation': encoded(shift), 'nonzero': shift is not None})
    counts = Counter(len(states) for states in differences.values())
    assert counts == {1: 4, 2: 4}
    assert len(transitions) == 20 and sum(t['nonzero'] for t in transitions) == 8
    nonzero = {t['translation'] for t in transitions if t['nonzero']}
    expected = {encoded(add(points[0], points[2])), encoded(add(points[0], points[3])),
                encoded(neg(add(points[0], points[2]))), encoded(neg(add(points[0], points[3])))}
    assert nonzero == expected
    return {'r': 2, 'roots_hex': [encoded(q) for q in points], 'ordered_pairs': pairs,
            'distinct_ordered_differences': len(differences),
            'difference_multiplicity_histogram': dict(counts),
            'same_scale_ordered_pair_transitions': transitions,
            'nonzero_translations': sorted(nonzero),
            'scope': 'exact secp256k1 r=2 enumeration; general four-root formulas are derived in the report'}


def free_r_relaxation():
    m = 7
    left = [scalar(f'R10-free-r-L-{i}') for i in range(m)]
    right = [scalar(f'R10-free-r-R-{i}') for i in range(m-1)]
    right.append(math.prod(left) * pow(math.prod(right) % N, -1, N) % N)
    rs = [scalar('R10-free-r-scale')]
    for i in range(1, m):
        rs.append(rs[-1]*left[i]*pow(right[i-1], -1, N) % N)
    assert all(right[(i-1) % m]*rs[i] % N == left[i]*rs[(i-1) % m] % N for i in range(m))
    assert math.prod(left) % N == math.prod(right) % N
    bad = list(right)
    bad[-1] = (bad[-1]+1) % N
    assert math.prod(left) % N != math.prod(bad) % N
    return {'vertices': m, 'left_z_hex': [f'{z:x}' for z in left],
            'right_z_hex': [f'{z:x}' for z in right], 'formal_r_hex': [f'{r:x}' for r in rs],
            'scope': 'formal scalar relaxation only: no nonce logarithms or native hash preimages supplied',
            'one_digest_mutation_breaks_product_constraint': True}


def audit_reference_interface():
    # Read-only audit: no importing the subject serializer or reproduction.
    path = HERE/'r10_reference_interface.json'
    source = path.read_bytes()
    subject = json.loads(source)
    constant_bytes = b'\x01'+bytes(31)
    constant = int.from_bytes(constant_bytes, 'big')
    assert constant == 2**248 == int(subject['bug_scalar']) and constant+N >= 2**256

    def independently_hash(code, flag, recipient):
        if flag & 31 == 3:
            return constant_bytes
        indices = [1] if flag & 128 else [0, 1]
        raw = struct.pack('<I', 2)+compact(len(indices))
        for i in indices:
            selected = code if i == 1 else b''
            sequence = 0 if i == 0 and flag & 31 == 2 else 0xfffffffe-i
            raw += bytes([i+1])*32+struct.pack('<I', i)+compact(len(selected))+selected+struct.pack('<I', sequence)
        if flag & 31 == 2:
            raw += b'\x00'
        else:
            script = b'\x00\x14'+bytes([recipient])*20
            raw += b'\x01'+struct.pack('<Q', 10000)+compact(len(script))+script
        return hash256(raw+struct.pack('<II', 0, flag))

    assert len(subject['all_256_flags']) == 256
    for flag, row in enumerate(subject['all_256_flags']):
        observed = independently_hash(b'\x6e\xad\xac', flag, 17) == independently_hash(b'\xac', flag, 17)
        assert row == {'flag': flag, 'equal': observed}
    recipients = (17, 34, 51, 68)
    for recipient, row in zip(recipients, subject['output_variants']):
        assert row == {'single': constant_bytes.hex(), 'all': independently_hash(b'\xac', 1, recipient).hex()}
    literal = subject['literal_single_all_layout']
    raw = bytes.fromhex(literal['raw_script'])
    sigs = [bytes.fromhex(s) for s in literal['literal_signatures']]
    codes = [b''.join(raw[a:b] for a, b, _, data in instructions(raw) if data != sig) for sig in sigs]
    assert codes[0].hex() == literal['single_scriptcode'] and codes[1].hex() == literal['all_scriptcode']
    assert len(raw) == 123 and all(len(c) == 93 for c in codes) and codes[0] != codes[1]
    keys = [mul(pow(2, -1, N), add(point, mul(-constant))) for point in roots()[:3]]
    replay = run_layout(raw, [pubkey(q) for q in keys], [constant]*6)
    assert replay == {'checks': 6, 'combined_stack_peak': 6, 'executed_non_push_opcodes': 41}
    for recipient, row in zip(recipients, literal['cases']):
        zs = [int.from_bytes(independently_hash(code, flag, recipient), 'big') % N
              for code, flag in zip(codes, (3, 1))]
        assert row['scalars'] == [str(z) for z in zs]
        assert row['checks'] == [[verify(z, 2, 1, q)[0] for q in keys] for z in zs]
    assert len(subject['two_root_scaling_vectors']) == 16
    for row in subject['two_root_scaling_vectors']:
        ka, t = row['k'], row['t']
        ra, sa, rb, sb, target = [int(row[k]) for k in ('r_a', 's_a', 'r_b', 's_b', 'target_scalar')]
        assert ra == mul(ka)[0] % N and rb == mul(ka*t)[0] % N
        assert ra >= P-N and rb >= P-N and target*ra % N == constant*rb % N
        original = rb*sa*pow(ra*t, -1, N) % N
        assert sb == min(original, N-original)
        qs = [decode_pubkey(bytes.fromhex(q)) for q in row['keys']]
        assert qs[0] != qs[1]
        assert all(verify(constant, ra, sa, q)[0] and verify(target, rb, sb, q)[0] for q in qs)
        assert not all(verify((target+1) % N, rb, sb, q)[0] for q in qs)
    return {'subject': path.name, 'subject_sha256': hashlib.sha256(source).hexdigest(),
            'flag_cases': 256, 'equal_flags': [i for i in range(256) if i & 31 == 3],
            'actual_output_variants': 4, 'literal_context_cases': 4,
            'literal_raw_script_bytes': len(raw), 'literal_scriptcode_bytes': list(map(len, codes)),
            'literal_target_only_stack_replay': replay, 'two_root_scaling_vectors': 16,
            'critical_issues': [], 'scope': 'independent serializer, opcode-boundary deletion, raw stack replay and algebra readback; shared existing EC helper; no Core'}


def main():
    layouts = [layout(7)[1], layout(6, size_cap=True)[1], layout(8)[1]]
    assert layouts[0]['counted_opcodes'] == 199
    assert layouts[1]['counted_opcodes'] == 188
    assert layouts[2]['counted_opcodes'] > 201
    parity_counts = Counter()
    for m in range(2, 10):
        for parity in itertools.product((-1, 1), repeat=m):
            factor = math.prod(parity)
            width = 37
            for tau in parity:
                width = tau*width % N
            assert (width == 37) == (factor == 1)
            parity_counts['odd_excluded' if factor == -1 else 'even_width_closure'] += 1
    report = {'question': 'Do two distinct parallel ECDSA key cycles keep only one useful digest relation?',
              'answer': 'For two nonce roots, no with fixed nonce r: there is one local center equality per vertex. Free formal r leaves a multiplicative condition but still lacks native nonce construction.',
              'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
              'layouts': layouts, 'exhaustive_sign_patterns': dict(parity_counts),
              'two_root_constructed_cases': [algebra_case(m) for m in (3, 4, 7)],
              'free_r_relaxation': free_r_relaxation(), 'four_root_pair_states': four_root_states(),
              'native_same_context_control': native_smoke(7),
              'native_capped_same_context_control': native_smoke(6, size_cap=True),
              'independent_reference_interface_audit': audit_reference_interface(),
              'all_expectations_met': True}
    output = Path(__file__).with_suffix('.json')
    output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'all_expectations_met': True,
                      'layouts': [{k: item[k] for k in ('vertices', 'raw_redeemscript_bytes', 'counted_opcodes', 'entry_data_items', 'combined_stack_peak_by_inspection')} for item in layouts],
                      'sign_patterns': dict(parity_counts), 'output': str(output)}, indent=2))


if __name__ == '__main__':
    main()
