#!/usr/bin/env python3
"""Public host equations for a same-input SINGLE/ALL reference interface.

Synthetic transactions and signatures only. No hash-derived signature witness,
Bitcoin Script execution, or complete covenant is asserted.
"""
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from legacy_same_signature_counterexample import G, N, P, add, mul, verify
from r5_root_flags import digest, recovery, ser, sighash
from r9_recovery_core import nonce_roots
from r9_four_roots import number, sig, variable_signature_layout

C = int.from_bytes(sighash.BUG, 'big')


def literal_layout():
    # Entry Q0 Q1 Q2. Explicit, separate literal signatures bind their flags.
    raw = b''
    for i in range(3):
        raw += number(2-i)+b'\x79\x82\x01\x21\x88\x75'
    for i, j in ((0, 1), (0, 2), (1, 2)):
        raw += number(2-i)+b'\x79'+number(3-j)+b'\x79\x87\x91\x69'
    signatures = [sig(1)[:-1]+bytes([flag]) for flag in (3, 1)]
    for sigma in signatures:
        for i in range(3):
            raw += bytes([len(sigma)])+sigma+number(3-i)+b'\x79\xad'
    raw += b'\x6d\x75\x51'
    opcount = sum(op > 0x60 for _, _, op in sighash.instructions(raw))
    assert (len(raw), opcount) == (123, 41)
    return raw, signatures


def run():
    assert C == 2**248 and C+N >= 2**256
    inputs = [(bytes([i+1])*32+struct.pack('<I', i), 0xfffffffe-i)
              for i in range(2)]
    outs = [[(10000, b'\x00\x14'+bytes([j])*20)] for j in (17, 34, 51, 68)]
    codes = [bytes.fromhex('6eadac'), b'\xac']
    flag_cases = []
    for flag in range(256):
        ds = [digest(inputs, outs[0], 1, code, flag) for code in codes]
        assert (ds[0] == ds[1]) == (flag & 31 == 3)
        flag_cases.append({'flag': flag, 'equal': ds[0] == ds[1]})
    context_cases = []
    for outputs in outs:
        bug = digest(inputs, outputs, 1, b'\xac', 3)
        all_digest = digest(inputs, outputs, 1, b'\xac', 1)
        assert bug == sighash.BUG and all_digest != bug
        context_cases.append({'single': bug.hex(), 'all': all_digest.hex()})
    assert len({row['all'] for row in context_cases}) == len(outs)

    raw, signatures = literal_layout()
    # FindAndDelete is signature-specific. Preserve exact ALL scriptCode.
    code_all = sighash.delete(raw, [signatures[1]])
    code_single = sighash.delete(raw, [signatures[0]])
    assert code_all != code_single
    points = nonce_roots(2)
    assert len(points) == 4
    keys = [recovery(2, 1, C, point) for point in points[:3]]
    assert len(set(keys)) == 3
    assert all(verify(C, 2, 1, key)[0] for key in keys)
    literal_cases = []
    for outputs in outs:
        zs = [int.from_bytes(digest(inputs, outputs, 1, code, flag), 'big') % N
              for code, flag in ((code_single, 3), (code_all, 1))]
        checks = [[verify(z, 2, 1, key)[0] for key in keys] for z in zs]
        assert checks[0] == [True]*3 and checks[1] == [False]*3
        literal_cases.append({'scalars': [str(z) for z in zs], 'checks': checks})

    # A constructive two-root cross-signature family, including all signs.
    # With Rb=t*Ra, its target scalar is zB=(rB/rA)*C.
    scaling = []
    for k in (1, 2, 7, 19):
        ra = mul(k)
        r_a, s_a = ra[0] % N, 17
        assert r_a >= P-N and len(nonce_roots(r_a)) == 2
        qa = [recovery(r_a, s_a, C, point) for point in (ra, (ra[0], -ra[1] % P))]
        assert qa[0] != qa[1] and all(verify(C, r_a, s_a, q)[0] for q in qa)
        for t in (1, 2, 5, 13):
            rb = mul(t, ra)
            r_b = rb[0] % N
            assert r_b >= P-N and len(nonce_roots(r_b)) == 2
            s_b = r_b*pow(r_a*t, -1, N)*s_a % N
            s_b = min(s_b, N-s_b)
            target = r_b*pow(r_a, -1, N)*C % N
            assert all(verify(target, r_b, s_b, q)[0] for q in qa)
            assert not all(verify((target+1) % N, r_b, s_b, q)[0] for q in qa)
            assert add(*qa) == mul(-2*C*pow(r_a, -1, N))
            assert add(*qa) == mul(-2*target*pow(r_b, -1, N))
            scaling.append({'k': k, 't': t, 'r_a': str(r_a), 's_a': s_a,
                            'r_b': str(r_b), 's_b': str(s_b),
                            'target_scalar': str(target), 'keys': [ser(q).hex() for q in qa],
                            'both_signatures_verify_under_both_keys': True})

    return {'question': 'Can constant-message and ALL checks coexist on one locked input and give a reference interface?',
            'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
            'scope': __doc__, 'bitcoin_core_semantics_revision': sighash.CORE,
            'all_assertions_passed': True,
            'bug_scalar': str(C), 'same_input_index': 1, 'input_count': 2,
            'all_256_flags': flag_cases, 'output_variants': context_cases,
            'variable_signature_equality_layout': variable_signature_layout(True),
            'literal_single_all_layout': {'raw_script': raw.hex(), 'raw_bytes': len(raw),
                'counted_opcodes': 41, 'entry_data_items': 3, 'hint_items': 0,
                'combined_stack_peak_by_inspection': 6, 'literal_signatures': [s.hex() for s in signatures],
                'all_scriptcode': code_all.hex(), 'single_scriptcode': code_single.hex(),
                'script_sig_bytes': None, 'serialized_witness_bytes': None,
                'resource_boundary': 'Raw complete predicate, no input pushes or transaction; not policy compiled.',
                'cases': literal_cases},
            'two_root_scaling_vectors': scaling,
            'obligations': ['The SINGLE-bug constant does not itself bind outputs.',
                'Same-signature three-key equality does not extend to unrelated signatures.',
                'The scaled two-key family still needs its target to equal the actual ALL scalar.',
                'No byte-extraction, flag-rewrite, hash preimage, or full reference evaluator was supplied.']}


if __name__ == '__main__':
    report = run()
    output = Path(__file__).with_suffix('.json')
    output.write_text(json.dumps(report, indent=2)+'\n')
    print(output)
