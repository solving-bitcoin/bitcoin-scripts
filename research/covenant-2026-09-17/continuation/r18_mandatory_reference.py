#!/usr/bin/env python3
"""Exact native preimage interfaces across different inputs; host-only fixture."""
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'seven'))
from search2_native_context import (BUG, clean, compact, delete, h256,
    instructions, legacy_preimage, output_bytes, push, vector)

CORE = '49faec4f87f5cd19c88db01a82e5c68b087c8227'
BIPS = '24e96e870fffaa257b465ce1f0370c14aac588e8'


def bip143(inputs, outputs, index, code, amount, flag):
    base = flag & 31
    prevouts = bytes(32) if flag & 128 else h256(b''.join(u for u, _ in inputs))
    sequences = bytes(32) if flag & 128 or base in (2, 3) else h256(
        b''.join(struct.pack('<I', q) for _, q in inputs))
    if base not in (2, 3):
        out = h256(b''.join(map(output_bytes, outputs)))
    elif base == 3 and index < len(outputs):
        out = h256(output_bytes(outputs[index]))
    else:
        out = bytes(32)
    own, seq = inputs[index]
    pre = struct.pack('<I', 2) + prevouts + sequences + own + vector(code)
    pre += struct.pack('<QI', amount, seq) + out + struct.pack('<II', 7, flag)
    assert pre[68:104] == own
    return pre


def run():
    signatures = [b'', bytes.fromhex('300602010102010103'), b'\xac',
                  b'\xad\xae\xaf\xab', bytes(range(73))]
    retained = []
    codes = []
    for opcode in (0xac, 0xad, 0xae, 0xaf):
        for sig in signatures:
            # A future separator and pushed opcode bytes are intentional.
            # This is an active suffix model, not a successful Script execution.
            suffix = push(sig) * 2 + bytes([opcode]) + b'\xab' + push(push(sig)) + push(sig)
            processed = clean(delete(suffix, [sig]))
            ops = [op for _, _, op in instructions(processed)]
            assert opcode in ops and len(processed) > 0
            assert push(push(sig)) in processed
            retained.append({'executing_opcode': hex(opcode), 'signature': sig.hex(),
                             'active_suffix': suffix.hex(), 'processed_code': processed.hex(),
                             'executing_opcode_survives': True})
        codes += [bytes([opcode]), bytes([opcode]) + b'\x51']

    inputs = [(bytes([i + 1]) * 32 + struct.pack('<I', i), 0xfffffffd - i)
              for i in range(3)]
    outputs = [(11000 + i, b'\x00\x14' + bytes([0x11 + i]) * 20) for i in range(2)]
    reports = []
    for kind in ('legacy', 'bip143'):
        groups = {}
        ordinary, constant = 0, 0
        for index in range(3):
            for flag in range(256):
                for code in codes:
                    pre = legacy_preimage(inputs, outputs, index, code, flag, locktime=7) if kind == 'legacy' else bip143(inputs, outputs, index, code, 50000, flag)
                    if pre is None:
                        constant += 1
                    else:
                        ordinary += 1
                        groups.setdefault(pre, set()).add(index)
        shared = sum(len(indices) > 1 for indices in groups.values())
        assert shared == 0
        reports.append({'family': kind, 'input_positions': 3, 'full_flag_bytes': 256,
                        'nonempty_code_variants': len(codes), 'ordinary_contexts': ordinary,
                        'constant_SINGLE_contexts': constant,
                        'distinct_ordinary_preimages': len(groups),
                        'ordinary_preimages_shared_across_input_positions': shared})

    empty = [legacy_preimage(inputs, outputs, i, b'', 1, locktime=7) for i in range(3)]
    assert len(set(empty)) == 1
    bug_pre = [legacy_preimage(inputs, outputs[:1], i, b'\xac', 3, locktime=7) for i in (1, 2)]
    assert bug_pre == [None, None]

    acp = []
    for kind in ('legacy', 'bip143'):
        for flag in (0x81, 0x82, 0x83):
            fn = lambda ins, outs, idx: (legacy_preimage(ins, outs, idx, b'\xac', flag, locktime=7)
                   if kind == 'legacy' else bip143(ins, outs, idx, b'\xac', 50000, flag))
            original = fn(inputs, outputs, 1)
            replaced = list(inputs)
            replaced[0] = (b'\x55' * 32 + struct.pack('<I', 19), 1234)
            removed = inputs[:2]
            assert original == fn(replaced, outputs, 1) == fn(removed, outputs, 1)
            acp.append({'family': kind, 'flag': hex(flag), 'original_preimage': original.hex(),
                        'changed_other_outpoint_preserves_preimage': True,
                        'removed_trailing_input_preserves_preimage': True})

    # Move the current input and its paired output together. BIP143 omits the
    # index under SINGLE|ANYONECANPAY; legacy retains it through null outputs.
    perm_inputs = [inputs[1], inputs[0], inputs[2]]
    perm_outputs = [outputs[1], outputs[0]]
    p0 = bip143(inputs, outputs, 1, b'\xac', 50000, 0x83)
    p1 = bip143(perm_inputs, perm_outputs, 0, b'\xac', 50000, 0x83)
    l0 = legacy_preimage(inputs, outputs, 1, b'\xac', 0x83, locktime=7)
    l1 = legacy_preimage(perm_inputs, perm_outputs, 0, b'\xac', 0x83, locktime=7)
    assert p0 == p1 and l0 != l1

    return {
        'question': 'Can exact native sighash reuse or ANYONECANPAY pairing force a separate verifier input?',
        'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
        'scope': 'Host serialization and opcode-boundary deletion; no signatures, Script execution, funded transaction or Core acceptance claimed.',
        'primary_sources': [f'https://github.com/bitcoin/bitcoin/blob/{CORE}/src/script/interpreter.cpp',
                            f'https://github.com/bitcoin/bips/blob/{BIPS}/bip-0143.mediawiki'],
        'current_check_opcode_survives_deletion': retained,
        'cross_input_preimage_families': reports,
        'abstract_empty_code_control': {'preimages_equal': True, 'preimage': empty[0].hex(),
                                       'realisable_as_current_legacy_signature_check': False},
        'out_of_range_SINGLE_control': {'input_positions': [1, 2], 'shared_digest_bytes': BUG.hex(),
                                       'output_binding': False},
        'ANYONECANPAY_other_input_controls': acp,
        'SINGLE_ANYONECANPAY_pair_permutation': {
            'bip143_same_preimage': True, 'bip143_preimage': p0.hex(),
            'legacy_same_preimage': False, 'legacy_before': l0.hex(), 'legacy_after': l1.hex()},
        'hint_items': 0, 'witness_bytes': 0,
        'script_bytes': None, 'combined_stack_peak': None, 'executed_opcodes': None,
        'resource_note': 'Serializer-only boundary; Script metrics inapplicable, not zero. No witness hints or transaction witnesses are supplied.',
        'construction_found': False,
        'limitations': ['Does not exclude hash collisions or scalar / curve relations between distinct preimages.',
                        'Does not compare different signature-hash families.',
                        'Does not prove a general mandatory-reference impossibility.'],
        'all_assertions_passed': True,
    }


if __name__ == '__main__':
    print(json.dumps(run(), indent=2))
