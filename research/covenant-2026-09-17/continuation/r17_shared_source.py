#!/usr/bin/env python3
"""Actual shared source/native hash inputs, without a mined DER witness.

Only hash computations and the prefix stack routing are replayed. The six
native signature checks are not claimed to pass.
"""
import json
import struct
from pathlib import Path

from r16_native_translation import h256, sha, layout, transaction, p2sh
from r11_endomorphism import N, signature
from r10_parallel_cycles import instructions

HERE = Path(__file__).resolve().parent


def positive_der32(raw):
    if len(raw) != 32 or raw[:3] != bytes.fromhex('301d02'):
        return False
    nr = raw[3]
    pos = 4 + nr
    if not 1 <= nr <= 24 or pos + 2 >= len(raw) or raw[pos] != 2:
        return False
    ns = raw[pos + 1]
    if nr + ns != 25:
        return False
    r = int.from_bytes(raw[4:pos], 'big')
    s = int.from_bytes(raw[pos + 2:-1], 'big')
    return 0 < r < N and 0 < s < N and signature(r, s, raw[-1]) == raw


def prefix_replay(prefix, source):
    # Symbolic unchanged operands; no claimed public keys or signatures.
    original = [b'beta', b'K1', b'K2', b'K3', source]
    stack = list(original)
    peak, ops = len(stack), 0
    for _, _, op, pushed in instructions(prefix):
        if pushed is not None:
            stack.append(pushed)
        elif op in (0xa8, 0xaa):
            stack.append((sha if op == 0xa8 else h256)(stack.pop()))
            ops += 1
        elif op == 0x54:
            stack.append(b'\x04')
        elif op == 0x7a:
            depth = int.from_bytes(stack.pop(), 'little')
            stack.append(stack.pop(-1-depth))
            ops += 1
        else:
            raise AssertionError(hex(op))
        peak = max(peak, len(stack))
    assert stack[1:] == original[:4]
    assert len(stack) == 5 and peak == 6 and ops == 5
    return stack[0]


def main():
    modes = []
    outputs = [(999000, b'\x11'*20, 0), (999000, b'\x22'*20, 0),
               (998999, b'\x11'*20, 0), (999000, b'\x11'*20, 1)]
    for name, opcode in [('SHA256_of_inner_digest', 0xa8),
                         ('HASH256_of_full_preimage', 0xaa)]:
        prefix = bytes([opcode]) + bytes.fromhex('547a')*4
        raw = prefix + layout()
        assert len(raw) == 88
        # No complete strict-DER signature push can occur in this scriptCode.
        assert b'\x30' not in raw
        assert sum(op > 0x60 for _, _, op, _ in instructions(raw)) == 55
        funding = transaction([b'\x35'*32+bytes(4)],
                              [(10000, b'\x51'), (1000000, p2sh(raw))])
        fid = h256(funding)
        prev = [fid+struct.pack('<I', i) for i in (0, 1)]
        vectors = []
        for amount, recipient, locktime in outputs:
            native_outputs = [(amount, b'\x00\x14'+recipient)]
            # Current input index 1: SINGLE would return the constant digest.
            pre = transaction(prev, native_outputs, [b'', raw], locktime)
            pre += struct.pack('<I', 1)
            actual = h256(pre)
            source = sha(pre) if opcode == 0xa8 else pre
            assert len(source) <= 520
            alpha = prefix_replay(prefix, source)
            assert alpha == actual
            assert not positive_der32(alpha)
            assert prefix_replay(prefix, source+b'\x00') != actual
            vectors.append({'amount': amount, 'recipient_20_bytes': recipient.hex(),
                            'locktime': locktime, 'actual_ALL_preimage': pre.hex(),
                            'preimage_bytes': len(pre), 'source_item': source.hex(),
                            'source_item_bytes': len(source), 'alpha_equals_ALL_digest': actual.hex(),
                            'positive_DER32': False, 'mutated_source_changes_alpha': True,
                            'native_signature_checks_executed': False})
        assert len({row['alpha_equals_ALL_digest'] for row in vectors}) == 4
        modes.append({'mode': name, 'prefix': prefix.hex(), 'candidate_script': raw.hex(),
                      'funding_transaction': funding.hex(), 'synthetic_funding_txid': fid[::-1].hex(),
                      'same_fixed_funding_for_all_four_variants': True, 'vectors': vectors})
    report = {'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
              'scope': 'Actual legacy ALL byte serialization and native hash-prefix replay only. No accepted ECDSA witness or Core execution.',
              'candidate_script_bytes': 88, 'candidate_static_non_push_opcodes': 55,
              'data_items_at_entry': 5, 'incremental_hint_items': 0,
              'prefix_measured_stack_peak': 6,
              'complete_candidate_structural_stack_peak': 8,
              'complete_scriptSig_and_transaction_weight': None,
              'witness_serialization': 'No witness vector in legacy; complete scriptSig cannot be supplied without beta and the three keys.',
              'modes': modes, 'complete_covenant': False}
    (HERE/'r17_shared_source.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'modes': len(modes), 'shared_answer_vectors': 8,
                      'valid_native_ECDSA_witnesses': 0}, indent=2))


if __name__ == '__main__':
    main()
