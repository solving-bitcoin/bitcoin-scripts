#!/usr/bin/env python3
"""Actual-signature hash references for R11's scalar-homogeneous witnesses.

Host-only native digest/equation and raw Script replay. No mined hash-to-DER
signature, Bitcoin Core execution, readable output reference or covenant.
"""
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from r11_endomorphism import C, GAP, N, P, add, mul, neg, solve, signature, layout
from r10_parallel_cycles import compact, hash256, instructions, number, pubkey, push
from r10_parallel_cycles import decode_pubkey, unpack_der
from legacy_same_signature_counterexample import verify


def hash_reference_layout():
    # Entry: h, alpha, beta, P, Q. Move h aside, hash the actual alpha,
    # compare, then execute the unchanged four native ECDSA checks.
    return b'\x74\x55\x88\x54\x7a\x6b\x53\x79\xa8\x6c\x88' + layout()


def reference_pin_layout():
    # Entry: K, alpha, beta, P, Q. Native CHECKSIG of SHA256(alpha)
    # under K, then the unchanged four native checks. A full rare root
    # witness was NOT mined. This script is only structurally measured.
    return b'\x74\x55\x88\x54\x7a\x6b\x53\x79\xa8\x6c\xad' + layout()


def tx(script_sig, outputs, locktime):
    result = struct.pack('<I', 2) + b'\x02'
    for index in range(2):
        script = script_sig if index == 1 else b''
        result += bytes([0x42+index])*32 + struct.pack('<I', 0)
        result += compact(len(script)) + script + struct.pack('<I', 0xfffffffe)
    result += compact(len(outputs))
    for amount, script in outputs:
        result += struct.pack('<Q', amount) + compact(len(script)) + script
    return result + struct.pack('<I', locktime)


def strict_der(blob):
    if not 9 <= len(blob) <= 73 or blob[0] != 0x30 or blob[1] != len(blob)-3:
        return False
    nr = blob[3]
    if 5+nr >= len(blob):
        return False
    ns = blob[5+nr]
    if nr+ns+7 != len(blob) or blob[2] != 2 or nr == 0 or blob[4] & 128:
        return False
    if nr > 1 and blob[4] == 0 and not blob[5] & 128:
        return False
    if blob[4+nr] != 2 or ns == 0 or blob[6+nr] & 128:
        return False
    if ns > 1 and blob[6+nr] == 0 and not blob[7+nr] & 128:
        return False
    return True


def run(raw, entry, z):
    stack, alt = list(entry), []
    peak, checks, executed = len(stack), 0, 0
    for _, _, op, data in instructions(raw):
        executed += op > 0x60
        if data is not None:
            stack.append(data)
        elif op == 0:
            stack.append(b'')
        elif 0x51 <= op <= 0x60:
            stack.append(bytes([op-0x50]))
        elif op == 0x74:
            stack.append(bytes([len(stack)]))
        elif op in (0x79, 0x7a):
            index_blob = stack.pop()
            assert len(index_blob) <= 4
            index = int.from_bytes(index_blob, 'little')
            assert 0 <= index < len(stack)
            stack.append(stack[-1-index] if op == 0x79 else stack.pop(-1-index))
        elif op == 0x6b:
            alt.append(stack.pop())
        elif op == 0x6c:
            stack.append(alt.pop())
        elif op == 0xa8:
            stack.append(hashlib.sha256(stack.pop()).digest())
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
        elif op == 0x75:
            stack.pop()
        elif op == 0x6d:
            stack.pop()
            stack.pop()
        elif op == 0xad:
            key, sig = decode_pubkey(stack.pop()), stack.pop()
            assert strict_der(sig)
            r, s = unpack_der(sig)
            assert 1 <= r < N and 1 <= s <= N//2
            assert sig[-1] in (1, 3)
            digest = C if sig[-1] == 3 else z
            assert verify(digest, r, s, key)[0]
            checks += 1
        else:
            raise AssertionError(hex(op))
        peak = max(peak, len(stack)+len(alt))
        assert peak <= 1000
    assert stack == [b'\x01'] and not alt and checks == 4
    return {'combined_stack_peak': peak, 'executed_non_push_opcodes': executed,
            'native_ecdsa_checks': checks}


def orbit_witness(solution, s):
    assert 1 <= s <= N//2
    r, rp, t = solution['r_alpha'], solution['r_beta'], solution['t']
    root = solution['R_alpha']
    sb = rp*s*pow(t*r, -1, N) % N
    sb = min(sb, N-sb)
    center = mul(-C*pow(r, -1, N))
    displacement = mul(s*pow(r, -1, N), root)
    keys = [add(center, displacement), add(center, neg(displacement))]
    if any(key is None for key in keys):
        return None  # At most two exceptional scalars over the full group.
    assert keys[0] != keys[1]
    alpha, beta = signature(r, s, 3), signature(rp, sb, 1)
    h = hashlib.sha256(alpha).digest()
    return [h, alpha, beta] + [pubkey(key) for key in keys]


def make_case(name, outputs):
    script = hash_reference_layout()
    attempts = []
    for locktime in range(128):
        preimage = tx(script, outputs, locktime)+struct.pack('<I', 1)
        digest = hash256(preimage)
        z = int.from_bytes(digest, 'big') % N
        solution = solve(z*pow(C, -1, N) % N) if z else None
        attempts.append({'locktime': locktime, 'digest': digest.hex(), 'found': solution is not None})
        if solution is not None:
            break
    assert solution is not None
    root, other = solution['R_alpha'], solution['R_beta']
    r, rp, t = solution['r_alpha'], solution['r_beta'], solution['t']
    assert mul(t, root) == other and rp == z*pow(C, -1, N)*r % N
    scalars = [1, 2, 127, 128, 255, 256, 2**31-1, 2**127+17,
               2**191+17, 2**247+17, N//2-1, N//2]
    rows = []
    for s in scalars:
        entry = orbit_witness(solution, s)
        assert entry is not None
        observation = run(script, entry, z)
        script_sig = b''.join(push(item) for item in entry)+push(script)
        spend = tx(script_sig, outputs, locktime)
        rows.append({'s': str(s), 'entry_hex': [item.hex() for item in entry],
                     'signature_lengths': [len(entry[1]), len(entry[2])],
                     'execution': observation, 'script_sig_bytes': len(script_sig),
                     'complete_synthetic_transaction_weight': 4*len(spend),
                     'transaction_hex': spend.hex()})
    assert len({row['entry_hex'][0] for row in rows}) == len(rows)
    # Hash-only exploration does no scalar multiplication and needs no new z.
    # This is a small actual SHA256 sample, not mining the ~2^46 rare event.
    hashes = [hashlib.sha256(signature(r, s, 3)).digest() for s in range(1, 4097)]
    assert len(set(hashes)) == len(hashes)
    negatives = []
    base = [bytes.fromhex(item) for item in rows[0]['entry_hex']]
    candidates = [('wrong_hash', [bytes(32)]+base[1:], z),
                  ('another_scalar_hash', [bytes.fromhex(rows[1]['entry_hex'][0])]+base[1:], z),
                  ('rehash_changed_alpha_retained_native_keys',
                   [bytes.fromhex(item) for item in rows[1]['entry_hex'][:2]]+base[2:], z),
                  ('extra_entry', [b'']+base, z), ('missing_entry', base[1:], z),
                  ('changed_native_digest', base, (z+1) % N)]
    for label, entry, test_z in candidates:
        try:
            run(script, entry, test_z)
        except (AssertionError, IndexError):
            negatives.append(label)
        else:
            raise AssertionError('accepted negative '+label)
    return {'name': name, 'outputs': [{'amount': a, 'script_hex': b.hex()} for a, b in outputs],
            'attempts': attempts, 'all_preimage': preimage.hex(), 'all_digest': digest.hex(),
            'solution': solution, 'witnesses': rows, 'negative_rejections': negatives,
            'hash_only_trials': len(hashes), 'hash_only_der_hits': sum(map(strict_der, hashes)),
            'funded': False, 'outputs_checked_by_script': False}


def main():
    outputs = [('intended', [(990000, b'\x00\x14'+b'\x11'*20)]),
               ('changed_recipient', [(990000, b'\x00\x14'+b'\x22'*20)]),
               ('changed_amount', [(989999, b'\x00\x14'+b'\x11'*20)]),
               ('changed_output_script', [(990000, b'\x51')])]
    cases = [make_case(name, out) for name, out in outputs]
    raw = hash_reference_layout()
    p = Fraction(780555, 2**65)
    result = {
        'evidence': 'locally-reproduced', 'deployment': 'unclassified',
        'question': 'Can H(actual full-length alpha) retain a large native witness domain?',
        'hash_reference_layout': {
            'raw_script_hex': raw.hex(), 'raw_script_bytes': len(raw),
            'static_non_push_opcodes': sum(op > 0x60 for _, _, op, _ in instructions(raw)),
            'entry_data_items': 5, 'hint_items': 0, 'script_sig_push_items_including_redeem': 6,
            'serialized_witness_bytes': 0,
            'includes': 'complete-leaf: raw boundary vector, exact-depth and live-hash equality, native checks, cleanup; no Script compilation or Core claim'},
        'unmined_hash_signature_pin_layout': {
            'raw_script_hex': reference_pin_layout().hex(),
            'raw_script_bytes': len(reference_pin_layout()),
            'static_non_push_opcodes': sum(op > 0x60 for _, _, op, _ in instructions(reference_pin_layout())),
            'entry_data_items': 5, 'hint_items': 0, 'structural_combined_stack_peak': 7,
            'native_checks_if_successful': 5, 'valid_full_witness_found': False},
        'scalar_domain': {'low_s_values': str(N//2), 'at_most_invalid_infinity_values': 2,
                          'distinct_keys_for_every_other_value': True,
                          'nonce_log_computed': False},
        'same_endomorphism_closure': {
            'gamma_required_r_equals_beta_r_for_ALL_on_same_antipodal_pair': True,
            'necessary_maximum_r_for_32_byte_gamma': str(2**191-1),
            'all_sample_beta_r_exceed_32_byte_gamma_bound':
                all(case['solution']['r_beta'] > 2**191-1 for case in cases),
            'scope': 'the same known endomorphism branch only; no all-four-root claim'},
        'conditional_hash_to_der_model': {
            'syntax_probability': str(p), 'expected_hash_queries_log2': math.log2(1/p),
            'fresh_sha256_random_oracle_assumption': True,
            'curve_lift_flag_and_complete_pin_success_not_included': True,
            'same_sampler_available_for_other_output_lists': True,
            'group_operations_per_hash_trial': 0,
            'full_work_below_2_64_established': False},
        'cases': cases,
        'totals': {'native_witnesses': sum(len(case['witnesses']) for case in cases),
                   'native_ecdsa_equations': sum(4*len(case['witnesses']) for case in cases),
                   'negative_rejections': sum(len(case['negative_rejections']) for case in cases),
                   'hash_only_trials': sum(case['hash_only_trials'] for case in cases)}}
    target = HERE/'r12_live_reference.json'
    target.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'output': str(target), 'totals': result['totals'],
                      'raw_bytes': len(raw), 'ops': result['hash_reference_layout']['static_non_push_opcodes'],
                      'locktime_attempts': [len(case['attempts']) for case in cases]}))


if __name__ == '__main__':
    main()
