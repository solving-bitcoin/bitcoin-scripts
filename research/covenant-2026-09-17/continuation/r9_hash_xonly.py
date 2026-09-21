#!/usr/bin/env python3
"""Hash-as-xonly candidate: real curve equations and a clearly separate toy.

No full-size hash-derived-key signature is generated. No Core or Script VM.
"""
import hashlib
import json
import math
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from legacy_same_signature_counterexample import G, N, P as FIELD, add, mul
import r5_tapscript_reference as tap

LEAF = bytes.fromhex("7c820140887ca8ac")
SEED = b"bitcoin-lab/r9-hash-xonly/v1/"


def contexts():
    leaf_hash = tap.tagged('TapLeaf', b'\xc0' + tap.vector(LEAF))
    internal = tap.lift(int('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0', 16))
    tweak = int.from_bytes(tap.tagged('TapTweak', tap.b32(internal[0]) + leaf_hash), 'big')
    assert tweak < N
    q = add(internal, mul(tweak))
    spk = b'\x51\x20' + tap.b32(q[0])
    control = bytes([0xc0 | (q[1] & 1)]) + tap.b32(internal[0])
    sequence = b'\xff' * 4
    funding = tap.raw_tx(tap.sha(SEED + b'synthetic ancestor') + bytes(4), sequence,
                         [tap.output(10000, spk)])
    outpoint = tap.sha(tap.sha(funding)) + bytes(4)
    result = []
    for amount, script in [(9000, b'\x51'), (8000, b'\x52')]:
        outputs = [tap.output(amount, script)]
        message, preimage = tap.default_tapsighash(outpoint, 10000, spk, sequence, outputs, leaf_hash)
        result.append({'amount': amount, 'output_script': script.hex(),
                       'message': message.hex(), 'preimage': preimage.hex()})
    return {'funding_hex': funding.hex(), 'outpoint_wire_hex': outpoint.hex(),
            'spk_hex': spk.hex(), 'control_hex': control.hex(), 'messages': result,
            'funding_ancestor_is_synthetic': True}


def real_hash_roots_and_affine(context):
    lifted, proofs = [], []
    for index in range(512):
        proof = SEED + index.to_bytes(4, 'big')
        root = tap.sha(proof)
        point = tap.lift(int.from_bytes(root, 'big'))
        if point is not None:
            lifted.append((proof, root, point))
        proofs.append({'index': index, 'liftable': point is not None})
    cases = []
    for proof, root, point in lifted[:8]:
        for a, b in [(1, 0), (0, 1), (7, 3), (19, 11), (101, 257), (5, N-1)]:
            raw_nonce = add(mul(a), mul(b, point))
            assert raw_nonce is not None
            sign = 1 if raw_nonce[1] % 2 == 0 else -1
            nonce = mul(sign, raw_nonce)
            target_e = -sign * b % N
            s = sign * a % N
            assert mul(s) == add(nonce, mul(target_e, point))
            message = bytes.fromhex(context['messages'][0]['message'])
            signature = tap.b32(nonce[0]) + tap.b32(s)
            actual_e = tap.challenge(signature[:32], root, message)
            assert actual_e != target_e
            assert not tap.verify(root, message, signature)
            # Raw leaf's stack routing, with the native check represented by
            # the host verifier; no Script VM execution is claimed.
            stack = [signature, proof]
            peak = len(stack)
            stack[-1], stack[-2] = stack[-2], stack[-1]
            stack.append(bytes([len(stack[-1])]))
            stack.append(b'\x40')
            peak = max(peak, len(stack))
            assert stack.pop() == stack.pop()
            stack[-1], stack[-2] = stack[-2], stack[-1]
            stack[-1] = tap.sha(stack[-1])
            key, sig = stack.pop(), stack.pop()
            assert not tap.verify(key, message, sig) and not stack
            assert peak == 4
            cases.append({'proof_hex': proof.hex(), 'root_hex': root.hex(),
                          'a': str(a), 'b': str(b), 'nonce_parity_sign': sign,
                          'target_e': hex(target_e), 'actual_e': hex(actual_e),
                          'synthetic_target_equation_valid': True,
                          'actual_schnorr_signature_valid': False})
    return {'sampled_proofs': len(proofs), 'liftable_roots': len(lifted),
            'nonliftable_roots': len(proofs)-len(lifted),
            'known_discrete_logs_for_hash_roots': False,
            'affine_nonce_cases': cases,
            'root_sample_transcript_sha256': tap.sha(json.dumps(proofs, sort_keys=True).encode()).hex()}


def conditional_known_nonce_replay(context):
    rows = []
    for d0 in [1, 7, 19, 41]:
        d = tap.normalize_scalar(d0)
        key = tap.b32(mul(d)[0])
        signatures = []
        for index, item in enumerate(context['messages']):
            message = bytes.fromhex(item['message'])
            k0 = 1001 + index + d0
            k = tap.normalize_scalar(k0)
            signature = tap.sign(d0, k0, message)
            assert tap.verify(key, message, signature)
            e = tap.challenge(signature[:32], key, message)
            assert e != 0
            extracted = (int.from_bytes(signature[32:], 'big') - k) * pow(e, -1, N) % N
            assert extracted == d
            other_message = bytes.fromhex(context['messages'][1-index]['message'])
            assert not tap.verify(key, other_message, signature)
            signatures.append(signature.hex())
        rows.append({'public_scalar': d0, 'normalized_key_hex': key.hex(),
                     'two_output_signatures': signatures,
                     'both_inner_bip340_host_verifiers_accept': True,
                     'known_nonce_extracts_signing_scalar': True,
                     'known_hash_preimage_for_this_key': False,
                     'complete_hash_key_leaf_witness': False})
    return rows


# Separate small-curve model; the adapter is not Bitcoin SHA256-to-xonly.
TP, TN, TG = 211, 199, (3, 33)


def tadd(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y + v) % TP == 0:
        return None
    slope = ((3*x*x) * pow(2*y, -1, TP) if a == b
             else (v-y)*pow(u-x, -1, TP)) % TP
    nx = (slope*slope-x-u) % TP
    return nx, (slope*(x-nx)-y) % TP


def tmul(k, point=TG):
    k %= TN
    out = None
    while k:
        if k & 1:
            out = tadd(out, point)
        point = tadd(point, point)
        k >>= 1
    return out


def tlift(x):
    y = pow((x*x*x+7) % TP, (TP+1)//4, TP)
    return None if y*y % TP != (x*x*x+7) % TP else (x, y if y % 2 == 0 else TP-y)


def tbsgs(point):
    width = math.isqrt(TN) + 1
    table, current = {}, None
    for j in range(width):
        table[current] = j
        current = tadd(current, TG)
    stride, current = tmul(-width), point
    for i in range(width):
        if current in table:
            d = (i*width+table[current]) % TN
            assert tmul(d) == point
            return d, {'baby_table_entries': len(table), 'giant_table_lookups': i+1}
        current = tadd(current, stride)
    raise AssertionError('small-curve logarithm not found')


def te(r, key, message):
    return int.from_bytes(tap.sha(SEED + b'toy challenge/' + bytes([r, key]) + message), 'big') % TN


def toy_complete_solver():
    for index in range(512):
        proof = SEED + b'toy-proof/' + index.to_bytes(4, 'big')
        # Entire digest reduced to the tiny coordinate field: a model adapter.
        x = int.from_bytes(tap.sha(proof), 'big') % TP
        point = tlift(x)
        if point is not None:
            break
    proof_attempts = index + 1
    d, work = tbsgs(point)
    outputs = []
    for index, descriptor in enumerate([b'9000:OP_TRUE', b'8000:OP_2']):
        message = tap.sha(SEED + b'toy same-outpoint/' + descriptor)
        k = 11 + index
        nonce = tmul(k)
        if nonce[1] % 2:
            nonce, k = tmul(-k), -k % TN
        e = te(nonce[0], point[0], message)
        s = (k + e*d) % TN
        reconstructed = tadd(tmul(s), tmul(-e, point))
        assert reconstructed == nonce and reconstructed[1] % 2 == 0
        assert tlift(int.from_bytes(tap.sha(proof), 'big') % TP) == point
        outputs.append({'output_descriptor': descriptor.decode(), 'message': message.hex(),
                        'model_signature': [nonce[0], s], 'accepted': True})
    return {'field': TP, 'order': TN, 'generator': TG,
            'hash_adapter': 'SHA256(proof) interpreted as integer modulo 211',
            'bitcoin_signature_encoding': False, 'proof_hex': proof.hex(),
            'proof_candidates_tested': proof_attempts,
            'hash_derived_even_key': point, 'retained_signing_scalar': d,
            'bsgs_counts': work, 'same_proof_for_both_outputs': True,
            'output_cases': outputs}


def main():
    context = contexts()
    result = {'question': 'Can SHA256(proof) directly used as a Schnorr key supply a cheap mandatory reference?',
              'evidence': 'locally-reproduced', 'deployment': 'unclassified',
              'seed_hex': SEED.hex(), 'raw_leaf_hex': LEAF.hex(),
              'inspected_raw_leaf_metrics': {'bytes': len(LEAF), 'non_push_opcodes': 6,
                 'entry_data_items': 2, 'hint_items': 0, 'combined_stack_peak': 4,
                 'complete_witness_items': 4, 'witness_bytes_for_proof_length_L_at_most_252': '110+L',
                 'nonempty_signature_budget_consumed': 50,
                 'successful_full_size_witness_exists_in_fixture': False},
              'actual_bip341_contexts': context,
              'real_hash_key_checks': real_hash_roots_and_affine(context),
              'conditional_retained_key_checks': conditional_known_nonce_replay(context),
              'separate_tiny_curve_complete_solver': toy_complete_solver(),
              'models': {'known_key_hash_list_match_bound_at_total_queries_2pow64': 2**-130,
                         'prequery_affine_nonce_cancellation_bound_at_queries_2pow64': 2**-191,
                         'scope': 'Independent fresh ideal hashes; not a universal algorithmic lower bound'},
              'source_pin': 'bitcoin/bips 24e96e870fffaa257b465ce1f0370c14aac588e8'}
    Path(__file__).with_suffix('.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'sampled_roots': 512,
                      'liftable_roots': result['real_hash_key_checks']['liftable_roots'],
                      'affine_nonce_cases': len(result['real_hash_key_checks']['affine_nonce_cases']),
                      'conditional_inner_signatures': 2*len(result['conditional_retained_key_checks']),
                      'toy_solver': result['separate_tiny_curve_complete_solver']}, indent=2))


if __name__ == '__main__':
    main()
