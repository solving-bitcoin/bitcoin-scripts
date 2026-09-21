#!/usr/bin/env python3
"""Deterministic, public host models of three restricted Tapscript proposals.

This is not a Bitcoin Script executor or a consensus-validity claim.
"""
import hashlib
import itertools
import json
import math
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from legacy_same_signature_counterexample import G, N, P as FIELD, add, mul


def sha(x):
    return hashlib.sha256(x).digest()


def tagged(tag, x):
    t = sha(tag.encode())
    return sha(t + t + x)


def b32(x):
    return x.to_bytes(32, 'big')


def compact(n):
    if n < 253:
        return bytes([n])
    if n <= 65535:
        return b'\xfd' + n.to_bytes(2, 'little')
    return b'\xfe' + n.to_bytes(4, 'little')


def vector(x):
    return compact(len(x)) + x


def lift(x):
    if x >= FIELD:
        return None
    y = pow((x*x*x + 7) % FIELD, (FIELD + 1)//4, FIELD)
    if y*y % FIELD != (x*x*x + 7) % FIELD:
        return None
    return (x, y if y % 2 == 0 else FIELD-y)


def normalize_scalar(d):
    p = mul(d)
    return d if p[1] % 2 == 0 else N-d


def challenge(r, pk, message):
    return int.from_bytes(tagged('BIP0340/challenge', r + pk + message), 'big') % N


def sign(d, k, message):
    d, k = normalize_scalar(d), normalize_scalar(k)
    pk, r = b32(mul(d)[0]), b32(mul(k)[0])
    s = (k + challenge(r, pk, message)*d) % N
    return r + b32(s)


def verify(pk, message, signature):
    if len(pk) != 32 or len(signature) != 64:
        return False
    p = lift(int.from_bytes(pk, 'big'))
    r = int.from_bytes(signature[:32], 'big')
    s = int.from_bytes(signature[32:], 'big')
    if p is None or r >= FIELD or s >= N:
        return False
    point = add(mul(s), mul(-challenge(signature[:32], pk, message) % N, p))
    return point is not None and point[1] % 2 == 0 and point[0] == r


def check_result(pk, message, signature):
    """Core's result/abort boundary, with ample budget and no policy flags.

    Only 64-byte DEFAULT signatures are needed by this model. Nonempty
    65-byte arguments are outside this helper's supported signature modes.
    """
    if not pk:
        return 'abort'
    if not signature:
        return 'false'
    if len(pk) != 32:
        return 'true'
    return 'true' if verify(pk, message, signature) else 'abort'


def output(amount, script):
    return amount.to_bytes(8, 'little') + vector(script)


def raw_tx(outpoint, sequence, outputs, witness=None):
    head = (2).to_bytes(4, 'little')
    vin = b'\x01' + outpoint + b'\x00' + sequence
    vout = compact(len(outputs)) + b''.join(outputs)
    tail = bytes(4)
    if witness is None:
        return head + vin + vout + tail
    return head + b'\x00\x01' + vin + vout + compact(len(witness)) + b''.join(map(vector, witness)) + tail


def default_tapsighash(outpoint, amount, spk, sequence, outputs, tapleaf):
    # BIP341 DEFAULT, one input, no annex; BIP342 ext_flag=1, no CODESEPARATOR.
    msg = (b'\x00' + (2).to_bytes(4, 'little') + bytes(4) + sha(outpoint)
           + sha(amount.to_bytes(8, 'little')) + sha(vector(spk)) + sha(sequence)
           + sha(b''.join(outputs)) + b'\x02' + bytes(4)
           + tapleaf + b'\x00' + b'\xff'*4)
    assert len(msg) == 211
    return tagged('TapSighash', b'\x00' + msg), msg


def main():
    d_values = list(range(1, 9))  # All scalars are public and retained.
    keys = [b32(mul(d)[0]) for d in d_values]
    # Witness entry: sig8 ... sig1. Eight CHECKSIGADDs, exact threshold 3.
    leaf = b'\x00' + b''.join(b'\x20' + pk + b'\xba' for pk in keys) + b'\x53\x9c'
    assert len(leaf) == 275
    tapleaf = tagged('TapLeaf', b'\xc0' + vector(leaf))
    internal = lift(int('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0', 16))
    tweak = int.from_bytes(tagged('TapTweak', b32(internal[0]) + tapleaf), 'big')
    assert tweak < N
    q = add(internal, mul(tweak))
    spk = b'\x51\x20' + b32(q[0])
    control = bytes([0xc0 | (q[1] & 1)]) + b32(internal[0])
    seq = b'\xff'*4
    funding = raw_tx(sha(b'public, synthetic funding ancestor') + bytes(4), seq, [output(10000, spk)])
    outpoint = sha(sha(funding)) + bytes(4)
    tx_cases = []
    for amount, script in [(9000, b'\x51'), (8000, b'\x52')]:
        outputs = [output(amount, script)]
        msg, preimage = default_tapsighash(outpoint, 10000, spk, seq, outputs, tapleaf)
        signatures = [sign(d, 100+i, msg) for i, d in enumerate(d_values)]
        assert all(verify(pk, msg, s) for pk, s in zip(keys, signatures))
        patterns = []
        for positions in itertools.combinations(range(8), 3):
            mask = sum(1 << i for i in positions)
            stack = [signatures[i] if i in positions else b'' for i in reversed(range(8))]
            results = [check_result(keys[i], msg, stack[7-i]) for i in range(8)]
            assert 'abort' not in results and results.count('true') == 3
            witness = stack + [leaf, control]
            full = raw_tx(outpoint, seq, outputs, witness)
            base = raw_tx(outpoint, seq, outputs)
            witness_size = len(compact(len(witness)) + b''.join(map(vector, witness)))
            assert witness_size == 513
            assert len(base)*3 + len(full) == 759
            patterns.append(mask)
        tx_cases.append({'output_amount': amount, 'output_script': script.hex(),
                         'sighash': msg.hex(), 'sigmsg': preimage.hex(),
                         'raw_stripped_transaction': base.hex(),
                         'all_56_threshold_patterns': patterns,
                         'signatures_by_key': [s.hex() for s in signatures],
                         'example_full_transaction': full.hex(),
                         'serialized_witness_bytes': witness_size,
                         'transaction_weight': len(base)*3 + len(full)})

    a, b = (bytes.fromhex(c['sighash']) for c in tx_cases)
    sa, sb = sign(1, 1, a), sign(1, 1, b)
    assert sa[:32] == sb[:32] and sa[32:] != sb[32:]
    assert verify(keys[0], a, sa) and verify(keys[0], b, sb)
    assert not verify(keys[0], b, sa) and not verify(keys[0], a, sb)
    ea, eb = challenge(sa[:32], keys[0], a), challenge(sb[:32], keys[0], b)
    assert (int.from_bytes(sa[32:], 'big') - int.from_bytes(sb[32:], 'big')) % N == (ea-eb) % N

    bad = bytes([sa[0] ^ 1]) + sa[1:]
    checks = [
        ('valid', keys[0], sa, 'true'),
        ('changed_message', keys[0], sb, 'abort'),
        ('changed_nonempty_signature', keys[0], bad, 'abort'),
        ('empty_signature', keys[0], b'', 'false'),
        ('invalid_x_and_empty_signature', b'\xff'*32, b'', 'false'),
        ('unknown_key_length_nonempty_signature', b'\x01'*20, b'\x01', 'true'),
        ('unknown_key_length_empty_signature', b'\x01'*20, b'', 'false'),
        ('empty_key_and_empty_signature', b'', b'', 'abort'),
    ]
    semantic_cases = []
    for label, pk, sig, want in checks:
        got = check_result(pk, a, sig)
        assert got == want
        semantic_cases.append({'case': label, 'result': got})

    # Generous literal-dictionary bound: grant all block weight to 65-byte
    # pushes, no transaction/witness/control or selector overhead.
    m_max = 4000000 // 65
    result = {
        'evidence': 'locally-reproduced', 'deployment': 'unclassified',
        'boundary': 'host-only BIP340 point equations, BIP341/342 preimage construction, and semantic model; no Bitcoin Core execution',
        'funding_ancestor_status': 'synthetic outpoint; no UTXO existence claim',
        'funding_raw': funding.hex(), 'leaf': leaf.hex(), 'tapleaf': tapleaf.hex(),
        'control_block': control.hex(), 'protected_scriptpubkey': spk.hex(),
        'metrics_by_inspection': {'locking_leaf_bytes': 275, 'entry_signature_data_items': 8,
                                  'entry_hint_items': 0, 'combined_stack_peak': 10,
                                  'executed_non_push_opcodes': 9, 'validation_budget_consumed': 150,
                                  'complete_witness_items': 10, 'complete_witness_bytes': 513,
                                  'complete_transaction_weight': 759},
        'transactions': tx_cases,
        'threshold_patterns_reproduced': 112,
        'signature_semantics': semantic_cases,
        'fixed_nonce_pair': {'nonce_x_equal': True, 'signature_scalars_equal': False,
                             'first_signature': sa.hex(), 'second_signature': sb.hex(),
                             'own_contexts_accept': True, 'cross_contexts_reject': True,
                             'scalar_difference_identity': True},
        'dictionary_bound': {'ideal_model': 'fixed key, nonce, and native context function; M scalar targets independent of fresh challenges',
                             'one_query_success_upper_bound': '2*M/2^256',
                             'q_query_success_upper_bound': '2*M*Q/2^256',
                             'max_literal_entries_in_4000000_byte_leaf_generous': m_max,
                             'log2_expected_queries_lower_bound': 255-math.log2(m_max),
                             'log2_success_upper_bound_at_2pow64_queries': 65+math.log2(m_max)-256,
                             'offchain_explicit_table_expected_work_lower_bound_log2': 128.5},
        'limits': ['The semantic model is not an independent consensus implementation.',
                   'No full covenant, arithmetic-proof binding, or universal lower bound is claimed.',
                   'The literal dictionary bound excludes other native predicates and cryptanalytic structure.'],
    }
    path = Path(__file__).with_suffix('.json')
    path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'result': str(path), 'threshold_patterns': 112,
                      'semantic_cases': len(semantic_cases), 'leaf_bytes': len(leaf),
                      'dictionary_literal_max': m_max}, indent=2))


if __name__ == '__main__':
    main()
