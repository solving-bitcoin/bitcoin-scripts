#!/usr/bin/env python3
"""Duplicate-signature CHECKMULTISIG nonce portfolio, host boundary fixtures.

No Core, repository Script executor/compiler, or field-library tests.
"""
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from legacy_same_signature_counterexample import (
    G, N, P, add, hash256, mul, signature_integer, tx, verify, vector,
)

FREE_SCRIPT = bytes.fromhex('6e8791696b6b007c76526c6c52ae')


def key(point):
    return bytes([2+point[1] % 2]) + point[0].to_bytes(32, 'big')


def signature(r, s):
    body = signature_integer(r) + signature_integer(s)
    return b'\x30' + vector(body) + b'\x01'


def decode_sig(sig):
    assert sig[0] == 0x30 and sig[1] == len(sig)-3 and sig[2] == 2 and sig[-1] == 1
    l_r = sig[3]
    assert sig[4+l_r] == 2
    l_s = sig[5+l_r]
    r = int.from_bytes(sig[4:4+l_r], 'big')
    s = int.from_bytes(sig[6+l_r:6+l_r+l_s], 'big')
    assert signature(r, s) == sig
    return r, s


def decode_key(pub):
    assert len(pub) == 33 and pub[0] in (2, 3)
    x = int.from_bytes(pub[1:], 'big')
    y = pow((x*x*x+7) % P, (P+1)//4, P)
    assert y*y % P == (x*x*x+7) % P
    if y % 2 != pub[0] % 2:
        y = P-y
    return x, y


def fixed_script(ds):
    m = len(ds)
    m_push = bytes([0x50+m]) if m <= 16 else vector(bytes([m]))
    return b'\x00\x7c\x76\x52' + b''.join(vector(key(mul(d))) for d in ds) + m_push + b'\xae'


def evaluate(script, inputs, z):
    # Exact stack routing for these raw fixtures; not a general consensus VM.
    stack, alt = list(inputs), []
    peak = len(stack)
    pc = counted = 0
    while pc < len(script):
        op = script[pc]
        pc += 1
        if op == 0:
            stack.append(b'')
        elif 1 <= op <= 75:
            stack.append(script[pc:pc+op])
            pc += op
        elif 0x51 <= op <= 0x60:
            stack.append(bytes([op-0x50]))
        else:
            counted += 1
            if op == 0x6e:
                stack.extend(stack[-2:])
            elif op == 0x87:
                stack.append(b'\x01' if stack.pop() == stack.pop() else b'')
            elif op == 0x91:
                stack.append(b'' if stack.pop() else b'\x01')
            elif op == 0x69:
                assert stack.pop(), 'VERIFY'
            elif op == 0x6b:
                alt.append(stack.pop())
            elif op == 0x6c:
                stack.append(alt.pop())
            elif op == 0x7c:
                stack[-1], stack[-2] = stack[-2], stack[-1]
            elif op == 0x76:
                stack.append(stack[-1])
            elif op == 0xae:
                m = int.from_bytes(stack.pop(), 'little')
                counted += m
                keys = [decode_key(stack.pop()) for _ in range(m)][::-1]
                required = int.from_bytes(stack.pop(), 'little')
                sigs = [decode_sig(stack.pop()) for _ in range(required)][::-1]
                assert stack.pop() == b'', 'NULLDUMMY'
                i = 0
                for pub in keys:
                    if i < len(sigs) and verify(z, *sigs[i], pub)[0]:
                        i += 1
                stack.append(b'\x01' if i == required else b'')
            else:
                raise AssertionError(hex(op))
        peak = max(peak, len(stack)+len(alt))
    assert not alt
    return stack == [b'\x01'], {'raw_script_bytes': len(script),
                              'counted_opcodes_including_multisig_key_charge': counted,
                              'combined_stack_peak': peak,
                              'entry_data_items': len(inputs), 'auxiliary_hint_items': 0}


def fixed_portfolio():
    ds = [1 << i for i in range(20)]
    script = fixed_script(ds)
    sums = {a+b for i, a in enumerate(ds) for b in ds[i+1:]}
    assert len(sums) == 190
    cases = []
    for k in (pow(2, -1, N), 1, 3, 5):
        r = mul(k)[0] % N
        assert r > P-N  # Exactly the two +/- roots for these nonce values.
        for i, j in ((0, 1), (0, 19), (5, 12)):
            z = -r*(ds[i]+ds[j])*pow(2, -1, N) % N
            raw_s = (z+r*ds[i])*pow(k, -1, N) % N
            s = min(raw_s, -raw_s % N)
            sig = signature(r, s)
            ok, metrics = evaluate(script, [sig], z)
            assert ok
            assert verify(z, r, s, mul(ds[i]))[0]
            assert verify(z, r, s, mul(ds[j]))[0]
            cases.append({'k': str(k), 'r': hex(r), 'z': hex(z), 'pair': [i, j],
                          'signature': sig.hex(), 'metrics': metrics})
    return {'scope': 'Constructed scalar digests; not actual transaction hashes',
            'public_signing_scalars': ds, 'script': script.hex(),
            'distinct_pair_sums': len(sums), 'cases': cases,
            'smaller_p2sh_size_m15': len(fixed_script(ds[:15]))}


def free_key_replay():
    variants = []
    for byte in (0x11, 0x22):
        output = b'\x00\x14' + bytes([byte])*20
        digest = hash256(tx(FREE_SCRIPT, output)+b'\x01\0\0\0')
        z = int.from_bytes(digest, 'big')
        for k in (pow(2, -1, N), 1, 3, 5):
            r = mul(k)[0] % N
            ds = [1, (-2*z*pow(r, -1, N)-1) % N]
            assert ds[1] not in (0, 1)
            pubkeys = [key(mul(d)) for d in ds]
            raw_s = (z+r)*pow(k, -1, N) % N
            sig = signature(r, min(raw_s, -raw_s % N))
            inputs = [sig]+pubkeys
            accepted, metrics = evaluate(FREE_SCRIPT, inputs, z)
            assert accepted
            assert not evaluate(FREE_SCRIPT, inputs, z+1)[0]
            script_sig = b''.join(vector(item) for item in inputs)+vector(FREE_SCRIPT)
            raw_tx = tx(script_sig, output)
            variants.append({'output_script': output.hex(), 'sighash': digest.hex(),
                             'nonce_scalar': str(k), 'r': hex(r),
                             'signature': sig.hex(), 'pubkeys': [p.hex() for p in pubkeys],
                             'metrics': dict(metrics, script_sig_bytes=len(script_sig),
                                             serialized_witness_bytes=0,
                                             transaction_weight=4*len(raw_tx)),
                             'transaction_hex': raw_tx.hex()})
    return {'scope': 'Actual legacy ALL preimage for one synthetic fixed outpoint; no Core',
            'script': FREE_SCRIPT.hex(), 'fresh_digest_trials_per_variant': 1,
            'positive_variants': len(variants),
            'changed_digest_negative_cases': len(variants), 'cases': variants}


def main():
    result = {'evidence': 'locally-reproduced', 'deployment': 'unclassified',
              'fixed_portfolio': fixed_portfolio(), 'free_key_replay': free_key_replay()}
    destination = Path(__file__).with_suffix('.json')
    destination.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'fixed_scalar_cases': len(result['fixed_portfolio']['cases']),
                      'fixed_metrics': result['fixed_portfolio']['cases'][0]['metrics'],
                      'free_actual_sighash_cases': result['free_key_replay']['positive_variants'],
                      'free_metrics': result['free_key_replay']['cases'][0]['metrics'],
                      'artifact': str(destination)}, indent=2))


if __name__ == '__main__':
    main()
