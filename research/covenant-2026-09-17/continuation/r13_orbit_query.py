#!/usr/bin/env python3
"""Exact three-point orbit identities and a native-check countermodel.

Public deterministic host mathematics; no Core or complete covenant claim.
The raw-vector interpreter intentionally supports only this fixture's opcodes.
"""
import json
from pathlib import Path
import struct

from r11_endomorphism import (
    BETA, LAMBDA, C, GAP, G, N, P, add, mul, lift, neg, solve,
    signature, serialize, hash256, instructions, number, pubkey, push,
)
from r10_parallel_cycles import decode_pubkey, unpack_der, verify

HERE = Path(__file__).resolve().parent


def orbit_identity():
    assert pow(BETA, 3, P) == 1 and BETA != 1
    assert (1+BETA+BETA*BETA) % P == 0
    assert pow(LAMBDA, 3, N) == 1 and LAMBDA != 1
    # No affine point has x=0; hence none is fixed by the nonidentity map.
    assert pow(7, (P-1)//2, P) == P-1
    # Equal r in different orbit positions would require x'=x +/- n.
    # p<2n makes this list exhaustive; x'=x would require x=0.
    equal_r_candidates = []
    for exponent in (1, 2):
        beta = pow(BETA, exponent, P)
        for sign in (-1, 1):
            x = sign*N*pow(beta-1, -1, P) % P
            xp = x+sign*N
            assert not 1 <= xp < P
            equal_r_candidates.append({
                'exponent': exponent, 'sign': sign, 'x': str(x),
                'required_x_prime': str(xp), 'both_in_field_interval': False,
            })
    rows = []
    initial = [mul(k) for k in (1, 2, 7, pow(2, -1, N))]
    initial += [lift(2), lift(N+2), lift(4), lift(N+4)]
    for root in initial:
        assert root is not None
        points = [(pow(BETA, j, P)*root[0] % P, root[1]) for j in range(3)]
        assert all(mul(pow(LAMBDA, j, N), root) == points[j] for j in range(3))
        xs, rs = [q[0] for q in points], [q[0] % N for q in points]
        h = sum(xs)//P
        assert h in (1, 2) and sum(xs) == h*P
        assert len(set(rs)) == 3 and all(rs)
        assert sum(rs) % N == h*GAP % N
        u, v = rs[1]*pow(rs[0], -1, N) % N, rs[2]*pow(rs[1], -1, N) % N
        denominator = (1+u+u*v) % N
        assert denominator and h*GAP*pow(denominator, -1, N) % N == rs[0]
        rows.append({'x': list(map(str, xs)), 'r': list(map(str, rs)),
                     'h': h, 'x_wraps': [x//N for x in xs],
                     'u': str(u), 'v': str(v), 'recovered_r0': str(rs[0])})
    return {'equal_r_candidates': equal_r_candidates, 'vectors': rows}


def layout():
    # Entry h, sigma0, sigma1, sigma2, P, Q; h must be 1 or 2.
    raw = bytes.fromhex('745688557a5153a569')
    for depth in (1, 0):
        raw += number(depth)+b'\x79\x82'+number(33)+b'\x88\x75'
    raw += bytes.fromhex('51795179879169')
    for signature_depth in (4, 3, 2):
        for key_depth in (2, 1):
            raw += number(signature_depth)+b'\x79'+number(key_depth)+b'\x79\xad'
    raw += bytes.fromhex('6d6d7551')
    assert len(raw) == 64
    assert sum(op > 0x60 for _, _, op, _ in instructions(raw)) == 39
    return raw


def run(raw, entry, z_all):
    stack, checks, ops, peak = list(entry), [], 0, len(entry)

    def integer(data):
        # Every numeric operand in these vectors is canonical, nonnegative.
        assert len(data) <= 4 and (not data or not data[-1] & 128)
        return int.from_bytes(data, 'little')

    def encode(value):
        return b'' if value == 0 else bytes([value])

    for _, _, op, data in instructions(raw):
        ops += int(op > 0x60)
        if data is not None:
            stack.append(data)
        elif op == 0:
            stack.append(b'')
        elif 0x51 <= op <= 0x60:
            stack.append(encode(op-0x50))
        elif op == 0x74:
            stack.append(encode(len(stack)))
        elif op in (0x79, 0x7a):
            depth = integer(stack.pop())
            assert depth < len(stack)
            item = stack[-1-depth] if op == 0x79 else stack.pop(-1-depth)
            stack.append(item)
        elif op == 0x82:
            stack.append(encode(len(stack[-1])))
        elif op == 0x88:
            assert stack.pop() == stack.pop()
        elif op == 0x87:
            stack.append(encode(int(stack.pop() == stack.pop())))
        elif op == 0x91:
            stack.append(encode(int(integer(stack.pop()) == 0)))
        elif op == 0xa5:
            high, low, value = [integer(stack.pop()) for _ in range(3)]
            stack.append(encode(int(low <= value < high)))
        elif op == 0x69:
            assert integer(stack.pop()) != 0
        elif op == 0x75:
            stack.pop()
        elif op == 0x6d:
            stack.pop()
            stack.pop()
        elif op == 0xad:
            key, sig = decode_pubkey(stack.pop()), stack.pop()
            r, s = unpack_der(sig)
            assert 1 <= r < N and 1 <= s <= N//2
            assert signature(r, s, sig[-1]) == sig  # Canonical strict DER.
            assert sig[-1] in (1, 3, 0x83)
            z = z_all if sig[-1] == 1 else C
            valid, nonce = verify(z, r, s, key)
            assert valid
            checks.append({'flag': sig[-1], 'z': str(z), 'r': str(r),
                           'nonce_x': str(nonce[0])})
        else:
            raise AssertionError(hex(op))
        peak = max(peak, len(stack))
        assert peak <= 1000
    assert stack == [b'\x01'] and len(checks) == 6 and ops == 39
    return {'ecdsa_checks': checks, 'combined_stack_peak': peak,
            'executed_non_push_opcodes': ops}


def rejected(raw, entry, z):
    try:
        run(raw, entry, z)
    except (AssertionError, ValueError, IndexError):
        return True
    return False


def native_countermodel(recipient):
    raw = layout()
    output = b'\x00\x14'+bytes([recipient])*20
    for locktime in range(128):
        preimage = serialize(raw, output, locktime)+struct.pack('<I', 1)
        digest = hash256(preimage)
        z = int.from_bytes(digest, 'big') % N
        if not z:
            continue
        solution = solve(z*pow(C, -1, N) % N)
        if solution is not None:
            break
    else:
        raise AssertionError('bounded deterministic witness search found no point')
    r, rp, t = solution['r_alpha'], solution['r_beta'], solution['t']
    root = solution['R_alpha']
    keys = [mul(pow(r, -1, N), add(q, neg(mul(C)))) for q in (root, neg(root))]
    assert keys[0] != keys[1] and all(keys)
    beta_s = rp*pow(t*r, -1, N) % N
    sigs = [signature(r, 1, 3), signature(r, 1, 0x83),
            signature(rp, min(beta_s, N-beta_s), 1)]
    assert len(set(sigs)) == 3
    native = sigs+[pubkey(q) for q in keys]
    traces = [run(raw, [bytes([h])]+native, z) for h in (1, 2)]
    assert traces[0] == traces[1]
    negative = {
        'h_zero': rejected(raw, [b'']+native, z),
        'h_three': rejected(raw, [b'\x03']+native, z),
        'equal_keys': rejected(raw, [b'\x01']+sigs+[pubkey(keys[0])]*2, z),
        'changed_alpha_s': rejected(raw, [b'\x01', signature(r, 2, 3)]+native[1:], z),
    }
    changed_output = b'\x00\x14'+bytes([recipient ^ 0xff])*20
    changed_preimage = serialize(raw, changed_output, locktime)+struct.pack('<I', 1)
    changed_z = int.from_bytes(hash256(changed_preimage), 'big') % N
    negative['changed_output_retained_witness'] = rejected(raw, [b'\x01']+native, changed_z)
    assert all(negative.values())
    script_sigs = [b''.join(push(x) for x in [bytes([h])]+native+[raw]) for h in (1, 2)]
    # OP_1/OP_2 are the minimal scriptSig pushes for the numeric h item.
    script_sigs = [number(h)+blob[2:] for h, blob in zip((1, 2), script_sigs)]
    transactions = [serialize(blob, output, locktime) for blob in script_sigs]
    return {
        'output_script': output.hex(), 'amount_sat': 990000,
        'locktime': locktime, 'native_candidates_tried': locktime+1,
        'all_preimage': preimage.hex(), 'all_digest': digest.hex(),
        'same_synthetic_outpoints_as_other_fixtures': True,
        'native_entry_hex': [x.hex() for x in native],
        'first_two_signatures_equal_numeric_rs': True,
        'all_three_signature_byte_strings_distinct': True,
        'actual_three_point_orbit': False,
        'h_values_accepted_with_identical_other_data': [1, 2],
        'trace': traces[0], 'negative_cases_rejected': negative,
        'script_sig_bytes': list(map(len, script_sigs)),
        'script_sig_push_items_including_redeemscript': 7,
        'synthetic_spending_transactions': [tx.hex() for tx in transactions],
        'complete_synthetic_transaction_weights': [4*len(tx) for tx in transactions],
        'serialized_witness_bytes': 0,
    }


def main():
    report = {
        'question': 'Does a readable h plus six shared-key ECDSA checks enforce a three-point orbit?',
        'answer': 'No. The same native signatures and keys accept h=1 and h=2; their first two r values coincide.',
        'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
        'scope': 'raw-vector host interpreter and exact public curve arithmetic; no Core, real funding, mined proof hash or covenant',
        'orbit_algebra': orbit_identity(),
        'raw_script_hex': layout().hex(), 'locking_script_bytes': 64,
        'p2sh_wrapper_bytes_if_used': 23, 'counted_non_push_opcodes': 39,
        'entry_bottom_to_top': ['h', 'sigma0', 'sigma1', 'sigma2', 'P', 'Q'],
        'entry_data_items': 6, 'auxiliary_hint_items': 0,
        'countermodels': [native_countermodel(recipient) for recipient in (0x31, 0x32)],
    }
    output = HERE/'r13_orbit_query.json'
    output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'orbit_vectors': len(report['orbit_algebra']['vectors']),
                      'native_output_variants': len(report['countermodels']),
                      'positive_h_cases': 4, 'negative_cases': 10,
                      'combined_stack_peak': 8, 'output': str(output)}, indent=2))


if __name__ == '__main__':
    main()
