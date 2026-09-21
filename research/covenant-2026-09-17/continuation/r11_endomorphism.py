#!/usr/bin/env python3
"""Hash-first secp256k1 endomorphism ratios via exact two-dimensional lattices.

Public host research. No nonce discrete logarithm, proof-hash preimage,
Bitcoin Core execution, or complete covenant is supplied.
"""
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
from r9_four_roots import encoded, neg
from r10_parallel_cycles import compact, hash256, instructions, number, pubkey, push, run_layout

BETA = pow(2, (P-1)//3, P)
LAMBDA = pow(3, (N-1)//3, N)
C = 2**248
GAP = P-N


def ceildiv(a, b):
    return -((-a)//b)


def dot(a, b):
    return a[0]*b[0]+a[1]*b[1]


def gauss_reduce(first, second):
    a, b = first, second
    steps = 0
    while True:
        steps += 1
        if dot(b, b) < dot(a, a):
            a, b = b, a
        q = (dot(a, b)+dot(a, a)//2)//dot(a, a)
        if q == 0:
            break
        b = (b[0]-q*a[0], b[1]-q*a[1])
    if a[0]*b[1]-a[1]*b[0] < 0:
        b = (-b[0], -b[1])
    assert dot(a, a) <= dot(b, b) and 2*abs(dot(a, b)) <= dot(a, a)
    return a, b, steps


def ratio_lattice(u, beta=BETA, p=P, n=N):
    assert 0 <= u < n and 0 < beta < p and p != n
    # CRT: v=beta mod p, v=u mod n. Coordinates are (x,x').
    v = beta+p*((u-beta)*pow(p, -1, n) % n)
    assert v % p == beta and v % n == u
    a, b, steps = gauss_reduce((1, v), (0, p*n))
    assert a[0]*b[1]-a[1]*b[0] == p*n
    for point in (a, b):
        assert (point[1]-beta*point[0]) % p == 0
        assert (point[1]-u*point[0]) % n == 0
    return {'basis': (a, b), 'steps': steps, 'crt_slope': v, 'determinant': p*n}


def box_lines(lattice, xlow, xhigh, ylow, yhigh):
    """Exact disjoint integer intervals for every lattice point in a rectangle."""
    assert xlow <= xhigh and ylow <= yhigh
    a, b = lattice['basis']
    determinant = lattice['determinant']
    numerators = [a[0]*y-a[1]*x for x in (xlow, xhigh) for y in (ylow, yhigh)]
    low_b, high_b = ceildiv(min(numerators), determinant), max(numerators)//determinant
    result = []
    for coefficient_b in range(low_b, high_b+1):
        low_a, high_a = None, None
        possible = True
        for j, (lo, hi) in enumerate(((xlow, xhigh), (ylow, yhigh))):
            offset = coefficient_b*b[j]
            if a[j] == 0:
                if not lo <= offset <= hi:
                    possible = False
                    break
                continue
            lower, upper = ((ceildiv(lo-offset, a[j]), (hi-offset)//a[j]) if a[j] > 0
                            else (ceildiv(hi-offset, a[j]), (lo-offset)//a[j]))
            low_a = lower if low_a is None else max(low_a, lower)
            high_a = upper if high_a is None else min(high_a, upper)
        if possible and low_a <= high_a:
            result.append((coefficient_b, low_a, high_a))
    return result


def points_in_lines(lattice, lines, cap=None):
    a, b = lattice['basis']
    yielded = 0
    for coefficient_b, low_a, high_a in lines:
        for coefficient_a in range(low_a, high_a+1):
            if cap is not None and yielded >= cap:
                return
            yielded += 1
            yield (coefficient_a*a[0]+coefficient_b*b[0],
                   coefficient_a*a[1]+coefficient_b*b[1])


def lift(x):
    if not 0 <= x < P:
        return None
    y = pow((x*x*x+7) % P, (P+1)//4, P)
    if y*y % P != (x*x*x+7) % P:
        return None
    return x, y if y % 2 == 0 else P-y


def solve(u, max_candidates=128, exponents=(1, 2), max_r=None):
    """Return one valid ratio witness or None for an arbitrary canonical u.

    Return fields: R_alpha, R_beta, t, beta, r_alpha, r_beta, and audit data.
    None means no point found within the explicitly bounded candidate search;
    it is not a proof that the target has no solution.
    No scalar log of R_alpha is computed or needed.
    """
    assert 1 <= u < N and max_candidates > 0
    assert max_r is None or 1 <= max_r < N
    for exponent in exponents:
        assert exponent in (1, 2)
        beta, t = pow(BETA, exponent, P), pow(LAMBDA, exponent, N)
        lattice = ratio_lattice(u, beta)
        ranges = [(1, P-1)] if max_r is None else [(1, max_r)]
        if max_r is not None and N+1 <= min(P-1, N+max_r):
            ranges.append((N+1, min(P-1, N+max_r)))
        lines = [line for low, high in ranges for line in box_lines(lattice, low, high, 1, P-1)]
        total_candidates = sum(hi-lo+1 for _, lo, hi in lines)
        for checked, (x, xp) in enumerate(points_in_lines(lattice, lines, max_candidates), 1):
            r, rp = x % N, xp % N
            if r == 0 or rp == 0:
                continue
            root = lift(x)
            if root is None:
                continue
            other = (xp, root[1])
            assert other[0] == beta*root[0] % P
            assert (other[1]**2-other[0]**3-7) % P == 0
            assert rp == u*r % N
            return {'R_alpha': root, 'R_beta': other, 't': t, 'beta': beta,
                    'r_alpha': r, 'r_beta': rp, 'exponent': exponent,
                    'gauss_steps': lattice['steps'], 'basis': lattice['basis'],
                    'total_rectangle_candidates': total_candidates,
                    'candidates_checked': checked, 'candidate_cap': max_candidates,
                    'all_candidates_covered_before_return': checked == total_candidates,
                    'max_r': max_r,
                    'u': u, 'wrap_p_quotient': beta*x//P,
                    'alpha_n_wrap': x//N, 'beta_n_wrap': xp//N}
    return None


def signature(r, s, flag):
    body = signature_integer(r)+signature_integer(s)
    return b'\x30'+bytes([len(body)])+body+bytes([flag])


def layout():
    # Entry bottom->top: alpha, beta, P, Q. No literal signature pushes.
    raw = b''
    for depth in (1, 0):
        raw += number(depth)+b'\x79\x82'+number(33)+b'\x88\x75'
    raw += b'\x51\x79\x51\x79\x87\x91\x69'
    for signature_depth in (3, 2):
        for key_depth in (2, 1):
            raw += number(signature_depth)+b'\x79'+number(key_depth)+b'\x79\xad'
    raw += b'\x6d\x6d\x51'
    count = sum(op > 0x60 for _, _, op, _ in instructions(raw))
    assert (len(raw), count) == (44, 27)
    return raw


def serialize(script_at_second_input, output_script, locktime):
    raw = struct.pack('<I', 2)+b'\x02'
    for i in range(2):
        script = script_at_second_input if i == 1 else b''
        raw += bytes([0x42+i])*32+struct.pack('<I', 0)+compact(len(script))+script+struct.pack('<I', 0xfffffffe)
    return raw+b'\x01'+struct.pack('<Q', 990000)+compact(len(output_script))+output_script+struct.pack('<I', locktime)


def native_vector(recipient, max_attempts=128):
    script = layout()
    output_script = b'\x00\x14'+bytes([recipient])*20
    attempts = []
    for locktime in range(max_attempts):
        preimage = serialize(script, output_script, locktime)+struct.pack('<I', 1)
        digest = hash256(preimage)
        z = int.from_bytes(digest, 'big') % N
        if z == 0:
            continue
        solution = solve(z*pow(C, -1, N) % N)
        attempts.append({'locktime': locktime, 'digest': digest.hex(), 'found': solution is not None})
        if solution is None:
            continue
        r, rp, t = solution['r_alpha'], solution['r_beta'], solution['t']
        assert r >= GAP and rp >= GAP  # Both native fixtures have two roots.
        root, other = solution['R_alpha'], solution['R_beta']
        assert mul(t, root) == other
        s_beta0 = rp*pow(t*r, -1, N) % N
        s_beta = min(s_beta0, N-s_beta0)
        keys = [mul(pow(r, -1, N), add(point, mul(-C))) for point in (root, neg(root))]
        assert all(q is not None for q in keys) and keys[0] != keys[1]
        alpha, beta = signature(r, 1, 3), signature(rp, s_beta, 1)
        entry = [alpha, beta]+[pubkey(q) for q in keys]
        observed = run_layout(script, entry, [C, C, z, z])
        assert not all(verify((z+1) % N, rp, s_beta, q)[0] for q in keys)
        script_sig = b''.join(push(item) for item in entry)+push(script)
        tx = serialize(script_sig, output_script, locktime)
        assert rp == (solution['beta']*r-solution['wrap_p_quotient']*GAP) % N
        return {'recipient': recipient, 'attempts': attempts, 'solution': solution,
                'all_preimage': preimage.hex(), 'all_digest': digest.hex(),
                'single_bug_digest': (b'\x01'+bytes(31)).hex(), 'entry_hex': [x.hex() for x in entry],
                'signature_bytes': [len(alpha), len(beta)], 'execution': observed,
                'script_sig_bytes': len(script_sig), 'script_sig_push_items': 5,
                'serialized_witness_bytes': 0, 'transaction_hex': tx.hex(),
                'transaction_weight': 4*len(tx), 'txid': hash256(tx)[::-1].hex(),
                'funded': False, 'nonce_discrete_log_computed': False}
    raise AssertionError('bounded native target search exhausted')


def toy_exhaustive():
    cases = points_checked = 0
    for p, n in ((31, 29), (43, 41), (67, 61), (103, 101)):
        beta = next(pow(a, (p-1)//3, p) for a in range(2, p) if pow(a, (p-1)//3, p) != 1)
        for u in range(n):
            lattice = ratio_lattice(u, beta, p, n)
            for xl, xh in ((1, p-1), (1, 2), (1, 8), (n+1, p-1)):
                if xl > xh:
                    continue
                got = set(points_in_lines(lattice, box_lines(lattice, xl, xh, 1, p-1)))
                expected = {(x, beta*x % p) for x in range(xl, xh+1) if (beta*x % p-u*x) % n == 0}
                assert got == expected
                cases += 1
                points_checked += len(expected)
    return {'rectangle_cases': cases, 'enumerated_points': points_checked,
            'parameter_pairs': [(31, 29), (43, 41), (67, 61), (103, 101)],
            'all_targets_in_each_small_modulus': True}


def deterministic_targets(count=64):
    rows = []
    for i in range(count):
        u = int.from_bytes(hashlib.sha256(f'R11-lattice-target-{i}'.encode()).digest(), 'big') % N or 1
        solution = solve(u)
        rows.append({'index': i, 'u': str(u), 'found': solution is not None,
                     'gauss_steps': None if solution is None else solution['gauss_steps'],
                     'exponent': None if solution is None else solution['exponent']})
    return rows


def wrap_vectors():
    xs = [2, N+2, 4, N+4, mul(1)[0], mul(pow(2, -1, N))[0]]
    rows = []
    for x in xs:
        root = lift(x)
        assert root is not None
        for exponent in (1, 2):
            beta, t = pow(BETA, exponent, P), pow(LAMBDA, exponent, N)
            xp = beta*x % P
            other = mul(t, root)
            assert other == (xp, root[1])
            # Include both n-wrap branches of the transformed point too.
            for a, b in ((root, other), (other, root)):
                exponent_now = exponent if a == root else 3-exponent
                beta_now = pow(BETA, exponent_now, P)
                q = beta_now*a[0]//P
                r, rp = a[0] % N, b[0] % N
                assert rp == (beta_now*r-q*GAP) % N
                rows.append({'x': str(a[0]), 'x_prime': str(b[0]), 'r': str(r), 'r_prime': str(rp),
                             'exponent': exponent_now, 'p_wrap_quotient': str(q),
                             'alpha_n_wrap': a[0]//N, 'beta_n_wrap': b[0]//N,
                             'naive_mod_n_beta_ratio_holds': rp == beta_now*r % N})
    assert any(row['alpha_n_wrap'] for row in rows) and any(row['beta_n_wrap'] for row in rows)
    return rows


def short_r_and_structured_families():
    # Exact 32-byte strict DER+flag implies nr+ns=25 and nr<=24;
    # a positive 24-byte DER integer has at most 191 value bits.
    max_r = 2**191-1
    planted = []
    for start in (2**190, 2**190+1000, 2**190+2000):
        x = next(start+i for i in range(256) if lift(start+i) is not None)
        for exponent in (1, 2):
            xp = pow(BETA, exponent, P)*x % P
            u = (xp % N)*pow(x, -1, N) % N
            got = solve(u, max_r=max_r, exponents=(exponent,))
            assert got is not None and got['r_alpha'] <= max_r
            assert len(signature(x, 1, 3)) == 32
            planted.append({'x': str(x), 'x_prime': str(xp), 'u': str(u), 'exponent': exponent,
                            'alpha_bytes': len(signature(x, 1, 3)), 'found_x': str(got['R_alpha'][0]),
                            'native_digest': False, 'hash_preimage_supplied': False})
    random_found = 0
    for i in range(64):
        u = int.from_bytes(hashlib.sha256(f'R11-short-target-{i}'.encode()).digest(), 'big') % N or 1
        random_found += solve(u, max_r=max_r) is not None

    a, b, steps = gauss_reduce((1, BETA), (0, P))
    # This deterministic reduced vector has both signs equal. Flip them.
    base_x, base_xp = (-a[0], -a[1]) if a[0] < 0 and a[1] < 0 else a
    assert base_x > 0 and base_xp > 0 and base_xp == BETA*base_x % P
    hmax = min(max_r//base_x, (P-1)//base_xp)
    ratio = base_xp*pow(base_x, -1, N) % N
    hs = [2**62+i for i in range(64) if lift(base_x*(2**62+i)) is not None][:3]
    family = []
    for h in hs:
        x, xp = base_x*h, base_xp*h
        assert h <= hmax and xp == BETA*x % P and xp*pow(x, -1, N) % N == ratio
        assert len(signature(x, 1, 3)) == 32
        family.append({'h': str(h), 'x': str(x), 'x_prime': str(xp), 'alpha_bytes': 32})
    coordinate_count = max_r+min(max_r, GAP-1)
    support = 2*coordinate_count  # Only beta and beta^2; signs add no x map.
    second_hash_representatives = 2**256-N
    digest_numerator_bound = support+min(support, second_hash_representatives)
    return {'max_r_for_exact_32_byte_der': str(max_r),
            'x_coordinate_count_bound_per_endomorphism': str(coordinate_count),
            'nonidentity_x_endomorphisms': 2, 'target_support_bound': str(support),
            'uniform_scalar_probability_upper_bound': f'{support}/{N}',
            'fresh_256_bit_hash_probability_upper_bound': f'{digest_numerator_bound}/{2**256}',
            'fresh_hash_bound_log2': math.log2(digest_numerator_bound)-256,
            'scope_of_bound': 'necessary short-r existence only; no curve-lift, DER remaining bytes, hash-derived-alpha, or funding cost included',
            'planted_short_r_vectors': planted, 'random_targets_checked': 64,
            'random_short_r_successes': random_found,
            'short_rational_family': {'gauss_basis': [a, b], 'gauss_steps': steps,
              'base_x': str(base_x), 'base_x_prime': str(base_xp), 'max_h': str(hmax),
              'all_h_have_same_target_ratio': str(ratio), 'distinct_target_count': 1,
              'curve_liftable_examples': family, 'hash_preimage_supplied': False}}


def orbit_vectors():
    rows = []
    for k in (1, 2, 7, pow(2, -1, N)):
        root = mul(k)
        xs = [pow(BETA, j, P)*root[0] % P for j in range(3)]
        rs = [x % N for x in xs]
        assert sum(xs) in (P, 2*P)
        h = sum(xs)//P
        us = [rs[(i+1) % 3]*pow(rs[i], -1, N) % N for i in range(3)]
        assert math.prod(us) % N == 1 and sum(rs) % N == h*GAP % N
        denominator = (1+us[0]+us[0]*us[1]) % N
        assert denominator != 0 and h*GAP*pow(denominator, -1, N) % N == rs[0]
        rows.append({'known_k': str(k), 'x_orbit': list(map(str, xs)), 'r_orbit': list(map(str, rs)),
                     'ratio_orbit': list(map(str, us)), 'sum_p_quotient': h,
                     'r0_recovered_from_first_two_ratios_and_h': str(rs[0])})
    return rows


def audit_core_artifact():
    """Read-only independent transaction/weight/preimage readback; no Core call."""
    from decimal import Decimal
    from r10_parallel_cycles import decode_pubkey, unpack_der
    path = HERE/'r11_endomorphism_core.json'
    source = path.read_bytes()
    subject = json.loads(source)

    def parse(raw):
        cursor = 4
        version = raw[:4]
        witness = raw[4:6] == b'\x00\x01'
        if witness:
            cursor += 2
        body_start = cursor

        def count():
            nonlocal cursor
            tag = raw[cursor]
            cursor += 1
            width = {253: 2, 254: 4, 255: 8}.get(tag, 0)
            if not width:
                return tag
            value = int.from_bytes(raw[cursor:cursor+width], 'little')
            cursor += width
            return value

        def vector():
            nonlocal cursor
            size = count()
            data = raw[cursor:cursor+size]
            assert len(data) == size
            cursor += size
            return data

        inputs = []
        for _ in range(count()):
            outpoint = raw[cursor:cursor+36]
            cursor += 36
            script = vector()
            sequence = raw[cursor:cursor+4]
            cursor += 4
            inputs.append({'outpoint': outpoint, 'script': script, 'sequence': sequence})
        outputs = []
        for _ in range(count()):
            amount = int.from_bytes(raw[cursor:cursor+8], 'little')
            cursor += 8
            outputs.append((amount, vector()))
        body_end = cursor
        witnesses = [[vector() for _ in range(count())] for _ in inputs] if witness else []
        witness_bytes = cursor-body_end
        locktime = raw[cursor:cursor+4]
        cursor += 4
        assert cursor == len(raw)
        base = version+raw[body_start:body_end]+locktime
        return {'version': version, 'inputs': inputs, 'outputs': outputs, 'witnesses': witnesses,
                'locktime': locktime, 'base': base, 'weight': 3*len(base)+len(raw),
                'witness_bytes': witness_bytes, 'marker_flag_bytes': 2 if witness else 0,
                'txid': hash256(base)[::-1].hex(), 'wtxid': hash256(raw)[::-1].hex()}

    def check_serialization(record):
        raw = bytes.fromhex(record['hex'])
        tx = parse(raw)
        for key in ('txid', 'wtxid', 'weight', 'witness_bytes'):
            assert tx[key] == record[key]
        assert len(tx['base']) == record['base_bytes'] and len(raw) == record['total_bytes']
        return tx

    def all_preimage(tx, script):
        raw = tx['version']+compact(len(tx['inputs']))
        for index, vin in enumerate(tx['inputs']):
            code = script if index == 1 else b''
            raw += vin['outpoint']+compact(len(code))+code+vin['sequence']
        raw += compact(len(tx['outputs']))
        raw += b''.join(struct.pack('<Q', amount)+compact(len(code))+code for amount, code in tx['outputs'])
        return raw+tx['locktime']+struct.pack('<I', 1)

    script = bytes.fromhex(subject['redeemscript'])
    assert script == layout() and len(script) == 44
    funding = check_serialization(subject['funding'])
    expected_p2sh = b'\xa9\x14'+hashlib.new('ripemd160', hashlib.sha256(script).digest()).digest()+b'\x87'
    expected_ordinary = b'\x00\x20'+hashlib.sha256(b'\x51').digest()
    assert funding['outputs'] == [(1000000, expected_p2sh), (1000000, expected_ordinary), (4997990000, expected_ordinary)]
    assert funding['witnesses'] == [[b'\x51']] and sum(a for a, _ in funding['outputs']) == 4999990000
    rows = []
    for row in subject['results']:
        tx = check_serialization(row['transaction'])
        assert len(tx['inputs']) == 2 and len(tx['outputs']) == 1
        for vin, vout in zip(tx['inputs'], (1, 0)):
            assert vin['outpoint'] == bytes.fromhex(funding['txid'])[::-1]+struct.pack('<I', vout)
            assert vin['sequence'] == b'\xff'*4
        assert tx['inputs'][0]['script'] == b'' and tx['witnesses'] == [[b'\x51'], []]
        assert tx['witness_bytes'] == row['complete_transaction_witness_bytes'] == 4
        assert tx['marker_flag_bytes'] == row['marker_flag_bytes'] == 2
        assert tx['outputs'] == [(r['amount'], bytes.fromhex(r['script'])) for r in row['outputs']]
        assert int.from_bytes(tx['locktime'], 'little') == row['locktime']
        entry = [bytes.fromhex(item) for item in row['input_items']]
        assert tx['inputs'][1]['script'] == b''.join(push(item) for item in entry)+push(script)
        assert len(tx['inputs'][1]['script']) == row['script_sig_bytes']
        assert row['input_data_items'] == 4 and row['hint_items'] == 0 and row['script_sig_push_items'] == 5
        assert entry[0][-1] == 3 and entry[1][-1] == 1
        assert row['single_bug_digest'] == (b'\x01'+bytes(31)).hex()
        preimage = all_preimage(tx, script)
        actual_digest = hash256(preimage)
        z = int.from_bytes(actual_digest, 'big') % N
        assert hash256(bytes.fromhex(row['all_preimage'])).hex() == row['all_digest']
        stored_context_is_current = preimage.hex() == row['all_preimage']
        assert stored_context_is_current == (row['name'] != 'changed-output-old-witness')
        qs = [decode_pubkey(q) for q in entry[2:]]
        signatures = [unpack_der(sig) for sig in entry[:2]]
        equations = [verify(message, r, s, q)[0] for message, (r, s) in zip((C, z), signatures) for q in qs]
        expected = row['policy']['allowed']
        assert row['consensus']['accepted'] == expected
        try:
            trace = run_layout(script, entry, [C, C, z, z])
            accepted = True
        except AssertionError:
            trace, accepted = None, False
        assert accepted == expected
        if expected:
            assert equations == [True]*4 and trace == {'checks': 4, 'combined_stack_peak': 7, 'executed_non_push_opcodes': 27}
            solution = row['solution']
            root, other = tuple(solution['R_alpha']), tuple(solution['R_beta'])
            assert mul(solution['t'], root) == other
            assert solution['r_beta'] == solution['u']*solution['r_alpha'] % N
            assert solution['u'] == z*pow(C, -1, N) % N
            recovered = [mul(pow(solution['r_alpha'], -1, N), add(point, mul(-C))) for point in (root, neg(root))]
            assert qs == recovered
            assert row['policy']['vsize'] == (tx['weight']+3)//4
            fee = 2000000-sum(a for a, _ in tx['outputs'])
            assert Decimal(str(row['policy']['fees']['base']))*10**8 == fee
        else:
            fee = 2000000-sum(a for a, _ in tx['outputs'])
        rows.append({'name': row['name'], 'accepted': accepted, 'ecdsa_checks': equations,
                     'actual_all_digest': actual_digest.hex(), 'stored_digest_is_current_transaction': stored_context_is_current,
                     'base_bytes': len(tx['base']), 'weight': tx['weight'], 'fee_sat': fee})
    assert len(rows) == 6 and sum(row['accepted'] for row in rows) == 3
    return {'subject': path.name, 'subject_sha256': hashlib.sha256(source).hexdigest(),
            'bitcoin_core_commit': subject['bitcoin_core']['commit'],
            'funding_txid': funding['txid'], 'funding_output_sum_sat': 4999990000,
            'funding_fee_sat_given_documented_50btc_coinbase': 10000,
            'funding_base_bytes': len(funding['base']), 'funding_weight': funding['weight'],
            'results': rows, 'critical_issues': [],
            'note': 'Changed-output-old-witness retains original witness-construction all_preimage/all_digest/trace; audit separately reconstructs its changed actual transaction digest.',
            'scope': 'independent parsing, stripping, serialization, native preimage and shared-key equation readback; existing EC helper; no new Core run'}


def main():
    assert BETA == int('7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee', 16)
    assert LAMBDA == int('5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72', 16)
    assert pow(BETA, 3, P) == 1 and pow(LAMBDA, 3, N) == 1
    assert mul(LAMBDA) == (BETA*G[0] % P, G[1])
    report = {'question': 'Can the known endomorphism solve a native digest-first nonce ratio?',
              'answer': 'Yes for freely selected full-length alpha: exact 2D lattice search supplies unknown-log nonce points with a known ratio. This does not supply a hash-derived alpha or output asymmetry.',
              'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
              'beta_hex': f'{BETA:x}', 'lambda_hex': f'{LAMBDA:x}',
              'raw_script_hex': layout().hex(), 'raw_script_bytes': 44, 'counted_opcodes': 27,
              'entry_data_items': 4, 'hint_items': 0, 'combined_stack_peak': 7,
              'toy_exhaustive': toy_exhaustive(), 'wrap_vectors': wrap_vectors(),
              'short_r_and_structured_families': short_r_and_structured_families(),
              'three_cycle_orbits': orbit_vectors(),
              'deterministic_targets': deterministic_targets(),
              'native_vectors': [native_vector(r) for r in (17, 34, 51, 68, 85, 102, 119, 136)],
              'all_expectations_met': True}
    if (HERE/'r11_endomorphism_core.json').exists():
        report['independent_core_artifact_audit'] = audit_core_artifact()
    output = Path(__file__).with_suffix('.json')
    output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'output': str(output), 'native_locktime_attempts': [len(v['attempts']) for v in report['native_vectors']],
                      'target_successes_of_64': sum(row['found'] for row in report['deterministic_targets']),
                      'toy_exhaustive': report['toy_exhaustive']}, indent=2))


if __name__ == '__main__':
    main()
