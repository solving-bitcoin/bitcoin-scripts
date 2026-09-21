#!/usr/bin/env python3
"""Literal ECDSA scaling on all four r=2 recovery roots, deterministic host research.

No Core, Script executor, repository compiler, or field-library tests.
"""
from collections import Counter, defaultdict
import hashlib
import itertools
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from legacy_same_signature_counterexample import G, N, P, add, mul, signature_integer, verify, vector


def neg(point):
    return None if point is None else (point[0], -point[1] % P)


def encoded(point):
    return 'infinity' if point is None else (bytes([2+point[1] % 2])+point[0].to_bytes(32, 'big')).hex()


def roots():
    out = []
    for x in (2, N+2):
        y = pow((x*x*x+7) % P, (P+1)//4, P)
        assert y*y % P == (x*x*x+7) % P
        point = (x, min(y, P-y))
        out.extend((point, neg(point)))
    assert len(set(out)) == 4
    return out


def offsets(scaled_by, points):
    out = defaultdict(list)
    scaled = [mul(scaled_by, point) for point in points]
    for i, a in enumerate(points):
        for j, b in enumerate(scaled):
            out[add(b, neg(a))].append([i, j])
    return out


def sig(s):
    body = signature_integer(2)+signature_integer(s)
    return b'\x30'+vector(body)+b'\x01'


def number(n):
    assert 0 <= n <= 16
    return bytes([0 if n == 0 else 0x50+n])


def layout(count, s2, code_separator=True):
    # Inspectable raw layout, not a policy-compiled repository primitive.
    raw = b''
    for i in range(count):
        raw += number(count-1-i)+b'\x79\x82\x01\x21\x88\x75'
    for i, j in itertools.combinations(range(count), 2):
        raw += number(count-1-i)+b'\x79'+number(count-j)+b'\x79\x87\x91\x69'
    for context, s in enumerate((1, s2)):
        if context and code_separator:
            raw += b'\xab'
        for i in range(count):
            raw += vector(sig(s))+number(count-i)+b'\x79\xad'
    raw += b'\x6d'*(count//2)+(b'\x75' if count % 2 else b'')+b'\x51'
    pc = opcount = 0
    while pc < len(raw):
        op = raw[pc]
        pc += 1
        if 1 <= op <= 75:
            pc += op
        elif op > 0x60:
            opcount += 1
    assert pc == len(raw)
    return {'raw_script': raw.hex(), 'raw_bytes': len(raw), 'counted_opcodes': opcount,
            'entry_key_data_items': count, 'auxiliary_hint_items': 0,
            'combined_stack_peak_by_inspection': count+3,
            'code_separator': code_separator,
            'literal_signatures': [sig(1).hex(), sig(s2).hex()],
            'scope': 'complete raw locking-predicate layout; input pushes and transaction excluded'}


def variable_signature_layout(code_separator=True):
    # Entry: sigma Q0 Q1 Q2. The same raw signature is copied for every check.
    count = 3
    raw = b''
    for i in range(count):
        raw += number(count-1-i)+b'\x79\x82\x01\x21\x88\x75'
    for i, j in itertools.combinations(range(count), 2):
        raw += number(count-1-i)+b'\x79'+number(count-j)+b'\x79\x87\x91\x69'
    for context in range(2):
        if context and code_separator:
            raw += b'\xab'
        for i in range(count):
            raw += number(count)+b'\x79'+number(count-i)+b'\x79\xad'
    raw += b'\x6d\x6d\x51'
    pc = opcount = 0
    while pc < len(raw):
        op = raw[pc]
        pc += 1
        if 1 <= op <= 75:
            pc += op
        elif op > 0x60:
            opcount += 1
    assert (len(raw), opcount) == (75+int(code_separator), 47+int(code_separator))
    return {'raw_script': raw.hex(), 'raw_bytes': len(raw), 'counted_opcodes': opcount,
            'entry_data_items': 4, 'entry_signature_data_items': 1, 'entry_key_data_items': 3,
            'auxiliary_hint_items': 0, 'combined_stack_peak_by_inspection': 7,
            'code_separator': code_separator,
            'entry_bottom_to_top': ['sigma', 'Q0', 'Q1', 'Q2'],
            'scope': 'complete raw predicate layout; no execution or transaction; variable sighash flag not constrained to ALL'}


def polynomial_trim(a):
    a = [x % P for x in a]
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    return a


def polynomial_subtract(a, b):
    c = list(a)+[0]*max(0, len(b)-len(a))
    for i, x in enumerate(b):
        c[i] -= x
    return polynomial_trim(c)


def polynomial_multiply(a, b):
    c = [0]*(len(a)+len(b)-1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            c[i+j] = (c[i+j]+x*y) % P
    return polynomial_trim(c)


def polynomial_divmod(a, b):
    remainder, b = polynomial_trim(a), polynomial_trim(b)
    assert b != [0]
    quotient = [0]*max(1, len(remainder)-len(b)+1)
    inverse = pow(b[-1], -1, P)
    while remainder != [0] and len(remainder) >= len(b):
        shift = len(remainder)-len(b)
        coefficient = remainder[-1]*inverse % P
        quotient[shift] = coefficient
        for j, x in enumerate(b):
            remainder[shift+j] = (remainder[shift+j]-coefficient*x) % P
        remainder = polynomial_trim(remainder)
    return polynomial_trim(quotient), remainder


def polynomial_monic(a):
    a = polynomial_trim(a)
    assert a != [0]
    inverse = pow(a[-1], -1, P)
    return [x*inverse % P for x in a]


def polynomial_gcd(a, b):
    a, b = polynomial_trim(a), polynomial_trim(b)
    while b != [0]:
        a, b = b, polynomial_divmod(a, b)[1]
    return polynomial_monic(a)


def polynomial_powmod(base, exponent, modulus):
    answer = [1]
    base = polynomial_divmod(base, modulus)[1]
    while exponent:
        if exponent & 1:
            answer = polynomial_divmod(polynomial_multiply(answer, base), modulus)[1]
        base = polynomial_divmod(polynomial_multiply(base, base), modulus)[1]
        exponent >>= 1
    return answer


def fully_split_roots(factor):
    # factor=gcd(F,X^p-X) is squarefree and already a product of linear factors.
    pending, found, split_trials = [polynomial_monic(factor)], [], []
    while pending:
        current = pending.pop()
        if len(current) == 1:
            continue
        if len(current) == 2:
            found.append(-current[0]*pow(current[1], -1, P) % P)
            continue
        for constant in range(256):
            linear = [constant, 1]
            g = polynomial_gcd(current, linear)
            if len(g) in (1, len(current)):
                powered = polynomial_powmod(linear, (P-1)//2, current)
                g = polynomial_gcd(current, polynomial_subtract(powered, [1]))
            if 1 < len(g) < len(current):
                other, remainder = polynomial_divmod(current, g)
                assert remainder == [0]
                split_trials.append({'degree': len(current)-1, 'constant': constant,
                                     'factor_degree': len(g)-1})
                pending.extend((polynomial_monic(g), polynomial_monic(other)))
                break
        else:
            raise AssertionError('deterministic splitting cap exhausted')
    product = [1]
    for root in found:
        product = polynomial_multiply(product, [-root, 1])
    assert product == polynomial_monic(factor)
    assert len(set(found)) == len(found)
    return sorted(found), split_trials


def all_r_tripling_check():
    results = []
    gap = P-N
    # Symbolic cancellation in the direct addition/doubling derivation.
    x, u, w = [0, 1], [7, 0, 0, 1], [0, 84, 0, 0, 3]
    add_polys = lambda a, b: polynomial_subtract(a, [-v for v in b])
    scale_poly = lambda a, c: polynomial_trim([c*v for v in a])
    first = polynomial_subtract(add_polys([0, 0, 0, 0, 9], w),
                                scale_poly(polynomial_multiply(x, u), 12))
    second = add_polys(polynomial_subtract(scale_poly(polynomial_multiply(u, u), 8),
                                          scale_poly(polynomial_multiply([0, 0, 1], w), 3)),
                       [-392, 0, 0, 140, 0, 0, 1])
    assert first == [0] and second == [0]
    for sign in (1, -1):
        # x(3P)-x=-8(x^3+7)(x^6+140x^3-392)/(3x^4+84x)^2.
        coefficients = polynomial_trim([-21952, 0, sign*7056*N, 4704, 0,
                                        sign*504*N, 1176, 0, sign*9*N, 8])
        xp_minus_x = polynomial_subtract(polynomial_powmod([0, 1], P, coefficients), [0, 1])
        split_factor = polynomial_gcd(coefficients, xp_minus_x)
        field_roots, trials = fully_split_roots(split_factor)
        lower, upper = (1, gap-1) if sign == 1 else (N+1, P-1)
        in_interval = [x for x in field_roots if lower <= x <= upper]
        for x in field_roots:
            value = 0
            for coefficient in reversed(coefficients):
                value = (value*x+coefficient) % P
            assert value == 0
        # This assertion certifies the stronger fact: no polynomial root even
        # before checking curve liftability or excluding denominator-zero roots.
        assert not in_interval
        results.append({'sign': sign, 'polynomial_coefficients_low_to_high': list(map(hex, coefficients)),
                        'frobenius_remainder_low_to_high': list(map(hex, xp_minus_x)),
                        'linear_factor_product_low_to_high': list(map(hex, split_factor)),
                        'degree_of_linear_factor_product': len(split_factor)-1,
                        'all_field_roots': list(map(hex, field_roots)),
                        'deterministic_splitting_trials': trials,
                        'eligible_x_interval': [hex(lower), hex(upper)],
                        'roots_in_eligible_interval': in_interval})
    # Independently check the rational tripling identity on actual points.
    identities = 0
    for k in (1, 2, 3, 7, 19, 43, pow(2, -1, N)):
        point = mul(k)
        x = point[0]
        denominator = (3*x**4+84*x)**2 % P
        numerator = 8*(x**3+7)*(x**6+140*x**3-392) % P
        assert denominator
        predicted = (x-numerator*pow(denominator, -1, P)) % P
        assert mul(3, point)[0] == predicted
        identities += 1
    return {'scope': 'All possible four-root ECDSA r values on secp256k1, via complete Fp root enumeration',
            'curve_prime': hex(P), 'group_order': hex(N), 'field_order_gap': hex(gap),
            'symbolic_tripling_cancellation_polynomials': [first, second],
            'tripling_identity_point_checks': identities,
            'polynomials': results,
            'four_root_arithmetic_progression_exists': False}


def main():
    points = roots()
    summary = []
    for t in range(1, 128):
        table = offsets(t, points)
        histogram = Counter(map(len, table.values()))
        if t == 1:
            assert histogram == {1: 4, 2: 4, 4: 1}
            assert len(table[None]) == 4
        else:
            assert len(table) == 16 and max(map(len, table.values())) == 1
            assert None not in table
        summary.append({'second_literal_s': t, 'distinct_point_offsets': len(table),
                        'maximum_shared_keys_for_any_two_digest_scalars': max(map(len, table.values())),
                        'multiplicity_histogram': dict(histogram)})
    neg_table = offsets(N-1, points)
    assert set(neg_table) == set(offsets(1, points))
    assert max(map(len, neg_table.values())) == 4

    # Every root and sign is covered; this is exhaustive in root choices.
    t2 = offsets(2, points)
    t2_rows = [{'point_offset': encoded(point), 'root_pairs': pairs}
               for point, pairs in t2.items()]
    z = int.from_bytes(hashlib.sha256(b'R9 fixed public scalar').digest(), 'big') % N
    base_keys = [mul(pow(2, -1, N), add(r, neg(mul(z)))) for r in points]
    assert all(verify(z, 2, 1, pub)[0] for pub in base_keys)
    assert all(not verify(z, 2, 2, pub)[0] for pub in base_keys)

    # A precomputed point offset can align separate keys for every z, with no
    # nonce logarithm. No native opcode that enforces these additions is claimed.
    public_offsets = [mul(pow(2, -1, N), add(mul(2, points[(i+2) % 4]), neg(points[i])))
                      for i in range(4)]
    alignment_cases = 0
    for j in range(8):
        z_j = int.from_bytes(hashlib.sha256(('R9 aligned scalar %d' % j).encode()).digest(), 'big') % N
        for i in range(4):
            p1 = mul(pow(2, -1, N), add(points[i], neg(mul(z_j))))
            p2 = add(p1, public_offsets[i])
            assert verify(z_j, 2, 1, p1)[0]
            assert verify(z_j, 2, 2, p2)[0]
            alignment_cases += 1

    # Limited escape check: explicit cheap scalar offsets do not account for
    # any nonzero root-switch difference. This is not a DLP hardness proof.
    difference_points = set(offsets(1, points))-{None}
    cheap_scalars = {j % N for j in range(-256, 257) if j}
    cheap_scalars |= {j*pow(2, -1, N) % N for j in range(-256, 257) if j}
    cheap_points = {mul(j): j for j in cheap_scalars}
    assert not (difference_points & set(cheap_points))

    two = layout(2, 2)
    three = layout(3, 1)
    assert (two['raw_bytes'], two['counted_opcodes']) == (76, 23)
    assert (three['raw_bytes'], three['counted_opcodes']) == (124, 42)
    report = {'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
              'scope': 'Host point-set and ECDSA algebra; no Script/Core execution',
              'roots_compressed': list(map(encoded, points)),
              'all_positive_one_byte_s_values': summary,
              's2_differences': t2_rows,
              'negative_s_symmetry': {'scalar': str(N-1), 'max_overlap': 4,
                                     'note': 'High-S counterpart; no policy-validity claim'},
              'single_scalar_root_checks': {'s1_accepted': 4, 's2_same_keys_rejected': 4},
              'public_offset_alignment': {'fixed_offsets': list(map(encoded, public_offsets)),
                                          'arbitrary_digest_cases': 8,
                                          'key_pairs_verified': alignment_cases,
                                          'native_offset_authentication_implemented': False},
              'small_known_offset_scan': {'distinct_public_scalars_checked': len(cheap_scalars),
                                           'family': 'nonzero j and j/2 modulo n, -256<=j<=256',
                                           'nonzero_root_switch_points': len(difference_points),
                                           'matches': 0},
              'two_common_keys_s1_s2_layout': two,
              'three_common_keys_same_signature_layout': three,
              'three_common_keys_variable_signature_layout': variable_signature_layout(),
              'three_common_keys_variable_signature_same_context_layout': variable_signature_layout(False),
              'three_common_keys_literal_signature_same_context_layout': layout(3, 1, False),
              'all_r_tripling_check': all_r_tripling_check(),
              'all_expectations_met': True}
    destination = Path(__file__).with_suffix('.json')
    destination.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'literal_scalings': len(summary), 's2_distinct_offsets': len(t2_rows),
                      'offset_alignment_pairs': alignment_cases,
                      'two_key_script_bytes_ops': [two['raw_bytes'], two['counted_opcodes']],
                      'three_key_script_bytes_ops': [three['raw_bytes'], three['counted_opcodes']],
                      'artifact': str(destination)}, indent=2))


if __name__ == '__main__':
    main()
