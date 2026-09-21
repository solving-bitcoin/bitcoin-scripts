#!/usr/bin/env python3
"""Independent small-domain/stack audit of the R10 packed-seed frontier.

Only the observable arithmetic/hash layout is executed. Native ECDSA/pin
checks remain unmined. This is not Bitcoin Core or a consensus result.
"""
import hashlib
import itertools
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import r10_parameter_frontier as candidate


def enc(value):
    negative = value < 0
    magnitude = abs(value)
    if magnitude == 0:
        return b''
    raw = bytearray()
    while magnitude:
        raw.append(magnitude & 255)
        magnitude >>= 8
    if raw[-1] & 128:
        raw.append(128 if negative else 0)
    elif negative:
        raw[-1] |= 128
    return bytes(raw)


def integer(raw):
    if len(raw) > 4:
        raise ValueError('numeric width')
    if not raw:
        return 0
    magnitude = sum(b << (8*i) for i, b in enumerate(raw[:-1]))
    magnitude += (raw[-1] & 127) << (8*(len(raw)-1))
    return -magnitude if raw[-1] & 128 else magnitude


def hash_value(op, value):
    if op == 0xa6: return hashlib.new('ripemd160', value).digest()
    if op == 0xa7: return hashlib.sha1(value).digest()
    h = hashlib.sha256(value).digest()
    if op == 0xa8: return h
    if op == 0xa9: return hashlib.new('ripemd160', h).digest()
    if op == 0xaa: return hashlib.sha256(h).digest()
    raise ValueError('hash opcode')


def execute(raw, items):
    main, alt, cursor, ops, peak = list(items), [], 0, 0, len(items)
    while cursor < len(raw):
        op = raw[cursor]
        cursor += 1
        if op <= 75:
            main.append(raw[cursor:cursor+op]); cursor += op
        elif 0x51 <= op <= 0x60:
            main.append(enc(op-0x50))
        else:
            ops += 1
            if op == 0x6b: alt.append(main.pop())
            elif op == 0x6c: main.append(alt.pop())
            elif op == 0x74: main.append(enc(len(main)))
            elif op == 0x75: main.pop()
            elif op == 0x76: main.append(main[-1])
            elif op == 0x77: del main[-2]
            elif op == 0x7a:
                i = integer(main.pop())
                if not 0 <= i < len(main): raise ValueError('roll')
                main.append(main.pop(len(main)-1-i))
            elif op == 0x93: main.append(enc(integer(main.pop())+integer(main.pop())))
            elif op in (0x87, 0x88, 0x9d):
                a, b = main.pop(), main.pop()
                equal = integer(a) == integer(b) if op == 0x9d else a == b
                if op == 0x87: main.append(enc(int(equal)))
                elif not equal: raise ValueError('comparison')
            elif 0xa6 <= op <= 0xaa: main.append(hash_value(op, main.pop()))
            else: raise ValueError('unexpected or native-check opcode')
        peak = max(peak, len(main)+len(alt))
    return main, alt, ops, peak


def main():
    expansions = {'S': 's', 'A': 'a', 'R': 'r', 'D': 'ss', 'T': 'sr'}
    hashops = {'s': 0xa8, 'a': 0xa7, 'r': 0xa6}
    language_cases = cases = malformed = 0
    for n in range(1, 11):
        schedule = candidate.schedule_for(n)
        # Independent explicit language construction, not epsilon-NFA/DFA.
        language = {''}
        for i, token in enumerate(schedule):
            applied = {w+expansions[token] for w in language}
            language = applied if i == n-1 else language | applied
        prefixes = {w[:i] for w in language for i in range(len(w)+1)}
        assert candidate.language_counts(schedule) == (len(language), len(prefixes))
        language_cases += 1
    for n in (1, 2, 5, 37):
        schedule = candidate.schedule_for(n)
        for q, t in itertools.product((-(2**27-1), -7, 0, 7, 2**27-1), (-19, 0, 19)):
            bits = tuple(i % 2 for i in range(n-1))
            states = ['', expansions[schedule[0]]]
            for bit, token in zip(bits, schedule[1:]):
                at = len(states)-1-bit
                states.append(states.pop(at)+expansions[token])
            x, y = 16*q+7, t+7
            expected = hashlib.sha256(enc(x)).digest()
            for h in states[-1]: expected = hash_value(hashops[h], expected)
            raw = candidate.packed_checker(schedule, expected)
            data = [enc(b) for b in reversed(bits)]+[enc(x), enc(q), enc(t), enc(y), b'key-placeholder']
            result = execute(raw, data)
            assert result[:2] == ([b'\x01'], []) and result[2] == 3*n+29
            assert result[3] <= n+7
            if n == 37: assert result[3] == 44
            cases += 1
            bad = list(data); bad[-2] = enc(y+1)
            try: execute(raw, bad)
            except ValueError: malformed += 1
            else: raise AssertionError('wrong affine output accepted')
    # Exact packing endpoint claim is a property of every numeric read,
    # including the penultimate intermediate, not only the final seed.
    assert len(enc(16*(-2**27))) == 5 and len(enc(16*(2**27))) == 5
    assert all(len(enc(16*q)) <= 4 and len(enc(16*q+7)) <= 4
               for q in (-(2**27-1), 2**27-1))
    row = next(r for r in candidate.frontier() if r['stages'] == 37)
    assert row['packed_total_root_candidates'] == 14715977732*(2**28-1)
    assert row['full_enumeration_primitive_hash_calls'] == 27837386332*(2**28-1)
    report = {'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
              'scope': __doc__, 'independent_explicit_language_cases': language_cases,
              'independent_observable_layout_cases': cases,
              'wrong_affine_output_rejections': malformed,
              'n37_root_candidates': row['packed_total_root_candidates'],
              'n37_primitive_hash_calls': row['full_enumeration_primitive_hash_calls'],
              'all_assertions_passed': True}
    path = Path(__file__).with_suffix('.json')
    path.write_text(json.dumps(report, indent=2)+'\n')
    print(path)


if __name__ == '__main__':
    main()
