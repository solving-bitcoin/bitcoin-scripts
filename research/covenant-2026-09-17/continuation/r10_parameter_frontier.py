#!/usr/bin/env python3
"""Finite numeric-root domains, packed blinding and a complete affine checker.

Host/raw-boundary research; no rare native signature/pin witness is mined.
"""
from fractions import Fraction
from functools import lru_cache
import hashlib
import itertools
import json
import math
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'seven'))
from search1_nonce_encoding import EXPANSIONS, HASH_OPCODE, hash_word, num_bytes, push, push_num, routing_output, word_count
sys.path.insert(0, str(HERE))
from r9_numeric_root import root_script, decode

P_DER = Fraction(780555, 1 << 65)
Q_MIN, Q_MAX = -(2**27 - 1), 2**27 - 1
SEED_COUNT = Q_MAX - Q_MIN + 1
COEFFICIENT = 7


def language_counts(schedule):
    n = len(schedule)
    trans = [{} for _ in range(n + 1)]
    eps = [set() for _ in range(n + 1)]
    for i, h in enumerate(schedule):
        if i < n - 1:
            eps[i].add(i + 1)
        expansion = EXPANSIONS[h]
        if len(expansion) == 1:
            trans[i].setdefault(expansion, set()).add(i + 1)
        else:
            j = len(trans)
            trans.append({expansion[1]: {i + 1}})
            eps.append(set())
            trans[i].setdefault(expansion[0], set()).add(j)
    @lru_cache(None)
    def close(states):
        result, todo = set(states), list(states)
        while todo:
            for dest in eps[todo.pop()]:
                if dest not in result:
                    result.add(dest)
                    todo.append(dest)
        return frozenset(result)
    @lru_cache(None)
    def counts(states):
        words, prefixes = int(n in states), 1
        for ch in 'sar':
            dest = frozenset(j for i in states for j in trans[i].get(ch, ()))
            if dest:
                w, p = counts(close(dest))
                words += w
                prefixes += p
        return words, prefixes
    result = counts(close(frozenset({0})))
    assert result[0] == word_count(schedule)[0]
    return result


@lru_cache(None)
def schedule_for(n):
    choices = []
    for perm in itertools.permutations('SARDT'):
        schedule = (''.join(perm) * 20)[:n]
        if schedule[-1] == 'S':
            choices.append((word_count(schedule)[0], schedule))
    return max(choices)[1]


def packed_checker(schedule, expected_root=None):
    # Entry: reverse selectors, x, q, t, y, P. Save P,y,t,q, in that order.
    raw = b'\x6b' * 4 + root_script(schedule)
    # x == 16*q+7; all intermediate numeric reads use the four-byte bound.
    raw += b'\x6c\x6c' + b'\x76\x93' * 4 + push_num(COEFFICIENT) + b'\x93\x9d'
    # Exact integer polynomial y=t+7, no free final oracle or coefficient.
    raw += b'\x6c' + push_num(COEFFICIENT) + b'\x93\x6c\x9d\x6c'
    if expected_root is None:
        raw += bytes.fromhex('76a800ac75ac')
    else:
        raw += b'\x75' + push(expected_root) + b'\x87'
    return raw


def execute(raw, items):
    stack, alt, pc, peak, ops = list(items), [], 0, len(items), 0
    assert len(stack) <= 1000 and all(len(x) <= 520 for x in stack)
    while pc < len(raw):
        op = raw[pc]
        pc += 1
        if op <= 75:
            stack.append(raw[pc:pc + op])
            pc += op
        elif 0x51 <= op <= 0x60:
            stack.append(num_bytes(op - 0x50))
        else:
            ops += 1
            if op == 0x6b:
                alt.append(stack.pop())
            elif op == 0x6c:
                stack.append(alt.pop())
            elif op == 0x74:
                stack.append(num_bytes(len(stack)))
            elif op == 0x75:
                stack.pop()
            elif op == 0x76:
                stack.append(stack[-1])
            elif op == 0x77:
                del stack[-2]
            elif op == 0x7a:
                index = decode(stack.pop())
                if not 0 <= index < len(stack):
                    raise ValueError('ROLL range')
                stack.append(stack.pop(-1-index))
            elif op == 0x93:
                a, b = decode(stack.pop()), decode(stack.pop())
                stack.append(num_bytes(a+b))
            elif op in (0x87, 0x88, 0x9d):
                a, b = stack.pop(), stack.pop()
                equal = decode(a) == decode(b) if op == 0x9d else a == b
                if op == 0x87:
                    stack.append(num_bytes(int(equal)))
                elif not equal:
                    raise ValueError('equality')
            elif op in HASH_OPCODE.values():
                name = next(k for k, value in HASH_OPCODE.items() if value == op)
                stack.append(hash_word(stack.pop(), EXPANSIONS[name]))
            else:
                raise ValueError('unimplemented native gate or opcode')
        peak = max(peak, len(stack)+len(alt))
        if peak > 1000:
            raise ValueError('stack limit')
    return stack, alt, {'script_bytes': len(raw), 'executed_non_push_opcodes': ops, 'combined_stack_peak': peak}


def opcode_count(raw):
    pc = count = 0
    while pc < len(raw):
        op = raw[pc]
        pc += 1
        if op <= 75:
            pc += op
        elif op > 0x60:
            count += 1
    return count


def checker_tests():
    public_key = bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
    positives = 0
    last = None
    for n in (1, 3, 6, 37):
        schedule = schedule_for(n)
        selections = list(itertools.product((0, 1), repeat=n-1)) if n < 7 else [tuple(i % 2 for i in range(n-1))]
        for selection in selections:
            for q in (Q_MIN, -1, 0, 1, Q_MAX):
                for t in (-(2**31-1), -7, 0, 2**31-8):
                    x, y = 16*q+COEFFICIENT, t+COEFFICIENT
                    seed = hashlib.sha256(num_bytes(x)).digest()
                    expected = routing_output(seed, schedule, selection)
                    raw = packed_checker(schedule, expected)
                    items = [num_bytes(i) for i in reversed(selection)] + [num_bytes(x), num_bytes(q), num_bytes(t), num_bytes(y), public_key]
                    stack, alt, metrics = execute(raw, items)
                    assert stack == [b'\x01'] and alt == []
                    assert metrics['executed_non_push_opcodes'] == 3*n+29
                    assert metrics['combined_stack_peak'] <= n+7
                    positives += 1
                    last = schedule, expected, items, metrics
    schedule, expected, good, metrics = last
    raw = packed_checker(schedule, expected)
    negatives = 0
    malformed = []
    for offset, replacement in ((-5, num_bytes(decode(good[-5])+1)), (-4, num_bytes(0)),
                                (-3, num_bytes(2**31-1)), (-2, num_bytes(0)), (-4, b'\x01'*5)):
        bad = good.copy()
        bad[offset] = replacement
        malformed.append(bad)
    malformed += [good[1:], [b'junk']+good]
    for q in (-2**27, 2**27):
        bad = good.copy()
        bad[-5], bad[-4] = num_bytes(16*q+7), num_bytes(q)
        malformed.append(bad)
    for bad in malformed:
        try:
            stack, alt, _ = execute(raw, bad)
            assert stack != [b'\x01'] or alt
        except (ValueError, IndexError):
            pass
        negatives += 1
    native = packed_checker(schedule)
    assert opcode_count(native) == 143 and len(native) == 185
    assert metrics['combined_stack_peak'] == 44
    return {'observable_valid_vectors': positives, 'malformed_or_false_rejections': negatives,
            'stages': 37, 'observable': metrics, 'native_unmined': {
                'script_hex': native.hex(), 'script_bytes': len(native), 'counted_opcodes': opcode_count(native),
                'complete_entry_data_items': 41, 'path_hint_items': 36, 'packing_hint_items': 1,
                'total_hint_items': 37, 'non_hint_operands': 4, 'combined_peak_by_inspection': 44,
                'scope': 'Unmined root-signature/pin check with complete affine arithmetic; not an output-reference verifier.'}}


def finite_probability(N, p, L, branches=1):
    p = float(p)
    per_root_pin = -math.expm1(branches*L*math.log1p(-p))
    success = -math.expm1(N*math.log1p(-p*per_root_pin))
    return success


def finite_toy():
    success = roots = pairs = 0
    for bits in itertools.product((0, 1), repeat=6):
        a = bits[:2]
        b = (bits[2:4], bits[4:6])
        roots += sum(a)
        pairs += sum(a[i]*sum(b[i]) for i in range(2))
        success += any(a[i] and any(b[i]) for i in range(2))
    assert Fraction(success, 64) == Fraction(39, 64)
    assert Fraction(roots, 64) == 1 and Fraction(pairs, 64) == 1
    assert finite_probability(2, Fraction(1, 2), 2) == 39/64
    return {'outcomes': 64, 'root_count_mean': '1', 'pair_count_mean': '1', 'success_probability': '39/64'}


def linear_identity_check():
    # Fully fixed F=t+7; grant authentication of each false G=a*t+b before t.
    roots = []
    for a, b in itertools.product(range(17), repeat=2):
        if (a, b) == (1, 7):
            continue
        accepted = [t for t in range(17) if (a*t+b-t-7) % 17 == 0]
        assert len(accepted) <= 1
        roots.append(len(accepted))
    assert roots.count(1) == 272 and roots.count(0) == 16
    assert (2*1+6) % 17 == (1+7) % 17
    return {'field_order': 17, 'false_authenticated_affine_polynomials': 288,
            'false_polynomials_with_one_selected_accepting_challenge': 272,
            'false_polynomials_with_no_accepting_challenge': 16,
            'example_false_G': [2, 6], 'example_selected_challenge': 1,
            'uniform_challenge_acceptance_for_example': '1/17'}


def frontier():
    rows = []
    p = float(P_DER)
    for n in (20, 30, 34, 35, 36, 37, 40, 45, 50, 55, 56, 59, 60, 61):
        schedule = schedule_for(n)
        words, prefixes = language_counts(schedule)
        total = words * SEED_COUNT
        rows.append({'stages': n, 'schedule': schedule, 'semantic_words_per_seed': words,
                     'semantic_word_bits': math.log2(words), 'prefix_trie_nodes_including_empty': prefixes,
                     'prefix_nodes_per_word': prefixes/words,
                     'plain_fixed_seed_syntax_roots_expected_bits': math.log2(words*p),
                     'plain_fixed_seed_pair_mass_L32_bits': math.log2(words*(2**32)*p*p),
                     'packed_seed_count': SEED_COUNT, 'packed_total_root_candidates': total,
                     'packed_total_candidate_bits': math.log2(total),
                     'packed_syntax_roots_expected_bits': math.log2(total*p),
                     'packed_pair_mass_L32_bits': math.log2(total*(2**32)*p*p),
                     'packed_iid_syntax_pin_success_L32': finite_probability(total, P_DER, 2**32),
                     # One seed SHA256 plus prefixes-1 primitive hash edges.
                     'full_enumeration_primitive_hash_calls': prefixes*SEED_COUNT,
                     'full_enumeration_hash_bits': math.log2(prefixes*SEED_COUNT),
                     'packed_complete_affine_candidate_ops': 3*n+32,
                     'ops_left_under_201': 201-(3*n+32)})
    return rows


def prefix_tests():
    from search1_nonce_encoding import selected_word
    cases = 0
    for n in range(1, 10):
        schedule = schedule_for(n)
        words = {selected_word(schedule, bits) for bits in itertools.product((0, 1), repeat=n-1)}
        prefixes = {w[:j] for w in words for j in range(len(w)+1)}
        assert language_counts(schedule) == (len(words), len(prefixes))
        cases += 1
    return cases


if __name__ == '__main__':
    report = {'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
              'syntax_probability': str(P_DER), 'packing': {'coefficient': COEFFICIENT,
                'scale': 16, 'q_minimum': Q_MIN, 'q_maximum': Q_MAX, 'legitimate_numeric_seeds': SEED_COUNT},
              'prefix_language_exhaustive_sizes': prefix_tests(), 'finite_iid_toy': finite_toy(),
              'linear_identity_check': linear_identity_check(),
              'checker': checker_tests(), 'frontier': frontier(),
              'all_expectations_met': True}
    output = HERE / 'r10_parameter_frontier.json'
    output.write_text(json.dumps(report, indent=2)+'\n')
    print(output)
