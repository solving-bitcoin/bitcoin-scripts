#!/usr/bin/env python3
"""Deterministic host tests for an explicit reusable-function proof interface.

No Bitcoin Core execution, no repository script compiler, and no field-library
tests. The small raw fragment is an intentionally unoptimized bytecode boundary
model, not a primitive metric or full covenant.
"""
import hashlib
import itertools
import json
from pathlib import Path

P = 17


def eq(x, z):
    out = 1
    for a, b in zip(x, z):
        out = out * (b if a else 1 - b) % P
    return out


def table(n):
    return {x: int.from_bytes(hashlib.sha256(b'R6/reference/' + bytes(x)).digest(), 'big') % P
            for x in itertools.product((0, 1), repeat=n)}


def mle(values, z):
    return sum(v * eq(x, z) for x, v in values.items()) % P


def poly_at(coeff, z):
    a, b, c = coeff
    return (a + z * (b + z * c)) % P


def interpolate_quadratic(y0, y1, y2):
    c = (y2 - 2 * y1 + y0) * pow(2, -1, P) % P
    return [y0, (y1 - y0 - c) % P, c]


def honest_proof(values, x, challenges):
    prefix = []
    rounds = []
    n = len(x)
    for i, r in enumerate(challenges):
        evaluations = []
        for z in range(3):
            evaluations.append(sum(
                eq(x, prefix + [z] + list(tail))
                * mle(values, prefix + [z] + list(tail))
                for tail in itertools.product((0, 1), repeat=n-i-1)) % P)
        rounds.append(interpolate_quadratic(*evaluations))
        prefix.append(r)
    return rounds, mle(values, challenges)


def verify_lookup(x, claimed, rounds, challenges, final_value):
    if len(rounds) != len(x) or len(challenges) != len(x):
        return False
    current = claimed
    for coeff, r in zip(rounds, challenges):
        if (poly_at(coeff, 0) + poly_at(coeff, 1)) % P != current:
            return False
        current = poly_at(coeff, r)
    return current == eq(x, challenges) * final_value % P


def forged_proof(claimed, challenges, x):
    # Constant round polynomials satisfy every sum-check consistency condition.
    current = claimed
    rounds = []
    for _ in challenges:
        current = current * pow(2, -1, P) % P
        rounds.append([current, 0, 0])
    final_value = current * pow(eq(x, challenges), -1, P) % P
    return rounds, final_value


def bit_root(seed, bits):
    if len(seed) != 33:
        raise ValueError('initial seed must be 33 bytes')
    state = seed
    for b in bits:
        state = hashlib.new('sha256' if b else 'ripemd160', state).digest()
    return hashlib.sha256(state).digest()


def root_script(n):
    # SIZE 33 EQUALVERIFY; then each branch computes and retains its semantic bit.
    return bytes.fromhex('82012188') + bytes.fromhex('7c63a8516b67a6006b68') * n + b'\xa8'


def cast_bool(x):
    return any(b != 0 and not (i == len(x)-1 and b == 0x80) for i, b in enumerate(x))


def run_root(raw, items):
    stack, alt, cond = list(items), [], []
    pc = static = executed = 0
    peak = len(stack)
    while pc < len(raw):
        op = raw[pc]
        pc += 1
        active = all(cond)
        if 1 <= op <= 75:
            value = raw[pc:pc+op]
            pc += op
            if active:
                stack.append(value)
        elif op == 0:
            if active:
                stack.append(b'')
        elif op == 0x51:
            if active:
                stack.append(b'\x01')
        else:
            static += 1
            if op == 0x63:
                executed += 1
                cond.append(cast_bool(stack.pop()) if active else False)
            elif op == 0x67:
                executed += 1
                cond[-1] = not cond[-1]
            elif op == 0x68:
                executed += 1
                cond.pop()
            elif active:
                executed += 1
                if op == 0x82:
                    stack.append(bytes([len(stack[-1])]))
                elif op == 0x88:
                    if stack.pop() != stack.pop():
                        raise ValueError('EQUALVERIFY')
                elif op == 0x7c:
                    stack[-1], stack[-2] = stack[-2], stack[-1]
                elif op == 0x6b:
                    alt.append(stack.pop())
                elif op in (0xa6, 0xa8):
                    stack.append(hashlib.new('sha256' if op == 0xa8 else 'ripemd160', stack.pop()).digest())
                else:
                    raise ValueError('unsupported opcode')
        peak = max(peak, len(stack) + len(alt))
    assert not cond
    return stack, alt, {'raw_script_bytes': len(raw), 'static_non_push_opcodes': static,
                        'executed_non_push_opcodes_including_control': executed,
                        'combined_stack_peak': peak}


def main():
    honest_count = 0
    values = table(5)
    for x in values:
        for offset in range(3):
            challenges = [2 + (3*i+offset) % 15 for i in range(5)]
            rounds, final = honest_proof(values, x, challenges)
            assert verify_lookup(x, values[x], rounds, challenges, final)
            assert not verify_lookup(x, (values[x]+1) % P, rounds, challenges, final)
            honest_count += 1
    small = table(3)
    x = (1, 0, 1)
    false_y = (small[x]+1) % P
    unbound_accepts = authenticated_accepts = 0
    for r in itertools.product(range(2, P), repeat=3):
        rounds, forged_final = forged_proof(false_y, r, x)
        assert verify_lookup(x, false_y, rounds, r, forged_final)
        unbound_accepts += 1
        authenticated_accepts += verify_lookup(x, false_y, rounds, r, mle(small, r))

    seed = b'\x02' + hashlib.sha256(b'R6 fixed public seed').digest()
    root_cases = 0
    examples = []
    for n in (1, 3, 8, 15):
        candidates = list(itertools.product((0, 1), repeat=n)) if n <= 8 else [(i % 2 for i in range(n))]
        for candidate in candidates:
            bits = list(candidate)
            items = [b'\x01' if b else b'' for b in reversed(bits)] + [seed]
            stack, alt, metrics = run_root(root_script(n), items)
            assert stack == [bit_root(seed, bits)]
            assert alt == [b'\x01' if b else b'' for b in bits]
            assert metrics['static_non_push_opcodes'] == 3+8*n
            assert metrics['combined_stack_peak'] == n+3
            root_cases += 1
        examples.append({'bits': n, 'raw_script_hex': root_script(n).hex(), **metrics,
                         'entry_data_items': n+1, 'auxiliary_hint_items': 0,
                         'input_push_bytes': n+34,
                         'stack_vector_serialized_bytes_if_witness_encoded': 35+n+sum(bits),
                         'retained_normalized_bit_items_on_alt_stack': n})
    # Legacy IF commits its semantic bit rather than the original byte encoding.
    for encoded, expected in [(b'\x80', 0), (b'\x00\x80', 0), (b'\x02', 1)]:
        stack, alt, _ = run_root(root_script(1), [encoded, seed])
        assert stack == [bit_root(seed, [expected])]
        assert alt == [b'\x01' if expected else b'']

    report = {
        'evidence': 'locally-reproduced', 'deployment_class': 'unclassified',
        'scope': 'Host finite-field algebra and raw fragment interpreter only; no Core or full Script covenant.',
        'field_prime': P,
        'honest_lookup_proofs_and_wrong_claim_rejections': honest_count,
        'false_lookup': {'dimensions': 3, 'query': x, 'actual': small[x], 'claimed': false_y,
                         'challenge_domain': 'F17 minus {0,1}, independently in each coordinate',
                         'total_challenge_vectors': 15**3, 'unbound_final_oracle_accepts': unbound_accepts,
                         'same_forged_rounds_with_authentic_final_oracle_accepts': authenticated_accepts},
        'bit_root_cases': root_cases, 'legacy_noncanonical_bit_cases': 3,
        'root_fragments': examples,
        'optimistic_sumcheck_cost': {'dimensions': 32+45,
             'degree_per_variable': 2, 'coefficient_items': 3*(32+45),
             'round_check_arithmetic_comparison_steps': 4,
             'horner_arithmetic_steps': 4,
             'total_granted_field_operations_and_comparisons': 8*(32+45),
             'caveat': 'Counts one field ADD/MUL/equality per step, ignores routing, field reduction, challenges, commitments and final oracle; not actual opcode measurement.'},
        'sources': [
             {'url': 'https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf',
              'document_version': 'July 18, 2023', 'sections': ['3.5', '4.1', '4.6', '7.3']},
             {'url': 'https://arxiv.org/abs/1304.3812v1', 'document_version': 'v1'}]
    }
    target = Path(__file__).with_suffix('.json')
    target.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({k: v for k, v in report.items() if k not in ('root_fragments', 'sources')}, indent=2))


if __name__ == '__main__':
    main()
