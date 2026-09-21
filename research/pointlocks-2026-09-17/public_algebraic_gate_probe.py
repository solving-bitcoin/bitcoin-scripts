#!/usr/bin/env python3
"""A publicly point-checked AND gate and its incompatible message-label access.

This scalar-field experiment is inspired by privacy-free formula garbling.
It is not an implementation of that paper's XOR-string garbling, nor Bitcoin
Script. All seeds are deterministic public fixtures. No ZKP or counterparty.
"""
import hashlib
import itertools
import json
from pathlib import Path
import unittest

from nonce_relation_extraction import G, N, P, add, mul, scalar_fixture

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
NAMES = ('left0', 'left1', 'right0', 'right1', 'output0', 'output1')


def valid_point(point):
    return (isinstance(point, tuple) and len(point) == 2
            and all(type(v) is int and 0 <= v < P for v in point)
            and (point[1] * point[1] - point[0] ** 3 - 7) % P == 0)


def fixture(index, *, distinct_zero_points=False):
    """Secret scalar labels; a,b make both zero-label points distinct if desired."""
    k0, left1, right1 = [scalar_fixture(f'public-gate/{index}/{name}')
                         for name in ('zero', 'left-one', 'right-one')]
    a, b = ((scalar_fixture(f'public-gate/{index}/{name}') for name in ('a', 'b'))
            if distinct_zero_points else (0, 0))
    secret = dict(left0=(k0+a) % N, left1=left1,
                  right0=(k0+b) % N, right1=right1,
                  output0=k0, output1=(left1+right1) % N)
    public = dict(points={name: mul(value) for name, value in secret.items()}, a=a, b=b)
    return secret, public


def public_check(public):
    """Uses only points and public offsets; no scalar-label encoding key."""
    if set(public) != {'points', 'a', 'b'} or set(public['points']) != set(NAMES):
        return False
    points = public['points']
    if not all(valid_point(point) for point in points.values()):
        return False
    a, b = public['a'], public['b']
    if any(type(v) is not int or not 0 <= v < N for v in (a, b)):
        return False
    return (points['left0'] == add(points['output0'], mul(a))
            and points['right0'] == add(points['output0'], mul(b))
            and points['output1'] == add(points['left1'], points['right1']))


def evaluate(public, message, opening):
    """Checks the two actual input scalars and returns the selected output scalar."""
    if not public_check(public) or message not in tuple(itertools.product((0, 1), repeat=2)):
        raise ValueError('invalid public setup or message')
    if len(opening) != 2 or any(type(v) is not int or not 0 < v < N for v in opening):
        raise ValueError('noncanonical scalar opening')
    for side, bit, scalar in zip(('left', 'right'), message, opening):
        if mul(scalar) != public['points'][side+str(bit)]:
            raise ValueError('opening does not match bound input label')
    left, right = message
    value = ((opening[0]-public['a']) if left == 0 else
             (opening[1]-public['b']) if right == 0 else sum(opening)) % N
    if mul(value) != public['points']['output'+str(left & right)]:
        raise AssertionError('publicly checked gate evaluated inconsistently')
    return value


def alternative_zero_opening(public, message, opening):
    """Public setup and one permitted opening suffice; no secret fixture input."""
    if message not in ((0, 1), (1, 0)):
        raise ValueError('this recovery applies to mixed input pairs')
    k0 = evaluate(public, message, opening)
    alternate = ((k0+public['a']) % N, (k0+public['b']) % N)
    # This authenticates a complete different input, not only a scalar guess.
    evaluate(public, (0, 0), alternate)
    return (0, 0), alternate


class PublicGateTests(unittest.TestCase):
    def test_public_check_and_every_honest_input(self):
        for shifted in (False, True):
            for index in range(8):
                secret, public = fixture(index, distinct_zero_points=shifted)
                self.assertTrue(public_check(public))
                if shifted:
                    self.assertEqual(len(set(public['points'].values())), 6)
                for message in itertools.product((0, 1), repeat=2):
                    opening = tuple(secret[side+str(bit)] for side, bit in zip(('left', 'right'), message))
                    self.assertEqual(evaluate(public, message, opening), secret['output'+str(message[0]&message[1])])

    def test_opposite_input_recovery_including_distinct_points(self):
        for shifted in (False, True):
            for index in range(8):
                secret, public = fixture(index, distinct_zero_points=shifted)
                for message in ((0, 1), (1, 0)):
                    opening = tuple(secret[side+str(bit)] for side, bit in zip(('left', 'right'), message))
                    alternate_message, alternate = alternative_zero_opening(public, message, opening)
                    self.assertNotEqual(alternate_message, message)
                    self.assertEqual(alternate, (secret['left0'], secret['right0']))
                    # The alternative has the same clear AND output. No failure
                    # of the source paper's output-authenticity claim follows.
                    self.assertEqual(evaluate(public, message, opening), evaluate(public, alternate_message, alternate))

    def test_public_check_rejects_bad_relations_and_encodings(self):
        _, public = fixture(0, distinct_zero_points=True)
        for name in NAMES:
            changed = dict(public, points=dict(public['points']))
            changed['points'][name] = add(changed['points'][name], G)
            self.assertFalse(public_check(changed), name)
        for name in ('a', 'b'):
            self.assertFalse(public_check(dict(public, **{name:(public[name]+1) % N})))
            self.assertFalse(public_check(dict(public, **{name:N})))
        for point in (None, (1, 1), (P, G[1])):
            changed = dict(public, points=dict(public['points'], left0=point))
            self.assertFalse(public_check(changed))

    def test_invalid_openings_do_not_create_a_false_counterexample(self):
        secret, public = fixture(3, distinct_zero_points=True)
        honest = (secret['left0'], secret['right1'])
        for opening in ((honest[0]+1, honest[1]), (honest[0], honest[1]+1),
                        (0, honest[1]), (N, honest[1]), (honest[0],)):
            with self.assertRaises(ValueError):
                evaluate(public, (0, 1), opening)
        with self.assertRaises(ValueError):
            evaluate(public, (2, 0), honest)


if __name__ == '__main__':
    program = unittest.main(exit=False)
    if not program.result.wasSuccessful():
        raise SystemExit(1)
    paths = [Path(__file__), HERE/'nonce_relation_extraction.py',
             HERE.parent/'covenant-2026-09-17/legacy_same_signature_counterexample.py']
    report = dict(evidence='locally-reproduced', deployment='unclassified',
        scope=__doc__, tests_run=program.result.testsRun, failures=0, errors=0,
        public_instances=16, honest_input_evaluations=64,
        alternate_complete_input_recoveries=32, distinct_point_recoveries=16,
        altered_public_relations_or_encodings_rejected=13,
        algebraic_gate_correctness=True, required_message_label_privacy=False,
        contradicts_source_output_authenticity=False, bitcoin_execution=False,
        script_bytes=None, witness_bytes=None, hint_items=None, entry_items=None,
        combined_stack_peak=None, executed_opcodes=None, validation_budget=None,
        setup_benchmark=None, onchain_vbytes=None,
        source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    (HERE/'public-algebraic-gate.json').write_text(json.dumps(report, indent=2)+'\n')
