#!/usr/bin/env python3
"""Publicly checked two-scalar input labels for a binary Boolean gate.

Host-only algebra experiment: deterministic public fixtures, no Bitcoin
execution, encrypted tables, ZKP, setup benchmark or full protocol claim.
The symbolic checks describe scalar-linear disclosure; curve commitments
add a discrete-log assumption, not information-theoretic secrecy.
"""
import copy
import hashlib
import itertools
import json
from pathlib import Path
import unittest

from nonce_relation_extraction import G, N, P, add, mul, scalar_fixture

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
INPUTS = ('left0', 'left1', 'right0', 'right1')
NAMES = INPUTS + ('output0', 'output1')
AND = (0, 0, 0, 1)
MESSAGES = tuple(itertools.product((0, 1), repeat=2))


def basis(i):
    return tuple(int(j == i) for j in range(6))


def difference(a, b):
    return tuple(x-y for x, y in zip(a, b))


def forms(truth):
    """Six independent secrets: output0, output1, pad00, pad01, pad10, pad11."""
    return dict(left0=(basis(2), basis(3)), left1=(basis(4), basis(5)),
        right0=(difference(basis(truth[0]), basis(2)),
                difference(basis(truth[2]), basis(4))),
        right1=(difference(basis(truth[1]), basis(3)),
                difference(basis(truth[3]), basis(5))),
        output0=(basis(0),), output1=(basis(1),))


def dot(a, b, modulus=N):
    return sum(x*y for x, y in zip(a, b)) % modulus


def rref(rows, modulus=N):
    a = [[x % modulus for x in row] for row in rows]
    if not a:
        return [], []
    pivot_columns = []
    for column in range(len(a[0])):
        pivot = len(pivot_columns)
        found = next((i for i in range(pivot, len(a)) if a[i][column]), None)
        if found is None:
            continue
        a[pivot], a[found] = a[found], a[pivot]
        scale = pow(a[pivot][column], -1, modulus)
        a[pivot] = [x*scale % modulus for x in a[pivot]]
        for i in range(len(a)):
            if i != pivot:
                scale = a[i][column]
                a[i] = [(x-scale*y) % modulus for x, y in zip(a[i], a[pivot])]
        pivot_columns.append(column)
        if len(pivot_columns) == len(a):
            break
    return a, pivot_columns


def rank(rows, modulus=N):
    return len(rref(rows, modulus)[1])


def null_direction(opened, target):
    """Return h with opened*h=0 and target*h=1, or reject a spanned target."""
    reduced, pivots = rref(opened)
    for free in range(6):
        if free in pivots:
            continue
        h = [int(i == free) for i in range(6)]
        for row, pivot in zip(reduced, pivots):
            h[pivot] = -row[free] % N
        scale = dot(target, h)
        if scale:
            return tuple(x*pow(scale, -1, N) % N for x in h)
    raise ValueError('target belongs to disclosed scalar-linear span')


def valid_point(point):
    return (isinstance(point, tuple) and len(point) == 2
        and all(type(x) is int and 0 <= x < P for x in point)
        and (point[1]*point[1]-point[0]**3-7) % P == 0)


def public_check(public, expected_truth=AND):
    """No private labels, pads, garbling seed or scalar encoding key are passed."""
    if not isinstance(public, dict) or set(public) != {'truth', 'points'}:
        return False
    truth, points = public['truth'], public['points']
    if (truth != expected_truth or not isinstance(truth, tuple) or len(truth) != 4
            or any(type(bit) is not int or bit not in (0, 1) for bit in truth)
            or not isinstance(points, dict) or set(points) != set(NAMES)):
        return False
    for name in NAMES:
        if (not isinstance(points[name], tuple)
                or len(points[name]) != (2 if name in INPUTS else 1)
                or not all(valid_point(point) for point in points[name])):
            return False
    if any(points[side+'0'] == points[side+'1'] for side in ('left', 'right', 'output')):
        return False
    return all(add(points['left'+str(a)][b], points['right'+str(b)][a])
               == points['output'+str(truth[2*a+b])][0] for a, b in MESSAGES)


def fixture(index, truth=AND):
    symbolic = forms(truth)
    for attempt in range(100):
        secrets = [scalar_fixture(f'vector-gate/{index}/{attempt}/{i}') for i in range(6)]
        labels = {name:tuple(dot(row, secrets) for row in rows)
                  for name, rows in symbolic.items()}
        public = dict(truth=truth, points={name:tuple(mul(x) for x in values)
                                          for name, values in labels.items()})
        if public_check(public, truth):
            return labels, public
    raise RuntimeError('fixture could not generate finite distinct labels')


def embedded_public_view(truth, message, target, challenge_point, known):
    """DLP reduction interface: receives X, never its logarithm.

    Commits to u=known+h*x symbolically. The chosen opening has A*h=0,
    so its actual scalars can be supplied without x. The target has h-dot=1.
    """
    symbolic = forms(truth)
    a, b = message
    selected = symbolic['left'+str(a)]+symbolic['right'+str(b)]
    h = null_direction(selected, target)
    public = dict(truth=truth, points={name:tuple(
        add(mul(dot(row, known)), mul(dot(row, h), challenge_point)) for row in rows)
        for name, rows in symbolic.items()})
    opening = tuple(tuple(dot(row, known) for row in symbolic[side+str(bit)])
                    for side, bit in zip(('left', 'right'), message))
    return public, opening, dot(target, known), h


def evaluate(public, message, opening, expected_truth=AND):
    if (not public_check(public, expected_truth) or not isinstance(message, tuple)
            or len(message) != 2
            or any(type(bit) is not int or bit not in (0, 1) for bit in message)):
        raise ValueError('invalid public setup or message')
    if (not isinstance(opening, tuple) or len(opening) != 2
            or any(not isinstance(label, tuple) or len(label) != 2 for label in opening)
            or any(type(x) is not int or not 0 < x < N for label in opening for x in label)):
        raise ValueError('expected two canonical two-scalar labels')
    for side, bit, label in zip(('left', 'right'), message, opening):
        if tuple(mul(x) for x in label) != public['points'][side+str(bit)]:
            raise ValueError('input label does not match its public points')
    a, b = message
    value = (opening[0][b]+opening[1][a]) % N
    output = public['truth'][2*a+b]
    if mul(value) != public['points']['output'+str(output)][0]:
        raise AssertionError('point-checked gate failed scalar reconstruction')
    return value


def disclosure_report():
    rows = []
    for truth in itertools.product((0, 1), repeat=4):
        symbolic = forms(truth)
        for a, b in MESSAGES:
            selected = symbolic['left'+str(a)]+symbolic['right'+str(b)]
            r = rank(selected)
            assert r == 4
            output = truth[2*a+b]
            assert rank(selected+symbolic['output'+str(output)]) == r
            assert rank(selected+symbolic['output'+str(1-output)]) == r+1
            residuals = []
            for c, d in MESSAGES:
                if (a, b) == (c, d):
                    continue
                alternative = symbolic['left'+str(c)]+symbolic['right'+str(d)]
                residuals.append(rank(selected+alternative)-r)
                unknown = next(row for row in alternative if rank(selected+(row,)) > r)
                h = null_direction(selected, unknown)
                assert all(dot(row, h) == 0 for row in selected)
                assert dot(unknown, h) == 1
            assert min(residuals) >= 1
            rows.append(dict(truth=list(truth), message=[a,b], selected_rank=r,
                             alternative_residual_ranks=residuals))
        assert all(rank(symbolic[name]) == 2 for name in INPUTS)
    return rows


def scalar_gate_screen(modulus):
    """Exhaustive projective lines in F_p^3; corroborates the scoped proof."""
    lines = []
    for vector in itertools.product(range(modulus), repeat=3):
        nonzero = next((x for x in vector if x), None)
        if nonzero == 1:
            lines.append(vector)
    accepted = 0
    for a, b, c, d in itertools.permutations(lines, 4):
        selections = ((a,c), (a,d), (b,c), (b,d))
        opposites = ((b,d), (b,c), (a,d), (a,c))
        if any(rank(selected+(other,), modulus) == rank(selected, modulus)
               for selected, others in zip(selections, opposites) for other in others):
            continue
        accepted += 1
        # A non-public zero-output form would belong to all three zero-input spans.
        assert not any(all(rank(selected+(line,), modulus) == rank(selected, modulus)
                           for selected in selections[:3]) for line in lines)
    return dict(modulus=modulus, ambient_dimension=3, projective_lines=len(lines),
                assignments_with_no_opposite_input_in_span=accepted,
                assignments_with_hidden_linear_AND_zero_output=0)


class VectorGateTests(unittest.TestCase):
    def test_every_truth_table_and_honest_opening(self):
        for index, truth in enumerate(itertools.product((0, 1), repeat=4)):
            labels, public = fixture(index, truth)
            for a, b in MESSAGES:
                opening = (labels['left'+str(a)], labels['right'+str(b)])
                self.assertEqual(evaluate(public, (a,b), opening, truth), labels['output'+str(truth[2*a+b])][0])

    def test_correct_garbling_of_wrong_function_is_rejected(self):
        truth = (0,1,1,1)
        labels, public = fixture(0, truth)
        self.assertTrue(public_check(public, truth))
        self.assertFalse(public_check(public, AND))
        with self.assertRaises(ValueError):
            evaluate(public, (0,1), (labels['left0'], labels['right1']), AND)

    def test_symbolic_opening_and_alternative_spans(self):
        self.assertEqual(len(disclosure_report()), 64)

    def test_every_point_mutation_breaks_AND_setup(self):
        _, public = fixture(0)
        for name in NAMES:
            for i in range(len(public['points'][name])):
                changed = copy.deepcopy(public)
                vector = list(changed['points'][name])
                vector[i] = add(vector[i], G)
                changed['points'][name] = tuple(vector)
                self.assertFalse(public_check(changed), (name, i))

    def test_bad_public_shapes_and_encodings(self):
        _, public = fixture(0)
        for point in (None, (1,1), (P,G[1]), (True,G[1])):
            changed = copy.deepcopy(public)
            changed['points']['left0'] = (point, public['points']['left0'][1])
            self.assertFalse(public_check(changed))
        for truth in ((0,0,0), (0,0,0,2), (False,0,0,1), [0,0,0,1]):
            self.assertFalse(public_check(dict(public, truth=truth)))
        for changed in ({}, dict(public, extra=0), dict(public, points={})):
            self.assertFalse(public_check(changed))

    def test_malformed_or_partial_openings_rejected(self):
        labels, public = fixture(1)
        left, right = labels['left0'], labels['right1']
        bad = ((left[:1],right), (left,right[:1]),
               ((0,left[1]),right), ((N,left[1]),right),
               ((left[0]+1,left[1]),right), (labels['left1'],right), (left,))
        for opening in bad:
            with self.assertRaises(ValueError):
                evaluate(public, (0,1), opening)
        for message in ((2,1), (False,1), (0,), [0,1]):
            with self.assertRaises(ValueError):
                evaluate(public, message, (left,right))

    def test_scalar_only_AND_boundary_small_fields(self):
        for modulus in (2,3):
            result = scalar_gate_screen(modulus)
            self.assertGreater(result['assignments_with_no_opposite_input_in_span'], 0)

    def test_public_DLP_embedding_without_challenge_scalar(self):
        symbolic = forms(AND)
        secret = scalar_fixture('vector-gate/reduction/challenge')
        challenge = mul(secret)
        known = [scalar_fixture(f'vector-gate/reduction/base/{i}') for i in range(6)]
        for message in MESSAGES:
            selected = symbolic['left'+str(message[0])]+symbolic['right'+str(message[1])]
            for alternative in MESSAGES:
                if alternative == message:
                    continue
                rows = symbolic['left'+str(alternative[0])]+symbolic['right'+str(alternative[1])]
                target = next(row for row in rows if rank(selected+(row,)) > rank(selected))
                public, opening, offset, h = embedded_public_view(AND, message, target, challenge, known)
                self.assertTrue(public_check(public))
                value = evaluate(public, message, opening)
                # Only the test oracle knows x; the simulator above receives X.
                actual = tuple((base+delta*secret) % N for base, delta in zip(known,h))
                expected = dot(symbolic['output'+str(message[0]&message[1])][0], actual)
                self.assertEqual(value, expected)
                self.assertEqual((dot(target, actual)-offset) % N, secret)

    def test_point_packing_equality_does_not_certify_digit_ranges(self):
        radix = 1 << 128
        symbolic = forms(AND)
        base = [scalar_fixture(f'vector-gate/packing/{i}') % (1 << 126)+1 for i in range(6)]
        old_left = tuple(dot(row, base) for row in symbolic['left0'])
        packed = (old_left[0]+radix*old_left[1]) % N
        self.assertEqual((packed % radix, packed // radix), old_left)
        # Change a -> a+radix, b -> b-1; the packed scalar/point stay fixed.
        base[2] += radix
        base[3] -= 1
        labels = {name:tuple(dot(row, base) for row in rows) for name,rows in symbolic.items()}
        public = dict(truth=AND, points={name:tuple(mul(x) for x in label) for name,label in labels.items()})
        self.assertTrue(public_check(public))
        self.assertEqual(add(public['points']['left0'][0], mul(radix, public['points']['left0'][1])), mul(packed))
        self.assertNotEqual(labels['left0'], old_left)
        with self.assertRaises(ValueError):
            evaluate(public, (0,1), (old_left, labels['right1']))


if __name__ == '__main__':
    result = unittest.main(exit=False).result
    if not result.wasSuccessful():
        raise SystemExit(1)
    paths = [Path(__file__), HERE/'nonce_relation_extraction.py',
             HERE.parent/'covenant-2026-09-17/legacy_same_signature_counterexample.py']
    report = dict(evidence='locally-reproduced', deployment='unclassified',
        scope=__doc__, tests_run=result.testsRun, failures=0, errors=0,
        public_curve_instances=16, honest_curve_evaluations=64,
        point_mutations_rejected=10, malformed_public_cases_rejected=11,
        malformed_openings_or_messages_rejected=11,
        public_DLP_embedding_cases=12,
        point_packing_range_counterexample=True,
        intended_truth_table_checked=True,
        disclosure_cases=disclosure_report(),
        scalar_gate_screens=[scalar_gate_screen(p) for p in (2,3)],
        per_gate=dict(secret_field_dimension=6, public_point_count=10,
                      public_relation_count=4, scalars_per_input_label=2,
                      selected_scalar_count=4, output_scalar_count=1,
                      public_compressed_point_payload_bytes=330,
                      selected_scalar_payload_bytes=128),
        direct_scalar_linear_delivery=dict(rank_per_input_label=2,
            minimum_independent_scalar_openings_per_label=2,
            scope='Independent honest masks; affine scalar recovery only, public constants quotiented out.'),
        one_layer_2048_bit_interface=dict(gates=1024, scalar_openings=4096,
            guarded_legacy_signature_push_floor_vbytes=4096*59,
            scope='This two-coordinate interface with one guarded legacy opening per scalar; signatures/pushes only, all other costs free. No native arbitrary-label wrapper supplied.'),
        native_scalar_binding_implemented=False, complete_verifier_implemented=False,
        bitcoin_execution=False, script_bytes=None, witness_bytes=None,
        hint_items=None, entry_items=None, combined_stack_peak=None,
        executed_opcodes=None, validation_budget=None, setup_benchmark=None,
        onchain_vbytes=None,
        source_sha256={str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in paths})
    (HERE/'vector-label-gate.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({key:report[key] for key in ('tests_run','public_curve_instances',
        'honest_curve_evaluations','scalar_gate_screens','per_gate','one_layer_2048_bit_interface')},indent=2))
