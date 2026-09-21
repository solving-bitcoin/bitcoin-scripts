#!/usr/bin/env python3
"""Share vector-label coordinates: a three-of-four algebraic binary gate.

Deterministic host-only reference and exact subset-support screens. No native
point-lock wrapper, Bitcoin transaction, setup benchmark or full verifier.
"""
import copy
import hashlib
import itertools
import json
import math
from pathlib import Path
import unittest

from vector_label_gate_probe import G, N, add, mul, rank, scalar_fixture, valid_point

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
AND = (0,0,0,1)
# The union of the selected left/right vectors omits exactly index 2*a+b.
WIRES = {'left0':(2,3), 'left1':(0,1), 'right0':(1,3), 'right1':(0,2)}


def truth_valid(truth):
    return (isinstance(truth, tuple) and len(truth) >= 2
            and all(type(bit) is int and bit in (0,1) for bit in truth)
            and set(truth) == {0,1})


def point_sum(points):
    result = None
    for point in points:
        result = add(result, point)
    return result


def public_check(public, expected_truth):
    """Expected truth table is external; all checks use points, not scalars."""
    if (not isinstance(public, dict) or set(public) != {'truth','points','outputs'}
            or not truth_valid(expected_truth) or public['truth'] != expected_truth):
        return False
    points, outputs = public['points'], public['outputs']
    if (not isinstance(points, tuple) or len(points) != len(expected_truth)
            or not isinstance(outputs, tuple) or len(outputs) != 2
            or not all(valid_point(p) for p in points+outputs)
            or len(set(points)) != len(points) or outputs[0] == outputs[1]):
        return False
    return all(point_sum(points[i] for i,bit in enumerate(expected_truth) if bit != output)
               == outputs[output] for output in (0,1))


def fixture(index, truth=AND):
    if not truth_valid(truth):
        raise ValueError('expected a nonconstant binary classifier')
    for attempt in range(100):
        scalars = tuple(scalar_fixture(f'shared-vector/{index}/{attempt}/{i}') for i in range(len(truth)))
        outputs = tuple(sum(x for x,bit in zip(scalars,truth) if bit != output) % N for output in (0,1))
        public = dict(truth=truth, points=tuple(mul(x) for x in scalars), outputs=tuple(mul(x) for x in outputs))
        if public_check(public, truth):
            return scalars, outputs, public
    raise RuntimeError('fixture generation exhausted')


def evaluate(public, expected_truth, opening):
    """Opening is an ordered tuple of n-1 (index, scalar) pairs."""
    if not public_check(public, expected_truth):
        raise ValueError('invalid point setup or wrong intended function')
    n = len(expected_truth)
    if (not isinstance(opening, tuple) or len(opening) != n-1
            or any(not isinstance(item, tuple) or len(item) != 2 for item in opening)):
        raise ValueError('expected exactly n-1 indexed scalar openings')
    indices = tuple(item[0] for item in opening)
    if (any(type(i) is not int or not 0 <= i < n for i in indices)
            or indices != tuple(sorted(set(indices)))
            or any(type(x) is not int or not 0 < x < N for _,x in opening)):
        raise ValueError('noncanonical indices or scalars')
    if any(mul(x) != public['points'][i] for i,x in opening):
        raise ValueError('scalar does not match its prebound point')
    missing = next(i for i in range(n) if i not in indices)
    bit = expected_truth[missing]
    scalar = sum(x for i,x in opening if expected_truth[i] != bit) % N
    if mul(scalar) != public['outputs'][bit]:
        raise AssertionError('public setup check failed to bind reconstruction')
    return missing, bit, scalar


def vector_report():
    basis = [tuple(int(i == j) for j in range(4)) for i in range(4)]
    result = []
    for a,b in itertools.product((0,1), repeat=2):
        left, right = WIRES['left'+str(a)], WIRES['right'+str(b)]
        selected_indices = sorted(set(left+right))
        assert selected_indices == [i for i in range(4) if i != 2*a+b]
        selected = tuple(basis[i] for i in selected_indices)
        assert rank(selected) == 3
        residuals = []
        for c,d in itertools.product((0,1), repeat=2):
            if (a,b) == (c,d):
                continue
            alternative = tuple(basis[i] for i in WIRES['left'+str(c)]+WIRES['right'+str(d)])
            residuals.append(rank(selected+alternative)-rank(selected))
        assert residuals == [1,1,1]
        result.append(dict(message=[a,b], missing_index=2*a+b, selected_indices=selected_indices,
                           selected_rank=3, alternative_residual_ranks=residuals))
    return result


def support_screen(n, t):
    """All unordered nonempty support pairs; no assumption about classifier f."""
    selections = [sum(1 << i for i in choice) for choice in itertools.combinations(range(n),t)]
    accepted = []
    for first in range(1,1 << n):
        for second in range(first+1,1 << n):
            if all(((s & first) == first) != ((s & second) == second) for s in selections):
                accepted.append((first,second))
    expected = (1 << (n-1))-1 if t == n-1 else 0
    assert len(accepted) == expected
    full = (1 << n)-1
    assert all((a & b) == 0 and (a | b) == full for a,b in accepted)
    return dict(n=n,t=t,subset_count=len(selections),
                support_pairs_examined=((1 << n)-1)*((1 << n)-2)//2,
                valid_unordered_support_pairs=len(accepted),
                all_valid_pairs_partition_inventory=True)


def rank_two_coordinate_screen():
    """Finite coordinate-subspace corroboration; the general proof is separate."""
    count = private = 0
    for a,b,c,d in itertools.product(range(1,16),repeat=4):
        count += 1
        views = (a|c,a|d,b|c,b|d)
        if max(bin(view).count('1') for view in views) > 2:
            continue
        opposites = ((b,d),(b,c),(a,d),(a,c))
        if any((view & other) == other for view,others in zip(views,opposites) for other in others):
            continue
        private += 1
        zero_support = views[0] & views[1] & views[2]
        assert zero_support == 0
    return dict(ambient_dimension=4,assignments_examined=count,
                input_private_assignments_with_max_rank_two=private,
                assignments_supporting_hidden_AND_zero_label=0)


def correlated_classifier_screen(n, t, modulus):
    """Correlated Vandermonde labels; every t+1 columns are independent."""
    columns = [tuple(pow(i,j,modulus) for j in range(t+1)) for i in range(n)]
    for subset in itertools.combinations(columns,t+1):
        assert rank(subset,modulus) == t+1
    views = list(itertools.combinations(columns,t))
    targets = [v for v in itertools.product(range(modulus),repeat=t+1)
               if next((x for x in v if x),None) == 1]
    masks = []
    inventory_counts, other_counts = [], []
    for target in targets:
        mask = sum(1 << i for i,view in enumerate(views) if rank(view+(target,),modulus) == t)
        count = bin(mask).count('1')
        if target in columns:
            inventory_counts.append(count)
            assert count == math.comb(n-1,t-1)
        else:
            other_counts.append(count)
            assert count <= math.comb(n,t-1)//2
        masks.append(mask)
    complete = (1 << len(views))-1
    covering = sum((a | b) == complete and (a & b) == 0
                   for i,a in enumerate(masks) for b in masks[i+1:])
    assert covering == 0
    return dict(n=n,t=t,modulus=modulus,hidden_dimension=t+1,
        target_projective_lines=len(targets),subset_count=len(views),
        maximum_inventory_target_coverage=max(inventory_counts),
        maximum_other_target_coverage=max(other_counts),
        other_target_coverage_bound=math.comb(n,t-1)//2,
        two_hidden_output_labels_covering_all_subsets=covering)


def constructive_missing_subsets():
    """Check the proof's explicit bad subset after t+1 basis selections."""
    cases = 0
    for t in range(1,7):
        for independent_extra in (False,True):
            width = t+2 if independent_extra else t+1
            basis = [tuple(int(i == j) for j in range(width)) for i in range(t+1)]
            extra = (tuple(int(j == t+1) for j in range(width)) if independent_extra
                     else tuple(scalar_fixture(f'shared-vector/extra/{t}/{i}') for i in range(width)))
            # Privacy of all t-subsets follows from these t+1-column checks.
            assert all(rank(subset)==t+1 for subset in itertools.combinations(basis+[extra],t+1))
            for partition in range(1,(1 << (t+1))-1):
                zero = tuple((i+2) if i<=t and partition & (1 << i) else 0 for i in range(width))
                one = tuple((i+3) if i<=t and not partition & (1 << i) else 0 for i in range(width))
                for omitted in range(t+1):
                    view = tuple(row for i,row in enumerate(basis) if i != omitted)
                    assert (rank(view+(zero,))==t) != (rank(view+(one,))==t)
                i = next(i for i,x in enumerate(zero) if x)
                j = next(j for j,x in enumerate(one) if x)
                failing = tuple(row for index,row in enumerate(basis) if index not in (i,j))+(extra,)
                assert rank(failing)==t
                assert rank(failing+(zero,))==rank(failing+(one,))==t+1
                cases += 1
    return cases


def current_publication_scope():
    current = json.loads((HERE/'round-major-message-benchmark.json').read_text())
    radix = math.comb(current['n'],current['t'])
    assert radix == current['radix']
    radix_v2 = (radix & -radix).bit_length()-1
    bound = (current['pools']-1)*radix_v2+(radix-1).bit_length()-1
    assert bound < 2048
    return dict(n=current['n'],t=current['t'],pools=current['pools'],radix=radix,
        radix_two_adic_valuation=radix_v2,
        maximum_single_pool_difference_two_adic_valuation=bound,
        message_bits=2048,single_pool_subset_change_always_changes_message=True,
        scope='A nonzero rank delta has magnitude below radix; delta*radix^i cannot vanish modulo2^2048. Multi-pool aliases still exist.')


class SharedVectorTests(unittest.TestCase):
    def test_all_nonconstant_binary_gates(self):
        for index, truth in enumerate(itertools.product((0,1),repeat=4)):
            if not truth_valid(truth):
                continue
            scalars, outputs, public = fixture(index,truth)
            for missing in range(4):
                opening = tuple((i,x) for i,x in enumerate(scalars) if i != missing)
                self.assertEqual(evaluate(public,truth,opening), (missing,truth[missing],outputs[truth[missing]]))

    def test_larger_complement_lookup_and_disclosure(self):
        for n in (3,5,6):
            # Deterministic nonconstant partitions; no message-dependent setup.
            truth = tuple(int(i % 3 == 0) for i in range(n))
            scalars, outputs, public = fixture(n,truth)
            for missing in range(n):
                opening = tuple((i,x) for i,x in enumerate(scalars) if i != missing)
                self.assertEqual(evaluate(public,truth,opening), (missing,truth[missing],outputs[truth[missing]]))
                # Missing x enters the opposite output with coefficient one.
                known_part = sum(x for i,x in opening if truth[i] == truth[missing]) % N
                self.assertEqual((outputs[1-truth[missing]]-known_part) % N, scalars[missing])

    def test_vector_wiring_and_full_alternative_exclusion(self):
        self.assertEqual(len(vector_report()),4)

    def test_changed_public_points_and_function_rejected(self):
        scalars, _, public = fixture(0)
        for key in ('points','outputs'):
            for i in range(len(public[key])):
                changed = copy.deepcopy(public)
                values = list(public[key])
                values[i] = add(values[i],G)
                changed[key] = tuple(values)
                self.assertFalse(public_check(changed,AND))
        for bad in (None, (1,1)):
            changed = dict(public,points=(bad,)+public['points'][1:])
            self.assertFalse(public_check(changed,AND))
        self.assertFalse(public_check(public,(0,1,1,1)))
        opening = tuple(enumerate(scalars[1:],start=1))
        with self.assertRaises(ValueError):
            evaluate(public,(0,1,1,1),opening)

    def test_malformed_openings_rejected(self):
        scalars, _, public = fixture(0)
        honest = tuple((i,scalars[i]) for i in (1,2,3))
        bad = (honest[:2], honest+((0,scalars[0]),), tuple(reversed(honest)),
               (honest[0],honest[0],honest[2]),
               ((0,scalars[1]),honest[1],honest[2]),
               ((1,0),honest[1],honest[2]), ((1,N),honest[1],honest[2]),
               ((True,scalars[1]),honest[1],honest[2]),
               ((4,scalars[0]),honest[1],honest[2]))
        for opening in bad:
            with self.assertRaises(ValueError):
                evaluate(public,AND,opening)

    def test_complete_support_family_boundary(self):
        rows = [support_screen(n,t) for n in range(2,8) for t in range(1,n)]
        self.assertEqual(len(rows),21)
        self.assertEqual(sum(row['valid_unordered_support_pairs'] for row in rows),120)

    def test_rank_two_worst_case_boundary(self):
        result = rank_two_coordinate_screen()
        self.assertEqual(result['assignments_examined'],50625)
        self.assertGreater(result['input_private_assignments_with_max_rank_two'],0)

    def test_correlated_labels_do_not_repair_full_subset_classification(self):
        for n,t,modulus in ((4,1,5),(5,2,5),(6,3,7)):
            self.assertEqual(correlated_classifier_screen(n,t,modulus)['two_hidden_output_labels_covering_all_subsets'],0)

    def test_constructive_extra_column_counterexamples(self):
        self.assertEqual(constructive_missing_subsets(),480)

    def test_subset_privacy_scope_matches_current_total_decoder(self):
        result = current_publication_scope()
        self.assertEqual((result['n'],result['t'],result['pools']),(54,5,95))
        self.assertEqual(result['maximum_single_pool_difference_two_adic_valuation'],115)


if __name__ == '__main__':
    result = unittest.main(exit=False).result
    if not result.wasSuccessful():
        raise SystemExit(1)
    paths = [Path(__file__), HERE/'vector_label_gate_probe.py', HERE/'nonce_relation_extraction.py',
             HERE.parent/'covenant-2026-09-17/legacy_same_signature_counterexample.py',
             HERE/'round-major-message-benchmark.json']
    report = dict(evidence='locally-reproduced', deployment='unclassified', scope=__doc__,
        tests_run=result.testsRun, failures=0,errors=0,
        nonconstant_binary_truth_tables=14, binary_gate_curve_evaluations=56,
        larger_lookup_instances=3, larger_lookup_curve_evaluations=14,
        public_point_mutations_rejected=6, malformed_point_encodings_rejected=2,
        malformed_opening_cases_rejected=9, intended_truth_table_checked=True,
        vector_wiring=vector_report(),
        support_screens=[support_screen(n,t) for n in range(2,8) for t in range(1,n)],
        rank_two_coordinate_screen=rank_two_coordinate_screen(),
        correlated_classifier_screens=[correlated_classifier_screen(*args)
                                       for args in ((4,1,5),(5,2,5),(6,3,7))],
        constructive_missing_subset_cases=constructive_missing_subsets(),
        current_publication_scope=current_publication_scope(),
        one_binary_gate=dict(secret_field_dimension=4, raw_public_point_slots=6,
            raw_public_point_payload_bytes=198, scalars_per_input_vector=2,
            distinct_selected_scalar_openings=3, selected_scalar_payload_bytes=96,
            public_output_sum_checks=2),
        direct_2048_bit_legacy_interface=dict(gates=1024,scalar_openings=3072,
            guarded_signature_push_floor_vbytes=3072*59,
            previous_independent_row_gate_floor_vbytes=4096*59,
            scope='One layer of independent binary gates; direct scalar-linear recovery from guarded legacy scalar openings. All other costs free. No native wrapper supplied.'),
        five_of_54_linear_classifier=dict(n=54,t=5,nonconstant_hidden_binary_output_possible=False,
            subsets=math.comb(54,5),maximum_inventory_target_coverage=math.comb(53,4),
            other_target_coverage_bound=math.comb(54,4)//2,
            evidence='inspected',scope='All five-subsets of scalar-linear labels, including correlations; every six candidate forms independent as required by full subset-label privacy. Fixed hidden output labels and scalar-linear recovery; nonlinear decoding excluded.'),
        bitcoin_execution=False,native_scalar_binding_implemented=False,
        complete_verifier_implemented=False,script_bytes=None,witness_bytes=None,
        hint_items=None,entry_items=None,combined_stack_peak=None,executed_opcodes=None,
        validation_budget=None,setup_benchmark=None,onchain_vbytes=None,
        source_sha256={str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in paths})
    (HERE/'shared-vector-gate.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({key:report[key] for key in ('tests_run','binary_gate_curve_evaluations',
        'larger_lookup_curve_evaluations','rank_two_coordinate_screen','one_binary_gate',
        'direct_2048_bit_legacy_interface')},indent=2))
