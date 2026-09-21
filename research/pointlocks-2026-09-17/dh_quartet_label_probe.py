#!/usr/bin/env python3
"""One of four scalar openings selects two implicit DH point labels.

Host-only interface experiment. The labels are secret group elements, not
their discrete logs and not publicly checked garbling ciphertexts. Independent
and publicly correlated input profiles are separate. No Bitcoin wrapper.
"""
import copy
import hashlib
import itertools
import json
from functools import lru_cache
from pathlib import Path
import unittest

from vector_label_gate_probe import G, N, add, mul, scalar_fixture, valid_point

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EDGES = (((0,1),(2,3)), ((0,2),(1,3)))
FORMS = ((1,0),(0,1),(1,1),(1,-1))


def bits(index):
    return (index//2,index % 2)


def dot(a,b):
    return sum(x*y for x,y in zip(a,b)) % N


@lru_cache(None)
def sqrt_minus_one():
    nonresidue = 2
    while pow(nonresidue,(N-1)//2,N) != N-1:
        nonresidue += 1
    root = pow(nonresidue,(N-1)//4,N)
    assert root*root % N == N-1
    # This fact excludes the other nontrivial pairwise equality polynomial.
    assert pow(5,(N-1)//2,N) == N-1
    return root


def public_input_check(public, expected_profile):
    """Checks input points and declared affine relations, not a garbled circuit."""
    if (not isinstance(public,dict) or set(public) != {'profile','points'}
            or expected_profile not in ('independent','correlated')
            or public['profile'] != expected_profile):
        return False
    points = public['points']
    if (not isinstance(points,tuple) or len(points) != 4
            or not all(valid_point(p) for p in points) or len(set(points)) != 4):
        return False
    if expected_profile == 'correlated':
        a,b = points[:2]
        imaginary_b = mul(sqrt_minus_one(),b)
        return (points[2] == add(a,b) and points[3] == add(a,mul(N-1,b))
                and a not in (imaginary_b,mul(N-1,imaginary_b)))
    return True


def fixture(profile, index):
    width = 4 if profile == 'independent' else 2
    for attempt in range(100):
        secret = tuple(scalar_fixture(f'dh-quartet/{profile}/{index}/{attempt}/{i}') for i in range(width))
        inputs = secret if profile == 'independent' else tuple(dot(f,secret) for f in FORMS)
        public = dict(profile=profile,points=tuple(mul(x) for x in inputs))
        if public_input_check(public,profile):
            # Expected labels are private test-oracle state, not public setup.
            labels = tuple(tuple(mul(inputs[i]*inputs[j] % N) for i,j in row) for row in EDGES)
            return inputs,public,labels
    raise RuntimeError('fixture generation exhausted')


def evaluate(public, expected_profile, opening):
    if not public_input_check(public,expected_profile):
        raise ValueError('invalid input setup or wrong profile')
    if (not isinstance(opening,tuple) or len(opening) != 2
            or type(opening[0]) is not int or not 0 <= opening[0] < 4
            or type(opening[1]) is not int or not 0 < opening[1] < N):
        raise ValueError('expected canonical (index, scalar) opening')
    index,scalar = opening
    if mul(scalar) != public['points'][index]:
        raise ValueError('opening does not match its prebound input point')
    label_points = []
    for row,bit in enumerate(bits(index)):
        edge = EDGES[row][bit]
        other = next(i for i in edge if i != index)
        label_points.append(mul(scalar,public['points'][other]))
    return bits(index),tuple(label_points)


def independent_embedding(index, bit, challenge_a, challenge_b):
    """Simulate the selected view without the two challenge scalar logs."""
    edge = EDGES[bit][1-bits(index)[bit]]
    assert index not in edge
    scalars = [scalar_fixture(f'dh-quartet/cdh/{index}/{bit}/{i}') for i in range(4)]
    points = [mul(x) for x in scalars]
    points[edge[0]],points[edge[1]] = challenge_a,challenge_b
    public = dict(profile='independent',points=tuple(points))
    opening = (index,scalars[index])
    selected = evaluate(public,'independent',opening)
    # The requested opposite point is exactly CDH(challenge_a,challenge_b).
    return public,opening,selected,edge


def correlated_embedding(index, bit, challenge):
    """Embed square-CDH with a known linear opening and public affine points."""
    form = FORMS[index]
    direction = (form[1] % N,-form[0] % N)
    origin = tuple(scalar_fixture(f'dh-quartet/square/{index}/{bit}/{j}') for j in range(2))
    base_points = tuple(add(mul(u),mul(h,challenge)) for u,h in zip(origin,direction))
    points = tuple(add(mul(f[0] % N,base_points[0]),mul(f[1] % N,base_points[1])) for f in FORMS)
    public = dict(profile='correlated',points=points)
    opening = (index,dot(form,origin))
    selected = evaluate(public,'correlated',opening)
    i,j = EDGES[bit][1-bits(index)[bit]]
    ui,uj = dot(FORMS[i],origin),dot(FORMS[j],origin)
    hi,hj = dot(FORMS[i],direction),dot(FORMS[j],direction)
    quadratic = hi*hj % N
    assert quadratic
    known_point = add(mul(ui*uj % N),mul((ui*hj+uj*hi) % N,challenge))
    return dict(public=public,opening=opening,selected=selected,
                known_point=known_point,quadratic=quadratic,
                origin=origin,direction=direction,opposite_edge=(i,j))


def extract_square(embedding, opposite_point):
    if not valid_point(opposite_point):
        raise ValueError('expected a finite point label')
    difference = add(opposite_point,mul(N-1,embedding['known_point']))
    return mul(pow(embedding['quadratic'],-1,N),difference)


@lru_cache(None)
def curve_reductions():
    cdh_cases = square_cases = 0
    quadratic_coefficients = []
    for index,bit in itertools.product(range(4),range(2)):
        a,b = (scalar_fixture(f'dh-quartet/challenge/{index}/{bit}/{j}') for j in range(2))
        public,opening,selected,edge = independent_embedding(index,bit,mul(a),mul(b))
        assert opening[0] not in edge
        assert selected[0] == bits(index)
        # Test oracle supplies the opposite label; it is exactly the CDH answer.
        oracle = mul(a*b % N)
        assert oracle == mul(a,public['points'][edge[1]])
        cdh_cases += 1
        embedded = correlated_embedding(index,bit,mul(a))
        secret = tuple((u+h*a) % N for u,h in zip(embedded['origin'],embedded['direction']))
        values = tuple(dot(f,secret) for f in FORMS)
        i,j = embedded['opposite_edge']
        opposite = mul(values[i]*values[j] % N)
        assert extract_square(embedded,opposite) == mul(a*a % N)
        assert extract_square(embedded,add(opposite,G)) != mul(a*a % N)
        quadratic_coefficients.append(embedded['quadratic'] if embedded['quadratic'] < N//2
                                      else embedded['quadratic']-N)
        square_cases += 1
    # Standard algebraic conversion, with three square-CDH oracle answers.
    u,v = (scalar_fixture('dh-quartet/polarize/'+str(j)) for j in range(2))
    cross = add(mul((u+v)**2 % N),mul(-(u*u+v*v) % N))
    assert mul(pow(2,-1,N),cross) == mul(u*v % N)
    return dict(cdh_embeddings=cdh_cases,square_cdh_embeddings=square_cases,
                square_extraction_coefficients=quadratic_coefficients,
                changed_opposite_points_change_extraction=square_cases,
                square_to_cdh_polarization_checks=1)


def graph_cover_classes(n,t):
    """All DH-edge-vector access masks for independent input scalars."""
    pairs = list(itertools.combinations(range(n),2))
    choices = list(itertools.combinations(range(n),t))
    masks = {}
    for edge_set in range(1,1 << len(pairs)):
        edges = [pair for j,pair in enumerate(pairs) if edge_set & (1 << j)]
        mask = sum(1 << k for k,selected in enumerate(choices)
                   if all(any(i in selected for i in pair) for pair in edges))
        masks.setdefault(mask,edge_set)
    full = (1 << len(choices))-1
    # Output label vectors can have arbitrary nonempty DH-edge supports.
    complements = sorted((a,full^a) for a in masks if 0 < a < (full^a) < full and (full^a) in masks)
    return dict(n=n,t=t,missing=n-t,choices=len(choices),
                nonempty_edge_vectors=(1 << len(pairs))-1,distinct_access_masks=len(masks),
                complementary_nonconstant_access_pairs=len(complements))


def missing_triple_example(n,left_size):
    left = tuple(itertools.combinations(range(left_size),2))
    right = tuple(itertools.combinations(range(left_size,n),2))
    assert left and right
    count = 0
    for missing in itertools.combinations(range(n),3):
        available = tuple(not any(set(edge).issubset(missing) for edge in side) for side in (left,right))
        assert sum(available) == 1
        count += 1
    return dict(n=n,t=n-3,left_vertices=left_size,right_vertices=n-left_size,
                left_label_point_items=len(left),right_label_point_items=len(right),
                selections_checked=count)


def retained_secret_collision():
    """A nonlinear product relation passes point-shape checks but aliases labels."""
    a,b,c = (scalar_fixture('dh-quartet/product-collision/'+str(j)) for j in range(3))
    d = a*b*pow(c,-1,N) % N
    inputs = (a,b,c,d)
    public = dict(profile='independent',points=tuple(mul(x) for x in inputs))
    assert public_input_check(public,'independent')
    first = evaluate(public,'independent',(0,a))
    alternative = evaluate(public,'independent',(2,c))
    assert first[0] == (0,0) and alternative[0] == (1,0)
    assert first[1] == alternative[1]
    assert a != c and a*b % N == c*d % N
    return dict(point_input_check_passes=True,all_input_points_distinct=True,
                original_message=list(first[0]),alternative_message=list(alternative[0]),
                complete_point_label_vectors_identical=True,
                public_relation='x0*x1 = x2*x3 mod n',
                extra_scalar_opening_used_to_reuse_original_vector=False,
                scope='Host-only chosen-input setup. No native Bitcoin setup/opening is supplied.')


def correlated_collisions_rejected():
    b = scalar_fixture('dh-quartet/correlated-collision')
    cases = 0
    for ratio in (sqrt_minus_one(),-sqrt_minus_one() % N):
        a = ratio*b % N
        inputs = (a,b,(a+b) % N,(a-b) % N)
        points = tuple(mul(x) for x in inputs)
        assert all(valid_point(p) for p in points) and len(set(points)) == 4
        assert points[2] == add(points[0],points[1])
        assert points[3] == add(points[0],mul(N-1,points[1]))
        # The old relation-only check would pass, but bit one's labels coincide.
        assert mul(inputs[0]*inputs[2] % N) == mul(inputs[1]*inputs[3] % N)
        assert not public_input_check(dict(profile='correlated',points=points),'correlated')
        cases += 1
    return dict(cases=cases,all_rejected=True,
                public_check='A != sqrt(-1)*B and A != -sqrt(-1)*B',
                five_is_quadratic_nonresidue=True,
                guarantee='Four implicit DH point labels are pairwise distinct in every accepted correlated setup. Does not certify entropy, exclude every efficiently known relation, or verify downstream garbling.')


class DhQuartetTests(unittest.TestCase):
    def test_every_message_in_both_profiles(self):
        for profile in ('independent','correlated'):
            for seed in range(4):
                inputs,public,labels = fixture(profile,seed)
                for index in range(4):
                    decoded,points = evaluate(public,profile,(index,inputs[index]))
                    self.assertEqual(decoded,bits(index))
                    self.assertEqual(points,tuple(labels[j][bit] for j,bit in enumerate(decoded)))

    def test_wrong_relation_profile_and_points_rejected(self):
        _,public,_ = fixture('correlated',0)
        for i in range(4):
            changed = copy.deepcopy(public)
            points = list(changed['points'])
            points[i] = add(points[i],G)
            changed['points'] = tuple(points)
            self.assertFalse(public_input_check(changed,'correlated'))
        self.assertFalse(public_input_check(public,'independent'))
        for point in (None,(1,1),public['points'][1]):
            changed = dict(public,points=(point,)+public['points'][1:])
            self.assertFalse(public_input_check(changed,'correlated'))

    def test_invalid_openings_rejected(self):
        inputs,public,_ = fixture('independent',0)
        for opening in ((-1,inputs[0]),(4,inputs[0]),(True,inputs[0]),(0,0),
                        (0,N),(0,True),(0,inputs[1]),(0,),[0,inputs[0]]):
            with self.assertRaises(ValueError):
                evaluate(public,'independent',opening)

    def test_no_opposite_output_is_an_edge_incident_to_opened_vertex(self):
        for index,bit in itertools.product(range(4),range(2)):
            self.assertIn(index,EDGES[bit][bits(index)[bit]])
            self.assertNotIn(index,EDGES[bit][1-bits(index)[bit]])

    def test_exact_cdh_and_square_cdh_embeddings(self):
        result = curve_reductions()
        self.assertEqual((result['cdh_embeddings'],result['square_cdh_embeddings']),(8,8))

    def test_full_alternative_codeword_requires_an_opposite_component(self):
        cases = 0
        for index,other in itertools.permutations(range(4),2):
            differing = [j for j in range(2) if bits(index)[j] != bits(other)[j]]
            self.assertTrue(differing)
            self.assertTrue(all(index not in EDGES[j][bits(other)[j]] for j in differing))
            cases += 1
        self.assertEqual(cases,12)

    def test_missing_triples_have_a_positive_vector_interface(self):
        for n,left in ((4,2),(5,2),(6,3),(7,3)):
            self.assertGreater(missing_triple_example(n,left)['selections_checked'],0)

    def test_four_missing_independent_coordinates_block_two_dh_vectors(self):
        for n,t in ((4,0),(5,1),(6,2)):
            result = graph_cover_classes(n,t)
            self.assertEqual(result['complementary_nonconstant_access_pairs'],0)

    def test_vector_graph_screen_reaches_three_missing_boundary(self):
        for n,t in ((4,1),(5,2),(6,3)):
            self.assertGreater(graph_cover_classes(n,t)['complementary_nonconstant_access_pairs'],0)

    def test_public_input_check_is_not_ciphertext_or_hash_binding(self):
        inputs,public,labels = fixture('independent',0)
        # Arbitrary downstream commitments are deliberately absent from the
        # public-input-check API. Their validity cannot be inferred from it.
        honest = repr(labels[0][0]).encode()
        false = repr(add(labels[0][0],G)).encode()
        self.assertNotEqual(hashlib.sha256(honest).digest(),hashlib.sha256(false).digest())
        self.assertTrue(public_input_check(public,'independent'))
        selected = evaluate(public,'independent',(0,inputs[0]))[1][0]
        self.assertEqual(selected,labels[0][0])
        self.assertNotEqual(hashlib.sha256(repr(selected).encode()).digest(),hashlib.sha256(false).digest())

    def test_retained_secret_product_relation_aliases_two_messages(self):
        result = retained_secret_collision()
        self.assertTrue(result['complete_point_label_vectors_identical'])
        self.assertFalse(result['extra_scalar_opening_used_to_reuse_original_vector'])

    def test_correlated_output_equalities_are_publicly_rejected(self):
        self.assertEqual(correlated_collisions_rejected()['cases'],2)
        for seed in range(4):
            _,public,labels = fixture('correlated',seed)
            self.assertTrue(public_input_check(public,'correlated'))
            self.assertEqual(len(set(p for row in labels for p in row)),4)


if __name__ == '__main__':
    result = unittest.main(exit=False).result
    if not result.wasSuccessful():
        raise SystemExit(1)
    paths = [Path(__file__),HERE/'vector_label_gate_probe.py',HERE/'nonce_relation_extraction.py',
             HERE.parent/'covenant-2026-09-17/legacy_same_signature_counterexample.py']
    report = dict(evidence='locally-reproduced',deployment='unclassified',scope=__doc__,
        tests_run=result.testsRun,failures=0,errors=0,
        honest_fixtures=8,message_evaluations=32,message_bits_per_scalar=2,
        opened_scalar_items=1,opened_scalar_payload_bytes=32,output_point_items=2,
        public_input_point_slots=4,correlated_independent_setup_scalars=2,
        labels_are_points_not_their_discrete_logs=True,
        curve_reductions=curve_reductions(),
        retained_secret_collision=retained_secret_collision(),
        correlated_output_equalities=correlated_collisions_rejected(),
        full_alternative_codeword_checks=12,
        graph_access_screens=[graph_cover_classes(n,t) for n,t in ((4,0),(4,1),(5,1),(5,2),(6,2),(6,3))],
        missing_triple_examples=[missing_triple_example(n,k) for n,k in ((4,2),(5,2),(6,3),(7,3))],
        public_ciphertext_binding=False,malicious_setup_label_separation_established=False,
        complete_verifier_implemented=False,
        native_wrapper_implemented=False,bitcoin_execution=False,
        independent_2048_bit_quartet_interface=dict(quartets=1024,scalar_openings=1024,
            guarded_legacy_signature_push_floor_vbytes=1024*59,
            scope='Opening-count comparison only. Excludes scripts, keys, selectors, outputs, inputs, authorization, framing and verifier binding; not a transaction size.'),
        script_bytes=None,witness_bytes=None,hint_items=None,entry_items=None,
        combined_stack_peak=None,executed_opcodes=None,validation_budget=None,
        setup_benchmark=None,onchain_vbytes=None,
        source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    (HERE/'dh-quartet-label.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('tests_run','message_evaluations','curve_reductions',
                    'graph_access_screens','independent_2048_bit_quartet_interface')},indent=2))
