#!/usr/bin/env python3
"""Exact ratio-label recovery from linear openings; host-only research.

Affine forms have their constant coefficient first. The modulus must be an
odd prime. Public metadata is limited to known affine combinations of the
committed hidden scalars. No Bitcoin execution or setup benchmark is claimed.
"""
import hashlib
import itertools
import json
import math
from collections import Counter
from functools import lru_cache
from pathlib import Path
import unittest

from vector_label_gate_probe import G, N, add, mul, rref, scalar_fixture, valid_point

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def dot(a, b, modulus=N):
    if len(a) != len(b):
        raise ValueError('dimension mismatch')
    return sum(x*y for x, y in zip(a, b)) % modulus


def value(form, x, modulus=N):
    return (form[0] + dot(form[1:], x, modulus)) % modulus


def fiber(rows, observed, width, modulus=N):
    """A particular solution and a basis of ker(rows), or reject inconsistency."""
    if modulus <= 2 or modulus % 2 == 0:
        raise ValueError('this probe requires an odd prime field')
    if (len(rows) != len(observed) or width < 1
            or any(len(row) != width for row in rows)):
        raise ValueError('dimension mismatch')
    reduced, pivots = rref([tuple(row)+(y,) for row,y in zip(rows,observed)], modulus)
    if width in pivots:
        raise ValueError('inconsistent scalar openings')
    origin = [0]*width
    for row,pivot in zip(reduced,pivots):
        origin[pivot] = row[-1]
    kernel = []
    for free in range(width):
        if free in pivots:
            continue
        direction = [int(i == free) for i in range(width)]
        for row,pivot in zip(reduced,pivots):
            direction[pivot] = -row[free] % modulus
        kernel.append(tuple(direction))
    return tuple(origin), tuple(kernel)


def restriction(form, origin, kernel, modulus=N):
    return (value(form,origin,modulus),) + tuple(dot(form[1:],h,modulus) for h in kernel)


def classify_restrictions(a, b, modulus=N):
    """Classify a/b on an affine fiber, restricted to nonzero denominators."""
    if len(a) != len(b) or not a:
        raise ValueError('dimension mismatch')
    if not any(b):
        return dict(kind='invalid_base', scalar=None)
    if not any(a[1:]) and not any(b[1:]):
        return dict(kind='reconstructible', scalar=a[0]*pow(b[0],-1,modulus) % modulus)
    # A constant on a nontrivial fiber can be read from public residual
    # coefficient vectors. The point equation checks it without an opening.
    index = next(i for i,x in enumerate(b) if x)
    scalar = a[index]*pow(b[index],-1,modulus) % modulus
    if all((x-scalar*y) % modulus == 0 for x,y in zip(a,b)):
        return dict(kind='public_constant', scalar=scalar)
    return dict(kind='underdetermined', scalar=None)


def classify(rows, observed, numerator, denominator, modulus=N):
    if len(numerator) != len(denominator):
        raise ValueError('dimension mismatch')
    origin,kernel = fiber(rows,observed,len(numerator)-1,modulus)
    return classify_restrictions(restriction(numerator,origin,kernel,modulus),
                                restriction(denominator,origin,kernel,modulus),modulus)


def point_form(form, points):
    if len(form) != len(points)+1:
        raise ValueError('dimension mismatch')
    result = mul(form[0] % N)
    for coefficient,point in zip(form[1:],points):
        result = add(result,mul(coefficient % N,point))
    return result


def check_ratio(base, target, scalar):
    return (valid_point(base) and (target is None or valid_point(target))
            and type(scalar) is int and 0 <= scalar < N
            and mul(scalar,base) == target)


def embed_challenge(rows, numerator, denominator, origin, direction, challenge):
    """Build every point and opening without knowing log_G(challenge)."""
    if not valid_point(challenge) or not any(direction):
        raise ValueError('need a finite challenge and nonzero direction')
    if any(dot(row,direction) for row in rows):
        raise ValueError('challenge would enter the disclosed openings')
    a0,b0 = value(numerator,origin),value(denominator,origin)
    alpha,beta = dot(numerator[1:],direction),dot(denominator[1:],direction)
    if (alpha*b0-beta*a0) % N == 0:
        raise ValueError('ratio is constant along the challenge direction')
    points = tuple(add(mul(u),mul(h,challenge)) for u,h in zip(origin,direction))
    return dict(points=points, opened=tuple(dot(row,origin) for row in rows),
                target=point_form(numerator,points), base=point_form(denominator,points),
                a0=a0,b0=b0,alpha=alpha,beta=beta)


def extract_challenge(embedded, scalar):
    if not check_ratio(embedded['base'],embedded['target'],scalar):
        raise ValueError('incorrect ratio label or zero base')
    divisor = (scalar*embedded['beta']-embedded['alpha']) % N
    if not divisor:
        raise ValueError('degenerate extraction')
    return (embedded['a0']-scalar*embedded['b0'])*pow(divisor,-1,N) % N


@lru_cache(None)
def exhaustive_screen(modulus):
    """Independent exhaustive fiber evaluation, including affine offsets."""
    width = 2
    forms = list(itertools.product(range(modulus),repeat=width+1))
    matrices = ((), ((1,0),), ((1,1),), ((1,0),(0,1)), ((1,1),(2,2)))
    counts = Counter()
    comparisons = 0
    for rows in matrices:
        groups = {}
        for x in itertools.product(range(modulus),repeat=width):
            y = tuple(dot(row,x,modulus) for row in rows)
            groups.setdefault(y,[]).append(x)
        for y,points in groups.items():
            origin,kernel = fiber(rows,y,width,modulus)
            restricted = [restriction(f,origin,kernel,modulus) for f in forms]
            evaluated = [[value(f,x,modulus) for x in points] for f in forms]
            for i,a in enumerate(restricted):
                for j,b in enumerate(restricted):
                    result = classify_restrictions(a,b,modulus)
                    ratios = {av*pow(bv,-1,modulus) % modulus
                              for av,bv in zip(evaluated[i],evaluated[j]) if bv}
                    if result['kind'] == 'invalid_base':
                        assert not ratios
                    elif result['kind'] in ('reconstructible','public_constant'):
                        assert ratios == {result['scalar']}
                    else:
                        assert len(ratios) >= 2
                    counts[result['kind']] += 1
                    comparisons += 1
    return dict(modulus=modulus,hidden_dimension=width,affine_forms=len(forms),
                disclosure_matrices=len(matrices),comparisons=comparisons,
                classification_counts=dict(sorted(counts.items())))


@lru_cache(None)
def curve_reductions():
    # Both-variable, fixed-denominator, and correlated-opening cases.
    profiles = (
        (((1,0,0),), (2,0,1,1), (3,1,2,-1), (0,1,0)),
        (((1,0,0),), (4,1,3,-2), (5,1,0,0), (0,1,0)),
        (((1,-1,0),(0,0,1)), (0,1,0,0), (0,0,1,0), (1,1,0)),
    )
    count = 0
    for profile,(rows,a,b,h) in enumerate(profiles):
        for index in range(4):
            # Only this test oracle uses x. The embedding accepts X=xG only.
            x = scalar_fixture(f'ratio/challenge/{profile}/{index}')
            origin = tuple(scalar_fixture(f'ratio/origin/{profile}/{index}/{j}') for j in range(3))
            embedded = embed_challenge(rows,a,b,origin,h,mul(x))
            secret = tuple((u+x*v) % N for u,v in zip(origin,h))
            assert embedded['points'] == tuple(mul(v) for v in secret)
            assert all(point_form((0,)+row,embedded['points']) == mul(opened)
                       for row,opened in zip(rows,embedded['opened']))
            scalar = value(a,secret)*pow(value(b,secret),-1,N) % N
            assert extract_challenge(embedded,scalar) == x
            try:
                extract_challenge(embedded,(scalar+1) % N)
            except ValueError:
                pass
            else:
                raise AssertionError('changed scalar was accepted')
            assert classify(rows,embedded['opened'],a,b)['kind'] == 'underdetermined'
            count += 1
    return dict(curve='secp256k1',profiles=len(profiles),instances=count,
                challenge_logs_recovered=count,changed_labels_rejected=count,
                unknown_challenge_scalar_used_by_embedding=False)


class RatioLabelTests(unittest.TestCase):
    def test_exhaustive_affine_fibers(self):
        for modulus in (3,5):
            result = exhaustive_screen(modulus)
            self.assertEqual(set(result['classification_counts']),
                             {'invalid_base','reconstructible','public_constant','underdetermined'})

    def test_reconstructible_nonconstant_ratio(self):
        self.assertEqual(classify(((1,0),(0,1)),(7,11),(3,2,1),(5,1,3)),
                         dict(kind='reconstructible',scalar=28*pow(45,-1,N) % N))

    def test_zero_difference_is_public_exception(self):
        a,b = (0,1,0),(0,0,1)
        self.assertEqual(classify(((1,-1),),(0,),a,b),dict(kind='public_constant',scalar=1))
        self.assertEqual(classify(((1,-1),),(7,),a,b)['kind'],'underdetermined')
        point = mul(scalar_fixture('ratio/equal-endpoints'))
        self.assertTrue(check_ratio(point,point,1))
        self.assertFalse(check_ratio(point,add(point,G),1))

    def test_affine_public_constant_without_scalar_openings(self):
        self.assertEqual(classify((),(),(6,4,2),(3,2,1)),
                         dict(kind='public_constant',scalar=2))

    def test_two_compatible_scalar_assignments_do_not_mean_same_points(self):
        first,second = (9,2),(10,3)
        self.assertEqual(first[0]-first[1],second[0]-second[1])
        self.assertNotEqual(first[0]*pow(first[1],-1,N) % N,
                            second[0]*pow(second[1],-1,N) % N)
        self.assertNotEqual(tuple(mul(x) for x in first),tuple(mul(x) for x in second))

    def test_inversion_and_multiplication_chain_do_not_hide_public_endpoints(self):
        x,y,z = (scalar_fixture('ratio/chain/'+str(i)) for i in range(3))
        xy,yz = y*pow(x,-1,N) % N,z*pow(y,-1,N) % N
        self.assertTrue(check_ratio(mul(x),mul(y),xy))
        self.assertTrue(check_ratio(mul(y),mul(x),pow(xy,-1,N)))
        self.assertTrue(check_ratio(mul(x),mul(z),xy*yz % N))

    def test_zero_base_and_malformed_inputs(self):
        self.assertEqual(classify(((0,1),),(0,),(0,1,0),(0,0,1))['kind'],'invalid_base')
        for base,target,label in ((None,G,1),(G,(1,1),1),(G,G,True),(G,G,N)):
            self.assertFalse(check_ratio(base,target,label))
        for rows,y,width,p in ((((1,0),(1,0)),(1,2),2,N),
                               (((1,),),(1,),2,N), ((),(),2,2)):
            with self.assertRaises(ValueError):
                fiber(rows,y,width,p)

    def test_nonconstant_ratio_recovers_embedded_discrete_log(self):
        self.assertEqual(curve_reductions()['instances'],12)

    def test_degenerate_embedding_is_rejected(self):
        for rows,a,b,u,h in (
                (((1,0),),(0,1,0),(0,0,1),(3,5),(1,0)),
                ((),(0,1,0),(0,0,1),(3,3),(1,1))):
            with self.assertRaises(ValueError):
                embed_challenge(rows,a,b,u,h,G)


if __name__ == '__main__':
    result = unittest.main(exit=False).result
    if not result.wasSuccessful():
        raise SystemExit(1)
    paths = [Path(__file__),HERE/'vector_label_gate_probe.py',HERE/'nonce_relation_extraction.py',
             HERE.parent/'covenant-2026-09-17/legacy_same_signature_counterexample.py']
    report = dict(evidence='locally-reproduced',deployment='unclassified',scope=__doc__,
        tests_run=result.testsRun,failures=0,errors=0,
        exhaustive_screens=[exhaustive_screen(p) for p in (3,5)],
        curve_reduction=curve_reductions(),
        public_constant_exception=dict(numerator='x',denominator='y',opening='x-y=0',
            scalar=1,public_check='X == Y',requires_opening_for_public_check=False),
        five_of_54_independent_coordinate_ratio=dict(n=54,t=5,
            all_subsets=math.comb(54,5),subsets_containing_both_coordinates=math.comb(52,3),
            required_scalar_forms=2),
        no_general_nonlinear_impossibility_claim=True,
        bitcoin_execution=False,complete_verifier_implemented=False,
        script_bytes=None,witness_bytes=None,hint_items=None,entry_items=None,
        combined_stack_peak=None,executed_opcodes=None,validation_budget=None,
        setup_benchmark=None,onchain_vbytes=None,
        source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    (HERE/'ratio-label.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('tests_run','exhaustive_screens','curve_reduction')},indent=2))
