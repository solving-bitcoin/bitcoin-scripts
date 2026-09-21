#!/usr/bin/env python3
"""Fixed-orbit key-sharing algebra and restricted legacy size lower bounds.

Actual r0=2 roots test ECDSA/commitment fixtures. Separate known-ratio bases
test the sharing implication only; they are NOT ECDSA recovery root sets.
No Script, native transaction, setup benchmark, or general impossibility claim.
"""
from decimal import Decimal, localcontext, ROUND_CEILING
from collections import Counter
import hashlib
import json
from pathlib import Path
import unittest

from core_check import unpack_signature
from anchored_extraction import der
from four_root_orbit_probe import roots
from nonce_relation_extraction import LAMBDA
from publication_core_check import encode_key
from legacy_same_signature_counterexample import N, P, add, mul, verify

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
C = 1 << 248


def canonical(s):
    s %= N
    assert s != 0
    return min(s,N-s)


def scalar_fixture(tag):
    return canonical(int.from_bytes(hashlib.sha256(tag.encode()).digest(),'big'))


def orbit(s, bases):
    result = set()
    for base in bases:
        point = mul(s,base)
        result.update((point,(point[0],-point[1] % P)))
    assert len(result) == 4
    return frozenset(result)


def recover_base_ratio(bases, s, t):
    """For two distinct valid canonical openings sharing a point, find rho.

    Their affine ECDSA-key transforms share iff these orbit points share.
    Every returned rho is checked against rho*R0=R1 using public operations.
    """
    assert 0 < s <= (N-1)//2 and 0 < t <= (N-1)//2
    if s == t or not orbit(s,bases).intersection(orbit(t,bases)):
        return None
    ratio = s*pow(t,-1,N) % N
    inverse = pow(ratio,-1,N)
    for value in (ratio,-ratio % N,inverse,-inverse % N):
        if mul(value,bases[0]) == bases[1]:
            return value
    raise AssertionError('shared distinct canonical orbits must expose the base ratio')


def propagate_openings(bases, commitments, disclosed, rho):
    """Walk neighboring orbit scalars with a now-known base ratio."""
    assert mul(rho,bases[0]) == bases[1]
    opened = dict(disclosed)
    reverse = {commitment:i for i,commitment in enumerate(commitments)}
    assert len(reverse) == len(commitments)
    for i,s in opened.items():
        assert orbit(s,bases) == commitments[i]
    todo = list(opened.values())
    while todo:
        s = todo.pop()
        for multiplier in (rho,pow(rho,-1,N)):
            candidate = canonical(s*multiplier)
            index = reverse.get(orbit(candidate,bases))
            if index is not None and index not in opened:
                opened[index] = candidate
                todo.append(candidate)
    return opened


def rate_bound(candidate_bytes, selected_bytes):
    """High-precision numerical solution of the analytic counting bound."""
    with localcontext() as ctx:
        ctx.prec = 90
        a,b = Decimal(candidate_bytes),Decimal(selected_bytes)
        lo,hi = Decimal('0.001'),Decimal(1000)
        logtwo = Decimal(2).ln()
        for _ in range(200):
            mid = (lo+hi)/2
            mass = (-a*logtwo/mid).exp()+(-(a+b)*logtwo/mid).exp()
            if mass < 1:
                lo = mid
            else:
                hi = mid
        # The printed integer is insensitive to the remaining bracket.
        low_int = int((2048*lo).to_integral_value(rounding=ROUND_CEILING))
        high_int = int((2048*hi).to_integral_value(rounding=ROUND_CEILING))
        assert low_int == high_int
        return dict(candidate_bytes=candidate_bytes,selected_extra_bytes=selected_bytes,
                    rate_lower=str(lo),rate_upper=str(hi),
                    lower_bound_2048_bits_vbytes=low_int)


class OrbitSharingTests(unittest.TestCase):
    def test_actual_root_orbits_and_signature_openings(self):
        basis4=roots(2)
        bases=(basis4[0],basis4[2])
        values=[scalar_fixture(f'orbit-sharing/actual/{i}') for i in range(8)]
        packets=[]
        for s in values:
            packet=orbit(s,bases)
            self.assertEqual(packet,orbit(N-s,bases))
            keys=[mul(pow(2,-1,N),add(point,mul(-C % N))) for point in packet]
            for response in (s,N-s):
                sigma=der(2,response)[:-1]+b'\x03'
                r,u,_=unpack_signature(sigma)
                for key in keys:
                    self.assertTrue(verify(C,r,u,key)[0])
            packets.append(packet)
        self.assertEqual(len(set.union(set(),*(set(p) for p in packets))),32)
        for i,s in enumerate(values):
            for t in values[i+1:]:
                self.assertIsNone(recover_base_ratio(bases,s,t))

    def test_shared_openings_recover_ratio_with_signs_and_orientation(self):
        # Only a group-algebra control: 7*R0 is not the second ECDSA r=2 root.
        root0=roots(2)[0]
        for rho in (7,N-7,pow(7,-1,N),-pow(7,-1,N) % N):
            bases=(root0,mul(rho,root0))
            s=scalar_fixture('orbit-sharing/known-ratio')
            t=canonical(s*rho)
            for left,right in ((s,t),(t,s)):
                with self.subTest(rho=rho,left=left):
                    self.assertEqual(recover_base_ratio(bases,left,right),rho)
            self.assertIsNone(recover_base_ratio(bases,s,s))

    def test_two_adjacent_openings_disclose_unselected_orbit_labels(self):
        root0=roots(2)[0]
        rho=7
        bases=(root0,mul(rho,root0))
        start=scalar_fixture('orbit-sharing/four-label-chain')
        values=[canonical(start*pow(rho,i,N)) for i in range(4)]
        packets=[orbit(s,bases) for s in values]
        for edge in ((0,1),(1,2),(2,3)):
            recovered=recover_base_ratio(bases,values[edge[0]],values[edge[1]])
            self.assertEqual(recovered,rho)
            opened=propagate_openings(bases,packets,{i:values[i] for i in edge},recovered)
            self.assertEqual(opened,dict(enumerate(values)))
            self.assertEqual(len(set(opened)-set(edge)),2)

    def test_three_key_relaxation_already_exceeds_goal(self):
        self.assertEqual(rate_bound(20,99)['lower_bound_2048_bits_vbytes'],112556)
        self.assertEqual(rate_bound(20,106)['lower_bound_2048_bits_vbytes'],116700)

    def test_two_owners_per_point_bound_can_be_tight_for_orbit_geometry(self):
        # This order-three base relation is again only a group-algebra control,
        # not the actual two r=2 ECDSA lifts. Three four-point packets use six
        # points and each point occurs twice, attaining the 2*t count.
        root0=roots(2)[0]
        bases=(root0,mul(LAMBDA,root0))
        s=scalar_fixture('orbit-sharing/tight-incidence-control')
        values=[canonical(s*pow(LAMBDA,i,N)) for i in range(3)]
        self.assertEqual(len(set(values)),3)
        packets=[orbit(t,bases) for t in values]
        self.assertEqual(len(set(packets)),3)
        owners=Counter(point for packet in packets for point in packet)
        self.assertEqual(len(owners),6)
        self.assertEqual(set(owners.values()),{2})


if __name__=='__main__':
    program=unittest.main(exit=False)
    if not program.result.wasSuccessful():
        raise SystemExit(1)
    rows=[]
    for keys,signature_bytes in ((4,0),(3,0),(3,40),(2,0),(2,40),(1,40)):
        row=rate_bound(20,33*keys+signature_bytes)
        row.update(supplied_keys=keys,signature_bytes=signature_bytes,
                   all_other_costs_granted_free=True)
        rows.append(row)
    shared_rows=[]
    for checks,signature_bytes in ((4,40),(3,40),(2,40),(4,13),(4,12)):
        row=rate_bound(20,33*checks/2+signature_bytes)
        row.update(checked_keys_per_label=checks,signature_bytes=signature_bytes,
                   maximum_label_owners_per_key=2,all_other_costs_granted_free=True,
                   fractional_key_count_relaxation=True)
        shared_rows.append(row)
    basis4=roots(2)
    paths=[Path(__file__),HERE/'four_root_orbit_probe.py',HERE/'four_recovery_key_probe.py',
           HERE/'core_check.py',HERE/'anchored_extraction.py',HERE/'publication_core_check.py',
           HERE/'nonce_relation_extraction.py',
           HERE.parent/'covenant-2026-09-17/legacy_same_signature_counterexample.py']
    report=dict(scope=__doc__,evidence='locally-reproduced',deployment='unclassified',
        tests_run=program.result.testsRun,actual_ecdsa_equations_checked=64,
        actual_root_scalar_fixtures=8,actual_root_fixture_shared_points=0,
        actual_roots=[encode_key(basis4[i]).hex() for i in (0,2)],
        synthetic_known_ratio_controls=8,synthetic_adjacent_pair_disclosure_cases=3,
        synthetic_unselected_labels_recovered_per_case=2,
        synthetic_bases_are_ecdsa_root_sets=False,actual_root_ratio_computed=False,
        representation_bounds=rows,ideal_key_sharing_bounds=shared_rows,
        embedded_all_keys_free_opening_lower_bound_vbytes=2048*2*33,
        native_execution=False,setup_benchmark=False,
        new_script_bytes=None,new_witness_bytes=None,new_hint_items=None,new_stack_peak=None,
        source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    (HERE/'orbit-key-sharing-probe.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(tests_run=program.result.testsRun,
        bounds=[{k:r[k] for k in ('supplied_keys','signature_bytes','lower_bound_2048_bits_vbytes')} for r in rows],
        shared_bounds=[{k:r[k] for k in ('checked_keys_per_label','signature_bytes','lower_bound_2048_bits_vbytes')} for r in shared_rows]),indent=2))
