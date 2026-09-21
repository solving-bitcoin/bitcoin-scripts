#!/usr/bin/env python3
"""Exact two-target anchor extraction and its prescribed-nonce opening boundary.

Digests in positive fixtures are chosen algebraically; they are NOT Bitcoin
sighashes or found hash preimages. No native transaction or setup benchmark.
"""
import hashlib
import json
from pathlib import Path
import sys
import unittest

from core_check import unpack_signature
from publication_core_check import encode_key
from legacy_same_signature_counterexample import N, P, G, add, mul, verify

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def integer(value):
    data = value.to_bytes((value.bit_length()+7)//8 or 1,'big')
    return b'\0'+data if data[0]&128 else data


def signature(r,s,flag=1):
    rb,sb=integer(r),integer(s)
    return b'\x30'+bytes([4+len(rb)+len(sb),2,len(rb)])+rb+bytes([2,len(sb)])+sb+bytes([flag])


def seeded_scalar(tag):
    return 1+int.from_bytes(hashlib.sha256(tag.encode()).digest(),'big')%(N-1)


def setup(seed):
    secrets,targets=[],[]
    for i in range(2):
        attempt=0
        while True:
            scalar=seeded_scalar(f'two-target-anchors-v1/{seed}/{i}/{attempt}')
            point=mul(scalar)
            attempt+=1
            if 1<<248 <= point[0] < 1<<255:
                secrets.append(scalar)
                targets.append(point)
                break
    anchors=[signature(point[0],1) for point in targets]
    a,b=[t*pow(point[0],-1,N)%N for t,point in zip(secrets,targets)]
    labels=[(a+b)%N,(a-b)%N]
    assert all(labels) and labels[0] not in (labels[1],-labels[1]%N)
    return dict(secrets=secrets,targets=targets,anchors=anchors,labels=labels)


def forced_r(z,aggregate,c):
    denominator=(aggregate-c*z)%N
    if not denominator:
        raise ValueError('zero dynamic key sum')
    return -2*z*pow(denominator,-1,N)%N


def inverse_digest(r,aggregate,c):
    denominator=(c*r-2)%N
    if not denominator:
        raise ValueError('excluded image point')
    return r*aggregate*pow(denominator,-1,N)%N


def public_setup(targets,anchors):
    if len(targets)!=2 or len(anchors)!=2 or len(set(targets))!=2:
        raise ValueError('two distinct anchor points required')
    weighted=[]
    c=0
    for target,tau in zip(targets,anchors):
        if (target is None or not 0<=target[0]<P or not 0<=target[1]<P
                or (target[1]*target[1]-target[0]**3-7)%P):
            raise ValueError('invalid anchor point')
        rt,st,flag=unpack_signature(tau)
        if not (rt==target[0] and rt>P-N and st==flag==1):
            raise ValueError('unsupported anchor')
        inverse=pow(rt,-1,N)
        c=(c+inverse)%N
        weighted.append(mul(inverse,target))
    labels=[add(weighted[0],weighted[1]),add(weighted[0],mul(N-1,weighted[1]))]
    if any(label is None for label in labels) or labels[0] in (labels[1],(labels[1][0],-labels[1][1]%P)):
        raise ValueError('degenerate canonical label points')
    return c,weighted,labels


def extract(targets,anchors,keys,z_anchor,z_open,sigma):
    """Only public transcript inputs; both anchor signs are determined publicly."""
    c,weighted,label_points=public_setup(targets,anchors)
    if len(keys)!=2 or keys[0] == keys[1] or any(k is None for k in keys):
        raise ValueError('distinct finite points required')
    if not 57 < len(sigma) <= 73 or not 0 <= z_anchor < N or not 0 <= z_open < N:
        raise ValueError('long signature and reduced digests required')
    signs=[]
    for target,tau,key in zip(targets,anchors,keys):
        rt,st,flag=unpack_signature(tau)
        if not verify(z_anchor,rt,st,key)[0]:
            raise ValueError('anchor verification failed')
        recovered=add(mul(z_anchor),mul(rt,key))
        if recovered == target:
            sign=1
        elif recovered == (target[0],-target[1]%P):
            sign=-1
        else:
            raise ValueError('anchor recovery mismatch')
        signs.append(sign)
    r,s,flag=unpack_signature(sigma)
    if not all(verify(z_open,r,s,key)[0] for key in keys):
        raise ValueError('common-signature verification failed')
    aggregate=(c*z_anchor-2*z_open*pow(r,-1,N))%N
    relative_sign=signs[0]*signs[1]
    label=0 if relative_sign==1 else 1
    point=label_points[label]
    secret=signs[0]*aggregate%N
    if point is None or mul(secret)!=point:
        raise ValueError('degenerate or inconsistent extracted target')
    return dict(label=label,scalar=secret,point=point,signs=signs,aggregate=aggregate,c=c,r=r,s=s)


def fixture(seed,signs,nonce_tag):
    state=setup(seed)
    rs=[point[0] for point in state['targets']]
    aggregate=sum(sign*t*pow(r,-1,N) for sign,t,r in zip(signs,state['secrets'],rs))%N
    c=sum(pow(r,-1,N) for r in rs)%N
    k=seeded_scalar(f'two-target-anchor-known-nonce/{nonce_tag}')
    nonce=mul(k)
    r=nonce[0]%N
    # Choose z from r. This reverses the native task and is explicitly synthetic.
    z=inverse_digest(r,aggregate,c)
    scalars=[(sign*t-z)*pow(rt,-1,N)%N for sign,t,rt in zip(signs,state['secrets'],rs)]
    keys=[mul(p) for p in scalars]
    assert keys[0]!=keys[1] and all(keys) and z and aggregate
    s=(z+r*scalars[0])*pow(k,-1,N)%N
    s=min(s,N-s)
    sigma=signature(r,s)
    assert len(sigma)>57 and forced_r(z,aggregate,c)==r
    result=extract(state['targets'],state['anchors'],keys,z,z,sigma)
    assert result['scalar']==state['labels'][result['label']]
    recovered_nonce=(z+r*scalars[0])*pow(s,-1,N)%N
    assert recovered_nonce in (k,N-k)
    assert mul(recovered_nonce)==mul(pow(s,-1,N),add(mul(z),mul(r,keys[0])))
    return state,keys,z,sigma,result,dict(
        seed=seed,anchor_signs=signs,nonce_tag=nonce_tag,
        target_points=[encode_key(v).hex() for v in state['targets']],
        anchors=[v.hex() for v in state['anchors']],
        dynamic_keys=[encode_key(v).hex() for v in keys],
        synthetic_digest=f'{z:064x}',signature=sigma.hex(),signature_bytes=len(sigma),
        canonical_label=result['label'],extracted_label_scalar=f'{result["scalar"]:064x}',
        label_point=encode_key(result['point']).hex(),
        recovered_nonce_scalar=f'{recovered_nonce:064x}',known_nonce_scalar=f'{k:064x}',
        exact_scalar_checks=True)


def different_digest_fixture(flag):
    assert flag != 1
    state=setup(21)
    signs=(1,-1)
    rs=[point[0] for point in state['targets']]
    c=sum(pow(r,-1,N) for r in rs)%N
    aggregate=state['labels'][1]
    z0=seeded_scalar('two-target-anchor-fixed-anchor-digest')
    k=seeded_scalar(f'two-target-anchor-different-digest-nonce/{flag}')
    r=mul(k)[0]%N
    z1=r*(c*z0-aggregate)*pow(2,-1,N)%N
    scalars=[(sign*t-z0)*pow(rt,-1,N)%N for sign,t,rt in zip(signs,state['secrets'],rs)]
    keys=[mul(p) for p in scalars]
    s=(z1+r*scalars[0])*pow(k,-1,N)%N
    sigma=signature(r,min(s,N-s),flag)
    result=extract(state['targets'],state['anchors'],keys,z0,z1,sigma)
    assert result['scalar']==aggregate and result['label']==1 and z0!=z1
    return dict(flag=flag,synthetic_anchor_digest=f'{z0:064x}',synthetic_opening_digest=f'{z1:064x}',
        signature=sigma.hex(),extracted_label_scalar=f'{result["scalar"]:064x}',
        exact_scalar_checks=True)


def zero_opening_fixture():
    state=setup(27)
    rs=[point[0] for point in state['targets']]
    c,_,_=public_setup(state['targets'],state['anchors'])
    aggregate=state['labels'][0]
    z0=aggregate*pow(c,-1,N)%N
    scalars=[(t-z0)*pow(rt,-1,N)%N for t,rt in zip(state['secrets'],rs)]
    assert (scalars[0]+scalars[1])%N==0
    keys=[mul(p) for p in scalars]
    k=seeded_scalar('two-target-anchor-zero-opening-nonce')
    r=mul(k)[0]%N
    s=r*scalars[0]*pow(k,-1,N)%N
    sigma=signature(r,min(s,N-s),2)
    result=extract(state['targets'],state['anchors'],keys,z0,0,sigma)
    assert result['scalar']==aggregate and result['label']==0
    return dict(synthetic_anchor_digest=f'{z0:064x}',synthetic_opening_digest='00'*32,
        signature=sigma.hex(),extracted_label_scalar=f'{result["scalar"]:064x}',exact_scalar_checks=True)


class Tests(unittest.TestCase):
    def test_public_extraction_all_anchor_signs(self):
        rows=[]
        for seed in range(3):
            for signs in ((1,1),(1,-1),(-1,1),(-1,-1)):
                for nonce in (0,1):
                    *_,row=fixture(seed,signs,nonce)
                    rows.append(row)
        self.assertEqual(len(rows),24)
        self.assertEqual({v['canonical_label'] for v in rows},{0,1})

    def test_other_flags_need_their_own_actual_digest(self):
        for flag in (0,2,3,128,129,255):
            different_digest_fixture(flag)

    def test_zero_opening_digest_still_extracts(self):
        zero_opening_fixture()

    def test_public_setup_rejects_zero_or_duplicate_labels(self):
        state=setup(31)
        c,_,labels=public_setup(state['targets'],state['anchors'])
        self.assertTrue(c)
        self.assertEqual(labels,[mul(t) for t in state['labels']])
        target=state['targets'][0]
        with self.assertRaises(ValueError):
            public_setup([target,(target[0],-target[1]%P)],[state['anchors'][0]]*2)
        with self.assertRaises(ValueError):
            public_setup([target,target],[state['anchors'][0]]*2)

    def test_signature_to_prescribed_nonce_equivalence(self):
        state,keys,z,sigma,result,_=fixture(7,(1,-1),8)
        r,s,_=unpack_signature(sigma)
        p=(state['secrets'][0]-z)*pow(state['targets'][0][0],-1,N)%N
        numerator=(z+r*p)%N
        self.assertNotEqual(numerator,0)
        k=numerator*pow(s,-1,N)%N
        self.assertEqual(mul(k)[0]%N,r)
        self.assertEqual(numerator*pow(k,-1,N)%N,s)
        self.assertEqual(forced_r(z,result['aggregate'],result['c']),r)

    def test_mobius_bijection_exhaustive_small_field(self):
        q=101
        for aggregate in (1,7,99):
            for c in (0,1,2,50,100):
                images={}
                for z in range(1,q):
                    denominator=(aggregate-c*z)%q
                    if not denominator: continue
                    r=-2*z*pow(denominator,-1,q)%q
                    self.assertNotIn(r,images)
                    self.assertEqual(r*aggregate*pow((c*r-2)%q,-1,q)%q,z)
                    images[r]=z
                excluded={0} if c==0 else {0,2*pow(c,-1,q)%q}
                self.assertEqual(set(images),set(range(q))-excluded)

    def test_zero_aggregate_is_public_constant_branch(self):
        for z in (1,17,N-1):
            self.assertEqual(forced_r(z,0,3),2*pow(3,-1,N)%N)
        with self.assertRaises(ValueError): forced_r(1,0,0)

    def test_malformed_transcripts_rejected(self):
        state,keys,z,sigma,_,_=fixture(9,(1,1),4)
        r,s,_=unpack_signature(sigma)
        cases=[(state['targets'],state['anchors'],keys,z,z,signature(r,(s+1)%N)),
               (state['targets'],state['anchors'],keys,(z+1)%N,z,sigma),
               (state['targets'],state['anchors'],keys,z,(z+1)%N,sigma),
               (state['targets'],state['anchors'],[keys[0],keys[0]],z,z,sigma),
               (list(reversed(state['targets'])),state['anchors'],keys,z,z,sigma),
               (state['targets'],state['anchors'],keys,z,0,sigma)]
        for args in cases:
            with self.assertRaises(ValueError): extract(*args)


def main():
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful(): sys.exit(1)
    rows=[fixture(seed,signs,nonce)[-1] for seed in range(3)
          for signs in ((1,1),(1,-1),(-1,1),(-1,-1)) for nonce in (0,1)]
    paths=[Path(__file__),HERE/'core_check.py',HERE/'publication_core_check.py',
           HERE.parent/'covenant-2026-09-17/legacy_same_signature_counterexample.py']
    report=dict(scope=__doc__,evidence='locally-reproduced',deployment='unclassified',
        native_sighashes=False,bitcoin_core_run=False,setup_benchmark=False,
        general_hardness_lower_bound_proved=False,tests_run=result.testsRun,
        positive_curve_cases=len(rows)+7,ecdsa_checks_per_case=4,
        synthetic_cases=rows,synthetic_different_digest_cases=[different_digest_fixture(flag) for flag in (0,2,3,128,129,255)],
        synthetic_zero_opening_case=zero_opening_fixture(),
        source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
    (HERE/'two-target-anchor-algebra.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__': main()
