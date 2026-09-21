#!/usr/bin/env python3
"""Canonical ECDSA recovery pairs and fixed affine Schnorr-key interfaces.

Reuses the already known two-root primitive. New scope is affine aggregation,
x-only symmetry, public signing scalars, and exact qualifications.
"""
import hashlib
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from r20_taproot_reference import P,N,G,add,mul,neg,point,encoded,b32,schnorr_sign,schnorr_verify
sys.path.insert(0,str(HERE.parent/'seven'))
from search3_native_algebra import nonce_roots
from search2_native_context import legacy_preimage,delete,clean,push,h256
from legacy_same_signature_counterexample import verify


def aggregate(keys,a,b,c):return add(add(mul(a,keys[0]),mul(b,keys[1])),mul(c))
def xsame(q,r):return q is not None and r is not None and q[0]==r[0]
def encoded_or_none(q):return None if q is None else encoded(q).hex()


def parameters(R,z,r,s=1):
    rinv=pow(r,-1,N)
    keys=[mul(rinv,add(mul(s,R),mul(-z))),mul(rinv,add(mul(-s,R),mul(-z)))]
    assert all(k is not None for k in keys) and keys[0]!=keys[1]
    assert len(nonce_roots(r))==2
    assert all(verify(z,r,s,k)[0] for k in keys)
    return keys


def main():
    prior=json.loads((HERE.parent/'seven/core_fragments.json').read_text())
    original=next(r for r in prior['results'] if r['name']=='two-recovery-keys-same-context')
    z=int(original['digest'],16)%N
    R=point(b'\x02'+b32(1))
    keys=parameters(R,z,1)
    assert sorted(encoded(k).hex() for k in keys)==sorted(original['input_items_hex'])
    assert original['consensus']['accepted']
    other=json.loads((HERE/'r20_taproot_reference_core.json').read_text())
    msgs=[bytes.fromhex(other['DEFAULT_message']),bytes.fromhex(next(r for r in other['results'] if r['name']=='helper-omitted-fresh-public-key-signature')['actual_DEFAULT_message'])]
    assert msgs[0]!=msgs[1]
    # These are BIP340 equation checks over recorded BIP341 hashes, not claims
    # that aggregate-key signatures spend the old 7G leaf from those records.
    cases=[]
    for name,r,nonce,nonce_scalar in [('unknown-log lift(1)',1,R,None),
            ('public G/2 nonce',mul(pow(2,-1,N))[0],mul(pow(2,-1,N)),pow(2,-1,N))]:
        k=parameters(nonce,z,r)
        rinv=pow(r,-1,N)
        rows=[]
        for a,b,c in ((1,1,0),(3,3,7),(1,-1,0),(3,-3,0),(1,2,0),(2,1,11)):
            a%=N;b%=N;c%=N
            u=(a-b)*rinv%N;v=(c-(a+b)*z*rinv)%N
            q=aggregate(k,a,b,c);swapped=aggregate(k,b,a,c)
            assert q==add(mul(u,nonce),mul(v))
            assert swapped==add(mul(-u,nonce),mul(v))
            assert q is not None and swapped is not None
            assert (q==swapped)==(u==0)
            assert (q==neg(swapped))==(v==0)
            assert xsame(q,swapped)==(u==0 or v==0)
            item={'a':str(a),'b':str(b),'c':str(c),'unknown_nonce_coefficient':str(u),
                  'public_G_coefficient':str(v),'aggregate':encoded_or_none(q),
                  'swapped_aggregate':encoded_or_none(swapped),
                  'same_point_after_swap':q==swapped,'same_xonly_key_after_swap':xsame(q,swapped)}
            scalar=v if u==0 else None
            if nonce_scalar is not None:
                scalar=(u*nonce_scalar+v)%N
                recovered=(scalar-v)*pow(u,-1,N)%N if u else None
                if u:assert recovered==nonce_scalar
                item['nonce_log_recovered_from_known_aggregate_log']=None if recovered is None else str(recovered)
            if scalar is not None:
                assert mul(scalar)==q
                signatures=[schnorr_sign(scalar,m,41+j) for j,m in enumerate(msgs)]
                assert all(schnorr_verify(sig,b32(q[0]),m) for sig,m in zip(signatures,msgs))
                item.update({'public_signing_scalar':str(scalar),'two_BIP340_equation_checks_pass':True,
                             'signatures':[s.hex() for s in signatures]})
            else:
                item.update({'public_signing_scalar':None,'honest_Schnorr_signer_demonstrated':False})
            if v==0:
                different=parameters(nonce,(z+1)%N,r)
                assert aggregate(different,a,b,c)==q
                item['unchanged_when_digest_changes_to_z_plus_one']=True
            rows.append(item)
        cases.append({'nonce':name,'r':str(r),'s':1,'R':encoded(nonce).hex(),
            'nonce_log_public':nonce_scalar is not None,'canonical_unordered_keys':[encoded(x).hex() for x in k],
            'fixed_coefficient_vectors':rows})
    # A permutation-equivariant coefficient rule is a genuine exception to
    # any unqualified "all symmetric linear aggregates cancel R" assertion.
    coefficient=lambda key:int.from_bytes(hashlib.sha256(encoded(key)).digest(),'big')%N
    a,b=coefficient(keys[0]),coefficient(keys[1]);assert a!=b
    q=aggregate(keys,a,b,0)
    swapped=aggregate(keys[::-1],coefficient(keys[1]),coefficient(keys[0]),0)
    assert q==swapped
    assert q==add(mul((a-b)%N,R),mul(-(a+b)*z))
    # Canonical SEC encoding is not canonical ordering. Even with a granted
    # prefix reader, selecting an even public key does not always select one.
    oldraw=bytes.fromhex(original['transaction']['hex'])
    assert oldraw[4]==1
    previous_inputs=[(oldraw[5:41],0xffffffff)]
    previous_outputs=[(990000,b'\x00\x14'+b'\x11'*20)]
    code=clean(delete(bytes.fromhex(original['redeemscript_hex']),[bytes.fromhex('300602010102010101')]))
    assert h256(legacy_preimage(previous_inputs,previous_outputs,0,code,1)).hex()==original['digest']
    parity_counts={0:0,1:0,2:0};parity_rows=[]
    for lock in range(64):
        pre=legacy_preimage(previous_inputs,previous_outputs,0,code,1,locktime=lock)
        digest=h256(pre);zz=int.from_bytes(digest,'big')%N
        pair=parameters(R,zz,1)
        count=sum(k[1]%2==0 for k in pair);parity_counts[count]+=1
        parity_rows.append({'locktime':lock,'native_digest':digest.hex(),'even_key_count':count})
    assert all(parity_counts.values())
    eq={'coefficient_rule':'SHA256(compressed key) mod n, evaluated off-chain only',
        'a':str(a),'b':str(b),'aggregate':encoded_or_none(q),'same_point_after_input_swap':True,
        'nonzero_unknown_nonce_coefficient':str((a-b)%N),
        'native_encoding_or_Schnorr_signer_demonstrated':False}
    # X-only sign adjustment is explicit in BIP340. All point equations above
    # use full points; sign normalization preserves whether a scalar is known.
    result={'evidence':'locally-reproduced','deployment_class':'unclassified',
        'scope':'Host point/scalar equations only; canonical pair reused from prior work. No new Script, funding construction or Core run.',
        'prior_canonical_pair_source':{'file':'../seven/core_fragments.json','name':original['name'],
            'native_legacy_digest':original['digest'],'z_mod_n':str(z),
            'prior_funding_txid':prior['funding']['txid'],'new_native_execution':False},
        'BIP340_message_controls':[m.hex() for m in msgs],
        'message_control_limit':'Recorded actual BIP341 hashes; generated aggregate-key signatures are point-equation controls, not spend witnesses for the recorded 7G leaf.',
        'cases':cases,'key_dependent_equivariant_control':eq,
        'public_key_parity_controls':{'actual_native_contexts':64,'counts':parity_counts,'rows':parity_rows,
            'no_prefix_reader_or_canonical_sort_opcode_claimed':True},
        'no_canonical_pair_primitive_novelty_claim':True,
        'complete_covenant':False,'all_assertions_passed':True}
    (HERE/'r21_canonical_affine.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'fixed_coefficient_vectors':sum(len(c['fixed_coefficient_vectors']) for c in cases),
        'BIP340_checks':sum(2 for c in cases for r in c['fixed_coefficient_vectors'] if r.get('two_BIP340_equation_checks_pass')),
        'permutation_equivariant_nonzero_unknown_nonce_control':True},indent=2))


if __name__=='__main__':main()
