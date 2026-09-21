#!/usr/bin/env python3
"""Fixed-C membership selectors and constant-digest recovery-pair paths.

Host equation controls and reuse of saved actual native-message vectors only.
No new Script, native flag guard, transaction, Core run or field-library test.
"""
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from r20_taproot_reference import P,N,G,add,mul,neg,point,encoded,b32,h256,signature_integer,verify
from r10_parallel_cycles import unpack_der
sys.path.insert(0,str(HERE.parent/'seven'))
from search3_native_algebra import nonce_roots

C = 1 << 248
DELTA = P-N

def der(r,s,flag):
    body=signature_integer(r)+signature_integer(s)
    return b'\x30'+bytes([len(body)])+body+bytes([flag])

def keys(r,s,z):
    result=[mul(pow(r,-1,N),add(mul(s,R),mul(-z))) for R in nonce_roots(r)]
    return [q for q in result if q is not None]

def enc(q):
    return None if q is None else encoded(q).hex()

def pair(R,r,s,z):
    result=[mul(pow(r,-1,N),add(mul(s,R),mul(-z))),
            mul(pow(r,-1,N),add(mul(-s,R),mul(-z)))]
    assert None not in result and result[0]!=result[1]
    assert all(verify(z,r,s,q)[0] for q in result)
    return result

def main():
    old=json.loads((HERE/'r11_endomorphism_core.json').read_text())
    native=[]
    for row in old['results']:
        if not row['consensus']['accepted']:
            continue
        a,b,K,L=map(bytes.fromhex,row['input_items'])
        ra,sa=unpack_der(a);rb,sb=unpack_der(b)
        K,L=point(K),point(L)
        assert a[-1]==3 and b[-1]==1
        assert h256(bytes.fromhex(row['actual_all_preimage'])).hex()==row['actual_all_digest']
        z=int(row['actual_all_digest'],16)%N
        assert int.from_bytes(bytes.fromhex(row['single_bug_digest']),'big')==C
        assert len(nonce_roots(ra))==len(nonce_roots(rb))==2
        assert len(b)>57 and K!=L
        assert all(verify(C,ra,sa,q)[0] and verify(z,rb,sb,q)[0] for q in (K,L))
        assert add(K,L)==mul(-2*C*pow(ra,-1,N))==mul(-2*z*pow(rb,-1,N))
        assert z*pow(rb,-1,N)%N==C*pow(ra,-1,N)%N
        native.append({'prior_case':row['name'],'actual_ALL_digest':row['actual_all_digest'],
            'C_signature':a.hex(),'ALL_signature':b.hex(),'keys':[enc(K),enc(L)],
            'constant_edge_r':str(ra),'source_ALL_r':str(rb),
            'one_edge_reciprocal_relation_pass':True,'prior_consensus_accepted':True,
            'new_Core_execution':False})
    assert len(native)==3
    # Fixed C signatures are finite membership tests, including a four-root
    # signature. Enumerate their target zG points without computing logs.
    R=point(b'\x02'+b32(1));source_r=source_s=1
    selectors=[]
    for fixed_r in (1,2):
        anchors=keys(fixed_r,1,C)
        targets={enc(add(mul(sign,R),neg(K))) for sign in (-1,1) for K in anchors}
        assert len(targets)<=2*len(anchors)<=8
        actual=[]
        for row in native:
            z=int(row['actual_ALL_digest'],16)%N
            source=pair(R,1,1,z)
            accepted=[verify(C,fixed_r,1,q)[0] for q in source]
            assert any(accepted)==(enc(mul(z)) in targets)
            assert not any(accepted)
            actual.append({'actual_ALL_digest':row['actual_ALL_digest'],'accepted_members':sum(accepted)})
        if fixed_r==1:
            assert len(targets)==3
            assert targets=={enc(mul(C)),enc(add(mul(C),mul(2,R))),enc(add(mul(C),mul(-2,R)))}
        selectors.append({'fixed_C_signature':der(fixed_r,1,3).hex(),
            'anchor_count':len(anchors),'anchors':[enc(q) for q in anchors],
            'candidate_digest_group_points':sorted(targets),'candidate_count':len(targets),
            'actual_native_digest_controls':actual})
    # Positive selectors use known nonce log 19, solely to provide explicit
    # scalar z for each exceptional point. Those z are not transaction hashes.
    known_R=mul(19);known_r=known_R[0]%N
    assert len(nonce_roots(known_r))==2
    selector_positives=[]
    for z,expected in ((C,2),((C+38)%N,1),((C-38)%N,1),((C+1)%N,0)):
        source=pair(known_R,known_r,1,z)
        outcomes=[verify(C,known_r,1,q)[0] for q in source]
        assert sum(outcomes)==expected
        selector_positives.append({'z':str(z),'accepted_members':sum(outcomes),
            'accepted_positions':outcomes,'actual_transaction_digest':False})
    # Build genuine C-edges by ordinary signing from known scalar 7, with
    # fixed public nonces. The source ALL scalar closing each path is then
    # manufactured and explicitly not claimed to equal a native hash.
    paths=[]
    for length in (1,2,3):
        scalar_vertices=[7];edges=[]
        for nonce_scalar in (11,13,17)[:length]:
            d=scalar_vertices[-1];r=mul(nonce_scalar)[0]%N
            s=(C+r*d)*pow(nonce_scalar,-1,N)%N
            s=min(s,N-s)
            next_d=(-d-2*C*pow(r,-1,N))%N
            left,right=mul(d),mul(next_d)
            sig=der(r,s,3)
            assert left is not None and right is not None and left!=right
            assert len(sig)>57 and r>=DELTA and len(nonce_roots(r))==2
            assert verify(C,r,s,left)[0] and verify(C,r,s,right)[0]
            assert add(left,right)==mul(-2*C*pow(r,-1,N))
            scalar_vertices.append(next_d)
            edges.append({'r':str(r),'s':str(s),'signature':sig.hex(),
                          'left':enc(left),'right':enc(right),'length':len(sig)})
        d0,dm=scalar_vertices[0],scalar_vertices[-1]
        r=known_r
        s=r*(d0-dm)*pow(38,-1,N)%N
        source_nonce_scalar=19
        if s>N//2:s=N-s;source_nonce_scalar=-19%N
        z=-r*(d0+dm)*pow(2,-1,N)%N
        source=pair(mul(source_nonce_scalar),r,s,z)
        assert source==[mul(d0),mul(dm)]
        S=sum((-1)**(length-1-i)*pow(int(edge['r']),-1,N) for i,edge in enumerate(edges))%N
        assert source[-1]==add(mul((-1)**length,source[0]),mul(-2*C*S))
        result={'edges':length,'source_r':str(r),'source_s':str(s),'source_z':str(z),
                'source_R':enc(mul(source_nonce_scalar)),'source_nonce_scalar':str(source_nonce_scalar),
                'source_ALL_signature':der(r,s,1).hex(),'actual_ALL_digest':False,
                'vertices':[enc(mul(d)) for d in scalar_vertices],
                'public_vertex_scalars':[str(d) for d in scalar_vertices],
                'C_edges':edges,'alternating_reciprocal_sum':str(S)}
        if length%2:
            assert z*pow(r,-1,N)%N==C*S%N
            reversed_S=sum((-1)**(length-1-i)*pow(int(edge['r']),-1,N) for i,edge in enumerate(edges[::-1]))%N
            assert S==reversed_S
            result['odd_path_digest_relation_and_reversal_invariance']=True
        else:
            recovered=C*r*S*pow(s,-1,N)%N
            assert recovered==source_nonce_scalar
            assert mul(recovered)==mul(source_nonce_scalar)
            result['extracted_source_nonce_log']=str(recovered)
        paths.append(result)
    # The existing mixed four-root exception must survive as a negative
    # control: distinct valid endpoints do not alone imply reflection.
    roots=nonce_roots(2)
    A=next(q for q in roots if q[0]==2)
    B=next(q for q in roots if q[0]==N+2)
    mixed=[mul(pow(2,-1,N),add(q,mul(-C))) for q in (A,B)]
    assert mixed[0]!=mixed[1] and all(verify(C,2,1,q)[0] for q in mixed)
    assert add(*mixed)!=mul(-C)
    # Exact DER upper bound when an extra r+n recovery branch is possible.
    assert DELTA.bit_length()==129
    max_r_DER=len(signature_integer(DELTA-1))-2
    max_s_DER=len(signature_integer(N-1))-2
    assert (max_r_DER,max_s_DER,7+max_r_DER+max_s_DER)==(17,33,57)
    report={'evidence':'locally-reproduced','deployment_class':'unclassified','scope':__doc__,
        'actual_native_controls_reused':native,'fixed_C_selectors':selectors,
        'known_nonce_selector_controls':selector_positives,'path_controls':paths,
        'mixed_four_root_negative_control':{'keys':[enc(q) for q in mixed],
            'both_C_checks_pass':True,'reflection_equation_holds':False},
        'long_signature_sufficient_guard':{'four_root_max_r_DER_bytes':17,
            'valid_max_s_DER_bytes':33,'four_root_max_signature_bytes_including_flag':57},
        'all_assertions_passed':True,'complete_covenant':False}
    (HERE/'r22_native_relation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'reused_actual_native_cases':len(native),
        'fixed_selector_actual_checks':sum(len(s['actual_native_digest_controls'])*2 for s in selectors),
        'positive_or_negative_selector_scalars':len(selector_positives),'C_paths':len(paths),
        'C_edge_equations':2*sum(p['edges'] for p in paths),'source_ALL_equations':2*len(paths)}))

if __name__=='__main__':main()
