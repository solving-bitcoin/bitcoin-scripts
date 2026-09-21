#!/usr/bin/env python3
"""Close three-common-key equations against real SHA256 transaction bytes.

Positive examples use a small prime-order curve and an explicit hash-to-scalar
alpha projection, NOT raw SHA256 bytes interpreted as a Bitcoin signature.
All tiny-curve logarithms are computed and retained; none are free on secp256k1.
"""
import hashlib
import json
import math
from pathlib import Path
import struct

from r15_three_common_keys import Curve
from r11_endomorphism import signature
from r11_endomorphism import P as SECP_P,N as SECP_N
from r11_lookup_reference import push_num, push, compact

P,N=163,139
C=pow(2,248,N)
HERE=Path(__file__).resolve().parent


def sha(x):return hashlib.sha256(x).digest()
def h256(x):return sha(sha(x))
def vec(x):return compact(len(x))+x
def p2sh(s):return b'\xa9\x14'+hashlib.new('ripemd160',sha(s)).digest()+b'\x87'
def key(q):return bytes([2+(q[1]&1)])+q[0].to_bytes(32,'big')


def layout():
    out=b'\x74\x55\x88'  # DEPTH5 EQUALVERIFY
    for i in (0,1,2):out+=push_num(i)+b'\x79\x82'+push_num(33)+b'\x88\x75'
    for i,j in ((0,1),(0,2),(1,2)):
        out+=push_num(i)+b'\x79'+push_num(j+1)+b'\x79\x87\x91\x69'
    for sigdepth in (4,3):
        for keydepth in (2,1,0):out+=push_num(sigdepth)+b'\x79'+push_num(keydepth+1)+b'\x79\xad'
    return out+bytes.fromhex('6d6d7551')


def transaction(outpoints,outputs,scripts=None,locktime=0):
    scripts=[b'']*len(outpoints) if scripts is None else scripts
    out=struct.pack('<I',2)+compact(len(outpoints))
    for prev,script in zip(outpoints,scripts):out+=prev+vec(script)+b'\xfe\xff\xff\xff'
    out+=compact(len(outputs))
    for value,script in outputs:out+=struct.pack('<Q',value)+vec(script)
    return out+struct.pack('<I',locktime)


def alpha_from_hash(counter):
    preimage=b'r16 public source scalar projection'+struct.pack('<I',counter)
    digest=sha(preimage)
    r=1+int.from_bytes(digest[:16],'big')%(N-1)
    s=1+int.from_bytes(digest[16:],'big')%((N-1)//2)
    return r,s,signature(r,s,3),preimage,digest


def parse(sig):
    assert sig[0]==0x30 and sig[1]==len(sig)-3 and sig[2]==2
    nr=sig[3];r=int.from_bytes(sig[4:4+nr],'big');pos=4+nr
    assert sig[pos]==2
    ns=sig[pos+1];s=int.from_bytes(sig[pos+2:pos+2+ns],'big')
    assert signature(r,s,sig[-1])==sig and 0<r<N and 0<s<=N//2
    return r,s,sig[-1]


def setup():
    curve=Curve(P,N,(2,34));points=[curve.mul(k) for k in range(N)]
    assert len(set(points))==N
    logs={q:k for k,q in enumerate(points)}
    roots={r:tuple(k for k,q in enumerate(points) if q and q[0]%N==r) for r in range(1,P-N)}
    roots={r:ks for r,ks in roots.items() if len(ks)==4}
    assert sorted(roots)==[6,9,13,21]
    return curve,points,logs,roots


def close_actual_digest(ri,si,z,points,roots):
    """Tiny-curve constructive closure. Every logarithm is from retained table.

    Mixed source pairs give known v, then rj=z*ri/(C-si*v). Given candidate
    target roots, sj is solved using their known toy logarithms, then checked.
    """
    assert 0<z<N  # Explicit nonzero-digest fixture branch; zero is discussed.
    if ri not in roots:return None
    source_keys={u:(si*u-C)*pow(ri,-1,N)%N for u in roots[ri]}
    for A in roots[ri]:
        for B in roots[ri]:
            if points[A][0]==points[B][0]:continue
            v=(A+B)*pow(2,-1,N)%N
            denominator=(C-si*v)%N
            if not denominator:continue  # z=0 branch not used in these fixtures.
            rj=z*ri*pow(denominator,-1,N)%N
            if rj not in roots:continue
            for target_root in roots[rj]:
                sj=(rj*source_keys[A]+z)*pow(target_root,-1,N)%N
                if not 0<sj<=N//2:continue
                target_keys={(sj*u-z)*pow(rj,-1,N)%N for u in roots[rj]}
                common=sorted((set(source_keys.values())&target_keys)-{0})
                if len(common)<3:continue
                a=rj*si*pow(sj*ri,-1,N)%N
                b=(z-rj*C*pow(ri,-1,N))*pow(sj,-1,N)%N
                if not b:continue  # Demonstrate the nonzero-offset branch.
                assert v==(C-z*ri*pow(rj,-1,N))*pow(si,-1,N)%N
                assert (a*v+b)%N==0
                assert sj==rj*si*pow(a*ri,-1,N)%N
                assert source_keys[A] in common and source_keys[B] in common
                assert len(common)==3
                return {'ri':ri,'si':si,'rj':rj,'sj':sj,'z_source':C,'z_ALL':z,
                    'source_mixed_nonce_scalars':[A,B],'source_V_scalar':v,
                    'source_V_point':points[v],'target_pair_nonce_scalar':target_root,
                    'a':a,'b':b,'common_key_scalars':common,
                    'alpha':signature(ri,si,3).hex(),'beta':signature(rj,sj,1).hex(),
                    'all_eliminated_scalar_equations_hold':True}
    return None


def run(raw,items,z,logs,points):
    stack=list(items);pc=0;ops=0;peak=len(stack);checks=[]
    number=lambda x:int.from_bytes(x,'little') if x else 0
    while pc<len(raw):
        op=raw[pc];pc+=1
        if op<=75:stack.append(raw[pc:pc+op]);pc+=op
        elif 0x51<=op<=0x60:stack.append(bytes([op-0x50]))
        else:
            ops+=1
            if op==0x74:stack.append(bytes([len(stack)]))
            elif op==0x79:depth=number(stack.pop());stack.append(stack[-1-depth])
            elif op==0x82:stack.append(bytes([len(stack[-1])]))
            elif op in (0x87,0x88):
                eq=stack.pop()==stack.pop()
                if op==0x88:assert eq
                else:stack.append(b'\x01' if eq else b'')
            elif op==0x91:stack.append(b'\x01' if not number(stack.pop()) else b'')
            elif op==0x69:assert number(stack.pop())
            elif op==0x75:stack.pop()
            elif op==0x6d:stack.pop();stack.pop()
            elif op==0xad:
                public=stack.pop();sig=stack.pop();r,s,flag=parse(sig)
                assert len(public)==33 and public[0] in (2,3)
                x=int.from_bytes(public[1:],'big');ys=[q for q in logs if q and q[0]==x and q[1]%2==public[0]%2]
                assert len(ys)==1
                k=logs[ys[0]];native=C if flag==3 else z
                assert flag in (1,3)
                nonce=(native+r*k)*pow(s,-1,N)%N
                assert nonce and points[nonce][0]%N==r
                checks.append({'flag':flag,'actual_digest_scalar':native,'r':r,'s':s,'public_key_scalar':k,'nonce_scalar':nonce})
            else:raise AssertionError(hex(op))
        peak=max(peak,len(stack))
    assert stack==[b'\x01'] and len(checks)==6
    return {'script_bytes':len(raw),'non_push_opcodes':ops,'combined_stack_peak':peak,'actual_toy_ECDSA_checks':checks}


def main():
    curve,points,logs,roots=setup();raw=layout()
    funding=transaction([b'\x24'*32+bytes(4)],[(10000,b'\x51'),(1000000,p2sh(raw))])
    fid=h256(funding);prev=[fid+struct.pack('<I',i) for i in (0,1)]
    out0=[(999000,b'\x00\x14'+b'\x11'*20)]
    out1=[(999000,b'\x00\x14'+b'\x22'*20)]
    def native(outputs,locktime):
        pre=transaction(prev,outputs,[b'',raw],locktime)+struct.pack('<I',1)
        return int.from_bytes(h256(pre),'big')%N,pre
    z0,pre0=native(out0,0)
    assert z0 and z0!=C
    for counter in range(100000):
        ri,si,alpha,alpha_preimage,alpha_hash=alpha_from_hash(counter)
        first=close_actual_digest(ri,si,z0,points,roots)
        if first:break
    else:raise AssertionError('bounded alpha search found no closure')
    for locktime in range(100000):
        z1,pre1=native(out1,locktime)
        if not z1 or z1 in (C,z0):continue
        second=close_actual_digest(ri,si,z1,points,roots)
        if second:break
    else:raise AssertionError('bounded alternate-output search found no closure')
    vectors=[]
    for outputs,locktime,pre,row in ((out0,0,pre0,first),(out1,locktime,pre1,second)):
        beta=bytes.fromhex(row['beta']);items=[alpha,beta]+[key(points[k]) for k in row['common_key_scalars']]
        assert push(alpha) not in raw and push(beta) not in raw
        metrics=run(raw,items,row['z_ALL'],logs,points)
        unlocking=b''.join(push(x) for x in items+[raw])
        tx=transaction(prev,outputs,[b'',unlocking],locktime)
        vectors.append({**row,'locktime':locktime,'actual_ALL_preimage':pre.hex(),
            'actual_ALL_digest_256':h256(pre).hex(),'script_sig':unlocking.hex(),'script_sig_bytes':len(unlocking),
            'data_items':5,'hint_items':0,'unlocking_push_items_including_redeemscript':6,
            'serialized_witness_bytes':0,'complete_synthetic_transaction':tx.hex(),
            'complete_synthetic_transaction_weight':4*len(tx),'metrics':metrics})
    first_items=[alpha,bytes.fromhex(first['beta'])]+[key(points[k]) for k in first['common_key_scalars']]
    def rejected(items,z):
        try:run(raw,items,z,logs,points)
        except AssertionError:return True
        return False
    duplicate=list(first_items);duplicate[-1]=duplicate[-2]
    changed_alpha=list(first_items);changed_alpha[0]=signature(ri,si+1,3)
    changed_alpha_checks=[]
    for k in first['common_key_scalars']:
        nonce=(C+ri*k)*pow(si+1,-1,N)%N
        changed_alpha_checks.append(bool(nonce and points[nonce][0]%N==ri))
    negatives={
        'duplicate_third_key_rejected':rejected(duplicate,first['z_ALL']),
        'changed_recipient_and_locktime_with_complete_first_witness_rejected':rejected(first_items,second['z_ALL']),
        'incremented_source_s_rejected':rejected(changed_alpha,first['z_ALL']),
        'incremented_source_s_individual_ECDSA_acceptances':changed_alpha_checks,
        'source_s_mutation':[si,si+1],
    }
    assert all(negatives[name] for name in ('duplicate_third_key_rejected',
        'changed_recipient_and_locktime_with_complete_first_witness_rejected','incremented_source_s_rejected'))
    assert changed_alpha_checks==[False]*3
    interval=SECP_P-SECP_N-1
    m=math.isqrt(interval)
    if m*m<interval:m+=1
    giants=(interval+m-1)//m
    expected_m=math.isqrt((interval+1)//2)
    if 2*expected_m*expected_m<interval:expected_m+=1
    expected_q,expected_remainder=divmod(interval,expected_m)
    # Uniform located solution j in [0,L): mean giant index floor(j/m).
    expected_numerator=(expected_m-1)*interval+expected_m*expected_q*(expected_q-1)//2+expected_q*expected_remainder
    result={'evidence':'locally-reproduced','deployment_class':'unclassified',
        'scope':'Small-curve analogue with SHA256-derived transaction scalars and explicit projected source alpha. NOT secp256k1 and NOT a32-byte hash-output DER signature or Bitcoin consensus execution.',
        'curve':{'p':P,'n':N,'generator':curve.g,'all_retained_public_group_points_by_scalar':points},
        'native_source_CONSTANT_C':C,'source_constant_256_bit_digest':(b'\x01'+bytes(31)).hex(),
        'funding_transaction':funding.hex(),'funding_txid':fid[::-1].hex(),'script':raw.hex(),
        'source_alpha':{'counter':counter,'hash_queries':counter+1,'SHA256_preimage':alpha_preimage.hex(),
            'SHA256_output':alpha_hash.hex(),'projection':'r=1+int(H[0:16])%(n-1), s=1+int(H[16:32])%((n-1)/2); DER(r,s)||03',
            'signature':alpha.hex(),'is_raw_32byte_hash_interpreted_as_DER':False},
        'vectors':vectors,'targeted_negative_checks':negatives,
        'same_funding_and_source_alpha':True,'distinct_actual_ALL_scalars':True,
        'alternative_output_native_queries':vectors[1]['locktime']+1,
        'eliminated_relation':'rj(si V-CG)=-ri*z_ALL*G; for known v, rj=z_ALL*ri/(C-si*v)',
        'unimplemented_secp_interval_test':{'interval_length':str(interval),
            'baby_table_entries':str(m),'giant_queries':str(giants),
            'point_additions_before_extra_scalar_mults':str(m+giants-2),
            'point_addition_count_log2':math.log2(m+giants-2),
            'point_addition_count_interpretation':'Complete or unsuccessful scan, not expected successful solve.',
            'compressed_point_storage_bytes_alone':str(33*m),
            'uniform_located_solution_optimized_baby_entries':str(expected_m),
            'uniform_located_solution_expected_additions_numerator':str(expected_numerator),
            'uniform_located_solution_expected_additions_denominator':str(interval),
            'uniform_located_solution_expected_additions_log2':math.log2(expected_numerator)-math.log2(interval),
            'not_executed':True,'not_a_generic_lower_bound':True},
        'secp_log_obligations':['Computing v for a hash-chosen source root pair is not free.',
            'When sj is recovered from a target root, its logarithm is not free either.'],
        'actual_Bitcoin_candidate_found':False,'setup_below_2_64_established':False}
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
