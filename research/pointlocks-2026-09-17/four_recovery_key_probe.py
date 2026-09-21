#!/usr/bin/env python3
"""Four-root ECDSA extraction algebra, not a Script or transaction experiment."""
import hashlib
import json
import math
from functools import reduce
from pathlib import Path

from core_check import unpack_signature
from publication_core_check import encode_key
from legacy_same_signature_counterexample import N, P, G, add, mul, verify
from anchored_extraction import der

C = 1 << 248


def root(x):
    y = pow((x*x*x+7) % P, (P+1)//4, P)
    return (x,y) if y*y % P == (x*x*x+7) % P else None


def main():
    cases=[]
    for seed in range(5):
        attempts=0
        while True:
            r=int.from_bytes(hashlib.sha256(f'four-recovery-{seed}-{attempts}'.encode()).digest(),'big')%(P-N-1)+1
            attempts+=1
            a,b=root(r),root(r+N)
            if a is not None and b is not None:
                break
        roots=[a,(a[0],-a[1]%P),b,(b[0],-b[1]%P)]
        s=1
        keys=[mul(pow(r,-1,N),add(mul(s,R),mul(-C))) for R in roots]
        assert len(set(keys))==4 and None not in keys
        target=reduce(add,keys)
        scalar=-4*C*pow(r,-1,N)%N
        assert target==mul(scalar) and target is not None
        signature=der(r,s)[:-1]+b'\x03'
        assert unpack_signature(signature)==(r,s,3)
        for key,R in zip(keys,roots):
            valid,recovered=verify(C,r,s,key)
            assert valid and recovered==R
        cases.append(dict(seed=seed,attempts=attempts,signature_hex=signature.hex(),signature_bytes=len(signature),
                          r=f'{r:x}',keys=[encode_key(k).hex() for k in keys],target=encode_key(target).hex(),
                          scalar_fixture=f'{scalar:064x}'))
    report=dict(scope=__doc__,evidence='locally-reproduced',deployment='unclassified',
                cases=cases,small_r_interval_size=P-N,
                interval_bits=math.log2(P-N),generic_interval_dlog_exponent=math.log2(P-N)/2,
                caveat='The DLP value is a square-root interval-search scale, not an executed attack or exact operation count. No native execution or transaction size is claimed.')
    Path(__file__).with_suffix('.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({key:report[key] for key in ('interval_bits','generic_interval_dlog_exponent')},indent=2))
    print('PASS five independent four-root fixtures; signature lengths:',[c['signature_bytes'] for c in cases])


if __name__=='__main__':
    main()
