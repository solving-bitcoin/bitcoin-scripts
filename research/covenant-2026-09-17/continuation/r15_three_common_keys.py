#!/usr/bin/env python3
"""Exact finite test for mismatched three-root affine recovery matches.

Public host mathematics. Complete toy enumeration, bounded secp256k1 cases.
No hash preimage, native C/ALL candidate, Core, or field-library tests.
"""
from functools import lru_cache
import itertools
import json
from pathlib import Path

from r11_endomorphism import P,N,G,GAP,LAMBDA,add,mul
from r9_four_roots import polynomial_gcd,polynomial_powmod,polynomial_subtract,fully_split_roots


class Curve:
    def __init__(self,p,n,g): self.p,self.n,self.g=p,n,g
    def neg(self,a): return None if a is None else (a[0],-a[1]%self.p)
    def add(self,a,b):
        if self.p==P: return add(a,b)
        if a is None:return b
        if b is None:return a
        x,y=a;u,v=b;p=self.p
        if x==u and (y+v)%p==0:return None
        slope=((v-y)*pow(u-x,-1,p) if x!=u else 3*x*x*pow(2*y,-1,p))%p
        xx=(slope*slope-x-u)%p
        return xx,(slope*(x-xx)-y)%p
    def mul(self,k,a=...):
        a=self.g if a is ... else a
        if a is None:return None
        if self.p==P:return mul(k,a)
        k%=self.n;out=None
        while k:
            if k&1:out=self.add(out,a)
            a=self.add(a,a);k>>=1
        return out


def coefficients(curve,vpoint):
    p,n=curve.p,curve.n
    x,y=vpoint;d2=n*n%p;w2=y*y%p
    return tuple(c%p for c in (d2*x**4-112*w2,-4*d2*x**3,6*d2*x*x,-4*d2*x-16*w2,d2))


def evaluate(poly,x,p):
    result=0
    for coefficient in reversed(poly):result=(result*x+coefficient)%p
    return result


@lru_cache(None)
def roots_of(poly,p):
    if p!=P:return tuple(x for x in range(p) if evaluate(poly,x,p)==0)
    factor=polynomial_gcd(list(poly),polynomial_subtract(polynomial_powmod([0,1],P,list(poly)),[0,1]))
    roots,_=fully_split_roots(factor)
    assert all(evaluate(poly,x,p)==0 for x in roots)
    assert len(roots)==len(factor)-1
    return tuple(roots)


def mismatch_test(curve,a,b):
    """Complete all mismatched triples for fixed nonzero scalar a,b.

    Source triple (A,-A,B) maps to (C,D,-C). Each side must represent
    three distinct ECDSA nonce roots, hence two exact x-coordinate branches.
    """
    p,n=curve.p,curve.n
    assert 0<a<n and 0<b<n and p<2*n
    v_scalar=-b*pow(a,-1,n)%n
    V=curve.mul(v_scalar)
    assert V is not None and V[1] and curve.mul(a,V)==curve.mul(-b)
    poly=coefficients(curve,V)
    assert evaluate(poly,V[0],p)==(-16*pow(V[1],4,p))%p!=0
    xs=roots_of(poly,p)
    assert len(xs)<=4
    candidates=[];source_gap_hits=0
    for sign,x in itertools.product((-1,1),xs):
        assert x!=V[0]  # U=+-V would make source A or B infinity.
        delta=sign*n
        y=-delta*(x-V[0])**2*pow(4*V[1],-1,p)%p
        U=(x,y)
        assert y*y%p==(x*x*x+7)%p
        A=curve.add(V,U);B=curve.add(V,curve.neg(U))
        assert A and B and (A[0]-B[0])%p==delta%p
        if A[0]-B[0]!=delta:continue  # The field gap alone is insufficient.
        ri=A[0]%n
        if not 0<ri<p-n:continue
        source_gap_hits+=1
        C=curve.mul(a,U)
        D=curve.neg(curve.mul(a,curve.add(curve.mul(2,V),U)))
        if C is None or D is None or abs(C[0]-D[0])!=n:continue
        rj=C[0]%n
        if not 0<rj<p-n:continue
        source=(A,curve.neg(A),B);target=(C,D,curve.neg(C))
        assert len(set(source))==len(set(target))==3
        assert all(curve.add(curve.mul(a,s),curve.mul(b))==t for s,t in zip(source,target))
        assert all(s[0]%n==ri for s in source) and all(t[0]%n==rj for t in target)
        candidates.append({'ri':ri,'rj':rj,'V':V,'U':U,'source':source,'target':target,
            'source_integer_gap':delta,'target_integer_gap':C[0]-D[0]})
    return candidates,{'a':a,'b':b,'v_scalar':v_scalar,'V':V,
        'quartic_coefficients':poly,'quartic_distinct_field_roots':xs,
        'field_root_count':len(xs),'exact_source_gap_cases':source_gap_hits,
        'complete_mismatched_triples':len(candidates)}


def toy_complete(p,n):
    points=[(x,y) for x in range(p) for y in range(p) if y*y%p==(x*x*x+7)%p]
    assert len(points)+1==n and all(n%d for d in range(2,int(n**0.5)+1))
    curve=Curve(p,n,points[0]);logs={curve.mul(k):k for k in range(n)}
    assert len(logs)==n
    groups={r:tuple(q for q in points if q[0]%n==r) for r in range(1,p-n)}
    groups={r:s for r,s in groups.items() if len(s)==4}
    triples=[tuple(sorted(logs[x] for x in subset)) for s in groups.values() for subset in itertools.combinations(s,3)]
    rootsets={r:set(map(logs.get,s)) for r,s in groups.items()}
    tests=0;hits=0;examples=[]
    for a in range(1,n):
        for b in range(1,n):
            # Independent brute enumeration uses only group scalar indices.
            expected={tri for tri in triples if any({(a*k+b)%n for k in tri}<=target for target in rootsets.values())}
            actual,summary=mismatch_test(curve,a,b)
            observed={tuple(sorted(logs[x] for x in row['source'])) for row in actual}
            assert observed==expected,(p,a,b,observed,expected)
            tests+=1;hits+=len(expected)
            if expected and len(examples)<4:
                examples.append({'a':a,'b':b,'source_scalar_triples':sorted(expected),
                    'quartic':summary,'point_candidates':actual})
    # b=0 is the separate matched-antipodal class, never a mismatched case.
    matched=0
    for a in range(1,n):
        for tri in triples:
            image={(a*k)%n for k in tri}
            if any(image<=target for target in rootsets.values()):
                sourcepair=next((x,y) for x,y in itertools.combinations(tri,2) if (x+y)%n==0)
                assert (a*sum(sourcepair))%n==0
                matched+=1
    return {'p':p,'n':n,'generator':curve.g,'four_root_r':sorted(groups),
        'nonzero_a_b_cases_exhausted':tests,'mismatched_triple_matches':hits,
        'b_zero_matched_triples':matched,'examples':examples,
        'quartic_equals_independent_brute_force':True}


def main():
    toy=[toy_complete(43,31),toy_complete(79,67),toy_complete(163,139)]
    curve=Curve(P,N,G);secp=[]
    for exponent,sign,v in itertools.product((1,2),(-1,1),(1,2,7,19)):
        a=sign*pow(LAMBDA,exponent,N)%N
        b=-a*v%N
        candidates,summary=mismatch_test(curve,a,b)
        # Results are an explicit finite sample, not exhaustive in translations.
        secp.append({'endomorphism_exponent':exponent,'scalar_sign':sign,
                     **summary,'candidates':candidates})
    report={'evidence':'locally-reproduced','deployment_class':'unclassified',
        'question':'Can three common keys force a pure endomorphism hop across distinct ECDSA signatures?',
        'scope':'Exact affine triple classification and finite translation test; complete tiny-curve tests and16 specified secp translations only. No native C/ALL candidate or hash-derived signature mined.',
        'map':'Uj=a Ui+bG; a=rj si/(sj ri), b=(zj-rj zi/ri)/sj',
        'mismatch_normal_form':'A=V+U, B=V-U; source(A,-A,B), target(aU,-a(2V+U),-aU); bG=-aV',
        'quartic':'n^2(X-v)^4-16w^2(X^3+7)=0 where V=(v,w)=-(b/a)G',
        'candidate_y':'Y=-delta(X-v)^2/(4w), delta in{-n,+n}',
        'must_filter_integer_not_modular_gaps':True,
        'both_signatures_require_four_roots':True,'both_r_bound_exclusive':str(GAP),
        'toy_complete':toy,'secp256k1_bounded_cases':secp,
        'public_nonce_necessary_condition':'If Uj=t Ui also, then(t-a)Ui=bG. If t!=a, k=b/(t-a) is the required public nonce scalar; finding a hash-chosen r with x(kG)%n=r remains necessary.',
        'actual_native_candidate_found':False,'setup_under_2_64_established':False}
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
