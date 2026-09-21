#!/usr/bin/env python3
"""Independent group/formula audit for slopes +/-2*lambda^k.

Uses only the previous independent audit's polynomial arithmetic, never the
construction's curve or polynomial routines. No Script or Core execution.
"""
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
from r18_resultant_audit import P, N, trim, plus, scale, times, remainder, gcd, powmod, at

HERE = Path(__file__).resolve().parent
G = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
     0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)


def derivative(f, p): return trim([i*f[i] for i in range(1,len(f))],p)


def polys(d, e, p):
    x, b = [0,1], [d,1]
    fA = [7,0,0,1]
    fB = plus(times(times(b,b,p),b,p),[7],p)
    # Derive tripling from addition A+2A, rather than copy N3 coefficients.
    T, U = [0,-56,0,0,1], [28,0,0,4]
    V = plus(times(derivative(T,p),U,p),scale(times(T,derivative(U,p),p),-1,p),p)
    psi = plus(times(x,U,p),scale(T,-1,p),p)
    N3 = plus(plus(times(times(x,T,p),plus(times(x,U,p),T,p),p),
                         scale(times(U,U,p),14,p),p),scale(times(fA,V,p),-1,p),p)
    assert N3 == trim([21952,0,0,2352,0,0,-672,0,0,1],p)
    D3 = times(psi,psi,p)
    Y = plus(times(derivative(N3,p),psi,p),scale(times(N3,derivative(psi,p),p),-2,p),p)
    Q = plus(times(b,D3,p),scale(N3,-1,p),p)
    Q2 = times(Q,Q,p)
    S = plus(times(times(x,b,p),plus(x,b,p),p),[14],p)
    M0 = plus(times(times(b,N3,p),plus(times(b,D3,p),N3,p),p),scale(times(D3,D3,p),14,p),p)
    M1 = scale(times(Y,psi,p),-2*pow(3,-1,p),p)
    L0 = plus(scale(M0,d*d,p),scale(times(plus(S,[e*d*d],p),Q2,p),-1,p),p)
    L1 = plus(scale(M1,d*d,p),scale(Q2,-2,p),p)
    H = plus(times(L0,L0,p),scale(times(times(L1,L1,p),times(fA,fB,p),p),-1,p),p)
    assert len(L0)<=22 and len(L1)<=19 and len(H)<=43
    Tb, Ub = [0], [0]
    for coefficient in reversed(T): Tb=plus(times(Tb,b,p),[coefficient],p)
    for coefficient in reversed(U): Ub=plus(times(Ub,b,p),[coefficient],p)
    Z = plus(plus(times(Tb,U,p),scale(times(T,Ub,p),-1,p),p),scale(times(U,Ub,p),-e,p),p)
    assert len(Z)<=8
    return {'T':trim(T,p),'U':trim(U,p),'psi':psi,'N3':N3,'D3':D3,'Y':Y,
            'Q':Q,'S':S,'M0':M0,'M1':M1,'L0':L0,'L1':L1,'H':H,'Z':Z}


class Curve:
    def __init__(self,p,n,g): self.p,self.n,self.g=p,n,g
    def neg(self,a): return None if a is None else (a[0],-a[1]%self.p)
    def add(self,a,b):
        if a is None:return b
        if b is None:return a
        x,y=a;u,v=b;p=self.p
        if x==u and (y+v)%p==0:return None
        m=((3*x*x)*pow(2*y,-1,p) if a==b else (v-y)*pow(u-x,-1,p))%p
        nx=(m*m-x-u)%p
        return nx,(m*(x-nx)-y)%p
    def mul(self,k,a=None):
        a=self.g if a is None else a
        k%=self.n;out=None
        while k:
            if k&1:out=self.add(out,a)
            a=self.add(a,a);k>>=1
        return out


def point_formula_controls(curve,scalar_pairs):
    p=curve.p;rows=[]
    for ka,kb in scalar_pairs:
        A,B=curve.mul(ka),curve.mul(kb)
        if A is None or B is None or A[0]==B[0]:continue
        trip=curve.mul(3,A)
        minus=curve.add(A,curve.neg(B))
        plus3=curve.add(trip,B)
        x,b=A[0],B[0];d=(b-x)%p;t=A[1]*B[1]%p
        e=(plus3[0]-minus[0])%p if plus3 else 1
        q=polys(d,e,p)
        psi=at(q['psi'],x,p);Q=at(q['Q'],x,p)
        assert psi and trip is not None
        assert trip[0] == at(q['N3'],x,p)*pow(psi,-2,p)%p
        assert trip[1] == A[1]*at(q['Y'],x,p)*pow(3*psi**3,-1,p)%p
        assert minus[0] == (at(q['S'],x,p)+2*t)*pow(d,-2,p)%p
        if Q:
            assert plus3 is not None
            assert plus3[0] == (at(q['M0'],x,p)+at(q['M1'],x,p)*t)*pow(Q,-2,p)%p
            assert (at(q['L0'],x,p)+at(q['L1'],x,p)*t)%p==0
            assert at(q['H'],x,p)==0
            kind='ordinary'
        else:
            assert B in (trip,curve.neg(trip))
            assert at(q['H'],x,p)==0
            if B==trip:
                assert plus3==curve.mul(6,A)
                assert (at(q['L0'],x,p)+at(q['L1'],x,p)*t)%p==0
                changed=polys(d,(e+1)%p,p)
                assert at(changed['H'],x,p)==0
                assert (at(changed['L0'],x,p)+at(changed['L1'],x,p)*t)%p==0
                assert (plus3[0]-minus[0])%p!=((e+1)%p)
                kind='B=3A: denominator clearing loses target-gap condition'
            else:
                assert plus3 is None
                kind='B=-3A: target point is infinite'
        rows.append({'a_scalar':ka,'b_scalar':kb,'branch':kind,
                     'xA':str(x),'xB':str(b),'psi_nonzero':True,'Q_zero':Q==0})
    return rows


def small_curve(p,n,g):
    from itertools import combinations
    c=Curve(p,n,g)
    points=[None]+[c.mul(k) for k in range(1,n)]
    assert len(set(points))==n
    assert set(points[1:]) == {(x,y) for x in range(p) for y in range(p) if (y*y-x*x*x-7)%p==0}
    beta=next(k for k in range(2,p) if pow(k,3,p)==1)
    lam=points.index((beta*g[0]%p,g[1]))
    slopes={(sign*2*pow(lam,k,n))%n:k for k in range(3) for sign in (-1,1)}
    assert len(slopes)==6
    rootsets={r:[k for k in range(1,n) if points[k][0]%n==r] for r in range(1,p-n)}
    rootsets={r:s for r,s in rootsets.items() if len(s)==4}
    tests=0;hits=[]
    for ri,source in rootsets.items():
        for triple in combinations(source,3):
            pair=next(t for t in combinations(triple,2) if sum(t)%n==0)
            B=next(t for t in triple if t not in pair)
            for a,k in slopes.items():
                for shift in range(n):
                    tests+=1
                    target=[(a*q+shift)%n for q in triple]
                    if 0 in target:continue
                    rs={points[t][0]%n for t in target}
                    if len(rs)!=1 or 0 in rs:continue
                    if shift:
                        A=next(q for q in pair if (a*(q+B)+2*shift)%n==0)
                        minus,plus3=(A-B)%n,(3*A+B)%n
                        assert minus and plus3
                        x,b=points[A][0],points[B][0]
                        d=b-x
                        gap=(pow(beta,k,p)*points[plus3][0]%p)-(pow(beta,k,p)*points[minus][0]%p)
                        assert abs(d)==abs(gap)==n
                        e=gap*pow(pow(beta,k,p),-1,p)%p
                        q=polys(d,e,p)
                        t=points[A][1]*points[B][1]%p
                        assert at(q['H'],x,p)==0
                        if at(q['Q'],x,p):assert (at(q['L0'],x,p)+at(q['L1'],x,p)*t)%p==0
                        branch='nonzero translation'
                    else:
                        A=pair[0];x,b=points[A][0],points[B][0];d=b-x
                        gap=(pow(beta,k,p)*points[2*B%n][0]%p)-(pow(beta,k,p)*points[2*A%n][0]%p)
                        assert abs(d)==abs(gap)==n
                        e=gap*pow(pow(beta,k,p),-1,p)%p
                        q=polys(d,e,p)
                        assert at(q['Z'],x,p)==0
                        branch='zero translation'
                    hits.append({'source_r':ri,'target_r':next(iter(rs)),'source_triple':triple,
                        'slope':a,'shift':shift,'exponent':k,'branch':branch,'A':A,'B':B,
                        'source_gap':d,'target_gap':gap,'Q_zero':at(q['Q'],x,p)==0})
    controls=point_formula_controls(c,[(a,b) for a in range(1,min(n,12)) for b in (2*a,3*a,-3*a,7*a)])
    return {'p':p,'n':n,'generator':g,'beta':beta,'lambda':lam,
            'complete_six_slope_maps_tested':tests,'matches':hits,'point_formula_controls':controls}



def validate_certificate(cert, expected):
    stored=list(map(int,cert['coefficients_low_to_high']))
    assert stored==expected
    assert cert['degree']==len(expected)-1
    frob=plus(powmod([0,1],P,expected,P),[0,-1],P)
    assert frob==list(map(int,cert['X_to_p_minus_X_remainder']))
    factor=gcd(expected,frob,P)
    assert factor==list(map(int,cert['linear_factor_product']))
    roots=list(map(int,cert['all_field_roots']))
    reconstructed=[1]
    for x in roots:
        assert at(expected,x,P)==0
        reconstructed=times(reconstructed,[-x,1],P)
    assert reconstructed==factor and len(roots)==len(set(roots))
    return roots


def lift_both(x):
    f=(x*x*x+7)%P
    y=pow(f,(P+1)//4,P)
    return [(x,y),(x,-y%P)] if y*y%P==f else []


def branch(x,sign):
    xb=x+sign*N
    return 0<x<P and 0<xb<P and 0<x%N<P-N and x%N==xb%N


def filter_groups(roots,sign,k,target_sign,translation):
    c=Curve(P,N,G);beta=pow(pow(2,(P-1)//3,P),k,P);result=[]
    for x in roots:
        if not branch(x,sign):continue
        aa,bb=lift_both(x),lift_both(x+sign*N)
        candidates=[]
        for A in aa:
            for B in bb:
                if translation:
                    left=c.add(A,c.neg(B));right=c.add(c.mul(3,A),B)
                else:
                    left,right=c.mul(2,A),c.mul(2,B)
                if left is None or right is None:continue
                lx,rx=beta*left[0]%P,beta*right[0]%P
                if rx-lx!=target_sign*N or not 0<lx%N<P-N:continue
                assert lx%N==rx%N
                candidates.append({'A':list(map(str,A)),'B':list(map(str,B)),
                    'left_target_x':str(lx),'right_target_x':str(rx),'target_r':str(lx%N)})
        result.append({'source_x':str(x),'both_source_x_lift':bool(aa and bb),
                       'actual_group_candidates':candidates})
    return result


def audit_saved_certificates():
    saved=json.loads((HERE/'r19_even_slopes.json').read_text())
    beta=pow(2,(P-1)//3,P)
    assert int(saved['constants']['p'])==P and int(saved['constants']['n'])==N
    assert int(saved['constants']['beta'])==beta
    assert len(saved['cases'])==12
    assert {(r['endomorphism_exponent'],r['source_gap_sign'],r['target_gap_sign']) for r in saved['cases']}=={(k,a,b) for k in range(3) for a in (-1,1) for b in (-1,1)}
    rows=[]
    for r in saved['cases']:
        k,sign,ts=r['endomorphism_exponent'],r['source_gap_sign'],r['target_gap_sign']
        d=sign*N%P;e=ts*N*pow(pow(beta,k,P),-1,P)%P
        assert int(r['d_mod_p'])==d and int(r['e_mod_p'])==e
        q=polys(d,e,P)
        assert q['L0']==list(map(int,r['L0_coefficients']))
        assert q['L1']==list(map(int,r['L1_coefficients']))
        assert remainder(q['H'],times(q['Q'],q['Q'],P),P)==[0]
        hr=validate_certificate(r['nonzero_translation_certificate'],q['H'])
        zr=validate_certificate(r['zero_translation_certificate'],q['Z'])
        hf=filter_groups(hr,sign,k,ts,True);zf=filter_groups(zr,sign,k,ts,False)
        assert hf==r['nonzero_translation_source_branch']
        assert zf==r['zero_translation_source_branch']
        assert hf==zf==[]
        rows.append({'exponent':k,'source_sign':sign,'target_sign':ts,
            'H_degree':len(q['H'])-1,'H_roots':len(hr),'zero_degree':len(q['Z'])-1,
            'zero_roots':len(zr),'H_divisible_by_Q_squared':True,
            'independent_frobenius_gcds_match':True,'complete_root_products_match':True,
            'exact_source_branch_candidates':0})
    psiroots=validate_certificate(saved['tripling_denominator_certificate'],polys(N,1,P)['psi'])
    assert all(not lift_both(x) for x in psiroots)
    denominator=[]
    assert {r['source_gap_sign'] for r in saved['addition_denominator_certificates']}=={-1,1}
    for r in saved['addition_denominator_certificates']:
        sign=r['source_gap_sign'];q=polys(sign*N%P,1,P)
        roots=validate_certificate(r,q['Q'])
        good=[x for x in roots if branch(x,sign)]
        assert list(map(str,good))==r['roots_in_exact_source_branch']==[]
        denominator.append({'source_sign':sign,'Q_roots':len(roots),'source_branch_candidates':0})
    return {'cases':rows,'independent_certificates_checked':27,
            'tripling_denominator_roots':len(psiroots),'tripling_denominator_curve_lifts':0,
            'addition_denominator_cases':denominator}

def main():
    secp=point_formula_controls(Curve(P,N,G),[(a,b) for a in (1,2,7,19,43,97) for b in (2*a,3*a,-3*a,7*a)])
    small=[small_curve(43,31,(2,12)),small_curve(79,67,(1,18)),
           small_curve(163,139,(2,34)),small_curve(211,199,(3,33))]
    certificates=audit_saved_certificates()
    result={'evidence':'locally-reproduced','deployment_class':'unclassified',
            'scope':'Independent host polynomial / group audit; no Script or Core.',
            'secp_point_controls':secp,'toy_complete_cases':small,
            'independent_full_size_certificates':certificates,'all_assertions_passed':True}
    (HERE/'r19_even_slopes_audit.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'secp_controls':len(secp),'toy_counts':[(c['p'],c['complete_six_slope_maps_tested'],len(c['matches'])) for c in small]},indent=2))


if __name__=='__main__':main()
