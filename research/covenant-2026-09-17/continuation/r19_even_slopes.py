#!/usr/bin/env python3
"""Complete degree-bounded root tests for doubled endomorphism slopes.

Standalone host curve mathematics. No Script, Core or library field tests.
"""
import json
import math
from pathlib import Path

from r11_endomorphism import P, N, GAP, BETA, LAMBDA, G, add, mul, lift, neg
from r9_four_roots import (polynomial_multiply as pmul, polynomial_subtract as psub,
                          polynomial_trim as trim, polynomial_gcd as pgcd,
                          polynomial_powmod as ppow, fully_split_roots)

HERE=Path(__file__).resolve().parent
X=[0,1]
PSI=[0,84,0,0,3]
D3=pmul(PSI,PSI)
N3=[21952,0,0,2352,0,0,-672,0,0,1]
T=[0,-56,0,0,1]
U=[28,0,0,4]


def scale(a,c):return trim([c*v for v in a])
def plus(a,b):return psub(a,scale(b,-1))
def derivative(a):return trim([i*a[i] for i in range(1,len(a))])
def ev(a,x):
    out=0
    for v in reversed(a):out=(out*x+v)%P
    return out


Y=psub(pmul(derivative(N3),PSI),scale(pmul(N3,derivative(PSI)),2))


def shift(poly,d):
    out=[0]*len(poly)
    for i,value in enumerate(poly):
        for j in range(i+1):out[j]=(out[j]+value*math.comb(i,j)*pow(d,i-j,P))%P
    return trim(out)


def polynomials(d,e):
    b=[d,1]
    q=psub(pmul(b,D3),N3)
    q2=pmul(q,q)
    m=plus(pmul(pmul(X,b),plus(X,b)),[14])
    nplus=plus(pmul(pmul(b,N3),plus(pmul(b,D3),N3)),scale(pmul(D3,D3),14))
    l0=psub(scale(nplus,d*d),pmul(plus(m,[e*d*d%P]),q2))
    l1=psub(scale(pmul(Y,PSI),-2*pow(3,-1,P)*d*d),scale(q2,2))
    curve_product=pmul([7,0,0,1],plus(pmul(pmul(b,b),b),[7]))
    h=psub(pmul(l0,l0),pmul(pmul(l1,l1),curve_product))
    zero=psub(psub(pmul(shift(T,d),U),pmul(T,shift(U,d))),scale(pmul(U,shift(U,d)),e))
    assert len(l0)<=22 and len(l1)<=19 and len(h)<=43 and len(zero)<=8
    return {'L0':l0,'L1':l1,'H':h,'Q':q,'zero_translation':zero}


def certificate(poly):
    assert poly != [0]
    remainder=psub(ppow(X,P,poly),X)
    factor=pgcd(poly,remainder)
    roots,trials=fully_split_roots(factor)
    return {'coefficients_low_to_high':list(map(str,poly)), 'degree':len(poly)-1,
            'X_to_p_minus_X_remainder':list(map(str,remainder)),
            'linear_factor_product':list(map(str,factor)),
            'all_field_roots':list(map(str,roots)),'splitting':trials}


def in_branch(x,sign):
    xb=x+sign*N
    return 0<x<P and 0<xb<P and 0<x%N<GAP and x%N==xb%N


def check_roots(cert,sign,k,target_sign,translation):
    beta=pow(BETA,k,P)
    result=[]
    for xtext in cert['all_field_roots']:
        x=int(xtext)
        if not in_branch(x,sign):continue
        aa,bb=lift(x),lift(x+sign*N)
        candidates=[]
        if aa is not None and bb is not None:
            for a in (aa,neg(aa)):
                for b in (bb,neg(bb)):
                    if translation:
                        left=add(a,neg(b));right=add(mul(3,a),b)
                    else:
                        left,right=mul(2,a),mul(2,b)
                    if left is None or right is None:continue
                    lx,rx=beta*left[0]%P,beta*right[0]%P
                    if rx-lx==target_sign*N and 0<lx%N<GAP:
                        candidates.append({'A':list(map(str,a)),'B':list(map(str,b)),
                                           'left_target_x':str(lx),'right_target_x':str(rx),
                                           'target_r':str(lx%N)})
        result.append({'source_x':xtext,'both_source_x_lift':aa is not None and bb is not None,
                       'actual_group_candidates':candidates})
    return result


def formula_vectors():
    rows=[]
    for ka,kb in ((1,2),(1,7),(7,19),(19,43),(43,97),(123,257),(257,123)):
        a,b=mul(ka),mul(kb);three=mul(3,a)
        x=a[0];xb=b[0];d=(xb-x)%P;t=a[1]*b[1]%P
        ps=ev(PSI,x);den=ev(D3,x);num=ev(N3,x);yy=ev(Y,x)
        assert num*pow(den,-1,P)%P==three[0]
        assert yy*pow(3*ps**3,-1,P)*a[1]%P==three[1]
        minus,tripplus=add(a,neg(b)),add(three,b)
        q=(xb*den-num)%P
        assert d and q and minus and tripplus
        xm=(x*xb*(x+xb)+14+2*t)*pow(d*d,-1,P)%P
        xp=(xb*num*(xb*den+num)+14*den*den-2*pow(3,-1,P)*yy*ps*t)*pow(q*q,-1,P)%P
        assert xm==minus[0] and xp==tripplus[0]
        polys=polynomials(d,(xp-xm)%P)
        assert (ev(polys['L0'],x)+ev(polys['L1'],x)*t)%P==0
        assert ev(polys['H'],x)==0
        e0=(mul(2,b)[0]-mul(2,a)[0])%P
        assert ev(polynomials(d,e0)['zero_translation'],x)==0
        rows.append({'a_scalar':ka,'b_scalar':kb,'xA':str(x),'xB':str(xb),
                     'x_A_minus_B':str(xm),'x_3A_plus_B':str(xp),
                     'tripling_coordinates_and_linear_t_equation_checked':True})
    return rows


def main():
    exceptions=[]
    psi=certificate(PSI)
    psi['roots_lifting_to_curve']=[r for r in psi['all_field_roots'] if lift(int(r)) is not None]
    assert not psi['roots_lifting_to_curve']
    for sign in (-1,1):
        q=certificate(polynomials(sign*N%P,1)['Q'])
        q['source_gap_sign']=sign
        q['roots_in_exact_source_branch']=[r for r in q['all_field_roots'] if in_branch(int(r),sign)]
        exceptions.append(q)
    rows=[]
    for k in range(3):
        for sign in (-1,1):
            for target_sign in (-1,1):
                d=sign*N%P;e=target_sign*N*pow(pow(BETA,k,P),-1,P)%P
                polys=polynomials(d,e)
                nonzero=certificate(polys['H']);zero=certificate(polys['zero_translation'])
                row={'endomorphism_exponent':k,'source_gap_sign':sign,'target_gap_sign':target_sign,
                     'd_mod_p':str(d),'e_mod_p':str(e),
                     'L0_coefficients':list(map(str,polys['L0'])),
                     'L1_coefficients':list(map(str,polys['L1'])),
                     'nonzero_translation_certificate':nonzero,'zero_translation_certificate':zero,
                     'nonzero_translation_source_branch':check_roots(nonzero,sign,k,target_sign,True),
                     'zero_translation_source_branch':check_roots(zero,sign,k,target_sign,False)}
                rows.append(row)
                print(json.dumps({'k':k,'source_sign':sign,'target_sign':target_sign,
                    'H_degree':nonzero['degree'],'H_field_roots':len(nonzero['all_field_roots']),
                    'H_source_branch':len(row['nonzero_translation_source_branch']),
                    'zero_degree':zero['degree'],'zero_field_roots':len(zero['all_field_roots']),
                    'zero_source_branch':len(row['zero_translation_source_branch'])}),flush=True)
    report={'evidence':'locally-reproduced','deployment_class':'unclassified',
        'question':'Complete affine three-root transport test for slopes +/-2*lambda^k, including zero translation.',
        'constants':{'p':str(P),'n':str(N),'delta':str(GAP),'beta':str(BETA),'lambda':str(LAMBDA)},
        'formula_vectors':formula_vectors(),'tripling_denominator_certificate':psi,
        'addition_denominator_certificates':exceptions,'cases':rows,
        'new_Script_or_Core_execution':False,'complete_covenant':False}
    (HERE/'r19_even_slopes.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
