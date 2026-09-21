#!/usr/bin/env python3
"""Finite-field elimination for three-root affine endomorphism transports.

Exact host mathematics only. No Script, native hash witness or Core claim.
"""
import json
from pathlib import Path
import sys

from r11_endomorphism import P, N, GAP, BETA, LAMBDA, add, mul, lift, neg
from r9_four_roots import (polynomial_multiply as pmul,
                          polynomial_subtract as psub,
                          polynomial_trim as trim,
                          polynomial_powmod as ppow,
                          polynomial_gcd as pgcd, fully_split_roots)

HERE = Path(__file__).resolve().parent
T = [0, -56, 0, 0, 1]
U = [28, 0, 0, 4]
TT, TU, UU = pmul(T,T), pmul(T,U), pmul(U,U)


def evaluate(poly, x):
    out = 0
    for c in reversed(poly):
        out = (out*x+c) % P
    return out


def lincomb(terms):
    out = [0]*max(len(poly) for _, poly in terms)
    for scalar, poly in terms:
        for j, value in enumerate(poly):
            out[j] = (out[j]+scalar*value) % P
    return trim(out)


def fg(x, d, e):
    # Clear duplication denominators in K(x,x+d,F(y)), K(y,y+e,F(x)).
    middle = x*(x+d)*(2*x+d)+14
    last = x*x*(x+d)**2-28*(2*x+d)
    f = lincomb([(d*d,TT), (-2*middle,TU), (last,UU)])
    tx, ux = evaluate(T,x), evaluate(U,x)
    g = trim([e*e*tx*tx-28*tx*ux-28*e*ux*ux,
              -2*e*e*tx*ux-56*ux*ux,
              -6*e*tx*ux+e*e*ux*ux,
              -4*tx*ux+2*e*ux*ux, ux*ux])
    return f, g


def determinant(matrix):
    a = [[v % P for v in row] for row in matrix]
    value = 1
    for col in range(len(a)):
        pivot = next((i for i in range(col,len(a)) if a[i][col]), None)
        if pivot is None:
            return 0
        if pivot != col:
            a[pivot], a[col] = a[col], a[pivot]
            value = -value
        v = a[col][col]
        value = value*v % P
        inv = pow(v,-1,P)
        for i in range(col+1,len(a)):
            ratio = a[i][col]*inv % P
            for j in range(col+1,len(a)):
                a[i][j] = (a[i][j]-ratio*a[col][j]) % P
            a[i][col] = 0
    return value


def resultant_value(x, d, e):
    f, g = fg(x,d,e)
    f = list(reversed(f+[0]*(9-len(f))))
    g = list(reversed(g+[0]*(5-len(g))))
    matrix = [[0]*i+f+[0]*(3-i) for i in range(4)]
    matrix += [[0]*i+g+[0]*(7-i) for i in range(8)]
    assert all(len(row)==12 for row in matrix)
    return determinant(matrix)


def interpolate_consecutive(values):
    differences = list(values)
    coefficients = [differences[0]]
    while len(differences)>1:
        differences = [(b-a)%P for a,b in zip(differences,differences[1:])]
        coefficients.append(differences[0])
    out, falling, factorial = [0], [1], 1
    for k,value in enumerate(coefficients):
        if k:
            falling = pmul(falling,[-(k-1),1])
            factorial = factorial*k % P
        out = lincomb([(1,out),(value*pow(factorial,-1,P),falling)])
    assert all(evaluate(out,i)==v for i,v in enumerate(values))
    return out


def coordinate_vectors():
    rows = []
    for ka,kb in ((1,2),(1,7),(7,19),(19,43),(43,97),(123,257)):
        a,b = mul(ka),mul(kb)
        c = mul(pow(2,-1,N),add(a,neg(b)))
        dpt = add(c,neg(mul(2,a)))
        assert a and b and c and dpt
        dx = (b[0]-a[0])%P
        dy = (dpt[0]-c[0])%P
        f,g = fg(a[0],dx,dy)
        assert evaluate(f,c[0])==evaluate(g,c[0])==0
        assert add(a,neg(mul(2,c)))==b
        assert mul(2,a)[0]==evaluate(T,a[0])*pow(evaluate(U,a[0]),-1,P)%P
        rows.append({'a_scalar':ka,'b_scalar':kb,'xA':str(a[0]),'xB':str(b[0]),
                     'xC':str(c[0]),'xD':str(dpt[0]),'both_K_polynomials_zero':True})
    return rows


def solve_case(exponent, source_sign, target_sign):
    beta = pow(BETA,exponent,P)
    d = source_sign*N % P
    e = target_sign*N*pow(beta,-1,P) % P
    values = [resultant_value(x,d,e) for x in range(81)]
    resultant = interpolate_consecutive(values)
    assert resultant != [0] and len(resultant)<=81
    # Additional check points supplement the proved degree <=80 bound.
    audits = [82,97,257,N-1,N+1,P-1]
    assert all(evaluate(resultant,x)==resultant_value(x,d,e) for x in audits)
    remainder = psub(ppow([0,1],P,resultant),[0,1])
    factor = pgcd(resultant,remainder)
    roots, splitting = fully_split_roots(factor)
    in_branch = []
    for x in roots:
        xb = x+source_sign*N
        if not (0<x<P and 0<xb<P and 0<x%N<GAP and x%N==xb%N):
            continue
        f,g = fg(x,d,e)
        common = pgcd(f,g)
        yr = pgcd(common,psub(ppow([0,1],P,common),[0,1]))
        ys,_ = fully_split_roots(yr)
        candidates = []
        for y in ys:
            yd=(y+e)%P
            cy,dy=beta*y%P,beta*yd%P
            if dy-cy != target_sign*N:
                continue
            aa,bb,cc=lift(x),lift(xb),lift(y)
            if aa is None or bb is None or cc is None:
                continue
            for a in (aa,neg(aa)):
                for c in (cc,neg(cc)):
                    b=add(a,neg(mul(2,c)))
                    dpt=add(c,neg(mul(2,a)))
                    if b and dpt and b[0]==xb and dpt[0]==yd:
                        candidates.append({'A':list(map(str,a)),'B':list(map(str,b)),
                                           'C':list(map(str,c)),'D':list(map(str,dpt))})
        in_branch.append({'x':str(x),'second_polynomial_field_roots':list(map(str,ys)),
                          'actual_group_candidates':candidates})
    return {'endomorphism_exponent':exponent,'source_integer_gap_sign':source_sign,
            'target_integer_gap_sign':target_sign,'delta_source_mod_p':str(d),
            'delta_target_before_endomorphism_mod_p':str(e),
            'resultant_degree_bound':80,'interpolation_values':list(map(str,values)),
            'resultant_coefficients_low_to_high':list(map(str,resultant)),
            'actual_resultant_degree':len(resultant)-1,'extra_determinant_check_points':list(map(str,audits)),
            'X_to_p_minus_X_remainder':list(map(str,remainder)),
            'linear_factor_product':list(map(str,factor)), 'field_roots':list(map(str,roots)),
            'splitting':splitting,'exact_source_branch_candidates':in_branch}


def main():
    rows=[]
    for exponent in range(3):
        for source_sign in (-1,1):
            for target_sign in (-1,1):
                row=solve_case(exponent,source_sign,target_sign)
                rows.append(row)
                print(json.dumps({'exponent':exponent,'source_sign':source_sign,
                                  'target_sign':target_sign,'resultant_degree':row['actual_resultant_degree'],
                                  'field_roots':len(row['field_roots']),
                                  'source_branch':len(row['exact_source_branch_candidates'])}),flush=True)
    report={'evidence':'locally-reproduced','deployment_class':'unclassified',
            'question':'Can any nonzero translation with slope +/-lambda^k map three recovery roots to three recovery roots?',
            'constants':{'p':str(P),'n':str(N),'p_minus_n':str(GAP),
                         'beta':str(BETA),'lambda':str(LAMBDA)},
            'coordinate_formula_vectors':coordinate_vectors(),'cases':rows,
            'all_nonzero_translation_candidates':sum(len(x['actual_group_candidates']) for row in rows for x in row['exact_source_branch_candidates']),
            'script_or_Core_execution':False,'complete_covenant':False}
    (HERE/'r18_endomorphism_resultant.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
