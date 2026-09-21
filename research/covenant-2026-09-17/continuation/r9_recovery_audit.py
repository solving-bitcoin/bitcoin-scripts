#!/usr/bin/env python3
"""Independent matrix certificate for every possible four-root exception.

Uses no polynomial gcd, modular-polynomial powering, or factor-splitting code
from r9_four_roots. No Bitcoin Core or repository field tests.
"""
import hashlib
import itertools
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
P=2**256-2**32-977
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def mm(a,b):
    n=len(a)
    columns=list(zip(*b))
    return [[sum(x*y for x,y in zip(row,col))%P for col in columns] for row in a]


def mpow(a,k):
    result=[[int(i==j) for j in range(len(a))] for i in range(len(a))]
    while k:
        if k&1: result=mm(result,a)
        a=mm(a,a)
        k//=2
    return result


def rank(matrix):
    a=[r[:] for r in matrix]
    row=0
    for col in range(len(a[0])):
        pivot=next((j for j in range(row,len(a)) if a[j][col]),None)
        if pivot is None: continue
        a[row],a[pivot]=a[pivot],a[row]
        inv=pow(a[row][col],-1,P)
        a[row]=[x*inv%P for x in a[row]]
        for j in range(len(a)):
            if j != row:
                factor=a[j][col]
                a[j]=[(x-factor*y)%P for x,y in zip(a[j],a[row])]
        row+=1
        if row==len(a): break
    return row,a


def convolution(a,b):
    out=[0]*(len(a)+len(b)-1)
    for i,x in enumerate(a):
        for j,y in enumerate(b): out[i+j]+=x*y
    return out


def matrix_certificates(source):
    # Independent integer expansion of numerator 8(x^3+7)(x^6+140x^3-392)
    # and denominator (3x^4+84x)^2 of x-x(3P).
    numerator=[8*x for x in convolution([7,0,0,1],[-392,0,0,140,0,0,1])]
    denominator=convolution([0,84,0,0,3],[0,84,0,0,3])+[0]
    records=[]
    for item in source['all_r_tripling_check']['polynomials']:
        sign=item['sign']
        coefficients=[(a+sign*N*b)%P for a,b in zip(numerator,denominator)]
        assert coefficients==[int(x,16) for x in item['polynomial_coefficients_low_to_high']]
        # Multiplication-by-X matrix of Fp[X]/(F), basis 1,X,...,X^8.
        dimension=9
        matrix=[[0]*dimension for _ in range(dimension)]
        for j in range(dimension-1): matrix[j+1][j]=1
        inverse=pow(coefficients[-1],-1,P)
        for i in range(dimension): matrix[i][-1]=-coefficients[i]*inverse%P
        powered=mpow(matrix,P)
        operator=[[(a-b)%P for a,b in zip(ra,rb)] for ra,rb in zip(powered,matrix)]
        matrix_rank,rref=rank(operator)
        kernel_dimension=dimension-matrix_rank
        roots=[int(x,16) for x in item['all_field_roots']]
        assert kernel_dimension==len(roots)==len(set(roots))
        for root in roots:
            assert sum(c*pow(root,i,P) for i,c in enumerate(coefficients))%P==0
        # kernel dimension = deg gcd(F,X^p-X) = number of distinct Fp roots.
        # Thus the roots above exhaust all possible roots without using gcd.
        lower,upper=(1,P-N-1) if sign==1 else (N+1,P-1)
        assert all(not lower<=x<=upper for x in roots)
        remainder=[operator[i][0] for i in range(dimension)]
        while len(remainder)>1 and remainder[-1]==0: remainder.pop()
        assert remainder==[int(x,16) for x in item['frobenius_remainder_low_to_high']]
        records.append({'sign':sign,'matrix_rank':matrix_rank,
                        'kernel_dimension_and_complete_root_count':kernel_dimension,
                        'complete_roots':list(map(hex,roots)),
                        'eligible_interval':[hex(lower),hex(upper)],
                        'operator_matrix':[[hex(x) for x in r] for r in operator],
                        'operator_reduced_row_echelon':[[hex(x) for x in r] for r in rref]})
    return records


def translation_checks():
    cases=large_overlaps=0
    for prime in (7,11,13,17,19):
        for a,b in itertools.combinations(range(1,(prime+1)//2),2):
            points={a,-a%prime,b,-b%prime}
            assert len(points)==4
            tripling_related=(3*a%prime in (b,-b%prime) or 3*b%prime in (a,-a%prime))
            observed=False
            for shift in range(1,prime):
                overlap=len(points & {(x+shift)%prime for x in points})
                cases+=1
                if overlap>=3:
                    observed=True
                    large_overlaps+=1
                    half=shift*pow(2,-1,prime)%prime
                    assert points=={half,-half%prime,3*half%prime,-3*half%prime}
            assert observed==tripling_related
    return {'tested_set_shift_pairs':cases,'nonzero_translations_with_overlap_at_least_three':large_overlaps}


def main():
    path=HERE/'r9_four_roots.json'
    source=json.loads(path.read_text())
    report={'evidence':'locally-reproduced','deployment_class':'unclassified',
            'scope':'Independent exact host certificate audit; no Script or Core execution.',
            'source_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
            'matrix_certificates':matrix_certificates(source),
            'small_group_translation_checks':translation_checks(),
            'all_expectations_met':True}
    Path(__file__).with_suffix('.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'root_counts':[x['kernel_dimension_and_complete_root_count'] for x in report['matrix_certificates']],
                      'matrix_ranks':[x['matrix_rank'] for x in report['matrix_certificates']],
                      'small_group_checks':report['small_group_translation_checks']},indent=2))


if __name__=='__main__':
    main()
