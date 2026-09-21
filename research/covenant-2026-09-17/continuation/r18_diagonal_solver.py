#!/usr/bin/env python3
"""Two exact full-size candidate generators for R17's first predicate.

Bounded reverse exclusion, complete finite domains, and arithmetic checks.
No claimed random distribution, native witness, Core or library tests.
"""
import hashlib
import json
import math
from pathlib import Path

from r7_variable_der import interval,layout
from r11_endomorphism import N,P

C=2**248
E=2**256-N
DELTA=P-N
FLAGS=tuple(range(3,256,32))
HERE=Path(__file__).resolve().parent


class SquareRoots:
    def __init__(self,p):
        self.p=p;self.q=p-1;self.h=0
        while self.q%2==0:self.q//=2;self.h+=1
        self.nonresidue=2
        while pow(self.nonresidue,(p-1)//2,p)!=p-1:self.nonresidue+=1
        self.c=pow(self.nonresidue,self.q,p)

    def roots(self,d):
        p=self.p;d%=p
        if not d:return (0,)
        if pow(d,(p-1)//2,p)!=1:return ()
        x=pow(d,(self.q+1)//2,p);t=pow(d,self.q,p);c=self.c;m=self.h
        while t!=1:
            i=1;u=t*t%p
            while u!=1:u=u*u%p;i+=1
            assert i<m
            b=pow(c,1<<(m-i-1),p)
            x=x*b%p;c=b*b%p;t=t*c%p;m=i
        assert x*x%p==d
        return tuple(sorted({x,(-x)%p}))


def quadratic_roots(A,D,target,modulus,rooter):
    discriminant=(D*D+4*A*target)%modulus
    inverse=pow(2*A,-1,modulus)
    roots=tuple(sorted({(-D+y)*inverse%modulus for y in rooter.roots(discriminant)}))
    assert all((A*r*r+D*r-target)%modulus==0 for r in roots)
    return roots


def inverse_power_two(A,D,target,bits):
    """Unique root A*r²+D*r=target mod2^bits; A even and D odd."""
    assert A%2==0 and D%2==1
    r=target%2;precision=1
    while precision<bits:
        precision=min(2*precision,bits);modulus=1<<precision
        r=(r-(A*r*r+D*r-target)*pow(2*A*r+D,-1,modulus))%modulus
    assert (A*r*r+D*r-target)%(1<<bits)==0
    return r


def four_lifts(r):
    if not 0<r<DELTA:return False
    for x in (r,r+N):
        y=pow((x*x*x+7)%P,(P+1)//4,P)
        if y*y%P!=(x*x*x+7)%P:return False
    return True


def arithmetic_audits():
    square_cases=0
    for p in (5,13,17,41):
        rooter=SquareRoots(p)
        for d in range(p):
            assert set(rooter.roots(d))=={x for x in range(p) if x*x%p==d}
            square_cases+=1
    rooter=SquareRoots(17);quadratics=0
    for A in range(1,17):
        for D in range(17):
            for target in range(17):
                assert set(quadratic_roots(A,D,target,17,rooter))=={r for r in range(17) if (A*r*r+D*r-target)%17==0}
                quadratics+=1
    hensel_cases=0
    for A in (2,16,128):
        for D in FLAGS:
            image={ (A*r*r+D*r)%256:r for r in range(256)}
            assert len(image)==256
            for target in range(256):
                assert inverse_power_two(A,D,target,8)==image[target]
                hensel_cases+=1
    return {'complete_square_root_residues':square_cases,'complete_quadratic_configurations':quadratics,
            'complete_power_two_inverse_configurations':hensel_cases,'all_checks_pass':True}


def domains():
    rows=[];total_k=0;forward=0
    for nr in range(1,18):
        ns=25-nr;lo,hi=interval(nr);hi=min(hi,DELTA-1)
        for flag in FLAGS:
            A,D=layout(32,nr,ns,flag)
            # C*rho=r*(D+A*r)+k*n. Its right polynomial is increasing in r.
            lower=C-hi*(D+A*hi)
            upper=C*(DELTA-1)-lo*(D+A*lo)
            kmin=-((-lower)//N);kmax=upper//N
            assert kmin<=kmax
            count=kmax-kmin+1;total_k+=count;forward+=hi-lo+1
            rows.append({'r_bytes':nr,'s_bytes':ns,'flag':flag,'A':A,'D':D,
                'r_min':lo,'r_max':hi,'quotient_min':kmin,'quotient_max':kmax,'quotient_count':count})
    assert forward==len(FLAGS)*(DELTA-1)
    return rows,{'flags':list(FLAGS),'layout_flag_rows':len(rows),
        'complete_forward_candidates':str(forward),'complete_forward_log2':math.log2(forward),
        'complete_rho_reverse_quadratics':str(len(rows)*(DELTA-1)),
        'complete_rho_reverse_log2':math.log2(len(rows)*(DELTA-1)),
        'complete_quotient_inverse_candidates':str(total_k),'complete_quotient_inverse_log2':math.log2(total_k),
        'scope':'Exact domain sizes before target-lift filtering; not expected effort or lower bounds. Each candidate costs different big-integer operations.'}


def reverse_certificate(rows,rho_max=256):
    rooter=SquareRoots(N);transcript=hashlib.sha256();cases=0;residue_cases=0;root_count=0
    source_domain_hits=[];lift_hits=[];per_width={nr:0 for nr in range(1,18)}
    target_four={rho:four_lifts(rho) for rho in range(1,rho_max+1)}
    for row in rows:
        A,D=row['A'],row['D'];inv2A=pow(2*A,-1,N)
        for rho in range(1,rho_max+1):
            discriminant=(D*D+4*A*C*rho)%N
            squares=rooter.roots(discriminant)
            roots=tuple(sorted({(-D+t)*inv2A%N for t in squares}))
            cases+=1;residue_cases+=bool(roots);root_count+=len(roots);per_width[row['r_bytes']]+=len(roots)
            transcript.update(bytes([row['r_bytes'],row['flag']])+rho.to_bytes(2,'big')+bytes([len(roots)]))
            for r in roots:
                assert (A*r*r+D*r-C*rho)%N==0
                transcript.update(r.to_bytes(32,'big'))
                if row['r_min']<=r<=row['r_max']:
                    hit={'r':str(r),'rho':rho,'r_bytes':row['r_bytes'],'flag':row['flag']}
                    source_domain_hits.append(hit)
                    if target_four[rho] and four_lifts(r):lift_hits.append(hit)
    assert not source_domain_hits
    return {'rho_min':1,'rho_max':rho_max,'all_source_r_in_all_valid_layouts_covered':True,
        'flags':list(FLAGS),'quadratic_cases':cases,'quadratic_cases_with_roots':residue_cases,
        'returned_mod_n_roots':root_count,'roots_per_source_byte_width':per_width,
        'source_r_DER_and_Delta_hits':source_domain_hits,'four_lift_hits':lift_hits,
        'target_rhos_with_four_roots':sum(target_four.values()),
        'ordered_root_transcript_sha256':transcript.hexdigest(),
        'order_mod4':N%4,'order_minus_one_two_adic_valuation':rooter.h,
        'fixed_quadratic_nonresidue':rooter.nonresidue,
        'scope':'Exact exclusion for rho1..256 and listed constant-SINGLE flags, every valid source r. Not an exclusion for larger rho.'}


def quotient_checks(rows):
    tested=0;hits=[];endpoint_checks=0
    for row in rows:
        A,D=row['A'],row['D']
        samples={row['quotient_min'],row['quotient_max'],(row['quotient_min']+row['quotient_max'])//2}
        for k in sorted(samples):
            r=inverse_power_two(A,D,E*k,248)
            numerator=r*(D+A*r)+k*N
            assert numerator%C==0
            rho=numerator//C;tested+=1
            if row['r_min']<=r<=row['r_max'] and 1<=rho<DELTA:
                assert rho==r*(D+A*r)*pow(C,-1,N)%N
                hits.append({'r':str(r),'rho':str(rho),'flag':row['flag'],'r_bytes':row['r_bytes']})
        # Independently map admissible r endpoints forward. If a positive
        # short rho occurred, its quotient must be in the full interval and
        # the inverse must reproduce r exactly (r<C).
        for r in (row['r_min'],row['r_max']):
            rho=r*(D+A*r)*pow(C,-1,N)%N
            k=(C*rho-r*(D+A*r))//N
            assert inverse_power_two(A,D,E*k,248)==r
            if 1<=rho<DELTA:assert row['quotient_min']<=k<=row['quotient_max']
            endpoint_checks+=1
    return {'full_size_sampled_quotients':tested,'sampled_valid_first_predicate_hits':hits,
        'full_size_forward_inverse_endpoint_checks':endpoint_checks,
        'sample_is_not_complete_quotient_domain':True}


def main():
    rows,costs=domains()
    report={'evidence':'locally-reproduced','deployment_class':'unclassified',
        'question':'Exact reverse candidate generation for rho=r*(D+A*r)/C in the two short r intervals.',
        'constants':{'p':str(P),'n':str(N),'C':str(C),'E_2_256_minus_n':str(E),'Delta_p_minus_n':str(DELTA)},
        'audits':arithmetic_audits(),'complete_domain_costs':costs,
        'bounded_reverse_certificate':reverse_certificate(rows),
        'quotient_inverse_checks':quotient_checks(rows),
        'quotient_rows':[{k:str(v) if k not in ('r_bytes','s_bytes','flag') else v for k,v in row.items()} for row in rows],
        'midpoint_and_q_stage_reached':False,'point_log_distribution_assumed':False,
        'hash_preimages_obtained':0,'new_script_or_witness':False,'general_impossibility_claim':False}
    output=HERE/'r18_diagonal_solver.json';output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'output':str(output),'costs':costs,'reverse':report['bounded_reverse_certificate'],
        'quotient_checks':report['quotient_inverse_checks']},indent=2))


if __name__=='__main__':main()
