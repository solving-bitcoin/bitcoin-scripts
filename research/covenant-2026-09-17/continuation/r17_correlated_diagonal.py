#!/usr/bin/env python3
"""Exact necessary conditions for raw-DER alpha equal to its native hash.

No chosen hash outputs, scalar projection, signature witness or Core claim.
The scan excludes a bounded slice of the exceptional all-s family only.
"""
from fractions import Fraction
import json
import math
from pathlib import Path

from r7_variable_der import blob, interval, layout
from r11_endomorphism import N,P
from r16_three_key_support import der_probability

C=2**248
DELTA=P-N
HERE=Path(__file__).resolve().parent


def check_affine_bytes():
    checks=0
    for nr in range(1,18):
        ns=25-nr
        low,high=interval(nr);high=min(high,DELTA-1)
        if low>high:continue
        slo,shi=interval(ns)
        for flag in (0,3,35,131,227,255):
            A,D=layout(32,nr,ns,flag)
            for r in {low,high,(low+high)//2}:
                for s in {slo,shi,(slo+shi)//2}:
                    alpha=blob(r,s,flag)
                    Z0=D+A*r
                    assert len(alpha)==32
                    assert int.from_bytes(alpha,'big')==Z0+256*s<N
                    assert 0<Z0<N
                    checks+=1
    return checks


def scalar_lemma():
    """Independent exhaustive solution sets for the scalar equation.

    v includes zero to cover the matched center. Nonzero C,r,rho are fixed
    in each configuration; every z0 and every s is enumerated modulo n.
    These are scalar identities, not small-curve/hash fixtures.
    """
    results=[]
    for n in (5,7,11):
        Ctoy=2%n;configs=0;degenerate=0;single=0;empty=0
        for r in range(1,n):
            for rho in range(1,n):
                for z0 in range(n):
                    for v in range(n):
                        direct={s for s in range(n) if (rho*(Ctoy-s*v)-r*(z0+256*s))%n==0}
                        L=(256*r+rho*v)%n;R=(Ctoy*rho-r*z0)%n
                        predicted=({R*pow(L,-1,n)%n} if L else (set(range(n)) if not R else set()))
                        assert direct==predicted
                        configs+=1
                        if len(direct)==n:degenerate+=1
                        elif direct:single+=1
                        else:empty+=1
        results.append({'prime_modulus':n,'constant_C':Ctoy,'configurations':configs,
            'all_s_configurations':degenerate,'one_s_configurations':single,
            'no_s_configurations':empty,'all_solution_sets_agree':True})
    return results


def scan_exceptional_small_r():
    invC=pow(C,-1,N);rows=[];total=0
    for nr in (1,2):
        ns=25-nr;rlo,rhi=interval(nr);A,D=layout(32,nr,ns,0)
        minimum=N;argmin=None;hits=[];constant_flags_hits=[];count=0
        for r in range(rlo,rhi+1):
            # rho(f)=r*(D+A*r+f)/C mod n. This recurrence visits all flags.
            rho=r*(D+A*r)*invC%N;step=r*invC%N
            for flag in range(256):
                if rho<minimum:minimum=rho;argmin={'r':r,'flag':flag}
                if 0<rho<DELTA:
                    hit={'r':r,'flag':flag,'rho':str(rho)};hits.append(hit)
                    if flag&31==3:constant_flags_hits.append(hit)
                if flag in (0,255):assert rho==r*(D+A*r+flag)*invC%N
                rho=(rho+step)%N;count+=1
        assert not hits
        rows.append({'r_der_bytes':nr,'s_der_bytes':ns,'r_min':rlo,'r_max':rhi,
            'flags_per_r':256,'candidate_pairs':count,'rho_below_delta':hits,
            'constant_SINGLE_flag_hits':constant_flags_hits,'minimum_rho':str(minimum),
            'minimum_rho_log2':math.log2(minimum),'minimum_at':argmin,
            'all_s_in_entire_canonical_interval_excluded_for_exceptional_family':True})
        total+=count
    return {'complete_candidate_pairs':total,'r_min':1,'r_max':32767,'rows':rows,
        'scope':'Only exceptional full-s families satisfying rho=r*Z0/C. Does not exclude ordinary one-s solutions, larger r, other source constants, or general covenants.'}


def main():
    pshort,_=der_probability(DELTA-1)
    # At most one flag per fixed r and mixed midpoint; at most four midpoints.
    exceptional_format_bound=pshort*Fraction(4,256)
    report={'evidence':'locally-reproduced','deployment_class':'unclassified',
        'question':'Can correlated alpha=actual native ALL hash share three keys at constant C without an independent-answer assumption?',
        'constant_C':str(C),'group_order':str(N),'delta':str(DELTA),
        'byte_layout':'alpha=DER(r,s)||flag, 32 bytes; z=int_big_endian(alpha)=Z0+256*s; Z0=D+2^(8*(sbytes+3))*r',
        'positive_canonical_layout_checks':check_affine_bytes(),
        'necessary_center_equation':'rho*(C-s*v)=r*(Z0+256*s)',
        'linear_s_equation':'s*(256*r+rho*v)=C*rho-r*Z0 (mod n)',
        'exceptional_full_s_condition':['rho=r*Z0/C mod n','v=-256*C/Z0 mod n'],
        'public_point_predicate':'Z0*V+256*C*G=O; no discrete logarithm required to check this predicate',
        'conditional_complete_family':{'required_fixed_q':'q nonzero; the three points ((rho/r)*U+256*G)/q for source U in (A,-A,B) must be distinct recovery roots at r=rho',
            'target_s':'q*s mod n, optionally normalized to LOW_S by negation',
            'finite_keys':'exclude any s yielding an infinity common key',
            'raw_hash_and_third_key_geometry_obtained':False},
        'scalar_lemma_exhaustion':scalar_lemma(),
        'exceptional_small_r_scan':scan_exceptional_small_r(),
        'all_flags_exceptional_raw_format_mass_upper_bound':str(exceptional_format_bound),
        'all_flags_exceptional_raw_format_mass_upper_bound_log2':math.log2(exceptional_format_bound),
        'format_bound_scope':'Only the exceptional all-s branch; grants every midpoint and skips small-rho/third-key tests. Deterministic accepted-string counting, not point-log randomness or a bound for the ordinary branch.',
        'native_hash_preimages_obtained':0,'positive_secp256k1_diagonal_witnesses':0,
        'script_metrics':'Not applicable: no new script or witness.',
        'no_hash_projection':True,'no_chosen_hash_outputs_assumed':True,
        'general_impossibility_claim':False}
    target=HERE/'r17_correlated_diagonal.json'
    target.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'output':str(target),'byte_checks':report['positive_canonical_layout_checks'],
        'scan_cases':report['exceptional_small_r_scan']['complete_candidate_pairs'],
        'small_r_exceptional_hits':0,'ordinary_branch_excluded':False},indent=2))


if __name__=='__main__':main()
