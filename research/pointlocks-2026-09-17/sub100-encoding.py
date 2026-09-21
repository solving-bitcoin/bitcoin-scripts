#!/usr/bin/env python3
"""Restricted explicit-table lower bounds; not universal point-lock bounds."""
from math import comb
from fractions import Fraction
import json

TARGET=1<<2048

def minimum_selected(n):
    if comb(n,n//2)<TARGET:
        return None
    lo,hi=1,n//2
    while lo<hi:
        mid=(lo+hi)//2
        if comb(n,mid)>=TARGET:
            hi=mid
        else:
            lo=mid+1
    return lo


def main():
    configurations={
        'embedded_keys_sig71':(34,72),
        'hash160_keys_sig71_ignore_hints':(21,106),
        'hash160_keys_sig71_one_hint':(21,107),
        'embedded_keys_sig65':(34,66),
        'hash160_keys_sig65_ignore_hints':(21,100),
        'hash160_keys_sig65_one_hint':(21,101),
        'hash160_keys_sig58_ignore_hints':(21,93),
        'selective_p2sh_outputs_fixed76B_redeem_sig71':(32,Fraction(765,4)),
    }
    best={name:None for name in configurations}
    first=None
    # Explicit check bounds this range: at n=10000 the cheapest21Bentry table
    # alone costs210000B, more than every incumbent reported below.
    for n in range(2048,10001):
        t=minimum_selected(n)
        if t is None:
            continue
        if first is None:
            first=n
        for name,(a,b) in configurations.items():
            cost=a*n+b*t
            if best[name] is None or cost<best[name]['cost']:
                best[name]={'n':n,'t':t,'cost':cost}
    for name,row in best.items():
        row['cost']=float(row['cost'])
        row['entry_bytes']=configurations[name][0]
        row['selected_bytes']=float(configurations[name][1])
    print(json.dumps({'payload_bits':2048,'minimum_independent_candidates':first,
                      'bounds':best,
                      'scope':'Fixed-weight subsets of explicitly independent candidates; omit verifiers, grouping, most transaction framing. Not a bound on implicit sets, special algebraic structures or other protocols.'},indent=2))

if __name__=='__main__':
    main()
