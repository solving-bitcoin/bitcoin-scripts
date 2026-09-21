#!/usr/bin/env python3
"""Exact combinatorial capacity and complete-transaction byte accounting.

No cryptographic or transaction validity claim: the serializer uses size-only
placeholders; script/scriptSig lengths come from separately checked probes.
"""
from dataclasses import dataclass
from math import ceil, comb, log2
from collections import Counter
from pathlib import Path
import argparse
import json

BITS = 2048
TARGET = 1 << BITS
MAX_WEIGHT = 400_000
MAX_SIGOPS_COST = 16_000


def compact(n):
    if n < 253:
        return bytes([n])
    if n <= 65535:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xffffffff:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def push_size(n):
    return n + (1 if n <= 75 else 2 if n <= 255 else 3)


@dataclass(frozen=True)
class Layout:
    name: str
    n: int
    t: int
    script: int
    scriptsig: int
    source: str
    evidence: str = "locally-reproduced"
    static_sigops: int = 0

    @property
    def sigops_cost(self):
        return 4 * (self.static_sigops or 2 * self.t)

    @property
    def radix(self):
        return comb(self.n, self.t)

    @property
    def input_weight(self):
        # Outpoint + sequence, CompactSize + scriptSig, empty witness vector.
        return 4 * (40 + len(compact(self.scriptsig)) + self.scriptsig) + 1

    @property
    def pair_weight(self):
        # A P2SH creation output is 8-byte amount + 1-byte size + 23-byte script.
        return 128 + self.input_weight


def layouts():
    rows = []
    # IF-tree choices, maximum selector depth; only recorded configurations.
    for n in (2, 4, 5, 6, 7):
        for kind in ("embedded", "hash"):
            script = 92 * n + 12 if kind == "embedded" else 66 * n + 20
            if script > 520:
                continue
            opening = 61 + (0 if kind == "embedded" else 68) + ceil(log2(n))
            rows.append(Layout(f"choice-{kind}-{n}", n, 1, script,
                               push_size(script) + opening, "one-of-n.md"))
    baseline = [(2,1,190,322),(3,1,254,386),(4,1,319,452),
                (4,2,377,640),(5,1,387,520),(5,2,449,712),
                (5,3,511,904),(6,1,452,585),(6,2,514,777),
                (7,1,516,649)]
    for n,t,script,ss in baseline:
        rows.append(Layout(f"subset-original-{t}-of-{n}", n,t,script,ss,
                           "subset-probe.md"))
    for label,script,ss in (("reordered",512,775),("multisig",518,781),
                            ("multisig-reordered",516,779)):
        rows.append(Layout(f"subset-{label}-2-of-6",6,2,script,ss,
                           "multisig-probe.md"))
    for n,t,script,ss in ((5,2,427,690),(6,2,495,758),(5,3,476,869),(7,1,506,639)):
        rows.append(Layout(f"lookup-destructive-{t}-of-{n}",n,t,script,ss,
                           "lookup-optimization.md"))
    for label,n,t,script,ss in (("hash-direct-depth",6,2,482,746),
                                  ("embedded-direct-depth",5,2,517,644)):
        rows.append(Layout(f"lookup-{label}-{t}-of-{n}",n,t,script,ss,
                           "lookup-optimization.md"))
    for label,n,t,script,ss in (("hash-alt-depth",6,2,474,738),
                                  ("hash-alt-depth",6,3,517,911),
                                  ("hash-alt-index",6,2,487,750),
                                  ("hash-alt-depth",5,2,409,672),
                                  ("hash-alt-depth",5,3,451,844)):
        rows.append(Layout(f"lookup-{label}-{t}-of-{n}",n,t,script,ss,
                           "lookup-optimization.md"))
    for n in range(2,15):
        for t in range(1,min(n-1,7)+1):
            overhead=[48,58,68,77,87,96,105][t-1]
            script=34*n+overhead
            if script>520 or n+t>15:
                continue
            ss=push_size(script)+1+72*t
            rows.append(Layout(f"common-g-cms-{t}-of-{n}",n,t,script,ss,
                               "common-key-multisig.md",static_sigops=n+t))
    source=Path(__file__).with_name("sum-lookup-vectors.json")
    for metric in json.loads(source.read_text())["metrics"]:
        n,t=metric["n"],metric["t"]
        if n==t or metric["script_bytes"]>520 or metric["accurate_sigops"]>15:
            continue
        rows.append(Layout(f"common-g-hash-lookup-{t}-of-{n}",n,t,
                           metric["script_bytes"],metric["script_sig_bytes"],
                           source.name,static_sigops=metric["accurate_sigops"]))
    return rows


def min_count(radix, remaining=TARGET):
    if remaining <= 1:
        return 0
    k = max(0, ceil(log2(remaining) / log2(radix)))
    while k and radix ** (k - 1) >= remaining:
        k -= 1
    while radix ** k < remaining:
        k += 1
    return k


def funding_weight(count):
    return 4 * (93 + len(compact(count + 1)) + 32 * count) + 68


def assert_weight(rows):
    return (4 * (93 + len(compact(len(rows) + 1))) + 68
            + sum(x.input_weight for x in rows))


def split(rows):
    # First-fit decreasing produces a concrete feasible grouping, not a proof
    # of optimal bin packing for arbitrary heterogeneous mixtures.
    chunks = []
    weights = []
    sigops = []
    for row in sorted(rows, key=lambda r: r.input_weight, reverse=True):
        for j, chunk in enumerate(chunks):
            count_extra = 8 if len(chunk) == 251 else 0
            if (weights[j] + row.input_weight + count_extra <= MAX_WEIGHT
                    and sigops[j] + row.sigops_cost <= MAX_SIGOPS_COST):
                chunk.append(row)
                weights[j] += row.input_weight + count_extra
                sigops[j] += row.sigops_cost
                break
        else:
            chunks.append([row])
            weights.append(444 + row.input_weight)
            sigops.append(row.sigops_cost)
    return chunks


def report(counts):
    rows = [r for r,count in counts.items() for _ in range(count)]
    capacity = 1
    for r,count in counts.items():
        capacity *= r.radix ** count
    chunks = split(rows)
    fw = funding_weight(len(rows))
    aw = assert_weight(rows)
    cw = [assert_weight(c) for c in chunks]
    return dict(layouts={r.name:n for r,n in counts.items() if n},
                bits=log2(capacity), capacity_sufficient=capacity >= TARGET,
                pools=len(rows), candidates=sum(r.n for r in rows),
                revelations=sum(r.t for r in rows),
                funding_weight=fw, funding_vbytes=ceil(fw/4),
                single_assert_weight=aw, single_assert_vbytes=ceil(aw/4),
                two_tx_vbytes=ceil(fw/4)+ceil(aw/4),
                funding_within_weight=fw<=MAX_WEIGHT,
                assert_chunks=[dict(pools=len(c),weight=w,vbytes=ceil(w/4),
                                    sigops_cost=sum(r.sigops_cost for r in c))
                               for c,w in zip(chunks,cw)],
                chunked_total_vbytes=ceil(fw/4)+sum(ceil(w/4) for w in cw))


def serialize_transaction(scriptsigs, output_scripts, witness=True):
    vin = compact(len(scriptsigs)) + b"".join(
        bytes(36) + compact(s) + bytes(s) + bytes.fromhex("ffffffff")
        for s in scriptsigs)
    vout = compact(len(output_scripts)) + b"".join(
        bytes(8) + compact(len(s)) + s for s in output_scripts)
    stripped = bytes.fromhex("02000000") + vin + vout + bytes(4)
    if not witness:
        return stripped, stripped
    witness_data = b"\x01\x40" + bytes(64) + bytes(len(scriptsigs) - 1)
    total = (bytes.fromhex("020000000001") + vin + vout
             + witness_data + bytes(4))
    return stripped, total


def verify_serialization(counts):
    rows = [r for r,count in counts.items() for _ in range(count)]
    p2tr = b"\x51\x20" + bytes(32)
    p2sh = b"\xa9\x14" + bytes(20) + b"\x87"
    b,t = serialize_transaction([0],[p2tr]+[p2sh]*len(rows))
    assert 3*len(b)+len(t) == funding_weight(len(rows))
    for chunk in [rows]+split(rows):
        b,t = serialize_transaction([0]+[r.scriptsig for r in chunk],[p2tr])
        assert 3*len(b)+len(t) == assert_weight(chunk)


def mixed_search(options):
    # Enumerate every pair of recorded layouts and the count of the first.
    # The other count is the exact integer amount still required. This allows
    # a partially used final radix, without assuming every slot is a full byte.
    # It is an exhaustive two-layout search, not a global optimum over designs.
    best = None
    best_counts = None
    best_weight = None
    for i,a in enumerate(options):
        for b in options[i:]:
            apower = 1
            for ca in range(min_count(a.radix)+1):
                remaining = (TARGET + apower - 1) // apower
                cb = min_count(b.radix,remaining)
                counts = Counter({a:ca})
                counts[b] += cb
                count = ca+cb
                # Exact lower bound before spending/chunk framing.
                lower = (a.pair_weight*ca+b.pair_weight*cb)/4+111
                if best_weight is None or lower < best_weight:
                    result = report(counts)
                    if best is None or result['chunked_total_vbytes'] < best['chunked_total_vbytes']:
                        best,best_counts = result,counts
                        best_weight=result['chunked_total_vbytes']
                apower *= a.radix
    verify_serialization(best_counts)
    return best,best_counts


def self_check():
    # Reproduce the earlier 187 fixed-point pair; it encodes no choices.
    five=Layout("fixed-five",5,5,500,808,"pointlock_transaction_size_probe.rs")
    two=Layout("fixed-two",2,2,200,324,"pointlock_transaction_size_probe.rs")
    counts=Counter({five:37,two:1})
    r=report(counts)
    assert (r['funding_vbytes'],r['single_assert_vbytes'],r['two_tx_vbytes']) == (1327,31975,33302)
    verify_serialization(counts)
    assert min_count(15)==525
    assert min_count(2)==2048
    assert min_count(15,1)==0



def coefficient_step(previous,n,max_t):
    current=[0]*(len(previous)+max_t)
    for total,count in enumerate(previous):
        if count:
            for t in range(1,max_t+1):
                current[total+t] += count*comb(n,t)
    return current


def variable_pool_search(n,max_t,script,max_pools=700,base_ss=None,per_selected=126,static_sigops=None):
    # Each omitted opening is four minimally encoded empty items. Selected
    # records are one60Bsignature,two33Bkeys,one single-byte depth hint.
    # Therefore scriptSig=push(redeem)+4*max_t+126*t.
    if base_ss is None:
        assert n<=5, "larger tables need actual depth-hint byte accounting"
        base_ss=push_size(script)+4*max_t
    assert len(compact(base_ss+per_selected))==3
    assert len(compact(base_ss+per_selected*max_t))==3
    coefficients=[1]
    best=None
    for pools in range(1,max_pools+1):
        if best is not None and pools*(75.25+base_ss+per_selected)>best['two_tx_vbytes']:
            break
        coefficients=coefficient_step(coefficients,n,max_t)
        for total in range(pools,max_t*pools+1):
            capacity=coefficients[total]
            if capacity<TARGET:
                continue
            # ScriptSig and surrounding CompactSize remain in the same
            # size class for every t, making total two-TX size independent
            # of how this fixed number of revelations is distributed.
            input_weight=4*(40+3+base_ss)*pools+4*per_selected*total+pools
            assertw=4*(93+len(compact(pools+1)))+68+input_weight
            pair_vbytes=ceil(funding_weight(pools)/4)+ceil(assertw/4)
            if best is None or pair_vbytes<best['two_tx_vbytes']:
                best=dict(n=n,max_t=max_t,script=script,pools=pools,
                          publication_binding="Conditional only: third parties can drop optional openings while Bitcoin scripts remain valid; a global decoder count alone does not prevent malformed publication.",
                          base_script_sig=base_ss,bytes_per_selected=per_selected,
                          static_sigops=static_sigops or 2*max_t,
                          revelations=total,candidates=n*pools,
                          capacity_bits=log2(capacity),two_tx_vbytes=pair_vbytes,
                          funding_vbytes=ceil(funding_weight(pools)/4),
                          single_assert_weight=assertw,
                          single_assert_vbytes=ceil(assertw/4))
    return best


def coefficient_rows(n,max_t,m):
    rows=[[1]]
    for _ in range(m):
        rows.append(coefficient_step(rows[-1],n,max_t))
    return rows


def coeff(rows,m,total):
    return rows[m][total] if 0<=total<len(rows[m]) else 0


def unrank_global(rank,n,max_t,m,total,rows):
    from itertools import combinations
    if not 0<=rank<coeff(rows,m,total):
        raise ValueError("rank outside code capacity")
    result=[]
    while m:
        for t in range(1,max_t+1):
            tails=coeff(rows,m-1,total-t)
            group=comb(n,t)*tails
            if rank>=group:
                rank-=group
                continue
            index,rank=divmod(rank,tails)
            result.append(tuple(combinations(range(n),t))[index])
            total-=t
            m-=1
            break
        else:
            raise AssertionError("no unranking branch")
    assert rank==0 and total==0
    return result


def rank_global(selections,n,max_t,total,rows):
    from itertools import combinations
    rank=0
    m=len(selections)
    for selection in selections:
        t=len(selection)
        if not 1<=t<=max_t or tuple(sorted(set(selection)))!=tuple(selection):
            raise ValueError("noncanonical subset")
        choices=tuple(combinations(range(n),t))
        index=choices.index(tuple(selection))
        for smaller in range(1,t):
            rank+=comb(n,smaller)*coeff(rows,m-1,total-smaller)
        rank+=index*coeff(rows,m-1,total-t)
        total-=t
        m-=1
    if total!=0:
        raise ValueError("wrong global revelation count")
    return rank


def verify_global_codec(best):
    import random
    n,max_t,m,total=(best[k] for k in ('n','max_t','pools','revelations'))
    rows=coefficient_rows(n,max_t,m)
    rng=random.Random(0xB17B3)
    for value in [0,1,TARGET-1]+[rng.getrandbits(BITS) for _ in range(8)]:
        selections=unrank_global(value,n,max_t,m,total,rows)
        assert rank_global(selections,n,max_t,total,rows)==value
        assert sum(map(len,selections))==total
    # One complete concrete profile for serializer/chunk verification.
    selections=unrank_global(TARGET-1,n,max_t,m,total,rows)
    counts=Counter()
    for t,count in Counter(map(len,selections)).items():
        script=best['script']
        ss=best["base_script_sig"]+best["bytes_per_selected"]*t
        row=Layout(f"variable1..{max_t}of{n}-selected{t}",n,t,script,ss,
                   "lookup-optimization.md",static_sigops=best["static_sigops"])
        counts[row]=count
    verify_serialization(counts)
    result=report(counts)
    assert result['two_tx_vbytes']==best['two_tx_vbytes']
    best['example_profile']=result
    return best



def fixed_publication_selection():
    import itertools
    import random
    value=random.Random(0xB17B3).getrandbits(BITS)
    proof=value.to_bytes(BITS//8,'big').hex()
    parameters=[{'n':17,'t':4}]*180+[{'n':18,'t':3}]*3
    selections=[]
    digits=[]
    for par in reversed(parameters):
        value,digit=divmod(value,comb(par['n'],par['t']))
        selections.append(list(tuple(itertools.combinations(range(par['n']),par['t']))[digit]))
        digits.append(digit)
    assert value==0
    selections.reverse();digits.reverse()
    recovered=0
    for par,digit in zip(parameters,digits):
        recovered=recovered*comb(par['n'],par['t'])+digit
    assert recovered.to_bytes(BITS//8,'big').hex()==proof
    return dict(seed='0xB17B3',proof_hex=proof,global_revelations=729,
                pool_count=183,pool_parameters=parameters,selections=selections,
                digits=digits,codec_order='Big-endian mixed radix; rank=rank*binomial(n,t)+lexicographic_subset_rank left-to-right by funding output index.')


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--json',action='store_true')
    p.add_argument('--write-selection',type=Path)
    p.add_argument('--no-search',action='store_true')
    p.add_argument('--variable-script',type=int)
    p.add_argument('--max-selected',type=int,default=3)
    p.add_argument('--candidates',type=int,default=5)
    p.add_argument('--base-script-sig',type=int)
    p.add_argument('--bytes-per-selected',type=int,default=126)
    p.add_argument('--static-sigops',type=int)
    args=p.parse_args()
    self_check()
    if args.write_selection:
        args.write_selection.write_text(json.dumps(fixed_publication_selection(),indent=2)+'\n')
        print(args.write_selection)
        return
    if args.variable_script:
        best=variable_pool_search(args.candidates,args.max_selected,args.variable_script,
                                  base_ss=args.base_script_sig,
                                  per_selected=args.bytes_per_selected,
                                  static_sigops=args.static_sigops)
        print(json.dumps(verify_global_codec(best),indent=2))
        return
    options=layouts()
    uniform=[]
    for row in options:
        counts=Counter({row:min_count(row.radix)})
        verify_serialization(counts)
        uniform.append(dict(layout=row.__dict__,**report(counts)))
    uniform.sort(key=lambda r:r['chunked_total_vbytes'])
    result={'bits':BITS,'signature_bytes':{'committed':60,'common_g':71},'uniform':uniform}
    if not args.no_search:
        # Dominated choices with the same radix cannot win this cost objective.
        by_radix={}
        for row in options:
            if row.radix not in by_radix or row.pair_weight<by_radix[row.radix].pair_weight:
                by_radix[row.radix]=row
        best,counts=mixed_search(list(by_radix.values()))
        result['best_two_layout_mixture']=best
    if args.json:
        print(json.dumps(result,indent=2))
    else:
        for r in uniform:
            print(f"{r['layout']['name']:40s} pools={r['pools']:4d} candidates={r['candidates']:4d} revelations={r['revelations']:4d} two_tx={r['two_tx_vbytes']:7d}vB chunks={len(r['assert_chunks'])} all_tx={r['chunked_total_vbytes']:7d}vB")
        if 'best_two_layout_mixture' in result:
            print(json.dumps(result['best_two_layout_mixture'],indent=2))

if __name__=='__main__':
    main()
