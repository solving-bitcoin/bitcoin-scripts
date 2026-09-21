#!/usr/bin/env python3
"""Exact host-model count of distinct primitive hash words in routing schedules."""
from functools import lru_cache
import itertools
import math

# Function composition written in execution order: HASH160 = SHA256 then RIPEMD160.
EXPANSIONS = {'S': 's', 'A': 'a', 'R': 'r', 'D': 'ss', 'T': 'sr'}

def word_count(schedule, require_final=True):
    n = len(schedule)
    trans = [{} for _ in range(n + 1)]
    eps = [set() for _ in range(n + 1)]
    for i, h in enumerate(schedule):
        if i < n - 1 or not require_final:
            eps[i].add(i + 1)
        expansion = EXPANSIONS[h]
        if len(expansion) == 1:
            trans[i].setdefault(expansion, set()).add(i + 1)
        else:
            k = len(trans)
            trans.append({expansion[1]: {i + 1}})
            eps.append(set())
            trans[i].setdefault(expansion[0], set()).add(k)
    @lru_cache(None)
    def closure(states):
        states=set(states)
        todo=list(states)
        while todo:
            for j in eps[todo.pop()]:
                if j not in states:
                    states.add(j);todo.append(j)
        return frozenset(states)
    @lru_cache(None)
    def count(states):
        ans = int(n in states)
        for ch in 'sar':
            dest=frozenset(j for i in states for j in trans[i].get(ch, ()))
            if dest:
                ans += count(closure(dest))
        return ans
    ans=count(closure(frozenset({0})))
    return ans, count.cache_info().currsize

def literal_count(schedule, require_final=True):
    out={''}
    for i,h in enumerate(schedule):
        transformed={w + EXPANSIONS[h] for w in out}
        out = transformed if require_final and i == len(schedule)-1 else out | transformed
    return len(out)

if __name__ == '__main__':
    for n in range(1, 9):
        for s in itertools.product(EXPANSIONS, repeat=min(n,3)):
            schedule=(''.join(s)*n)[:n]
            assert word_count(schedule)[0] == literal_count(schedule)
    for n in range(28, 34):
        rows=[]
        for p in itertools.permutations(EXPANSIONS):
            sched=(''.join(p)*10)[:n]
            cnt,states=word_count(sched)
            rows.append((cnt,sched,states))
        cnt,sched,states=max(rows)
        print(n, cnt, math.log2(cnt), sched, 'dfa_states',states)

# Raw consensus-boundary byte vectors, deliberately not repository compiler metrics.
HASH_OPCODE={'A':0xa7,'S':0xa8,'R':0xa6,'D':0xaa,'T':0xa9}

def num_bytes(n):
    if n == 0:return b''
    negative=n<0;n=abs(n)
    x=n.to_bytes((n.bit_length()+7)//8,'little')
    if x[-1]&0x80:x+=b'\x80' if negative else b'\x00'
    elif negative:x=x[:-1]+bytes([x[-1]|0x80])
    return x

def push(x):
    if not x:return b'\x00'
    if len(x)==1 and 1<=x[0]<=16:return bytes([0x50+x[0]])
    if len(x)<=75:return bytes([len(x)])+x
    if len(x)<=255:return b'\x4c'+bytes([len(x)])+x
    return b'\x4d'+len(x).to_bytes(2,'little')+x

def push_num(n):return push(num_bytes(n))

def full_script(schedule):
    n=len(schedule)
    # Exactly n-1 selectors and one native-bound opaque root.
    out=b'\x74'+push_num(n)+b'\x88'
    out+=push(bytes.fromhex('300602010102010101'))+b'\x78\xad'
    # Main: selectors root. Alt: fixed-nonce DER digest.
    out+=bytes.fromhex('76a87600ac756b')
    out+=b'\x76'+bytes([HASH_OPCODE[schedule[0]]])
    for h in schedule[1:]:out+=b'\x52\x7a\x7a'+bytes([HASH_OPCODE[h]])
    out+=bytes.fromhex('777600ac756c8791')
    return out

def hash_word(root,word):
    import hashlib
    for h in word:
        root=hashlib.new({'s':'sha256','a':'sha1','r':'ripemd160'}[h],root).digest()
    return root

def selected_word(schedule,selectors):
    states=['',EXPANSIONS[schedule[0]]]
    for h,k in zip(schedule[1:],selectors):
        states.append(states.pop(-1-k)+EXPANSIONS[h])
    return states[-1]

def routing_output(root,schedule,selectors):
    states=[root,hash_word(root,EXPANSIONS[schedule[0]])]
    for h,k in zip(schedule[1:],selectors):
        states.append(hash_word(states.pop(-1-k),EXPANSIONS[h]))
    return states[-1]

def observable_script(schedule,expected):
    # No CHECKSIG, no DER gates: consume exact selector/root input to true.
    out=b'\x74'+push_num(len(schedule))+b'\x88'
    out+=b'\x76'+bytes([HASH_OPCODE[schedule[0]]])
    for h in schedule[1:]:out+=b'\x52\x7a\x7a'+bytes([HASH_OPCODE[h]])
    return out+b'\x77'+push(expected)+b'\x87'

def evaluate_observable(script,stack):
    # Small independent raw-opcode interpreter. No consensus claims.
    stack=list(stack);pc=0;peak=len(stack);count=0
    def number(x):
        if len(x)>4:raise ValueError('oversized ScriptNum')
        if not x:return 0
        a=int.from_bytes(x,'little')
        return -(a & ~(0x80<<(8*(len(x)-1)))) if x[-1]&0x80 else a
    while pc<len(script):
        op=script[pc];pc+=1
        if op<=75:
            stack.append(script[pc:pc+op]);pc+=op
        elif 0x51<=op<=0x60:stack.append(num_bytes(op-0x50))
        else:
            count+=1
            if op==0x74:stack.append(num_bytes(len(stack)))
            elif op==0x76:stack.append(stack[-1])
            elif op==0x77:del stack[-2]
            elif op==0x7a:
                k=number(stack.pop())
                if k<0 or k>=len(stack):raise ValueError('ROLL index out of range')
                stack.append(stack.pop(-1-k))
            elif op in (0x87,0x88):
                a=stack.pop();b=stack.pop();equal=a==b
                if op==0x88:
                    if not equal:raise ValueError('EQUALVERIFY failure')
                else:stack.append(num_bytes(int(equal)))
            elif op in HASH_OPCODE.values():
                h=next(k for k,v in HASH_OPCODE.items() if v==op)
                stack.append(hash_word(stack.pop(),EXPANSIONS[h]))
            else:raise ValueError(f'unsupported opcode {op:x}')
        peak=max(peak,len(stack))
        if len(stack)>1000:raise ValueError('stack overflow')
    return {'clean_success':stack==[b'\x01'],'peak':peak,'opcodes':count}

def generate_report():
    import json,random,pathlib
    rng=random.Random(20260917)
    rows=[]
    for n in (30,31,60,61):
        choices=[]
        for perm in itertools.permutations(EXPANSIONS):
            s=(''.join(perm)*20)[:n]
            if s[-1] != 'S':continue
            cnt,states=word_count(s)
            choices.append((cnt,s,states))
        cnt,s,states=max(choices)
        raw=full_script(s)
        rows.append({'stages':n,'schedule':s,'effective_words':cnt,
                     'bits':math.log2(cnt),'dfa_states':states,
                     'full_pair_static_non_push_opcodes':3*n+16,
                     'raw_full_pair_script_bytes':len(raw),
                     'full_pair_script_hex':raw.hex()})
    schedule=rows[-1]['schedule']
    root=bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
    vectors=[]
    for i in range(8):
        selectors=[rng.randrange(2) for _ in schedule[1:]]
        word=selected_word(schedule,selectors)
        digest=routing_output(root,schedule,selectors)
        assert digest==hash_word(root,word)
        raw=observable_script(schedule,digest)
        stack=[num_bytes(k) for k in reversed(selectors)]+[root]
        verdict=evaluate_observable(raw,stack)
        assert verdict['clean_success']
        vectors.append({'selectors_execution_order':selectors,'effective_word':word,
                        'root_hex':root.hex(),'output_hex':digest.hex(),
                        'script_hex':raw.hex(),'input_items_hex':[x.hex() for x in stack],
                        'host_evaluation':verdict})
    # Exhaustive raw-program semantics versus word semantics on all selector paths.
    exhaustive=0
    for n in range(1,11):
        s=('ATDRS'*3)[:n]
        outputs=set()
        for selectors in itertools.product((0,1),repeat=n-1):
            w=selected_word(s,selectors);outputs.add(w)
            digest=routing_output(root,s,selectors)
            assert digest==hash_word(root,w)
            stack=[num_bytes(k) for k in reversed(selectors)]+[root]
            assert evaluate_observable(observable_script(s,digest),stack)['clean_success']
            exhaustive+=1
        assert len(outputs)==word_count(s)[0]
    # Every possible out-of-range selection position: skip an input selector.
    rejected=0
    raw=bytes.fromhex(vectors[0]['script_hex'])
    good=[bytes.fromhex(x) for x in vectors[0]['input_items_hex']]
    for j in range(len(schedule)-1):
        for bad in (-1,2,3,60,999):
            stack=good.copy();stack[-2-j]=num_bytes(bad)
            try:evaluate_observable(raw,stack)
            except (ValueError,IndexError):rejected+=1
            else:raise AssertionError(('bad index accepted',j,bad))
    for stack in ([b'junk']+good,good[1:]):
        try:evaluate_observable(raw,stack)
        except (ValueError,IndexError):rejected+=1
        else:raise AssertionError('incorrect entry depth accepted')
    report={'evidence':'locally-reproduced','deployment':'unclassified',
            'boundary':'Host-language hash-word counts and raw-fragment model only; no full PoW witness mined.',
            'seed':20260917,'families':rows,'observable_vectors':vectors,
            'exhaustive_selector_vectors':exhaustive,'malformed_rejections':rejected}
    dest=pathlib.Path(__file__).with_suffix('.json')
    dest.write_text(json.dumps(report,indent=2)+'\n')
    print('report',dest,'exhaustive',exhaustive,'rejections',rejected)
    for row in rows:print({k:v for k,v in row.items() if k!='full_pair_script_hex'})

if __name__=='__main__':generate_report()
