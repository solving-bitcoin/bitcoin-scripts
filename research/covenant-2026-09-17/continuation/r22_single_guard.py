#!/usr/bin/env python3
"""Raw legacy boundary fixture for a variable-signature SINGLE-bug guard.

The general claim is conditional on no distinct-preimage double-SHA256
collision modulo n. This guard commits to no outputs and is not a covenant.
"""
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from r11_lookup_reference import N, P, G, add, mul, point, encoded
from r11_endomorphism import C, signature, neg
from r10_parallel_cycles import instructions, unpack_der
sys.path.insert(0, str(HERE.parent))
from legacy_same_signature_counterexample import verify, signature_integer
sys.path.insert(0, str(HERE.parent/'seven'))
from search2_native_context import legacy_preimage, clean, delete, h256


def layout():
    # Entry beta,P,Q; exact depth, 33-byte keys, distinct encodings, beta>57.
    guard = bytes.fromhex('745388820121887c820121887c6e8791695279820139a06975')
    # Preserve all three inputs while verifying beta under P and Q.
    pair = bytes.fromhex('52795279ad52795179ad')
    return guard+pair+b'\xab'+pair+bytes.fromhex('6d7551')


def codes(script):
    separator = 0
    result = []
    for _, end, op, _ in instructions(script):
        if op == 0xab: separator = end
        elif op == 0xad: result.append(clean(script[separator:]))
    assert len(result) == 4 and result[0] == result[1] and result[2] == result[3]
    assert len(result[0]) > len(result[2])
    return result


def native(inputs, outputs, index, script, flag):
    preimages = [legacy_preimage(inputs, outputs, index, code, flag) for code in codes(script)]
    hashes = [b'\x01'+bytes(31) if p is None else h256(p) for p in preimages]
    return preimages, hashes, [int.from_bytes(h, 'big') % N for h in hashes]


def row(z, flag=3, short=False):
    nonce = point(b'\x02'+(1).to_bytes(32,'big')) if short else G
    r = nonce[0] % N
    s = 1 if short else min(r, N-r)
    keys = [mul(pow(r,-1,N),add(mul(sign*s,nonce),mul(-z))) for sign in (1,-1)]
    assert all(k is not None for k in keys) and keys[0] != keys[1]
    assert all(verify(z,r,s,k)[0] for k in keys)
    return [signature(r,s,flag)]+[encoded(k) for k in keys]


def execute(script, items, digests):
    """Small explicit stack model, independently checked by Core companion."""
    stack = list(items)
    peak, operations, checks = len(stack), 0, 0
    for _, _, op, data in instructions(script):
        if data is not None: stack.append(data)
        elif 0x51 <= op <= 0x60: stack.append(bytes([op-0x50]))
        else:
            operations += 1
            if op == 0x74: stack.append(bytes([len(stack)]))
            elif op == 0x82: stack.append(bytes([len(stack[-1])]))
            elif op == 0x7c: stack[-1],stack[-2]=stack[-2],stack[-1]
            elif op == 0x6e: stack.extend(stack[-2:])
            elif op == 0x79:
                index=int.from_bytes(stack.pop(),'little'); assert index < len(stack)
                stack.append(stack[-1-index])
            elif op == 0x88: assert stack.pop() == stack.pop(), 'EQUALVERIFY'
            elif op == 0x87: stack.append(bytes([int(stack.pop()==stack.pop())]))
            elif op == 0x91: stack.append(bytes([int(not any(stack.pop()))]))
            elif op == 0xa0:
                b,a=stack.pop(),stack.pop()
                stack.append(bytes([int(int.from_bytes(a,'little')>int.from_bytes(b,'little'))]))
            elif op == 0x69: assert any(stack.pop()), 'VERIFY'
            elif op == 0x75: stack.pop()
            elif op == 0x6d: stack.pop();stack.pop()
            elif op == 0xab: pass
            elif op == 0xad:
                key,sig=stack.pop(),stack.pop();r,s=unpack_der(sig)
                assert 0<r<N and 0<s<N
                assert verify(digests[checks],r,s,point(key))[0], 'CHECKSIGVERIFY'
                checks+=1
            else: raise AssertionError(hex(op))
        peak=max(peak,len(stack))
    assert stack==[b'\x01'] and checks==4
    return {'combined_stack_peak':peak,'executed_non_push_opcodes':operations,'signature_checks':checks}


def main():
    script=layout();code=codes(script)
    inputs=[(bytes([i+1])*36,0xffffffff) for i in range(2)]
    outputs=[(1990000,b'\x00\x14'+b'\x11'*20)]
    flags=[]
    for index,outs in ((1,outputs),(0,outputs),(1,outputs+[(1,b'\x51')])):
        for flag in range(256):
            pre,h,z=native(inputs,outs,index,script,flag)
            bug=flag&31==3 and index>=len(outs)
            assert (pre[0] is None)==bug
            assert (z[0]==z[2])==bug
            if not bug: assert pre[0]!=pre[2] and len(pre[0])-len(pre[2])==len(code[0])-len(code[2])
            sig=signature(G[0],min(G[0],N-G[0]),flag)
            assert all(delete(c,[sig])==c for c in code)
            flags.append({'input_index':index,'output_count':len(outs),'flag':flag,
                'single_bug':bug,'digest0':h[0].hex(),'digest1':h[2].hex(),
                'preimage_lengths':None if bug else [len(pre[0]),len(pre[2])]})
    data=row(C)
    trace=execute(script,data,[C]*4)
    assert len(data[0])>57
    positives=[]
    for flag in (3,0x23,0x83):
        item=row(C,flag)
        assert execute(script,item,native(inputs,outputs,1,script,flag)[2])==trace
        positives.append({'flag':flag,'data':[x.hex() for x in item]})
    negatives=[]
    for flag in (1,2,0,0x81):
        z=native(inputs,outputs,1,script,flag)[2]
        candidate=row(z[0],flag)
        try: execute(script,candidate,z)
        except AssertionError as error: negatives.append({'flag':flag,'reason':str(error),'first_context_valid':True})
        else: raise AssertionError('nonbug accepted')
    # Width proof includes high-S and DER sign padding, independently of LOW_S.
    max_r=P-N-1
    assert len(signature_integer(max_r))-2==17
    assert len(signature_integer(N-1))-2==33
    assert len(signature(max_r,N-1,3))==57
    result={'evidence':'locally-reproduced','deployment_class':'unclassified',
        'scope':'Host raw boundary vectors; see companion Core results for actual funded execution.',
        'redeemscript_hex':script.hex(),'redeemscript_bytes':len(script),
        'processed_context_script_bytes':[len(code[0]),len(code[2])],
        'redeem_entry_data_items':3,'hint_items':0,'all_data_coexist_at_entry':True,
        'script_sig_push_items_including_redeem':4,'trace':trace,
        'flags':flags,'positive_rows':positives,'negative_controls':negatives,
        'four_root_max_der_signature_bytes':57,
        'condition':'An accepting nonbug case requires distinct legacy preimages with equal double-SHA256 modulo n; raw hashes may also differ by exactly n.',
        'complete_covenant':False,'all_assertions_passed':True}
    Path(__file__).with_suffix('.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'script_bytes':len(script),'trace':trace,'contexts':len(flags)},indent=2))


if __name__=='__main__': main()
