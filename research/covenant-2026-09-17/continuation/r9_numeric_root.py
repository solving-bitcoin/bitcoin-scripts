#!/usr/bin/env python3
"""Readable ScriptNum root with a separate public hash-path mining domain.

Raw host boundary experiment. No rare root or complete covenant was mined.
"""
import hashlib
import itertools
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent/'seven'))
from search1_nonce_encoding import HASH_OPCODE, hash_word, num_bytes, push_num, routing_output, word_count


def decode(raw):
    if len(raw) > 4:
        raise ValueError('oversized ScriptNum')
    if not raw:
        return 0
    value = int.from_bytes(raw, 'little')
    return -(value & ~(0x80 << (8*(len(raw)-1)))) if raw[-1]&0x80 else value


def root_script(schedule):
    # Exact main-stack boundary: selectors reversed, ScriptNum. Empty altstack.
    out = b'\x74'+push_num(len(schedule))+b'\x88'
    # Normalize, retain the readable numeric value, then seed with a long hash.
    out += bytes.fromhex('0093766ba8')
    out += b'\x76'+bytes([HASH_OPCODE[schedule[0]]])
    for h in schedule[1:]:
        out += b'\x52\x7a\x7a'+bytes([HASH_OPCODE[h]])
    return out+b'\x77'


def run(raw, items):
    stack, alt = list(items), []
    if len(stack)>1000 or any(len(x)>520 for x in stack):
        raise ValueError('entry bound')
    peak, pc, ops = len(stack), 0, 0
    while pc < len(raw):
        op = raw[pc]
        pc += 1
        if op <= 75:
            stack.append(raw[pc:pc+op]); pc += op
        elif 0x51 <= op <= 0x60:
            stack.append(num_bytes(op-0x50))
        else:
            ops += 1
            if op == 0x74:
                stack.append(num_bytes(len(stack)))
            elif op == 0x88:
                if stack.pop() != stack.pop(): raise ValueError('equality')
            elif op == 0x93:
                a,b=decode(stack.pop()),decode(stack.pop())
                stack.append(num_bytes(a+b))
            elif op == 0x76:
                stack.append(stack[-1])
            elif op == 0x77:
                del stack[-2]
            elif op == 0x6b:
                alt.append(stack.pop())
            elif op == 0x6c:
                stack.append(alt.pop())
            elif op == 0x7a:
                index=decode(stack.pop())
                if index<0 or index>=len(stack): raise ValueError('ROLL range')
                stack.append(stack.pop(-1-index))
            elif op in HASH_OPCODE.values():
                name=next(k for k,v in HASH_OPCODE.items() if v==op)
                word={'A':'a','S':'s','R':'r','D':'ss','T':'sr'}[name]
                stack.append(hash_word(stack.pop(),word))
            else:
                raise ValueError('unsupported opcode')
        peak=max(peak,len(stack)+len(alt))
        if peak>1000: raise ValueError('stack limit')
    return stack,alt,{'bytes':len(raw),'executed_non_push_opcodes':ops,'combined_peak':peak}


def main():
    cases=0
    parameters=[-(2**31-1),-128,-1,0,1,128,2**31-1]
    for stages in range(1,9):
        schedule=('ATDRS'*2)[:stages]
        raw=root_script(schedule)
        for selectors in itertools.product((0,1),repeat=stages-1):
            for value in parameters:
                inputs=[num_bytes(x) for x in reversed(selectors)]+[num_bytes(value)]
                stack,alt,metrics=run(raw,inputs)
                seed=hashlib.sha256(num_bytes(value)).digest()
                assert stack == [routing_output(seed,schedule,selectors)]
                assert alt == [num_bytes(value)]
                assert metrics['executed_non_push_opcodes'] == 3*stages+6
                assert metrics['combined_peak'] <= stages+3
                cases += 1
    # Match the optimized 61-stage routing schedule, without claiming new entropy.
    source=json.loads((HERE.parent/'seven/search1_nonce_encoding.json').read_text())
    schedule=next(x['schedule'] for x in source['families'] if x['stages']==61)
    raw=root_script(schedule)
    selectors=[(i*17+3)%2 for i in range(60)]
    good=[num_bytes(x) for x in reversed(selectors)]+[num_bytes(123456789)]
    stack,alt,metrics=run(raw,good)
    assert metrics['executed_non_push_opcodes']==189 and metrics['combined_peak']==64
    malformed=0
    for position in range(60):
        for bad in (-1,2,3,60,999):
            items=good.copy(); items[position]=num_bytes(bad)
            try: run(raw,items)
            except (ValueError,IndexError): malformed+=1
            else: raise AssertionError(('accepted selector',position,bad))
    for items in (good+[b''],good[1:],good[:-1]+[b'\x01'*5]):
        try: run(raw,items)
        except (ValueError,IndexError): malformed+=1
        else: raise AssertionError('accepted malformed input')
    normalization=[]
    for encoded in (b'',b'\0',b'\x80',b'\0\x80',b'\x01',b'\x01\0',b'\x81',b'\x01\x80'):
        items=good[:-1]+[encoded]
        result,kept,_=run(raw,items)
        normalized=num_bytes(decode(encoded))
        assert kept == [normalized]
        assert result == [routing_output(hashlib.sha256(normalized).digest(),schedule,selectors)]
        normalization.append({'input':encoded.hex(),'semantic_value':decode(encoded),'normalized':normalized.hex()})
    # A complete candidate uses the root as a signature under witness P, pins
    # H(P) to DER syntax, and verifies the retained parameter equals a literal.
    # This is generated, not executed: no full PoW witness has been mined.
    candidate=b'\x6b'+raw+b'\x6c'+push_num(123456789)+b'\x9d\x6c'+bytes.fromhex('76a800ac75ac')
    report={'evidence':'locally-reproduced','deployment_class':'unclassified',
            'exhaustive_valid_vectors':cases,'malformed_rejections':malformed,
            'normalization_cases':normalization,'schedule':schedule,
            'semantic_hash_words':word_count(schedule)[0],
            'root_fragment':{'script_hex':raw.hex(),**metrics,'input_data_items':61,
                             'hint_items':60,'non_hint_operands':1,'retained_alt_items':1,
                             'root_hex':stack[0].hex(),'retained_number':alt[0].hex()},
            'unmined_candidate':{'script_hex':candidate.hex(),'script_bytes':len(candidate),
                                'counted_non_push_opcodes':198,'entry_data_items':62,
                                'hint_items':60,'non_hint_operands':2,
                                'combined_peak_by_inspection':65,
                                'scope':'Complete numeric-equality/root-signature/pinning candidate; not executed, not an output verifier.'},
            'all_expectations_met':True}
    Path(__file__).with_suffix('.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('exhaustive_valid_vectors','malformed_rejections','root_fragment','unmined_candidate')},indent=2))


if __name__=='__main__':
    main()
