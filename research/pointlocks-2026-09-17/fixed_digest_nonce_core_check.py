#!/usr/bin/env python3
"""Native known-digest filter and arbitrary nonce-point extraction.

Small consensus fixtures and a DH-quartet adapter, not a full publication.
Only public deterministic inputs and an isolated wallet/network-disabled
regtest are used. No independent payment authorization is provided here.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from core_check import (BUG_DIGEST, Node, consensus_check, decode_key, instructions,
                        isolated_core_binary, native_digest, p2sh, push, scalar_bytes,
                        scalar_value, serialize_spend, transaction, unpack_signature)
from publication_core_check import encode_key
from two_target_anchor_algebra import signature
from legacy_same_signature_counterexample import G, N, P, add, mul, verify
from dh_quartet_label_probe import public_input_check, evaluate, bits

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
C=int.from_bytes(BUG_DIGEST,'big')


def minimal_push(data):
    if not data: return b'\x00'
    if len(data)==1 and 1<=data[0]<=16: return bytes([0x50+data[0]])
    if data==b'\x81': return b'\x4f'
    return push(data)


def trace(code,entry,inputs,outputs,index):
    stack,alt,conditions=list(entry),[],[]
    peak=len(stack)
    separator=0
    checks=[]
    processed=0
    reason=None
    try:
        for _,end,op,data in instructions(code):
            active=all(conditions)
            if op==0x63:
                conditions.append(bool(scalar_value(stack.pop())) if active else False)
                processed+=1
                continue
            if op==0x67:
                conditions[-1]=not conditions[-1]
                processed+=1
                continue
            if op==0x68:
                conditions.pop()
                processed+=1
                continue
            if not active:
                continue
            processed+=op>0x60
            if data is not None: stack.append(data)
            elif op==0: stack.append(b'')
            elif 0x51<=op<=0x60: stack.append(scalar_bytes(op-0x50))
            elif op==0x6b: alt.append(stack.pop())
            elif op==0x6c: stack.append(alt.pop())
            elif op==0x6e: stack.extend(stack[-2:])
            elif op==0x74: stack.append(scalar_bytes(len(stack)))
            elif op==0x75: stack.pop()
            elif op==0x82: stack.append(scalar_bytes(len(stack[-1])))
            elif op==0x88: assert stack.pop()==stack.pop(), 'equalverify'
            elif op==0xa0:
                right,left=scalar_value(stack.pop()),scalar_value(stack.pop())
                stack.append(scalar_bytes(int(left>right)))
            elif op==0x69: assert scalar_value(stack.pop())!=0, 'verify'
            elif op==0xab: separator=end
            elif op in (0xac,0xad):
                key,sigma=decode_key(stack.pop()),stack.pop()
                message,preimage,script_code=native_digest(inputs,outputs,index,code[separator:],sigma)
                r,s,flag=unpack_signature(sigma)
                accepted,nonce=verify(int.from_bytes(message,'big')%N,r,s,key)
                checks.append(dict(key=encode_key(key).hex(),digest=message.hex(),
                    script_code=script_code.hex(),preimage=None if preimage is None else preimage.hex(),
                    accepted=accepted,nonce=None if nonce is None else encode_key(nonce).hex(),
                    single_bug=preimage is None))
                if op==0xad: assert accepted, 'checksigverify'
                else: stack.append(scalar_bytes(int(accepted)))
            else: raise ValueError(f'unsupported opcode {op:02x}')
            peak=max(peak,len(stack)+len(alt))
        assert not conditions and not alt and stack==[b'\x01'], 'terminal-stack'
    except (AssertionError,IndexError,ValueError) as error:
        reason=str(error) or type(error).__name__
    return dict(accepted=reason is None,failure=reason,checks=checks,
                combined_stack_peak=peak,processed_non_push_opcodes=processed,
                processed_count_includes_all_flow_control=True,
                static_non_push_opcodes=sum(op>0x60 for _,_,op,_ in instructions(code)))


def extract(target,sigma,transcript):
    assert transcript['accepted'] and len(transcript['checks'])==4
    first=transcript['checks'][:3]
    assert all(check['key']==encode_key(G).hex() and check['single_bug'] for check in first)
    assert all(check['digest']==BUG_DIGEST.hex() for check in first)
    assert len({check['script_code'] for check in first})==3
    r,s,_=unpack_signature(sigma)
    assert len(sigma)>57 and r>P-N and r==target[0]
    recovered=(C+r)*pow(s,-1,N)%N
    if mul(recovered)!=target:
        recovered=-recovered%N
    assert mul(recovered)==target
    return recovered


def cases(built):
    quartet=bytes.fromhex(built['quartet_script_hex'])
    for row in built['cases']:
        i=row['index']
        for high in (False,True):
            sigma=bytes.fromhex(row['signatures'][int(high)])
            for selected in (False,True):
                code=quartet if selected else bytes.fromhex(row['script_hex'])
                entry=[sigma]+([scalar_bytes(i%2),scalar_bytes(i//2)] if selected else [])
                yield dict(name=f'{"quartet" if selected else "single"}-{i}-{"high" if high else "low"}',
                    code=code,entry=entry,target=row,expected=True,selected=selected,mutation=None)
    row=built['cases'][0]
    sigma=bytes.fromhex(row['signatures'][0])
    for flag in (0x23,0x43,0x63,0x83,0xa3,0xc3,0xe3):
        yield dict(name=f'quartet-flag-{flag:02x}',code=quartet,entry=[sigma[:-1]+bytes([flag]),b'',b''],
            target=row,expected=True,selected=True,mutation=None)
    for mutation in ('wrong-selection','mutated-s','size-57','index-zero','two-outputs',
                     'extra-entry','missing-hint','ordinary-all-resigned'):
        yield dict(name=mutation,code=quartet,entry=[sigma,b'',b''],target=row,
                   expected=False,selected=True,mutation=mutation)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host-only',action='store_true')
    args=parser.parse_args()
    run=subprocess.run(['cargo','run','--release','--locked','--example','pointlock_fixed_digest_nonce_probe'],
        cwd=ROOT,text=True,capture_output=True,check=True)
    built=json.loads(run.stdout)
    rows=list(cases(built))
    assert {r['script_bytes'] for r in built['cases']}=={86}
    assert built['quartet_script_bytes']==199
    public=dict(profile='correlated',points=tuple(decode_key(bytes.fromhex(r['target_hex'])) for r in built['cases']))
    assert public_input_check(public,'correlated')
    assert len({p[0] for p in public['points']})==4, 'nonce sign aliases must be rejected'
    for row,target in zip(built['cases'],public['points']):
        r=target[0]
        assert P-N<r<N and r.bit_length()>=144
        expected=(-2*C*pow(r,-1,N)-1)%N
        assert expected not in (0,1)
        assert mul(expected)==decode_key(bytes.fromhex(row['derived_key_hex']))
    binary,provenance=(None,None) if args.host_only else isolated_core_binary(Path('/private/tmp/covenant-core-30.3'),False)
    report=dict(scope=__doc__,fixture=built,bitcoin_core=provenance,results=[],
        evidence='locally-reproduced' if args.host_only else 'differentially-validated',
        deployment='unclassified' if args.host_only else 'consensus-validated',
        complete_publication=False,independent_payment_authorization=False,setup_benchmark=None)
    with tempfile.TemporaryDirectory(prefix='bitcoin-lab-fixed-digest-nonce-') as temporary:
        node=Node(binary,Path(temporary)) if binary else None
        try:
            if node:
                node.ready()
                assert not node.rpc('getnetworkinfo')['networkactive'] and not node.rpc('getpeerinfo')
                report['node_options']=node.options
                address=node.rpc('decodescript','51')['segwit']['address']
                mining=bytes.fromhex(node.rpc('validateaddress',address)['scriptPubKey'])
                blocks=[]
                for _ in range(101):
                    node.tick()
                    blocks+=node.rpc('generatetoaddress',1,address)
                coinbase=node.rpc('getblock',blocks[0],2)['tx'][0]
                coin=next(v for v in coinbase['vout'] if v['scriptPubKey']['hex']==mining.hex())
                outputs=[]
                for row in rows: outputs.extend([(1000000,mining),(1000000,p2sh(row['code']))])
                outputs.append((5000000000-len(outputs)*1000000-10000,mining))
                funding=transaction(coinbase['txid'],coin['n'],[b'\x51'],outputs)
                assert consensus_check(node,address,funding)['accepted']
                report['funding']=funding
                txid=funding['txid']
            else:
                txid='11'*32
            for ordinal,row in enumerate(rows):
                code,entry=row['code'],copy.deepcopy(row['entry'])
                mutation=row['mutation']
                if mutation=='wrong-selection': entry[-1]=b'\x01'
                elif mutation=='mutated-s':
                    r,s,f=unpack_signature(entry[0]); entry[0]=signature(r,(s+1)%N,f)
                elif mutation=='size-57': entry[0]=b'\x00'*57
                elif mutation=='extra-entry': entry.insert(0,b'\x07')
                elif mutation=='missing-hint': entry.pop()
                inputs=[(txid,ordinal*2,b'',0xffffffff),(txid,ordinal*2+1,b'',0xffffffff)]
                outputs=[(1990000,b'\x00\x14'+b'\x11'*20)]
                index,helper=1,0
                if mutation=='index-zero': inputs.reverse(); index,helper=0,1
                if mutation=='two-outputs': outputs=[(990000,outputs[0][1]),(1000000,outputs[0][1])]
                if mutation=='ordinary-all-resigned':
                    provisional=entry[0][:-1]+b'\x01'
                    digest,_,_=native_digest(inputs,outputs,index,code,provisional)
                    k=123456789
                    r=mul(k)[0]%N
                    s=(int.from_bytes(digest,'big')+r)*pow(k,-1,N)%N
                    entry[0]=signature(r,min(s,N-s),1)
                script_sig=b''.join(minimal_push(v) for v in entry)+push(code)
                item=inputs[index]
                inputs[index]=(item[0],item[1],script_sig,item[3])
                spent=serialize_spend(inputs,outputs,helper)
                checked=trace(code,entry,inputs,outputs,index)
                assert checked['accepted']==row['expected'],(row['name'],checked)
                if mutation=='ordinary-all-resigned':
                    assert checked['checks'][0]['accepted'] and not checked['checks'][1]['accepted']
                    assert len({v['preimage'] for v in checked['checks']})==2
                extracted=None
                if row['expected']:
                    target=decode_key(bytes.fromhex(row['target']['target_hex']))
                    recovered=extract(target,entry[0],checked)
                    assert recovered==int(row['target']['scalar_hex'],16)
                    extracted=dict(scalar_hex=f'{recovered:064x}',target_hex=encode_key(target).hex())
                    decoded,label_points=evaluate(public,'correlated',(row['target']['index'],recovered))
                    assert decoded==bits(row['target']['index'])
                    extracted.update(message=list(decoded),point_labels=[encode_key(p).hex() for p in label_points])
                policy=consensus=None
                if node:
                    decoded=node.rpc('decoderawtransaction',spent['hex'])
                    assert decoded['txid']==spent['txid'] and decoded['weight']==spent['weight']
                    policy=node.rpc('testmempoolaccept',[spent['hex']])[0]
                    consensus=consensus_check(node,address,spent)
                    assert consensus['accepted']==row['expected'],(row['name'],consensus)
                    assert not policy['allowed'],(row['name'],policy)
                report['results'].append(dict(name=row['name'],expected_consensus=row['expected'],
                    policy=policy,consensus=consensus,script_bytes=len(code),script_sig_bytes=len(script_sig),
                    signature_bytes=len(entry[1] if mutation=='extra-entry' else entry[0]),
                    hint_items=2 if row['selected'] else 0,
                    entry_items=len(entry),all_entry_items_coexist=True,complete_script_sig_pushes=len(entry)+1,
                    locked_input_witness_items=0,helper_witness_items=1,
                    script_hex=code.hex(),entry_hex=[v.hex() for v in entry],
                    host_trace=checked,extraction=extracted,transaction=spent))
                print('PASS',row['name'],flush=True)
            # Every raw sighash byte is inspected against the same transaction.
            first=rows[0]; code=first['code']; sig=first['entry'][0]
            inputs=[('22'*32,0,b'',0xffffffff),('22'*32,1,b'',0xffffffff)]
            outputs=[(1,b'\x51')]
            accepted=[]
            for flag in range(256):
                checked=trace(code,[sig[:-1]+bytes([flag])],inputs,outputs,1)
                assert checked['accepted']==(flag&31==3)
                if checked['accepted']: accepted.append(flag)
            report['all_raw_flag_host_screen']=dict(tested=256,accepted=accepted,consensus_tested_separately=False)
        finally:
            if node: node.close()
    paths=[ROOT/'examples/pointlock_fixed_digest_nonce_probe.rs',Path(__file__),HERE/'core_check.py',
           HERE/'publication_core_check.py',
           HERE/'dh_quartet_label_probe.py',HERE/'two_target_anchor_algebra.py',
           ROOT/'tests/pointlock_fixed_digest_nonce_vectors.rs',
           HERE.parent/'covenant-2026-09-17/legacy_same_signature_counterexample.py',ROOT/'Cargo.lock']
    report['source_sha256']={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    report['all_expectations_met']=True
    report['positive_cases']=sum(r['expected'] for r in rows)
    report['negative_cases']=sum(not r['expected'] for r in rows)
    output=HERE/('fixed-digest-nonce-host.json' if args.host_only else 'fixed-digest-nonce-core.json')
    output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(output=str(output),positive=report['positive_cases'],negative=report['negative_cases'])))


if __name__=='__main__': main()
