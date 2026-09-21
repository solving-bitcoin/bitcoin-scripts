#!/usr/bin/env python3
"""Publish/recover one256bytevalue through183 independent sum-lock pools on Core.

Fresh regtest, wallets/network disabled. A test-only grant supplies the initial
P2TR input. Reported publication cost includes the creation and two assertion
transactions, excluding mining/setup. No complete BitVM3 protocol is claimed.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import itertools
import math
import json
from pathlib import Path
import subprocess
import tempfile

from core_check import isolated_core_binary, Node, transaction, p2sh
from core_check import unpack_signature, decode_key
from legacy_same_signature_counterexample import N, G, mul, add

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
BUG_SCALAR=1 << 248
spec=importlib.util.spec_from_file_location('encoding_optimization',HERE/'encoding-optimization.py')
encoding=importlib.util.module_from_spec(spec)
spec.loader.exec_module(encoding)


def hash160(data):
    return hashlib.new('ripemd160',hashlib.sha256(data).digest()).digest()


def instructions(script):
    pc=0
    while pc<len(script):
        op=script[pc];pc+=1;data=None
        if op<=75:
            data=script[pc:pc+op];pc+=op
        elif op in (0x4c,0x4d,0x4e):
            width={0x4c:1,0x4d:2,0x4e:4}[op]
            count=int.from_bytes(script[pc:pc+width],'little');pc+=width
            data=script[pc:pc+count];pc+=count
        assert pc<=len(script),'truncated push'
        yield op,data


def pushed_elements(script):
    items=[]
    for op,data in instructions(script):
        if data is not None:
            items.append(data)
        elif op==0x4f:
            items.append(b'\x81')
        elif 0x51<=op<=0x60:
            items.append(bytes([op-0x50]))
        else:
            raise AssertionError(f'non-push opcode {op:x} in scriptSig')
    return items


def encode_key(point):
    assert point is not None
    return bytes([2+(point[1]&1)])+point[0].to_bytes(32,'big')


def accept_and_mine(node,address,raw):
    decoded=node.rpc('decoderawtransaction',raw)
    policy=node.rpc('testmempoolaccept',[raw])[0]
    assert policy['allowed'],policy
    assert decoded['weight']<=400000,decoded['weight']
    assert node.rpc('sendrawtransaction',raw)==decoded['txid']
    node.tick()
    block_hash=node.rpc('generatetoaddress',1,address)[0]
    block=node.rpc('getblock',block_hash)
    assert decoded['txid'] in block['tx']
    assert decoded['txid'] not in node.rpc('getrawmempool')
    return decoded,{'txid':decoded['txid'],'wtxid':decoded['hash'],
                    'weight':decoded['weight'],'vsize':decoded['vsize'],
                    'size':decoded['size'],'inputs':len(decoded['vin']),
                    'outputs':len(decoded['vout']),'policy':policy,
                    'block_hash':block_hash,'block_height':block['height'],
                    'consensus_accepted':True,'hex':raw}


def recover_from_transactions(funding,assertions,selection,built):
    parameters=selection['pool_parameters']
    pools,total=len(parameters),selection['global_revelations']
    proof_bytes=len(bytes.fromhex(selection['proof_hex']))
    assert len(funding['vout'])==pools+1
    recovered=[None]*pools
    seen=set()
    extraction=[]
    commitments_by_pool=built['pool_commitments']
    all_keys=[key for table in commitments_by_pool for key in table['verification_keys_hex']]
    candidates=sum(p['n'] for p in parameters)
    assert len(all_keys)==candidates and len(set(all_keys))==candidates
    for tx in assertions:
        assert len(tx['vout'])==1,'constant digest requires exactly one output'
        for input_index,vin in enumerate(tx['vin'][1:],1):
            assert vin['txid']==funding['txid']
            pool=vin['vout']-1
            assert 0<=pool<pools and pool not in seen
            n,t=parameters[pool]['n'],parameters[pool]['t']
            seen.add(pool)
            assert input_index>=len(tx['vout'])
            items=pushed_elements(bytes.fromhex(vin['scriptSig']['hex']))
            assert len(items)==3*t+1
            redeem=items.pop()
            assert len(redeem)=={(17,4):505,(18,3):502,(14,3):410,(15,3):434}[(n,t)]
            assert funding['vout'][pool+1]['scriptPubKey']['hex']==p2sh(redeem).hex()
            commitments=[data for _,data in instructions(redeem)
                         if data is not None and len(data)==20]
            assert len(commitments)==n and len(set(commitments))==n
            table=commitments_by_pool[pool]
            assert [hash160(bytes.fromhex(key)) for key in table['verification_keys_hex']]==commitments
            assert table['redeem_hex']==redeem.hex()
            selected=[]
            for j in range(t):
                signature,key,hint=items[3*j:3*j+3]
                assert len(signature)==71 and len(key)==33 and hint
                digest=hash160(key)
                index=commitments.index(digest)
                assert index not in selected
                selected.append(index)
                r,s,flag=unpack_signature(signature)
                assert flag==3 and s<=N//2
                scalar=(-2*BUG_SCALAR*pow(r,-1,N))%N
                target=add(decode_key(key),G)
                assert mul(scalar)==target,'independent scalar extraction failed'
                assert key.hex()==table['verification_keys_hex'][index]
                assert encode_key(target).hex()==table['targets_hex'][index]
                extraction.append({'pool':pool,'index':index,'scalar_hex':f'{scalar:064x}',
                                   'target_point':encode_key(target).hex(),
                                   'signature_r':f'{r:064x}'})
            selected.sort()
            assert len(selected)==t
            recovered[pool]=selected
    assert len(seen)==pools and len(extraction)==total
    rank=0
    for par,selected in zip(parameters,recovered):
        digit=tuple(itertools.combinations(range(par['n']),par['t'])).index(tuple(selected))
        rank=rank*math.comb(par['n'],par['t'])+digit
    assert rank<1<<(8*proof_bytes),'unused codeword'
    proof=rank.to_bytes(proof_bytes,'big').hex()
    assert proof==selection['proof_hex']
    assert recovered==selection['selections']
    return {'proof_hex':proof,'proof_sha256':hashlib.sha256(bytes.fromhex(proof)).hexdigest(),
            'global_revelations':total,'recovered_selections':recovered,
            'independently_extracted_points':len(extraction),'extractions':extraction,
            'method':'Parse actual Core-decoded scriptSigs; authenticate P against funded HASH160 table; check tG=P+G with t=-2C/r; rank mixed-radix complete selections.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',type=int,choices=(128,256),default=256)
    parser.add_argument('--selection',type=Path)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--transactions-output',type=Path)
    parser.add_argument('--cache-dir',type=Path,default=Path('/private/tmp/covenant-core-30.3'))
    args=parser.parse_args()
    prefix='conditional128-' if args.profile==128 else ''
    args.selection=args.selection or HERE/(prefix+'publication-selection.json')
    args.output=args.output or HERE/(prefix+'publication_core_check.json')
    args.transactions_output=args.transactions_output or HERE/(prefix+'publication-transactions.json')
    selection=json.loads(args.selection.read_text())
    if args.profile==256:
        assert selection['pool_parameters']==[{'n':17,'t':4}]*180+[{'n':18,'t':3}]*3
        assert len(selection['selections'])==183 and sum(map(len,selection['selections']))==729
    else:
        assert selection['pool_parameters']==[{'n':17,'t':4}]*89+[{'n':14,'t':3}]*2+[{'n':15,'t':3}]
        assert len(selection['selections'])==92 and sum(map(len,selection['selections']))==365
    assert len(bytes.fromhex(selection['proof_hex']))==args.profile
    binary,provenance=isolated_core_binary(args.cache_dir,False)
    report={'scope':(__doc__ if args.profile==256 else 'Conditional 128-byte synthetic payload publication. No claim that arbitrary 256 bytes compress, or that this synthetic value is a Groth16 proof.'),'bitcoin_core':provenance,
            'payload_bytes':args.profile,
            'selection_sha256':hashlib.sha256(args.selection.read_bytes()).hexdigest(),
            'evidence':'differentially-validated','deployment_class':'policy-validated',
            'policy_method':'Default testmempoolaccept and sendrawtransaction; each transaction mined before the next.',
            'transactions':[]}
    with tempfile.TemporaryDirectory(prefix='bitcoin-lab-publication-') as temporary:
        node=Node(binary,Path(temporary))
        try:
            node.ready()
            report['node_options']=node.options
            report['networkactive']=node.rpc('getnetworkinfo')['networkactive']
            report['peer_count']=len(node.rpc('getpeerinfo'))
            assert not report['networkactive'] and report['peer_count']==0
            address=node.rpc('decodescript','51')['segwit']['address']
            mining=bytes.fromhex(node.rpc('validateaddress',address)['scriptPubKey'])
            blocks=[]
            for _ in range(101):
                node.tick();blocks+=node.rpc('generatetoaddress',1,address)
            coinbase=node.rpc('getblock',blocks[0],2)['tx'][0]
            coin=next(v for v in coinbase['vout'] if v['scriptPubKey']['hex']==mining.hex())
            raw_p2tr=b'\x51\x20'+G[0].to_bytes(32,'big')
            amount=100_000_000
            grant=transaction(coinbase['txid'],coin['n'],[b'\x51'],
                              [(amount,raw_p2tr),(5_000_000_000-amount-10_000,mining)])
            grant_decoded,grant_report=accept_and_mine(node,address,grant['hex'])
            report['excluded_test_setup_grant']=grant_report
            print('Core ready; public deterministic test input funded.',flush=True)
            command=['cargo','run','--locked','--example','pointlock_publication_probe','--',
                     '--profile',str(args.profile),
                     '--selection-json',str(args.selection),
                     '--funding-txid',grant_decoded['txid'],'--funding-vout','0',
                     '--funding-amount',str(amount)]
            completed=subprocess.run(command,cwd=ROOT,text=True,capture_output=True,check=True)
            built=json.loads(completed.stdout)
            args.transactions_output.write_text(json.dumps(built,indent=2)+'\n')
            report['rust_generation_stderr']=completed.stderr
            raw_transactions=[built['funding_tx_hex']]+built['assertion_tx_hexes']
            assert len(raw_transactions)==(3 if args.profile==256 else 2)
            decoded=[]
            for ordinal,raw in enumerate(raw_transactions):
                dec,result=accept_and_mine(node,address,raw)
                decoded.append(dec);report['transactions'].append(result)
                print(f"PASS transaction {ordinal}: {result['vsize']}vB/{result['weight']}WU",flush=True)
            report['recovery']=recover_from_transactions(decoded[0],decoded[1:],selection,built)
            report['combined_vbytes']=sum(r['vsize'] for r in report['transactions'])
            report['combined_weight']=sum(r['weight'] for r in report['transactions'])
            if args.profile==256:
                assert report['combined_vbytes']==185146,report['combined_vbytes']
            else:
                assert report['combined_vbytes']<=92853,report['combined_vbytes']
            report['all_expectations_met']=True
            print(f"PASS independent recovery of all {selection['global_revelations']} scalars and exact {args.profile}-byte value.",flush=True)
        finally:
            node.close()
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(args.output)

if __name__=='__main__':
    main()
