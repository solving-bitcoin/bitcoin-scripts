#!/usr/bin/env python3
"""Reduced-work cap59 P2WSH functionality only; no production cap53 grind."""
import hashlib
import argparse
import math
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from core_check import isolated_core_binary, Node, consensus_check, transaction, unpack_signature, decode_key
from publication_core_check import accept_and_mine, encode_key, hash160, instructions
from legacy_same_signature_counterexample import N, G, mul, verify, hash256
from core_regtest import vector

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

def satoshis(value):
    return round(value * 100_000_000)

def native_digest(tx, funding, index, script):
    vin=tx['vin'][index]
    out=tx['vout'][index]
    output=struct.pack('<Q',satoshis(out['value']))+vector(bytes.fromhex(out['scriptPubKey']['hex']))
    preimage=(struct.pack('<I',tx['version'])+bytes(64)
              +bytes.fromhex(vin['txid'])[::-1]+struct.pack('<I',vin['vout'])
              +vector(script)+struct.pack('<Q',satoshis(funding['vout'][vin['vout']]['value']))
              +struct.pack('<I',vin['sequence'])+hash256(output)
              +struct.pack('<II',tx['locktime'],0x83))
    return hash256(preimage)

def recover(funding,spend,built):
    records=[]
    proof_rank=0
    candidate_count=0
    for pool in built['pools']:
        i=pool['input_index']
        witness=[bytes.fromhex(x) for x in spend['vin'][i]['txinwitness']]
        script=witness.pop()
        assert script.hex()==pool['script_hex']
        assert funding['vout'][i]['scriptPubKey']['hex']=='0020'+hashlib.sha256(script).hexdigest()
        digest=native_digest(spend,funding,i,script)
        assert digest.hex()==pool['native_digest_hex']
        z=int.from_bytes(digest,'big')
        frames=[]
        if pool.get('family')=='batched-multisig':
            assert [data.hex() for _,data in instructions(script) if data is not None and len(data)==33]==pool['keys_hex']
            blocks=pool['blocks'];per=pool['selected_per_block'];n=pool['keys_per_block']
            assert len(witness)==blocks*(per+1)
            for block in range(blocks):
                chunk=witness[(blocks-1-block)*(per+1):(blocks-block)*(per+1)]
                assert chunk[0]==b''
                allowed={pool['keys_hex'][block*n+j]:block*n+j for j in range(n)}
                selected_block=[]
                for sig in chunk[1:]:
                    r,s,flag=unpack_signature(sig)
                    scalars=[((s*k-z)*pow(r,-1,N))%N for k in ((N+1)//2,(N-1)//2)]
                    possible=[encode_key(mul(t)).hex() for t in scalars]
                    matched=[key for key in possible if key in allowed]
                    assert len(matched)==1
                    key=matched[0];selected=allowed[key]
                    selected_block.append(selected-block*n)
                    frames.append((sig,bytes.fromhex(key),selected))
                assert selected_block==sorted(set(selected_block))
                proof_rank=proof_rank*math.comb(n,per)+rank_subset(selected_block,n)
        else:
            assert [data.hex() for _,data in instructions(script) if data is not None and len(data)==20]==[hash160(bytes.fromhex(k)).hex() for k in pool['keys_hex']]
            remaining=list(range(pool['n']))
            recovered_indices=[]
            for j in range(pool['t']):
                sig,key,hint=witness[3*j:3*j+3]
                depth=int.from_bytes(hint,'little')
                assert 2<=depth<len(remaining)+2
                selected=remaining.pop(len(remaining)+1-depth)
                frames.append((sig,key,selected));recovered_indices.append(selected)
            if built.get('payload_bytes',0):
                proof_rank=proof_rank*math.comb(pool['n'],pool['t'])+rank_subset(sorted(recovered_indices),pool['n'])
        for j,(sig,key,selected) in enumerate(frames):
            assert len(sig)==59
            assert selected==pool['selected'][j]
            assert key.hex()==pool['keys_hex'][selected]
            r,s,flag=unpack_signature(sig)
            assert flag==0x83 and r==int('3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63',16)
            point=decode_key(key)
            assert verify(z,r,s,point)[0]
            candidates=[((s*k-z)*pow(r,-1,N))%N for k in ((N+1)//2,(N-1)//2)]
            matches=[t for t in candidates if mul(t)==point]
            assert len(matches)==1
            scalar=matches[0]
            assert f'{scalar:064x}'==pool['selected_secret_hex'][j]
            records.append(dict(pool=pool['pool'],index=selected,scalar_hex=f'{scalar:064x}',target_point=encode_key(point).hex()))
        # Verify every candidate's opening at the same actual native digest,
        # including the five candidates not selected in this transaction.
        for key,sig in zip(pool['keys_hex'],pool['all_signature_hex']):
            sig=bytes.fromhex(sig);r,s,flag=unpack_signature(sig)
            assert len(sig)==59 and flag==0x83
            assert verify(z,r,s,decode_key(bytes.fromhex(key)))[0]
            candidate_count+=1
    assert len(records)==sum(p['t'] for p in built['pools'])
    report=dict(extracted_points=len(records),all_candidate_signatures_checked=candidate_count,extractions=records)
    if built.get('payload_bytes',0):
        assert proof_rank<1<<2048
        payload=proof_rank.to_bytes(256,'big')
        assert payload.hex()==built['payload_hex']
        report.update(payload_hex=payload.hex(),payload_sha256=hashlib.sha256(payload).hexdigest(),payload_bytes=len(payload))
    return report

def rank_subset(selected,n):
    rank=0;low=0
    for j,v in enumerate(selected):
        for candidate in range(low,v):
            rank+=math.comb(n-candidate-1,len(selected)-j-1)
        low=v+1
    return rank

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',choices=('two-pool','full256','batch256'),default='two-pool')
    args=parser.parse_args()
    prefix={'two-pool':'windowed','full256':'windowed256','batch256':'windowedbatch256'}[args.profile]
    binary,provenance=isolated_core_binary(Path('/private/tmp/covenant-core-30.3'),False)
    report=dict(scope=__doc__,bitcoin_core=provenance,production_work_executed=False,
                evidence='differentially-validated',deployment_class='policy-validated',negative_cases=[])
    with tempfile.TemporaryDirectory(prefix='bitcoin-lab-windowed-native-') as temporary:
        node=Node(binary,Path(temporary))
        try:
            node.ready();report['node_options']=node.options
            assert not node.rpc('getnetworkinfo')['networkactive'] and not node.rpc('getpeerinfo')
            address=node.rpc('decodescript','51')['segwit']['address']
            mining=bytes.fromhex(node.rpc('validateaddress',address)['scriptPubKey'])
            blocks=[]
            for _ in range(101):
                node.tick();blocks+=node.rpc('generatetoaddress',1,address)
            coinbase=node.rpc('getblock',blocks[0],2)['tx'][0]
            coin=next(v for v in coinbase['vout'] if v['scriptPubKey']['hex']==mining.hex())
            amount=100_000_000
            grant=transaction(coinbase['txid'],coin['n'],[b'\x51'],[(amount,b'\x51\x20'+G[0].to_bytes(32,'big')),(5_000_000_000-amount-10_000,mining)])
            grant_decoded,report['excluded_test_setup_grant']=accept_and_mine(node,address,grant['hex'])
            command=['cargo','run','--locked','--example','pointlock_windowed_native_probe','--','--profile',args.profile,'--funding-txid',grant_decoded['txid'],'--funding-vout','0','--funding-amount',str(amount)]
            completed=subprocess.run(command,cwd=ROOT,text=True,capture_output=True,check=True)
            built=json.loads(completed.stdout)
            (HERE/(prefix+'-native-transactions.json')).write_text(json.dumps(built,indent=2)+'\n')
            report['rust_generation_stderr']=completed.stderr
            funding,report['funding']=accept_and_mine(node,address,built['funding']['hex'])
            for case in built['negative_cases']:
                tx=case['transaction']
                policy=node.rpc('testmempoolaccept',[tx['hex']])[0]
                consensus=consensus_check(node,address,tx)
                assert not policy['allowed'] and not consensus['accepted'],case['name']
                report['negative_cases'].append(dict(name=case['name'],policy=policy,consensus=consensus))
                print('PASS negative',case['name'],flush=True)
            spending,report['spending']=accept_and_mine(node,address,built['spending']['hex'])
            report['recovery']=recover(funding,spending,built)
            report['profile']=args.profile
            report['pools']=built['pools']
            report['combined_vbytes']=report['funding']['vsize']+report['spending']['vsize']
            report['all_expectations_met']=True
            print(f"PASS cap59 {args.profile} native publication: {report['combined_vbytes']} combined vB; {report['recovery']['extracted_points']} extractions; {report['recovery']['all_candidate_signatures_checked']} native signatures.",flush=True)
        finally:
            node.close()
    path=HERE/(prefix+'_native_core_check.json')
    path.write_text(json.dumps(report,indent=2)+'\n')
    print(path)

if __name__=='__main__': main()
