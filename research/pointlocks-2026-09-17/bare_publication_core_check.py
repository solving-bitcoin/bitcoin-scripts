#!/usr/bin/env python3
"""Complete bare-legacy sum-key publication on isolated Bitcoin Core regtest.

Validate funding, alternative 256-byte publications, consensus edge cases and
script-failing controls. Public deterministic fixtures; wallets and networking
disabled. This is a publication experiment, not complete BitVM3 integration.
"""
import functools
import hashlib
import json
import math
from pathlib import Path
import subprocess
import tempfile

from core_check import (Node, consensus_check, isolated_core_binary, transaction,
                        instructions, scalar_bytes, scalar_value, native_digest,
                        unpack_signature, decode_key, BUG_DIGEST)
from publication_core_check import accept_and_mine, encode_key, hash160
from legacy_same_signature_counterexample import N, G, mul, add, verify

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EXAMPLE = 'pointlock_bare_publication_probe'
MANIFEST = HERE/'bare-publication-transactions.json'
REPORT = HERE/'bare-publication-core-check.json'


@functools.lru_cache(maxsize=None)
def equation(signature, key, digest):
    r, s, flag = unpack_signature(signature)
    return verify(int.from_bytes(digest,'big') % N,r,s,decode_key(key))[0]


@functools.lru_cache(maxsize=None)
def scalar_opening(signature,key,digest):
    r,_,_ = unpack_signature(signature)
    value = -2*int.from_bytes(digest,'big')*pow(r,-1,N) % N
    assert mul(value) == add(decode_key(key),G)
    return f'{value:064x}'


def truth(data):
    return any(v != 0 and not (i == len(data)-1 and v == 128)
               for i,v in enumerate(data))


def script_sig_items(code):
    """Explicitly supported fixture scriptSigs, including DUP DROP control."""
    stack=[]
    peak=0
    for _,_,op,data in instructions(code):
        if data is not None: stack.append(data)
        elif op == 0: stack.append(b'')
        elif op == 0x4f: stack.append(b'\x81')
        elif 0x51 <= op <= 0x60: stack.append(scalar_bytes(op-0x50))
        elif op == 0x76: stack.append(stack[-1])
        elif op == 0x75: stack.pop()
        else: raise ValueError(f'unsupported fixture scriptSig opcode {op:02x}')
        peak=max(peak,len(stack))
    return stack,peak


def trace(code,entry,inputs,outputs,index):
    stack,alt=list(entry),[]
    peak=len(stack)
    checks=[]
    processed=0
    failure=None
    def number(data):
        assert len(data)<=4, 'scriptnum-overflow'
        return scalar_value(data)
    try:
        for _,_,op,data in instructions(code):
            processed += op > 0x60
            if data is not None: stack.append(data)
            elif op == 0: stack.append(b'')
            elif 0x51 <= op <= 0x60: stack.append(scalar_bytes(op-0x50))
            elif op == 0x6b: alt.append(stack.pop())
            elif op == 0x6c: stack.append(alt.pop())
            elif op == 0x76: stack.append(stack[-1])
            elif op == 0x78: stack.append(stack[-2])
            elif op == 0x82: stack.append(scalar_bytes(len(stack[-1])))
            elif op == 0xa0:
                right,left=number(stack.pop()),number(stack.pop())
                stack.append(scalar_bytes(int(left>right)))
            elif op == 0xa5:
                maximum,minimum,value=number(stack.pop()),number(stack.pop()),number(stack.pop())
                stack.append(scalar_bytes(int(minimum<=value<maximum)))
            elif op == 0x69: assert truth(stack.pop()), 'verify'
            elif op in (0x79,0x7a):
                depth=number(stack.pop())
                assert 0<=depth<len(stack), 'lookup-depth'
                item=stack[-1-depth] if op==0x79 else stack.pop(-1-depth)
                stack.append(item)
            elif op == 0xa9: stack.append(hash160(stack.pop()))
            elif op == 0x88: assert stack.pop()==stack.pop(), 'equalverify'
            elif op in (0xac,0xad):
                key,sigma=stack.pop(),stack.pop()
                digest,preimage,_=native_digest(inputs,outputs,index,code,sigma)
                accepted=equation(sigma,key,digest)
                checks.append(dict(key=key.hex(),signature=sigma.hex(),digest=digest.hex(),
                                   single_bug=preimage is None,accepted=accepted))
                if op==0xad: assert accepted, 'checksigverify'
                else: stack.append(scalar_bytes(int(accepted)))
            else: raise ValueError(f'unsupported locking opcode {op:02x}')
            peak=max(peak,len(stack)+len(alt))
            assert len(stack)+len(alt)<=1000, 'stack-limit'
        assert stack and truth(stack[-1]), 'false-terminal'
        assert not alt, 'unexpected-altstack'
    except (AssertionError,IndexError) as error:
        failure=str(error) or type(error).__name__
    return dict(accepted=failure is None,failure=failure,checks=checks,
                combined_stack_peak=peak,executed_non_push_opcodes=processed,
                final_main_items=len(stack),final_alt_items=len(alt))


def rank_subset(selected):
    value=0
    low=0
    for slot,index in enumerate(selected):
        assert low<=index<48
        value+=sum(math.comb(48-i-1,7-slot-1) for i in range(low,index))
        low=index+1
    return value


def inspect(funding,tx,built,expected_payload):
    inputs=[(v['txid'],v['vout'],bytes.fromhex(v['scriptSig']['hex']),v['sequence']) for v in tx['vin']]
    outputs=[(round(v['value']*100_000_000),bytes.fromhex(v['scriptPubKey']['hex'])) for v in tx['vout']]
    extracted=[]
    selected_by_pool={}
    traces=[]
    for index,vin in enumerate(tx['vin']):
        if vin['vout']==0: continue
        pool=vin['vout']-1
        assert vin['txid']==funding['txid'] and pool not in selected_by_pool
        code=bytes.fromhex(funding['vout'][pool+1]['scriptPubKey']['hex'])
        assert code.hex()==built['pool_commitments'][pool]['script_hex']
        entry,initial_peak=script_sig_items(bytes.fromhex(vin['scriptSig']['hex']))
        traced=trace(code,entry,inputs,outputs,index)
        traced['pool']=pool
        traced['entry_items']=len(entry)
        traced['script_sig_peak']=initial_peak
        traces.append(traced)
        if not traced['accepted']:
            return dict(lock_scripts_accepted=False,traces=traces)
        assert len(traced['checks'])==14
        commits=[data for _,_,_,data in instructions(code) if data is not None and len(data)==20]
        assert len(commits)==len(set(commits))==48
        assert commits==[hash160(bytes.fromhex(k)) for k in built['pool_commitments'][pool]['keys']]
        selected=[]
        for j in range(0,14,2):
            common,other=traced['checks'][j:j+2]
            assert common['key']==encode_key(G).hex()
            assert common['signature']==other['signature'] and common['digest']==other['digest']
            sig,key,digest=bytes.fromhex(other['signature']),bytes.fromhex(other['key']),bytes.fromhex(other['digest'])
            assert len(sig)>57
            label=commits.index(hash160(key))
            assert label not in selected
            selected.append(label)
            extracted.append(dict(pool=pool,label=label,scalar=scalar_opening(sig,key,digest)))
        selected_by_pool[pool]=sorted(selected)
    complete=len(selected_by_pool)==79
    rank=None
    payload=None
    if complete:
        rank=0
        for pool in range(79): rank=rank*math.comb(48,7)+rank_subset(selected_by_pool[pool])
        if rank < 2**2048: payload=rank.to_bytes(256,'big').hex()
    if expected_payload is not None: assert payload==expected_payload
    return dict(lock_scripts_accepted=True,complete_pools=complete,
                payload_hex=payload,unused_codeword=complete and payload is None,
                extracted_scalars=len(extracted),extractions=extracted,traces=traces,
                payload_sha256=None if payload is None else hashlib.sha256(bytes.fromhex(payload)).hexdigest())


def main():
    binary,provenance=isolated_core_binary(Path('/private/tmp/covenant-core-30.3'),False)
    report=dict(scope=__doc__,bitcoin_core=provenance,cases=[],
        evidence='differentially-validated',deployment='consensus-validated',
        policy_accepted=False,complete_bitvm3_protocol=False,setup_benchmark=None)
    with tempfile.TemporaryDirectory(prefix='bitcoin-lab-bare-publication-') as temporary:
        node=Node(binary,Path(temporary))
        try:
            node.ready()
            assert not node.rpc('getnetworkinfo')['networkactive'] and not node.rpc('getpeerinfo')
            report['node_options']=node.options
            deployments=node.rpc('getdeploymentinfo')['deployments']
            assert all(deployments[k]['active'] for k in ('segwit','taproot'))
            report['active_consensus_deployments']=['segwit','taproot']
            address=node.rpc('decodescript','51')['segwit']['address']
            mining=bytes.fromhex(node.rpc('validateaddress',address)['scriptPubKey'])
            blocks=[]
            for _ in range(101):
                node.tick();blocks+=node.rpc('generatetoaddress',1,address)
            coinbase=node.rpc('getblock',blocks[0],2)['tx'][0]
            coin=next(v for v in coinbase['vout'] if v['scriptPubKey']['hex']==mining.hex())
            grant=transaction(coinbase['txid'],coin['n'],[b'\x51'],[
                (100_000_000,b'\x51\x20'+G[0].to_bytes(32,'big')),
                (4_899_990_000,mining)])
            granted,report['excluded_test_grant']=accept_and_mine(node,address,grant['hex'])
            print('Core ready; building 3,792 independent public fixture points.',flush=True)
            command=['cargo','run','--release','--locked','--example',EXAMPLE,'--',
                     '--funding-txid',granted['txid'],'--funding-amount','100000000']
            run=subprocess.run(command,cwd=ROOT,text=True,capture_output=True,check=True)
            built=json.loads(run.stdout)
            MANIFEST.write_text(json.dumps(built,indent=2)+'\n')
            report['generator_command']=command
            report['generator_stderr']=run.stderr
            report['profile']=built['profile']
            funding=node.rpc('decoderawtransaction',built['funding']['hex'])
            assert funding['vsize']==98308 and funding['weight']==built['funding']['weight']
            policy=node.rpc('testmempoolaccept',[built['funding']['hex']])[0]
            assert not policy['allowed'] and policy['reject-reason']=='scriptpubkey',policy
            accepted=consensus_check(node,address,built['funding'])
            assert accepted['accepted']
            report['funding']=dict(**built['funding'],policy=policy,consensus=accepted)
            print('PASS bare funding: 98,308 vB, mined; default policy rejects custom outputs.',flush=True)
            # Test policy against the same funded chain before any conflicting spend.
            policies=[node.rpc('testmempoolaccept',[c['transaction']['hex']])[0] for c in built['cases']]
            height=node.rpc('getblockcount')
            for case,policy in zip(built['cases'],policies):
                decoded=node.rpc('decoderawtransaction',case['transaction']['hex'])
                assert decoded['vsize']==case['transaction']['vbytes'] and decoded['weight']==case['transaction']['weight']
                assert decoded['size']==case['transaction']['size'] and decoded['txid']==case['transaction']['txid']
                assert not policy['allowed'],(case['name'],policy)
                result=consensus_check(node,address,case['transaction'])
                assert result['accepted']==case['expected'],(case['name'],result)
                expected_payload=case['payload_hex'] if case['expected'] else None
                recovered=inspect(funding,decoded,built,expected_payload)
                if case['name']=='invalid-helper': assert recovered['lock_scripts_accepted']
                else: assert recovered['lock_scripts_accepted']==case['expected'],case['name']
                if result['accepted']:
                    remaining=[i for i in range(1,80) if node.rpc('gettxout',funding['txid'],i,False) is not None]
                    assert len(remaining)==(78 if case['name']=='partial-one-pool' else 0)
                    node.rpc('invalidateblock',result['block_hash'])
                assert node.rpc('getblockcount')==height
                report['cases'].append(dict(name=case['name'],expected=case['expected'],
                    transaction_metrics={k:v for k,v in case['transaction'].items() if k!='hex'},
                    consensus=result,policy=policy,recovery=recovered))
                print('PASS',case['name'],'consensus=',result['accepted'],
                      'scalars=',recovered.get('extracted_scalars',0),flush=True)
            primary=report['cases'][0]
            maximum=next(c for c in report['cases'] if c['name']=='message-zero')
            assert maximum['transaction_metrics']['vbytes']==63252
            report['combined_vbytes']=funding['vsize']+primary['transaction_metrics']['vbytes']
            report['maximum_canonical_vbytes']=funding['vsize']+maximum['transaction_metrics']['vbytes']
            assert report['maximum_canonical_vbytes']==161560
            report['summary']=dict(positive_cases=sum(c['expected'] for c in built['cases']),
                negative_cases=sum(not c['expected'] for c in built['cases']),all_expectations_met=True)
        finally:
            node.close()
    paths=[Path(__file__),ROOT/f'examples/{EXAMPLE}.rs',ROOT/'examples/pointlock_sum_lookup_probe.rs',
           ROOT/'Cargo.lock',ROOT/'tools/core_regtest.py',HERE/'core_check.py',HERE/'publication_core_check.py',
           HERE.parent/'covenant-2026-09-17/core_gate_check.py',
           HERE.parent/'covenant-2026-09-17/legacy_same_signature_counterexample.py',
           ROOT/'src/signatures/pointlocks/mod.rs',ROOT/'src/signatures/pointlocks/sum_key/mod.rs',
           ROOT/'src/support/script.rs',MANIFEST]
    report['source_sha256']={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    report['generator_binary_sha256']=hashlib.sha256((ROOT/f'target/release/examples/{EXAMPLE}').read_bytes()).hexdigest()
    REPORT.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(**report['summary'],combined_vbytes=report['combined_vbytes'],
                          maximum_canonical_vbytes=report['maximum_canonical_vbytes'])),flush=True)


if __name__=='__main__':
    main()
