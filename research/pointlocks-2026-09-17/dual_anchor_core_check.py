#!/usr/bin/env python3
"""Public opening of a proposed dual-anchor/sum-key repair, without log(T).

This is a negative result for that replacement, not for the existing cap60
anchored predicate. Only a disposable network/wallet-disabled regtest is used.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from core_check import (Node, consensus_check, decode_key, instructions,
                        isolated_core_binary, scalar_bytes, scalar_value,
                        transaction, unpack_signature)
from core_regtest import compact_size, vector
from anchored_extraction import der
from anchored_native_core_check import digest
from anchored_consensus_flags_check import serialized
from publication_core_check import accept_and_mine, encode_key
from typed_selector_core_check import sign
from legacy_same_signature_counterexample import G, N, P as FIELD, add, mul, verify

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def opening(fixture, txid, mining):
    """Accept only public points and transaction context, never target scalars."""
    code = bytes.fromhex(fixture['script_hex'])
    target = decode_key(bytes.fromhex(fixture['target_hex']))
    tau = bytes.fromhex(fixture['tau_hex'])
    rt, st, flag = unpack_signature(tau)
    assert rt == target[0] and st == flag == 1 and len(tau) == 40
    assert not any(op == 0xab for _,_,op,data in instructions(code) if data is None)
    tx = dict(version=2, locktime=0, vin=[
        dict(txid=txid, vout=i, sequence=0xffffffff, scriptSig={'hex':''},
             txinwitness=['51'] if i == 0 else []) for i in range(2)],
        vout=[dict(value=0.0019,scriptPubKey={'hex':mining.hex()})])
    message = digest(tx, 1, code, 1)
    z = int.from_bytes(message, 'big') % N
    assert z != 0
    neg_z = mul(-z % N)
    left = mul(pow(rt,-1,N), add(target, neg_z))
    right = mul(pow(rt,-1,N), add((target[0], -target[1] % FIELD), neg_z))
    assert left is not None and right is not None and left != right
    sigma = der(rt, N-1)
    assert len(sigma) == 72
    # The only scalar revealed by the sum-key theorem is already computable
    # from public rt and z. No equation below computes log(target).
    sum_scalar = -2*z*pow(rt,-1,N) % N
    assert add(left,right) == mul(sum_scalar)
    expected = [(tau,left,target), (tau,right,(target[0],-target[1] % FIELD)),
                (sigma,left,(target[0],-target[1] % FIELD)), (sigma,right,target)]
    for signature, key, nonce in expected:
        r,s,_ = unpack_signature(signature)
        assert verify(z,r,s,key) == (True,nonce)
    auth = sign(1, message)
    tx['vin'][1]['txinwitness'] = [v.hex() for v in
        (sigma, encode_key(left), encode_key(right), auth, code)]
    return tx, dict(digest_hex=message.hex(), target_hex=encode_key(target).hex(),
        sum_scalar_hex=f'{sum_scalar:064x}', sigma_bytes=len(sigma),
        target_scalar_used=False, public_curve_equations_checked=4)


def trace(tx):
    """Independent narrow stack and actual BIP143 equation trace."""
    witness = [bytes.fromhex(x) for x in tx['vin'][1]['txinwitness']]
    code = witness.pop()
    stack = witness
    peak, checks, ops = len(stack), 0, 0
    failure = None
    try:
        for _,_,op,data in instructions(code):
            if data is not None:
                stack.append(data)
            elif op == 0:
                stack.append(b'')
            elif 0x51 <= op <= 0x60:
                stack.append(scalar_bytes(op-0x50))
            elif op == 0x69:
                assert scalar_value(stack.pop()) != 0, 'verify'
            elif op == 0x6e:
                stack.extend(stack[-2:])
            elif op == 0x75:
                stack.pop()
            elif op == 0x76:
                stack.append(stack[-1])
            elif op == 0x78:
                stack.append(stack[-2])
            elif op == 0x79:
                index = scalar_value(stack.pop())
                assert 0 <= index < len(stack), 'pick'
                stack.append(stack[-1-index])
            elif op == 0x7b:
                stack.append(stack.pop(-3))
            elif op == 0x7c:
                stack[-2:] = stack[-2:][::-1]
            elif op == 0x82:
                stack.append(scalar_bytes(len(stack[-1])))
            elif op in (0x87,0x88):
                equal = stack.pop() == stack.pop()
                if op == 0x88:
                    assert equal, 'equalverify'
                else:
                    stack.append(scalar_bytes(int(equal)))
            elif op == 0x91:
                stack.append(scalar_bytes(int(scalar_value(stack.pop()) == 0)))
            elif op == 0xa0:
                right, left = scalar_value(stack.pop()), scalar_value(stack.pop())
                stack.append(scalar_bytes(int(left > right)))
            elif op == 0xad:
                key, signature = decode_key(stack.pop()), stack.pop()
                r,s,flag = unpack_signature(signature)
                z = int.from_bytes(digest(tx,1,code,flag),'big') % N
                assert verify(z,r,s,key)[0], 'ecdsa'
                checks += 1
            else:
                raise ValueError(f'unmodeled opcode {op:02x}')
            peak = max(peak,len(stack))
            ops += op > 0x60 and data is None
        assert stack == [b'\x01'], 'cleanstack'
    except (AssertionError,IndexError) as error:
        failure = str(error) or type(error).__name__
    return dict(accepted=failure is None, failure=failure, signature_checks=checks,
                combined_stack_peak=peak, executed_non_push_opcodes=ops)


def cases(fixture, tx, derivation):
    yield dict(name='public-high-s-opening', tx=tx, expected_consensus=True,
               expected_policy=False, derivation=derivation)
    swapped = copy.deepcopy(tx)
    w = swapped['vin'][1]['txinwitness']
    w[1],w[2] = w[2],w[1]
    yield dict(name='public-high-s-opening-swapped-keys',tx=swapped,
               expected_consensus=True,expected_policy=False)
    rt = decode_key(bytes.fromhex(fixture['target_hex']))[0]
    mutations = [
        ('low-s-anchor-fails-long-size-guard',0,fixture['tau_hex']),
        ('wrong-response',0,der(rt,N-2).hex()),
        ('duplicate-recovery-keys',2,tx['vin'][1]['txinwitness'][1]),
        ('wrong-recovery-key',2,encode_key(G).hex()),
        ('different-signature-flag',0,(der(rt,N-1)[:-1]+b'\x21').hex()),
    ]
    for name,index,value in mutations:
        changed = copy.deepcopy(tx)
        changed['vin'][1]['txinwitness'][index] = value
        yield dict(name=name,tx=changed,expected_consensus=False,expected_policy=False)
    extra = copy.deepcopy(tx)
    extra['vin'][1]['txinwitness'].insert(0,'01')
    yield dict(name='extra-entry',tx=extra,expected_consensus=False,expected_policy=False)
    changed = copy.deepcopy(tx)
    changed['vin'][1]['sequence'] -= 1
    code = bytes.fromhex(fixture['script_hex'])
    changed['vin'][1]['txinwitness'][-2] = sign(1,digest(changed,1,code,1)).hex()
    yield dict(name='changed-transaction-with-fresh-authorization',tx=changed,
               expected_consensus=False,expected_policy=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host-only',action='store_true')
    args = parser.parse_args()
    built = subprocess.run(['cargo','run','--release','--locked','--example',
                            'pointlock_dual_anchor_probe'],cwd=ROOT,text=True,capture_output=True,check=True)
    fixture = json.loads(built.stdout)
    binary, provenance = (None,None) if args.host_only else isolated_core_binary(Path('/private/tmp/covenant-core-30.3'),False)
    report = dict(scope=__doc__,fixture=fixture,cases=[],evidence='locally-reproduced',
                  deployment='unclassified',general_pointlock=False,
                  target_scalar_computed=False)
    with tempfile.TemporaryDirectory(prefix='bitcoin-lab-dual-anchor-') as temporary:
        node = Node(binary,Path(temporary)) if binary else None
        try:
            if node:
                node.ready()
                assert not node.rpc('getnetworkinfo')['networkactive'] and not node.rpc('getpeerinfo')
                address = node.rpc('decodescript','51')['segwit']['address']
                mining = bytes.fromhex(node.rpc('validateaddress',address)['scriptPubKey'])
                blocks=[]
                for _ in range(101):
                    node.tick(); blocks += node.rpc('generatetoaddress',1,address)
                coinbase=node.rpc('getblock',blocks[0],2)['tx'][0]
                coin=next(v for v in coinbase['vout'] if v['scriptPubKey']['hex']==mining.hex())
                code=bytes.fromhex(fixture['script_hex'])
                fund=transaction(coinbase['txid'],coin['n'],[b'\x51'],[
                    (100_000,mining),(100_000,b'\x00\x20'+hashlib.sha256(code).digest()),
                    (5_000_000_000-210_000,mining)])
                funding,report['test_only_funding']=accept_and_mine(node,address,fund['hex'])
                txid=funding['txid']
                report.update(bitcoin_core=provenance,node_options=node.options)
            else:
                txid='11'*32
                mining=b'\x00\x20'+hashlib.sha256(b'\x51').digest()
            tx,derivation=opening(fixture,txid,mining)
            for case in cases(fixture,tx,derivation):
                observation=trace(case['tx'])
                assert observation['accepted']==case['expected_consensus'],(case['name'],observation)
                record={k:v for k,v in case.items() if k!='tx'}
                record.update(independent_trace=observation,transaction=serialized(case['tx']))
                if node:
                    policy=node.rpc('testmempoolaccept',[record['transaction']['hex']])[0]
                    assert policy['allowed']==case['expected_policy'],(case['name'],policy)
                    record['policy']=policy
                report['cases'].append(record)
            if node:
                height=node.rpc('getblockcount')
                for case in report['cases']:
                    verdict=consensus_check(node,address,case['transaction'])
                    assert verdict['accepted']==case['expected_consensus'],(case['name'],verdict)
                    case['consensus']=verdict
                    if verdict['accepted']:
                        node.rpc('invalidateblock',verdict['block_hash'])
                    assert node.rpc('getblockcount')==height
                report.update(evidence='differentially-validated',deployment='consensus-validated')
            witness=[bytes.fromhex(v) for v in tx['vin'][1]['txinwitness']]
            report['metrics']=dict(script_bytes=fixture['script_bytes'],hint_items_per_input=0,
                total_hint_items=0,entry_items=4,complete_witness_items=5,
                serialized_witness_bytes=len(compact_size(len(witness)))+sum(len(vector(v)) for v in witness),
                combined_stack_peak=trace(tx)['combined_stack_peak'],
                executed_non_push_opcodes=trace(tx)['executed_non_push_opcodes'],
                signature_checks=5)
        finally:
            if node:
                node.close()
    paths=[Path(__file__),ROOT/'examples/pointlock_dual_anchor_probe.rs',ROOT/'Cargo.lock',
           HERE/'core_check.py',HERE/'anchored_native_core_check.py',HERE/'anchored_extraction.py',
           HERE/'anchored_consensus_flags_check.py',HERE/'publication_core_check.py',
           HERE/'typed_selector_core_check.py',HERE/'nonce_relation_extraction.py',
           HERE.parent/'covenant-2026-09-17/legacy_same_signature_counterexample.py']
    report['source_sha256']={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    report['summary']=dict(positive_consensus_cases=2,negative_cases=7,all_expectations_met=True)
    suffix='host' if args.host_only else 'core'
    (HERE/f'dual-anchor-{suffix}-check.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report['summary'],sort_keys=True))


if __name__=='__main__':
    main()
