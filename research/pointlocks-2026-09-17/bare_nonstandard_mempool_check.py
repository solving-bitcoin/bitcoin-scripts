#!/usr/bin/env python3
"""Test bare publication with explicit nonstandard relay policy on isolated regtest."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tempfile

from core_check import Node, consensus_check, isolated_core_binary, transaction
from publication_core_check import accept_and_mine
from bare_publication_core_check import inspect
from legacy_same_signature_counterexample import G

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--patched',action='store_true')
    parser.add_argument('--default-policy',action='store_true')
    args=parser.parse_args()
    assert not args.default_policy or args.patched
    baseline=json.loads((HERE/'bare-publication-transactions.json').read_text())
    if args.patched:
        provenance=json.loads((HERE/'core-nonstandard-build.json').read_text())
        binary=Path(provenance['binary'])
        assert hashlib.sha256(binary.read_bytes()).hexdigest()==provenance['binary_sha256']
    else:
        binary,provenance=isolated_core_binary(Path('/private/tmp/covenant-core-30.3'),False)
    label='patched-default' if args.default_policy else 'patched' if args.patched else 'config-only'
    report=dict(scope=__doc__,mode=label,bitcoin_core=provenance,cases=[],
        original_scripts_unchanged=True,consensus_rules_relaxed=False,
        default_relay_accepted=False,evidence='differentially-validated',
        deployment='consensus-validated')
    with tempfile.TemporaryDirectory(prefix='bitcoin-lab-bare-nonstandard-') as temporary:
        temp=Path(temporary)
        # Only this disposable node receives the opt-in switch. Core uses the
        # last command-line setting; the funding acceptance tests this override.
        wrapper=temp/'nonstandard-bitcoind'
        override=[] if args.default_policy else ['-acceptnonstdtxn=1']
        wrapper.write_text('#!/bin/sh\nexec '+shlex.quote(str(binary))+' "$@" '+ ' '.join(override)+'\n')
        wrapper.chmod(0o700)
        datadir=temp/'data';datadir.mkdir()
        node=Node(wrapper,datadir)
        try:
            node.ready()
            report['effective_node_options']=node.options+override
            assert not node.rpc('getnetworkinfo')['networkactive'] and not node.rpc('getpeerinfo')
            address=node.rpc('decodescript','51')['segwit']['address']
            mining=bytes.fromhex(node.rpc('validateaddress',address)['scriptPubKey'])
            blocks=[]
            for _ in range(101):
                node.tick();blocks+=node.rpc('generatetoaddress',1,address)
            coinbase=node.rpc('getblock',blocks[0],2)['tx'][0]
            coin=next(v for v in coinbase['vout'] if v['scriptPubKey']['hex']==mining.hex())
            grant=transaction(coinbase['txid'],coin['n'],[b'\x51'],[
                (100_000_000,b'\x51\x20'+G[0].to_bytes(32,'big')),(4_899_990_000,mining)])
            granted,report['excluded_test_grant']=accept_and_mine(node,address,grant['hex'])
            run=subprocess.run(['cargo','run','--release','--locked','--example','pointlock_bare_publication_probe','--',
                '--funding-txid',granted['txid'],'--funding-amount','100000000'],cwd=ROOT,
                text=True,capture_output=True,check=True)
            built=json.loads(run.stdout)
            assert built['pool_commitments']==baseline['pool_commitments']
            assert built['profile']==baseline['profile']
            for old,new in zip(baseline['cases'],built['cases']):
                assert old['name']==new['name'] and old['expected']==new['expected']
                assert old['transaction']['vbytes']==new['transaction']['vbytes']
            if args.default_policy:
                funding=node.rpc('decoderawtransaction',built['funding']['hex'])
                policy=node.rpc('testmempoolaccept',[built['funding']['hex']])[0]
                assert not policy['allowed'] and policy['reject-reason']=='scriptpubkey',policy
                result=consensus_check(node,address,built['funding'])
                assert result['accepted']
                report['funding']=dict(**built['funding'],policy=policy,consensus=result)
            else:
                funding,report['funding']=accept_and_mine(node,address,built['funding']['hex'])
            assert funding['vsize']==98308
            print('PASS',label,'funding', 'default policy rejection preserved' if args.default_policy else 'accepted into mempool and mined',flush=True)
            relaxed=args.patched and not args.default_policy
            cases=built['cases'] if relaxed else built['cases'][:1]
            policies=[node.rpc('testmempoolaccept',[c['transaction']['hex']])[0] for c in cases]
            for case,policy in zip(cases,policies):
                if relaxed:
                    assert policy['allowed']==case['expected'],(case['name'],policy)
                elif args.default_policy:
                    assert not policy['allowed'] and policy['reject-reason']=='bad-txns-nonstandard-inputs',policy
                else:
                    assert not policy['allowed'] and 'exactly one' in policy.get('reject-reason','').lower(),policy
                report['cases'].append(dict(name=case['name'],expected_consensus=case['expected'],policy=policy))
            if relaxed:
                # Invalid controls must also fail block consensus on this build.
                for case,record in zip(cases,report['cases']):
                    if not case['expected']:
                        result=consensus_check(node,address,case['transaction'])
                        assert not result['accepted']
                        record['consensus']=result
                        print('PASS rejected by mempool and consensus:',case['name'],flush=True)
                # Exercise ordinary mempool admission and block-template mining.
                primary=cases[0]
                decoded,report['spending']=accept_and_mine(node,address,primary['transaction']['hex'])
                recovered=inspect(funding,decoded,built,primary['payload_hex'])
                assert recovered['extracted_scalars']==553 and recovered['complete_pools']
                assert all(node.rpc('gettxout',funding['txid'],i,False) is None for i in range(80))
                report['recovery']=recovered
                report['combined_vbytes']=funding['vsize']+decoded['vsize']
                assert report['combined_vbytes']==161382
                report['summary']=dict(mempool_accepted_variants=sum(c['expected'] for c in cases),
                    invalid_mempool_and_consensus_rejections=sum(not c['expected'] for c in cases),
                    funding_and_spending_mempool_submitted_and_mined=True,all_expectations_met=True)
                print('PASS original 161,382-vB publication admitted, mined and independently decoded',flush=True)
            elif args.default_policy:
                report['summary']=dict(default_funding_and_spending_policy_rejections_preserved=True,all_expectations_met=True)
                print('PASS patched build preserves default standardness policy',flush=True)
            else:
                report['summary']=dict(funding_mempool_accepted=True,spending_still_requires_policy_patch=True,
                                      all_expectations_met=True)
                print('PASS config alone still rejects spending:',policies[0]['reject-reason'],flush=True)
            report['generation_stderr']=run.stderr
            report['transactions']=built
        finally:node.close()
    paths=[Path(__file__),HERE/'bare_publication_core_check.py',HERE/'publication_core_check.py',
        HERE/'core_check.py',ROOT/'tools/core_regtest.py',ROOT/'examples/pointlock_bare_publication_probe.rs',
        ROOT/'examples/pointlock_sum_lookup_probe.rs',HERE/'bare-publication-transactions.json',ROOT/'Cargo.lock']
    if args.patched:paths.extend([HERE/'core-nonstandard-policy.patch',HERE/'core-nonstandard-build.json'])
    report['source_sha256']={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    path=HERE/f'bare-nonstandard-{label}.json'
    path.write_text(json.dumps(report,indent=2)+'\n')
    print(path,flush=True)


if __name__=='__main__':main()
