#!/usr/bin/env python3
"""Validate table-first point-lock pool fixtures on isolated, unmodified Core.

This validates individual pools, not a complete 256-byte publication.
"""
import hashlib
import json
from pathlib import Path
import tempfile

from core_check import (Node, consensus_check, transaction, serialize_spend,
                        native_digest, BUG_DIGEST, unpack_signature)
from multisig_core_check import minimal_push, script_counts
from bare_publication_core_check import equation, scalar_opening

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]


def main():
    vectors_path=HERE/'clamped-lookup-comparison.json'
    vectors=json.loads(vectors_path.read_text())
    for path,digest in vectors['source_sha256'].items():
        assert hashlib.sha256((ROOT/path).read_bytes()).hexdigest()==digest,path
    pin=json.loads((HERE/'bare-publication-core-check.json').read_text())['bitcoin_core']
    binary=Path('/private/tmp/covenant-core-30.3/bitcoind')
    assert hashlib.sha256(binary.read_bytes()).hexdigest()==pin['binary_sha256']
    rows=vectors['cases']
    report=dict(scope=__doc__,bitcoin_core=pin,results=[],
                evidence='differentially-validated',deployment='consensus-validated',
                full_publication_validated=False,consensus_rules_relaxed=False,
                vectors_sha256=hashlib.sha256(vectors_path.read_bytes()).hexdigest())
    with tempfile.TemporaryDirectory(prefix='bitcoin-lab-clamped-lookup-') as temporary:
        node=Node(binary,Path(temporary))
        try:
            node.ready()
            report['node_options']=node.options
            assert not node.rpc('getnetworkinfo')['networkactive'] and not node.rpc('getpeerinfo')
            address=node.rpc('decodescript','51')['segwit']['address']
            mining=bytes.fromhex(node.rpc('validateaddress',address)['scriptPubKey'])
            blocks=[]
            for _ in range(101):
                node.tick();blocks+=node.rpc('generatetoaddress',1,address)
            coinbase=node.rpc('getblock',blocks[0],2)['tx'][0]
            coin=next(v for v in coinbase['vout'] if v['scriptPubKey']['hex']==mining.hex())
            funding_outputs=[]
            for row in rows:
                funding_outputs += [(1_000_000,mining),(1_000_000,bytes.fromhex(row['script_hex']))]
            funding_outputs.append((5_000_000_000-2_000_000*len(rows)-10_000,mining))
            funding=transaction(coinbase['txid'],coin['n'],[b'\x51'],funding_outputs)
            report['funding']=dict(transaction=funding,consensus=consensus_check(node,address,funding))
            assert report['funding']['consensus']['accepted']
            generator=bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
            for ordinal,row in enumerate(rows):
                script=bytes.fromhex(row['script_hex'])
                items=[bytes.fromhex(v) for v in row['items_hex']]
                ss=b''.join(minimal_push(v) for v in items)
                inputs=[(funding['txid'],ordinal*2,b'',0xffffffff),
                        (funding['txid'],ordinal*2+1,ss,0xffffffff)]
                index=row['locked_input_index'];helper=0
                if index==0:inputs.reverse();helper=1
                outputs=[(1_990_000,mining)]
                if row['output_count']==2:outputs=[(990_000,mining),(1_000_000,mining)]
                spend=serialize_spend(inputs,outputs,helper)
                decoded=node.rpc('decoderawtransaction',spend['hex'])
                assert decoded['txid']==spend['txid'] and decoded['weight']==spend['weight']
                result=consensus_check(node,address,spend)
                assert result['accepted']==row['expected'],(row['name'],result)
                recovered=[]
                if row['expected']:
                    frames=items[-3*row['t']:]
                    for pos in range(0,len(frames),3):
                        frame=frames[pos:pos+3]
                        sigma,key=(frame[0],frame[1]) if row['direct'] else (frame[2],frame[1])
                        assert key.hex() in row['keys_hex'] and len(sigma)>57
                        digest,preimage,_=native_digest(inputs,outputs,index,script,sigma)
                        assert digest==BUG_DIGEST and preimage is None
                        assert equation(sigma,generator,digest) and equation(sigma,key,digest)
                        recovered.append(dict(candidate=row['keys_hex'].index(key.hex()),
                                              scalar=scalar_opening(sigma,key,digest)))
                    assert len({v['candidate'] for v in recovered})==row['t']
                ops,sigops=script_counts(script)
                report['results'].append(dict(name=row['name'],expected=row['expected'],consensus=result,
                    transaction=spend,script_bytes=len(script),script_sig_bytes=len(ss),
                    static_non_push_opcodes=ops,sigops=sigops,hint_items=row['hint_items'],
                    entry_items=len(items),local_combined_stack_peak=row['combined_stack_peak'],
                    recovered=recovered))
                print('PASS',row['name'],result['accepted'],flush=True)
        finally:
            node.close()
    report['all_expectations_met']=True
    paths=['examples/pointlock_clamped_lookup_probe.rs',
           'research/pointlocks-2026-09-17/clamped_lookup_core_check.py',
           'research/pointlocks-2026-09-17/core_check.py',
           'research/pointlocks-2026-09-17/bare_publication_core_check.py','tools/core_regtest.py']
    report['source_sha256']={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in paths}
    (HERE/'clamped-lookup-core-check.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':
    main()
