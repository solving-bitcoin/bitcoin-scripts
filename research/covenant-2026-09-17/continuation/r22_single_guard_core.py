#!/usr/bin/env python3
"""Fund R22 guard boundary vectors on private, peerless Bitcoin Core regtest."""
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import r22_single_guard as host
from r11_endomorphism_core import spend_tx
sys.path.insert(0,str(HERE.parent))
from core_gate_check import isolated_core_binary,p2sh,push
from core_regtest import Node,consensus_check,transaction


def main():
    script=host.layout()
    report={'scope':'Complete funded raw consensus-boundary transactions. No repository compiler metrics, no output covenant.',
        'redeem_script':script.hex(),'redeem_script_bytes':len(script),
        'locking_script_bytes':23,'redeem_entry_data_items':3,'hint_items':0,
        'all_hint_items_at_entry':0,'script_sig_push_items':4,
        'combined_stack_peak_if_success':6,'redeem_executed_non_push_opcodes':32,
        'P2SH_additional_non_push_opcodes':2,'native_signature_checks':4,
        'stack_composition':'Three non-hint data items at redeem entry; scriptSig also pushes the redeem script. Empty altstack. Redeem peak six includes every data item; P2SH outer peak five. The separate OP_TRUE P2WSH input has one witness item.',
        'processed_script_code_bytes':[len(host.codes(script)[i]) for i in (0,2)],
        'results':[]}
    with tempfile.TemporaryDirectory(prefix='covenant-r22-guard-') as directory:
        root=Path(directory);cache=root/'binary';cache.mkdir()
        for archive in Path('/private/tmp/covenant-core-30.3').glob('bitcoin-30.3-*.tar.gz'):
            shutil.copyfile(archive,cache/archive.name)
        binary,provenance=isolated_core_binary(cache,False)
        report['bitcoin_core']=provenance
        chain=root/'chain';chain.mkdir();node=Node(binary,chain)
        try:
            node.ready()
            address=node.rpc('decodescript','51')['segwit']['address']
            mining=bytes.fromhex(node.rpc('validateaddress',address)['scriptPubKey'])
            blocks=[]
            for _ in range(101):
                node.tick();blocks+=node.rpc('generatetoaddress',1,address)
            coinbase=node.rpc('getblock',blocks[0],2)['tx'][0]
            coin=next(o for o in coinbase['vout'] if o['scriptPubKey']['hex']==mining.hex())
            funding=transaction(coinbase['txid'],coin['n'],[b'\x51'],
                [(1000000,p2sh(script)),(1000000,mining),(4997990000,mining)])
            assert consensus_check(node,address,funding)['accepted']
            report['funding']=funding
            wire=bytes.fromhex(funding['txid'])[::-1]
            inputs=[(wire+struct.pack('<I',i),0xffffffff) for i in (1,0)]
            outputs=[(1990000,b'\x00\x14'+b'\x11'*20)]
            other=[(1990000,b'\x00\x14'+b'\x22'*20)]
            inrange=[(1900000,outputs[0][1]),(90000,other[0][1])]
            cases=[]

            def build(name,data,outs,expected):
                pre,hashes,z=host.native(inputs,outs,1,script,data[0][-1])
                try:
                    trace=host.execute(script,data,z);accepted=True
                except (AssertionError,ValueError):
                    trace=None;accepted=False
                assert accepted==expected,(name,accepted)
                sigscript=b''.join(push(x) for x in data+[script])
                tx=spend_tx(funding['txid'],sigscript,outs,0)
                cases.append({'name':name,'expected':expected,'data':[x.hex() for x in data],
                    'signature_bytes':len(data[0]),'script_sig_bytes':len(sigscript),
                    'processed_preimages':[None if p is None else p.hex() for p in (pre[0],pre[2])],
                    'actual_digest_bytes':[hashes[0].hex(),hashes[2].hex()],
                    'output_values':[v for v,_ in outs],'fee_sats':2000000-sum(v for v,_ in outs),
                    'locked_input_witness_items':0,'locked_input_serialized_witness_bytes':1,
                    'helper_witness_items':1,'helper_hint_items':0,'helper_serialized_witness_bytes':3,
                    'all_inputs_hint_items':0,'all_inputs_data_items':4,
                    'transaction':tx,'host_trace':trace})

            data=host.row(host.C)
            build('SINGLE-bug',data,outputs,True)
            build('SINGLE-bug-changed-recipient-same-data',data,other,True)
            build('SINGLE-ANYONECANPAY-bug',host.row(host.C,0x83),outputs,True)
            build('undefined-upper-bits-SINGLE-bug',host.row(host.C,0x23),outputs,True)
            for name,flag,outs in [('ALL-first-context-only',1,outputs),('NONE-first-context-only',2,outputs),
                                  ('in-range-SINGLE-first-context-only',3,inrange)]:
                z=host.native(inputs,outs,1,script,flag)[2]
                assert z[0]!=z[2]
                build(name,host.row(z[0],flag),outs,False)
            build('duplicate-compressed-key',[data[0],data[1],data[1]],outputs,False)
            build('short-valid-SINGLE-signature',host.row(host.C,3,short=True),outputs,False)
            q=host.point(data[2]);uncompressed=b'\x04'+q[0].to_bytes(32,'big')+q[1].to_bytes(32,'big')
            build('uncompressed-second-key',[data[0],data[1],uncompressed],outputs,False)

            for case in cases:
                tx=case['transaction'];decoded=node.rpc('decoderawtransaction',tx['hex'])
                assert decoded['txid']==tx['txid'] and decoded['weight']==tx['weight']
                case['policy']=node.rpc('testmempoolaccept',[tx['hex']])[0]
                assert not case['policy']['allowed'],case['name']
            for case in cases:
                actual=consensus_check(node,address,case['transaction'])
                assert actual['accepted']==case['expected'],(case['name'],actual)
                case['consensus']=actual
                case['evidence']='differentially-validated'
                case['deployment_class']='consensus-validated' if actual['accepted'] else 'consensus-incompatible'
                if actual['accepted']:
                    node.rpc('invalidateblock',actual['block_hash'])
                    case['test_block_invalidated_for_same_funding_comparison']=True
                print('PASS',case['name'],'accepted=',actual['accepted'],flush=True)
            report['results']=cases;report['all_expectations_met']=True
        finally:node.close()
    Path(__file__).with_suffix('.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
