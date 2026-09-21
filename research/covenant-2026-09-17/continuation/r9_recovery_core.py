#!/usr/bin/env python3
"""Core boundary checks of the universal three-common-key relation.

Positive contexts are identical. No reference hash collision or covenant.
"""
import json
from pathlib import Path
import sys
import tempfile

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent))
from core_gate_check import isolated_core_binary,p2sh,push
from core_regtest import Node,consensus_check,transaction
from legacy_same_signature_counterexample import N,P,add,mul,hash256,signature_integer,verify
from r6_length_puzzle import with_locktime
from r9_four_roots import variable_signature_layout


def nonce_roots(r):
    points=[]
    for x in (r,r+N):
        if x>=P: continue
        y=pow((x*x*x+7)%P,(P+1)//4,P)
        if y*y%P != (x*x*x+7)%P: continue
        points += [(x,y),(x,-y%P)]
    return points


def compressed(q):
    return bytes([2+q[1]%2])+q[0].to_bytes(32,'big')


def main():
    ordinary=bytes.fromhex(variable_signature_layout(False)['raw_script'])
    separated=bytes.fromhex(variable_signature_layout(True)['raw_script'])
    scripts=[ordinary]*5+[separated]
    nonce_values=[r for r in range(1,100) if len(nonce_roots(r))==4][:4]
    assert len(nonce_values)==4
    binary,provenance=isolated_core_binary(Path('/private/tmp/covenant-core-30.3'),False)
    report={'scope':__doc__,'bitcoin_core':provenance,
            'ordinary_layout':variable_signature_layout(False),
            'separated_layout':variable_signature_layout(True),'results':[]}
    with tempfile.TemporaryDirectory(prefix='covenant-r9-recovery-') as tmp:
        node=Node(binary,Path(tmp))
        try:
            node.ready()
            address=node.rpc('decodescript','51')['segwit']['address']
            mining=bytes.fromhex(node.rpc('validateaddress',address)['scriptPubKey'])
            blocks=[]
            for _ in range(101):
                node.tick(); blocks+=node.rpc('generatetoaddress',1,address)
            cb=node.rpc('getblock',blocks[0],2)['tx'][0]
            coin=next(o for o in cb['vout'] if o['scriptPubKey']['hex']==mining.hex())
            funding=transaction(cb['txid'],coin['n'],[b'\x51'],
                                [(1000000,p2sh(script)) for script in scripts]+[(4993990000,mining)])
            assert consensus_check(node,address,funding)['accepted']
            report['funding']=funding
            outputs=[(990000,b'\x00\x14'+b'\x11'*20)]

            def make(index,r,s,excluded=3):
                script=scripts[index]
                # There are no literal signature pushes in this generated script.
                # CODESEPARATOR bytes occur only as opcodes, not inside pushes.
                first_code=script.replace(b'\xab',b'')
                first_digest=hash256(with_locktime(funding['txid'],index,first_code,outputs,0)+b'\x01\0\0\0')
                z=int.from_bytes(first_digest,'big')%N
                inv=pow(r,-1,N)
                keys=[mul(inv,add(mul(s,point),mul(-z))) for point in nonce_roots(r)]
                assert len(keys)==4 and all(verify(z,r,s,q)[0] for q in keys)
                body=signature_integer(r)+signature_integer(s)
                sigma=b'\x30'+bytes([len(body)])+body+b'\x01'
                assert push(sigma) not in script
                selected=[q for j,q in enumerate(keys) if j!=excluded]
                items=[sigma]+[compressed(q) for q in selected]
                second_code=script.split(b'\xab')[-1] if b'\xab' in script else first_code
                second_digest=hash256(with_locktime(funding['txid'],index,second_code,outputs,0)+b'\x01\0\0\0')
                return items,{'r':r,'s':s,'excluded_nonce_root':excluded,
                             'first_sighash':first_digest.hex(),'second_sighash':second_digest.hex()},selected

            def check(name,index,items,expected,details):
                assert node.rpc('getrawmempool')==[]
                script=scripts[index]
                script_sig=b''.join(push(x) for x in items)+push(script)
                raw=with_locktime(funding['txid'],index,script_sig,outputs,0)
                spend={'hex':raw.hex(),'txid':hash256(raw)[::-1].hex(),'weight':4*len(raw),
                       'total_bytes':len(raw),'witness_bytes':0}
                policy=node.rpc('testmempoolaccept',[spend['hex']])[0]
                consensus=consensus_check(node,address,spend)
                assert consensus['accepted']==expected and policy['allowed']==expected,(name,policy,consensus)
                report['results'].append({'name':name,'redeemscript':script.hex(),'redeemscript_bytes':len(script),
                    'input_items':[x.hex() for x in items],'entry_data_items':len(items),'hint_items':0,
                    'script_sig_push_items':len(items)+1,'script_sig_bytes':len(script_sig),
                    'combined_stack_peak_by_inspection':7 if expected else None,
                    'executed_non_push_opcodes_redeem_if_success':47 if expected else None,
                    'p2sh_additional_opcodes_if_success':2 if expected else None,
                    'transaction':spend,'policy':policy,'consensus':consensus,
                    'evidence':'differentially-validated',
                    'deployment_class':'policy-validated' if expected else 'consensus-incompatible',**details})
                print('PASS',name,'accepted=',expected,flush=True)

            for index,(r,s) in enumerate(zip(nonce_values,(1,2,17,129))):
                items,details,_=make(index,r,s,index)
                assert details['first_sighash']==details['second_sighash']
                check('three-common-keys-r%d-s%d'%(r,s),index,items,True,details)
            items,details,keys=make(4,2,1)
            check('duplicate-key',4,[items[0],items[1],items[1],items[3]],False,details)
            uncompressed=b'\x04'+keys[1][0].to_bytes(32,'big')+keys[1][1].to_bytes(32,'big')
            check('uncompressed-key',4,[items[0],items[1],uncompressed,items[3]],False,details)
            check('changed-signature',4,[items[0][:-2]+b'\x02\x01']+items[1:],False,details)
            items,details,_=make(5,2,1)
            assert details['first_sighash']!=details['second_sighash']
            check('different-codeseparator-context',5,items,False,details)
            report['all_expectations_met']=True
        finally:
            node.close()
    output=HERE/'r9_recovery_core.json'
    output.write_text(json.dumps(report,indent=2)+'\n')
    print(output)


if __name__=='__main__':
    main()
